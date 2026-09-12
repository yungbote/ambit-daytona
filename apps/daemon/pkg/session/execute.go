// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/daytonaio/daemon/internal/util"
	"github.com/google/uuid"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/daytonaio/common-go/pkg/log"
)

func (s *SessionService) Execute(sessionId, cmdId, cmd string, async, isCombinedOutput, skipServerDemux, suppressInputEcho bool, closeInputAfterCommand ...bool) (observation *SessionExecute, executionErr error) {
	session, ok := s.sessions.Get(sessionId)
	if !ok {
		return nil, common_errors.NewNotFoundError(errors.New("session not found"))
	}

	var scope *processScope
	defer func() {
		if observation == nil {
			return
		}
		observation.ProcessScope = "unavailable"
		if scope != nil {
			observation.ProcessScope = scope.state()
		}
		observation.InputClosed = session.ctx.Err() != nil || scope == nil || scope.inputClosed.Load()
	}()

	session.mu.Lock()
	scope = session.scope.Load()
	locked := true
	defer func() {
		if locked {
			session.mu.Unlock()
		}
	}()
	if session.ctx.Err() != nil || scope == nil || scope.inputClosed.Load() || scope.state() != "running" {
		return nil, common_errors.NewGoneError(errors.New("session is no longer accepting commands"))
	}

	if cmdId == util.EmptyCommandID {
		cmdId = uuid.NewString()
	}

	if _, ok := session.commands.Get(cmdId); ok {
		return nil, common_errors.NewConflictError(errors.New("command with the given ID already exists"))
	}

	command := &Command{
		Id:                cmdId,
		Command:           cmd,
		SuppressInputEcho: suppressInputEcho,
	}
	session.commands.Set(cmdId, command)

	logFilePath, exitCodeFilePath := command.LogFilePath(session.Dir(s.configDir))
	logDir := filepath.Dir(logFilePath)

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, common_errors.NewBadRequestError(fmt.Errorf("failed to create log directory: %w", err))
	}

	logFile, err := os.Create(logFilePath)
	if err != nil {
		return nil, common_errors.NewBadRequestError(fmt.Errorf("failed to create log file: %w", err))
	}

	defer logFile.Close()

	cmdFilePath := filepath.Join(logDir, "cmd.sh")
	if err := os.WriteFile(cmdFilePath, []byte(cmd), 0600); err != nil {
		return nil, common_errors.NewBadRequestError(fmt.Errorf("failed to write command file: %w", err))
	}

	stdinRedirect := `< /dev/null`
	if async {
		stdinRedirect = `<> "$ip"`
	}

	cmdToExec := fmt.Sprintf(cmdWrapperFormat+"\n",
		logFilePath, // %q  -> log
		logDir,      // %q  -> dir
		command.InputFilePath(session.Dir(s.configDir)), // %q  -> input
		toOctalEscapes(log.STDOUT_PREFIX),               // %s  -> stdout prefix
		toOctalEscapes(log.STDERR_PREFIX),               // %s  -> stderr prefix
		exitCodeFilePath,                                // %q  -> durable command result
		cmdFilePath,                                     // %q  -> command file path
		stdinRedirect,                                   // %s  -> stdin behavior
	)

	_, err = scope.input.Write([]byte(cmdToExec))
	if err != nil {
		return nil, common_errors.NewBadRequestError(fmt.Errorf("failed to write command: %w", err))
	}

	if len(closeInputAfterCommand) > 0 && closeInputAfterCommand[0] {
		if err := scope.closeInput(); err != nil {
			return nil, common_errors.NewBadRequestError(fmt.Errorf("command accepted but closing session input failed: %w", err))
		}
	}
	session.mu.Unlock()
	locked = false

	if async {
		return &SessionExecute{
			CommandId: cmdId,
		}, nil
	}

	for {
		select {
		case <-session.ctx.Done():
			_, ok := session.commands.Get(cmdId)
			if !ok {
				return nil, common_errors.NewBadRequestError(errors.New("command not found"))
			}

			return nil, common_errors.NewBadRequestError(errors.New("session cancelled"))
		default:
			exitCode, err := os.ReadFile(exitCodeFilePath)
			if err != nil {
				if os.IsNotExist(err) {
					if scope.shellExited.Load() || scope.state() != "running" {
						// Recheck after the terminal observation: the shell may have
						// published its result between the first read and its exit.
						if _, err := os.Stat(exitCodeFilePath); err == nil {
							continue
						}
						return nil, common_errors.NewBadRequestError(errors.New("session shell ended without a command result"))
					}
					time.Sleep(50 * time.Millisecond)
					continue
				}
				return nil, common_errors.NewBadRequestError(fmt.Errorf("failed to read exit code file: %w", err))
			}

			exitCodeInt, err := strconv.Atoi(strings.TrimRight(string(exitCode), "\n"))
			if err != nil {
				return nil, common_errors.NewBadRequestError(fmt.Errorf("failed to convert exit code to int: %w", err))
			}

			_, ok := session.commands.Get(cmdId)
			if !ok {
				return nil, common_errors.NewBadRequestError(errors.New("command not found"))
			}

			logBytes, err := os.ReadFile(logFilePath)
			if err != nil {
				return nil, common_errors.NewBadRequestError(fmt.Errorf("failed to read log file: %w", err))
			}

			if isCombinedOutput {
				stripped := bytes.ReplaceAll(bytes.ReplaceAll(logBytes, log.STDOUT_PREFIX, []byte{}), log.STDERR_PREFIX, []byte{})
				output := string(stripped)
				return &SessionExecute{
					CommandId: cmdId,
					Output:    &output,
					ExitCode:  &exitCodeInt,
				}, nil
			}

			output := string(logBytes)
			result := &SessionExecute{
				CommandId: cmdId,
				Output:    &output,
				ExitCode:  &exitCodeInt,
			}

			if !skipServerDemux {
				stdoutBytes, stderrBytes := DemuxLogBytes(logBytes)
				stdoutStr := string(stdoutBytes)
				stderrStr := string(stderrBytes)
				result.Stdout = &stdoutStr
				result.Stderr = &stderrStr
			}

			return result, nil
		}
	}
}

func DemuxLogBytes(data []byte) (stdout, stderr []byte) {
	prefixLen := len(log.STDOUT_PREFIX)
	var outBuf, errBuf []byte
	pos := 0

	for pos < len(data) {
		if pos+prefixLen <= len(data) && bytes.Equal(data[pos:pos+prefixLen], log.STDOUT_PREFIX) {
			end := findNextMarker(data, pos+prefixLen, prefixLen)
			outBuf = append(outBuf, data[pos+prefixLen:end]...)
			pos = end
		} else if pos+prefixLen <= len(data) && bytes.Equal(data[pos:pos+prefixLen], log.STDERR_PREFIX) {
			end := findNextMarker(data, pos+prefixLen, prefixLen)
			errBuf = append(errBuf, data[pos+prefixLen:end]...)
			pos = end
		} else {
			pos++
		}
	}

	return outBuf, errBuf
}

func findNextMarker(data []byte, from int, prefixLen int) int {
	for i := from; i+prefixLen <= len(data); i++ {
		if bytes.Equal(data[i:i+prefixLen], log.STDOUT_PREFIX) || bytes.Equal(data[i:i+prefixLen], log.STDERR_PREFIX) {
			return i
		}
	}
	return len(data)
}

func toOctalEscapes(b []byte) string {
	out := ""
	for _, c := range b {
		out += fmt.Sprintf("\\%03o", c) // e.g. 0x01 → \001
	}
	return out
}

var cmdWrapperFormat string = `
{
	log=%q
	dir=%q

	# per-command FIFOs
	sp="$dir/stdout.pipe"
	ep="$dir/stderr.pipe"
	ip=%q
	
	rm -f "$sp" "$ep" "$ip" && mkfifo "$sp" "$ep" "$ip" || exit 1

	cleanup() { rm -f "$sp" "$ep" "$ip"; }
	trap 'cleanup' HUP INT TERM

  # prefix each stream and append to shared log
	( while IFS= read -r line || [ -n "$line" ]; do printf '%s%%s\n' "$line"; done < "$sp" ) >> "$log" & r1=$!
	( while IFS= read -r line || [ -n "$line" ]; do printf '%s%%s\n' "$line"; done < "$ep" ) >> "$log" & r2=$!

	# The sourced command can exit this shell explicitly or through errexit.
	# Preserve that exact status before draining output, including on that path.
	finish_command() {
		_ec=$1
		wait "$r1" "$r2" || return
		# Publish atomically only after both streams drain: readers cannot see
		# the empty file between creation and writing its complete exit code.
		result=%q
		printf '%%s\n' "$_ec" > "$result.pending" && mv -f "$result.pending" "$result"
		cleanup
	}
	# An exit from inside the redirected source still owns the FIFO writer FDs.
	# Close them before waiting, otherwise its own labelers never receive EOF.
	trap '_exit_code=$?; exec > /dev/null 2>&1; finish_command "$_exit_code"' EXIT

	# Source the command so ordinary stateful session semantics are preserved.
	# Sync input is /dev/null; async input retains its FIFO writer until done.
	{ . %q; } %s > "$sp" 2> "$ep"
	_ec=$?
	finish_command "$_ec"
	# Normal completion already recorded the result; a later shell exit only
	# performs cleanup and cannot overwrite this command's status.
	trap 'cleanup' EXIT

}
`
