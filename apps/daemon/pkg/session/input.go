// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/daytonaio/common-go/pkg/log"
)

// SendInput sends data to the session's stdin for a specific running command
// This enables interactive command input for sessions
func (s *SessionService) SendInput(ctx context.Context, sessionId, commandId string, data string) error {
	session, ok := s.sessions.Get(sessionId)
	if !ok {
		return common_errors.NewNotFoundError(errors.New("session not found"))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopSessionCancellation := context.AfterFunc(session.ctx, cancel)
	defer stopSessionCancellation()
	f, command, err := s.openCommandInput(ctx, session, commandId)
	if err != nil {
		return err
	}
	defer f.Close()
	stopClosing := context.AfterFunc(ctx, func() { _ = f.Close() })
	defer stopClosing()

	// Ensure newline for commands like `read`
	if !strings.HasSuffix(data, "\n") {
		data += "\n"
	}

	// Write to input pipe
	if _, err := f.Write([]byte(data)); err != nil {
		return common_errors.NewInternalServerError(fmt.Errorf("failed to write to input pipe: %w", err))
	}

	if ctx.Err() != nil || session.ctx.Err() != nil {
		return common_errors.NewGoneError(errors.New("session closed during input delivery; input outcome is unknown"))
	}
	if !command.SuppressInputEcho {
		// Also echo input to log file for visibility (appears as stdout)
		logFilePath, _ := command.LogFilePath(session.Dir(s.configDir))
		logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			s.logger.Debug("failed to open log file to echo input", "error", err)
		} else {
			defer logFile.Close()
			// Deletion cancels this immutable owner before it removes paths.
			// If open reached a replacement directory, that cancellation is
			// already observable. Otherwise this descriptor keeps the old log.
			if ctx.Err() != nil || session.ctx.Err() != nil {
				return common_errors.NewGoneError(errors.New("session closed during input delivery; input outcome is unknown"))
			}
			// Write with STDOUT prefix to maintain log format consistency
			dataWithPrefix := append(log.STDOUT_PREFIX, []byte(data)...)
			_, err = logFile.Write(dataWithPrefix)
			if err != nil {
				s.logger.Error("failed to echo input to log file", "error", err)
			}
		}
	}

	return nil
}

func (s *SessionService) openCommandInput(ctx context.Context, owned *session, commandID string) (*os.File, *Command, error) {
	for {
		scope := owned.scope.Load()
		if ctx.Err() != nil || owned.ctx.Err() != nil || scope == nil || scope.shellExited.Load() || scope.state() != "running" {
			return nil, nil, common_errors.NewGoneError(errors.New("session process is no longer accepting input"))
		}
		command, err := s.commandObservation(owned, commandID)
		if err != nil {
			return nil, nil, err
		}
		if command.ExitCode != nil {
			return nil, nil, common_errors.NewGoneError(fmt.Errorf("command has already completed with exit code %d", *command.ExitCode))
		}
		file, err := os.OpenFile(command.InputFilePath(owned.Dir(s.configDir)), os.O_WRONLY|syscall.O_NONBLOCK, 0600)
		if err == nil {
			// Never wait for submission serialization here: the shell may
			// need this input before it can drain queued command writes.
			// Cancellation precedes path removal, so this post-open check
			// rejects replacement paths before any input can be written.
			if ctx.Err() != nil || owned.ctx.Err() != nil {
				_ = file.Close()
				return nil, nil, common_errors.NewGoneError(errors.New("session process is no longer accepting input"))
			}
			return file, command, nil
		}
		if !errors.Is(err, syscall.ENXIO) && !os.IsNotExist(err) {
			return nil, nil, common_errors.NewInternalServerError(fmt.Errorf("failed to open input pipe: %w", err))
		}
		// The async receipt may precede FIFO creation or its reader opening.
		// Never block inside open: cancellation must also end this wait when
		// the command has closed stdin or deletion has unlinked the pipe.
		select {
		case <-ctx.Done():
			return nil, nil, common_errors.NewGoneError(errors.New("session process is no longer accepting input"))
		case <-time.After(25 * time.Millisecond):
		}
	}
}
