// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package pty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/daytonaio/daemon/pkg/childreap"
	"github.com/daytonaio/daemon/pkg/common"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/shirou/gopsutil/v4/process"
)

// createAndStartSession creates a PTYSession, adds it to the manager, and starts it if not lazy.
// On start failure it removes the session from the manager and returns the error.
func createAndStartSession(id, cwd string, envs map[string]string, cols, rows uint16, lazyStart bool, logger *slog.Logger) (*PTYSession, error) {
	if envs == nil {
		envs = make(map[string]string, 1)
	}
	if envs["TERM"] == "" {
		envs["TERM"] = "xterm-256color"
	}

	session := &PTYSession{
		info: PTYSessionInfo{
			ID:        id,
			Cwd:       cwd,
			Envs:      envs,
			Cols:      cols,
			Rows:      rows,
			CreatedAt: time.Now(),
			Active:    false,
			LazyStart: lazyStart,
		},
		clients: cmap.New[*wsClient](),
		logger:  logger.With(slog.String("sessionId", id)),
	}

	if !ptyManager.AddIfAbsent(session) {
		return nil, fmt.Errorf("PTY session with ID '%s' already exists", id)
	}

	if !lazyStart {
		if err := session.start(); err != nil {
			ptyManager.Delete(id)
			return nil, err
		}
	}

	return session, nil
}

// Info returns the current session information
func (s *PTYSession) Info() PTYSessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}

// start initializes and starts the PTY session
func (s *PTYSession) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// already running?
	if s.info.Active && s.cmd != nil && s.ptmx != nil {
		return nil
	}

	// Prevent restarting - once a session exits, it should be removed from manager
	if s.cmd != nil {
		return errors.New("PTY session has already been used and cannot be restarted")
	}

	if s.inCh == nil {
		s.inCh = make(chan []byte, 1024)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.cancel = cancel

	shell := common.GetShell()
	if shell == "" {
		return errors.New("no shell resolved")
	}

	cmd := exec.CommandContext(ctx, shell, "-i", "-l")
	cmd.Dir = s.info.Cwd

	// Env
	cmd.Env = os.Environ()
	for k, v := range s.info.Envs {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: s.info.Rows, Cols: s.info.Cols})
	if err != nil {
		cancel()
		return fmt.Errorf("pty.StartWithSize: %w", err)
	}

	s.cmd = cmd
	s.ptmx = ptmx
	s.inputWriter = ptmx
	s.info.Active = true

	s.logger.Debug("Started PTY session", "sessionId", s.info.ID, "pid", s.cmd.Process.Pid)

	s.readLoopDone = make(chan struct{})

	// 1) PTY -> clients broadcaster
	go s.ptyReadLoop()

	// 2) clients -> PTY writer
	go s.inputWriteLoop()

	// Reap the process; mark inactive on exit and send exit event.
	// Uses Reap (not Wait) because pty.StartWithSize wires std{in,out,err}
	// to *os.File slaves — no Go-level I/O goroutines to drain.
	go func() {
		exitCode, err := childreap.Reap(s.cmd)
		// Reason is paren-free and shared by the "exited" control message and the
		// close frame (via exitCloseFrame) so both channels report identical text.
		var exitReason string
		if err != nil {
			exitCode = 1
			exitReason = "process error"
		} else {
			exitReason = exitReasonText(exitCode)
		}

		s.mu.Lock()
		s.info.Active = false
		sessionID := s.info.ID
		s.mu.Unlock()

		// Build the "exited" control message delivered (before the close frame) to
		// clients that advertised the exit-control capability. Clients that did not
		// opt in (incl. older SDKs) still learn the exit via the universal close
		// frame, so this message can never break them.
		exitMsg := map[string]interface{}{
			"type":     "control",
			"status":   "exited",
			"exitCode": exitCode,
		}
		// Only attach exitReason for a non-zero (failed) exit; exitCloseFrame omits
		// it for code 0 as well, so both channels stay consistent.
		if exitCode != 0 && exitReason != "" {
			exitMsg["exitReason"] = exitReason
		}
		var exitJSON []byte
		if data, err := json.Marshal(exitMsg); err == nil {
			exitJSON = data
		}

		// Flush each client's queued output, then send the "exited" message and the
		// transport-level close frame — draining first so the tail is never dropped.
		s.gracefulCloseClientsWithExitCode(exitCode, exitReason, exitJSON)

		// Remove session from manager - process has exited and won't be reused
		ptyManager.Delete(sessionID)

		s.logger.Debug("PTY session process exited and cleaned up", "sessionId", sessionID, "exitCode", exitCode, "exitReason", exitReason)
	}()

	return nil
}

// kill terminates the PTY session
func (s *PTYSession) kill() {
	// kill process and PTY
	s.mu.Lock()
	// Check if already killed to prevent double-kill
	if !s.info.Active {
		s.mu.Unlock()
		return
	}

	sessionID := s.info.ID
	var pid int
	if s.cmd != nil && s.cmd.Process != nil {
		pid = s.cmd.Process.Pid
	}

	// SIGKILL descendants BEFORE we cancel the ctx or close the PTY
	// master. Both of those have side effects that quickly kill the
	// shell — ctx cancel triggers an async SIGKILL via exec.CommandContext's
	// watchdog, and closing ptmx makes the shell's tty disappear — and
	// once the shell exits, the kernel reparents its children to PID 1.
	// At that point gopsutil.Children(shell_pid) returns nothing (the
	// children's PPID is no longer shell_pid), so descendants like a
	// `sleep & disown` that escaped job-control pgid would slip through
	// and survive teardown. Walking while the shell is still alive
	// guarantees we see and kill them.
	if pid > 0 {
		killProcessTree(pid)
	}

	if s.cancel != nil {
		s.cancel()
	}
	if s.ptmx != nil {
		_ = s.ptmx.Close()
		s.ptmx = nil
		s.inputWriter = nil
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	s.info.Active = false
	s.mu.Unlock()

	// Close WebSocket connections with kill exit code - 137 = 128 + 9 (SIGKILL)
	s.closeClientsWithExitCode(137)

	// Remove session from manager - manually killed
	ptyManager.Delete(sessionID)
}

// killProcessTree sends SIGKILL to every descendant of pid, depth-first so
// leaves die before their parents and don't get a chance to be reparented to
// PID 1 mid-teardown.
func killProcessTree(pid int) {
	parent, err := process.NewProcess(int32(pid))
	if err != nil {
		return
	}
	descendants, err := parent.Children()
	if err != nil {
		return
	}
	for _, child := range descendants {
		killProcessTree(int(child.Pid))
	}
	for _, child := range descendants {
		if p, err := os.FindProcess(int(child.Pid)); err == nil {
			_ = p.Signal(syscall.SIGKILL)
		}
	}
}

// ptyReadLoop reads from PTY and broadcasts to all clients
func (s *PTYSession) ptyReadLoop() {
	defer close(s.readLoopDone)
	buf := make([]byte, 32*1024)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			b := make([]byte, n)
			copy(b, buf[:n])
			s.broadcast(b)
		}
		if err != nil {
			return
		}
	}
}

// inputWriteLoop writes client input to PTY
func (s *PTYSession) inputWriteLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case data, ok := <-s.inCh:
			if !ok {
				return
			}
			s.mu.Lock()
			writer := s.inputWriter
			cancel := s.cancel
			s.mu.Unlock()
			if writer == nil {
				return
			}
			if err := writePTYInput(s.ctx, writer, data); err != nil {
				s.logger.Error("PTY input write failed", "error", err)
				if cancel != nil {
					cancel()
				}
				return
			}
		}
	}
}

// writePTYInput preserves every byte of one admitted WebSocket message. Go's
// io.Writer contract permits short writes, so a single Write call is not a
// complete transport operation. Zero progress and invalid overrun reports fail
// closed rather than spinning or silently dropping a suffix.
func writePTYInput(ctx context.Context, writer io.Writer, data []byte) error {
	for len(data) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		written, err := writer.Write(data)
		if written < 0 || written > len(data) {
			return io.ErrShortWrite
		}
		if written > 0 {
			data = data[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

// sendToPTY sends data from a client to the PTY
func (s *PTYSession) sendToPTY(data []byte) error {
	// Check if inCh is available to prevent panic
	if s.inCh == nil {
		return fmt.Errorf("PTY session input channel not available")
	}

	select {
	case s.inCh <- append([]byte(nil), data...):
		return nil
	case <-s.ctx.Done():
		return fmt.Errorf("PTY session input channel closed")
	}
}

// resize changes the PTY window size
func (s *PTYSession) resize(cols, rows uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if session is still active
	if !s.info.Active {
		return errors.New("cannot resize inactive PTY session")
	}

	if cols > 1000 {
		return fmt.Errorf("cols must be less than 1000")
	}
	if rows > 1000 {
		return fmt.Errorf("rows must be less than 1000")
	}

	s.info.Cols = cols
	s.info.Rows = rows

	if s.ptmx != nil {
		if err := pty.Setsize(s.ptmx, &pty.Winsize{Cols: cols, Rows: rows}); err != nil {
			s.logger.Debug("PTY resize error", "error", err)
			return err
		}
	} else {
		return errors.New("PTY file descriptor is not available")
	}
	return nil
}
