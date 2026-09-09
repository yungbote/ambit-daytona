// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func newStdinTestService(t *testing.T) *SessionService {
	t.Helper()
	return newTestServiceIn(t, t.TempDir())
}

// newTestServiceIn constructs a service over an exact configuration directory,
// so a test can build a second service over the first one's retained state.
func newTestServiceIn(t *testing.T, configDir string) *SessionService {
	t.Helper()
	svc, err := NewSessionService(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		configDir,
		250*time.Millisecond,
		25*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("new session service: %v", err)
	}
	return svc
}

func openSession(t *testing.T, svc *SessionService, id string) {
	t.Helper()
	if err := svc.Create(id, false); err != nil {
		t.Fatalf("create session %s: %v", id, err)
	}
	t.Cleanup(func() { _ = svc.Delete(context.Background(), id) })
}

// pollCommand returns the command once it reports an exit code, or fails at the deadline.
func pollCommand(t *testing.T, svc *SessionService, sessionID, commandID string, within time.Duration) *Command {
	t.Helper()
	timeout := time.After(within)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		cmd, err := svc.GetSessionCommand(sessionID, commandID)
		if err != nil {
			t.Fatalf("get command %s: %v", commandID, err)
		}
		if cmd.ExitCode != nil {
			return cmd
		}
		select {
		case <-timeout:
			t.Fatalf("command %s did not exit within %s", commandID, within)
			return nil
		case <-ticker.C:
		}
	}
}

// expectRunning fails if the command exits before the window elapses.
func expectRunning(t *testing.T, svc *SessionService, sessionID, commandID string, window time.Duration) {
	t.Helper()
	timeout := time.After(window)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-timeout:
			return
		case <-ticker.C:
			cmd, err := svc.GetSessionCommand(sessionID, commandID)
			if err != nil {
				t.Fatalf("get command %s: %v", commandID, err)
			}
			if cmd.ExitCode != nil {
				t.Fatalf("command %s exited early (code %d)", commandID, *cmd.ExitCode)
			}
		}
	}
}

// A synchronous command gets an immediate stdin EOF, so the `read` fails and the
// else branch runs.
func TestSyncCommandGetsStdinEOF(t *testing.T) {
	svc := newStdinTestService(t)
	const sessionID = "sync-eof"
	openSession(t, svc, sessionID)

	const script = `if read -r line; then printf 'read:%s\n' "$line"; else printf 'eof\n'; fi`

	type result struct {
		exec *SessionExecute
		err  error
	}
	done := make(chan result, 1)
	go func() {
		exec, err := svc.Execute(sessionID, "", script, false, true, false, true)
		done <- result{exec: exec, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("execute sync command: %v", r.err)
		}
		if r.exec.ExitCode == nil || *r.exec.ExitCode != 0 {
			t.Fatalf("exit code = %#v, want 0", r.exec.ExitCode)
		}
		if r.exec.Output == nil || !strings.Contains(*r.exec.Output, "eof") {
			t.Fatalf("output = %#v, want it to contain %q", r.exec.Output, "eof")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sync command never observed stdin EOF")
	}
}

// An async command keeps stdin open until SendInput delivers a line.
func TestAsyncCommandBlocksUntilSendInput(t *testing.T) {
	svc := newStdinTestService(t)
	const sessionID = "async-hold"
	openSession(t, svc, sessionID)

	const script = `read -r line; printf 'got:%s\n' "$line"`
	exec, err := svc.Execute(sessionID, "", script, true, true, false, true)
	if err != nil {
		t.Fatalf("execute async command: %v", err)
	}

	expectRunning(t, svc, sessionID, exec.CommandId, 300*time.Millisecond)

	if err := svc.SendInput(context.Background(), sessionID, exec.CommandId, "hello from test"); err != nil {
		t.Fatalf("send input: %v", err)
	}

	cmd := pollCommand(t, svc, sessionID, exec.CommandId, 2*time.Second)
	if cmd.ExitCode == nil || *cmd.ExitCode != 0 {
		t.Fatalf("exit code = %#v, want 0", cmd.ExitCode)
	}

	logs, err := svc.GetSessionCommandLogs(sessionID, exec.CommandId, nil, nil, FetchLogsOptions{IsCombinedOutput: true})
	if err != nil {
		t.Fatalf("read command logs: %v", err)
	}
	if !strings.Contains(string(logs), "got:hello from test") {
		t.Fatalf("logs = %q, want it to contain %q", string(logs), "got:hello from test")
	}
}
