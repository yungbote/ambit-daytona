package session

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestExplicitExitPublishesExactCommandResult(t *testing.T) {
	for _, exitCode := range []int{0, 7} {
		for _, async := range []bool{false, true} {
			t.Run(fmt.Sprintf("exit%d_async%t", exitCode, async), func(t *testing.T) {
				svc := newStdinTestService(t)
				id := fmt.Sprintf("exit%d-%t", exitCode, async)
				openSession(t, svc, id)
				result, err := svc.Execute(id, "exit-result", fmt.Sprintf("printf 'before-exit'; printf 'diagnostic' >&2; exit %d", exitCode), async, true, false, true, true)
				if err != nil {
					t.Fatal(err)
				}
				command := pollCommand(t, svc, id, result.CommandId, 3*time.Second)
				if *command.ExitCode != exitCode {
					t.Fatalf("exit = %d, want %d", *command.ExitCode, exitCode)
				}
				logs, err := svc.GetSessionCommandLogs(id, result.CommandId, nil, nil, FetchLogsOptions{IsCombinedOutput: true})
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(logs), "before-exit") || !strings.Contains(string(logs), "diagnostic") {
					t.Fatalf("logs not drained: %#v", logs)
				}
			})
		}
	}
}

func TestExplicitExitWaitsForBackgroundOutputBeforeResult(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "exit-with-output-child")
	result, err := svc.Execute("exit-with-output-child", "exit-background", `(sleep 0.2; printf 'last-child-byte') & exit 7`, true, true, false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	expectRunning(t, svc, "exit-with-output-child", result.CommandId, 80*time.Millisecond)
	command := pollCommand(t, svc, "exit-with-output-child", result.CommandId, 3*time.Second)
	if *command.ExitCode != 7 {
		t.Fatalf("exit=%d", *command.ExitCode)
	}
	logs, err := svc.GetSessionCommandLogs("exit-with-output-child", result.CommandId, nil, nil, FetchLogsOptions{IsCombinedOutput: true})
	if err != nil || !strings.Contains(string(logs), "last-child-byte") {
		t.Fatalf("child output: %#v, %v", logs, err)
	}
}

func TestMissingExitReceiptDoesNotInventSuccessfulCommand(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "killed-shell")
	result, err := svc.Execute("killed-shell", "killed-command", `kill -KILL $$`, true, true, false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	command, err := svc.GetSessionCommand("killed-shell", result.CommandId)
	if err != nil {
		t.Fatal(err)
	}
	if command.ExitCode != nil {
		t.Fatalf("invented exit code %d", *command.ExitCode)
	}
	_ = svc.Delete(context.Background(), "killed-shell")
}

func TestErrexitAndFastOutputHaveCompleteResults(t *testing.T) {
	cases := []struct {
		name, script string
		code         int
		expected     string
	}{
		{"errexit", "set -e; printf 'before-failure'; false", 1, "before-failure"},
		{"fast-output", "i=0; while [ $i -lt 1000 ]; do printf 'record-%s\\n' \"$i\"; i=$((i+1)); done; exit 7", 7, "record-999\n"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			svc := newStdinTestService(t)
			openSession(t, svc, item.name)
			result, err := svc.Execute(item.name, "result", item.script, true, true, false, true, true)
			if err != nil {
				t.Fatal(err)
			}
			command := pollCommand(t, svc, item.name, result.CommandId, 3*time.Second)
			if *command.ExitCode != item.code {
				t.Fatalf("exit=%d", *command.ExitCode)
			}
			logs, err := svc.GetSessionCommandLogs(item.name, result.CommandId, nil, nil, FetchLogsOptions{IsCombinedOutput: true})
			if err != nil || !strings.Contains(string(logs), item.expected) {
				t.Fatalf("incomplete logs: %q, %v", string(logs), err)
			}
		})
	}
}
