//go:build linux

package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func runCustodyFixture(args []string) bool {
	if len(args) != 3 || args[0] != "--custody-fixture" {
		return false
	}
	mode, path := args[1], args[2]
	switch mode {
	case "fork", "fork-again":
		next := "fork-again"
		if mode == "fork-again" {
			next = "actor"
		}
		cmd := exec.Command("/proc/self/exe", "--custody-fixture", next, path)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			panic(err)
		}
		_ = cmd.Process.Release()
	case "actor":
		signal.Ignore(syscall.SIGTERM, syscall.SIGHUP)
		if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			panic(err)
		}
		// A failed test is bounded even if its cleanup path is broken.
		time.Sleep(20 * time.Second)
	case "owner":
		svc := NewSessionService(slog.New(slog.NewTextHandler(io.Discard, nil)), filepath.Join(filepath.Dir(path), "owner-state"), 100*time.Millisecond, 10*time.Millisecond)
		if err := svc.Create("owner-dies", false); err != nil {
			panic(err)
		}
		command := fixtureCommand("fork", path)
		if _, err := svc.Execute("owner-dies", "start", command, false, true, true, false, true); err != nil {
			panic(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(path); err == nil {
				return true
			}
			time.Sleep(5 * time.Millisecond)
		}
		panic("actor did not start")
	default:
		panic("unknown custody fixture")
	}
	return true
}

func fixtureCommand(mode, path string) string {
	executable, err := os.Executable()
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s --custody-fixture %s %s </dev/null >/dev/null 2>&1", shellFixtureQuote(executable), shellFixtureQuote(mode), shellFixtureQuote(path))
}

func shellFixtureQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func actorFD(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		value, err := os.ReadFile(path)
		if err == nil {
			pid, err := strconv.Atoi(string(value))
			if err != nil {
				t.Fatal(err)
			}
			fd, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); _ = unix.Close(fd) })
			return fd
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("actor did not start")
	return -1
}

func fdTerminated(t *testing.T, fd int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		remaining := max(0, int(time.Until(deadline).Milliseconds()))
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, remaining)
		if errors.Is(err, unix.EINTR) {
			continue // SIGCHLD from another owned helper can interrupt poll.
		}
		if err != nil {
			t.Fatal(err)
		}
		return ready > 0
	}
}

func TestDeleteWaitsForShellItself(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "idle-shell")
	owned, _ := svc.sessions.Get("idle-shell")
	fd, err := unix.PidfdOpen(owned.cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := svc.Delete(context.Background(), "idle-shell"); err != nil {
		t.Fatal(err)
	}
	if !fdTerminated(t, fd, 0) {
		t.Fatal("successful deletion retained its supervisor")
	}
}

func TestDetachedActorStaysOwnedAfterCommandExitAndCancelsExactly(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "detached")
	openSession(t, svc, "unrelated")
	path := filepath.Join(t.TempDir(), "actor.pid")
	other := filepath.Join(t.TempDir(), "other.pid")
	for _, value := range []struct{ id, path string }{{"detached", path}, {"unrelated", other}} {
		result, err := svc.Execute(value.id, "start", fixtureCommand("fork", value.path), false, true, true, false, true)
		if err != nil || result.ExitCode == nil || *result.ExitCode != 0 {
			t.Fatalf("start: %+v %v", result, err)
		}
	}
	fd, otherFD := actorFD(t, path), actorFD(t, other)
	observed, err := svc.Get("detached")
	if err != nil || observed.ProcessScope != "running" || !observed.InputClosed {
		t.Fatalf("background custody lost: %+v %v", observed, err)
	}
	if fdTerminated(t, fd, 0) {
		t.Fatal("main command exit killed useful background work")
	}
	if err := svc.Delete(context.Background(), "detached"); err != nil {
		t.Fatal(err)
	}
	if !fdTerminated(t, fd, 0) {
		t.Fatal("double-forked setsid actor survived successful deletion")
	}
	if fdTerminated(t, otherFD, 0) {
		t.Fatal("another session's retained actor was killed")
	}
}

func TestClosedInputSettlesNaturallyAndPreservesResult(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "natural")
	result, err := svc.Execute("natural", "command", "printf final-output", false, true, true, false, true)
	if err != nil || result.Output == nil || !strings.Contains(*result.Output, "final-output") {
		t.Fatalf("result lost: %+v %v", result, err)
	}
	owned, _ := svc.sessions.Get("natural")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := owned.scope.awaitSettlement(ctx); err != nil {
		t.Fatal(err)
	}
	observed, err := svc.Get("natural")
	if err != nil || observed.ProcessScope != "settled" {
		t.Fatalf("natural settlement absent: %+v %v", observed, err)
	}
	if _, err := svc.Execute("natural", "later", "true", true, true, true, false); err == nil {
		t.Fatal("closed scope accepted a later command")
	}
}

func TestDaemonParentDeathClosesDetachedScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orphan.pid")
	owner := exec.Command("/proc/self/exe", "--custody-fixture", "owner", path)
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Process.Kill() })
	fd := actorFD(t, path)
	if err := owner.Wait(); err != nil {
		t.Fatal(err)
	}
	if !fdTerminated(t, fd, 3*time.Second) {
		t.Fatal("daemon parent death left its actor alive")
	}
}

func TestFailedOrCancelledCleanupRetainsCustodyForRetry(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "pending")
	path := filepath.Join(t.TempDir(), "actor.pid")
	if _, err := svc.Execute("pending", "start", fixtureCommand("fork", path), false, true, true, false, true); err != nil {
		t.Fatal(err)
	}
	fd := actorFD(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := svc.Delete(ctx, "pending"); err == nil {
		t.Fatal("cancelled cleanup reported success")
	}
	if _, exists := svc.sessions.Get("pending"); !exists {
		t.Fatal("failed cleanup lost its owner")
	}
	if _, err := svc.Execute("pending", "late", "true", true, true, true, false); err == nil {
		t.Fatal("cancelling scope accepted new work")
	}
	if err := svc.Delete(context.Background(), "pending"); err != nil {
		t.Fatal(err)
	}
	if !fdTerminated(t, fd, 0) {
		t.Fatal("retry success retained the actor")
	}
}

func TestLostSupervisorNeverConfirmsDeletion(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "lost")
	owned, _ := svc.sessions.Get("lost")
	if err := owned.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-owned.scope.done
	if err := svc.Delete(context.Background(), "lost"); err == nil {
		t.Fatal("lost supervisor was treated as a settled scope")
	}
	if _, exists := svc.sessions.Get("lost"); !exists {
		t.Fatal("lost scope custody was discarded")
	}
}

func TestRetainedDirectoryIsNotProofOfAbsentScope(t *testing.T) {
	svc := newStdinTestService(t)
	path := (&session{id: "old-owner"}).Dir(svc.configDir)
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(context.Background(), "old-owner"); err == nil || !strings.Contains(err.Error(), "custody is unavailable") {
		t.Fatalf("lost ownership was reported as absent: %v", err)
	}
}

func TestConcurrentCreateHasOneSessionOwner(t *testing.T) {
	svc := newStdinTestService(t)
	var successes atomic.Int32
	var workers sync.WaitGroup
	for range 12 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if svc.Create("one-owner", false) == nil {
				successes.Add(1)
			}
		}()
	}
	workers.Wait()
	if successes.Load() != 1 || svc.sessions.Count() != 1 {
		t.Fatalf("multiple owners created: %d", successes.Load())
	}
	if err := svc.Delete(context.Background(), "one-owner"); err != nil {
		t.Fatal(err)
	}
}

func TestReusableSessionPreservesShellState(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "reusable")
	if _, err := svc.Execute("reusable", "set", "export CUSTODY_TEST_VALUE=retained", false, true, true, false); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Execute("reusable", "get", "printf '%s' \"$CUSTODY_TEST_VALUE\"", false, true, true, false)
	if err != nil || result.Output == nil || *result.Output != "retained\n" {
		t.Fatalf("shell state lost: %+v %v", result, err)
	}
	observed, err := svc.Get("reusable")
	if err != nil || observed.ProcessScope != "running" || observed.InputClosed {
		t.Fatalf("reusable session was implicitly retired: %+v %v", observed, err)
	}
}

func TestFailedShellStartupSettlesWithoutForgettingCustody(t *testing.T) {
	scope, err := startProcessScope("/does-not-exist/daytona-shell", "", 100*time.Millisecond, 10*time.Millisecond)
	if err == nil || scope == nil {
		t.Fatalf("startup failure not reported: %+v %v", scope, err)
	}
	scope.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := scope.awaitSettlement(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBackgroundWorkCanSettleNaturallyWithoutCancellation(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "natural-background")
	result, err := svc.Execute("natural-background", "start", "sleep 1 </dev/null >/dev/null 2>&1 &", false, true, true, false, true)
	if err != nil || result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatalf("start failed: %+v %v", result, err)
	}
	owned, _ := svc.sessions.Get("natural-background")
	if owned.scope.state() != "running" {
		t.Fatal("background work was killed on main exit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := owned.scope.awaitSettlement(ctx); err != nil {
		t.Fatal(err)
	}
}
