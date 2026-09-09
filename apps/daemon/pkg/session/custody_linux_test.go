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
	"runtime/debug"
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
	case "fd-pressure":
		previousGC := debug.SetGCPercent(-1)
		defer debug.SetGCPercent(previousGC)
		r, w, err := os.Pipe()
		if err != nil {
			panic(err)
		}
		r.Close()
		w.Close()
		count := func() int {
			entries, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				panic(err)
			}
			return len(entries) - 1
		}
		before := count()
		var original unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
			panic(err)
		}
		limited := original
		limited.Cur = 64
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limited); err != nil {
			panic(err)
		}
		var filler []int
		for {
			fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if errors.Is(err, unix.EMFILE) {
				break
			}
			if err != nil {
				panic(err)
			}
			filler = append(filler, fd)
		}
		for range 3 {
			unix.Close(filler[len(filler)-1])
			filler = filler[:len(filler)-1]
		}
		scope, startErr := startProcessScope(context.Background(), "sh", "", 100*time.Millisecond, 10*time.Millisecond)
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
			panic(err)
		}
		for _, fd := range filler {
			unix.Close(fd)
		}
		after := count()
		if scope != nil || startErr == nil || !strings.Contains(startErr.Error(), "too many open files") || after != before {
			panic(fmt.Sprintf("unexpected startup/FD custody: scope=%v error=%v before=%d after=%d", scope, startErr, before, after))
		}
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
	fd, err := unix.PidfdOpen(owned.scope.Load().cmd.Process.Pid, 0)
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
	if err := owned.scope.Load().awaitSettlement(ctx); err != nil {
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
	if err := owned.scope.Load().cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-owned.scope.Load().done
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
	if err := svc.Create("old-owner", false); err == nil {
		t.Fatal("a new scope replaced retained unresolved custody")
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
	scope, err := startProcessScope(context.Background(), "/does-not-exist/daytona-shell", "", 100*time.Millisecond, 10*time.Millisecond)
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
	if owned.scope.Load().state() != "running" {
		t.Fatal("background work was killed on main exit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := owned.scope.Load().awaitSettlement(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBlockedSubmissionDoesNotBlockObservationOrCancellation(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "backpressure")
	if _, err := svc.Execute("backpressure", "hold", "sleep 3", true, true, true, false); err != nil {
		t.Fatal(err)
	}
	queued := make(chan struct{})
	go func() {
		defer close(queued)
		for i := range 64 {
			if _, err := svc.Execute("backpressure", fmt.Sprint(i), "true", true, true, true, false); err != nil {
				return
			}
		}
	}()
	time.Sleep(250 * time.Millisecond)
	observation := make(chan error, 1)
	go func() { _, err := svc.Get("backpressure"); observation <- err }()
	select {
	case err := <-observation:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("observation blocked behind a full command pipe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- svc.Delete(ctx, "backpressure") }()
	select {
	case firstErr := <-stopped:
		if firstErr != nil {
			if !errors.Is(firstErr, context.DeadlineExceeded) {
				t.Fatal(firstErr)
			}
			if err := svc.Delete(context.Background(), "backpressure"); err != nil {
				t.Fatal(err)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation could not reach the blocked command pipe")
	}
	select {
	case <-queued:
	case <-time.After(time.Second):
		t.Fatal("queued command writer did not unblock")
	}
}

func TestExitedShellClosesIntakeWhileRetainingBackgroundWork(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "shell-exits")
	if _, err := svc.Execute("shell-exits", "main", "sleep 2 </dev/null >/dev/null 2>&1 & exit 0", true, true, true, false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	var observed *Session
	for time.Now().Before(deadline) {
		var err error
		observed, err = svc.Get("shell-exits")
		if err != nil {
			t.Fatal(err)
		}
		if observed.InputClosed {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if observed == nil || !observed.InputClosed || observed.ProcessScope != "running" {
		t.Fatalf("shell lifetime confused with descendant lifetime: %+v", observed)
	}
	if _, err := svc.Execute("shell-exits", "late", "true", true, true, true, false); err == nil {
		t.Fatal("dead shell falsely accepted another command")
	}
}

func TestFailedPipeAllocationClosesEveryOwnedDescriptor(t *testing.T) {
	child := exec.Command("/proc/self/exe", "--custody-fixture", "fd-pressure", "unused")
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("isolated descriptor-pressure check: %v: %s", err, output)
	}
}

func TestTrustedEntrypointKeepsSnapshotLogsWithoutReusingOrdinaryCustody(t *testing.T) {
	svc := newStdinTestService(t)
	path := filepath.Join(svc.configDir, "sessions", "entrypoint", "retained.log")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("snapshot log"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateEntrypoint(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Delete(context.Background(), "entrypoint") })
	if content, err := os.ReadFile(path); err != nil || string(content) != "snapshot log" {
		t.Fatalf("trusted startup discarded logs: %q %v", content, err)
	}
}

func TestClosingCommandInputPreservesInteractiveTaskInput(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "closed-stream-interactive")
	result, err := svc.Execute("closed-stream-interactive", "read", `read -r answer; printf 'answer:%s\n' "$answer"`, true, true, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.InputClosed || result.ProcessScope != "running" {
		t.Fatalf("missing accepted scope receipt: %+v", result)
	}
	pipe := filepath.Join(svc.configDir, "sessions", "closed-stream-interactive", "read", "input.pipe")
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(pipe); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("accepted command did not prepare interactive input")
		}
		time.Sleep(time.Millisecond)
	}
	if err := svc.SendInput(context.Background(), "closed-stream-interactive", "read", "hello"); err != nil {
		t.Fatal(err)
	}
	command := pollCommand(t, svc, "closed-stream-interactive", "read", time.Second)
	if command.ExitCode == nil || *command.ExitCode != 0 {
		t.Fatalf("interactive command failed: %+v", command)
	}
	owned, _ := svc.sessions.Get("closed-stream-interactive")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := owned.scope.Load().awaitSettlement(ctx); err != nil {
		t.Fatal(err)
	}
	logPath, _ := command.LogFilePath(owned.Dir(svc.configDir))
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	stdout, _ := DemuxLogBytes(content)
	if !strings.Contains(string(stdout), "answer:hello\n") {
		t.Fatalf("interactive result missing: %q", stdout)
	}

}

func TestInputWithoutReaderEndsWhenSessionIsDeleted(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "input-reader-closed")
	marker := filepath.Join(t.TempDir(), "stdin-closed")
	script := "exec 0</dev/null; printf ready > " + shellFixtureQuote(marker) + "; sleep 20"
	if _, err := svc.Execute("input-reader-closed", "main", script, true, true, true, false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("command did not close stdin")
		}
		time.Sleep(time.Millisecond)
	}
	sent := make(chan error, 1)
	go func() { sent <- svc.SendInput(context.Background(), "input-reader-closed", "main", "late-input") }()
	select {
	case err := <-sent:
		if err == nil {
			t.Fatal("input succeeded without a reader")
		}
	case <-time.After(50 * time.Millisecond):
		if err := svc.Delete(context.Background(), "input-reader-closed"); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-sent:
			if err == nil {
				t.Fatal("input succeeded after deletion")
			}
		case <-time.After(time.Second):
			t.Fatal("input remained blocked after deletion")
		}
	}
}

func TestBlockedInputWriteHonorsRequestCancellation(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "blocked-input-write")
	if _, err := svc.Execute("blocked-input-write", "main", "sleep 20", true, true, true, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	sent := make(chan error, 1)
	go func() { sent <- svc.SendInput(ctx, "blocked-input-write", "main", strings.Repeat("x", 1024*1024)) }()
	select {
	case err := <-sent:
		if err == nil {
			t.Fatal("input delivery succeeded without a consuming reader")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked input write ignored request cancellation")
	}
	observed, err := svc.Get("blocked-input-write")
	if err != nil || observed.ProcessScope != "running" {
		t.Fatalf("canceling input changed process custody: observation=%+v error=%v", observed, err)
	}
}

func TestSynchronousShellExitRetainsBackgroundWithoutWaitingForAResult(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "sync-shell-exit")
	result := make(chan error, 1)
	go func() {
		_, err := svc.Execute("sync-shell-exit", "main", "sleep 20 </dev/null >/dev/null 2>&1 & exit 7", false, true, true, false)
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "shell ended without a command result") {
			t.Fatalf("unexpected shell-exit result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("synchronous call waited for a result after its shell exited")
	}
	observed, err := svc.Get("sync-shell-exit")
	if err != nil || !observed.InputClosed || observed.ProcessScope != "running" {
		t.Fatalf("shell exit lost background custody: observation=%+v error=%v", observed, err)
	}
}

func TestInteractiveInputProgressesBehindQueuedCommandBackpressure(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "review-queued-input")
	if _, err := svc.Execute("review-queued-input", "active", "read -r answer; printf '%s' \"$answer\"", true, true, true, true); err != nil {
		t.Fatal(err)
	}
	owned, _ := svc.sessions.Get("review-queued-input")
	queued := make(chan struct{})
	go func() {
		defer close(queued)
		for i := range 64 {
			if _, err := svc.Execute("review-queued-input", fmt.Sprintf("queued-%d", i), "true", true, true, true, false); err != nil {
				return
			}
		}
	}()
	time.Sleep(250 * time.Millisecond)
	if owned.mu.TryLock() {
		owned.mu.Unlock()
		t.Fatal("fixture did not reach blocked command submission")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	input := make(chan error, 1)
	go func() { input <- svc.SendInput(ctx, "review-queued-input", "active", "hello") }()
	select {
	case err := <-input:
		if err != nil {
			t.Fatalf("interactive input failed behind queued commands: %v", err)
		}
		pollCommand(t, svc, "review-queued-input", "active", time.Second)
	case <-time.After(750 * time.Millisecond):
		t.Errorf("SendInput is deadlocked behind queued command submission and ignored its request deadline")
	}
	if err := svc.Delete(context.Background(), "review-queued-input"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-queued:
	case <-time.After(time.Second):
		t.Error("queued submission did not stop")
	}
}
