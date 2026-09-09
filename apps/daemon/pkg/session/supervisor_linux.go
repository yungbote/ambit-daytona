// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const supervisorArgument = "--daytona-session-supervisor"

// RunSupervisor is an early daemon entry point, before the global child reaper.
// This process owns only one session's shell and adopted descendants. It never
// executes model work itself and exits successfully only after wait4 proves
// there are no children left, including double-forked and setsid descendants.
func RunSupervisor(args []string) (int, bool) {
	if len(args) == 0 || args[0] != supervisorArgument {
		return 0, false
	}
	if len(args) != 4 {
		return 2, true
	}
	control := os.NewFile(3, "session-control")
	status := os.NewFile(4, "session-status")
	if control == nil || status == nil {
		return 2, true
	}
	defer control.Close()
	defer status.Close()
	unix.CloseOnExec(3)
	unix.CloseOnExec(4)
	fail := func(err error) (int, bool) {
		_, _ = fmt.Fprintf(status, "error %s\n", strings.ReplaceAll(err.Error(), "\n", " "))
		if none, _, checkErr := reapScopeChildren(0); checkErr == nil && none {
			_, _ = fmt.Fprintln(status, "settled")
		}
		return 1, true
	}
	grace, err := time.ParseDuration(args[1])
	if err != nil || grace <= 0 {
		return fail(errors.New("invalid session termination grace period"))
	}
	interval, err := time.ParseDuration(args[2])
	if err != nil || interval <= 0 {
		return fail(errors.New("invalid session termination check interval"))
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return fail(fmt.Errorf("session child custody unavailable: %w", err))
	}
	// Do not expose the private status/control descriptors through procfs to
	// ordinary same-user children. This is not a cross-tenant security boundary.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fail(fmt.Errorf("session supervisor descriptor privacy unavailable: %w", err))
	}
	// Cancellation signals the children the kernel names. Enumeration treats a
	// missing children file as a thread that ended mid-scan, so on a kernel
	// without this interface every signal round would find nothing, report no
	// failure, and leave the scope running while cancellation looked healthy.
	// Prove the interface once, here, where refusing is still visible: the
	// scope never reaches "ready", so the session is never created and the
	// caller gets the reason instead of a scope it cannot cancel.
	if err := probeChildEnumeration(scopeTaskRoot, os.Getpid()); err != nil {
		return fail(err)
	}
	// Install a handled SIGCHLD disposition (not SIG_IGN/SA_NOCLDWAIT).
	// This loop is the only waiter, so an unreaped direct child's PID cannot
	// be recycled between enumeration and signaling, even if it has exited.
	childChanges := make(chan os.Signal, 1)
	signal.Notify(childChanges, syscall.SIGCHLD)
	defer signal.Stop(childChanges)
	parentGone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, control)
		close(parentGone)
	}()
	shell := exec.Command(args[3])
	shell.Stdin, shell.Stdout, shell.Stderr = os.Stdin, os.Stdout, os.Stderr
	shell.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := shell.Start(); err != nil {
		return fail(fmt.Errorf("session shell did not start: %w", err))
	}
	// The supervisor owns wait4 for every descendant; exec.Cmd.Wait must not
	// compete for this shell. No copying goroutines exist for *os.File streams.
	defer shell.Process.Release()
	// Only the actual shell may retain the command pipe reader. Otherwise a
	// dead shell with live descendants could appear to accept later commands.
	_ = os.Stdin.Close()
	_, _ = fmt.Fprintln(status, "ready")
	var ticker *time.Ticker
	var tick <-chan time.Time
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	var stoppingAt time.Time
	reportedFailure := false
	for {
		noChildren, shellExited, err := reapScopeChildren(shell.Process.Pid)
		if shellExited {
			_, _ = fmt.Fprintln(status, "input_closed")
		}
		if err != nil {
			if !reportedFailure {
				_, _ = fmt.Fprintf(status, "error child status unavailable: %v\n", err)
				reportedFailure = true
			}
		} else if noChildren {
			_, _ = fmt.Fprintln(status, "settled")
			return 0, true
		}
		if !stoppingAt.IsZero() {
			sig := unix.SIGTERM
			if time.Since(stoppingAt) >= grace {
				sig = unix.SIGKILL
			}
			if err := signalScopeChildren(sig); err != nil && !reportedFailure {
				_, _ = fmt.Fprintf(status, "error child termination pending: %v\n", err)
				reportedFailure = true
			}
		}
		select {
		case <-parentGone:
			if stoppingAt.IsZero() {
				stoppingAt = time.Now()
				ticker = time.NewTicker(interval)
				tick = ticker.C
			}
			// A nil channel keeps the loop responsive without spinning on EOF.
			parentGone = nil
		case <-childChanges:
		case <-tick:
		}
	}
}

func supervisorCommand(grace, interval time.Duration, shell string) *exec.Cmd {
	return exec.Command("/proc/self/exe", supervisorArgument, grace.String(), interval.String(), shell)
}

func reapScopeChildren(shellPID int) (bool, bool, error) {
	shellExited := false
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WNOHANG|unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) {
			return true, shellExited, nil
		}
		if err != nil {
			return false, shellExited, err
		}
		if pid == shellPID && (status.Exited() || status.Signaled()) {
			shellExited = true
		}
		if pid == 0 {
			return false, shellExited, nil
		}
	}
}

const scopeTaskRoot = "/proc/self/task"

// probeChildEnumeration proves the kernel exposes a thread's children before
// this scope owns any. The thread-group leader's task directory exists for the
// life of the process, so an error here names the interface, not a race.
func probeChildEnumeration(taskRoot string, pid int) error {
	if _, err := os.ReadFile(filepath.Join(taskRoot, strconv.Itoa(pid), "children")); err != nil {
		return fmt.Errorf("session descendant enumeration is unavailable, so this scope could not be cancelled: %w", err)
	}
	return nil
}

// Only direct children need signaling. When a parent exits, the kernel adopts
// its orphaned descendants into this subreaper, regardless of process groups.
// Repeating until ECHILD handles arbitrary ancestry without guessing a tree's
// historical membership. No other goroutine calls wait: every enumerated
// direct child retains its PID until the next reapScopeChildren call.
func signalScopeChildren(sig unix.Signal) error {
	threads, err := os.ReadDir(scopeTaskRoot)
	if err != nil {
		return err
	}
	var failures []error
	seen := make(map[int]bool)
	for _, thread := range threads {
		value, err := os.ReadFile(filepath.Join(scopeTaskRoot, thread.Name(), "children"))
		if os.IsNotExist(err) {
			// The interface itself was proven at startup, so this can only be
			// a Go runtime thread that ended during enumeration.
			continue
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for _, field := range strings.Fields(string(value)) {
			pid, err := strconv.Atoi(field)
			if err != nil || pid <= 0 {
				failures = append(failures, errors.New("invalid kernel child identity"))
				continue
			}
			if seen[pid] {
				continue
			}
			seen[pid] = true
			if err := signalScopeChild(pid, sig); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func signalScopeChild(pid int, sig unix.Signal) error {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return errors.New("child identity is incomplete")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 2 || fields[1] != strconv.Itoa(os.Getpid()) {
		return nil // The PID no longer names a direct child of this scope.
	}
	if err := unix.Kill(pid, sig); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}
