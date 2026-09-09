// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daytonaio/daemon/pkg/childreap"
)

type scopeResult struct {
	settled bool
	err     error
}

type processScope struct {
	cmd         *exec.Cmd
	input       io.WriteCloser
	control     *os.File
	stop        sync.Once
	inputClosed atomic.Bool
	shellExited atomic.Bool
	done        chan struct{}
	result      scopeResult // Published by closing done, then immutable.
}

func startProcessScope(ctx context.Context, shell, dir string, grace, interval time.Duration) (*processScope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd := supervisorCommand(grace, interval, shell)
	if cmd == nil {
		return nil, errors.New("session descendant custody requires the Linux daemon runtime")
	}
	cmd.Dir, cmd.Env = dir, os.Environ()
	inputRead, input, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer inputRead.Close()
	cmd.Stdin = inputRead
	controlRead, controlWrite, err := os.Pipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		input.Close()
		controlRead.Close()
		controlWrite.Close()
		return nil, err
	}
	cmd.ExtraFiles = []*os.File{controlRead, statusWrite}
	if err := cmd.Start(); err != nil {
		input.Close()
		controlRead.Close()
		controlWrite.Close()
		statusRead.Close()
		statusWrite.Close()
		return nil, err
	}
	inputRead.Close()
	controlRead.Close()
	statusWrite.Close()
	scope := &processScope{cmd: cmd, input: input, control: controlWrite, done: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			scope.cancel()
		case <-scope.done:
		}
	}()
	ready := make(chan error, 1)
	observed := make(chan scopeResult, 1)
	go func() {
		defer statusRead.Close()
		scanner := bufio.NewScanner(statusRead)
		scanner.Buffer(make([]byte, 1024), 4096)
		readySent := false
		result := scopeResult{}
		for scanner.Scan() {
			switch line := scanner.Text(); {
			case line == "ready" && !readySent:
				ready <- nil
				readySent = true
			case line == "input_closed":
				scope.shellExited.Store(true)
				scope.inputClosed.Store(true)
			case line == "settled":
				result.settled = true
			case strings.HasPrefix(line, "error "):
				result.err = errors.New(strings.TrimPrefix(line, "error "))
			default:
				result.err = errors.New("invalid session supervisor observation")
			}
		}
		result.err = errors.Join(result.err, scanner.Err())
		if !readySent {
			ready <- errors.Join(errors.New("session supervisor did not confirm startup"), result.err)
		}
		observed <- result
	}()
	go func() {
		code, waitErr := childreap.Reap(cmd)
		result := <-observed
		if !result.settled {
			result.err = errors.Join(result.err, waitErr, fmt.Errorf("session process scope stopped without settlement (exit %d)", code))
		} else if waitErr != nil {
			result.settled = false
			result.err = errors.Join(result.err, waitErr)
		}
		scope.result = result
		scope.cancel()
		close(scope.done)
	}()
	select {
	case err := <-ready:
		return scope, err
	case <-time.After(10 * time.Second):
		return scope, errors.New("session supervisor startup timed out")
	}
}

func (scope *processScope) cancel() {
	scope.stop.Do(func() {
		// EOF is the lifetime signal. Children never inherit this descriptor;
		// the same signal is delivered automatically when the daemon dies.
		_ = scope.control.Close()
		_ = scope.closeInput()
	})
}

func (scope *processScope) awaitSettlement(ctx context.Context) error {
	select {
	case <-scope.done:
		if scope.result.settled {
			return nil
		}
		return scope.result.err
	case <-ctx.Done():
		return fmt.Errorf("session process cleanup remains pending: %w", ctx.Err())
	}
}

func (scope *processScope) state() string {
	select {
	case <-scope.done:
		if scope.result.settled {
			return "settled"
		}
		return "unavailable"
	default:
		return "running"
	}
}

func (scope *processScope) closeInput() error {
	scope.inputClosed.Store(true)
	return scope.input.Close()
}
