// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// OwnedProcess identifies a currently observed descendant, including its kernel
// start time so a reused PID never preserves an old view's identity.
type OwnedProcess struct {
	PID       int
	StartTime string
}

var ErrProcessCustodyEnded = errors.New("session process custody ended")

// ObserveOwnedProcess attributes a process to the existing native session
// supervisor. Browser adapters use this custody check; filenames and command
// text do not establish process ownership.
func (s *SessionService) ObserveOwnedProcess(sessionID string, pid int) (OwnedProcess, error) {
	owned, exists := s.sessions.Get(sessionID)
	if !exists || owned.ctx.Err() != nil {
		return OwnedProcess{}, ErrProcessCustodyEnded
	}
	scope := owned.scope.Load()
	if scope != nil && scope.state() == "settled" {
		return OwnedProcess{}, ErrProcessCustodyEnded
	}
	if scope == nil || scope.state() != "running" || scope.cmd.Process == nil {
		return OwnedProcess{}, errors.New("session process custody is unavailable")
	}
	root := scope.cmd.Process
	identity := OwnedProcess{PID: pid}
	visited := map[int]bool{}
	for current := pid; current > 1 && !visited[current]; {
		visited[current] = true
		if current == root.Pid {
			// os.Process retains the kernel process handle. Signal(0) checks that
			// handle rather than treating a recycled numeric PID as this owner.
			if err := root.Signal(syscall.Signal(0)); err != nil {
				if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
					return OwnedProcess{}, ErrProcessCustodyEnded
				}
				return OwnedProcess{}, err
			}
			if owned.ctx.Err() != nil {
				return OwnedProcess{}, ErrProcessCustodyEnded
			}
			if err := s.stillOwned(sessionID, owned); err != nil {
				return OwnedProcess{}, errors.New("session process custody changed")
			}
			return identity, nil
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", current))
		if err != nil {
			return OwnedProcess{}, err
		}
		closeParen := strings.LastIndexByte(string(stat), ')')
		if closeParen < 0 {
			return OwnedProcess{}, errors.New("invalid kernel process identity")
		}
		fields := strings.Fields(string(stat[closeParen+1:]))
		if len(fields) < 20 {
			return OwnedProcess{}, errors.New("incomplete kernel process identity")
		}
		if current == pid {
			identity.StartTime = fields[19]
		}
		current, err = strconv.Atoi(fields[1])
		if err != nil {
			return OwnedProcess{}, err
		}
	}
	return OwnedProcess{}, errors.New("process is outside the native session")
}
