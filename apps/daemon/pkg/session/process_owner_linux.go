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
	SessionID string
}

var ErrProcessCustodyEnded = errors.New("session process custody ended")
var ErrProcessNotOwned = errors.New("process is outside the native session")

// ObserveOwnedProcess attributes a process to the existing native session
// supervisor. Browser adapters use this custody check; filenames and command
// text do not establish process ownership.
func (s *SessionService) ObserveOwnedProcess(sessionID string, pid int) (OwnedProcess, error) {
	owned, exists := s.sessions.Get(sessionID)
	if !exists || owned.ctx.Err() != nil {
		return OwnedProcess{}, ErrProcessCustodyEnded
	}
	// Custody has exactly three answers: this session owns the process, it does
	// not, or its custody has ended. A session state that cannot own anything is
	// one of the two negative answers, never an opaque failure to observe: a
	// workspace-wide lookup joins those, and a live stream reads an unclassified
	// error as a transport fault rather than the end of the browser.
	scope := owned.scope.Load()
	switch {
	case scope == nil || scope.cmd.Process == nil:
		// The owner is registered while its supervisor starts. Custody has not
		// begun, so this session owns no process yet.
		return OwnedProcess{}, ErrProcessNotOwned
	case scope.state() != "running":
		// "settled" is a clean shell exit and "unavailable" an unclean one.
		// Both end this session's custody of everything it started.
		return OwnedProcess{}, ErrProcessCustodyEnded
	}
	root := scope.cmd.Process
	identity := OwnedProcess{PID: pid, SessionID: sessionID}
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
	return OwnedProcess{}, ErrProcessNotOwned
}

// FindProcessSession resolves a native owner without hydrating command logs or
// opening a second process registry. All candidates are the existing owners.
//
// Each session answers only for itself. A session that cannot be observed is
// therefore not an answer about the process, and the result stays not-owned so
// one unobservable owner never masks another owner's process. The reason is
// still carried, so a caller that wants it can report why the answer is partial.
func (s *SessionService) FindProcessSession(pid int) (OwnedProcess, error) {
	var unresolved error
	for _, id := range s.sessions.Keys() {
		identity, err := s.ObserveOwnedProcess(id, pid)
		if err == nil {
			return identity, nil
		}
		if !errors.Is(err, ErrProcessNotOwned) && !errors.Is(err, ErrProcessCustodyEnded) {
			unresolved = errors.Join(unresolved, err)
		}
	}
	if unresolved != nil {
		return OwnedProcess{}, fmt.Errorf("%w: %w", ErrProcessNotOwned, unresolved)
	}
	return OwnedProcess{}, ErrProcessNotOwned
}
