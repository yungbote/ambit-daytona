// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/daytonaio/daemon/pkg/common"
	cmap "github.com/orcaman/concurrent-map/v2"
)

func validSessionID(id string) bool {
	return id != "" && id != "." && id != ".." && filepath.Base(id) == id && !strings.ContainsAny(id, "/\\\x00")
}

func (s *SessionService) Create(sessionID string, isLegacy bool) error {
	if !validSessionID(sessionID) {
		return common_errors.NewBadRequestError(errors.New("invalid session ID"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	owned := &session{id: sessionID, commands: cmap.New[*Command](), ctx: ctx, cancel: cancel}
	owned.mu.Lock()
	defer owned.mu.Unlock()
	if !s.sessions.SetIfAbsent(sessionID, owned) {
		cancel()
		return common_errors.NewConflictError(errors.New("session already exists"))
	}
	removeReservation := func() {
		s.sessions.RemoveCb(sessionID, func(_ string, current *session, exists bool) bool { return exists && current == owned })
		cancel()
	}
	// Keep the existing session directory/log layout, including entrypoint
	// state carried by snapshots. The in-memory owner reservation is atomic.
	if err := os.MkdirAll(owned.Dir(s.configDir), 0755); err != nil {
		removeReservation()
		return err
	}

	dir := ""
	if isLegacy {
		var err error
		dir, err = os.UserHomeDir()
		if err != nil {
			_ = os.Remove(owned.Dir(s.configDir))
			removeReservation()
			return err
		}
	}
	scope, err := startProcessScope(common.GetShell(), dir, s.terminationGracePeriod, s.terminationCheckInterval)
	owned.scope = scope
	if scope != nil {
		owned.cmd, owned.stdinWriter = scope.cmd, scope.input
	}
	if err != nil {
		owned.stopping = true
		if scope != nil {
			scope.cancel()
			cleanupCtx, stop := context.WithTimeout(context.Background(), s.terminationGracePeriod+2*time.Second)
			cleanupErr := scope.awaitSettlement(cleanupCtx)
			stop()
			if cleanupErr != nil {
				return errors.Join(err, cleanupErr)
			}
		}
		_ = os.Remove(owned.Dir(s.configDir))
		removeReservation()
		return err
	}
	return nil
}
