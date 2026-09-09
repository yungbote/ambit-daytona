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
	"github.com/daytonaio/daemon/internal/util"
	"github.com/daytonaio/daemon/pkg/common"
	cmap "github.com/orcaman/concurrent-map/v2"
)

func validSessionID(id string) bool {
	return id != "" && id != "." && id != ".." && filepath.Base(id) == id && !strings.ContainsAny(id, "/\\\x00")
}

func (s *SessionService) Create(sessionID string, isLegacy bool) error {
	return s.create(sessionID, isLegacy, false)
}

// CreateEntrypoint preserves the existing trusted daemon-startup owner and its
// snapshot-carried logs. The public API reserves this ID and cannot invoke it.
func (s *SessionService) CreateEntrypoint() error {
	return s.create(util.EntrypointSessionID, false, true)
}

func (s *SessionService) create(sessionID string, isLegacy, entrypoint bool) error {
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
	if err := os.MkdirAll(filepath.Dir(owned.Dir(s.configDir)), 0755); err != nil {
		removeReservation()
		return err
	}
	mkdir := os.Mkdir
	if entrypoint {
		mkdir = os.MkdirAll
	}
	if err := mkdir(owned.Dir(s.configDir), 0755); err != nil {
		if !os.IsExist(err) {
			removeReservation()
			return err
		}
		// This owner holds the ID, so no live scope can be behind that
		// directory: an owner is installed before its scope starts and removed
		// only after the scope settles. Retained state without an owner is the
		// same unreachable output startup reconciliation retires, so retiring
		// it here keeps a reused ID convergent instead of conflicting forever.
		s.logger.Info("retired retained session state without process custody", "session_id", sessionID)
		if err := os.RemoveAll(owned.Dir(s.configDir)); err != nil {
			removeReservation()
			return err
		}
		if err := mkdir(owned.Dir(s.configDir), 0755); err != nil {
			removeReservation()
			return err
		}
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
	scope, err := startProcessScope(ctx, common.GetShell(), dir, s.terminationGracePeriod, s.terminationCheckInterval)
	owned.scope.Store(scope)
	if err != nil {
		cancel()
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
