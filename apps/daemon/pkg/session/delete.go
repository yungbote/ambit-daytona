// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"context"
	"errors"
	"os"
	"time"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
)

func (s *SessionService) Delete(ctx context.Context, sessionID string) error {
	if !validSessionID(sessionID) {
		return common_errors.NewBadRequestError(errors.New("invalid session ID"))
	}
	owned, ok := s.sessions.Get(sessionID)
	if !ok {
		// No owner means no live scope: an owner is installed before its scope
		// starts and removed only after the scope settles. Anything still on
		// disk is unreachable output of custody that is gone, so this sweeps it
		// and reports the absence the caller asked about. Deletion converges;
		// it never leaves state a later Create would conflict with.
		if err := os.RemoveAll((&session{id: sessionID}).Dir(s.configDir)); err != nil {
			return common_errors.NewBadRequestError(err)
		}
		return common_errors.NewNotFoundError(errors.New("session not found"))
	}
	// Cancel before waiting for the lifecycle lock: a queued command may be
	// blocked writing to the shell pipe while holding it. The existing context
	// closes that pipe independently and unblocks the writer.
	owned.cancel()
	owned.mu.Lock()
	defer owned.mu.Unlock()
	if current, exists := s.sessions.Get(sessionID); !exists || current != owned {
		return common_errors.NewConflictError(errors.New("session owner changed before deletion"))
	}
	scope := owned.scope.Load()
	if scope == nil {
		return errors.New("session process custody is unavailable")
	}
	scope.cancel()
	waitCtx, cancel := context.WithTimeout(ctx, s.terminationGracePeriod+2*time.Second)
	defer cancel()
	if err := scope.awaitSettlement(waitCtx); err != nil {
		// The same owner and its output remain available for observation/retry.
		// A transport timeout never turns failed termination into a deletion.
		return err
	}
	if err := os.RemoveAll(owned.Dir(s.configDir)); err != nil {
		return common_errors.NewBadRequestError(err)
	}
	s.sessions.RemoveCb(sessionID, func(_ string, current *session, exists bool) bool { return exists && current == owned })
	return nil
}
