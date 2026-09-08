// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"context"
	"errors"
	"fmt"
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
		_, err := os.Lstat((&session{id: sessionID}).Dir(s.configDir))
		if err == nil || !os.IsNotExist(err) {
			return fmt.Errorf("session process custody is unavailable; retained session state requires workspace reconciliation")
		}
		return common_errors.NewNotFoundError(errors.New("session not found"))
	}
	owned.mu.Lock()
	defer owned.mu.Unlock()
	if current, exists := s.sessions.Get(sessionID); !exists || current != owned {
		return common_errors.NewConflictError(errors.New("session owner changed before deletion"))
	}
	owned.stopping = true
	owned.inputClosed = true
	owned.cancel()
	if owned.scope == nil {
		return errors.New("session process custody is unavailable")
	}
	owned.scope.cancel()
	waitCtx, cancel := context.WithTimeout(ctx, s.terminationGracePeriod+2*time.Second)
	defer cancel()
	if err := owned.scope.awaitSettlement(waitCtx); err != nil {
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
