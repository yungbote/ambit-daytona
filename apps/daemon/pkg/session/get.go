// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"errors"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
)

func (s *SessionService) Get(sessionId string) (*Session, error) {
	owned, ok := s.sessions.Get(sessionId)
	if !ok {
		return nil, common_errors.NewNotFoundError(errors.New("session not found"))
	}

	if err := s.stillOwned(sessionId, owned); err != nil {
		return nil, err
	}
	commands, err := s.getSessionCommandsFor(owned)
	if err != nil {
		return nil, err
	}

	if err := s.stillOwned(sessionId, owned); err != nil {
		return nil, err
	}

	scopeState := "unavailable"
	scope := owned.scope.Load()
	if scope != nil {
		scopeState = scope.state()
	}
	return &Session{
		SessionId:    sessionId,
		ProcessScope: scopeState,
		InputClosed:  owned.ctx.Err() != nil || scope == nil || scope.inputClosed.Load(),
		Commands:     commands,
	}, nil
}

// stillOwned reports why an observation cannot be attributed to this owner. A
// session retired during the observation is absent, not a conflict over an
// owner that still exists; only a different owner is a conflict.
func (s *SessionService) stillOwned(sessionId string, owned *session) error {
	current, exists := s.sessions.Get(sessionId)
	if !exists {
		return common_errors.NewNotFoundError(errors.New("session not found"))
	}
	if current != owned {
		return common_errors.NewConflictError(errors.New("session owner changed during observation"))
	}
	return nil
}
