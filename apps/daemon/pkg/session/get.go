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

	if current, exists := s.sessions.Get(sessionId); !exists || current != owned {
		return nil, common_errors.NewConflictError(errors.New("session owner changed during observation"))
	}
	commands, err := s.getSessionCommandsFor(owned)
	if err != nil {
		return nil, err
	}

	if current, exists := s.sessions.Get(sessionId); !exists || current != owned {
		return nil, common_errors.NewConflictError(errors.New("session owner changed during observation"))
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
