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

	owned.mu.Lock()
	defer owned.mu.Unlock()
	if current, exists := s.sessions.Get(sessionId); !exists || current != owned {
		return nil, common_errors.NewConflictError(errors.New("session owner changed during observation"))
	}
	commands, err := s.getSessionCommands(sessionId)
	if err != nil {
		return nil, err
	}

	scopeState := "unavailable"
	if owned.scope != nil {
		scopeState = owned.scope.state()
	}
	return &Session{
		SessionId:    sessionId,
		ProcessScope: scopeState,
		InputClosed:  owned.inputClosed || owned.stopping || scopeState != "running",
		Commands:     commands,
	}, nil
}
