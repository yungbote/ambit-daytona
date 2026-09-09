// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"errors"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/daytonaio/daemon/internal/util"
)

func (s *SessionService) List() ([]Session, error) {
	return s.list(s.sessions.Keys())
}

// list observes an exact key snapshot. A session deleted or replaced while the
// snapshot is walked was never part of this listing, so it is skipped: one
// caller retiring its own session must not turn every other caller's listing
// into a conflict. Any other failure is still reported.
func (s *SessionService) list(ids []string) ([]Session, error) {
	sessions := []Session{}

	for _, sessionId := range ids {
		if sessionId == util.EntrypointSessionID {
			continue
		}

		observed, err := s.Get(sessionId)
		if err != nil {
			var absent *common_errors.NotFoundError
			var replaced *common_errors.ConflictError
			if errors.As(err, &absent) || errors.As(err, &replaced) {
				continue
			}
			return nil, err
		}
		sessions = append(sessions, *observed)
	}

	return sessions, nil
}
