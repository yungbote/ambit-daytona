// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/daytonaio/daemon/internal/util"
	cmap "github.com/orcaman/concurrent-map/v2"
)

type SessionService struct {
	logger                   *slog.Logger
	configDir                string
	sessions                 cmap.ConcurrentMap[string, *session]
	terminationGracePeriod   time.Duration
	terminationCheckInterval time.Duration
}

// NewSessionService reconciles retained session state before serving, so a
// restarted daemon starts from session identities that are actually free.
func NewSessionService(logger *slog.Logger, configDir string, terminationGracePeriod, terminationCheckInterval time.Duration) (*SessionService, error) {
	if terminationGracePeriod <= 0 {
		terminationGracePeriod = 5 * time.Second
	}
	if terminationCheckInterval <= 0 {
		terminationCheckInterval = 25 * time.Millisecond
	}
	service := &SessionService{
		logger:                   logger.With(slog.String("component", "session_service")),
		configDir:                configDir,
		sessions:                 cmap.New[*session](),
		terminationGracePeriod:   terminationGracePeriod,
		terminationCheckInterval: terminationCheckInterval,
	}
	if err := service.reconcileRetainedSessions(); err != nil {
		return nil, err
	}
	return service, nil
}

func (s *SessionService) sessionsDir() string {
	return filepath.Join(s.configDir, "sessions")
}

// reconcileRetainedSessions retires session state that outlived the daemon
// that owned it.
//
// A session supervisor holds the read end of a lifetime pipe whose only writer
// is this daemon process. A daemon exit closes that writer, so every scope a
// previous daemon started is already terminating without anyone asking
// (TestDaemonParentDeathClosesDetachedScope). The map entry that could observe
// or delete such a session died with that daemon, and log reads, command
// results and deletion all require it: a retained directory found at startup
// is therefore unreachable output of custody that is gone, not custody.
//
// Retiring it here is what makes the session ID usable again. Leaving it made
// the ID permanently unconvergeable: Create failed with a conflict on the
// existing directory, Delete refused because it could not prove absence, and
// both repeated forever. The entrypoint is the one exception; it is a reserved
// ID whose snapshot-carried logs are read from disk by the daemon itself.
//
// This assumes one daemon per configuration directory, which the toolbox's
// single listening port already requires. Reconciliation removes retained
// state; it never signals a process, because a scope from a dead daemon has
// already been asked to terminate and this daemon holds no handle on it.
func (s *SessionService) reconcileRetainedSessions() error {
	entries, err := os.ReadDir(s.sessionsDir())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == util.EntrypointSessionID {
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.sessionsDir(), entry.Name())); err != nil {
			return err
		}
		s.logger.Info("retired retained session state without process custody", "session_id", entry.Name())
	}
	return nil
}
