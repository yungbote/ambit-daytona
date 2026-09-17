// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"log/slog"
	"time"

	"github.com/daytonaio/daemon/pkg/session"
)

// The workspace image installs the browser driver at a fixed path and gives it
// one socket directory, and a browser control channel pings its peer on a
// fixed interval. They are controller state rather than constants so a test
// can observe a real driver process outside the image layout, or a peer that
// stops answering, without waiting on production values; the daemon itself
// never changes them.
const (
	DefaultBrowserSocketDir    = "/workspace/.ambit/browser/sockets"
	DefaultBrowserExecutable   = "/opt/ambit/browser/bin/agent-browser"
	DefaultBrowserPingInterval = 15 * time.Second
)

type SessionController struct {
	logger              *slog.Logger
	configDir           string
	sessionService      *session.SessionService
	browserSocketDir    string
	browserExecutable   string
	browserPingInterval time.Duration
}

func NewSessionController(logger *slog.Logger, configDir string, sessionService *session.SessionService) *SessionController {
	return &SessionController{
		logger:              logger.With(slog.String("component", "session_controller")),
		configDir:           configDir,
		sessionService:      sessionService,
		browserSocketDir:    DefaultBrowserSocketDir,
		browserExecutable:   DefaultBrowserExecutable,
		browserPingInterval: DefaultBrowserPingInterval,
	}
}
