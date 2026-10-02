// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	commonerrors "github.com/daytonaio/common-go/pkg/errors"
	nativesession "github.com/daytonaio/daemon/pkg/session"
	"github.com/gin-gonic/gin"
)

// Runs the real SessionController/supervisor inside a task-owned container.
// This is a qualification fixture, not an alternate Product/provider server.
// Only the backend harness holds its task token; CODE gets a scoped relay.
func runBrowserProgramHostFixture(args []string) bool {
	if len(args) != 1 || args[0] != "--real-browser-program-host" {
		return false
	}
	credential := os.Getenv("AMBIT_PROGRAM_FIXTURE_TOKEN")
	driver := os.Getenv("AMBIT_PROGRAM_FIXTURE_DRIVER")
	sockets := os.Getenv("AGENT_BROWSER_SOCKET_DIR")
	if credential == "" || !filepath.IsAbs(driver) || !filepath.IsAbs(sockets) {
		panic("missing task-owned programme fixture binding")
	}
	directory := "/tmp/ambit-program-host-fixture"
	if os.MkdirAll(directory, 0700) != nil {
		panic("programme fixture directory unavailable")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := nativesession.NewSessionService(logger, directory, 250*time.Millisecond, 25*time.Millisecond)
	if err != nil {
		panic("programme fixture supervisor unavailable")
	}
	controller := NewSessionController(logger, directory, service)
	controller.browserExecutable = driver
	controller.browserSocketDir = sockets
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(commonerrors.NewErrorMiddleware(func(_ *gin.Context, err error) commonerrors.ErrorResponse {
		return commonerrors.ErrorResponse{StatusCode: http.StatusInternalServerError, Message: strings.ReplaceAll(err.Error(), credential, "[task credential]")}
	}, false))
	engine.Use(func(c *gin.Context) {
		if c.GetHeader("Authorization") != "Bearer "+credential {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	})
	engine.GET("/health", func(c *gin.Context) { c.Status(http.StatusOK) })
	process := engine.Group("/process")
	process.GET("/browser-views", controller.ListBrowserViews)
	sessions := process.Group("/session")
	sessions.POST("", controller.CreateSession)
	sessions.GET("/:sessionId", controller.GetSession)
	sessions.DELETE("/:sessionId", controller.DeleteSession)
	sessions.POST("/:sessionId/exec", controller.SessionExecuteCommand)
	sessions.GET("/:sessionId/browser-views/:viewId/agent/channel", controller.AgentBrowserViewChannel)
	sessions.GET("/:sessionId/browser-views/:viewId/program/:programId/channel", controller.ProgramBrowserViewChannel)
	if http.ListenAndServe(":9099", engine) != nil {
		panic("programme fixture server ended")
	}
	return true
}
