//go:build linux

package session

import (
	"io"
	"log/slog"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCredentialProcessFixtureIncludesProductionPTYRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := credentialProcessFixtureEngine(slog.New(slog.NewTextHandler(io.Discard, nil)), t.TempDir(), nil)
	routes := make(map[string]bool)
	for _, route := range engine.Routes() {
		routes[route.Method+" "+route.Path] = true
	}
	for _, expected := range []string{
		"GET /process/pty/create-connect",
		"GET /process/pty",
		"POST /process/pty",
		"GET /process/pty/:sessionId",
		"DELETE /process/pty/:sessionId",
		"GET /process/pty/:sessionId/connect",
		"POST /process/pty/:sessionId/resize",
		"POST /process/session/:sessionId/exec",
		"DELETE /process/session/:sessionId",
	} {
		if !routes[expected] {
			t.Errorf("the real native fixture is missing %s", expected)
		}
	}
}
