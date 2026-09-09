// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/daytonaio/daemon/pkg/session"
	"github.com/gin-gonic/gin"
)

// TestMain also serves the session supervisor: a session scope re-executes
// /proc/self/exe, which is this test binary.
func TestMain(m *testing.M) {
	if code, handled := session.RunSupervisor(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// router builds the real session routes behind the real error middleware, so a
// status code here is the status code a client receives.
func router(t *testing.T, configDir string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := session.NewSessionService(logger, configDir, 250*time.Millisecond, 25*time.Millisecond)
	if err != nil {
		t.Fatalf("new session service: %v", err)
	}
	engine := gin.New()
	engine.Use(common_errors.NewErrorMiddleware(func(ctx *gin.Context, err error) common_errors.ErrorResponse {
		return common_errors.ErrorResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}, false))
	controller := NewSessionController(logger, configDir, service)
	sessions := engine.Group("/process/session")
	sessions.GET("", controller.ListSessions)
	sessions.POST("", controller.CreateSession)
	sessions.GET("/:sessionId", controller.GetSession)
	sessions.DELETE("/:sessionId", controller.DeleteSession)
	sessions.POST("/:sessionId/exec", controller.SessionExecuteCommand)
	return engine
}

func call(t *testing.T, engine *gin.Engine, method, target string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, target, reader)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	return recorder.Code, recorder.Body.Bytes()
}

// retain seeds exactly what a daemon leaves behind when it dies mid-session.
func retain(t *testing.T, configDir, sessionID string) string {
	t.Helper()
	dir := filepath.Join(configDir, "sessions", sessionID, "cmd-1")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "output.log"), []byte("previous life"), 0600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(configDir, "sessions", sessionID)
}

// A restarted daemon must expose retained state as absent and free its ID for
// reuse. Holding it made the reachable production arm — a start that reuses a
// previously used session ID — fail with 409 forever.
func TestRestartedDaemonServesReusableSessionIdentities(t *testing.T) {
	configDir := t.TempDir()
	retained := retain(t, configDir, "hp-build")
	engine := router(t, configDir)

	if _, err := os.Lstat(retained); !os.IsNotExist(err) {
		t.Fatalf("restart kept unreachable retained state: %v", err)
	}
	if code, body := call(t, engine, http.MethodGet, "/process/session/hp-build", nil); code != http.StatusNotFound {
		t.Fatalf("GET after restart = %d %s, want 404", code, body)
	}
	code, body := call(t, engine, http.MethodGet, "/process/session", nil)
	if code != http.StatusOK || string(bytes.TrimSpace(body)) != "[]" {
		t.Fatalf("LIST after restart = %d %s, want 200 []", code, body)
	}
	if code, body := call(t, engine, http.MethodPost, "/process/session", CreateSessionRequest{SessionId: "hp-build"}); code != http.StatusCreated {
		t.Fatalf("CREATE after restart = %d %s, want 201", code, body)
	}
	code, body = call(t, engine, http.MethodPost, "/process/session/hp-build/exec",
		SessionExecuteRequest{Command: "printf restarted", CloseInputAfterCommand: true})
	if code != http.StatusOK {
		t.Fatalf("EXEC on the reused ID = %d %s, want 200", code, body)
	}
	var executed SessionExecuteResponse
	if err := json.Unmarshal(body, &executed); err != nil {
		t.Fatal(err)
	}
	if executed.ExitCode == nil || *executed.ExitCode != 0 || executed.Output == nil || !bytes.Contains([]byte(*executed.Output), []byte("restarted")) {
		t.Fatalf("reused session did not run its command: %s", body)
	}
	if code, body := call(t, engine, http.MethodDelete, "/process/session/hp-build", nil); code != http.StatusNoContent {
		t.Fatalf("DELETE = %d %s, want 204", code, body)
	}
	if code, body := call(t, engine, http.MethodDelete, "/process/session/hp-build", nil); code != http.StatusNotFound {
		t.Fatalf("repeated DELETE = %d %s, want 404", code, body)
	}
}

// Deletion converges on state no owner is behind, instead of reporting an
// untyped failure that reached clients as 500 and repeated forever.
func TestDeleteRetiresUnownedRetainedState(t *testing.T) {
	configDir := t.TempDir()
	engine := router(t, configDir)
	retained := retain(t, configDir, "hp-cancelled")

	code, body := call(t, engine, http.MethodDelete, "/process/session/hp-cancelled", nil)
	if code != http.StatusNotFound {
		t.Fatalf("DELETE of unowned retained state = %d %s, want 404", code, body)
	}
	if _, err := os.Lstat(retained); !os.IsNotExist(err) {
		t.Fatalf("deletion left retained state behind: %v", err)
	}
	if code, body := call(t, engine, http.MethodPost, "/process/session", CreateSessionRequest{SessionId: "hp-cancelled"}); code != http.StatusCreated {
		t.Fatalf("CREATE after deletion = %d %s, want 201", code, body)
	}
	if code, body := call(t, engine, http.MethodDelete, "/process/session/hp-cancelled", nil); code != http.StatusNoContent {
		t.Fatalf("DELETE of the live session = %d %s, want 204", code, body)
	}
}

// A live owner still owns its ID: reuse is a conflict, not a silent takeover.
func TestCreateStillConflictsWithALiveOwner(t *testing.T) {
	configDir := t.TempDir()
	engine := router(t, configDir)
	if code, body := call(t, engine, http.MethodPost, "/process/session", CreateSessionRequest{SessionId: "hp-live"}); code != http.StatusCreated {
		t.Fatalf("CREATE = %d %s, want 201", code, body)
	}
	t.Cleanup(func() { call(t, engine, http.MethodDelete, "/process/session/hp-live", nil) })
	if code, body := call(t, engine, http.MethodPost, "/process/session", CreateSessionRequest{SessionId: "hp-live"}); code != http.StatusConflict {
		t.Fatalf("CREATE over a live owner = %d %s, want 409", code, body)
	}
	code, body := call(t, engine, http.MethodGet, "/process/session/hp-live", nil)
	if code != http.StatusOK {
		t.Fatalf("GET = %d %s, want 200", code, body)
	}
	var observed SessionDTO
	if err := json.Unmarshal(body, &observed); err != nil {
		t.Fatal(err)
	}
	if observed.ProcessScope != "running" {
		t.Fatalf("live owner reported scope %q, want running", observed.ProcessScope)
	}
}
