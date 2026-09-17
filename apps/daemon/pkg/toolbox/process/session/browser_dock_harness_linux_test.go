// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opt-in fixture serves the production native handlers while a frontend uses
// the real browser dock. Only the Product authentication edge is a fixture.
// Interrupt the test PID in the metadata file to release all task processes.
func TestBrowserDockHarness(t *testing.T) {
	output := os.Getenv("AMBIT_TEST_BROWSER_HARNESS_OUTPUT")
	if output == "" {
		t.Skip("set AMBIT_TEST_BROWSER_HARNESS_OUTPUT to hold a local native dock fixture")
	}
	driver := os.Getenv("AMBIT_TEST_BROWSER_EXECUTABLE")
	chrome := os.Getenv("AMBIT_TEST_CHROME_EXECUTABLE")
	if driver == "" || chrome == "" {
		t.Fatal("real browser executables are required")
	}
	driver, err := filepath.EvalSymlinks(driver)
	if err != nil {
		t.Fatal(err)
	}
	scratch, err := os.MkdirTemp("", "browser-dock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(scratch) })
	config := filepath.Join(scratch, "config.json")
	if err := os.WriteFile(config, []byte(`{"requireSandbox":true,"requireDaemon":true,"idleTimeout":"0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	engine, _ := newSessionEngine(t, t.TempDir(), func(controller *SessionController) {
		controller.browserSocketDir = scratch
		controller.browserExecutable = driver
	})
	workspace := &browserWorkspace{engine: engine, socketDir: scratch}
	const session = "browser-dock"
	workspace.open(t, session)
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'" }
	var environment []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "AGENT_BROWSER_") {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "AGENT_BROWSER_SOCKET_DIR="+scratch, "AGENT_BROWSER_EXECUTABLE_PATH="+chrome, "NO_COLOR=1")
	command := []string{"env", "AGENT_BROWSER_SOCKET_DIR=" + quote(scratch), "AGENT_BROWSER_EXECUTABLE_PATH=" + quote(chrome)}
	windowMode := os.Getenv("AGENT_BROWSER_WINDOW_STREAM") == "1"
	if windowMode {
		helper := os.Getenv("AGENT_BROWSER_DISPLAY_HELPER")
		environment = append(environment, "DISPLAY=", "AGENT_BROWSER_WINDOW_STREAM=1", "AGENT_BROWSER_DISPLAY_HELPER="+helper)
		command = append(command, "DISPLAY=", "AGENT_BROWSER_WINDOW_STREAM=1", "AGENT_BROWSER_DISPLAY_HELPER="+quote(helper))
	}
	command = append(command, quote(driver), "--config", quote(config), "--session", "primary", "daemon")
	if status, body := call(t, engine, http.MethodPost, "/process/session/"+session+"/exec", SessionExecuteRequest{Command: strings.Join(command, " "), RunAsync: true}); status != http.StatusAccepted {
		t.Fatalf("driver start: %d %s", status, body)
	}
	awaitPath(t, filepath.Join(scratch, "primary.sock"))
	args := []string{"--config", config, "--session", "primary", "--json"}
	actions := [][]string{{"open", "data:text/html,<title>Native browser dock</title><h1>Browser ready</h1><input aria-label=Message>"}}
	width, height := 1280, 720
	if !windowMode {
		actions = append(actions, []string{"set", "viewport", "960", "720"})
		width = 960
	}
	for _, action := range actions {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, driver, append(append([]string{}, args...), action...)...)
		cmd.Env = environment
		body, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("initial browser command: %v %s", err, body)
		}
	}
	id, _ := workspace.only(t, session, "primary")
	server := httptest.NewServer(engine)
	defer server.Close()
	metadata := map[string]any{"baseUrl": server.URL, "sessionId": session, "viewId": id, "pid": os.Getpid(),
		"streamPath":              "/process/session/" + session + "/browser-views/" + id + "/stream",
		"controlPath":             "/process/session/" + session + "/browser-views/" + id + "/control",
		"viewChannelPath":         "/process/session/" + session + "/browser-views/" + id + "/channel",
		"viewChannelViewerHeader": "X-Ambit-Browser-Viewer",
		"viewChannelFrameWindow":  8,
		"driver":                  driver, "config": config, "socketDir": scratch, "chrome": chrome, "viewport": map[string]int{"width": width, "height": height},
		"maxFps": 10, "pacing": "ack", "auth": "task-local fixture only"}
	if windowMode {
		metadata["maxFps"] = 60
		metadata["passiveMaxFps"] = 10
		helper := os.Getenv("AGENT_BROWSER_DISPLAY_HELPER")
		bytes, err := os.ReadFile(helper)
		if err != nil {
			t.Fatalf("read exact display helper: %v", err)
		}
		metadata["displayHelper"] = helper
		metadata["displayHelperSha256"] = fmt.Sprintf("%x", sha256.Sum256(bytes))
	}
	body, _ := json.MarshalIndent(metadata, "", "  ")
	if err := os.WriteFile(output, body, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("native dock fixture: %s; PID %d", server.URL, os.Getpid())
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	select {
	case <-ctx.Done():
	case <-time.After(60 * time.Minute):
	}
}
