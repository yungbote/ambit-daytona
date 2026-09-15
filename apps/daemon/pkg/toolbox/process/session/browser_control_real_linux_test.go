// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The native HTTP endpoint, actual Unix driver and Chromium share the same
// native session here. No provider/model or external website participates.
func TestRealBrowserControlThroughOwnedSession(t *testing.T) {
	executable := os.Getenv("AMBIT_TEST_BROWSER_EXECUTABLE")
	chrome := os.Getenv("AMBIT_TEST_CHROME_EXECUTABLE")
	if os.Getenv("AMBIT_TEST_BROWSER_CONTROL") != "1" || executable == "" || chrome == "" {
		t.Skip("set the real browser executables and AMBIT_TEST_BROWSER_CONTROL=1")
	}
	executable, err := filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	socketDir := t.TempDir()
	config := filepath.Join(socketDir, "settings.json")
	if err := os.WriteFile(config, []byte(`{"requireSandbox":true,"requireDaemon":true,"idleTimeout":"0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	engine, _ := newSessionEngine(t, t.TempDir(), func(controller *SessionController) {
		controller.browserSocketDir = socketDir
		controller.browserExecutable = executable
	})
	workspace := &browserWorkspace{engine: engine, socketDir: socketDir}
	workspace.open(t, "browser-owner")
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>Browser control qualification</title><style>button,input{position:absolute;left:10px;height:40px}button{top:10px;width:100px}input{top:70px;width:250px}output{position:absolute;top:130px;left:10px;font:20px sans-serif}</style><button onclick="window.clickCount++;document.querySelector('output').textContent='Clicks: '+window.clickCount">Count</button><input aria-label="Message"><output>Clicks: 0</output><script>window.clickCount=0</script>`)
	}))
	defer page.Close()
	var environment []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "AGENT_BROWSER_") {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "AGENT_BROWSER_SOCKET_DIR="+socketDir, "AGENT_BROWSER_EXECUTABLE_PATH="+chrome, "NO_COLOR=1")
	arguments := []string{"--config", config, "--session", "primary", "--json"}
	cli := func(wantSuccess bool, args ...string) map[string]any {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, executable, append(append([]string{}, arguments...), args...)...)
		command.Env = environment
		body, _ := command.CombinedOutput()
		var response map[string]any
		if err := json.Unmarshal(body, &response); err != nil || response["success"] != wantSuccess {
			t.Fatalf("browser command %v returned an unexpected response: %s", args, body)
		}
		return response
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'" }
	parts := []string{"env"}
	for _, entry := range environment {
		if strings.HasPrefix(entry, "AGENT_BROWSER_") {
			parts = append(parts, quote(entry))
		}
	}
	parts = append(parts, quote(executable), "--config", quote(config), "--session", "primary", "daemon")
	if status, body := call(t, engine, http.MethodPost, "/process/session/browser-owner/exec", SessionExecuteRequest{Command: strings.Join(parts, " "), RunAsync: true}); status != http.StatusAccepted {
		t.Fatalf("browser daemon start failed: %d %s", status, body)
	}
	awaitPath(t, filepath.Join(socketDir, "primary.sock"))
	cli(true, "open", page.URL)
	id, _ := workspace.only(t, "browser-owner", "primary")
	target := "/process/session/browser-owner/browser-views/" + id + "/control"
	control := func(body any, expected int) map[string]any {
		t.Helper()
		status, raw := call(t, engine, http.MethodPost, target, body)
		var response map[string]any
		if status != expected || json.Unmarshal(raw, &response) != nil {
			t.Fatalf("native browser control failed: %d %s", status, raw)
		}
		return response
	}
	if result := control(map[string]any{"op": "inspect"}, http.StatusOK); result["supported"] != true || result["controlled"] != false {
		t.Fatalf("initial inspection: %v", result)
	}
	control(map[string]any{"op": "acquire", "controllerId": browserFixtureController, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()}, http.StatusOK)
	if result := cli(false, "get", "title"); result["code"] != "browser_controlled_by_user" {
		t.Fatalf("agent command was not fenced: %v", result)
	}
	click := []map[string]any{
		{"type": "input_mouse", "eventType": "mousePressed", "x": 30, "y": 30, "button": "left", "buttons": 1, "clickCount": 1},
		{"type": "input_mouse", "eventType": "mouseReleased", "x": 30, "y": 30, "button": "left", "buttons": 0, "clickCount": 1},
	}
	first := map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": 1, "events": click}
	control(first, http.StatusOK)
	if result := control(first, http.StatusOK); result["status"] != "duplicate" {
		t.Fatalf("duplicate input was not acknowledged: %v", result)
	}
	text := []map[string]any{
		{"type": "input_mouse", "eventType": "mousePressed", "x": 30, "y": 90, "button": "left", "buttons": 1, "clickCount": 1},
		{"type": "input_mouse", "eventType": "mouseReleased", "x": 30, "y": 90, "button": "left", "buttons": 0, "clickCount": 1},
		{"type": "input_keyboard", "eventType": "insertText", "text": "Native browser control ✓"},
	}
	control(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": 2, "events": text}, http.StatusOK)
	if result := control(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": 4, "events": click}, http.StatusConflict); result["code"] != "browser_control_sequence_gap" {
		t.Fatalf("input gap was not refused: %v", result)
	}
	control(map[string]any{"op": "release", "controllerId": browserFixtureController}, http.StatusOK)
	result := cli(true, "eval", `JSON.stringify({count:window.clickCount,value:document.querySelector('input').value})`)
	data, ok := result["data"].(map[string]any)
	if !ok {
		t.Fatalf("missing observed browser result: %v", result)
	}
	var observed struct {
		Count int    `json:"count"`
		Value string `json:"value"`
	}
	encoded, ok := data["result"].(string)
	if !ok || json.Unmarshal([]byte(encoded), &observed) != nil || observed.Count != 1 || observed.Value != "Native browser control ✓" {
		t.Fatalf("real browser effects differ from admitted inputs: %v", result)
	}
	if evidence := os.Getenv("AMBIT_BROWSER_CONTROL_EVIDENCE_DIR"); evidence != "" {
		cli(true, "screenshot", filepath.Join(evidence, "native-control-result.png"))
	}
	cli(true, "close")
}
