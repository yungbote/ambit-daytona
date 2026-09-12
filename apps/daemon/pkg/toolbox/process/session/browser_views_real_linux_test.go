// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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

// This opt-in proof uses the real compiled agent-browser and real Chrome under
// the native session owner. Unit fixtures cannot prove a driver's shutdown
// ordering. No model, external account, production workspace or network is used.
func TestRealBrowserViewExplicitCloseAndReopen(t *testing.T) {
	executable := os.Getenv("AMBIT_TEST_BROWSER_EXECUTABLE")
	chrome := os.Getenv("AMBIT_TEST_CHROME_EXECUTABLE")
	if executable == "" || chrome == "" {
		t.Skip("set AMBIT_TEST_BROWSER_EXECUTABLE and AMBIT_TEST_CHROME_EXECUTABLE for real browser qualification")
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
		fmt.Fprint(w, `<!doctype html><title>Browser close qualification</title><body style="background:#eef0f2"><h1>First frame</h1></body>`)
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
	cli := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, executable, append(append([]string{}, arguments...), args...)...)
		command.Env = environment
		body, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("browser command %v failed: %v %s", args, err, body)
		}
		var response struct {
			Success bool `json:"success"`
		}
		if err := json.Unmarshal(body, &response); err != nil || !response.Success {
			t.Fatalf("browser command %v returned %s: %v", args, body, err)
		}
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'" }
	start := func() string {
		t.Helper()
		parts := []string{"env"}
		for _, entry := range os.Environ() {
			if key, _, ok := strings.Cut(entry, "="); ok && strings.HasPrefix(key, "AGENT_BROWSER_") {
				parts = append(parts, "-u", quote(key))
			}
		}
		parts = append(parts, quote("AGENT_BROWSER_SOCKET_DIR="+socketDir), quote("AGENT_BROWSER_EXECUTABLE_PATH="+chrome), "NO_COLOR=1", quote(executable))
		for _, argument := range append(append([]string{}, arguments...), "daemon") {
			parts = append(parts, quote(argument))
		}
		code, body := call(t, engine, http.MethodPost, "/process/session/browser-owner/exec", SessionExecuteRequest{Command: strings.Join(parts, " "), RunAsync: true})
		if code != http.StatusAccepted {
			t.Fatalf("daemon start = %d %s", code, body)
		}
		awaitPath(t, filepath.Join(socketDir, "primary.sock"))
		cli("open", page.URL)
		id, _ := workspace.only(t, "browser-owner", "primary")
		return id
	}
	frame := func(records chan string) map[string]any {
		t.Helper()
		for {
			record := nextRecord(t, records, 15*time.Second)
			if record["type"] == "frame" {
				pixels, err := base64.StdEncoding.DecodeString(record["data"].(string))
				if err != nil || len(pixels) < 100 {
					t.Fatalf("invalid real browser pixels: %v", err)
				}
				t.Logf("real browser frame seq=%v bytes=%d sha256=%x", record["seq"], len(pixels), sha256.Sum256(pixels))
				return record
			}
			if record["type"] == "finished" || record["type"] == "unavailable" {
				t.Fatalf("browser ended before its frame: %v", record)
			}
		}
	}
	finish := func(records chan string) {
		t.Helper()
		for {
			record := nextRecord(t, records, 10*time.Second)
			if record["type"] == "finished" {
				expectStreamEnd(t, records, 10*time.Second)
				return
			}
			if record["type"] == "unavailable" {
				t.Fatalf("explicit close became unavailable: %v", record)
			}
		}
	}
	first := start()
	_, records := openStream(t, engine, "browser-owner", first)
	frame(records)
	cli("stream", "disable")
	finish(records)
	cli("stream", "enable")
	second, _ := workspace.only(t, "browser-owner", "primary")
	if second == first {
		t.Fatal("reopened stream reused its finished instance")
	}
	_, records = openStream(t, engine, "browser-owner", second)
	frame(records)
	cli("close")
	finish(records)
	// CLI close acknowledges before its foreground daemon has finished exiting.
	// Wait for its actual socket removal, not a guessed shutdown sleep.
	for deadline := time.Now().Add(10 * time.Second); ; {
		_, err := os.Stat(filepath.Join(socketDir, "primary.sock"))
		if os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed daemon retained its socket")
		}
		time.Sleep(5 * time.Millisecond)
	}
	third := start()
	if third == first || third == second {
		t.Fatal("reopened browser reused a finished view")
	}
	_, records = openStream(t, engine, "browser-owner", third)
	frame(records)
	cli("close")
	finish(records)
	t.Logf("view instances: first=%s stream-reopened=%s browser-reopened=%s", first, second, third)
}
