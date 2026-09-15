// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/jpeg"
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
		fmt.Fprint(w, `<!doctype html><title>Browser control qualification</title><style>body{min-height:2000px}button,input{position:absolute;left:10px;height:40px}button{top:10px;width:100px}input{top:70px;width:250px}output{position:absolute;top:130px;left:10px;font:20px sans-serif}</style><button onclick="window.clickCount++;document.querySelector('output').textContent='Clicks: '+window.clickCount">Count</button><input aria-label="Message"><output>Clicks: 0</output><script>window.clickCount=0</script>`)
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
	cli(true, "set", "viewport", "800", "600", "2")
	status, records := openStream(t, engine, "browser-owner", id)
	if status != http.StatusOK {
		t.Fatalf("stream attachment returned %d", status)
	}
	next := func(predicate func(map[string]any) bool) map[string]any {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				t.Fatal("expected browser activity was not observed")
			}
			record := nextRecord(t, records, remaining)
			if predicate(record) {
				return record
			}
		}
	}

	initialTabs := next(func(record map[string]any) bool { return record["type"] == "tabs" })
	if initialTabs["complete"] != true {
		t.Fatal("initial real browser roster was partial")
	}
	firstTab := initialTabs["tabs"].([]any)[0].(map[string]any)["id"].(string)
	frame := next(func(record map[string]any) bool { return record["type"] == "frame" })
	generation, ok := frame["pageGeneration"].(string)
	if !ok || generation == "" {
		t.Fatalf("frame has no page identity: %v", frame)
	}
	cli(true, "mouse", "move", "30", "30")
	cli(true, "click", "button")
	cli(true, "fill", "input", "agent-private-input")
	cli(true, "fill", "input", "")
	cli(true, "scroll", "down", "200")
	cli(true, "scroll", "up", "200")
	observedActivity := map[string]bool{}
	for len(observedActivity) < 5 {
		next(func(record map[string]any) bool {
			if record["source"] != "agent" || record["pageGeneration"] != generation {
				return false
			}
			if record["type"] == "pointer" {
				if event, ok := record["eventType"].(string); ok && (event == "move" || event == "press" || event == "release") {
					observedActivity[event] = true
				}
			} else if record["type"] == "activity" {
				if kind, ok := record["kind"].(string); ok && (kind == "typing" || kind == "scrolling") {
					observedActivity[kind] = true
				}
				if len(record) != 5 {
					t.Fatalf("activity leaked nonvisual fields: %v", record)
				}
			}
			return true
		})
	}
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
		{"type": "viewport", "width": 640, "height": 480},
		{"type": "input_mouse", "eventType": "mousePressed", "x": 30, "y": 30, "button": "left", "buttons": 1, "clickCount": 1},
		{"type": "input_mouse", "eventType": "mouseReleased", "x": 30, "y": 30, "button": "left", "buttons": 0, "clickCount": 1},
	}
	first := map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": 1, "events": click}
	control(first, http.StatusOK)
	reset := next(func(record map[string]any) bool { return record["type"] == "pointer" && record["eventType"] == "reset" })
	if reset["pageGeneration"] == generation {
		t.Fatal("viewport resize retained old coordinate identity")
	}
	next(func(record map[string]any) bool {
		if record["type"] == "pointer" && record["eventType"] == "reset" {
			reset = record
		}
		if record["type"] != "frame" || record["pageGeneration"] != reset["pageGeneration"] {
			return false
		}
		metadata, ok := record["metadata"].(map[string]any)
		return ok && metadata["deviceWidth"] == float64(640) && metadata["deviceHeight"] == float64(480)
	})
	if result := control(first, http.StatusOK); result["status"] != "duplicate" {
		t.Fatalf("duplicate input was not acknowledged: %v", result)
	}
	text := []map[string]any{
		{"type": "input_mouse", "eventType": "mousePressed", "x": 30, "y": 90, "button": "left", "buttons": 1, "clickCount": 1},
		{"type": "input_mouse", "eventType": "mouseReleased", "x": 30, "y": 90, "button": "left", "buttons": 0, "clickCount": 1},
		{"type": "input_keyboard", "eventType": "insertText", "text": "Native browser control ✓"},
	}
	control(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": 2, "events": text}, http.StatusOK)
	selection := []map[string]any{
		{"type": "input_keyboard", "eventType": "keyDown", "key": "a", "code": "KeyA", "windowsVirtualKeyCode": 65, "modifiers": 2},
		{"type": "input_keyboard", "eventType": "keyUp", "key": "a", "code": "KeyA", "windowsVirtualKeyCode": 65, "modifiers": 2},
	}
	control(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": 3, "events": selection}, http.StatusOK)
	copied := control(map[string]any{"op": "copy", "controllerId": browserFixtureController}, http.StatusOK)
	clipboard, ok := copied["clipboard"].(map[string]any)
	if !ok || clipboard["text"] != "Native browser control ✓" || clipboard["bytes"] != float64(len("Native browser control ✓")) || clipboard["complete"] != true || copied["lastSequence"] != float64(3) {
		t.Fatalf("copy did not preserve the exact selected text and sequence: %v", copied)
	}
	if result := control(map[string]any{"op": "copy", "controllerId": "aaaabbbb-cccc-4ddd-8eee-ffff00002222"}, http.StatusConflict); result["code"] != "browser_control_stale" {
		t.Fatalf("foreign copy returned %v", result)
	}
	if result := control(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": 6, "events": click}, http.StatusConflict); result["code"] != "browser_control_sequence_gap" {
		t.Fatalf("input gap was not refused: %v", result)
	}
	tabSequence := 3
	tabInput := func(events []map[string]any) {
		t.Helper()
		tabSequence++
		control(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": tabSequence, "events": events}, http.StatusOK)
	}
	roster := func(count int, active string) map[string]any {
		return next(func(record map[string]any) bool {
			if record["type"] != "tabs" || record["complete"] != true {
				return false
			}
			tabs, ok := record["tabs"].([]any)
			if !ok || len(tabs) != count {
				return false
			}
			return active == "" || tabs[0].(map[string]any)["id"] == active
		})
	}
	tabInput([]map[string]any{
		{"type": "tab", "action": "new"},
		{"type": "navigation", "action": "navigate", "url": page.URL + "/second-tab"},
	})
	opened := roster(2, "")
	secondTab := opened["tabs"].([]any)[0].(map[string]any)["id"].(string)
	if secondTab == firstTab {
		t.Fatal("new tab did not receive its own stable identity")
	}
	// A navigation acknowledgement starts loading; coordinates follow the
	// actual newly painted page, just as the dock's geometry barrier does.
	next(func(record map[string]any) bool {
		if record["type"] != "frame" || record["pageGeneration"] == reset["pageGeneration"] {
			return false
		}
		metadata := record["metadata"].(map[string]any)
		if metadata["deviceWidth"] != float64(640) || metadata["deviceHeight"] != float64(480) {
			return false
		}
		encoded, ok := record["data"].(string)
		if !ok {
			return false
		}
		pixels, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return false
		}
		image, err := jpeg.Decode(bytes.NewReader(pixels))
		if err != nil {
			return false
		}
		for y := 0; y < 300 && y < image.Bounds().Dy(); y += 8 {
			for x := 0; x < 256 && x < image.Bounds().Dx(); x += 8 {
				r, g, b, _ := image.At(x, y).RGBA()
				if r < 55000 || g < 55000 || b < 55000 {
					return true
				}
			}
		}
		return false
	})
	tabInput([]map[string]any{
		{"type": "input_mouse", "eventType": "mousePressed", "x": 30, "y": 90, "button": "left", "buttons": 1, "clickCount": 1},
		{"type": "input_mouse", "eventType": "mouseReleased", "x": 30, "y": 90, "button": "left", "buttons": 0, "clickCount": 1},
		{"type": "input_keyboard", "eventType": "insertText", "text": "Second tab text"},
	})
	tabInput(selection)
	secondCopy := control(map[string]any{"op": "copy", "controllerId": browserFixtureController}, http.StatusOK)
	if secondCopy["clipboard"].(map[string]any)["text"] != "Second tab text" {
		t.Fatalf("new tab copy did not match dispatched text: %v", secondCopy)
	}
	tabInput([]map[string]any{{"type": "tab", "action": "select", "tabId": firstTab}, {"type": "tab", "action": "close", "tabId": secondTab}})
	roster(1, firstTab)
	refusal := control(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": tabSequence + 1, "events": []any{map[string]any{"type": "tab", "action": "close", "tabId": firstTab}}}, http.StatusConflict)
	if refusal["code"] != "browser_control_invalid" {
		t.Fatalf("last-tab refusal lost its known no-effect result: %v", refusal)
	}
	tabInput([]map[string]any{{"type": "tab", "action": "new"}})
	reopened := roster(2, "")
	thirdTab := reopened["tabs"].([]any)[0].(map[string]any)["id"].(string)
	if thirdTab == secondTab || thirdTab == firstTab {
		t.Fatal("closed tab identity was reused")
	}
	tabInput([]map[string]any{{"type": "tab", "action": "select", "tabId": firstTab}, {"type": "tab", "action": "close", "tabId": thirdTab}})
	roster(1, firstTab)
	next(func(record map[string]any) bool {
		if record["type"] != "frame" {
			return false
		}
		metadata := record["metadata"].(map[string]any)
		return metadata["deviceWidth"] == float64(640) && metadata["deviceHeight"] == float64(480)
	})
	control(map[string]any{"op": "release", "controllerId": browserFixtureController}, http.StatusOK)
	result := cli(true, "eval", `JSON.stringify({count:window.clickCount,value:document.querySelector('input').value,width:innerWidth,height:innerHeight,scale:devicePixelRatio})`)
	data, ok := result["data"].(map[string]any)
	if !ok {
		t.Fatalf("missing observed browser result: %v", result)
	}
	var observed struct {
		Count  int    `json:"count"`
		Value  string `json:"value"`
		Width  int    `json:"width"`
		Height int    `json:"height"`
		Scale  int    `json:"scale"`
	}
	encoded, ok := data["result"].(string)
	if !ok || json.Unmarshal([]byte(encoded), &observed) != nil || observed.Count != 2 || observed.Value != "Native browser control ✓" || observed.Width != 640 || observed.Height != 480 || observed.Scale != 2 {
		t.Fatalf("real browser effects differ from admitted inputs: %v", result)
	}
	if evidence := os.Getenv("AMBIT_BROWSER_CONTROL_EVIDENCE_DIR"); evidence != "" {
		cli(true, "screenshot", filepath.Join(evidence, "native-control-result.png"))
	}
	const navigationOwner = "aaaabbbb-cccc-4ddd-8eee-ffff00002222"
	control(map[string]any{"op": "acquire", "controllerId": navigationOwner, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()}, http.StatusOK)
	sequence := 0
	navigate := func(action, url, expected string) map[string]any {
		t.Helper()
		sequence++
		event := map[string]any{"type": "navigation", "action": action}
		if url != "" {
			event["url"] = url
		}
		control(map[string]any{"op": "input", "controllerId": navigationOwner, "sequence": sequence, "events": []any{event}}, http.StatusOK)
		return next(func(record map[string]any) bool { return record["type"] == "url" && record["url"] == expected })
	}
	location := navigate("navigate", page.URL+"/second", page.URL+"/second")
	if location["canGoBack"] != true || location["canGoForward"] != false {
		t.Fatalf("navigation history state: %v", location)
	}
	location = navigate("back", "", page.URL+"/")
	if location["canGoForward"] != true {
		t.Fatalf("back lost forward history: %v", location)
	}
	navigate("forward", "", page.URL+"/second")
	navigate("reload", "", page.URL+"/second")
	control(map[string]any{"op": "release", "controllerId": navigationOwner}, http.StatusOK)
	cli(true, "eval", "document.querySelector('input').value='<'.repeat(100000);document.querySelector('input').focus();document.querySelector('input').select()")
	const largeCopyOwner = "aaaabbbb-cccc-4ddd-8eee-ffff00003333"
	control(map[string]any{"op": "acquire", "controllerId": largeCopyOwner, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()}, http.StatusOK)
	large := control(map[string]any{"op": "copy", "controllerId": largeCopyOwner}, http.StatusOK)
	copiedText := large["clipboard"].(map[string]any)
	if copiedText["text"] != strings.Repeat("<", 100000) || copiedText["bytes"] != float64(100000) || copiedText["complete"] != true {
		t.Fatal("copy truncated or changed text across the large JSON response")
	}
	control(map[string]any{"op": "release", "controllerId": largeCopyOwner}, http.StatusOK)
	cli(true, "close")
}
