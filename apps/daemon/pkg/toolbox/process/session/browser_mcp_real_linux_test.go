// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The actual bundled SDK helper runs as an ordinary synchronous command with
// closed input. Its detached browser must remain owned by the first native
// supervisor after the helper exits, and later helpers must reuse that browser.
func TestRealBrowserMcpHelperRetainsNativeSessionCustody(t *testing.T) {
	driver := os.Getenv("AMBIT_TEST_BROWSER_EXECUTABLE")
	chrome := os.Getenv("AMBIT_TEST_CHROME_EXECUTABLE")
	bundle := os.Getenv("AMBIT_TEST_BROWSER_MCP_BUNDLE")
	windowMode := os.Getenv("AMBIT_TEST_BROWSER_WINDOW") == "1"
	displayHelper := os.Getenv("AMBIT_TEST_BROWSER_DISPLAY_HELPER")
	if driver == "" || chrome == "" || bundle == "" {
		t.Skip("set real browser executables and AMBIT_TEST_BROWSER_MCP_BUNDLE")
	}
	if windowMode && displayHelper == "" {
		t.Fatal("window qualification requires AMBIT_TEST_BROWSER_DISPLAY_HELPER")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}
	driver, err = filepath.EvalSymlinks(driver)
	if err != nil {
		t.Fatal(err)
	}
	driverBytes, err := os.ReadFile(driver)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(driverBytes))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	descriptorBytes, err := exec.CommandContext(ctx, driver, "mcp", "--describe-host-bound").Output()
	if err != nil {
		t.Fatal(err)
	}
	var descriptor any
	if err := json.Unmarshal(descriptorBytes, &descriptor); err != nil {
		t.Fatal(err)
	}
	// Short paths preserve the same 32-hex namespace under the Unix socket bound.
	scratch, err := os.MkdirTemp("", "browser-mcp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(scratch) })
	socketDir := filepath.Join(scratch, "s")
	if err := os.Mkdir(socketDir, 0700); err != nil {
		t.Fatal(err)
	}
	engine, service := newSessionEngine(t, t.TempDir(), func(controller *SessionController) {
		controller.browserExecutable = driver
		controller.browserSocketDir = socketDir
	})
	workspace := &browserWorkspace{engine: engine, socketDir: socketDir}
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>Supervisor browser</title><input id=field><button style="position:absolute;left:40px;top:120px;width:100px;height:40px" onclick="document.querySelector('#field').value='Image coordinates hit'">Target</button>`)
	}))
	defer page.Close()
	environment := map[string]string{}
	for _, item := range os.Environ() {
		name, value, _ := strings.Cut(item, "=")
		if !strings.HasPrefix(name, "AGENT_BROWSER_") {
			environment[name] = value
		}
	}
	environment["AGENT_BROWSER_EXECUTABLE_PATH"] = chrome
	environment["AGENT_BROWSER_SOCKET_DIR"] = socketDir
	environment["AGENT_BROWSER_REQUIRE_SANDBOX"] = "1"
	environment["AGENT_BROWSER_IDLE_TIMEOUT_MS"] = "20000"
	environment["AGENT_BROWSER_NO_WEBMCP"] = "1"
	environment["NO_COLOR"] = "1"
	if windowMode {
		environment["DISPLAY"] = ""
		environment["AGENT_BROWSER_WINDOW_STREAM"] = "1"
		environment["AGENT_BROWSER_DISPLAY_HELPER"] = displayHelper
	}
	jsonString := func(value any) string {
		bytes, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(bytes)
	}
	helper := filepath.Join(scratch, "helper.cjs")
	script := fmt.Sprintf(`const fs=require('node:fs');
const {invokeIntrinsicBrowserMcp}=require(%s);
const request=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
invokeIntrinsicBrowserMcp(request,{command:%s,artifactDigest:%s,cwd:%s,environment:%s})
.then(result=>process.stdout.write(JSON.stringify(result)+'\n'))
.catch(()=>{process.stderr.write('Browser helper failed.\n');process.exitCode=1;});
`, jsonString(bundle), jsonString(driver), jsonString(digest), jsonString(scratch), jsonString(environment))
	if err := os.WriteFile(helper, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	const namespace = "aaaabbbbcccc4dddeeeeffff00001111"
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'" }
	invokeChecked := func(session, name string, arguments any, observation any, errorCode string) map[string]any {
		t.Helper()
		workspace.open(t, session)
		directory := filepath.Join(scratch, session)
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		configPath := filepath.Join(directory, "config.json")
		config := map[string]any{"version": 1, "namespace": namespace, "session": "browser", "requireSandbox": true, "captureDirectory": directory}
		if observation != nil {
			config["expectedObservation"] = observation
		}
		if err := os.WriteFile(configPath, []byte(jsonString(config)), 0600); err != nil {
			t.Fatal(err)
		}
		request := filepath.Join(directory, "request.json")
		if err := os.WriteFile(request, []byte(jsonString(map[string]any{"catalog": descriptor, "configPath": configPath, "name": name, "arguments": arguments})), 0600); err != nil {
			t.Fatal(err)
		}
		type response struct {
			status int
			body   []byte
		}
		completed := make(chan response, 1)
		go func() {
			body := []byte(jsonString(SessionExecuteRequest{
				Command: quote(node) + " " + quote(helper) + " " + quote(request), RunAsync: false, SuppressInputEcho: true, CloseInputAfterCommand: true,
			}))
			input := httptest.NewRequest(http.MethodPost, "/process/session/"+session+"/exec", bytes.NewReader(body))
			input.Header.Set("Content-Type", "application/json")
			input.Header.Set("X-Daytona-SDK-Version", "0.203.0")
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, input)
			completed <- response{recorder.Code, recorder.Body.Bytes()}

		}()
		select {
		case reply := <-completed:
			var execution SessionExecuteResponse
			if reply.status != http.StatusOK || json.Unmarshal(reply.body, &execution) != nil || execution.ExitCode == nil || *execution.ExitCode != 0 || execution.Stdout == nil || !execution.InputClosed {
				t.Fatalf("synchronous helper failed: %d %s", reply.status, reply.body)
			}
			var result map[string]any
			if json.Unmarshal([]byte(*execution.Stdout), &result) != nil || (result["isError"] == true) != (errorCode != "") {
				t.Fatalf("helper result: %s", *execution.Stdout)
			}
			content := result["structuredContent"].(map[string]any)
			if errorCode != "" && content["response"].(map[string]any)["code"] != errorCode {
				t.Fatalf("unexpected native result: %s", *execution.Stdout)
			}
			t.Logf("helper session=%s exit=%d scope=%s inputClosed=%v", session, *execution.ExitCode, execution.ProcessScope, execution.InputClosed)
			return content
		case <-time.After(15 * time.Second):
			t.Fatal("synchronous helper did not return while its browser remained live")
			return nil
		}
	}
	invoke := func(session, name string, arguments any) map[string]any {
		return invokeChecked(session, name, arguments, nil, "")
	}
	first := invoke("mcp-first", "agent_browser_open", map[string]any{"url": page.URL})
	view, _ := workspace.only(t, "mcp-first", "browser")
	identity := first["browser"].(map[string]any)["page"].(map[string]any)["targetId"]
	pidPath := filepath.Join(socketDir, "namespaces", namespace, "run", "browser.pid")
	pid, err := strconv.Atoi(strings.TrimSpace(string(awaitFile(t, pidPath))))
	if err != nil {
		t.Fatal(err)
	}
	if owned, err := service.ObserveOwnedProcess("mcp-first", pid); err != nil || owned.PID != pid {
		t.Fatalf("detached MCP browser lost first-session custody: %v %v", owned, err)
	}
	second := invoke("mcp-next", "agent_browser_fill", map[string]any{"selector": "#field", "text": "Retained across helpers"})
	if current, _ := workspace.only(t, "mcp-first", "browser"); current != view || second["browser"].(map[string]any)["page"].(map[string]any)["targetId"] != identity {
		t.Fatal("later helper replaced the retained browser")
	}
	if _, err := service.ObserveOwnedProcess("mcp-next", pid); err == nil {
		t.Fatal("later helper adopted first-session browser custody")
	}
	third := invoke("mcp-next-run", "agent_browser_get_value", map[string]any{"selector": "#field"})
	if third["response"].(map[string]any)["data"].(map[string]any)["value"] != "Retained across helpers" {
		t.Fatal("later helper lost existing page state")
	}
	if owner, err := service.Get("mcp-first"); err != nil || owner.ProcessScope != "running" || !owner.InputClosed {
		t.Fatalf("first helper's closed input ended browser custody: %v %v", owner, err)
	}
	if windowMode {
		server := httptest.NewServer(engine)
		defer server.Close()
		path := "/process/session/mcp-first/browser-views/" + view
		request, _ := http.NewRequest(http.MethodGet, server.URL+path+"/stream?width=780&height=600", nil)
		request.Header.Set("X-Ambit-Browser-Viewer", "baaaaabb-cccc-4ddd-8eee-ffff00000002")
		stream, err := server.Client().Do(request)
		if err != nil || stream.StatusCode != http.StatusOK {
			t.Fatalf("native MCP window stream: %v", err)
		}
		defer stream.Body.Close()
		records := streamRecords(t, stream.Body)
		for {
			record := nextRecord(t, records, 10*time.Second)
			if record["type"] == "frame" {
				surface := record["surface"].(map[string]any)
				if surface["width"] == float64(1560) && surface["height"] == float64(1200) {
					break
				}
			}
		}
		fresh := invokeChecked("mcp-resized", "agent_browser_get_value", map[string]any{"selector": "#field"}, nil, "browser_observation_required")
		browser := fresh["browser"].(map[string]any)
		capture := browser["capture"].(map[string]any)
		space := capture["coordinateSpace"].(map[string]any)
		if space["name"] != "viewport-css" || space["cssWidth"] != float64(780) || space["devicePixelRatio"] != float64(2) {
			t.Fatalf("MCP capture retained old or display geometry: %v", space)
		}
		page := browser["page"].(map[string]any)
		observation := map[string]any{"targetId": page["targetId"], "loaderId": page["loaderId"], "pageGeneration": page["pageGeneration"], "geometrySha256": space["geometrySha256"]}
		invokeChecked("mcp-image-move", "agent_browser_mouse_move", map[string]any{"x": 90, "y": 140}, observation, "")
		invokeChecked("mcp-image-down", "agent_browser_mouse_down", map[string]any{"button": "left"}, observation, "")
		invokeChecked("mcp-image-up", "agent_browser_mouse_up", map[string]any{"button": "left"}, observation, "")
		clicked := invoke("mcp-image-read", "agent_browser_get_value", map[string]any{"selector": "#field"})
		if clicked["response"].(map[string]any)["data"].(map[string]any)["value"] != "Image coordinates hit" {
			t.Fatal("image coordinates after X11 resize missed the real page target")
		}
		control := func(request any) map[string]any {
			t.Helper()
			status, body := call(t, engine, http.MethodPost, path+"/control", request)
			var value map[string]any
			if status != http.StatusOK || json.Unmarshal(body, &value) != nil {
				t.Fatalf("native MCP control: %d %s", status, body)
			}
			return value
		}
		lease := control(map[string]any{"op": "acquire", "controllerId": browserFixtureController, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()})
		control(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": 1,
			"expectedSurfaceGeneration": lease["surface"].(map[string]any)["generation"],
			"events": []map[string]any{
				{"type": "input_keyboard", "eventType": "keyDown", "key": "w", "code": "KeyW", "windowsVirtualKeyCode": 87, "modifiers": 10},
				{"type": "input_keyboard", "eventType": "keyUp", "key": "w", "code": "KeyW", "windowsVirtualKeyCode": 87, "modifiers": 0},
			}})
		deadline := time.Now().Add(5 * time.Second)
		for control(map[string]any{"op": "inspect"})["surface"] != nil {
			if time.Now().After(deadline) {
				t.Fatal("native Close window did not end the owned Chrome process")
			}
			time.Sleep(10 * time.Millisecond)
		}
		closed := invokeChecked("mcp-after-close", "agent_browser_mouse_move", map[string]any{"x": 90, "y": 140}, observation, "browser_observation_required")
		if closed["browser"].(map[string]any)["capture"].(map[string]any)["code"] != "no_active_page" {
			t.Fatalf("closed browser was silently relaunched before feedback: %v", closed)
		}
		if current := strings.TrimSpace(string(awaitFile(t, pidPath))); current != strconv.Itoa(pid) {
			t.Fatal("native window close replaced the retained daemon")
		}
		reopened := invoke("mcp-reopen", "agent_browser_open", map[string]any{"url": "about:blank"})
		if reopened["browser"].(map[string]any)["page"].(map[string]any)["targetId"] == identity {
			t.Fatal("explicit reopen claimed to restore a closed tab")
		}
		if owned, err := service.ObserveOwnedProcess("mcp-first", pid); err != nil || owned.PID != pid {
			t.Fatalf("explicit reopen lost original native custody: %v %v", owned, err)
		}
	}
	invoke("mcp-close", "agent_browser_close", map[string]any{})
	deadline := time.Now().Add(5 * time.Second)
	for {
		owner, err := service.Get("mcp-first")
		if err == nil && owner.ProcessScope == "settled" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("explicit browser close did not settle first native supervisor: %v %v", owner, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if views, _ := workspace.views(t); len(views) != 0 {
		t.Fatalf("explicit close retained live browser views: %v", views)
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("explicit close retained daemon metadata: %v", err)
	}
}
