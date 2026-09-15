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

// Real native session, driver, private X11 helper and Chrome. These assertions
// observe actual pixels and page state; there is no model or external site.
func TestRealBrowserWindowGeometryInputAndHandoff(t *testing.T) {
	driver, chrome, helper := os.Getenv("AMBIT_TEST_BROWSER_EXECUTABLE"), os.Getenv("AMBIT_TEST_CHROME_EXECUTABLE"), os.Getenv("AMBIT_TEST_BROWSER_DISPLAY_HELPER")
	if os.Getenv("AMBIT_TEST_BROWSER_WINDOW") != "1" || driver == "" || chrome == "" || helper == "" {
		t.Skip("set AMBIT_TEST_BROWSER_WINDOW and real driver, Chrome, display helper paths")
	}
	driver, err := filepath.EvalSymlinks(driver)
	if err != nil {
		t.Fatal(err)
	}
	scratch, err := os.MkdirTemp("", "window-session-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(scratch) })
	config := filepath.Join(scratch, "config.json")
	if err := os.WriteFile(config, []byte(`{"requireSandbox":true,"requireDaemon":true,"idleTimeout":"0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	engine, _ := newSessionEngine(t, t.TempDir(), func(c *SessionController) { c.browserSocketDir = scratch; c.browserExecutable = driver })
	workspace := &browserWorkspace{engine: engine, socketDir: scratch}
	workspace.open(t, "window-owner")
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/modal" {
			fmt.Fprint(w, `<!doctype html><title>Native modal</title><button autofocus onclick="document.body.dataset.answer=String(confirm('Local window qualification'))">Confirm</button>`)
			return
		}
		fmt.Fprintf(w, `<!doctype html><title>Window %s</title><style>html,body{margin:0;background:#134f2f;color:white;min-height:100%%}button{position:absolute;left:20px;top:10px;width:100px;height:40px}textarea{position:absolute;left:20px;top:80px;width:280px;height:120px}</style><button onclick="window.clicks++">Count</button><textarea aria-label="Notes"></textarea><script>window.clicks=0;addEventListener('pointermove',e=>window.actualPointer={x:e.screenX,y:e.screenY})</script>`, r.URL.Path)
	}))
	defer page.Close()
	var environment []string
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "AGENT_BROWSER_") && !strings.HasPrefix(item, "DISPLAY=") {
			environment = append(environment, item)
		}
	}
	environment = append(environment, "DISPLAY=", "AGENT_BROWSER_SOCKET_DIR="+scratch, "AGENT_BROWSER_EXECUTABLE_PATH="+chrome, "AGENT_BROWSER_WINDOW_STREAM=1", "AGENT_BROWSER_DISPLAY_HELPER="+helper, "NO_COLOR=1")
	args := []string{"--config", config, "--session", "primary", "--json"}
	cli := func(success bool, command ...string) map[string]any {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		process := exec.CommandContext(ctx, driver, append(append([]string{}, args...), command...)...)
		process.Env = environment
		output, _ := process.CombinedOutput()
		var value map[string]any
		if json.Unmarshal(output, &value) != nil || value["success"] != success {
			t.Fatalf("CLI %v: %s", command, output)
		}
		return value
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'" }
	command := []string{"env"}
	for _, item := range environment {
		if strings.HasPrefix(item, "AGENT_BROWSER_") || strings.HasPrefix(item, "DISPLAY=") {
			command = append(command, quote(item))
		}
	}
	command = append(command, quote(driver), "--config", quote(config), "--session", "primary", "daemon")
	if status, body := call(t, engine, http.MethodPost, "/process/session/window-owner/exec", SessionExecuteRequest{Command: strings.Join(command, " "), RunAsync: true}); status != http.StatusAccepted {
		t.Fatalf("native owner start: %d %s", status, body)
	}
	awaitPath(t, filepath.Join(scratch, "primary.sock"))
	cli(true, "open", page.URL)
	view, _ := workspace.only(t, "window-owner", "primary")
	server := httptest.NewServer(engine)
	defer server.Close()
	path := "/process/session/window-owner/browser-views/" + view
	var stream *http.Response
	defer func() {
		if stream != nil {
			stream.Body.Close()
		}
	}()
	var records chan string
	var surface map[string]any
	const viewer = "baaaaabb-cccc-4ddd-8eee-ffff00000001"
	for _, size := range [][2]int{{780, 600}, {390, 844}, {1440, 900}, {800, 1200}} {
		if stream != nil {
			stream.Body.Close()
		}
		request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s%s/stream?width=%d&height=%d", server.URL, path, size[0], size[1]), nil)
		request.Header.Set("X-Ambit-Browser-Viewer", viewer)
		stream, err = server.Client().Do(request)
		if err != nil || stream.StatusCode != http.StatusOK {
			t.Fatalf("stream: %v", err)
		}
		records = streamRecords(t, stream.Body)
		var applied string
		for {
			record := nextRecord(t, records, 10*time.Second)
			if record["type"] == "presentation" && record["applied"] != nil {
				applied = record["applied"].(map[string]any)["generation"].(string)
			}
			if record["type"] != "frame" {
				continue
			}
			current := record["surface"].(map[string]any)
			if current["width"] != float64(size[0]*2) || current["height"] != float64(size[1]*2) {
				continue
			}
			if current["generation"] != applied {
				t.Fatal("new window frame preceded its applied layout")
			}
			data, err := base64.StdEncoding.DecodeString(record["data"].(string))
			if err != nil {
				t.Fatal(err)
			}
			image, err := jpeg.Decode(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			var chromeLight uint64
			for y := 4; y < 24; y++ {
				for x := image.Bounds().Dx() - 80; x < image.Bounds().Dx()-20; x++ {
					r, g, b, _ := image.At(x, y).RGBA()
					chromeLight += uint64((r + g + b) >> 8)
				}
			}
			if chromeLight/(20*60*3) < 16 {
				t.Fatalf("first resized frame has unpainted native chrome at %v", size)
			}
			r, g, b, _ := image.At(image.Bounds().Dx()/2, image.Bounds().Dy()-24).RGBA()
			if int(r>>8) < 10 || int(r>>8) > 30 || int(g>>8) < 65 || int(g>>8) > 95 || int(b>>8) < 35 || int(b>>8) > 60 {
				t.Fatalf("first resized frame has unpainted page pixels at %v: %d,%d,%d", size, r>>8, g>>8, b>>8)
			}
			surface = current
			break
		}
		cli(true, "snapshot")
		metrics := cli(true, "eval", "JSON.stringify({width:innerWidth,dpr:devicePixelRatio})")["data"].(map[string]any)["result"].(string)
		var geometry struct {
			Width int     `json:"width"`
			DPR   float64 `json:"dpr"`
		}
		if json.Unmarshal([]byte(metrics), &geometry) != nil || geometry.Width != size[0] || geometry.DPR != 2 {
			t.Fatalf("native page geometry %s", metrics)
		}
		t.Logf("first painted window at CSS%d×%d, DPR2", size[0], size[1])
	}
	cli(true, "mouse", "move", "40", "140")
	var pointer map[string]any
	for {
		record := nextRecord(t, records, 5*time.Second)
		if record["type"] == "pointer" && record["eventType"] == "move" && record["source"] == "agent" {
			pointer = record
			break
		}
	}
	if pointer["coordinateSpace"] != "display-pixels" || pointer["surfaceGeneration"] != surface["generation"] {
		t.Fatalf("agent pointer was not proven in window space: %v", pointer)
	}
	actual := cli(true, "eval", "JSON.stringify(window.actualPointer)")["data"].(map[string]any)["result"].(string)
	var coordinates map[string]float64
	if json.Unmarshal([]byte(actual), &coordinates) != nil || pointer["x"] != coordinates["x"]*2 || pointer["y"] != coordinates["y"]*2 {
		t.Fatalf("screen pointer mismatch: %v %s", pointer, actual)
	}
	cli(true, "click", "textarea")
	control := func(request any, status int) map[string]any {
		t.Helper()
		code, body := call(t, engine, http.MethodPost, path+"/control", request)
		var value map[string]any
		if code != status || json.Unmarshal(body, &value) != nil {
			t.Fatalf("control: %d %s", code, body)
		}
		return value
	}
	lease := control(map[string]any{"op": "acquire", "controllerId": browserFixtureController, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()}, http.StatusOK)
	if denied := cli(false, "get", "title"); denied["code"] != "browser_controlled_by_user" {
		t.Fatalf("missing custody gate: %v", denied)
	}
	paste := strings.Repeat("Unicode café 漢字 ✓\n", 6000)
	input := map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": 1, "expectedSurfaceGeneration": surface["generation"], "events": []map[string]any{{"type": "input_keyboard", "eventType": "insertText", "text": paste}}}
	if stale := control(input, http.StatusConflict); stale["code"] != "browser_control_surface_stale" {
		t.Fatalf("old window generation was not refused: %v", stale)
	}
	input["expectedSurfaceGeneration"] = lease["surface"].(map[string]any)["generation"]
	control(input, http.StatusOK)
	if duplicate := control(input, http.StatusOK); duplicate["status"] != "duplicate" {
		t.Fatalf("input replay: %v", duplicate)
	}
	control(map[string]any{"op": "release", "controllerId": browserFixtureController}, http.StatusOK)
	if refresh := cli(false, "get", "title"); refresh["code"] != "browser_observation_required" {
		t.Fatalf("missing handoff observation: %v", refresh)
	}
	cli(true, "snapshot")
	value := cli(true, "get", "value", "textarea")["data"].(map[string]any)["value"]
	if value != paste {
		t.Fatalf("atomic Unicode paste did not survive native handoff: got %d bytes", len(fmt.Sprint(value)))
	}
	// The native tab strip changes focus without calling the driver's tab
	// selection primitive. The following snapshot must follow actual focus.
	cli(true, "tab", "new", page.URL+"/second")
	tabController := "baaaaabb-cccc-4ddd-8eee-ffff00000003"
	tabLease := control(map[string]any{"op": "acquire", "controllerId": tabController, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()}, http.StatusOK)
	control(map[string]any{"op": "input", "controllerId": tabController, "sequence": 1,
		"expectedSurfaceGeneration": tabLease["surface"].(map[string]any)["generation"], "events": []map[string]any{
			{"type": "input_mouse", "eventType": "mousePressed", "x": 200, "y": 40, "button": "left", "buttons": 1},
			{"type": "input_mouse", "eventType": "mouseReleased", "x": 200, "y": 40, "button": "left", "buttons": 0},
		}}, http.StatusOK)
	control(map[string]any{"op": "release", "controllerId": tabController}, http.StatusOK)
	cli(true, "snapshot")
	if title := cli(true, "get", "title")["data"].(map[string]any)["title"]; title != "Window /" {
		t.Fatalf("native tab-strip selection left CDP on the cached page: %v", title)
	}
	for index, key := range []string{"Escape", "Enter"} {
		cli(true, "open", page.URL+"/modal")
		cli(true, "focus", "button")
		owner := fmt.Sprintf("baaaaabb-cccc-4ddd-8eee-ffff0000000%d", index+4)
		lease := control(map[string]any{"op": "acquire", "controllerId": owner, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()}, http.StatusOK)
		generation := lease["surface"].(map[string]any)["generation"]
		keys := func(key string) []map[string]any {
			return []map[string]any{{"type": "input_keyboard", "eventType": "keyDown", "key": key, "code": key}, {"type": "input_keyboard", "eventType": "keyUp", "key": key, "code": key}}
		}
		control(map[string]any{"op": "input", "controllerId": owner, "sequence": 1, "expectedSurfaceGeneration": generation, "events": keys("Enter")}, http.StatusOK)
		resized := control(map[string]any{"op": "input", "controllerId": owner, "sequence": 2, "expectedSurfaceGeneration": generation,
			"events": []map[string]any{{"type": "viewport", "width": 780 + index*20, "height": 600}}}, http.StatusOK)
		generation = resized["surface"].(map[string]any)["generation"]
		control(map[string]any{"op": "renew", "controllerId": owner, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()}, http.StatusOK)
		control(map[string]any{"op": "input", "controllerId": owner, "sequence": 3, "expectedSurfaceGeneration": generation, "events": keys(key)}, http.StatusOK)
		control(map[string]any{"op": "release", "controllerId": owner}, http.StatusOK)
		cli(true, "snapshot")
		answer := cli(true, "eval", "document.body.dataset.answer")["data"].(map[string]any)["result"]
		if answer != fmt.Sprint(key == "Enter") {
			t.Fatalf("native %s did not resolve the preserved dialog after resize: %v", key, answer)
		}
	}
	cli(true, "close")
}
