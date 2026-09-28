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

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// A textarea to type into and enough height that scrolling repaints.
const oldDriverProbePage = `<!doctype html><title>Old driver</title><body style="margin:0;font:16px sans-serif">` +
	`<textarea id=notes style="width:600px;height:120px"></textarea>` +
	`<div style="height:4000px;background:linear-gradient(#fff,#36c)"></div></body>`

// TestRealOldDriverBehindTheNewToolbox runs a retained workspace's own (older) driver behind this
// toolbox, as every retained workspace runs after the runner changes. The live frontend declares
// `video=` and `audio=` on every viewer upgrade and this toolbox forwards both: the viewer channel must
// still carry the driver's JPEG frames, with no media offer and no close. The control channel must take
// control, type and hand back. The agent route must answer as the r6.1 agent-channel contract documents
// for a driver without the endpoint: a reply with the frame's id and browser_observation_required when
// the driver owes an observation, otherwise a close 1011 (both are transport failures, so the host keeps
// the file protocol). Skipped unless asked for by name with the real executables.
func TestRealOldDriverBehindTheNewToolbox(t *testing.T) {
	driver, chrome, helper := os.Getenv("AMBIT_TEST_BROWSER_EXECUTABLE"), os.Getenv("AMBIT_TEST_CHROME_EXECUTABLE"), os.Getenv("AMBIT_TEST_BROWSER_DISPLAY_HELPER")
	if os.Getenv("AMBIT_TEST_BROWSER_OLD_DRIVER") != "1" || driver == "" || chrome == "" || helper == "" {
		t.Skip("set AMBIT_TEST_BROWSER_OLD_DRIVER=1 and the real (older) driver, Chrome and display helper paths")
	}
	scratch, err := os.MkdirTemp("", "old-driver-")
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
	workspace.open(t, "old-driver-owner")
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, oldDriverProbePage)
	}))
	defer page.Close()
	var environment []string
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "AGENT_BROWSER_") && !strings.HasPrefix(item, "DISPLAY=") {
			environment = append(environment, item)
		}
	}
	environment = append(environment, "DISPLAY=", "AGENT_BROWSER_SOCKET_DIR="+scratch, "AGENT_BROWSER_EXECUTABLE_PATH="+chrome,
		"AGENT_BROWSER_WINDOW_STREAM=1", "AGENT_BROWSER_DISPLAY_HELPER="+helper, "NO_COLOR=1")
	args := []string{"--config", config, "--session", "primary", "--json"}
	cli := func(command ...string) map[string]any {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		process := exec.CommandContext(ctx, driver, append(append([]string{}, args...), command...)...)
		process.Env = environment
		output, _ := process.CombinedOutput()
		var value map[string]any
		if json.Unmarshal(output, &value) != nil || value["success"] != true {
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
	if status, body := call(t, engine, http.MethodPost, "/process/session/old-driver-owner/exec", SessionExecuteRequest{Command: strings.Join(command, " "), RunAsync: true}); status != http.StatusAccepted {
		t.Fatalf("native owner start: %d %s", status, body)
	}
	awaitPath(t, filepath.Join(scratch, "primary.sock"))
	cli("open", page.URL)
	view, _ := workspace.only(t, "old-driver-owner", "primary")
	server := httptest.NewServer(engine)
	defer server.Close()
	path := "/process/session/old-driver-owner/browser-views/" + view
	base := "ws" + strings.TrimPrefix(server.URL, "http") + path
	report := map[string]any{}

	// The viewer channel with the declaration the live frontend sends.
	declaration := "frames=binary&cursor=viewer&visible=crop&video=av1-444,av1&audio=opus&width=920&height=944&frameWindow=4"
	viewer := dialMediaViewer(t, base+"/channel?"+declaration, "baaaaabb-cccc-4ddd-8eee-ffff00000201")
	first := viewer.await(t, 0, "first JPEG frame", 20*time.Second, func(m mediaMessage) bool { return m.frame != nil })
	for index := 0; index < 10; index++ {
		cli("scroll", "down", "300")
		time.Sleep(150 * time.Millisecond)
	}

	// Control: take it, type key by key, hand it back.
	control := func(request any, status int) map[string]any {
		t.Helper()
		code, body := call(t, engine, http.MethodPost, path+"/control", request)
		var value map[string]any
		if code != status || json.Unmarshal(body, &value) != nil {
			t.Fatalf("control: %d %s", code, body)
		}
		return value
	}
	cli("click", "#notes")
	lease := control(map[string]any{"op": "acquire", "controllerId": browserFixtureController, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()}, http.StatusOK)
	generation := lease["surface"].(map[string]any)["generation"]
	typed := "old driver"
	for index, letter := range typed {
		key, code := string(letter), "Key"+strings.ToUpper(string(letter))
		if letter == ' ' {
			code = "Space"
		}
		control(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": index + 1, "expectedSurfaceGeneration": generation,
			"events": []map[string]any{
				{"type": "input_keyboard", "eventType": "keyDown", "key": key, "text": key, "code": code},
				{"type": "input_keyboard", "eventType": "keyUp", "key": key, "code": code}}}, http.StatusOK)
		time.Sleep(30 * time.Millisecond)
	}
	control(map[string]any{"op": "release", "controllerId": browserFixtureController}, http.StatusOK)

	// The agent route while the driver owes an observation, then after one.
	owing := oldDriverAgentHello(base + "/agent/channel")
	cli("snapshot")
	value := cli("get", "value", "#notes")["data"].(map[string]any)["value"]
	observed := oldDriverAgentHello(base + "/agent/channel")

	// Still open, still painting.
	mark := viewer.count()
	cli("scroll", "up", "600")
	viewer.await(t, mark, "a frame after the agent route", 15*time.Second, func(m mediaMessage) bool { return m.frame != nil })
	var offers []string
	frames := 0
	for _, m := range viewer.all() {
		switch {
		case m.frame != nil:
			frames++
		case m.unit != nil, m.packet != nil, m.record["type"] == "video", m.record["type"] == "audio":
			encoded, _ := json.Marshal(m.record)
			offers = append(offers, string(encoded))
		}
	}
	select {
	case closing := <-viewer.closing:
		t.Fatalf("the viewer channel closed during the probe: %v", closing)
	default:
	}
	cli("close")
	report["declaration"] = declaration
	report["firstFrameBytes"] = first.bytes
	report["frames"] = frames
	report["mediaRecords"] = offers
	report["control"] = map[string]any{"leaseGeneration": generation, "typed": typed, "pageHolds": value}
	report["agentRoute"] = map[string]any{"owingObservation": owing, "afterObservation": observed}
	report["viewerClose"] = viewer.closed(t, 15*time.Second)
	encoded, _ := json.MarshalIndent(report, "", "  ")
	t.Logf("OLD_DRIVER %s", encoded)

	if frames < 5 {
		t.Fatalf("only %d JPEG frames reached the viewer", frames)
	}
	if len(offers) != 0 {
		t.Fatalf("an older driver was offered or sent media: %v", offers)
	}
	if value != typed {
		t.Fatalf("typed %q through control, the page holds %q", typed, value)
	}
	for name, answer := range map[string]map[string]any{"owing an observation": owing, "after an observation": observed} {
		if documentedOldDriverAgentAnswer(answer) == "" {
			t.Fatalf("the agent route %s answered %v, which the contract does not document for a driver without the endpoint", name, answer)
		}
	}
}

// oldDriverAgentHello opens the agent route, sends one hello and returns exactly what came back: a
// relayed reply, or the close.
func oldDriverAgentHello(address string) map[string]any {
	connection, response, err := websocket.DefaultDialer.Dial(address, nil)
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		return map[string]any{"dialError": err.Error(), "status": status}
	}
	defer connection.Close()
	frame, _ := json.Marshal(map[string]any{"type": "hello", "id": 1, "protocol": 1, "channel": uuid.NewString(),
		"binding": map[string]any{"version": 1, "session": "primary", "requireSandbox": true}})
	started := time.Now()
	if err := connection.WriteMessage(websocket.TextMessage, frame); err != nil {
		return map[string]any{"writeError": err.Error()}
	}
	_ = connection.SetReadDeadline(time.Now().Add(15 * time.Second))
	kind, data, err := connection.ReadMessage()
	answer := map[string]any{"ms": time.Since(started).Milliseconds()}
	if err != nil {
		answer["error"] = err.Error()
		if closed, ok := err.(*websocket.CloseError); ok {
			answer["closeCode"], answer["closeReason"] = closed.Code, closed.Text
		}
		return answer
	}
	var reply map[string]any
	_ = json.Unmarshal(data, &reply)
	answer["messageType"], answer["reply"] = kind, reply
	return answer
}

// documentedOldDriverAgentAnswer names which of the contract's two answers this is, or "".
func documentedOldDriverAgentAnswer(answer map[string]any) string {
	if reply, ok := answer["reply"].(map[string]any); ok {
		if reply["id"] == float64(1) && reply["success"] == false && reply["code"] == "browser_observation_required" {
			return "reply_browser_observation_required"
		}
		return ""
	}
	if answer["closeCode"] == websocket.CloseInternalServerErr {
		return "closed_1011"
	}
	return ""
}
