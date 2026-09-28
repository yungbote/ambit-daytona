// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// The agent channel route at this commit in front of the real driver: the
// host-bound file protocol starts the daemon inside a session, as a plan's
// first step does, and a host then speaks to that daemon through
// GET /process/session/:sessionId/browser-views/:viewId/agent/channel.
//
// Set AMBIT_TEST_BROWSER_EXECUTABLE (the driver), AMBIT_TEST_CHROME_EXECUTABLE,
// AMBIT_TEST_BROWSER_DISPLAY_HELPER, and AMBIT_TEST_AGENT_CHANNEL_EVIDENCE (a
// file the measurements are written to).
func TestRealAgentChannelRouteInFrontOfTheDriver(t *testing.T) {
	driver := os.Getenv("AMBIT_TEST_BROWSER_EXECUTABLE")
	chrome := os.Getenv("AMBIT_TEST_CHROME_EXECUTABLE")
	helper := os.Getenv("AMBIT_TEST_BROWSER_DISPLAY_HELPER")
	evidence := os.Getenv("AMBIT_TEST_AGENT_CHANNEL_EVIDENCE")
	// Asked for by name, like the control and media probes: a driver without the
	// agent endpoint (every retained image) is probed by those two alone.
	if os.Getenv("AMBIT_TEST_BROWSER_AGENT_CHANNEL") != "1" || driver == "" || chrome == "" || helper == "" {
		t.Skip("set AMBIT_TEST_BROWSER_AGENT_CHANNEL=1 and the real driver, Chrome and display helper paths")
	}
	driver, err := filepath.EvalSymlinks(driver)
	if err != nil {
		t.Fatal(err)
	}
	driverBytes, err := os.ReadFile(driver)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(driverBytes))
	report := map[string]any{"driver": driver, "driverSha256": digest}
	var closes []map[string]any

	scratch, err := os.MkdirTemp("", "agent-route-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(scratch) })
	socketDir := filepath.Join(scratch, "s")
	if err := os.Mkdir(socketDir, 0700); err != nil {
		t.Fatal(err)
	}
	engine, _ := newSessionEngine(t, t.TempDir(), func(controller *SessionController) {
		controller.browserExecutable = driver
		controller.browserSocketDir = socketDir
	})
	workspace := &browserWorkspace{engine: engine, socketDir: socketDir}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "no-store")
		switch r.URL.Path {
		case "/form":
			fmt.Fprint(w, `<!doctype html><title>Forms</title><main style="padding:16px"><form action="/results" method="get"><input id="q" name="q" aria-label="Search"><button id="go">Search</button></form><input id="name" aria-label="Name" style="width:400px"></main>`)
		case "/results":
			fmt.Fprint(w, `<!doctype html><title>Results</title><h1>Results</h1>`)
		default:
			fmt.Fprint(w, `<!doctype html><title>Home</title><h1>Home</h1>`)
		}
	}))
	defer site.Close()

	const namespace = "aaaabbbbcccc4dddeeeeffff00002222"
	const session = "agent-owner"
	actionID := uuid.NewString()
	workspace.open(t, session)
	directory := filepath.Join(scratch, "action")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'" }
	encode := func(value any) []byte {
		bytes, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return bytes
	}
	configPath := filepath.Join(scratch, "config.json")
	if err := os.WriteFile(configPath, encode(map[string]any{"version": 1, "namespace": namespace, "session": "browser", "requireSandbox": true, "captureDirectory": directory}), 0600); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(scratch, "request.json")
	if err := os.WriteFile(requestPath, append(encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "agent_browser_open", "arguments": map[string]any{"url": site.URL + "/"}}}), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	environment := []string{"AGENT_BROWSER_SOCKET_DIR=" + socketDir, "AGENT_BROWSER_EXECUTABLE_PATH=" + chrome,
		"AGENT_BROWSER_WINDOW_STREAM=1", "DISPLAY=", "AGENT_BROWSER_DISPLAY_HELPER=" + helper,
		"AGENT_BROWSER_NO_WEBMCP=1", "AGENT_BROWSER_IDLE_TIMEOUT_MS=120000", "NO_COLOR=1"}
	parts := []string{"env"}
	for _, entry := range environment {
		parts = append(parts, quote(entry))
	}
	parts = append(parts, quote(driver), "mcp", "--host-bound-config", quote(configPath), "<", quote(requestPath))
	status, body := call(t, engine, http.MethodPost, "/process/session/"+session+"/exec",
		SessionExecuteRequest{Command: strings.Join(parts, " "), RunAsync: false, SuppressInputEcho: true, CloseInputAfterCommand: true})
	var execution SessionExecuteResponse
	if status != http.StatusOK || json.Unmarshal(body, &execution) != nil || execution.ExitCode == nil || *execution.ExitCode != 0 || execution.Output == nil || !strings.Contains(*execution.Output, `"isError":false`) {
		t.Fatalf("the file protocol's first step failed: %d %s", status, body)
	}
	view, _ := workspace.only(t, session, "browser")
	server := workspace.serve(t)
	address := "ws" + strings.TrimPrefix(server.URL, "http") + "/process/session/" + session + "/browser-views/" + view + "/agent/channel"
	socketPath := filepath.Join(socketDir, "namespaces", namespace, "run", "browser.sock")

	// One channel through the route, or straight to the driver's socket.
	type exchange interface {
		send(frame []byte) error
		receive() (map[string]any, error)
		close()
	}
	dial := func() *websocket.Conn {
		t.Helper()
		connection, response, err := websocket.DefaultDialer.Dial(address, nil)
		if err != nil {
			t.Fatalf("agent channel dial: %v %v", err, response)
		}
		return connection
	}
	closeOf := func(connection *websocket.Conn) (int, string) {
		_ = connection.SetReadDeadline(time.Now().Add(15 * time.Second))
		for {
			_, _, err := connection.ReadMessage()
			if err == nil {
				continue
			}
			if closed, ok := err.(*websocket.CloseError); ok {
				return closed.Code, closed.Text
			}
			return 0, err.Error()
		}
	}
	routeFrame := func(connection *websocket.Conn, frame any) (map[string]any, time.Duration) {
		t.Helper()
		started := time.Now()
		if err := connection.WriteMessage(websocket.TextMessage, encode(frame)); err != nil {
			t.Fatal(err)
		}
		_ = connection.SetReadDeadline(time.Now().Add(60 * time.Second))
		kind, text, err := connection.ReadMessage()
		if err != nil || kind != websocket.TextMessage {
			t.Fatalf("agent reply: kind=%d err=%v", kind, err)
		}
		elapsed := time.Since(started)
		var reply map[string]any
		if err := json.Unmarshal(text, &reply); err != nil {
			t.Fatal(err)
		}
		return reply, elapsed
	}
	hello := func(id int, channel string) map[string]any {
		return map[string]any{"type": "hello", "id": id, "protocol": 1, "channel": channel,
			"binding":  map[string]any{"version": 1, "namespace": namespace, "session": "browser", "requireSandbox": true},
			"actionId": actionID, "ownerGeneration": "41"}
	}
	sequence := func(id int, steps []any) map[string]any {
		return map[string]any{"type": "sequence", "id": id, "actionId": actionID, "ownerGeneration": "41",
			"directory": directory, "steps": steps}
	}
	step := func(op string, arguments map[string]any) map[string]any {
		return map[string]any{"op": op, "arguments": arguments}
	}
	success := func(reply map[string]any, what string) {
		t.Helper()
		if reply["success"] != true {
			t.Fatalf("%s: %v", what, reply)
		}
	}

	// hello.
	channelA := uuid.NewString()
	route := dial()
	greeting, helloRTT := routeFrame(route, hello(1, channelA))
	success(greeting, "hello")
	data := greeting["data"].(map[string]any)
	if data["driverArtifactDigest"] != digest {
		t.Fatalf("the hello's driver digest %v is not the driver's %s", data["driverArtifactDigest"], digest)
	}
	report["hello"] = map[string]any{"roundTripUs": helloRTT.Microseconds(), "catalog": data["catalog"], "driverArtifactDigest": data["driverArtifactDigest"], "limits": data["limits"]}

	// A multi-step sequence with an observation and resolutions.
	frame := sequence(2, []any{
		step("agent_browser_open", map[string]any{"url": site.URL + "/form"}),
		step("agent_browser_get_title", map[string]any{}),
	})
	frame["observe"] = true
	frame["resolve"] = []string{"#name", "#go", "#q"}
	observed, observedRTT := routeFrame(route, frame)
	success(observed, "sequence with observe and resolve")
	steps := observed["steps"].([]any)
	if len(steps) != 2 || observed["observation"] == nil || len(observed["resolved"].([]any)) != 3 {
		t.Fatalf("sequence answered %v", observed)
	}
	page := observed["browser"].(map[string]any)["page"].(map[string]any)
	resolved := observed["resolved"].([]any)
	node := func(index int) any { return resolved[index].(map[string]any)["backendNodeId"] }
	report["sequence"] = map[string]any{"roundTripUs": observedRTT.Microseconds(), "timing": observed["timing"],
		"candidates": len(observed["observation"].(map[string]any)["candidates"].([]any))}

	// A judged fill, then a judged click that submits a GET form.
	fill := sequence(3, []any{map[string]any{"op": "agent_browser_fill", "arguments": map[string]any{"selector": "#name", "text": "Ada Lovelace"},
		"preconditions": map[string]any{"pageGeneration": page["pageGeneration"], "backendNodeId": node(0), "effects": "fill"}}})
	filled, fillRTT := routeFrame(route, fill)
	success(filled, "judged fill")
	landed := filled["steps"].([]any)[0].(map[string]any)["landed"].(map[string]any)
	if landed["target"].(map[string]any)["value"] != "Ada Lovelace" {
		t.Fatalf("the fill landed as %v", landed)
	}
	click := sequence(4, []any{map[string]any{"op": "agent_browser_click", "arguments": map[string]any{"selector": "#go"},
		"preconditions": map[string]any{"pageGeneration": page["pageGeneration"], "backendNodeId": node(1), "effects": "read"}}})
	clicked, clickRTT := routeFrame(route, click)
	success(clicked, "judged click")
	navigation := clicked["steps"].([]any)[0].(map[string]any)["landed"].(map[string]any)["navigation"].(map[string]any)
	if navigation["kind"] != "document" || navigation["httpStatus"] != float64(200) {
		t.Fatalf("the click landed as %v", clicked)
	}
	report["fill"] = map[string]any{"roundTripUs": fillRTT.Microseconds(), "timing": filled["timing"], "landed": landed}
	report["click"] = map[string]any{"roundTripUs": clickRTT.Microseconds(), "timing": clicked["timing"], "navigation": navigation}

	// The hop: the same frames through the route and straight to the socket.
	direct, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	directReader := bufio.NewReaderSize(direct, 64<<10)
	directFrame := func(frame map[string]any) (map[string]any, time.Duration) {
		t.Helper()
		members := encode(frame)
		line := append([]byte(`{"action":"ambit_browser_agent",`), members[1:]...)
		started := time.Now()
		if _, err := direct.Write(append(line, '\n')); err != nil {
			t.Fatal(err)
		}
		text, err := directReader.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(started)
		var reply map[string]any
		if err := json.Unmarshal(text, &reply); err != nil {
			t.Fatal(err)
		}
		return reply, elapsed
	}
	directGreeting, _ := directFrame(hello(1, uuid.NewString()))
	success(directGreeting, "direct hello")
	daemonUs := func(reply map[string]any) float64 {
		timing := reply["timing"].(map[string]any)
		return timing["queueUs"].(float64) + timing["opUs"].(float64) + timing["observeUs"].(float64)
	}
	var viaRoute, viaSocket, routeOverDaemon []float64
	for index := 0; index < 40; index++ {
		title := []any{step("agent_browser_get_title", map[string]any{})}
		routed, routedRTT := routeFrame(route, sequence(10+index, title))
		success(routed, "routed title")
		straight, straightRTT := directFrame(sequence(10+index, title))
		success(straight, "direct title")
		viaRoute = append(viaRoute, float64(routedRTT.Microseconds()))
		viaSocket = append(viaSocket, float64(straightRTT.Microseconds()))
		routeOverDaemon = append(routeOverDaemon, float64(routedRTT.Microseconds())-daemonUs(routed))
	}
	_ = direct.Close()
	quantile := func(values []float64, q float64) float64 {
		sorted := append([]float64(nil), values...)
		sort.Float64s(sorted)
		return sorted[int(q*float64(len(sorted)-1))]
	}
	report["hop"] = map[string]any{"frames": len(viaRoute),
		"routeRoundTripUs":   map[string]any{"p50": quantile(viaRoute, 0.5), "p95": quantile(viaRoute, 0.95)},
		"socketRoundTripUs":  map[string]any{"p50": quantile(viaSocket, 0.5), "p95": quantile(viaSocket, 0.95)},
		"routeAddedUs":       map[string]any{"p50": quantile(viaRoute, 0.5) - quantile(viaSocket, 0.5), "p95": quantile(viaRoute, 0.95) - quantile(viaSocket, 0.95)},
		"routeMinusDaemonUs": map[string]any{"p50": quantile(routeOverDaemon, 0.5), "p95": quantile(routeOverDaemon, 0.95)},
	}

	// A link dropped mid-sequence: the running step completes, nothing after
	// it starts, and a reopened channel reads the prefix from the ledger.
	if err := route.WriteMessage(websocket.TextMessage, encode(sequence(100, []any{
		step("agent_browser_wait_ms", map[string]any{"ms": 1500}),
		step("agent_browser_get_title", map[string]any{}),
	}))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	_ = route.Close()
	time.Sleep(2 * time.Second)
	reopened := dial()
	regreeting, _ := routeFrame(reopened, hello(1, uuid.NewString()))
	success(regreeting, "reopened hello")
	status100, _ := routeFrame(reopened, map[string]any{"type": "op_status", "id": 2, "actionId": actionID, "ownerGeneration": "41",
		"of": map[string]any{"channel": channelA, "id": 100}})
	success(status100, "op_status of the dropped frame")
	settled := status100["data"].(map[string]any)
	if settled["state"] != "settled" || len(settled["result"].(map[string]any)["steps"].([]any)) != 1 {
		t.Fatalf("the dropped frame's ledger entry is %v", settled)
	}
	report["dropped"] = map[string]any{"state": settled["state"], "stepsRun": 1}

	// A person takes control during a sequence: the typing stops and the
	// step says how far it got; the landing is pending.
	controller := uuid.NewString()
	// Up to 64 characters are typed key by key, one per 25 ms.
	long := strings.Repeat("abcdefghij", 6)
	typing := sequence(3, []any{map[string]any{"op": "agent_browser_open", "arguments": map[string]any{"url": site.URL + "/form"}}})
	reopenedOpen, _ := routeFrame(reopened, typing)
	success(reopenedOpen, "reopen the form")
	resolve := sequence(4, []any{})
	resolve["resolve"] = []string{"#name"}
	named, _ := routeFrame(reopened, resolve)
	success(named, "resolve the field")
	namedPage := named["browser"].(map[string]any)["page"].(map[string]any)
	field := named["resolved"].([]any)[0].(map[string]any)["backendNodeId"]
	if err := reopened.WriteMessage(websocket.TextMessage, encode(sequence(5, []any{map[string]any{"op": "agent_browser_fill",
		"arguments":     map[string]any{"selector": "#name", "text": long},
		"preconditions": map[string]any{"pageGeneration": namedPage["pageGeneration"], "backendNodeId": field, "effects": "fill"}}}))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	acquired, acquireBody := call(t, engine, http.MethodPost, "/process/session/"+session+"/browser-views/"+view+"/control",
		map[string]any{"op": "acquire", "controllerId": controller, "expiresAt": time.Now().Add(20 * time.Second).UnixMilli()})
	if acquired != http.StatusOK {
		t.Fatalf("take control = %d %s", acquired, acquireBody)
	}
	_ = reopened.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, text, err := reopened.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var interrupted map[string]any
	if err := json.Unmarshal(text, &interrupted); err != nil {
		t.Fatal(err)
	}
	stepFive := interrupted["steps"].([]any)[0].(map[string]any)
	response := stepFive["result"].(map[string]any)["structuredContent"].(map[string]any)["response"].(map[string]any)
	report["takeover"] = map[string]any{"code": response["code"], "data": response["data"], "landed": stepFive["landed"], "timing": stepFive["timing"]}
	if response["code"] != "browser_operation_interrupted" {
		t.Fatalf("a takeover during typing answered %v", interrupted)
	}
	released, releaseBody := call(t, engine, http.MethodPost, "/process/session/"+session+"/browser-views/"+view+"/control",
		map[string]any{"op": "release", "controllerId": controller})
	if released != http.StatusOK {
		t.Fatalf("release control = %d %s", released, releaseBody)
	}
	_ = reopened.Close()

	// The route's own refusals and closes.
	refusal := func(name string, raw []byte) {
		connection := dial()
		defer connection.Close()
		greeting, _ := routeFrame(connection, hello(1, uuid.NewString()))
		success(greeting, "hello before "+name)
		if err := connection.WriteMessage(websocket.TextMessage, raw); err != nil {
			t.Fatal(err)
		}
		code, reason := closeOf(connection)
		closes = append(closes, map[string]any{"case": name, "code": code, "reason": reason})
	}
	refusal("a frame naming an action", []byte(`{"action":"ambit_browser_control","type":"op_status","id":2,"actionId":"`+actionID+`","ownerGeneration":"41"}`))
	refusal("a duplicate key", []byte(`{"type":"op_status","id":2,"id":3,"actionId":"`+actionID+`","ownerGeneration":"41"}`))
	refusal("an id that does not increase", []byte(`{"type":"op_status","id":1,"actionId":"`+actionID+`","ownerGeneration":"41"}`))
	refusal("a request over 2 MiB", append(append([]byte(`{"type":"op_status","id":2,"actionId":"`+actionID+`","ownerGeneration":"41","pad":"`), []byte(strings.Repeat("p", 2<<20))...), []byte(`"}`)...))

	// Four frames in flight, answered in order.
	pipelined := dial()
	greeting, _ = routeFrame(pipelined, hello(1, uuid.NewString()))
	success(greeting, "hello before pipelining")
	started := time.Now()
	for id := 2; id <= 9; id++ {
		if err := pipelined.WriteMessage(websocket.TextMessage, encode(map[string]any{"type": "op_status", "id": id, "actionId": actionID, "ownerGeneration": "41"})); err != nil {
			t.Fatal(err)
		}
	}
	var order []any
	for range 8 {
		_ = pipelined.SetReadDeadline(time.Now().Add(15 * time.Second))
		_, text, err := pipelined.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		var reply map[string]any
		_ = json.Unmarshal(text, &reply)
		order = append(order, reply["id"])
	}
	report["pipelined"] = map[string]any{"frames": 8, "order": order, "elapsedUs": time.Since(started).Microseconds()}

	// What ends a view, and what does not. A command on the daemon's own
	// socket, as its other clients send them.
	daemonCommand := func(command map[string]any) map[string]any {
		t.Helper()
		connection, err := net.Dial("unix", socketPath)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if _, err := connection.Write(append(encode(command), '\n')); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(connection).ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var reply map[string]any
		if err := json.Unmarshal(line, &reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	// Closing the browser keeps the daemon and its stream listener: the view
	// and the channel stay.
	closed, _ := routeFrame(pipelined, sequence(10, []any{step("agent_browser_close", map[string]any{})}))
	success(closed, "close the browser")
	if current, _ := workspace.only(t, session, "browser"); current != view {
		t.Fatalf("closing the browser replaced the view %s with %s", view, current)
	}
	reopenedBrowser, _ := routeFrame(pipelined, sequence(11, []any{step("agent_browser_open", map[string]any{"url": site.URL + "/"})}))
	success(reopenedBrowser, "the next step launches the browser again on the same channel")
	report["browserClosed"] = map[string]any{"viewKept": true, "channelKept": true}
	// Switching the stream off closes the listener the view is proved by
	// while the daemon lives: the route closes 4410 at its next check.
	disabled := time.Now()
	if reply := daemonCommand(map[string]any{"id": "stream-off", "action": "stream_disable"}); reply["success"] != true {
		t.Fatalf("stream_disable answered %v", reply)
	}
	code, reason := closeOf(pipelined)
	closes = append(closes, map[string]any{"case": "the stream switched off while the daemon lives", "code": code, "reason": reason,
		"afterUs": time.Since(disabled).Microseconds()})
	// A CLI outside the host binding, with other launch settings, restarts
	// the daemon it reaches ("restartedBackground"): the link is lost before
	// the view's one-second check, so the route closes 1011.
	if reply := daemonCommand(map[string]any{"id": "stream-on", "action": "stream_enable"}); reply["success"] != true {
		t.Fatalf("stream_enable answered %v", reply)
	}
	renewed, _ := workspace.only(t, session, "browser")
	if renewed == view {
		t.Fatalf("a new stream listener kept the view id %s", view)
	}
	renewedAddress := "ws" + strings.TrimPrefix(server.URL, "http") + "/process/session/" + session + "/browser-views/" + renewed + "/agent/channel"
	last, dialed, err := websocket.DefaultDialer.Dial(renewedAddress, nil)
	if err != nil {
		t.Fatalf("agent channel dial on the renewed view: %v %v", err, dialed)
	}
	greeting, _ = routeFrame(last, hello(1, uuid.NewString()))
	success(greeting, "hello on the renewed view")
	outside := exec.Command(driver, "--session", "browser", "--json", "stream", "status")
	outside.Env = append(append([]string{}, environment...), "AGENT_BROWSER_NAMESPACE="+namespace, "PATH="+os.Getenv("PATH"))
	cliOutput, err := outside.CombinedOutput()
	if err != nil {
		t.Fatalf("stream status: %v %s", err, cliOutput)
	}
	code, reason = closeOf(last)
	closes = append(closes, map[string]any{"case": "a CLI outside the host binding restarted the daemon", "code": code, "reason": reason,
		"cli": strings.TrimSpace(string(cliOutput))})
	report["closes"] = closes

	if evidence != "" {
		written, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(evidence, written, 0644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%s", encode(report))
}
