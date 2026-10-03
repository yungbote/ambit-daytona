// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The page a person types into: one textarea that takes every key.
const burstPage = `<!doctype html><meta charset=utf-8><title>Burst</title><style>body{margin:0}` +
	`#notes{position:fixed;left:20px;top:20px;width:860px;height:560px;font:14px monospace}</style>` +
	`<textarea id=notes spellcheck=false autocomplete=off autocapitalize=off></textarea>`

// TestRealBrowserControlBurstThroughTheToolbox types into the real driver,
// display helper and Chrome the way the production dock sends a person's
// keys: every key is a keyDown and a keyUp, one frame each while the line is
// idle, while a viewer channel paints the window's video and plays its sound.
// It measures a key alone, steady typing at 10, 30 and 100 keys a second,
// 5,000 characters written as fast as the channel takes them, the same 5,000
// under the dock's own window of 64 unanswered frames, and production's case
// of 2026-09-29: Control+L and a 1,500-character address typed at about 200
// characters a second. Each scenario reports how every frame was answered,
// where the driver says the time went, how the viewer's pictures and sound
// kept up, and whether the text that arrived is exactly the text typed.
//
// AMBIT_TEST_BURST_LINE selects the line under test: "toolbox" (default), the
// toolbox's control channel in front of the driver; "driver", the driver's
// own control socket, as the toolbox dials it. AMBIT_TEST_BURST_SCENARIOS
// narrows the scenarios (comma separated names). It runs when
// AMBIT_TEST_BROWSER_CONTROL_BURST=1 and AMBIT_TEST_BROWSER_EXECUTABLE,
// AMBIT_TEST_CHROME_EXECUTABLE and AMBIT_TEST_BROWSER_DISPLAY_HELPER name a
// workspace image's own driver, Chrome and helper; AMBIT_TEST_BURST_REPORT,
// when set, receives the report as JSON.
func TestRealBrowserControlBurstThroughTheToolbox(t *testing.T) {
	driver, chrome, helper := os.Getenv("AMBIT_TEST_BROWSER_EXECUTABLE"), os.Getenv("AMBIT_TEST_CHROME_EXECUTABLE"), os.Getenv("AMBIT_TEST_BROWSER_DISPLAY_HELPER")
	if os.Getenv("AMBIT_TEST_BROWSER_CONTROL_BURST") != "1" || driver == "" || chrome == "" || helper == "" {
		t.Skip("set AMBIT_TEST_BROWSER_CONTROL_BURST=1 and the real driver, Chrome and display helper paths")
	}
	line := os.Getenv("AMBIT_TEST_BURST_LINE")
	if line == "" {
		line = "toolbox"
	}
	selected := map[string]bool{}
	for _, name := range strings.Split(os.Getenv("AMBIT_TEST_BURST_SCENARIOS"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			selected[name] = true
		}
	}
	runs := func(name string) bool { return len(selected) == 0 || selected[name] }

	scratch, err := os.MkdirTemp("", "burst-")
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
	workspace.open(t, "burst-owner")
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, burstPage)
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
	attempt := func(command ...string) (map[string]any, []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		process := exec.CommandContext(ctx, driver, append(append([]string{}, args...), command...)...)
		process.Env = environment
		output, _ := process.CombinedOutput()
		var value map[string]any
		_ = json.Unmarshal(output, &value)
		return value, output
	}
	cli := func(command ...string) map[string]any {
		t.Helper()
		value, output := attempt(command...)
		if value["success"] != true {
			t.Fatalf("CLI %v: %s", command, output)
		}
		return value
	}
	evaluate := func(script string) string {
		t.Helper()
		result, _ := cli("eval", script)["data"].(map[string]any)["result"].(string)
		return result
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'" }
	command := []string{"env"}
	for _, item := range environment {
		if strings.HasPrefix(item, "AGENT_BROWSER_") || strings.HasPrefix(item, "DISPLAY=") {
			command = append(command, quote(item))
		}
	}
	command = append(command, quote(driver), "--config", quote(config), "--session", "primary", "daemon")
	if status, body := call(t, engine, http.MethodPost, "/process/session/burst-owner/exec", SessionExecuteRequest{Command: strings.Join(command, " "), RunAsync: true}); status != http.StatusAccepted {
		t.Fatalf("native owner start: %d %s", status, body)
	}
	awaitPath(t, filepath.Join(scratch, "primary.sock"))
	cli("open", page.URL)
	var viewport struct{ X, Y, DPR float64 }
	placement := evaluate("JSON.stringify({x:screenX+(outerWidth-innerWidth)/2,y:screenY+outerHeight-innerHeight,dpr:devicePixelRatio})")
	if json.Unmarshal([]byte(placement), &viewport) != nil || viewport.DPR <= 0 {
		t.Fatalf("page placement: %q", placement)
	}
	view, _ := workspace.only(t, "burst-owner", "primary")
	server := httptest.NewServer(engine)
	defer server.Close()
	path := "/process/session/burst-owner/browser-views/" + view
	base := "ws" + strings.TrimPrefix(server.URL, "http") + path

	// The dock's viewer: video and sound, every unit acknowledged on arrival.
	viewer := dialMediaViewer(t, base+"/channel?frames=binary&cursor=viewer&visible=crop&video=av1-444,av1&audio=opus&width=920&height=944&frameWindow=4",
		"baaaaabb-cccc-4ddd-8eee-ffff00000401")
	// A driver that offers video paints with it; an older one paints JPEG
	// frames, which the viewer acknowledges the same way.
	viewer.await(t, 0, "first picture", 20*time.Second, func(m mediaMessage) bool { return m.frame != nil || m.unit != nil })
	if _, ok := viewer.within(0, 5*time.Second, func(m mediaMessage) bool { return m.record["type"] == "video" && m.record["state"] == "available" }); ok {
		mark := viewer.count()
		viewer.send(t, map[string]any{"type": "video", "enabled": true, "generation": 1})
		viewer.await(t, mark, "first key unit", 20*time.Second, func(m mediaMessage) bool { return m.unit != nil && m.unit["key"] == true })
	}
	if _, ok := viewer.within(0, 5*time.Second, func(m mediaMessage) bool { return m.record["type"] == "audio" && m.record["state"] == "available" }); ok {
		viewer.send(t, map[string]any{"type": "audio", "enabled": true, "generation": 1})
	}

	var control burstLine
	switch line {
	case "toolbox":
		control = dialSustainedControl(t, base+"/control/channel")
	case "driver":
		control = dialBurstDriver(t, filepath.Join(scratch, "primary.sock"))
	default:
		t.Fatalf("AMBIT_TEST_BURST_LINE=%q names no line", line)
	}
	report := map[string]any{"line": line, "driver": driver, "helper": helper}
	scenarios := map[string]any{}
	report["scenarios"] = scenarios
	t.Cleanup(func() {
		encoded, _ := json.MarshalIndent(report, "", "  ")
		t.Logf("BURST %s", encoded)
		if output := os.Getenv("AMBIT_TEST_BURST_REPORT"); output != "" {
			_ = os.WriteFile(output, encoded, 0644)
		}
	})

	// One take of control per scenario, as the dock's is: acquired over
	// POST, answered in band, renewed in band while the scenario runs.
	take := func() *burstLease {
		t.Helper()
		lease := &burstLease{controller: uuid.NewString()}
		status, body := call(t, engine, http.MethodPost, path+"/control", map[string]any{"op": "acquire", "controllerId": lease.controller, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()})
		var acquired struct {
			Surface struct {
				Generation string `json:"generation"`
			} `json:"surface"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &acquired) != nil || acquired.Surface.Generation == "" {
			t.Fatalf("acquire: %d %s", status, body)
		}
		lease.generation = acquired.Surface.Generation
		lease.stopRenewal = control.renewEvery(lease.controller, 5*time.Second)
		return lease
	}
	release := func(lease *burstLease) map[string]any {
		t.Helper()
		lease.stopRenewal()
		status, body := call(t, engine, http.MethodPost, path+"/control", map[string]any{"op": "release", "controllerId": lease.controller})
		return map[string]any{"status": status, "body": string(body)}
	}
	input := func(lease *burstLease, events ...map[string]any) *sustainedPending {
		lease.sequence++
		return control.send(map[string]any{"op": "input", "controllerId": lease.controller, "sequence": lease.sequence,
			"expectedSurfaceGeneration": lease.generation, "events": events})
	}
	clickNotes := func(lease *burstLease) {
		t.Helper()
		x, y := (viewport.X+300)*viewport.DPR, (viewport.Y+100)*viewport.DPR
		for _, pending := range []*sustainedPending{
			input(lease, map[string]any{"type": "input_mouse", "eventType": "mousePressed", "x": x, "y": y, "button": "left", "buttons": 1, "clickCount": 1}),
			input(lease, map[string]any{"type": "input_mouse", "eventType": "mouseReleased", "x": x, "y": y, "button": "left", "buttons": 0, "clickCount": 1}),
		} {
			if reply := pending.await(t, 15*time.Second); !reply.ok() {
				t.Fatalf("click: %s", reply.raw)
			}
		}
	}
	// The agent observes the page again after a person's control. Chrome may
	// still be taking keys the display already acknowledged, and until it
	// answers the driver cannot tell which page is in front: how long that
	// lasts is reported, never waited out silently.
	observe := func(result map[string]any) {
		t.Helper()
		released := time.Now()
		for {
			value, output := attempt("snapshot")
			if value["success"] == true {
				result["agentObservedAfterReleaseMs"] = time.Since(released).Milliseconds()
				return
			}
			if value["code"] != "browser_active_page_ambiguous" || time.Since(released) > 30*time.Second {
				t.Fatalf("CLI snapshot %v after release: %s", time.Since(released), output)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	notes := func(result map[string]any) string {
		t.Helper()
		observe(result)
		value, _ := cli("get", "value", "#notes")["data"].(map[string]any)["value"].(string)
		return value
	}
	// Types text into the textarea with send, and states how it arrived.
	textarea := func(name, text string, send func(lease *burstLease, text string) []*sustainedPending) {
		t.Helper()
		evaluate("document.querySelector('#notes').value='';'cleared'")
		lease := take()
		clickNotes(lease)
		mark := viewer.count()
		sent := send(lease, text)
		result := summarizeBurst(sent, 180*time.Second)
		result["viewer"] = summarizeBurstViewer(viewer.since(mark))
		result["release"] = release(lease)
		arrived := notes(result)
		result["typedCharacters"], result["arrivedCharacters"] = len([]rune(text)), len([]rune(arrived))
		result["exact"], result["firstDifference"] = arrived == text, firstDifference(text, arrived)
		scenarios[name] = result
		t.Logf("%s: %v", name, burstHeadline(result))
	}

	if runs("isolated") {
		textarea("isolated", strings.Repeat("abcdefghij", 3), func(lease *burstLease, text string) []*sustainedPending {
			var sent []*sustainedPending
			for _, letter := range text {
				key := burstKey(letter)
				down, up := input(lease, key.down()), input(lease, key.up())
				down.await(t, 15*time.Second)
				up.await(t, 15*time.Second)
				sent = append(sent, down, up)
				time.Sleep(200 * time.Millisecond)
			}
			return sent
		})
	}
	for _, rate := range []int{10, 30, 100} {
		name := fmt.Sprintf("steady-%d-keys-per-second", rate)
		if !runs(name) {
			continue
		}
		textarea(name, burstText(4*rate, int64(rate)), func(lease *burstLease, text string) []*sustainedPending {
			interval := time.Second / time.Duration(rate)
			var sent []*sustainedPending
			start := time.Now()
			for index, letter := range []rune(text) {
				key := burstKey(letter)
				time.Sleep(time.Until(start.Add(time.Duration(index) * interval)))
				sent = append(sent, input(lease, key.down()))
				time.Sleep(time.Until(start.Add(time.Duration(index)*interval + interval/3)))
				sent = append(sent, input(lease, key.up()))
			}
			return sent
		})
	}
	if runs("burst") {
		// Every frame written as soon as the last write returned: only the
		// channel's own backpressure paces the sender.
		textarea("burst", burstText(5000, 5000), func(lease *burstLease, text string) []*sustainedPending {
			sent := make([]*sustainedPending, 0, 2*len(text))
			for _, letter := range text {
				key := burstKey(letter)
				sent = append(sent, input(lease, key.down()), input(lease, key.up()))
			}
			return sent
		})
	}
	if runs("dock-window") {
		// The dock's own line: at most 64 frames unanswered, and whatever
		// arrived meanwhile leaves in one frame of up to 64 events.
		textarea("dock-window", burstText(5000, 5001), func(lease *burstLease, text string) []*sustainedPending {
			var events []map[string]any
			for _, letter := range text {
				key := burstKey(letter)
				events = append(events, key.down(), key.up())
			}
			return windowed(events, 64, 64, func(batch []map[string]any) *sustainedPending { return input(lease, batch...) })
		})
	}
	if runs("address-bar") {
		// Production's case: Control+L, then a long address typed at about
		// 200 characters a second, then Enter, one frame per key event.
		address := productionAddress()
		lease := take()
		clickNotes(lease)
		mark := viewer.count()
		var sent []*sustainedPending
		ctrl := map[string]any{"type": "input_keyboard", "key": "Control", "code": "ControlLeft", "windowsVirtualKeyCode": 17}
		letterL := map[string]any{"type": "input_keyboard", "key": "l", "code": "KeyL", "windowsVirtualKeyCode": 76}
		for _, event := range []map[string]any{
			with(ctrl, "keyDown", 2), with(letterL, "keyDown", 2), with(letterL, "keyUp", 2), with(ctrl, "keyUp", 0),
		} {
			sent = append(sent, input(lease, event))
		}
		time.Sleep(500 * time.Millisecond)
		pace := time.NewTicker(2500 * time.Microsecond)
		for _, letter := range address {
			key := burstKey(letter)
			<-pace.C
			sent = append(sent, input(lease, key.down()))
			<-pace.C
			sent = append(sent, input(lease, key.up()))
		}
		pace.Stop()
		enter := map[string]any{"type": "input_keyboard", "key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13, "modifiers": 0}
		sent = append(sent, input(lease, with(enter, "keyDown", 0, "\r")), input(lease, with(enter, "keyUp", 0)))
		result := summarizeBurst(sent, 180*time.Second)
		time.Sleep(2 * time.Second)
		result["viewer"] = summarizeBurstViewer(viewer.since(mark))
		result["release"] = release(lease)
		observe(result)
		arrived := evaluate("decodeURIComponent(location.href)")
		result["typedCharacters"], result["arrivedCharacters"] = len(address), len(arrived)
		result["exact"], result["firstDifference"] = arrived == address, firstDifference(address, arrived)
		scenarios["address-bar"] = result
		t.Logf("address-bar: %v", burstHeadline(result))
	}
	cli("close")
}

// productionAddress is the address production's probe typed on 2026-09-29
// (sound-colour.mjs): eight colour bars and a PLAY button, as a data URL.
func productionAddress() string {
	bars := [][3]int{{255, 255, 255}, {255, 255, 0}, {0, 255, 255}, {0, 255, 0}, {255, 0, 255}, {255, 0, 0}, {0, 0, 255}, {128, 128, 128}}
	var cells strings.Builder
	for _, c := range bars {
		fmt.Fprintf(&cells, `<div style="flex:1;background:rgb(%d,%d,%d)"></div>`, c[0], c[1], c[2])
	}
	return `data:text/html,<!doctype html><meta charset=utf-8><title>bars</title><body style="margin:0;background:#000"><div style="display:flex;height:100vh">` +
		cells.String() + `</div><button id=p style="position:fixed;left:0;top:0;width:220px;height:120px;font:40px sans-serif" onclick="const c=new AudioContext();const o=c.createOscillator();o.frequency.value=440;const g=c.createGain();g.gain.value=0.2;o.connect(g).connect(c.destination);o.start();this.textContent='TONE'">PLAY</button></body>`
}

// burstLine is the control line a scenario types on: the toolbox's channel
// or the driver's own socket.
type burstLine interface {
	send(command map[string]any) *sustainedPending
	renewEvery(controller string, every time.Duration) func()
}

type burstLease struct {
	controller  string
	generation  string
	sequence    uint64
	stopRenewal func()
}

// burstDriver is the driver's control socket as the toolbox dials it: one
// command line after another, answered one line each in order. Its answers
// are restated in the channel's envelope so one reply model reads both.
type burstDriver struct {
	socket  net.Conn
	writes  sync.Mutex
	mu      sync.Mutex
	waiting []*sustainedPending
}

func dialBurstDriver(t *testing.T, socketPath string) *burstDriver {
	t.Helper()
	socket, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial the driver: %v", err)
	}
	d := &burstDriver{socket: socket}
	t.Cleanup(func() { _ = socket.Close() })
	go d.read()
	return d
}

func (d *burstDriver) read() {
	reader := bufio.NewReaderSize(d.socket, 1<<20)
	for {
		line, err := reader.ReadBytes('\n')
		at := time.Now()
		d.mu.Lock()
		if err != nil {
			for _, pending := range d.waiting {
				close(pending.answered)
			}
			d.waiting = nil
			d.mu.Unlock()
			return
		}
		if len(d.waiting) == 0 {
			d.mu.Unlock()
			continue
		}
		pending := d.waiting[0]
		d.waiting = d.waiting[1:]
		d.mu.Unlock()
		var answer struct {
			Success bool            `json:"success"`
			Code    string          `json:"code"`
			Data    json.RawMessage `json:"data"`
		}
		var envelope []byte
		if json.Unmarshal(line, &answer) != nil {
			envelope, _ = json.Marshal(map[string]any{"ok": false, "status": 502, "error": map[string]any{"code": "undecodable_driver_line"}})
		} else if answer.Success {
			envelope, _ = json.Marshal(map[string]any{"ok": true, "result": answer.Data})
		} else {
			envelope, _ = json.Marshal(map[string]any{"ok": false, "status": 409, "error": map[string]any{"code": answer.Code}})
		}
		pending.answered <- sustainedReply{at, envelope}
	}
}

func (d *burstDriver) send(command map[string]any) *sustainedPending {
	document := map[string]any{"action": "ambit_browser_control"}
	for key, value := range command {
		document[key] = value
	}
	encoded, _ := json.Marshal(document)
	sequence, _ := command["sequence"].(uint64)
	pending := &sustainedPending{sequence: sequence, answered: make(chan sustainedReply, 1)}
	d.writes.Lock()
	defer d.writes.Unlock()
	d.mu.Lock()
	pending.sent = time.Now()
	d.waiting = append(d.waiting, pending)
	d.mu.Unlock()
	_ = d.socket.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := d.socket.Write(append(encoded, '\n')); err != nil {
		_ = d.socket.Close()
	}
	return pending
}

func (d *burstDriver) renewEvery(controller string, every time.Duration) func() {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				pending := d.send(map[string]any{"op": "renew", "controllerId": controller, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()})
				<-pending.answered
			}
		}
	}()
	var stopping sync.Once
	return func() { stopping.Do(func() { close(done) }); <-finished }
}

// windowed sends events as the dock's input queue does: while fewer than
// window frames are unanswered, what has arrived leaves at once in one frame
// of at most batch events; an answer makes room for the next frame.
func windowed(events []map[string]any, window, batch int, send func([]map[string]any) *sustainedPending) []*sustainedPending {
	var sent []*sustainedPending
	var unanswered []*sustainedPending
	for next := 0; next < len(events); {
		for len(unanswered) >= window {
			reply, open := <-unanswered[0].answered
			if !open {
				// The line ended: nothing more can be sent on it.
				return sent
			}
			unanswered[0].reply = &reply
			unanswered = unanswered[1:]
		}
		end := next + batch
		if end > len(events) {
			end = len(events)
		}
		if len(sent) < window {
			// Before the window first fills, a key finds the line idle and
			// leaves alone.
			end = next + 1
		}
		pending := send(events[next:end])
		sent = append(sent, pending)
		unanswered = append(unanswered, pending)
		next = end
	}
	return sent
}

// burstKeyEvent is one character as a US keyboard in the dock sends it.
type burstKeyEvent struct {
	key, code string
	vk        int
}

func (k burstKeyEvent) down() map[string]any {
	return map[string]any{"type": "input_keyboard", "eventType": "keyDown", "key": k.key, "code": k.code, "text": k.key, "windowsVirtualKeyCode": k.vk, "modifiers": 0}
}

func (k burstKeyEvent) up() map[string]any {
	return map[string]any{"type": "input_keyboard", "eventType": "keyUp", "key": k.key, "code": k.code, "windowsVirtualKeyCode": k.vk, "modifiers": 0}
}

func with(event map[string]any, eventType string, modifiers int, text ...string) map[string]any {
	copied := map[string]any{"eventType": eventType, "modifiers": modifiers}
	for key, value := range event {
		if key != "modifiers" {
			copied[key] = value
		}
	}
	if len(text) > 0 {
		copied["text"] = text[0]
	}
	return copied
}

var burstPunctuation = map[rune]burstKeyEvent{
	' ': {" ", "Space", 32}, '-': {"-", "Minus", 189}, '_': {"_", "Minus", 189}, '=': {"=", "Equal", 187}, '+': {"+", "Equal", 187},
	'[': {"[", "BracketLeft", 219}, '{': {"{", "BracketLeft", 219}, ']': {"]", "BracketRight", 221}, '}': {"}", "BracketRight", 221},
	'\\': {"\\", "Backslash", 220}, '|': {"|", "Backslash", 220}, ';': {";", "Semicolon", 186}, ':': {":", "Semicolon", 186},
	'\'': {"'", "Quote", 222}, '"': {"\"", "Quote", 222}, ',': {",", "Comma", 188}, '<': {"<", "Comma", 188},
	'.': {".", "Period", 190}, '>': {">", "Period", 190}, '/': {"/", "Slash", 191}, '?': {"?", "Slash", 191},
	'`': {"`", "Backquote", 192}, '~': {"~", "Backquote", 192}, '!': {"!", "Digit1", 49}, '@': {"@", "Digit2", 50},
	'#': {"#", "Digit3", 51}, '$': {"$", "Digit4", 52}, '%': {"%", "Digit5", 53}, '^': {"^", "Digit6", 54},
	'&': {"&", "Digit7", 55}, '*': {"*", "Digit8", 56}, '(': {"(", "Digit9", 57}, ')': {")", "Digit0", 48},
}

func burstKey(letter rune) burstKeyEvent {
	switch {
	case letter >= 'a' && letter <= 'z':
		return burstKeyEvent{string(letter), "Key" + strings.ToUpper(string(letter)), int(letter - 'a' + 'A')}
	case letter >= 'A' && letter <= 'Z':
		return burstKeyEvent{string(letter), "Key" + string(letter), int(letter)}
	case letter >= '0' && letter <= '9':
		return burstKeyEvent{string(letter), "Digit" + string(letter), int(letter)}
	}
	key, ok := burstPunctuation[letter]
	if !ok {
		panic(fmt.Sprintf("no US key types %q", letter))
	}
	return key
}

// burstText is length characters a US keyboard types: letters of both cases,
// digits, space and every punctuation key, shifted or not, in an order fixed
// by seed.
func burstText(length int, seed int64) string {
	alphabet := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789      ")
	for letter := range burstPunctuation {
		alphabet = append(alphabet, letter)
	}
	// Map iteration order is random; the alphabet is ordered before use.
	sortRunes(alphabet)
	random := rand.New(rand.NewSource(seed))
	text := make([]rune, length)
	for index := range text {
		text[index] = alphabet[random.Intn(len(alphabet))]
	}
	return string(text)
}

func sortRunes(values []rune) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func firstDifference(typed, arrived string) int {
	a, b := []rune(typed), []rune(arrived)
	for index := 0; index < len(a) && index < len(b); index++ {
		if a[index] != b[index] {
			return index
		}
	}
	if len(a) == len(b) {
		return -1
	}
	if len(a) < len(b) {
		return len(a)
	}
	return len(b)
}

// summarizeBurst reads every frame's answer: how long it took, what the
// driver says the time went to, and every refusal by code, with the first.
func summarizeBurst(sent []*sustainedPending, limit time.Duration) map[string]any {
	var answers, queued, injected []time.Duration
	refusals := map[string]int{}
	var first map[string]any
	unanswered := 0
	deadline := time.Now().Add(limit)
	var last time.Time
	for index, pending := range sent {
		var reply sustainedReply
		var open bool
		if pending.reply != nil {
			reply, open = *pending.reply, true
		} else {
			select {
			case reply, open = <-pending.answered:
				if open {
					pending.reply = &reply
				}
			case <-time.After(time.Until(deadline)):
			}
		}
		if !open {
			unanswered++
			continue
		}
		last = reply.at
		answers = append(answers, reply.at.Sub(pending.sent))
		var value struct {
			OK     bool `json:"ok"`
			Status int  `json:"status"`
			Error  struct {
				Code string `json:"code"`
			} `json:"error"`
			Result struct {
				Timing *struct {
					QueueUs  int64 `json:"queueUs"`
					InjectUs int64 `json:"injectUs"`
				} `json:"timing"`
			} `json:"result"`
		}
		_ = json.Unmarshal(reply.raw, &value)
		if !value.OK {
			refusals[value.Error.Code]++
			if first == nil {
				first = map[string]any{"frame": index, "status": value.Status, "code": value.Error.Code, "afterMs": reply.at.Sub(sent[0].sent).Milliseconds()}
			}
			continue
		}
		if value.Result.Timing != nil {
			queued = append(queued, time.Duration(value.Result.Timing.QueueUs)*time.Microsecond)
			injected = append(injected, time.Duration(value.Result.Timing.InjectUs)*time.Microsecond)
		}
	}
	result := map[string]any{"frames": len(sent), "unanswered": unanswered, "refusals": refusals, "firstRefusal": first}
	if len(answers) > 0 {
		result["answerMs"] = sustainedStats(answers)
		seconds := last.Sub(sent[0].sent).Seconds()
		result["seconds"] = seconds
		result["framesAnsweredPerSecond"] = float64(len(answers)) / seconds
	}
	if len(queued) > 0 {
		result["driverQueueMs"], result["driverInjectMs"] = sustainedStats(queued), sustainedStats(injected)
	}
	return result
}

// summarizeBurstViewer states how the viewer's pictures and sound kept up
// while the scenario ran: video units, JPEG frames and sound packets
// received, and the longest silence of each.
func summarizeBurstViewer(messages []mediaMessage) map[string]any {
	longest := map[string]float64{}
	last := map[string]uint64{}
	counts := map[string]int{}
	for _, message := range messages {
		track := ""
		switch {
		case message.unit != nil:
			track = "video"
		case message.packet != nil:
			track = "audio"
		case message.frame != nil:
			track = "frame"
		default:
			continue
		}
		counts[track]++
		if previous, ok := last[track]; ok {
			if gap := float64(message.at-previous) / 1000; gap > longest[track] {
				longest[track] = gap
			}
		}
		last[track] = message.at
	}
	return map[string]any{"units": counts, "longestGapMs": longest}
}

func burstHeadline(result map[string]any) string {
	return fmt.Sprintf("frames %v unanswered %v refusals %v first %v answer %v exact %v (typed %v, arrived %v, first difference %v) viewer %v",
		result["frames"], result["unanswered"], result["refusals"], result["firstRefusal"], result["answerMs"], result["exact"],
		result["typedCharacters"], result["arrivedCharacters"], result["firstDifference"], result["viewer"])
}
