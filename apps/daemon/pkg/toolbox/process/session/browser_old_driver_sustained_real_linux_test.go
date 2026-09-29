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
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// A textarea and a row of hover targets that stay in view, over rows that
// repaint as the page scrolls.
const sustainedPage = `<!doctype html><title>Sustained</title><style>` +
	`body{margin:0;font:16px sans-serif}` +
	`#notes{position:fixed;left:20px;top:20px;width:560px;height:100px;z-index:2}` +
	`#targets{position:fixed;left:20px;top:140px;z-index:2;display:flex;gap:8px}` +
	`#targets div{width:60px;height:60px;background:#ddd}#targets div:hover{background:#c33}` +
	`.row{height:40px;border-bottom:1px solid #ccc;background:linear-gradient(90deg,#fff,#9cf)}` +
	`</style><textarea id=notes></textarea>` +
	`<div id=targets><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div></div>` +
	`<div style="padding-top:220px" id=rows></div><script>` +
	`for(let i=0;i<1500;i++){const r=document.createElement('div');r.className='row';r.textContent='row '+i;rows.appendChild(r)}` +
	`</script>`

// The production dock's declaration as the host forwards it: binary patch
// frames, the pointer drawn by the viewer, frames cropped to the visible
// window, the dock's frame window and no media; its presentation size is
// added per channel.
const sustainedDeclaration = "frames=binary&patches=1&cursor=viewer&visible=crop&frameWindow=8"

// What makes the dock unusable, far outside what a healthy toolbox and driver
// give on any machine this runs on (on a workstation: frames at 55 a second,
// input answered within milliseconds, a new channel painted within tens of
// milliseconds, a relaunch answered within a second). These detect a collapse;
// the report carries the numbers.
const (
	// Frames a second while typing or wheel input repaints the page.
	sustainedMinFramesPerSecond = 10
	// The slowest tenth of input answers.
	sustainedMaxAnswer = 500 * time.Millisecond
	// The slowest tenth of hover moves, from the send to the frame that shows it.
	sustainedMaxShown = time.Second
	// From a new channel's dial, or a resize, to its first frame.
	sustainedMaxFirstFrame = 2 * time.Second
	// From the sign-in or the hand-back to its answer, the browser restarted
	// and its first frame.
	sustainedMaxRelaunch = 10 * time.Second
)

// TestRealOldDriverSustainedUseThroughTheToolbox drives a retained image's own
// (older) driver through this toolbox the way the production dock and host
// do, at the rates a person produces: the dock's viewer channel painting and
// acknowledging every frame, the control channel, typing at about 100
// characters a second, hover, six seconds of wheel input at 25 notches a
// second, a controlled resize, the dock's channel reopened while the old one
// is still open and after it closed, a second device watching, and the
// sign-in relaunch and hand-back. It reports frames a second, input answer
// latency, time to each new channel's first frame and the relaunch, and fails
// when the dock would be unusable.
//
// It runs when AMBIT_TEST_BROWSER_OLD_DRIVER=1 and AMBIT_TEST_BROWSER_EXECUTABLE,
// AMBIT_TEST_CHROME_EXECUTABLE and AMBIT_TEST_BROWSER_DISPLAY_HELPER name a
// retained image's own driver, Chrome and display helper, as the other
// old-driver probe does; AMBIT_TEST_SUSTAINED_REPORT, when set, receives the
// report as JSON. The runner-swap acceptance builds this binary per daemon
// commit and runs it inside a retained image with build.sh and run.sh in
// /home/bote/m/artifacts/browser-frontier-20260927/media-producer/old-driver-sustained/;
// mutate.sh there, with mutations.py, builds the two deliberately broken
// viewer paths it must fail on.
func TestRealOldDriverSustainedUseThroughTheToolbox(t *testing.T) {
	driver, chrome, helper := os.Getenv("AMBIT_TEST_BROWSER_EXECUTABLE"), os.Getenv("AMBIT_TEST_CHROME_EXECUTABLE"), os.Getenv("AMBIT_TEST_BROWSER_DISPLAY_HELPER")
	if os.Getenv("AMBIT_TEST_BROWSER_OLD_DRIVER") != "1" || driver == "" || chrome == "" || helper == "" {
		t.Skip("set AMBIT_TEST_BROWSER_OLD_DRIVER=1 and the real (older) driver, Chrome and display helper paths")
	}
	scratch, err := os.MkdirTemp("", "sustained-")
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
	workspace.open(t, "sustained-owner")
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, sustainedPage)
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
	if status, body := call(t, engine, http.MethodPost, "/process/session/sustained-owner/exec", SessionExecuteRequest{Command: strings.Join(command, " "), RunAsync: true}); status != http.StatusAccepted {
		t.Fatalf("native owner start: %d %s", status, body)
	}
	awaitPath(t, filepath.Join(scratch, "primary.sock"))
	cli("open", page.URL)
	// Where the page's CSS pixels are on the display: the window is the
	// surface, with the browser's own toolbar above the page.
	var viewport struct{ X, Y, DPR float64 }
	placement := cli("eval", "JSON.stringify({x:screenX+(outerWidth-innerWidth)/2,y:screenY+outerHeight-innerHeight,dpr:devicePixelRatio})")
	if json.Unmarshal([]byte(placement["data"].(map[string]any)["result"].(string)), &viewport) != nil || viewport.DPR <= 0 {
		t.Fatalf("page placement: %v", placement)
	}
	at := func(cssX, cssY float64) (float64, float64) {
		return (viewport.X + cssX) * viewport.DPR, (viewport.Y + cssY) * viewport.DPR
	}
	view, _ := workspace.only(t, "sustained-owner", "primary")
	server := httptest.NewServer(engine)
	defer server.Close()
	base := "ws" + strings.TrimPrefix(server.URL, "http") + "/process/session/sustained-owner/browser-views/" + view
	// The report is stated however the journey ends, with what it found.
	report := map[string]any{"declaration": sustainedDeclaration}
	var failures []string
	check := func(held bool, format string, values ...any) {
		if !held {
			failures = append(failures, fmt.Sprintf(format, values...))
		}
	}
	t.Cleanup(func() {
		encoded, _ := json.MarshalIndent(report, "", "  ")
		t.Logf("SUSTAINED %s", encoded)
		if path := os.Getenv("AMBIT_TEST_SUSTAINED_REPORT"); path != "" {
			_ = os.WriteFile(path, encoded, 0644)
		}
		if len(failures) > 0 {
			t.Errorf("the dock would be unusable:\n%s", strings.Join(failures, "\n"))
		}
	})

	// Attach: the dock's viewer channel.
	const dock, phone = "baaaaabb-cccc-4ddd-8eee-ffff00000301", "baaaaabb-cccc-4ddd-8eee-ffff00000302"
	width, height := 920, 944
	channel := func(viewer string, presents bool) string {
		address := base + "/channel?" + sustainedDeclaration
		if presents {
			address += fmt.Sprintf("&width=%d&height=%d", width, height)
		}
		return address
	}
	viewer := dialSustainedViewer(t, channel(dock, true), dock)
	report["firstFrameMs"] = viewer.awaitFrame(t, 0, 20*time.Second, "first frame", nil).at.Sub(viewer.dialed).Milliseconds()

	control := dialSustainedControl(t, base+"/control/channel")
	// Each take of control is a new controller, as the dock's is.
	controller, sequence := "", uint64(0)
	acquire := func() string {
		t.Helper()
		controller, sequence = uuid.NewString(), 0
		reply := control.request(t, map[string]any{"op": "acquire", "controllerId": controller, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()})
		surface, _ := reply.result()["surface"].(map[string]any)
		generation, _ := surface["generation"].(string)
		if !reply.ok() || generation == "" {
			t.Fatalf("acquire: %s", reply.raw)
		}
		return generation
	}
	input := func(generation string, events ...map[string]any) *sustainedPending {
		sequence++
		return control.send(map[string]any{"op": "input", "controllerId": controller, "sequence": sequence,
			"expectedSurfaceGeneration": generation, "events": events})
	}
	click := func(generation string, cssX, cssY float64) {
		t.Helper()
		x, y := at(cssX, cssY)
		for _, pending := range []*sustainedPending{
			input(generation, map[string]any{"type": "input_mouse", "eventType": "mousePressed", "x": x, "y": y, "button": "left", "buttons": 1, "clickCount": 1}),
			input(generation, map[string]any{"type": "input_mouse", "eventType": "mouseReleased", "x": x, "y": y, "button": "left", "buttons": 0, "clickCount": 1}),
		} {
			if reply := pending.await(t, 10*time.Second); !reply.ok() {
				t.Fatalf("click: %s", reply.raw)
			}
		}
	}
	sustained := func(name string, summary sustainedInput) {
		report[name] = summary
		check(summary.Failed == 0, "%s: %d of %d input batches failed", name, summary.Failed, summary.Batches)
		check(summary.FramesPerSecond >= sustainedMinFramesPerSecond, "%s: %.1f frames a second reached the viewer, want at least %d", name, summary.FramesPerSecond, sustainedMinFramesPerSecond)
		check(summary.AnswerP90 <= sustainedMaxAnswer, "%s: the slowest tenth of input answers took %v, want at most %v", name, summary.AnswerP90, sustainedMaxAnswer)
	}

	// Typing at about 100 characters a second, one batch per key as the dock
	// sends them, without waiting for answers.
	generation := acquire()
	click(generation, 300, 70)
	typed := strings.Repeat("the quick brown fox jumps over the lazy dog ", 4)[:160]
	mark := viewer.frameCount()
	var typing []*sustainedPending
	pace := time.NewTicker(10 * time.Millisecond)
	for _, letter := range typed {
		<-pace.C
		key, code := string(letter), "Key"+strings.ToUpper(string(letter))
		if letter == ' ' {
			code = "Space"
		}
		typing = append(typing, input(generation,
			map[string]any{"type": "input_keyboard", "eventType": "keyDown", "key": key, "text": key, "code": code},
			map[string]any{"type": "input_keyboard", "eventType": "keyUp", "key": key, "code": code}))
	}
	pace.Stop()
	sustained("typing", summarizeSustainedInput(t, typing, viewer.framesSince(mark)))
	if reply := control.request(t, map[string]any{"op": "release", "controllerId": controller}); !reply.ok() {
		t.Fatalf("release: %s", reply.raw)
	}
	value := cli("get", "value", "#notes")["data"].(map[string]any)["value"]
	check(value == typed, "typed %q through the control channel, the page holds %q", typed, value)

	// Hover, one move at a time: each is shown by the first frame captured
	// after the driver applied it.
	generation = acquire()
	renewals := control.renewEvery(controller, 5*time.Second)
	defer renewals()
	click(generation, 700, 400)
	var hovers []time.Duration
	for index := 0; index < 12; index++ {
		x, y := at(50+float64(index%8)*68, 170)
		pending := input(generation, map[string]any{"type": "input_mouse", "eventType": "mouseMoved", "x": x, "y": y, "buttons": 0})
		shown := viewer.awaitFrame(t, viewer.frameCount(), 10*time.Second, fmt.Sprintf("frame showing hover %d", index), func(f sustainedFrame) bool { return f.inputSeq >= pending.sequence })
		if reply := pending.await(t, 10*time.Second); !reply.ok() {
			t.Fatalf("hover: %s", reply.raw)
		}
		hovers = append(hovers, shown.at.Sub(pending.sent))
		time.Sleep(250 * time.Millisecond)
	}
	report["hoverSendToFrame"] = sustainedStats(hovers)
	check(sustainedPercentile(hovers, 0.9) <= sustainedMaxShown, "hover: the slowest tenth of moves was shown after %v, want at most %v", sustainedPercentile(hovers, 0.9), sustainedMaxShown)

	// Six seconds of wheel input at 25 notches a second.
	x, y := at(460, 600)
	mark = viewer.frameCount()
	started := time.Now()
	var wheel []*sustainedPending
	pace = time.NewTicker(40 * time.Millisecond)
	for time.Since(started) < 6*time.Second {
		<-pace.C
		wheel = append(wheel, input(generation, map[string]any{"type": "input_mouse", "eventType": "mouseWheel", "x": x, "y": y, "deltaX": 0, "deltaY": 100}))
	}
	pace.Stop()
	sustained("wheel", summarizeSustainedInput(t, wheel, viewer.framesSince(mark)))

	// A controlled resize: the dock presents a new size.
	width, height = 700, 600
	mark = viewer.frameCount()
	resized := time.Now()
	viewer.send(t, map[string]any{"type": "presentation", "width": width, "height": height})
	fitted := viewer.awaitFrame(t, mark, 20*time.Second, "frame at the new size", func(f sustainedFrame) bool {
		return f.visibleWidth() == uint32(float64(width)*viewport.DPR) && f.visibleHeight() == uint32(float64(height)*viewport.DPR)
	})
	firstFrame := func(name string, ms time.Duration) {
		report[name] = ms.Milliseconds()
		check(ms <= sustainedMaxFirstFrame, "%s: the first frame came after %v, want at most %v", name, ms, sustainedMaxFirstFrame)
	}
	firstFrame("resizeToFrameMs", fitted.at.Sub(resized))

	// The dock's channel reopened while the old one is still open (a
	// restored view), then after it closed (the drawer closed and opened),
	// and a second device watching.
	reopened := dialSustainedViewer(t, channel(dock, true), dock)
	firstFrame("overlappingChannelFirstFrameMs", reopened.awaitFrame(t, 0, 20*time.Second, "first frame on the overlapping channel", nil).at.Sub(reopened.dialed))
	viewer.close()
	viewer = reopened
	viewer.close()
	viewer = dialSustainedViewer(t, channel(dock, true), dock)
	firstFrame("reopenedChannelFirstFrameMs", viewer.awaitFrame(t, 0, 20*time.Second, "first frame on the reopened channel", nil).at.Sub(viewer.dialed))
	watching := dialSustainedViewer(t, channel(phone, false), phone)
	firstFrame("secondDeviceFirstFrameMs", watching.awaitFrame(t, 0, 20*time.Second, "first frame for the second device", nil).at.Sub(watching.dialed))

	// The sign-in relaunch: the driver restarts the browser without its
	// automation for the person, then restarts it with it at the hand-back.
	relaunch := func(name string, before int, send func() sustainedReply) int {
		t.Helper()
		mark := viewer.frameCount()
		sent := time.Now()
		reply := send()
		answered := time.Since(sent)
		if !reply.ok() {
			t.Fatalf("%s: %s", name, reply.raw)
		}
		browser := awaitSustainedBrowser(t, chrome, before, sustainedMaxRelaunch, name)
		restarted := time.Since(sent)
		painted := viewer.awaitFrame(t, mark, sustainedMaxRelaunch, "frame after "+name, func(f sustainedFrame) bool { return f.at.After(reply.at) }).at.Sub(sent)
		report[name] = map[string]any{"answerMs": answered.Milliseconds(), "browserRestartedByMs": restarted.Milliseconds(), "firstFrameMs": painted.Milliseconds()}
		check(answered <= sustainedMaxRelaunch && painted <= sustainedMaxRelaunch, "%s: answered after %v and painted after %v, want each within %v", name, answered, painted, sustainedMaxRelaunch)
		return browser
	}
	browser := awaitSustainedBrowser(t, chrome, 0, time.Second, "the browser")
	browser = relaunch("signIn", browser, func() sustainedReply {
		return input(viewer.latestGeneration(), map[string]any{"type": "sign_in", "idleTimeoutMs": 600000}).await(t, 30*time.Second)
	})
	time.Sleep(2 * time.Second)
	renewals()
	relaunch("handBack", browser, func() sustainedReply {
		return control.request(t, map[string]any{"op": "release", "controllerId": controller})
	})
	report["titleAfterHandBack"] = cli("get", "title")["data"].(map[string]any)["title"]
	for name, channel := range map[string]*sustainedViewer{"dock": viewer, "second device": watching} {
		check(channel.endedWith() == nil, "the %s's channel ended: %v", name, channel.endedWith())
	}
	cli("close")
}

// awaitSustainedBrowser waits until exactly one Chrome browser process runs
// and it is not before, and returns it.
func awaitSustainedBrowser(t *testing.T, chrome string, before int, limit time.Duration, what string) int {
	t.Helper()
	var running []int
	for deadline := time.Now().Add(limit); ; time.Sleep(20 * time.Millisecond) {
		running = sustainedBrowsers(chrome)
		if len(running) == 1 && running[0] != before {
			return running[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: browser processes %v within %v, want one other than %d", what, running, limit, before)
		}
	}
}

// sustainedBrowsers lists the Chrome browser processes: the executable
// without a --type, which its helpers carry.
func sustainedBrowsers(chrome string) []int {
	entries, _ := os.ReadDir("/proc")
	var browsers []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		arguments := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		if err != nil || arguments[0] != chrome {
			continue
		}
		helper := false
		for _, argument := range arguments[1:] {
			helper = helper || strings.HasPrefix(argument, "--type=")
		}
		if !helper {
			browsers = append(browsers, pid)
		}
	}
	return browsers
}

// One binary frame as a viewer received it.
type sustainedFrame struct {
	at         time.Time
	seq        uint64
	inputSeq   uint64
	generation string
	width      uint32
	height     uint32
	visible    *browserVisible
	bytes      int
}

func (f sustainedFrame) visibleWidth() uint32 {
	if f.visible != nil {
		return f.visible.Width
	}
	return f.width
}

func (f sustainedFrame) visibleHeight() uint32 {
	if f.visible != nil {
		return f.visible.Height
	}
	return f.height
}

// A viewer channel as the production dock opens it: it paints every frame on
// arrival and acknowledges it, so the driver's frame window, not this viewer,
// sets the pace.
type sustainedViewer struct {
	socket  *websocket.Conn
	dialed  time.Time
	writes  sync.Mutex
	mu      sync.Mutex
	frames  []sustainedFrame
	ended   error
	arrived chan struct{}
}

func dialSustainedViewer(t *testing.T, address, viewer string) *sustainedViewer {
	t.Helper()
	dialed := time.Now()
	socket, response, err := (&websocket.Dialer{HandshakeTimeout: 20 * time.Second}).Dial(address, http.Header{"X-Ambit-Browser-Viewer": []string{viewer}})
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		t.Fatalf("dial %s: %v (%d)", address, err, status)
	}
	socket.SetReadLimit(64 << 20)
	v := &sustainedViewer{socket: socket, dialed: dialed, arrived: make(chan struct{}, 1)}
	t.Cleanup(func() { _ = socket.Close() })
	go v.read()
	return v
}

func (v *sustainedViewer) read() {
	for {
		kind, data, err := v.socket.ReadMessage()
		at := time.Now()
		if err == nil && kind == websocket.TextMessage {
			continue
		}
		var frame browserFrameHeader
		if err == nil {
			header, _, valid := browserBinaryParts(data)
			if !valid || json.Unmarshal(header, &frame) != nil || frame.Seq == 0 {
				err = fmt.Errorf("an undecodable binary message of %d bytes", len(data))
			}
		}
		v.mu.Lock()
		if err != nil {
			v.ended = err
		} else {
			v.frames = append(v.frames, sustainedFrame{at: at, seq: frame.Seq, inputSeq: frame.InputSeq, generation: frame.Surface.Generation,
				width: frame.Surface.Width, height: frame.Surface.Height, visible: frame.Visible, bytes: len(data)})
		}
		v.mu.Unlock()
		select {
		case v.arrived <- struct{}{}:
		default:
		}
		if err != nil {
			return
		}
		v.send(nil, map[string]any{"type": "ack", "seq": frame.Seq})
	}
}

func (v *sustainedViewer) send(t *testing.T, message map[string]any) {
	encoded, _ := json.Marshal(message)
	v.writes.Lock()
	_ = v.socket.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err := v.socket.WriteMessage(websocket.TextMessage, encoded)
	v.writes.Unlock()
	if err != nil && t != nil {
		t.Fatalf("viewer send %s: %v", encoded, err)
	}
}

func (v *sustainedViewer) close() {
	v.writes.Lock()
	_ = v.socket.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	v.writes.Unlock()
	_ = v.socket.Close()
}

func (v *sustainedViewer) frameCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.frames)
}

func (v *sustainedViewer) framesSince(mark int) []sustainedFrame {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]sustainedFrame(nil), v.frames[mark:]...)
}

func (v *sustainedViewer) latestGeneration() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.frames[len(v.frames)-1].generation
}

func (v *sustainedViewer) endedWith() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.ended
}

// awaitFrame returns the first frame from mark on that matches, failing when
// none does within limit or the channel ends.
func (v *sustainedViewer) awaitFrame(t *testing.T, mark int, limit time.Duration, what string, matches func(sustainedFrame) bool) sustainedFrame {
	t.Helper()
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	for {
		v.mu.Lock()
		for _, frame := range v.frames[mark:] {
			if matches == nil || matches(frame) {
				v.mu.Unlock()
				return frame
			}
		}
		mark = len(v.frames)
		ended := v.ended
		v.mu.Unlock()
		if ended != nil {
			t.Fatalf("the viewer channel ended while waiting for a %s: %v", what, ended)
		}
		select {
		case <-v.arrived:
		case <-deadline.C:
			t.Fatalf("no %s within %v", what, limit)
		}
	}
}

// The control channel as the host keeps it: command documents written as
// they come, answered one text frame each in order.
type sustainedControl struct {
	socket  *websocket.Conn
	writes  sync.Mutex
	mu      sync.Mutex
	waiting []*sustainedPending
}

type sustainedPending struct {
	sequence uint64
	sent     time.Time
	answered chan sustainedReply
	// The answer once awaited.
	reply *sustainedReply
}

type sustainedReply struct {
	at  time.Time
	raw []byte
}

func (r sustainedReply) ok() bool {
	var value struct {
		OK bool `json:"ok"`
	}
	return json.Unmarshal(r.raw, &value) == nil && value.OK
}

func (r sustainedReply) result() map[string]any {
	var value struct {
		Result map[string]any `json:"result"`
	}
	_ = json.Unmarshal(r.raw, &value)
	return value.Result
}

func dialSustainedControl(t *testing.T, address string) *sustainedControl {
	t.Helper()
	socket, response, err := (&websocket.Dialer{HandshakeTimeout: 20 * time.Second}).Dial(address, nil)
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		t.Fatalf("dial %s: %v (%d)", address, err, status)
	}
	c := &sustainedControl{socket: socket}
	t.Cleanup(func() { _ = socket.Close() })
	go c.read()
	return c
}

func (c *sustainedControl) read() {
	for {
		_, data, err := c.socket.ReadMessage()
		at := time.Now()
		c.mu.Lock()
		if err != nil {
			for _, pending := range c.waiting {
				close(pending.answered)
			}
			c.waiting = nil
			c.mu.Unlock()
			return
		}
		if len(c.waiting) == 0 {
			c.mu.Unlock()
			continue
		}
		pending := c.waiting[0]
		c.waiting = c.waiting[1:]
		c.mu.Unlock()
		pending.answered <- sustainedReply{at, data}
	}
}

// send writes one command document and returns its place in the answers. A
// failed write breaks the socket, and its reader then ends every wait.
func (c *sustainedControl) send(command map[string]any) *sustainedPending {
	encoded, _ := json.Marshal(command)
	sequence, _ := command["sequence"].(uint64)
	pending := &sustainedPending{sequence: sequence, answered: make(chan sustainedReply, 1)}
	c.writes.Lock()
	defer c.writes.Unlock()
	c.mu.Lock()
	pending.sent = time.Now()
	c.waiting = append(c.waiting, pending)
	c.mu.Unlock()
	_ = c.socket.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if c.socket.WriteMessage(websocket.TextMessage, encoded) != nil {
		_ = c.socket.Close()
	}
	return pending
}

func (c *sustainedControl) request(t *testing.T, command map[string]any) sustainedReply {
	t.Helper()
	return c.send(command).await(t, 15*time.Second)
}

// renewEvery keeps the controller's lease; the returned stop, which may be
// called again, waits for the last renewal's answer.
func (c *sustainedControl) renewEvery(controller string, every time.Duration) func() {
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
				pending := c.send(map[string]any{"op": "renew", "controllerId": controller, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()})
				<-pending.answered
			}
		}
	}()
	var stopping sync.Once
	return func() { stopping.Do(func() { close(done) }); <-finished }
}

func (p *sustainedPending) await(t *testing.T, limit time.Duration) sustainedReply {
	t.Helper()
	if p.reply != nil {
		return *p.reply
	}
	select {
	case reply, open := <-p.answered:
		if !open {
			t.Fatalf("the control channel ended before answering input %d", p.sequence)
		}
		p.reply = &reply
		return reply
	case <-time.After(limit):
		t.Fatalf("no answer to input %d within %v", p.sequence, limit)
	}
	return sustainedReply{}
}

// One burst of input as a person sends it: how it was answered, and what
// the viewer received from its first send to its last.
type sustainedInput struct {
	Batches         int            `json:"batches"`
	Failed          int            `json:"failed"`
	Seconds         float64        `json:"seconds"`
	Answer          map[string]any `json:"answerMs"`
	AnswerP90       time.Duration  `json:"-"`
	Frames          int            `json:"frames"`
	FramesPerSecond float64        `json:"framesPerSecond"`
	Bytes           int            `json:"bytes"`
}

func summarizeSustainedInput(t *testing.T, batches []*sustainedPending, frames []sustainedFrame) sustainedInput {
	t.Helper()
	var answers []time.Duration
	summary := sustainedInput{Batches: len(batches)}
	for _, pending := range batches {
		reply := pending.await(t, 30*time.Second)
		if !reply.ok() {
			summary.Failed++
		}
		answers = append(answers, reply.at.Sub(pending.sent))
	}
	from, to := batches[0].sent, batches[len(batches)-1].sent
	for _, frame := range frames {
		if frame.at.After(from) && !frame.at.After(to) {
			summary.Frames++
			summary.Bytes += frame.bytes
		}
	}
	summary.Seconds = to.Sub(from).Seconds()
	summary.FramesPerSecond = float64(summary.Frames) / summary.Seconds
	summary.Answer, summary.AnswerP90 = sustainedStats(answers), sustainedPercentile(answers, 0.9)
	return summary
}

func sustainedPercentile(values []time.Duration, q float64) time.Duration {
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[int(q*float64(len(sorted)-1)+0.5)]
}

func sustainedStats(values []time.Duration) map[string]any {
	ms := func(value time.Duration) float64 { return float64(value.Microseconds()) / 1000 }
	return map[string]any{"n": len(values), "p50": ms(sustainedPercentile(values, 0.5)), "p90": ms(sustainedPercentile(values, 0.9)),
		"max": ms(sustainedPercentile(values, 1))}
}
