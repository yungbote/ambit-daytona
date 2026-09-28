// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"context"
	"encoding/binary"
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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

// The media producer lane's probe: the toolbox's viewer channel in front of a
// real driver, display helper and Chrome, with video and audio declared. A
// second viewer connected to the driver directly receives the same encoded
// pictures, so each unit's arrival behind the toolbox is timed against its
// arrival without it. Every record, unit and packet is kept with its arrival
// on the media clock (CLOCK_MONOTONIC, the driver's `ts`), and every close is
// reported with its reason.
func TestRealBrowserMediaThroughToolbox(t *testing.T) {
	driver, chrome, helper := os.Getenv("AMBIT_TEST_BROWSER_EXECUTABLE"), os.Getenv("AMBIT_TEST_CHROME_EXECUTABLE"), os.Getenv("AMBIT_TEST_BROWSER_DISPLAY_HELPER")
	if os.Getenv("AMBIT_TEST_BROWSER_MEDIA") != "1" || driver == "" || chrome == "" || helper == "" {
		t.Skip("set AMBIT_TEST_BROWSER_MEDIA and real driver, Chrome, display helper paths")
	}
	runFor := 75 * time.Second
	scratch, err := os.MkdirTemp("", "media-session-")
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
	workspace.open(t, "media-owner")
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, mediaProbePage)
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
	if status, body := call(t, engine, http.MethodPost, "/process/session/media-owner/exec", SessionExecuteRequest{Command: strings.Join(command, " "), RunAsync: true}); status != http.StatusAccepted {
		t.Fatalf("native owner start: %d %s", status, body)
	}
	awaitPath(t, filepath.Join(scratch, "primary.sock"))
	cli("open", page.URL)
	view, _ := workspace.only(t, "media-owner", "primary")
	server := httptest.NewServer(engine)
	defer server.Close()
	path := "/process/session/media-owner/browser-views/" + view
	port := strings.TrimSpace(string(awaitFile(t, filepath.Join(scratch, "primary.stream"))))

	started := monotonicMicros()
	// The dock's viewer, through the toolbox, and a second viewer straight to
	// the driver declaring the same pictures and sound, never presenting a
	// size: the two connections from the driver carry the same traffic.
	toolbox := dialMediaViewer(t, "ws"+strings.TrimPrefix(server.URL, "http")+path+
		"/channel?frames=binary&cursor=viewer&visible=crop&video=av1-444,av1&audio=opus&width=920&height=944&frameWindow=4",
		"baaaaabb-cccc-4ddd-8eee-ffff00000101")
	direct := dialMediaViewer(t, "ws://127.0.0.1:"+port+
		"/?pacing=ack&maxFps=60&patches=1&frameWindow=4&frames=binary&cursor=viewer&visible=crop&video=av1-444,av1&audio=opus",
		"baaaaabb-cccc-4ddd-8eee-ffff00000102")
	var phases []map[string]any
	phase := func(name string, detail map[string]any) {
		entry := map[string]any{"phase": name, "at": monotonicMicros()}
		for key, value := range detail {
			entry[key] = value
		}
		phases = append(phases, entry)
		t.Logf("phase %s %v", name, detail)
	}
	state := func(track, name string) func(mediaMessage) bool {
		return func(m mediaMessage) bool { return m.record["type"] == track && m.record["state"] == name }
	}
	// A viewer's own request and the mark its answer is awaited from.
	request := func(v *mediaViewer, message map[string]any) int {
		mark := v.count()
		v.send(t, message)
		return mark
	}
	// The offers come once, whenever the driver decides; they are looked for
	// from the first message on.
	toolbox.await(t, 0, "video available", 10*time.Second, state("video", "available"))
	toolbox.await(t, 0, "audio available", 10*time.Second, state("audio", "available"))
	direct.await(t, 0, "direct video available", 10*time.Second, state("video", "available"))
	mark := request(toolbox, map[string]any{"type": "video", "enabled": true, "generation": 1})
	request(direct, map[string]any{"type": "video", "enabled": true, "generation": 1})
	toolbox.await(t, mark, "first key unit", 10*time.Second, func(m mediaMessage) bool { return m.unit != nil && m.unit["key"] == true })
	phase("subscribed", nil)

	cli("click", "#play")
	direct.await(t, 0, "direct audio available", 10*time.Second, state("audio", "available"))
	request(direct, map[string]any{"type": "audio", "enabled": true, "generation": 1})
	mark = request(toolbox, map[string]any{"type": "audio", "enabled": true, "generation": 1})
	toolbox.await(t, mark, "audio packets", 10*time.Second, func(m mediaMessage) bool { return m.packet != nil })
	phase("sound", nil)

	for index := 0; index < 20; index++ {
		cli("scroll", "down", "300")
		time.Sleep(100 * time.Millisecond)
	}
	phase("agent scroll", nil)

	control := func(request any, status int) map[string]any {
		t.Helper()
		code, body := call(t, engine, http.MethodPost, path+"/control", request)
		var value map[string]any
		if code != status || json.Unmarshal(body, &value) != nil {
			t.Fatalf("control: %d %s", code, body)
		}
		return value
	}
	cli("focus", "#notes")
	painted := toolbox.lastUnit()
	mark = toolbox.count()
	lease := control(map[string]any{"op": "acquire", "controllerId": browserFixtureController, "expiresAt": time.Now().Add(25 * time.Second).UnixMilli()}, http.StatusOK)
	generation := lease["surface"].(map[string]any)["generation"]
	time.Sleep(500 * time.Millisecond)
	restarted := 0
	for _, m := range toolbox.since(mark) {
		if m.record["type"] == "video" && m.record["state"] == "started" {
			restarted++
		}
	}
	phase("take control", map[string]any{"generationKept": generation == painted["surface"].(map[string]any)["generation"], "videoStartedWithin500Ms": restarted})
	typed := "through the toolbox"
	sequence := 0
	for _, letter := range typed {
		key := string(letter)
		code := "Key" + strings.ToUpper(key)
		if letter == ' ' {
			code = "Space"
		}
		sequence++
		control(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": sequence, "expectedSurfaceGeneration": generation,
			"events": []map[string]any{
				{"type": "input_keyboard", "eventType": "keyDown", "key": key, "text": key, "code": code},
				{"type": "input_keyboard", "eventType": "keyUp", "key": key, "code": code}}}, http.StatusOK)
		time.Sleep(30 * time.Millisecond)
	}
	phase("typed", map[string]any{"keys": len(typed)})
	for index := 0; index < 30; index++ {
		sequence++
		control(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": sequence, "expectedSurfaceGeneration": generation,
			"events": []map[string]any{{"type": "input_mouse", "eventType": "mouseWheel", "x": 460, "y": 600, "deltaX": 0, "deltaY": 120}}}, http.StatusOK)
		time.Sleep(33 * time.Millisecond)
	}
	phase("wheel scroll", map[string]any{"notches": 30})
	control(map[string]any{"op": "release", "controllerId": browserFixtureController}, http.StatusOK)
	cli("snapshot")
	if value := cli("get", "value", "#notes")["data"].(map[string]any)["value"]; value != typed {
		t.Fatalf("typed %q, the page holds %q", typed, value)
	}
	phase("released", nil)

	for _, size := range [][2]int{{1100, 944}, {800, 700}, {1300, 1000}, {960, 880}, {920, 944}} {
		toolbox.send(t, map[string]any{"type": "presentation", "width": size[0], "height": size[1]})
		time.Sleep(900 * time.Millisecond)
	}
	phase("presentations", map[string]any{"sizes": 5})

	keyRequested := monotonicMicros()
	mark = request(toolbox, map[string]any{"type": "video", "keyframe": true, "generation": 1})
	key := toolbox.await(t, mark, "requested key unit", 5*time.Second, func(m mediaMessage) bool { return m.unit != nil && m.unit["key"] == true })
	unitsBefore := 0
	for _, m := range toolbox.since(mark) {
		if m.unit != nil && m.at < key.at {
			unitsBefore++
		}
	}
	phase("key unit requested", map[string]any{"msToKey": float64(key.at-keyRequested) / 1000, "unitsBeforeKey": unitsBefore})

	// Rev 2: a viewer more than a second behind is given a new stream under
	// the same generation. The dock's viewer stops reading while the page
	// scrolls and the direct viewer keeps pictures coming, so its path backs
	// up through the toolbox to the driver.
	mark = toolbox.count()
	holdStarted := monotonicMicros()
	toolbox.holdReads(true)
	scrolling := make(chan struct{})
	go func() {
		defer close(scrolling)
		for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			process := exec.CommandContext(ctx, driver, append(append([]string{}, args...), "scroll", "down", "600")...)
			process.Env = environment
			_ = process.Run()
			cancel()
		}
	}()
	<-scrolling
	toolbox.holdReads(false)
	holdEnded := monotonicMicros()
	resynchronized := map[string]any{"heldMs": (holdEnded - holdStarted) / 1000}
	if resync, ok := toolbox.within(mark, 10*time.Second, state("video", "started")); ok {
		first := toolbox.await(t, mark, "first unit of the new stream", 5*time.Second, func(m mediaMessage) bool {
			return m.unit != nil && m.unit["streamId"] == resync.record["streamId"]
		})
		resynchronized["generation"], resynchronized["firstSeq"], resynchronized["firstKey"] = resync.record["generation"], first.unit["seq"], first.unit["key"]
	} else {
		resynchronized["started"] = "none within 10 s of the hold"
	}
	phase("resynchronized", resynchronized)

	// A newer generation retires the older one silently.
	retired := toolbox.lastUnit()["streamId"]
	mark = request(toolbox, map[string]any{"type": "video", "enabled": true, "generation": 2})
	second := toolbox.await(t, mark, "started under generation 2", 5*time.Second, state("video", "started"))
	time.Sleep(500 * time.Millisecond)
	retiredAfter, recordsOfOne := 0, 0
	for _, m := range toolbox.since(mark) {
		if m.unit != nil && m.unit["streamId"] == retired && m.at > second.at {
			retiredAfter++
		}
		if m.record["type"] == "video" && m.record["generation"] == float64(1) {
			recordsOfOne++
		}
	}
	phase("generation 2", map[string]any{"startedGeneration": second.record["generation"], "retiredUnitsAfterStarted": retiredAfter, "generationOneRecords": recordsOfOne})

	mark = request(toolbox, map[string]any{"type": "video", "enabled": false, "generation": 3})
	stopped := toolbox.await(t, mark, "stopped", 5*time.Second, state("video", "stopped"))
	frame := toolbox.await(t, mark, "a frame after stop", 5*time.Second, func(m mediaMessage) bool { return m.frame != nil })
	phase("stopped", map[string]any{"generation": stopped.record["generation"], "firstFrameBaseSeq": frame.frame["baseSeq"]})
	mark = request(toolbox, map[string]any{"type": "video", "enabled": true, "generation": 4})
	toolbox.await(t, mark, "started under generation 4", 5*time.Second, state("video", "started"))
	mark = request(toolbox, map[string]any{"type": "audio", "enabled": false, "generation": 2})
	toolbox.await(t, mark, "audio stopped", 5*time.Second, state("audio", "stopped"))
	mark = request(toolbox, map[string]any{"type": "audio", "enabled": true, "generation": 3})
	toolbox.await(t, mark, "audio started again", 5*time.Second, state("audio", "started"))
	phase("resubscribed", nil)

	for time.Duration(monotonicMicros()-started)*time.Microsecond < runFor {
		cli("scroll", "down", "200")
		time.Sleep(250 * time.Millisecond)
	}
	phase("ran", map[string]any{"seconds": (monotonicMicros() - started) / 1_000_000})
	cli("close")
	closing := toolbox.closed(t, 15*time.Second)
	directClosing := direct.closed(t, 15*time.Second)

	// The hop is timed outside the hold, when the dock's viewer reads at once.
	result := summarizeMediaProbe(toolbox.all(), direct.all(), [2]uint64{holdStarted, holdEnded + 2_000_000})
	result["phases"] = phases
	result["closes"] = map[string]any{"toolbox": closing, "direct": directClosing}
	encoded, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("MEDIA %s", encoded)
	if output := os.Getenv("AMBIT_TEST_MEDIA_REPORT"); output != "" {
		if err := os.WriteFile(output, encoded, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if closing["reason"] != "browser_view_ended" {
		t.Fatalf("the toolbox closed the channel with %v", closing)
	}
	if violations := result["contractViolations"].([]string); len(violations) != 0 {
		t.Fatalf("contract violations: %v", violations)
	}
}

const mediaProbePage = `<!doctype html><meta charset=utf-8><title>Media through the toolbox</title>
<style>body{margin:0;font:14px/1.5 system-ui,sans-serif;color:#1d1d1f;background:#fff}
#bar{position:fixed;top:0;left:0;height:6px;width:120px;background:#0a66c2}
#play{position:fixed;top:12px;right:12px;width:120px;height:36px}
textarea{display:block;margin:56px 24px 12px;width:420px;height:80px}
p{margin:0 24px 10px;max-width:900px}a{color:#0a58ca}</style>
<div id=bar></div><button id=play>Play</button><textarea id=notes aria-label=Notes></textarea><main id=doc></main>
<script>let seed=7;const rnd=()=>(seed=(seed*1103515245+12345)%2147483648)/2147483648;
const words='the of and to in is that for it as was with be by on not this are or from at which but have an they you were one all we their has would when been if more will who no out so can said what up its about into them than some could time these two may then do first any now such like other how our over also back after use well way even new want because day most us service window pointer video frame picture encoder stream viewer display render layout scroll'.split(' ');
let html='';for(let p=0;p<400;p++){html+='<p>'+Array.from({length:80},()=>{const w=words[Math.floor(rnd()*words.length)];return rnd()<.06?'<a href=#>'+w+'</a>':w}).join(' ')+'</p>'}
doc.innerHTML=html;let x=0;(function tick(){x=(x+4)%Math.max(1,innerWidth-120);bar.style.transform='translateX('+x+'px)';requestAnimationFrame(tick)})();
let audio;play.onclick=async()=>{if(audio)return;audio=new AudioContext({sampleRate:48000});await audio.resume();const o=audio.createOscillator();o.frequency.value=440;const g=audio.createGain();g.gain.value=.25;o.connect(g).connect(audio.destination);o.start();play.textContent='Playing'};
</script>`

func monotonicMicros() uint64 {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		panic(err)
	}
	return uint64(now.Sec)*1_000_000 + uint64(now.Nsec)/1_000
}

// One message a viewer received, stamped at arrival on the media clock.
type mediaMessage struct {
	at     uint64
	record map[string]any
	unit   map[string]any
	packet map[string]any
	frame  map[string]any
	bytes  int
}

type mediaViewer struct {
	socket   *websocket.Conn
	writes   sync.Mutex
	mu       sync.Mutex
	messages []mediaMessage
	arrived  chan struct{}
	closing  chan map[string]any
	// Closed while reads may proceed; replaced while they are held.
	reading chan struct{}
}

// A small receive buffer, fixed rather than tuned: a viewer that stops
// reading backs up its path the way a slow network does.
const mediaViewerReceiveBuffer = 64 << 10

func dialMediaViewer(t *testing.T, address, viewer string) *mediaViewer {
	t.Helper()
	dialer := websocket.Dialer{NetDialContext: (&net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if controlErr := raw.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, mediaViewerReceiveBuffer)
		}); controlErr != nil {
			return controlErr
		}
		return err
	}}).DialContext, HandshakeTimeout: 10 * time.Second}
	socket, response, err := dialer.Dial(address, http.Header{"X-Ambit-Browser-Viewer": []string{viewer}})
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		t.Fatalf("dial %s: %v (%d)", address, err, status)
	}
	socket.SetReadLimit(64 << 20)
	reading := make(chan struct{})
	close(reading)
	v := &mediaViewer{socket: socket, arrived: make(chan struct{}, 1), closing: make(chan map[string]any, 1), reading: reading}
	t.Cleanup(func() { _ = socket.Close() })
	go v.read()
	return v
}

// holdReads stops reading the socket, or reads again.
func (v *mediaViewer) holdReads(hold bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if hold {
		v.reading = make(chan struct{})
	} else {
		close(v.reading)
	}
}

func (v *mediaViewer) read() {
	for {
		v.mu.Lock()
		reading := v.reading
		v.mu.Unlock()
		<-reading
		kind, data, err := v.socket.ReadMessage()
		at := monotonicMicros()
		if err != nil {
			closing := map[string]any{"at": at, "error": err.Error()}
			if closed, ok := err.(*websocket.CloseError); ok {
				closing["code"], closing["reason"] = closed.Code, closed.Text
			}
			v.closing <- closing
			return
		}
		message := mediaMessage{at: at, bytes: len(data)}
		if kind == websocket.TextMessage {
			_ = json.Unmarshal(data, &message.record)
		} else if len(data) >= 4 {
			end := 4 + int(binary.BigEndian.Uint32(data))
			var header map[string]any
			if end <= len(data) && json.Unmarshal(data[4:end], &header) == nil {
				switch {
				case header["type"] == "media" && header["track"] == "video":
					message.unit = header
				case header["type"] == "media" && header["track"] == "audio":
					message.packet = header
				default:
					message.frame = header
				}
			}
		}
		v.mu.Lock()
		v.messages = append(v.messages, message)
		v.mu.Unlock()
		select {
		case v.arrived <- struct{}{}:
		default:
		}
		// Painted on arrival: the producer's pacing, not this viewer, sets
		// the rate.
		switch {
		case message.unit != nil:
			v.send(nil, map[string]any{"type": "ack", "track": "video", "streamId": message.unit["streamId"], "seq": message.unit["seq"]})
		case message.frame != nil && message.frame["seq"] != nil:
			v.send(nil, map[string]any{"type": "ack", "seq": message.frame["seq"]})
		}
	}
}

func (v *mediaViewer) send(t *testing.T, message map[string]any) {
	encoded, _ := json.Marshal(message)
	v.writes.Lock()
	err := v.socket.WriteMessage(websocket.TextMessage, encoded)
	v.writes.Unlock()
	if err != nil && t != nil {
		t.Fatalf("send %s: %v", encoded, err)
	}
}

func (v *mediaViewer) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.messages)
}

func (v *mediaViewer) since(mark int) []mediaMessage {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]mediaMessage(nil), v.messages[mark:]...)
}

func (v *mediaViewer) all() []mediaMessage { return v.since(0) }

func (v *mediaViewer) lastUnitLocked() map[string]any {
	for index := len(v.messages) - 1; index >= 0; index-- {
		if v.messages[index].unit != nil {
			return v.messages[index].unit
		}
	}
	return nil
}

func (v *mediaViewer) lastUnit() map[string]any {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lastUnitLocked()
}

// within returns the first message from `mark` on that matches, if one
// arrives in time and the channel stays open.
func (v *mediaViewer) within(mark int, limit time.Duration, matches func(mediaMessage) bool) (mediaMessage, bool) {
	deadline := time.After(limit)
	for {
		for _, message := range v.since(mark) {
			mark++
			if matches(message) {
				return message, true
			}
		}
		select {
		case <-v.arrived:
		case closing := <-v.closing:
			v.closing <- closing
			return mediaMessage{}, false
		case <-deadline:
			return mediaMessage{}, false
		}
	}
}

// await returns the first message from `mark` on that matches, failing when
// none does in time or the channel closes. A caller answering its own
// action takes the mark before acting.
func (v *mediaViewer) await(t *testing.T, mark int, what string, limit time.Duration, matches func(mediaMessage) bool) mediaMessage {
	t.Helper()
	message, ok := v.within(mark, limit, matches)
	if !ok {
		select {
		case closing := <-v.closing:
			v.closing <- closing
			t.Fatalf("%s: the channel closed: %v; %s", what, closing, v.describe(mark))
		default:
			t.Fatalf("%s did not arrive within %s; %s", what, limit, v.describe(mark))
		}
	}
	return message
}

// describe names what arrived from `mark` on: records in full, media and
// frames by count.
func (v *mediaViewer) describe(mark int) string {
	counts := map[string]int{}
	var records []string
	for _, m := range v.since(mark) {
		switch {
		case m.unit != nil:
			counts["units"]++
		case m.packet != nil:
			counts["audio"]++
		case m.frame != nil:
			counts["frames"]++
		case m.record["type"] == "video" || m.record["type"] == "audio":
			encoded, _ := json.Marshal(m.record)
			records = append(records, string(encoded))
		default:
			counts[fmt.Sprint(m.record["type"])]++
		}
	}
	return fmt.Sprintf("arrived %v, media records %v", counts, records)
}

func (v *mediaViewer) closed(t *testing.T, within time.Duration) map[string]any {
	t.Helper()
	select {
	case closing := <-v.closing:
		v.closing <- closing
		return closing
	case <-time.After(within):
		t.Fatalf("the channel stayed open")
		return nil
	}
}

// summarizeMediaProbe checks every unit against the contract and times the
// toolbox's hop per unit against the direct viewer's copy of the same
// capture, leaving out units that arrived within `held` (when the dock's
// viewer did not read).
func summarizeMediaProbe(toolbox, direct []mediaMessage, held [2]uint64) map[string]any {
	var violations []string
	type stream struct {
		seq, ts uint64
		coded   string
	}
	streams := map[string]*stream{}
	counts := map[string]int{}
	var unitBytes, keys int
	var captureToArrival []float64
	directArrival, directAudio := map[uint64]uint64{}, map[uint64]uint64{}
	for _, m := range direct {
		switch {
		case m.unit != nil:
			directArrival[uint64(m.unit["ts"].(float64))] = m.at
		case m.packet != nil:
			directAudio[uint64(m.packet["ts"].(float64))] = m.at
		}
	}
	var hop, audioHop []float64
	var audioLatency []float64
	audioStreams := map[string]uint64{}
	for _, m := range toolbox {
		switch {
		case m.unit != nil:
			counts["units"]++
			unitBytes += m.bytes
			header := m.unit
			id := header["streamId"].(string)
			seq, ts := uint64(header["seq"].(float64)), uint64(header["ts"].(float64))
			key := header["key"] == true
			coded, _ := json.Marshal(header["coded"])
			if key {
				keys++
			}
			if key != (header["codecString"] != nil) {
				violations = append(violations, fmt.Sprintf("codecString on key only: %v", header))
			}
			known, ok := streams[id]
			switch {
			case !ok && (seq != 1 || !key):
				violations = append(violations, fmt.Sprintf("stream begins at 1 with a key unit: %v", header))
			case ok && seq != known.seq+1:
				violations = append(violations, fmt.Sprintf("seq %d after %d in %s", seq, known.seq, id))
			case ok && ts < known.ts:
				violations = append(violations, fmt.Sprintf("ts %d before %d in %s", ts, known.ts, id))
			case ok && string(coded) != known.coded && !key:
				violations = append(violations, fmt.Sprintf("coded changed without a key unit: %v", header))
			}
			streams[id] = &stream{seq, ts, string(coded)}
			if m.at >= held[0] && m.at <= held[1] {
				counts["unitsWhileHeld"]++
				break
			}
			captureToArrival = append(captureToArrival, float64(m.at-ts)/1000)
			if arrived, ok := directArrival[ts]; ok {
				hop = append(hop, (float64(m.at)-float64(arrived))/1000)
			}
		case m.packet != nil:
			counts["audioPackets"]++
			id := m.packet["streamId"].(string)
			seq := uint64(m.packet["seq"].(float64))
			if last, ok := audioStreams[id]; ok && seq != last+1 {
				violations = append(violations, fmt.Sprintf("audio seq %d after %d", seq, last))
			}
			audioStreams[id] = seq
			if m.at < held[0] || m.at > held[1] {
				ts := uint64(m.packet["ts"].(float64))
				audioLatency = append(audioLatency, float64(m.at-ts)/1000)
				if arrived, ok := directAudio[ts]; ok {
					audioHop = append(audioHop, (float64(m.at)-float64(arrived))/1000)
				}
			}
		case m.frame != nil:
			counts["frames"]++
		case m.record != nil:
			counts["record:"+fmt.Sprint(m.record["type"])]++
		}
	}
	var videoRecords []map[string]any
	for _, m := range toolbox {
		if m.record["type"] == "video" || m.record["type"] == "audio" {
			entry := map[string]any{"at": m.at}
			for key, value := range m.record {
				entry[key] = value
			}
			videoRecords = append(videoRecords, entry)
		}
	}
	return map[string]any{
		"counts":                  counts,
		"streams":                 len(streams),
		"keyUnits":                keys,
		"unitBytes":               unitBytes,
		"captureToArrivalMs":      mediaStats(captureToArrival),
		"hopMs":                   mediaStats(hop),
		"hopMatchedUnits":         len(hop),
		"audioCaptureToArrivalMs": mediaStats(audioLatency),
		"audioHopMs":              mediaStats(audioHop),
		"mediaRecords":            videoRecords,
		"contractViolations":      append([]string{}, violations...),
	}
}

func mediaStats(values []float64) map[string]any {
	if len(values) == 0 {
		return map[string]any{"n": 0}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	at := func(share float64) float64 { return sorted[int(share*float64(len(sorted)-1))] }
	return map[string]any{"n": len(sorted), "min": sorted[0], "p50": at(0.5), "p95": at(0.95), "p99": at(0.99), "max": sorted[len(sorted)-1]}
}
