// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// A document that re-lays out with its width, which records every width it
// painted (per animation frame) on its own clock.
const resizeDragPage = `<!doctype html><meta charset=utf-8><title>Resize</title>
<style>body{margin:0;font:15px/1.5 system-ui,sans-serif;color:#1d1d1f;background:#fff}
header{position:sticky;top:0;height:48px;background:#0a66c2;color:#fff;display:flex;align-items:center;padding:0 16px}
main{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;padding:12px}
article{border:1px solid #d0d7de;border-radius:6px;padding:8px}</style>
<header>Resize</header><main id=doc></main>
<script>let seed=11;const rnd=()=>(seed=(seed*1103515245+12345)%2147483648)/2147483648;
const words='the of and to in is that for it as was with be by on not this are or from at which but have an they you were one all we their has would when been if more will who no out so can said what up its about into them than some could time these two may then do first any now such like other how our over also back after use well way even new want because day most us service window pointer video frame picture encoder stream viewer display render layout scroll'.split(' ');
let html='';for(let a=0;a<120;a++){html+='<article><b>Card '+a+'</b><p>'+Array.from({length:60},()=>words[Math.floor(rnd()*words.length)]).join(' ')+'</p></article>'}
doc.innerHTML=html;window.painted=[];let last=0;
(function frame(){if(innerWidth!==last){last=innerWidth;painted.push([performance.now(),innerWidth])}requestAnimationFrame(frame)})();
</script>`

// One drag of the dock's divider: the presented width moves from one value
// to another at a steady rate for two seconds.
type resizeSweep struct {
	name     string
	from, to int
}

// A drag inside the display's size class both ways, one that crosses it
// (the framebuffer and the video's coded size grow past 2048 display pixels
// at 1024 CSS pixels), and back inside the new class.
var resizeSweeps = []resizeSweep{
	{"shrink", 920, 620},
	{"grow", 620, 920},
	{"grow across a size class", 920, 1220},
	{"shrink inside the new class", 1220, 920},
}

const resizeHeight = 944

// TestRealBrowserResizeUnderDrag measures what a person sees while dragging
// the dock's divider: presentations at 30 and 60 a second for 2 s, each sweep
// moving the width 300 CSS pixels, on the frame track and on the video track,
// through this toolbox to the real driver, display helper and Chrome. It
// reports, per sweep, the pictures and the distinct sizes a second, the time
// from each presentation to the first picture that honours it (its size or a
// newer one's), the presentations never shown, the longest gap, blank
// pictures, the framebuffer and coded sizes, key units, and the widths the
// page itself painted. Before that it reopens the dock's channel six times,
// as the same viewer and as a new one, and drags 0, 100 and 500 ms after
// subscribing to video. A measurement, not a guard: it fails only when a
// sweep's last size never shows or a channel ends.
//
// It runs when AMBIT_TEST_BROWSER_RESIZE=1 and AMBIT_TEST_BROWSER_EXECUTABLE,
// AMBIT_TEST_CHROME_EXECUTABLE and AMBIT_TEST_BROWSER_DISPLAY_HELPER name the
// driver, Chrome and display helper; AMBIT_TEST_RESIZE_REPORT, when set,
// receives the report as JSON. run.sh in
// /home/bote/m/artifacts/browser-frontier-20260927/media-producer/resize/
// runs it inside the workspace image.
func TestRealBrowserResizeUnderDrag(t *testing.T) {
	if os.Getenv("AMBIT_TEST_BROWSER_RESIZE") != "1" {
		t.Skip("set AMBIT_TEST_BROWSER_RESIZE=1 and the real driver, Chrome and display helper paths")
	}
	base, cli := startResizeSession(t, resizeDragPage)
	// The page's clock against this one: the widths it painted are stamped on it.
	pageClock := func() (time.Time, float64) {
		before := time.Now()
		now := cli("eval", "performance.now()")["data"].(map[string]any)["result"].(float64)
		return before.Add(time.Since(before) / 2), now
	}
	anchor, anchorPage := pageClock()
	painted := func(from, to time.Time) []int {
		var values [][2]float64
		result := cli("eval", "JSON.stringify(painted)")["data"].(map[string]any)["result"].(string)
		_ = json.Unmarshal([]byte(result), &values)
		var widths []int
		for _, value := range values {
			at := anchor.Add(time.Duration((value[0] - anchorPage) * float64(time.Millisecond)))
			if !at.Before(from) && !at.After(to) {
				widths = append(widths, int(value[1]))
			}
		}
		return widths
	}

	report := map[string]any{}
	t.Cleanup(func() {
		encoded, _ := json.MarshalIndent(report, "", "  ")
		t.Logf("RESIZE %s", encoded)
		if path := os.Getenv("AMBIT_TEST_RESIZE_REPORT"); path != "" {
			_ = os.WriteFile(path, encoded, 0644)
		}
	})
	// A person reopening the dock and resizing at once: the dock's channel
	// closes and a new one opens straight after, subscribes to video and
	// drags 0, 100 or 500 ms later, each drag moving the window from where
	// the last one left it to the other end. The new channel is the same
	// viewer (a drawer closed and opened in one mount) or a new one (a
	// remounted dock, another tab).
	subscribing := map[string]any{}
	var previous *resizeViewer
	width := 920
	for attempt, variant := range []struct {
		viewer string
		delay  time.Duration
	}{{"same", 0}, {"same", 100 * time.Millisecond}, {"same", 500 * time.Millisecond},
		{"new", 0}, {"new", 100 * time.Millisecond}, {"new", 500 * time.Millisecond}} {
		id := "baaaaabb-cccc-4ddd-8eee-ffff00000500"
		if variant.viewer == "new" {
			id = fmt.Sprintf("baaaaabb-cccc-4ddd-8eee-ffff0000051%d", attempt)
		}
		if previous != nil {
			previous.close()
		}
		viewer := dialResizeViewer(t, fmt.Sprintf("%s/channel?frames=binary&patches=1&cursor=viewer&visible=crop&frameWindow=8&video=av1-444,av1&width=%d&height=%d", base, width, resizeHeight), id)
		previous = viewer
		viewer.awaitRecord(t, 10*time.Second, func(record map[string]any) bool { return record["type"] == "video" && record["state"] == "available" })
		mark := viewer.pictureCount()
		viewer.send(t, map[string]any{"type": "video", "enabled": true, "generation": 1})
		subscribed := time.Now()
		time.Sleep(variant.delay)
		sweep := resizeSweep{"drag", width, 1540 - width}
		presented := dragResize(t, viewer, sweep, 30)
		width = sweep.to
		name := fmt.Sprintf("%s viewer, drag %v after subscribing", variant.viewer, variant.delay)
		shown := viewer.awaitPicture(t, mark, 10*time.Second, fmt.Sprintf("%s: the last width %d", name, width),
			func(p resizePicture) bool { return p.unit && p.visibleWidth == uint32(2*width) })
		units := viewer.picturesSince(mark)
		summary := summarizeResizeSweep(presented, units, shown.at)
		for _, picture := range units {
			if picture.unit {
				summary["subscribedToFirstUnitMs"] = picture.at.Sub(subscribed).Milliseconds()
				break
			}
		}
		for _, picture := range units {
			if picture.unit && picture.visibleWidth != uint32(2*sweep.from) {
				summary["firstPresentationToFirstNewSizeMs"] = picture.at.Sub(presented[0].at).Milliseconds()
				break
			}
		}
		subscribing[name] = summary
	}
	previous.close()
	time.Sleep(3 * time.Second)
	report["videoDragRightAfterSubscribing"] = subscribing

	for index, track := range []string{"frames", "video"} {
		declaration := "frames=binary&patches=1&cursor=viewer&visible=crop&frameWindow=8"
		if track == "video" {
			declaration += "&video=av1-444,av1"
		}
		dial := func(width int) *resizeViewer {
			return dialResizeViewer(t, fmt.Sprintf("%s/channel?%s&width=%d&height=%d", base, declaration, width, resizeHeight),
				fmt.Sprintf("baaaaabb-cccc-4ddd-8eee-ffff0000040%d", index))
		}
		viewer := dial(920)
		if track == "video" {
			viewer.awaitRecord(t, 10*time.Second, func(record map[string]any) bool { return record["type"] == "video" && record["state"] == "available" })
			viewer.send(t, map[string]any{"type": "video", "enabled": true, "generation": 1})
		}
		viewer.awaitPicture(t, 0, 20*time.Second, "the first "+track+" picture", func(p resizePicture) bool { return p.visibleWidth == 1840 })
		// Both size classes start where the dock's size needs them: after ten
		// seconds at a size that needs a smaller class, and then a layout, the
		// framebuffer and the video's coded size shrink to the dock's, so each
		// rate's crossing sweep grows them again.
		reset := func() {
			t.Helper()
			mark := viewer.pictureCount()
			viewer.send(t, map[string]any{"type": "presentation", "width": 620, "height": resizeHeight})
			time.Sleep(11 * time.Second)
			viewer.send(t, map[string]any{"type": "presentation", "width": 621, "height": resizeHeight})
			time.Sleep(time.Second)
			viewer.send(t, map[string]any{"type": "presentation", "width": 920, "height": resizeHeight})
			viewer.awaitPicture(t, mark, 10*time.Second, "the reset to 920", func(p resizePicture) bool { return p.visibleWidth == 1840 })
			time.Sleep(time.Second)
		}
		results := map[string]any{}
		for _, rate := range []int{30, 60} {
			reset()
			for _, sweep := range resizeSweeps {
				mark := viewer.pictureCount()
				presented := dragResize(t, viewer, sweep, rate)
				last := presented[len(presented)-1]
				shown := viewer.awaitPicture(t, mark, 10*time.Second, fmt.Sprintf("%s at %d a second: the last width %d", sweep.name, rate, last.width),
					func(p resizePicture) bool { return p.at.After(last.at) && p.visibleWidth == uint32(2*last.width) })
				time.Sleep(300 * time.Millisecond)
				end := shown.at
				summary := summarizeResizeSweep(presented, viewer.picturesSince(mark), end)
				summary["pageWidthsPainted"] = len(painted(presented[0].at, end))
				results[fmt.Sprintf("%s at %d a second", sweep.name, rate)] = summary
			}
		}
		if ended := viewer.endedWith(); ended != nil {
			t.Fatalf("the %s viewer's channel ended: %v", track, ended)
		}
		report[track] = results
		viewer.close()
	}
	cli("close")
}

// startResizeSession runs the real driver for one page in a toolbox session
// and returns the view's channel base address and the driver's command line.
// AMBIT_TEST_CHROME_ARGS, when set, is passed to the driver as Chrome's
// launch arguments (AGENT_BROWSER_ARGS).
func startResizeSession(t *testing.T, html string) (string, func(...string) map[string]any) {
	t.Helper()
	driver, chrome, helper := os.Getenv("AMBIT_TEST_BROWSER_EXECUTABLE"), os.Getenv("AMBIT_TEST_CHROME_EXECUTABLE"), os.Getenv("AMBIT_TEST_BROWSER_DISPLAY_HELPER")
	if driver == "" || chrome == "" || helper == "" {
		t.Skip("set the real driver, Chrome and display helper paths")
	}
	scratch, err := os.MkdirTemp("", "resize-")
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
	workspace.open(t, "resize-owner")
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, html)
	}))
	t.Cleanup(page.Close)
	var environment []string
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "AGENT_BROWSER_") && !strings.HasPrefix(item, "DISPLAY=") {
			environment = append(environment, item)
		}
	}
	environment = append(environment, "DISPLAY=", "AGENT_BROWSER_SOCKET_DIR="+scratch, "AGENT_BROWSER_EXECUTABLE_PATH="+chrome,
		"AGENT_BROWSER_WINDOW_STREAM=1", "AGENT_BROWSER_DISPLAY_HELPER="+helper, "NO_COLOR=1")
	if extra := os.Getenv("AMBIT_TEST_CHROME_ARGS"); extra != "" {
		environment = append(environment, "AGENT_BROWSER_ARGS="+extra)
	}
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
	if status, body := call(t, engine, http.MethodPost, "/process/session/resize-owner/exec", SessionExecuteRequest{Command: strings.Join(command, " "), RunAsync: true}); status != http.StatusAccepted {
		t.Fatalf("native owner start: %d %s", status, body)
	}
	awaitPath(t, filepath.Join(scratch, "primary.sock"))
	cli("open", page.URL)
	view, _ := workspace.only(t, "resize-owner", "primary")
	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)
	return "ws" + strings.TrimPrefix(server.URL, "http") + "/process/session/resize-owner/browser-views/" + view, cli
}

// One presentation as the dock sent it.
type resizePresentation struct {
	at    time.Time
	width int
}

// dragResize sends the sweep's presentations at rate a second for two seconds.
func dragResize(t *testing.T, viewer *resizeViewer, sweep resizeSweep, rate int) []resizePresentation {
	t.Helper()
	count := 2 * rate
	var sent []resizePresentation
	pace := time.NewTicker(time.Second / time.Duration(rate))
	defer pace.Stop()
	for index := 0; index < count; index++ {
		width := sweep.from + (sweep.to-sweep.from)*index/(count-1)
		if index > 0 {
			<-pace.C
		}
		sent = append(sent, resizePresentation{time.Now(), width})
		viewer.send(t, map[string]any{"type": "presentation", "width": width, "height": resizeHeight})
	}
	return sent
}

// One picture a viewer received: a frame, or a video unit.
type resizePicture struct {
	at            time.Time
	unit          bool
	seq           uint64
	whole         bool
	key           bool
	visibleWidth  uint32
	visibleHeight uint32
	surface       [2]uint32
	coded         [2]uint32
	bytes         int
	// The JPEG images of a frame, kept to look for blank pictures after the
	// sweep, off the timed path.
	images [][]byte
}

type resizeViewer struct {
	socket   *websocket.Conn
	writes   sync.Mutex
	mu       sync.Mutex
	pictures []resizePicture
	records  []map[string]any
	ended    error
	arrived  chan struct{}
}

func dialResizeViewer(t *testing.T, address, viewer string) *resizeViewer {
	t.Helper()
	socket, response, err := (&websocket.Dialer{HandshakeTimeout: 20 * time.Second}).Dial(address, http.Header{"X-Ambit-Browser-Viewer": []string{viewer}})
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		t.Fatalf("dial %s: %v (%d)", address, err, status)
	}
	socket.SetReadLimit(64 << 20)
	v := &resizeViewer{socket: socket, arrived: make(chan struct{}, 1)}
	t.Cleanup(func() { _ = socket.Close() })
	go v.read()
	return v
}

// read paints every picture on arrival and acknowledges it, as the dock does.
func (v *resizeViewer) read() {
	for {
		kind, data, err := v.socket.ReadMessage()
		at := time.Now()
		if err != nil {
			v.mu.Lock()
			v.ended = err
			v.mu.Unlock()
			v.signal()
			return
		}
		if kind == websocket.TextMessage {
			var record map[string]any
			_ = json.Unmarshal(data, &record)
			v.mu.Lock()
			v.records = append(v.records, record)
			v.mu.Unlock()
			v.signal()
			continue
		}
		picture, ack, ok := parseResizePicture(data, at)
		if !ok {
			continue
		}
		v.mu.Lock()
		v.pictures = append(v.pictures, picture)
		v.mu.Unlock()
		v.signal()
		v.send(nil, ack)
	}
}

// parseResizePicture reads a binary frame or video unit and the
// acknowledgement the dock sends for it; audio and anything else is skipped.
func parseResizePicture(data []byte, at time.Time) (resizePicture, map[string]any, bool) {
	if len(data) < 4 {
		return resizePicture{}, nil, false
	}
	end := 4 + int(binary.BigEndian.Uint32(data))
	if end > len(data) {
		return resizePicture{}, nil, false
	}
	var header struct {
		Type       string `json:"type"`
		Track      string `json:"track"`
		Seq        uint64 `json:"seq"`
		BaseSeq    uint64 `json:"baseSeq"`
		Key        bool   `json:"key"`
		StreamID   string `json:"streamId"`
		ByteLength int    `json:"byteLength"`
		Visible    *struct {
			Width  uint32 `json:"width"`
			Height uint32 `json:"height"`
		} `json:"visible"`
		Surface struct {
			Width  uint32 `json:"width"`
			Height uint32 `json:"height"`
		} `json:"surface"`
		Coded struct {
			Width  uint32 `json:"width"`
			Height uint32 `json:"height"`
		} `json:"coded"`
		Patches []struct {
			ByteLength int `json:"byteLength"`
		} `json:"patches"`
	}
	if json.Unmarshal(data[4:end], &header) != nil {
		return resizePicture{}, nil, false
	}
	picture := resizePicture{at: at, seq: header.Seq, key: header.Key, surface: [2]uint32{header.Surface.Width, header.Surface.Height},
		coded: [2]uint32{header.Coded.Width, header.Coded.Height}, bytes: len(data)}
	picture.visibleWidth, picture.visibleHeight = header.Surface.Width, header.Surface.Height
	if header.Visible != nil {
		picture.visibleWidth, picture.visibleHeight = header.Visible.Width, header.Visible.Height
	}
	switch {
	case header.Type == "media" && header.Track == "video":
		picture.unit, picture.whole = true, header.Key
		return picture, map[string]any{"type": "ack", "track": "video", "streamId": header.StreamID, "seq": header.Seq}, true
	case header.Type == "frame":
		payload := data[end:]
		if header.Patches == nil {
			picture.whole = true
			picture.images = [][]byte{payload}
		} else {
			for _, patch := range header.Patches {
				if patch.ByteLength > len(payload) {
					break
				}
				picture.images = append(picture.images, payload[:patch.ByteLength])
				payload = payload[patch.ByteLength:]
			}
		}
		return picture, map[string]any{"type": "ack", "seq": header.Seq}, true
	}
	return resizePicture{}, nil, false
}

func (v *resizeViewer) signal() {
	select {
	case v.arrived <- struct{}{}:
	default:
	}
}

func (v *resizeViewer) send(t *testing.T, message map[string]any) {
	encoded, _ := json.Marshal(message)
	v.writes.Lock()
	_ = v.socket.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err := v.socket.WriteMessage(websocket.TextMessage, encoded)
	v.writes.Unlock()
	if err != nil && t != nil {
		t.Fatalf("viewer send %s: %v", encoded, err)
	}
}

func (v *resizeViewer) close() {
	v.writes.Lock()
	_ = v.socket.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	v.writes.Unlock()
	_ = v.socket.Close()
}

func (v *resizeViewer) pictureCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.pictures)
}

func (v *resizeViewer) picturesSince(mark int) []resizePicture {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]resizePicture(nil), v.pictures[mark:]...)
}

func (v *resizeViewer) endedWith() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.ended
}

func (v *resizeViewer) awaitPicture(t *testing.T, mark int, limit time.Duration, what string, matches func(resizePicture) bool) resizePicture {
	t.Helper()
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	for {
		v.mu.Lock()
		for _, picture := range v.pictures[mark:] {
			if matches(picture) {
				v.mu.Unlock()
				return picture
			}
		}
		mark = len(v.pictures)
		ended := v.ended
		v.mu.Unlock()
		if ended != nil {
			t.Fatalf("the viewer channel ended while waiting for %s: %v", what, ended)
		}
		select {
		case <-v.arrived:
		case <-deadline.C:
			t.Fatalf("no picture for %s within %v", what, limit)
		}
	}
}

func (v *resizeViewer) awaitRecord(t *testing.T, limit time.Duration, matches func(map[string]any) bool) {
	t.Helper()
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	for {
		v.mu.Lock()
		for _, record := range v.records {
			if matches(record) {
				v.mu.Unlock()
				return
			}
		}
		v.mu.Unlock()
		select {
		case <-v.arrived:
		case <-deadline.C:
			t.Fatalf("no matching record within %v", limit)
		}
	}
}

// summarizeResizeSweep states what the viewer received from the sweep's
// first presentation to the picture of its last.
func summarizeResizeSweep(presented []resizePresentation, pictures []resizePicture, end time.Time) map[string]any {
	start := presented[0].at
	span := end.Sub(start)
	var inside []resizePicture
	for _, picture := range pictures {
		if picture.at.After(start) && !picture.at.After(end) {
			inside = append(inside, picture)
		}
	}
	// Which presentation each width belongs to: the widths of one sweep are
	// distinct except where the integer steps repeat, which honour the later.
	index := map[uint32]int{}
	for k, presentation := range presented {
		index[uint32(2*presentation.width)] = k
	}
	var latencies []time.Duration
	shown := map[int]bool{}
	distinct, keys, wholes, blanks := 0, 0, 0, 0
	var gaps []time.Duration
	bytes := 0
	surfaces, codeds := map[string]bool{}, map[string]bool{}
	previous := uint32(0)
	for position, picture := range inside {
		if k, ok := index[picture.visibleWidth]; ok {
			shown[k] = true
		}
		if picture.visibleWidth != previous {
			distinct++
			previous = picture.visibleWidth
		}
		if picture.key {
			keys++
		}
		if picture.whole && !picture.unit {
			wholes++
		}
		if blankResizePicture(picture) {
			blanks++
		}
		bytes += picture.bytes
		if position > 0 {
			gaps = append(gaps, picture.at.Sub(inside[position-1].at))
		}
		surfaces[fmt.Sprintf("%dx%d", picture.surface[0], picture.surface[1])] = true
		if picture.unit {
			codeds[fmt.Sprintf("%dx%d", picture.coded[0], picture.coded[1])] = true
		}
	}
	for k, presentation := range presented {
		for _, picture := range inside {
			if later, ok := index[picture.visibleWidth]; ok && later >= k && picture.at.After(presentation.at) {
				latencies = append(latencies, picture.at.Sub(presentation.at))
				break
			}
		}
	}
	keysOf := func(set map[string]bool) []string {
		var keys []string
		for key := range set {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return keys
	}
	summary := map[string]any{
		"presentations":               len(presented),
		"presentationsShown":          len(shown),
		"seconds":                     span.Seconds(),
		"pictures":                    len(inside),
		"picturesPerSecond":           float64(len(inside)) / span.Seconds(),
		"distinctSizes":               distinct,
		"distinctSizesPerSecond":      float64(distinct) / span.Seconds(),
		"presentationToPictureMs":     resizeStats(latencies),
		"lastPresentationToPictureMs": float64(end.Sub(presented[len(presented)-1].at).Microseconds()) / 1000,
		"longestGapMs":                resizeStats(gaps)["max"],
		"blankPictures":               blanks,
		"megabytesPerSecond":          float64(bytes) / 1e6 / span.Seconds(),
		"surfaces":                    keysOf(surfaces),
	}
	if len(codeds) > 0 {
		summary["coded"], summary["keyUnits"] = keysOf(codeds), keys
	} else {
		summary["wholeFrames"] = wholes
	}
	return summary
}

// blankResizePicture reports a frame image, whole or a patch of at least
// 64x64, whose sampled pixels are nine tenths black: an unpainted window.
func blankResizePicture(picture resizePicture) bool {
	for _, encoded := range picture.images {
		decoded, err := jpeg.Decode(bytes.NewReader(encoded))
		if err != nil {
			continue
		}
		bounds := decoded.Bounds()
		if bounds.Dx() < 64 || bounds.Dy() < 64 {
			continue
		}
		black, samples := 0, 0
		for y := bounds.Min.Y; y < bounds.Max.Y; y += max(1, bounds.Dy()/32) {
			for x := bounds.Min.X; x < bounds.Max.X; x += max(1, bounds.Dx()/32) {
				r, g, b, _ := decoded.At(x, y).RGBA()
				samples++
				if r>>8 < 16 && g>>8 < 16 && b>>8 < 16 {
					black++
				}
			}
		}
		if black*10 >= samples*9 {
			return true
		}
	}
	return false
}

func resizeStats(values []time.Duration) map[string]any {
	if len(values) == 0 {
		return map[string]any{"n": 0}
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	at := func(q float64) float64 {
		return float64(sorted[int(q*float64(len(sorted)-1)+0.5)].Microseconds()) / 1000
	}
	return map[string]any{"n": len(sorted), "p50": at(0.5), "p90": at(0.9), "max": at(1)}
}
