// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/gorilla/websocket"
)

// TestRealBrowserViewTranscriptRecord records a view transcript straight at a
// real driver: it dials the driver's view endpoint with the upgrade this route
// sends, stands where the page stands (it acknowledges every picture as soon
// as it arrives, subscribes to every track the driver offers, and answers each
// stream as the page does), drives the page for about fifteen seconds, and
// writes the driver's messages and its own replies in the order it observed
// them (browser_view_transcript_linux_test.go replays them through the route).
//
// It runs when AMBIT_TEST_BROWSER_TRANSCRIPT_RECORD names the output file and
// AMBIT_TEST_BROWSER_EXECUTABLE, AMBIT_TEST_CHROME_EXECUTABLE and
// AMBIT_TEST_BROWSER_DISPLAY_HELPER name a real driver, Chrome and display
// helper, as the other real-driver tests do.
func TestRealBrowserViewTranscriptRecord(t *testing.T) {
	output := os.Getenv("AMBIT_TEST_BROWSER_TRANSCRIPT_RECORD")
	driver, chrome, helper := os.Getenv("AMBIT_TEST_BROWSER_EXECUTABLE"), os.Getenv("AMBIT_TEST_CHROME_EXECUTABLE"), os.Getenv("AMBIT_TEST_BROWSER_DISPLAY_HELPER")
	if output == "" || driver == "" || chrome == "" || helper == "" {
		t.Skip("set AMBIT_TEST_BROWSER_TRANSCRIPT_RECORD and the real driver, Chrome and display helper paths")
	}
	scratch, err := os.MkdirTemp("", "transcript-")
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
	workspace.open(t, "transcript-owner")
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
	cli := func(command ...string) {
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
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'" }
	command := []string{"env"}
	for _, item := range environment {
		if strings.HasPrefix(item, "AGENT_BROWSER_") || strings.HasPrefix(item, "DISPLAY=") {
			command = append(command, quote(item))
		}
	}
	command = append(command, quote(driver), "--config", quote(config), "--session", "primary", "daemon")
	if status, body := call(t, engine, http.MethodPost, "/process/session/transcript-owner/exec", SessionExecuteRequest{Command: strings.Join(command, " "), RunAsync: true}); status != http.StatusAccepted {
		t.Fatalf("native owner start: %d %s", status, body)
	}
	awaitPath(t, filepath.Join(scratch, "primary.sock"))
	cli("open", page.URL)
	port := strings.TrimSpace(string(awaitFile(t, filepath.Join(scratch, "primary.stream"))))

	// The dock's upgrade as the production relay declares it, and the route's
	// own members as the route sends them to the driver.
	const width, height = 920, 944
	viewer := uuid.NewString()
	declaration := fmt.Sprintf("width=%d&height=%d&frames=binary&patches=1&frameWindow=8&cursor=viewer&visible=crop&audio=opus&video=av1-444%%2Cav1", width, height)
	address := fmt.Sprintf("ws://127.0.0.1:%s/?pacing=ack&maxFps=60&patches=1&width=%d&height=%d&frames=binary&frameWindow=8&cursor=viewer&visible=crop&audio=opus&video=av1-444,av1", port, width, height)
	socket, response, err := websocket.DefaultDialer.Dial(address, http.Header{"X-Ambit-Browser-Viewer": []string{viewer}})
	if err != nil {
		t.Fatalf("driver dial: %v %v", err, response)
	}
	socket.SetReadLimit(64 << 20)
	recorder := &browserViewRecorder{socket: socket, tracks: map[string]*browserViewRecorderTrack{}, announced: map[string]bool{},
		events: map[string]chan struct{}{"picture": make(chan struct{}), "audio": make(chan struct{}), "video": make(chan struct{})},
		header: browserViewTranscriptHeader{Declaration: declaration, Viewer: viewer, Driver: os.Getenv("AMBIT_TEST_BROWSER_DRIVER_REVISION")}}
	done := make(chan struct{})
	go func() { defer close(done); recorder.read() }()

	wait := func(event <-chan struct{}, what string, limit time.Duration) bool {
		select {
		case <-event:
			return true
		case <-time.After(limit):
			t.Logf("%s: none within %v", what, limit)
			return false
		}
	}
	if !wait(recorder.events["picture"], "first picture", 15*time.Second) {
		t.Fatal("the driver sent no picture")
	}
	video := wait(recorder.events["video"], "video started", 5*time.Second)
	cli("click", "#play")
	audio := wait(recorder.events["audio"], "audio started", 5*time.Second)
	for index := 0; index < 6; index++ {
		cli("scroll", "down", "300")
		time.Sleep(100 * time.Millisecond)
	}
	for _, size := range [][2]int{{1100, 944}, {800, 700}, {width, height}} {
		recorder.send(map[string]any{"type": "presentation", "width": size[0], "height": size[1]})
		time.Sleep(800 * time.Millisecond)
	}
	cli("type", "#notes", "through the pipe")
	if video {
		recorder.send(map[string]any{"type": "video", "keyframe": true, "generation": recorder.generation("video")})
		time.Sleep(500 * time.Millisecond)
		for _, enabled := range []bool{true, false, true} {
			recorder.subscribe("video", enabled)
			time.Sleep(700 * time.Millisecond)
		}
	}
	if audio {
		for _, enabled := range []bool{false, true} {
			recorder.subscribe("audio", enabled)
			time.Sleep(600 * time.Millisecond)
		}
	}
	for index := 0; index < 3; index++ {
		cli("scroll", "up", "300")
		time.Sleep(150 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	_ = socket.Close()
	<-done
	cli("close")
	if err := recorder.write(output); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, line := range recorder.lines {
		kind := line.Direction
		if line.Binary {
			kind += " binary"
		}
		counts[kind]++
	}
	t.Logf("recorded %d messages %v, video %v, audio %v, into %s", len(recorder.lines), counts, video, audio, output)
}

// browserViewRecorder is the page's side of one view connection, recording.
type browserViewRecorder struct {
	socket *websocket.Conn
	header browserViewTranscriptHeader
	// One lock orders the transcript and the socket's writer: a reply is
	// recorded after everything the recorder had received when it chose it.
	mu     sync.Mutex
	lines  []browserViewTranscriptLine
	tracks map[string]*browserViewRecorderTrack
	// The first picture and each track's first stream, each announced once.
	events    map[string]chan struct{}
	announced map[string]bool
}

// announce closes an event's channel the first time. The caller holds mu.
func (r *browserViewRecorder) announce(event string) {
	if !r.announced[event] {
		r.announced[event] = true
		close(r.events[event])
	}
}

// A track as the page holds it: its generation, whether it asked for the
// track, and the stream it bound.
type browserViewRecorderTrack struct {
	offered    bool
	generation int
	enabled    bool
	stream     string
}

func (r *browserViewRecorder) track(name string) *browserViewRecorderTrack {
	if r.tracks[name] == nil {
		r.tracks[name] = &browserViewRecorderTrack{}
	}
	return r.tracks[name]
}

func (r *browserViewRecorder) generation(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.track(name).generation
}

// sendLocked records a reply and writes it. The caller holds mu.
func (r *browserViewRecorder) sendLocked(message map[string]any) {
	encoded, _ := json.Marshal(message)
	r.lines = append(r.lines, browserViewTranscriptLine{Direction: "up", Data: encoded})
	_ = r.socket.WriteMessage(websocket.TextMessage, encoded)
}

func (r *browserViewRecorder) send(message map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sendLocked(message)
}

// subscribe asks for a track anew under a new generation, as the page does.
func (r *browserViewRecorder) subscribe(name string, enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	track := r.track(name)
	if !track.offered {
		return
	}
	track.generation++
	track.enabled, track.stream = enabled, ""
	r.sendLocked(map[string]any{"type": name, "enabled": enabled, "generation": track.generation})
}

func (r *browserViewRecorder) read() {
	for {
		kind, message, err := r.socket.ReadMessage()
		if err != nil {
			return
		}
		r.mu.Lock()
		r.lines = append(r.lines, browserViewTranscriptLine{Direction: "down", Binary: kind == websocket.BinaryMessage, Data: message})
		if kind == websocket.BinaryMessage {
			r.picture(message)
		} else {
			r.record(message)
		}
		r.mu.Unlock()
	}
}

// picture answers a picture as the page does once it painted it: a frame by
// its sequence, a unit of the bound video stream by its stream and sequence.
// The caller holds mu.
func (r *browserViewRecorder) picture(message []byte) {
	header, _, valid := browserBinaryParts(message)
	var value struct {
		Type     string `json:"type"`
		Track    string `json:"track"`
		StreamID string `json:"streamId"`
		Seq      uint64 `json:"seq"`
	}
	if !valid || json.Unmarshal(header, &value) != nil {
		return
	}
	switch {
	case value.Type == "frame":
		r.announce("picture")
		r.sendLocked(map[string]any{"type": "ack", "seq": value.Seq})
	case value.Type == "media" && value.Track == "video" && value.StreamID != "" && value.StreamID == r.track("video").stream:
		r.announce("picture")
		r.sendLocked(map[string]any{"type": "ack", "track": "video", "streamId": value.StreamID, "seq": value.Seq})
	}
}

// record follows a track's records as the page does: an offer is taken up at
// once, and a start of the current, enabled generation binds its stream. The
// caller holds mu.
func (r *browserViewRecorder) record(message []byte) {
	var value struct {
		Type       string `json:"type"`
		State      string `json:"state"`
		Generation int    `json:"generation"`
		StreamID   string `json:"streamId"`
	}
	if json.Unmarshal(message, &value) != nil || (value.Type != "audio" && value.Type != "video") {
		return
	}
	track := r.track(value.Type)
	switch value.State {
	case "available":
		if !track.offered {
			track.offered = true
			track.generation++
			track.enabled = true
			r.sendLocked(map[string]any{"type": value.Type, "enabled": true, "generation": track.generation})
		}
	case "started":
		if value.Generation == track.generation && track.enabled {
			track.stream = value.StreamID
			r.announce(value.Type)
		}
	case "stopped", "unavailable":
		if value.Generation == track.generation {
			track.stream = ""
		}
	}
}

func (r *browserViewRecorder) write(path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := gzip.NewWriter(file)
	encoder := json.NewEncoder(writer)
	if err := encoder.Encode(r.header); err != nil {
		return err
	}
	for _, line := range r.lines {
		if err := encoder.Encode(line); err != nil {
			return err
		}
	}
	return writer.Close()
}
