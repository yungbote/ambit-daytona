// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const browserFixtureViewer = "33333333-3333-4333-8333-333333333333"

// browserViewFixtureDriver is the driver's side of one view connection. It
// records every message the route forwards to it, one base64 line each in
// <name>.upstream, so a test can state what reached the driver byte for byte.
type browserViewFixtureDriver struct {
	connection *websocket.Conn
	received   *os.File
}

func (d *browserViewFixtureDriver) read() (int, []byte, error) {
	kind, message, err := d.connection.ReadMessage()
	if err == nil {
		_, _ = d.received.WriteString(base64.StdEncoding.EncodeToString(message) + "\n")
	}
	return kind, message, err
}

func (d *browserViewFixtureDriver) drain() {
	for {
		if _, _, err := d.read(); err != nil {
			return
		}
	}
}

func (d *browserViewFixtureDriver) send(record map[string]any) bool {
	return d.connection.WriteJSON(record) == nil
}

func (d *browserViewFixtureDriver) sendBinary(message []byte) bool {
	return d.connection.WriteMessage(websocket.BinaryMessage, message) == nil
}

// awaitAcknowledgement reads until the viewer acknowledges seq, answering a
// presenter's sizes as the driver does. It reports whether the connection
// is still usable.
func (d *browserViewFixtureDriver) awaitAcknowledgement(seq int, onPresentation func(width, height uint32) bool) bool {
	for {
		_, message, err := d.read()
		if err != nil {
			return false
		}
		var value struct {
			Type   string `json:"type"`
			Seq    int    `json:"seq"`
			Width  uint32 `json:"width"`
			Height uint32 `json:"height"`
		}
		if json.Unmarshal(message, &value) != nil {
			continue
		}
		if value.Type == "presentation" && !onPresentation(value.Width, value.Height) {
			return false
		}
		if value.Type == "ack" && value.Seq == seq {
			return true
		}
	}
}

// This executes in the existing owned driver process, behind its real loopback
// listener, and speaks the driver's side of the view route. It checks only
// what the route owns on the upgrade: ack pacing, patch compositing, the
// presenter's rate, size and identity, or an observer's absence of them. The
// rest of the upgrade is recorded in <name>.upgrade exactly as it arrived.
func serveBrowserViewChannelFixture(w http.ResponseWriter, r *http.Request, dir, name, mode string, closeListener func() error) {
	query := r.URL.Query()
	presenter := query.Get("maxFps") == "60" && query.Get("width") == "320" && query.Get("height") == "240" && r.Header.Get("X-Ambit-Browser-Viewer") == browserFixtureViewer
	switch mode {
	case "view-channel-observer":
		presenter = query.Get("maxFps") == "10" && !query.Has("width") && !query.Has("height") && r.Header.Get("X-Ambit-Browser-Viewer") == ""
	case "view-channel-replay":
		// A recorded dock presents at its own size.
		presenter = query.Get("maxFps") == "60" && query.Has("width") && query.Has("height") && validBrowserUUID(r.Header.Get("X-Ambit-Browser-Viewer"))
	}
	if query.Get("pacing") != "ack" || query.Get("patches") != "1" || !presenter {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, name+".upgrade"), []byte(r.RequestURI), 0600); err != nil {
		return
	}
	connection, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer connection.Close()
	connection.SetReadLimit(64 << 20)
	received, err := os.OpenFile(filepath.Join(dir, name+".upstream"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer received.Close()
	closed, err := os.OpenFile(filepath.Join(dir, name+".view-closed"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer func() { _, _ = closed.WriteString("closed\n"); _ = closed.Close() }()
	driver := &browserViewFixtureDriver{connection: connection, received: received}
	switch mode {
	case "view-channel-replay":
		serveBrowserViewReplay(driver, filepath.Join(dir, name+".transcript"))
		return
	case "view-channel-stall":
		// One picture, then this driver never reads again.
		header, payload := browserFixtureFrame(false)
		_ = driver.sendBinary(packBrowserFixtureFrame(header, payload))
		time.Sleep(30 * time.Second)
		return
	case "view-channel-oversize":
		for _, size := range []int{browserBinaryFrameLimit, browserBinaryFrameLimit + 1} {
			if !driver.sendBinary(browserFixtureFrameOfSize(size)) {
				return
			}
		}
		driver.drain()
		return
	}
	_ = driver.send(map[string]any{"type": "status", "connected": true, "screencasting": true, "private": browserFixtureSecret})
	_ = driver.send(map[string]any{"type": "console", "text": browserFixtureSecret})
	switch mode {
	case "view-channel-media":
		for _, message := range browserFixtureMedia() {
			if message.binary {
				_ = driver.sendBinary(message.data)
			} else {
				_ = connection.WriteMessage(websocket.TextMessage, message.data)
			}
		}
		driver.drain()
		return
	case "view-channel-records":
		// A files doorbell and a cursor record, each with a field that must
		// not travel; a doorbell without its clock does not travel at all.
		_ = driver.send(map[string]any{"type": "files", "ts": 1234567, "path": browserFixtureSecret})
		_ = driver.send(map[string]any{"type": "files"})
		_ = driver.send(map[string]any{"type": "cursor", "ts": 1234568, "serial": 17, "css": "text", "private": browserFixtureSecret})
	case "view-channel-legacy-binary", "view-channel-malformed-legacy-binary":
		header, payload := browserFixtureFrame(false)
		delete(header, "surface")
		header["metadata"] = map[string]any{"deviceWidth": 640, "deviceHeight": 480}
		if mode == "view-channel-malformed-legacy-binary" {
			payload[len(payload)-1] = 0
		}
		_ = driver.sendBinary(packBrowserFixtureFrame(header, payload))
		driver.drain()
		return
	case "view-channel-legacy", "view-channel-old-native", "view-channel-malformed-text":
		header, payload := browserFixtureFrame(false)
		delete(header, "byteLength")
		header["data"] = base64.StdEncoding.EncodeToString(payload)
		if mode == "view-channel-legacy" {
			delete(header, "surface")
		}
		if mode == "view-channel-malformed-text" {
			header["data"] = "not-a-jpeg"
		}
		_ = driver.send(header)
		driver.drain()
		return
	case "view-channel-window":
		// Nine pictures before any acknowledgement: the window is the
		// driver's own, and the viewer's cumulative acknowledgement of the
		// last one comes back as it was sent.
		for sequence := 10; sequence <= 26; sequence += 2 {
			if !driver.sendBinary(browserFixtureSequencedFrame(sequence)) {
				return
			}
		}
		if driver.awaitAcknowledgement(26, func(uint32, uint32) bool { return true }) {
			_ = driver.send(map[string]any{"type": "finished"})
		}
		driver.drain()
		return
	case "view-channel-error":
		_ = driver.send(map[string]any{"type": "error", "message": browserFixtureSecret})
		driver.drain()
		return
	}
	binaryFrames := query.Get("frames") == "binary"
	for _, patched := range []bool{false, true} {
		header, payload := browserFixtureFrame(patched)
		message := packBrowserFixtureFrame(header, payload)
		switch {
		case mode == "view-channel-legacy-binary-after-native" && patched:
			header, payload = browserFixtureFrame(false)
			header["seq"] = 12
			delete(header, "surface")
			header["metadata"] = map[string]any{"deviceWidth": 640, "deviceHeight": 480}
			message = packBrowserFixtureFrame(header, payload)
		case mode == "view-channel-format-change" && patched:
			header, payload = browserFixtureFrame(false)
			header["seq"] = 12
			delete(header, "byteLength")
			header["data"] = base64.StdEncoding.EncodeToString(payload)
			_ = driver.send(header)
			driver.drain()
			return
		case mode == "view-channel-bad-frame":
			header["byteLength"] = len(payload) + 1
			message = packBrowserFixtureFrame(header, payload)
		case mode == "view-channel-bad-chain" && patched:
			header["baseSeq"] = 9
			message = packBrowserFixtureFrame(header, payload)
		}
		if binaryFrames {
			if !driver.sendBinary(message) {
				return
			}
		} else {
			if patched {
				patch := header["patches"].([]any)[0].(map[string]any)
				delete(patch, "byteLength")
				patch["data"] = base64.StdEncoding.EncodeToString(payload)
			} else {
				delete(header, "byteLength")
				header["data"] = base64.StdEncoding.EncodeToString(payload)
			}
			if !driver.send(header) {
				return
			}
		}
		acknowledged := driver.awaitAcknowledgement(header["seq"].(int), func(width, height uint32) bool {
			if mode == "view-channel-listener-ended" {
				_ = closeListener()
				return false
			}
			return driver.send(map[string]any{"type": "presentation", "role": "primary", "requested": map[string]uint32{"width": width, "height": height}, "applied": browserFixtureSurface(), "private": browserFixtureSecret})
		})
		if !acknowledged {
			driver.drain()
			return
		}
		if mode == "view-channel-eof" {
			return
		}
	}
	if mode == "view-channel-finished" {
		_ = driver.send(map[string]any{"type": "finished", "private": browserFixtureSecret})
	}
	driver.drain()
}

// A whole picture at seq and, after the first, a patch on the one before.
func browserFixtureSequencedFrame(sequence int) []byte {
	header, payload := browserFixtureFrame(sequence != 10)
	header["seq"] = sequence
	if sequence != 10 {
		header["baseSeq"] = sequence - 2
	}
	return packBrowserFixtureFrame(header, payload)
}

type browserFixtureMessage struct {
	binary bool
	data   []byte
}

// Pictures, sound and their records that the previous route refused or
// dropped: a codec token it did not know, a record state and a header member
// it did not know, a stream that starts past 1 and skips, sound of a codec it
// did not know, a unit of a stream no viewer subscribed to. Each is the
// contract of the driver and the viewer, and passes as sent.
func browserFixtureMedia() []browserFixtureMessage {
	unit := func(header map[string]any, payload []byte) browserFixtureMessage {
		return browserFixtureMessage{binary: true, data: packBrowserFixtureFrame(header, payload)}
	}
	record := func(value map[string]any) browserFixtureMessage {
		encoded, _ := json.Marshal(value)
		return browserFixtureMessage{data: encoded}
	}
	stream := "44444444-4444-4444-8444-444444444444"
	video := func(seq int, key bool) map[string]any {
		header := map[string]any{"type": "media", "track": "video", "codec": "av2", "streamId": stream, "seq": seq, "ts": 1000 + seq,
			"key": key, "coded": map[string]any{"width": 640, "height": 480}, "visible": map[string]any{"x": 0, "y": 0, "width": 640, "height": 480},
			"surface": browserFixtureFrameSurface(), "quality": "motion", "byteLength": 3, "pageGeneration": "55555555-5555-4555-8555-555555555555"}
		if key {
			header["codecString"] = "av02.0.08M.08"
		}
		return header
	}
	return []browserFixtureMessage{
		record(map[string]any{"type": "video", "state": "available", "codec": "av2"}),
		record(map[string]any{"type": "video", "state": "warming", "codec": "av2", "generation": 1}),
		record(map[string]any{"type": "video", "state": "started", "codec": "av2", "codecString": "av02.0.08M.08", "generation": 1, "streamId": stream, "rate": 4000000}),
		unit(video(5, true), []byte{1, 2, 3}),
		unit(video(7, false), []byte{4, 5, 6}),
		record(map[string]any{"type": "audio", "state": "started", "codec": "flac", "generation": 9, "streamId": stream}),
		unit(map[string]any{"type": "media", "track": "audio", "codec": "flac", "streamId": stream, "seq": 1, "ts": 1, "samples": 960, "byteLength": 2}, []byte{7, 8}),
		unit(map[string]any{"type": "media", "track": "haptics", "streamId": stream, "seq": 1, "byteLength": 1}, []byte{9}),
		{binary: true, data: browserFixtureSequencedFrame(10)},
	}
}

func browserFixtureFrameSurface() map[string]any {
	header, _ := browserFixtureFrame(false)
	return header["surface"].(map[string]any)
}

func browserViewerAddress(server *httptest.Server, sessionID, viewID string) string {
	return "ws" + strings.TrimPrefix(server.URL, "http") + "/process/session/" + sessionID + "/browser-views/" + viewID + "/channel"
}

func openBrowserViewer(t *testing.T, server *httptest.Server, sessionID, viewID string, binary bool) *websocket.Conn {
	t.Helper()
	query := "?width=320&height=240"
	if binary {
		query += "&frames=binary&patches=1"
	}
	return openBrowserViewerWith(t, server, sessionID, viewID, query)
}

// openBrowserViewerWith opens a presenting viewer with the given query and
// reads the driver's status record, which every fixture sends first.
func openBrowserViewerWith(t *testing.T, server *httptest.Server, sessionID, viewID, query string) *websocket.Conn {
	t.Helper()
	connection, response, err := websocket.DefaultDialer.Dial(browserViewerAddress(server, sessionID, viewID)+query, http.Header{"X-Ambit-Browser-Viewer": []string{browserFixtureViewer}})
	if err != nil {
		t.Fatalf("viewer dial: %v response=%v", err, response)
	}
	t.Cleanup(func() { _ = connection.Close() })
	connection.SetReadLimit(64 << 20)
	if status := readViewerText(t, connection); status["type"] != "status" || status["connected"] != true {
		t.Fatalf("initial state: %v", status)
	}
	return connection
}

func readViewerText(t *testing.T, connection *websocket.Conn) map[string]any {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	kind, message, err := connection.ReadMessage()
	if err != nil || kind != websocket.TextMessage || bytes.Contains(message, []byte(browserFixtureSecret)) {
		t.Fatalf("visual text: kind=%d err=%v message=%s", kind, err, message)
	}
	var result map[string]any
	if err := json.Unmarshal(message, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

// readViewerMessage reads the next message and fails unless it is exactly
// the one the driver sent, kind and bytes.
func readViewerMessage(t *testing.T, connection *websocket.Conn, want browserFixtureMessage) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	kind, message, err := connection.ReadMessage()
	wantKind := websocket.TextMessage
	if want.binary {
		wantKind = websocket.BinaryMessage
	}
	if err != nil || kind != wantKind || !bytes.Equal(message, want.data) {
		t.Fatalf("viewer received kind=%d err=%v %d bytes, want kind=%d %d bytes as the driver sent them", kind, err, len(message), wantKind, len(want.data))
	}
}

// readViewerFrame reads the next message and fails unless it is the driver's
// picture: the same header members and values, and the same image bytes. It
// holds on every revision of the route; the tests of the pipe itself state
// byte identity with readViewerMessage.
func readViewerFrame(t *testing.T, connection *websocket.Conn, patched bool) {
	t.Helper()
	header, payload := browserFixtureFrame(patched)
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	kind, message, err := connection.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage {
		t.Fatalf("picture: kind=%d err=%v", kind, err)
	}
	if !browserViewSamePicture(message, packBrowserFixtureFrame(header, payload)) {
		t.Fatalf("the viewer's picture of %d bytes is not the driver's", len(message))
	}
}

// browserViewSamePicture reports whether two binary messages carry the same
// JSON header and the same bytes after it.
func browserViewSamePicture(a, b []byte) bool {
	aHeader, aPayload, aValid := browserBinaryParts(a)
	bHeader, bPayload, bValid := browserBinaryParts(b)
	return aValid && bValid && bytes.Equal(aPayload, bPayload) && browserViewJSONEqual(aHeader, bHeader)
}

// browserFixtureFrameOfSize is a whole picture whose message is exactly size
// bytes: the image, then padding a JPEG reader never reaches.
func browserFixtureFrameOfSize(size int) []byte {
	header, image := browserFixtureFrame(false)
	// The header states the payload's length, so its own length depends on
	// that number's digits: settle both together.
	length := size
	for {
		header["byteLength"] = length
		encoded, err := json.Marshal(header)
		if err != nil {
			panic(err)
		}
		next := size - 4 - len(encoded)
		if next == length {
			break
		}
		length = next
	}
	return packBrowserFixtureFrame(header, append(image, make([]byte, length-len(image))...))
}

// awaitDriverReceived waits until the driver has received at least count
// messages from the route and returns them, in order.
func awaitDriverReceived(t *testing.T, workspace *browserWorkspace, name string, count int) [][]byte {
	t.Helper()
	var received [][]byte
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		received = nil
		file, err := os.Open(filepath.Join(workspace.socketDir, name+".upstream"))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64<<10), 16<<20)
		for scanner.Scan() {
			message, err := base64.StdEncoding.DecodeString(scanner.Text())
			if err != nil {
				t.Fatal(err)
			}
			received = append(received, message)
		}
		_ = file.Close()
		if len(received) >= count {
			return received
		}
	}
	t.Fatalf("the driver received %d messages, want %d", len(received), count)
	return nil
}

func driverUpgrade(t *testing.T, workspace *browserWorkspace, name string) string {
	t.Helper()
	return string(awaitFile(t, filepath.Join(workspace.socketDir, name+".upgrade")))
}

func TestBrowserViewerChannelWaitsForPaintAndResizesWithoutRedial(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel-finished")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	channel := openBrowserViewer(t, workspace.serve(t), "viewer-owner", id, true)
	readViewerFrame(t, channel, false)
	// An acknowledged resize response arrives while the first frame is still
	// pending. If the relay had auto-acked it, the next frame would arrive first.
	sendFrame(t, channel, map[string]any{"type": "presentation", "width": 400, "height": 300})
	presentation := readViewerText(t, channel)
	if presentation["type"] != "presentation" || presentation["requested"].(map[string]any)["width"] != float64(400) {
		t.Fatalf("presentation: %v", presentation)
	}
	sendFrame(t, channel, map[string]any{"type": "ack", "seq": 10})
	readViewerFrame(t, channel, true)
	sendFrame(t, channel, map[string]any{"type": "ack", "seq": 12})
	if finished := readViewerText(t, channel); len(finished) != 1 || finished["type"] != "finished" {
		t.Fatalf("terminal projection: %v", finished)
	}
	expectClose(t, channel, browserChannelViewEnded, "browser_view_ended", 5*time.Second)
	awaitFile(t, filepath.Join(workspace.socketDir, "primary.view-closed"))
}

// This channel carries pictures only as binary messages: a viewer that did
// not ask for them gets the driver's text pictures refused as unsupported,
// the answer that sends it to the compatible reader.
func TestBrowserViewerChannelCarriesPicturesOnlyAsBinaryMessages(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel-finished")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	channel := openBrowserViewer(t, workspace.serve(t), "viewer-owner", id, false)
	expectClose(t, channel, websocket.CloseUnsupportedData, "browser_view_channel_unsupported", 5*time.Second)
}

func TestBrowserViewerChannelRejectsUnboundAndForeignUpgrades(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.open(t, "foreign-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	server := workspace.serve(t)
	for _, test := range []struct {
		owner, query, viewer string
		status               int
	}{
		{"viewer-owner", "", "", http.StatusBadRequest},
		{"viewer-owner", "?width=320&height=240", "", http.StatusBadRequest},
		{"viewer-owner", "?width=0&height=240", browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=2049&height=240", browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=320", browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=320&width=320&height=240", browserFixtureViewer, http.StatusBadRequest},
		// A declaration past its bound, or one the driver would read as
		// something else than what was declared, is refused, never forwarded.
		{"viewer-owner", "?width=320&height=240&video=" + strings.Repeat("a", browserViewDeclarationLimit), browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=320&height=240&video=av1%26maxFps%3D60", browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=320&height=240&video=av1+x", browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=320&height=240&video=%ZZ", browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=320&height=240&=binary", browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=320&height=240&video=%C3%A9", browserFixtureViewer, http.StatusBadRequest},
		{"foreign-owner", "?width=320&height=240&frames=binary", browserFixtureViewer, http.StatusNotFound},
	} {
		connection, response, err := websocket.DefaultDialer.Dial(browserViewerAddress(server, test.owner, id)+test.query, http.Header{"X-Ambit-Browser-Viewer": []string{test.viewer}})
		if connection != nil {
			_ = connection.Close()
		}
		if err == nil || response == nil || response.StatusCode != test.status {
			t.Fatalf("upgrade %s %s: response=%v error=%v", test.owner, test.query, response, err)
		}
		_ = response.Body.Close()
	}
	response, err := server.Client().Get(strings.Replace(browserViewerAddress(server, "viewer-owner", id), "ws://", "http://", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("plain GET: %d", response.StatusCode)
	}
}

// The viewer's declaration of what it draws and plays reaches the driver as
// it was made, whatever it names, while the members the route owns are the
// route's: a viewer cannot declare its own pacing, rate, compositing or size.
func TestBrowserViewerChannelForwardsTheDeclarationAsMade(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	channel := openBrowserViewerWith(t, workspace.serve(t), "viewer-owner", id,
		"?width=320&frames=binary&pacing=push&frameWindow=9&cursor=hidden&visible=scale&audio=flac&height=240&maxFps=120&video=av2%2Cav1-444&patches=0&maxWidth=4096&maxHeight=2048&frames=binary&flag")
	readViewerFrame(t, channel, false)
	want := "/?pacing=ack&maxFps=60&patches=1&width=320&height=240&frames=binary&frameWindow=9&cursor=hidden&visible=scale&audio=flac&video=av2,av1-444&maxWidth=4096&maxHeight=2048&frames=binary&flag"
	if upgrade := driverUpgrade(t, workspace, "primary"); upgrade != want {
		t.Fatalf("the driver's upgrade is %s, want %s", upgrade, want)
	}
}

// An observer's upgrade names no presenter, so the driver holds it to the
// secondary rate and no size (the fixture refuses any other upgrade). What it
// sends reaches the driver as sent: the driver answers a size only from the
// presenter its upgrade named.
func TestBrowserViewerChannelObserverUpgradeNamesNoPresenter(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel-observer")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	channel := openBrowserViewerWith(t, workspace.serve(t), "viewer-owner", id, "?frames=binary&frameWindow=8")
	readViewerFrame(t, channel, false)
	sendFrame(t, channel, map[string]any{"type": "presentation", "width": 400, "height": 300})
	received := awaitDriverReceived(t, workspace, "primary", 1)
	if string(received[0]) != `{"height":300,"type":"presentation","width":400}` {
		t.Fatalf("the driver received %s", received[0])
	}
}

// The driver's files doorbell and cursor records reach the viewer as their
// bounded projections, and a doorbell without its clock does not.
func TestBrowserViewerChannelProjectsDoorbellsAndCursors(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel-records")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	channel := openBrowserViewer(t, workspace.serve(t), "viewer-owner", id, true)
	if doorbell := readViewerText(t, channel); len(doorbell) != 2 || doorbell["type"] != "files" || doorbell["ts"] != float64(1234567) {
		t.Fatalf("files doorbell: %v", doorbell)
	}
	if cursor := readViewerText(t, channel); len(cursor) != 4 || cursor["type"] != "cursor" || cursor["ts"] != float64(1234568) || cursor["serial"] != float64(17) || cursor["css"] != "text" {
		t.Fatalf("cursor record: %v", cursor)
	}
	readViewerFrame(t, channel, false)
}

// A driver that cannot speak this channel sends the viewer to the compatible
// reader with its first picture; any other picture is the viewer's to read.
func TestBrowserViewerChannelFallsBackOnlyForValidInitialOldFrames(t *testing.T) {
	for _, mode := range []string{"view-channel-legacy", "view-channel-old-native", "view-channel-malformed-text", "view-channel-format-change", "view-channel-legacy-binary"} {
		t.Run(mode, func(t *testing.T) {
			workspace := newBrowserWorkspace(t)
			workspace.open(t, "viewer-owner")
			workspace.runDriver(t, "viewer-owner", "primary", mode)
			id, _ := workspace.only(t, "viewer-owner", "primary")
			channel := openBrowserViewer(t, workspace.serve(t), "viewer-owner", id, true)
			if mode == "view-channel-format-change" {
				readViewerFrame(t, channel, false)
				sendFrame(t, channel, map[string]any{"type": "ack", "seq": 10})
			}
			if mode == "view-channel-malformed-text" || mode == "view-channel-format-change" {
				expectClose(t, channel, websocket.CloseInternalServerErr, "browser_view_invalid_frame", 5*time.Second)
			} else {
				expectClose(t, channel, websocket.CloseUnsupportedData, "browser_view_channel_unsupported", 5*time.Second)
			}
		})
	}
}

// Pictures are the driver's and the viewer's contract: the route reads
// neither their envelope, their chain nor their window. A picture that is
// not the one a view that cannot speak this channel sends, or that follows
// the first, passes as sent, and so do more pictures than any window.
func TestBrowserViewerChannelLeavesPicturesToTheViewer(t *testing.T) {
	legacy := func(seq int) []byte {
		header, payload := browserFixtureFrame(false)
		header["seq"] = seq
		delete(header, "surface")
		header["metadata"] = map[string]any{"deviceWidth": 640, "deviceHeight": 480}
		return packBrowserFixtureFrame(header, payload)
	}
	malformedLegacy := func() []byte {
		header, payload := browserFixtureFrame(false)
		delete(header, "surface")
		header["metadata"] = map[string]any{"deviceWidth": 640, "deviceHeight": 480}
		payload[len(payload)-1] = 0
		return packBrowserFixtureFrame(header, payload)
	}
	whole := browserFixtureSequencedFrame(10)
	badLength := func() []byte {
		header, payload := browserFixtureFrame(false)
		header["byteLength"] = len(payload) + 1
		return packBrowserFixtureFrame(header, payload)
	}
	badChain := func() []byte {
		header, payload := browserFixtureFrame(true)
		header["baseSeq"] = 9
		return packBrowserFixtureFrame(header, payload)
	}
	for _, test := range []struct {
		mode     string
		pictures [][]byte
	}{
		{"view-channel-malformed-legacy-binary", [][]byte{malformedLegacy()}},
		{"view-channel-legacy-binary-after-native", [][]byte{whole, legacy(12)}},
		{"view-channel-bad-frame", [][]byte{badLength()}},
		{"view-channel-bad-chain", [][]byte{whole, badChain()}},
		{"view-channel-window", nil},
	} {
		t.Run(test.mode, func(t *testing.T) {
			workspace := newBrowserWorkspace(t)
			workspace.open(t, "viewer-owner")
			workspace.runDriver(t, "viewer-owner", "primary", test.mode)
			id, _ := workspace.only(t, "viewer-owner", "primary")
			channel := openBrowserViewerWith(t, workspace.serve(t), "viewer-owner", id, "?width=320&height=240&frames=binary&frameWindow=8")
			if test.mode == "view-channel-window" {
				for sequence := 10; sequence <= 26; sequence += 2 {
					readViewerMessage(t, channel, browserFixtureMessage{binary: true, data: browserFixtureSequencedFrame(sequence)})
				}
				sendFrame(t, channel, map[string]any{"type": "ack", "seq": 26})
				if readViewerText(t, channel)["type"] != "finished" {
					t.Fatal("the driver did not receive the acknowledgement as sent")
				}
				return
			}
			for index, picture := range test.pictures {
				readViewerMessage(t, channel, browserFixtureMessage{binary: true, data: picture})
				if index+1 < len(test.pictures) {
					sendFrame(t, channel, map[string]any{"type": "ack", "seq": 10})
				}
			}
		})
	}
}

// Pictures pass byte for byte: the driver's own header, in its own spelling,
// and its image bytes. The previous route rewrote every picture's header.
func TestBrowserViewerChannelPassesPicturesByteForByte(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	channel := openBrowserViewer(t, workspace.serve(t), "viewer-owner", id, true)
	for _, patched := range []bool{false, true} {
		header, payload := browserFixtureFrame(patched)
		readViewerMessage(t, channel, browserFixtureMessage{binary: true, data: packBrowserFixtureFrame(header, payload)})
		sendFrame(t, channel, map[string]any{"type": "ack", "seq": header["seq"]})
	}
}

// Sound, pictures and their records pass as the driver sends them, byte for
// byte, including what the previous route refused or dropped: a codec it did
// not know, a record state and members it did not know, a stream that starts
// past 1 and skips, a track it did not know.
func TestBrowserViewerChannelPassesMediaAsSent(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel-media")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	channel := openBrowserViewerWith(t, workspace.serve(t), "viewer-owner", id, "?width=320&height=240&frames=binary&video=av2&audio=flac")
	for _, message := range browserFixtureMedia() {
		readViewerMessage(t, channel, message)
	}
}

// What the viewer sends reaches the driver byte for byte, including what the
// previous route refused or dropped: an acknowledgement of a picture never
// sent, a repeated one, sizes the driver bounds itself, a request for a track
// before any offer, and messages the contract has not named yet. The route
// refuses only what is not one bounded JSON object, and the driver's input
// vocabulary, which never travels on the view route.
func TestBrowserViewerChannelForwardsViewerMessagesAsSent(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	server := workspace.serve(t)
	channel := openBrowserViewer(t, server, "viewer-owner", id, true)
	readViewerFrame(t, channel, false)
	sent := []string{
		`{"type":"ack","seq":9}`,
		`{"type":"ack","seq":10}`,
		`{"type":"ack","seq":10}`,
		`{"type":"presentation","width":400,"height":300,"viewer":"changed"}`,
		`{"type":"presentation","width":2049,"height":300}`,
		`{"type":"video","keyframe":true,"generation":7}`,
		`{"type":"audio","enabled":true,"generation":1,"extra":1}`,
		`{"type":"rate","generation":1,"bitsPerSecond":4000000,"burstBytes":65536}`,
		`{"seq":3}`,
		browserViewerMessageOf(browserViewerMessageLimit),
	}
	for _, message := range sent {
		if err := channel.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			t.Fatal(err)
		}
	}
	received := awaitDriverReceived(t, workspace, "primary", len(sent))
	for index, message := range sent {
		if string(received[index]) != message {
			t.Fatalf("the driver received %s, want %s", received[index], message)
		}
	}
	for _, refused := range []struct {
		name    string
		kind    int
		message string
		reason  string
	}{
		{"not-json", websocket.TextMessage, `{`, "browser_view_invalid_message"},
		{"not-an-object", websocket.TextMessage, `[{"type":"ack","seq":10}]`, "browser_view_invalid_message"},
		{"null", websocket.TextMessage, `null`, "browser_view_invalid_message"},
		{"past-the-bound", websocket.TextMessage, strings.Repeat(" ", browserViewerMessageLimit+1), "browser_view_invalid_message"},
		{"not-utf8", websocket.TextMessage, "{\"type\":\"ack\",\"x\":\"\xff\"}", "browser_view_invalid_message"},
		{"mouse", websocket.TextMessage, `{"type":"input_mouse","eventType":"mousePressed","x":1,"y":1,"button":"left"}`, "browser_view_invalid_message"},
		{"keyboard", websocket.TextMessage, `{"type":"input_keyboard","eventType":"keyDown","key":"a","text":"a"}`, "browser_view_invalid_message"},
		{"touch", websocket.TextMessage, `{"type":"input_touch","eventType":"touchStart","touchPoints":[]}`, "browser_view_invalid_message"},
		{"duplicate-type", websocket.TextMessage, `{"type":"ack","type":"input_mouse","eventType":"mouseMoved","x":1,"y":1}`, "browser_view_invalid_message"},
		{"escaped-type", websocket.TextMessage, `{"type":"input_mouse","eventType":"mouseMoved","x":1,"y":1}`, "browser_view_invalid_message"},
		{"binary", websocket.BinaryMessage, `{"type":"ack","seq":10}`, "frame_not_text"},
	} {
		t.Run(refused.name, func(t *testing.T) {
			channel := openBrowserViewer(t, server, "viewer-owner", id, true)
			readViewerFrame(t, channel, false)
			if err := channel.WriteMessage(refused.kind, []byte(refused.message)); err != nil {
				t.Fatal(err)
			}
			expectClose(t, channel, websocket.ClosePolicyViolation, refused.reason, 5*time.Second)
		})
	}
}

// The route bounds one message in each direction: the driver's at 12 MiB and
// the viewer's at 4 KiB, each inclusive. A driver message past its bound ends
// the channel as a failed screencast.
func TestBrowserViewerChannelBoundsTheDriversMessages(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel-oversize")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	connection, _, err := websocket.DefaultDialer.Dial(browserViewerAddress(workspace.serve(t), "viewer-owner", id)+"?width=320&height=240&frames=binary", http.Header{"X-Ambit-Browser-Viewer": []string{browserFixtureViewer}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetReadLimit(64 << 20)
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	kind, message, err := connection.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || !browserViewSamePicture(message, browserFixtureFrameOfSize(browserBinaryFrameLimit)) {
		t.Fatalf("a message at the bound: kind=%d %d bytes err=%v", kind, len(message), err)
	}
	expectClose(t, connection, websocket.CloseInternalServerErr, "screencast_failed", 10*time.Second)
}

// A driver that stops reading holds one write of the viewer's messages for at
// most the driver write deadline; then the channel ends as a failed screencast.
func TestBrowserViewerChannelBoundsADriverThatStopsReading(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel-stall")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	connection, _, err := websocket.DefaultDialer.Dial(browserViewerAddress(workspace.serve(t), "viewer-owner", id)+"?width=320&height=240&frames=binary", http.Header{"X-Ambit-Browser-Viewer": []string{browserFixtureViewer}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	readViewerFrame(t, connection, false)
	message := []byte(`{"type":"presentation","width":400,"height":300}`)
	started := time.Now()
	// The viewer writes until its own transport backs up behind the route,
	// or the channel ends.
	go func() {
		for connection.WriteMessage(websocket.TextMessage, message) == nil {
		}
	}()
	expectClose(t, connection, websocket.CloseInternalServerErr, "screencast_failed", 30*time.Second)
	if elapsed := time.Since(started); elapsed < browserDriverWriteTimeout {
		t.Fatalf("the channel ended after %v, before the driver write deadline", elapsed)
	}
}

func TestBrowserViewerChannelClosesOnDriverFailureAndRecoversAfterEOF(t *testing.T) {
	for _, mode := range []string{"view-channel-eof", "view-channel-error"} {
		t.Run(mode, func(t *testing.T) {
			workspace := newBrowserWorkspace(t)
			workspace.open(t, "viewer-owner")
			workspace.runDriver(t, "viewer-owner", "primary", mode)
			id, _ := workspace.only(t, "viewer-owner", "primary")
			server := workspace.serve(t)
			channel := openBrowserViewer(t, server, "viewer-owner", id, true)
			if mode == "view-channel-eof" {
				readViewerFrame(t, channel, false)
				sendFrame(t, channel, map[string]any{"type": "ack", "seq": 10})
			}
			if mode == "view-channel-error" {
				failure := readViewerText(t, channel)
				if failure["type"] != "unavailable" || failure["reason"] != "screencast_failed" || len(failure) != 2 {
					t.Fatalf("failure: %v", failure)
				}
			}
			expectClose(t, channel, websocket.CloseInternalServerErr, "screencast_failed", 5*time.Second)
			if mode == "view-channel-eof" {
				reopened := openBrowserViewer(t, server, "viewer-owner", id, true)
				readViewerFrame(t, reopened, false)
			}
		})
	}
}

func TestBrowserViewerChannelEndsWithExactProcessAndListener(t *testing.T) {
	for _, mode := range []string{"shell", "driver", "listener"} {
		t.Run(mode, func(t *testing.T) {
			workspace := newBrowserWorkspace(t)
			supervisor := workspace.open(t, "viewer-owner")
			fixture := "view-channel"
			if mode == "listener" {
				fixture = "view-channel-listener-ended"
			}
			driver := workspace.runDriver(t, "viewer-owner", "primary", fixture)
			id, _ := workspace.only(t, "viewer-owner", "primary")
			channel := openBrowserViewer(t, workspace.serve(t), "viewer-owner", id, true)
			readViewerFrame(t, channel, false)
			switch mode {
			case "shell":
				workspace.endShellUncleanly(t, "viewer-owner", supervisor)
			case "driver":
				if err := syscall.Kill(driver, syscall.SIGKILL); err != nil {
					t.Fatal(err)
				}
			case "listener":
				sendFrame(t, channel, map[string]any{"type": "presentation", "width": 400, "height": 300})
			}
			if mode == "driver" {
				// Kernel socket teardown can precede the custody observation of
				// process exit. Do not turn an ambiguous EOF into a lifecycle fact.
				_ = channel.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, _, err := channel.ReadMessage()
				var closed *websocket.CloseError
				if !errors.As(err, &closed) ||
					!((closed.Code == browserChannelViewEnded && closed.Text == "browser_view_ended") ||
						(closed.Code == websocket.CloseInternalServerErr && closed.Text == "screencast_failed")) {
					t.Fatalf("process exit close: %v", err)
				}
				observed, proofErr := workspace.controller.sessionService.ObserveOwnedProcess("viewer-owner", driver)
				t.Logf("SIGKILL close %d %q; subsequent custody PID=%d error=%v", closed.Code, closed.Text, observed.PID, proofErr)
				return
			}
			expectClose(t, channel, browserChannelViewEnded, "browser_view_ended", 5*time.Second)
		})
	}
}

func TestBrowserViewerChannelBoundsSilentPeersAndKeepsAnsweringPeers(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	workspace.controller.browserPingInterval = 100 * time.Millisecond
	server := workspace.serve(t)
	answering := openBrowserViewer(t, server, "viewer-owner", id, true)
	readViewerFrame(t, answering, false)
	read := make(chan error, 1)
	go func() { _, _, err := answering.ReadMessage(); read <- err }()
	silent := openBrowserViewer(t, server, "viewer-owner", id, true)
	readViewerFrame(t, silent, false)
	silent.SetPingHandler(func(string) error { return nil })
	_ = silent.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := silent.ReadMessage()
	var closed *websocket.CloseError
	if !errors.As(err, &closed) || closed.Code != websocket.CloseAbnormalClosure {
		t.Fatalf("silent viewer: %v", err)
	}
	sendFrame(t, answering, map[string]any{"type": "presentation", "width": 400, "height": 300})
	select {
	case err := <-read:
		if err != nil {
			t.Fatalf("answering viewer closed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("answering viewer stopped receiving")
	}
}

// browserViewerMessageOf is a message of the contract not named yet, of
// exactly size bytes.
func browserViewerMessageOf(size int) string {
	const prefix, suffix = `{"type":"future","pad":"`, `"}`
	return prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix
}
