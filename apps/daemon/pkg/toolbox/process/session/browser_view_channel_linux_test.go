// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// This executes in the existing owned driver process, behind its real loopback
// listener. It accepts presentation updates while a frame remains unacknowledged.
func serveBrowserViewChannelFixture(w http.ResponseWriter, r *http.Request, dir, name, mode string, closeListener func() error) {
	query := r.URL.Query()
	observer := mode == "view-channel-observer"
	validPresentation := query.Get("maxFps") == "60" && query.Get("width") == "320" && query.Get("height") == "240" && r.Header.Get("X-Ambit-Browser-Viewer") == browserFixtureViewer
	if observer {
		validPresentation = query.Get("maxFps") == "10" && !query.Has("width") && !query.Has("height") && r.Header.Get("X-Ambit-Browser-Viewer") == ""
	}
	if query.Get("pacing") != "ack" || query.Get("patches") != "1" || !validPresentation {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	connection, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer connection.Close()
	closed, err := os.OpenFile(filepath.Join(dir, name+".view-closed"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer func() { _, _ = closed.WriteString("closed\n"); _ = closed.Close() }()
	binaryFrames := query.Get("frames") == "binary"
	_ = connection.WriteJSON(map[string]any{"type": "status", "connected": true, "screencasting": true, "private": browserFixtureSecret})
	_ = connection.WriteJSON(map[string]any{"type": "console", "text": browserFixtureSecret})
	if mode == "view-channel-legacy" || mode == "view-channel-old-native" || mode == "view-channel-malformed-text" {
		header, payload := browserFixtureFrame(false)
		delete(header, "byteLength")
		header["data"] = base64.StdEncoding.EncodeToString(payload)
		if mode == "view-channel-legacy" {
			delete(header, "surface")
		}
		if mode == "view-channel-malformed-text" {
			header["data"] = "not-a-jpeg"
		}
		_ = connection.WriteJSON(header)
		drainBrowserFixture(connection)
		return
	}
	if mode == "view-channel-window" || mode == "view-channel-window-overflow" {
		if query.Get("frameWindow") != "8" {
			return
		}
		serveBrowserViewerWindowFixture(connection, mode == "view-channel-window-overflow")
		return
	}
	if mode == "view-channel-error" {
		_ = connection.WriteJSON(map[string]any{"type": "error", "message": browserFixtureSecret})
		drainBrowserFixture(connection)
		return
	}
	for _, patched := range []bool{false, true} {
		header, payload := browserFixtureFrame(patched)
		if mode == "view-channel-format-change" && patched {
			header, payload = browserFixtureFrame(false)
			header["seq"] = 12
			delete(header, "byteLength")
			header["data"] = base64.StdEncoding.EncodeToString(payload)
			_ = connection.WriteJSON(header)
			drainBrowserFixture(connection)
			return
		}
		if mode == "view-channel-bad-frame" {
			header["byteLength"] = len(payload) + 1
		}
		if mode == "view-channel-bad-chain" && patched {
			header["baseSeq"] = 9
		}
		if binaryFrames {
			if connection.WriteMessage(websocket.BinaryMessage, packBrowserFixtureFrame(header, payload)) != nil {
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
			if connection.WriteJSON(header) != nil {
				return
			}
		}
		for {
			var message struct {
				Type   string `json:"type"`
				Seq    int    `json:"seq"`
				Width  uint32 `json:"width"`
				Height uint32 `json:"height"`
			}
			if connection.ReadJSON(&message) != nil {
				return
			}
			if message.Type == "presentation" {
				if mode == "view-channel-listener-ended" {
					_ = closeListener()
					drainBrowserFixture(connection)
					return
				}
				_ = connection.WriteJSON(map[string]any{"type": "presentation", "role": "primary", "requested": map[string]uint32{"width": message.Width, "height": message.Height}, "applied": browserFixtureSurface(), "private": browserFixtureSecret})
				continue
			}
			if message.Type != "ack" || message.Seq != header["seq"].(int) {
				return
			}
			break
		}
		if mode == "view-channel-eof" {
			return
		}
	}
	if mode == "view-channel-finished" {
		_ = connection.WriteJSON(map[string]any{"type": "finished", "private": browserFixtureSecret})
	}
	drainBrowserFixture(connection)
}

func serveBrowserViewerWindowFixture(connection *websocket.Conn, overflow bool) {
	send := func(sequence int) bool {
		header, payload := browserFixtureFrame(sequence != 10)
		header["seq"] = sequence
		if sequence != 10 {
			header["baseSeq"] = sequence - 2
		}
		return connection.WriteMessage(websocket.BinaryMessage, packBrowserFixtureFrame(header, payload)) == nil
	}
	for sequence := 10; sequence <= 24; sequence += 2 {
		if !send(sequence) {
			return
		}
	}
	if overflow {
		_ = send(26)
		drainBrowserFixture(connection)
		return
	}
	var ack struct {
		Type string `json:"type"`
		Seq  int    `json:"seq"`
	}
	if connection.ReadJSON(&ack) != nil || ack.Type != "ack" || ack.Seq != 18 {
		return
	}
	if !send(26) {
		return
	}
	if connection.ReadJSON(&ack) != nil || ack.Type != "ack" || ack.Seq != 26 {
		return
	}
	_ = connection.WriteJSON(map[string]any{"type": "finished"})
	drainBrowserFixture(connection)
}

func browserViewerAddress(server *httptest.Server, sessionID, viewID string) string {
	return "ws" + strings.TrimPrefix(server.URL, "http") + "/process/session/" + sessionID + "/browser-views/" + viewID + "/channel"
}

func openBrowserViewer(t *testing.T, server *httptest.Server, sessionID, viewID string, binary bool) *websocket.Conn {
	return openBrowserViewerWindow(t, server, sessionID, viewID, binary, 0)
}

func openBrowserViewerWindow(t *testing.T, server *httptest.Server, sessionID, viewID string, binary bool, window int) *websocket.Conn {
	t.Helper()
	address := browserViewerAddress(server, sessionID, viewID) + "?width=320&height=240"
	if binary {
		address += "&frames=binary&patches=1"
	}
	if window != 0 {
		address += fmt.Sprintf("&frameWindow=%d", window)
	}
	connection, response, err := websocket.DefaultDialer.Dial(address, http.Header{"X-Ambit-Browser-Viewer": []string{browserFixtureViewer}})
	if err != nil {
		t.Fatalf("viewer dial: %v response=%v", err, response)
	}
	t.Cleanup(func() { _ = connection.Close() })
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

func readViewerFrame(t *testing.T, connection *websocket.Conn, patched bool) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	kind, message, err := connection.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || bytes.Contains(message, []byte(browserFixtureSecret)) {
		t.Fatalf("binary frame: kind=%d err=%v", kind, err)
	}
	frame, err := parseBrowserBinaryFrame(message)
	if err != nil {
		t.Fatal(err)
	}
	expectedHeader, expectedPayload := browserFixtureFrame(patched)
	if frame.header.Seq != uint64(expectedHeader["seq"].(int)) || !bytes.Equal(frame.payload, expectedPayload) {
		t.Fatal("sequence or JPEG bytes changed in transit")
	}
	if patched && (len(frame.header.Patches) != 1 || frame.header.BaseSeq != 10 || frame.header.Patches[0].SourceX != 16 || frame.header.Patches[0].SourceY != 16) {
		t.Fatalf("patch crop/base changed: %+v", frame.header)
	}
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

func TestBrowserViewerChannelRetainsTextFrameNegotiation(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel-finished")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	channel := openBrowserViewer(t, workspace.serve(t), "viewer-owner", id, false)
	for _, sequence := range []int{10, 12} {
		frame := readViewerText(t, channel)
		if frame["type"] != "frame" || frame["seq"] != float64(sequence) {
			t.Fatalf("text frame: %v", frame)
		}
		sendFrame(t, channel, map[string]any{"type": "ack", "seq": sequence})
	}
	if readViewerText(t, channel)["type"] != "finished" {
		t.Fatal("text channel did not finish")
	}
	expectClose(t, channel, browserChannelViewEnded, "browser_view_ended", 5*time.Second)
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
		{"viewer-owner", "?width=320", browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=320&height=240&frames=other", browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=320&height=240&frames=binary&frames=binary", browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=320&height=240&frameWindow=9", browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=320&height=240&frameWindow=0", browserFixtureViewer, http.StatusBadRequest},
		{"viewer-owner", "?width=320&height=240&frameWindow=8&frameWindow=8", browserFixtureViewer, http.StatusBadRequest},
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

func TestBrowserViewerChannelObserverHasNoPresentationAuthority(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel-observer")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	server := workspace.serve(t)
	channel, _, err := websocket.DefaultDialer.Dial(browserViewerAddress(server, "viewer-owner", id)+"?frames=binary&frameWindow=8", http.Header{"X-Ambit-Browser-Viewer": []string{browserFixtureViewer}})
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	if readViewerText(t, channel)["type"] != "status" {
		t.Fatal("observer state missing")
	}
	readViewerFrame(t, channel, false)
	sendFrame(t, channel, map[string]any{"type": "ack", "seq": 10})
	readViewerFrame(t, channel, true)
	sendFrame(t, channel, map[string]any{"type": "presentation", "width": 400, "height": 300})
	expectClose(t, channel, websocket.ClosePolicyViolation, "browser_view_invalid_message", 5*time.Second)
}

func TestBrowserViewerChannelFallsBackOnlyForValidInitialOldFrames(t *testing.T) {
	for _, mode := range []string{"view-channel-legacy", "view-channel-old-native", "view-channel-malformed-text", "view-channel-format-change"} {
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
			if mode == "view-channel-legacy" || mode == "view-channel-old-native" {
				expectClose(t, channel, websocket.CloseUnsupportedData, "browser_view_channel_unsupported", 5*time.Second)
			} else {
				expectClose(t, channel, websocket.CloseInternalServerErr, "browser_view_invalid_frame", 5*time.Second)
			}
		})
	}
}

func TestBrowserViewerChannelRejectsClientControlAndBadAcknowledgements(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	server := workspace.serve(t)
	for _, message := range []string{`{`, `{"type":"ack","seq":9}`, `{"type":"ack","seq":11}`, `{"type":"input","events":[]}`, `{"type":"cdp","method":"Runtime.evaluate"}`, `{"type":"presentation","width":400,"height":300,"viewer":"changed"}`, `{"type":"presentation","width":2049,"height":300}`, strings.Repeat(" ", browserViewerMessageLimit+1)} {
		t.Run(fmt.Sprintf("message-%x", []byte(message)[:min(len(message), 16)]), func(t *testing.T) {
			channel := openBrowserViewer(t, server, "viewer-owner", id, true)
			readViewerFrame(t, channel, false)
			if err := channel.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
				t.Fatal(err)
			}
			expectClose(t, channel, websocket.ClosePolicyViolation, "browser_view_invalid_message", 5*time.Second)
		})
	}
	channel := openBrowserViewer(t, server, "viewer-owner", id, true)
	readViewerFrame(t, channel, false)
	_ = channel.WriteMessage(websocket.BinaryMessage, []byte(`{"type":"ack","seq":10}`))
	expectClose(t, channel, websocket.ClosePolicyViolation, "frame_not_text", 5*time.Second)
	channel = openBrowserViewer(t, server, "viewer-owner", id, true)
	readViewerFrame(t, channel, false)
	sendFrame(t, channel, map[string]any{"type": "ack", "seq": 10})
	readViewerFrame(t, channel, true)
	sendFrame(t, channel, map[string]any{"type": "ack", "seq": 10})
	sendFrame(t, channel, map[string]any{"type": "presentation", "width": 400, "height": 300})
	if readViewerText(t, channel)["type"] != "presentation" {
		t.Fatal("stale acknowledgement was not ignored")
	}
}

func TestBrowserViewerChannelClosesOnInvalidFramesAndRecoversAfterEOF(t *testing.T) {
	for _, mode := range []string{"view-channel-bad-frame", "view-channel-bad-chain", "view-channel-eof", "view-channel-error"} {
		t.Run(mode, func(t *testing.T) {
			workspace := newBrowserWorkspace(t)
			workspace.open(t, "viewer-owner")
			workspace.runDriver(t, "viewer-owner", "primary", mode)
			id, _ := workspace.only(t, "viewer-owner", "primary")
			server := workspace.serve(t)
			channel := openBrowserViewer(t, server, "viewer-owner", id, true)
			if mode == "view-channel-bad-chain" || mode == "view-channel-eof" {
				readViewerFrame(t, channel, false)
				sendFrame(t, channel, map[string]any{"type": "ack", "seq": 10})
			}
			reason := "browser_view_invalid_frame"
			if mode == "view-channel-eof" || mode == "view-channel-error" {
				reason = "screencast_failed"
			}
			if mode == "view-channel-error" {
				failure := readViewerText(t, channel)
				if failure["type"] != "unavailable" || failure["reason"] != "screencast_failed" || len(failure) != 2 {
					t.Fatalf("failure: %v", failure)
				}
			}
			expectClose(t, channel, websocket.CloseInternalServerErr, reason, 5*time.Second)
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

func TestBrowserViewerChannelUsesBoundedWindowAndCumulativePaintACK(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		t.Run(fmt.Sprintf("overflow-%v", overflow), func(t *testing.T) {
			workspace := newBrowserWorkspace(t)
			workspace.open(t, "viewer-owner")
			mode := "view-channel-window"
			if overflow {
				mode = "view-channel-window-overflow"
			}
			workspace.runDriver(t, "viewer-owner", "primary", mode)
			id, _ := workspace.only(t, "viewer-owner", "primary")
			channel := openBrowserViewerWindow(t, workspace.serve(t), "viewer-owner", id, true, 8)
			for sequence := 10; sequence <= 24; sequence += 2 {
				kind, message, err := channel.ReadMessage()
				if err != nil || kind != websocket.BinaryMessage {
					t.Fatalf("window frame: %v", err)
				}
				frame, err := parseBrowserBinaryFrame(message)
				if err != nil || frame.header.Seq != uint64(sequence) {
					t.Fatalf("window sequence %d: %v", sequence, err)
				}
			}
			if overflow {
				expectClose(t, channel, websocket.CloseInternalServerErr, "browser_view_invalid_frame", 5*time.Second)
				return
			}
			// Eight frames crossed the real transport without an ACK. One ACK
			// releases the first five, then the next delta retains its exact base.
			sendFrame(t, channel, map[string]any{"type": "ack", "seq": 18})
			kind, message, err := channel.ReadMessage()
			if err != nil || kind != websocket.BinaryMessage {
				t.Fatalf("resumed frame: %v", err)
			}
			frame, err := parseBrowserBinaryFrame(message)
			if err != nil || frame.header.Seq != 26 || frame.header.BaseSeq != 24 {
				t.Fatalf("resumed chain: %+v/%v", frame.header, err)
			}
			sendFrame(t, channel, map[string]any{"type": "ack", "seq": 26})
			if readViewerText(t, channel)["type"] != "finished" {
				t.Fatal("window did not finish")
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
