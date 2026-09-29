// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// serve exposes the workspace over the real HTTP transport, which a WebSocket
// upgrade needs; the recorder-backed call helper cannot be hijacked.
func (w *browserWorkspace) serve(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(w.engine)
	t.Cleanup(server.Close)
	return server
}

func browserChannelAddress(server *httptest.Server, sessionID, viewID string) string {
	return "ws" + strings.TrimPrefix(server.URL, "http") + "/process/session/" + sessionID + "/browser-views/" + viewID + "/control/channel"
}

// channel opens one control channel. A refused upgrade is reported by its
// HTTP status; an open channel is closed with the test.
func (w *browserWorkspace) channel(t *testing.T, server *httptest.Server, sessionID, viewID string) (*websocket.Conn, int) {
	t.Helper()
	connection, response, err := websocket.DefaultDialer.Dial(browserChannelAddress(server, sessionID, viewID), nil)
	if err != nil {
		if response == nil {
			t.Fatalf("channel dial: %v", err)
		}
		return nil, response.StatusCode
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection, http.StatusSwitchingProtocols
}

func (w *browserWorkspace) openChannel(t *testing.T, server *httptest.Server, sessionID, viewID string) *websocket.Conn {
	t.Helper()
	channel, status := w.channel(t, server, sessionID, viewID)
	if channel == nil {
		t.Fatalf("channel refused with %d", status)
	}
	return channel
}

// awaitFinishedConnections waits until the stand-in has finished with exactly
// this many command-carrying connections.
func (w *browserWorkspace) awaitFinishedConnections(t *testing.T, name string, want int) {
	t.Helper()
	path := filepath.Join(w.socketDir, name+".connections")
	var last string
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		content, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		last = strings.TrimSpace(string(content))
		if last == strconv.Itoa(want) {
			return
		}
	}
	t.Fatalf("the stand-in finished %q connections, want %d", last, want)
}

func sendFrame(t *testing.T, connection *websocket.Conn, document any) {
	t.Helper()
	frame, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.WriteMessage(websocket.TextMessage, frame); err != nil {
		t.Fatalf("send frame: %v", err)
	}
}

// browserChannelReply is one reply frame with its documents left as bytes, so
// parity with the POST route can be stated byte for byte.
type browserChannelReply struct {
	OK     bool            `json:"ok"`
	Status int             `json:"status"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

func readReply(t *testing.T, connection *websocket.Conn, within time.Duration) browserChannelReply {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(within))
	kind, frame, err := connection.ReadMessage()
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if kind != websocket.TextMessage {
		t.Fatalf("reply frame kind %d, want text", kind)
	}
	if strings.Contains(string(frame), browserFixtureSecret) {
		t.Fatalf("a driver channel reached the peer: %s", frame)
	}
	var reply browserChannelReply
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reply); err != nil {
		t.Fatalf("reply frame %s: %v", frame, err)
	}
	return reply
}

func readResult(t *testing.T, connection *websocket.Conn, within time.Duration) map[string]any {
	t.Helper()
	reply := readReply(t, connection, within)
	if !reply.OK {
		t.Fatalf("command failed: %d %s", reply.Status, reply.Error)
	}
	var result map[string]any
	if err := json.Unmarshal(reply.Result, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func expectFailure(t *testing.T, connection *websocket.Conn, status int, code string) {
	t.Helper()
	reply := readReply(t, connection, 15*time.Second)
	if reply.OK || reply.Status != status || string(reply.Error) != `{"code":"`+code+`"}` {
		t.Fatalf("reply %+v %s, want failure %d %s", reply, reply.Error, status, code)
	}
}

func expectClose(t *testing.T, connection *websocket.Conn, code int, reason string, within time.Duration) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(within))
	_, frame, err := connection.ReadMessage()
	var closed *websocket.CloseError
	if !errors.As(err, &closed) {
		t.Fatalf("channel continued: frame=%s err=%v", frame, err)
	}
	if closed.Code != code || closed.Text != reason {
		t.Fatalf("channel closed %d %q, want %d %q", closed.Code, closed.Text, code, reason)
	}
}

func browserInput(sequence int) map[string]any {
	return map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": sequence,
		"events": []map[string]any{{"type": "input_mouse", "eventType": "mouseMoved", "x": 12, "y": 34}}}
}

func applied(t *testing.T, channel *websocket.Conn, sequence int) {
	t.Helper()
	sendFrame(t, channel, browserInput(sequence))
	if result := readResult(t, channel, 15*time.Second); result["status"] != "applied" || result["lastSequence"] != float64(sequence) {
		t.Fatalf("input %d acknowledgement is invalid: %v", sequence, result)
	}
}

// Every frame is answered in order by exactly what the POST route answers for
// the same document, failures included, and a failed command does not end the
// channel. A session that does not own the view, and a request that is not an
// upgrade, are refused before any channel exists.
func TestBrowserControlChannelAnswersEachCommandAsThePostWould(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel")
	id, _ := workspace.only(t, "browser-owner", "primary")
	server := workspace.serve(t)
	channel := workspace.openChannel(t, server, "browser-owner", id)
	documents := []map[string]any{
		{"op": "inspect"},
		{"op": "acquire", "controllerId": browserFixtureController, "expiresAt": time.Now().Add(20 * time.Second).UnixMilli()},
		browserInput(1),
		browserInput(browserFixtureUnknownSequence),                               // the driver reports an unknown outcome
		{"op": "release", "controllerId": "aaaabbbb-cccc-4ddd-8eee-ffff00002222"}, // stale at the driver
		{"op": "cdp", "method": "Runtime.evaluate"},                               // refused before the driver
		browserInput(3),
	}
	// Everything is sent before anything is read: replies must still arrive
	// one per command, in the frames' order.
	for _, document := range documents {
		sendFrame(t, channel, document)
	}
	target := "/process/session/browser-owner/browser-views/" + id + "/control"
	for index, document := range documents {
		expectedStatus, expectedBody := call(t, workspace.engine, http.MethodPost, target, document)
		reply := readReply(t, channel, 15*time.Second)
		if expectedStatus == http.StatusOK {
			if !reply.OK || reply.Status != 0 || reply.Error != nil || !bytes.Equal(reply.Result, expectedBody) {
				t.Fatalf("reply %d = %+v, want ok with result %s", index, reply, expectedBody)
			}
		} else if reply.OK || reply.Status != expectedStatus || reply.Result != nil || !bytes.Equal(reply.Error, expectedBody) {
			t.Fatalf("reply %d = %+v, want failure %d %s", index, reply, expectedStatus, expectedBody)
		}
	}
	workspace.open(t, "other-owner")
	if refused, status := workspace.channel(t, server, "other-owner", id); refused != nil || status != http.StatusNotFound {
		t.Fatalf("cross-session channel answered %d, want 404", status)
	}
	response, err := server.Client().Get(server.URL + "/process/session/browser-owner/browser-views/" + id + "/control/channel")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("plain GET answered %d, want 426", response.StatusCode)
	}
}

// The driver link is dialled once and kept: no driver connection finishes
// while a channel carries commands, while every POST finishes its own.
func TestBrowserControlChannelKeepsOneDriverLink(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel")
	id, _ := workspace.only(t, "browser-owner", "primary")
	server := workspace.serve(t)
	channel := workspace.openChannel(t, server, "browser-owner", id)
	for _, sequence := range []int{1, 3, 4} {
		applied(t, channel, sequence)
	}
	target := "/process/session/browser-owner/browser-views/" + id + "/control"
	if status, body := call(t, workspace.engine, http.MethodPost, target, browserInput(5)); status != http.StatusOK {
		t.Fatalf("POST = %d %s", status, body)
	}
	workspace.awaitFinishedConnections(t, "primary", 1)
	applied(t, channel, 6)
	if content, err := os.ReadFile(filepath.Join(workspace.socketDir, "primary.connections")); err != nil || strings.TrimSpace(string(content)) != "1" {
		t.Fatalf("the channel's driver link was replaced: finished=%q err=%v", content, err)
	}
}

// A kept link the driver closed while idle is found out by the next command's
// first write. Nothing reached the driver, so the command is carried once more
// on a new link and the peer sees only its acknowledgement.
func TestBrowserControlChannelResendsWhatAClosedLinkNeverCarried(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "control")
	id, _ := workspace.only(t, "browser-owner", "primary")
	channel := workspace.openChannel(t, workspace.serve(t), "browser-owner", id)
	for index, sequence := range []int{1, 3, 4} {
		applied(t, channel, sequence)
		// The driver has hung up before the next command is sent.
		workspace.awaitFinishedConnections(t, "primary", index+1)
	}
}

// A link lost while a command is in flight leaves that command's outcome
// unknown and is replaced for the next one. A driver that no longer accepts
// connections fails each following command exactly as the POST route would,
// and the channel stays open.
func TestBrowserControlChannelRetiresALinkLostMidCommand(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel")
	id, _ := workspace.only(t, "browser-owner", "primary")
	channel := workspace.openChannel(t, workspace.serve(t), "browser-owner", id)
	applied(t, channel, 1)
	sendFrame(t, channel, browserInput(browserFixtureHangUpSequence))
	expectFailure(t, channel, http.StatusBadGateway, "browser_control_outcome_unknown")
	workspace.awaitFinishedConnections(t, "primary", 1)
	applied(t, channel, 8)
	sendFrame(t, channel, browserInput(browserFixtureRefuseSequence))
	expectFailure(t, channel, http.StatusBadGateway, "browser_control_outcome_unknown")
	workspace.awaitFinishedConnections(t, "primary", 2)
	for _, sequence := range []int{10, 11} {
		sendFrame(t, channel, browserInput(sequence))
		expectFailure(t, channel, http.StatusServiceUnavailable, "browser_control_unavailable")
	}
}

// Commands reach the driver as their frames arrive: a command is written
// while earlier ones are still unanswered, and the replies still come back
// one per frame, in the frames' order.
func TestBrowserControlChannelPipelinesCommandsInOrder(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel-slow")
	id, _ := workspace.only(t, "browser-owner", "primary")
	channel := workspace.openChannel(t, workspace.serve(t), "browser-owner", id)
	sequences := []int{1, 3, 4, 5, 6, 8}
	for _, sequence := range sequences {
		sendFrame(t, channel, browserInput(sequence))
	}
	sendFrame(t, channel, map[string]any{"op": "cdp"}) // refused by the relay, answered in its turn
	for _, sequence := range sequences {
		if result := readResult(t, channel, 15*time.Second); result["status"] != "applied" || result["lastSequence"] != float64(sequence) {
			t.Fatalf("reply for input %d is out of order: %v", sequence, result)
		}
	}
	expectFailure(t, channel, http.StatusBadRequest, "browser_control_invalid")
	overlapped, err := os.ReadFile(filepath.Join(workspace.socketDir, "primary.overlapped"))
	if count, _ := strconv.Atoi(strings.TrimSpace(string(overlapped))); err != nil || count == 0 {
		t.Fatalf("no command reached the driver before the previous reply: %q %v", overlapped, err)
	}
}

// The channel proves its driver link when it dials it. Replies are not
// re-proved one by one; the custody watch re-observes the whole view (the
// process and its stream listener) every second and ends the channel when
// the view ends.
func TestBrowserControlChannelProvesItsLinkOnceAndWatchesTheView(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel")
	id, _ := workspace.only(t, "browser-owner", "primary")
	channel := workspace.openChannel(t, workspace.serve(t), "browser-owner", id)
	applied(t, channel, 1)
	// The driver closes the view's stream listener while applying this input.
	applied(t, channel, browserFixtureEndViewSequence)
	expectClose(t, channel, browserChannelViewEnded, "browser_view_ended", 15*time.Second)
}

// The driver's account of an input's path (queued, then injected until the
// display acknowledged it) rides the acknowledgement to the controller. An
// account outside the controller's integer range makes the outcome unknown
// rather than a wrong number.
func TestBrowserControlChannelRelaysTheDriverTiming(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel")
	id, _ := workspace.only(t, "browser-owner", "primary")
	channel := workspace.openChannel(t, workspace.serve(t), "browser-owner", id)
	sendFrame(t, channel, browserInput(browserFixtureTimedSequence))
	result := readResult(t, channel, 5*time.Second)
	timing, _ := result["timing"].(map[string]any)
	if result["status"] != "applied" || timing["queueUs"] != float64(12) || timing["injectUs"] != float64(3) {
		t.Fatalf("the timing account did not ride the acknowledgement: %v", result)
	}
	sendFrame(t, channel, browserInput(browserFixtureUnboundedSequence))
	expectFailure(t, channel, http.StatusBadGateway, "browser_control_outcome_unknown")
}

// A frame that is not one text JSON document within the POST body limit ends
// the channel with 1008 and a reason. A frame of exactly the limit, and a
// well-formed command the relay refuses, are that command's failure and
// nothing more.
func TestBrowserControlChannelClosesOnProtocolViolations(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel")
	id, _ := workspace.only(t, "browser-owner", "primary")
	server := workspace.serve(t)
	padded := func(size int) []byte {
		frame := []byte(`{"op":"inspect","pad":"`)
		frame = append(frame, bytes.Repeat([]byte("a"), size-len(frame)-2)...)
		return append(frame, '"', '}')
	}
	for _, violation := range []struct {
		reason string
		kind   int
		frame  []byte
	}{
		{"frame_not_text", websocket.BinaryMessage, []byte(`{"op":"inspect"}`)},
		{"frame_not_json", websocket.TextMessage, []byte(`inspect`)},
		{"frame_not_json", websocket.TextMessage, []byte(``)},
		{"frame_not_json", websocket.TextMessage, []byte(`{"op":"inspect"} {"op":"inspect"}`)},
		{"frame_too_large", websocket.TextMessage, padded(browserPasteRequestLimit + 1)},
	} {
		channel := workspace.openChannel(t, server, "browser-owner", id)
		if err := channel.WriteMessage(violation.kind, violation.frame); err != nil {
			t.Fatal(err)
		}
		expectClose(t, channel, websocket.ClosePolicyViolation, violation.reason, 15*time.Second)
	}
	channel := workspace.openChannel(t, server, "browser-owner", id)
	// Exactly the limit is read and decoded; its unknown field is the
	// relay's own refusal, exactly as the POST states it.
	if err := channel.WriteMessage(websocket.TextMessage, padded(browserPasteRequestLimit)); err != nil {
		t.Fatal(err)
	}
	expectFailure(t, channel, http.StatusBadRequest, "browser_control_invalid")
	// Within the body limit but past the 64 KiB an ordinary batch may use.
	oversized := browserInput(1)
	oversized["events"] = []map[string]any{
		{"type": "input_keyboard", "eventType": "insertText", "text": strings.Repeat("a", 40<<10)},
		{"type": "input_keyboard", "eventType": "insertText", "text": strings.Repeat("a", 40<<10)},
	}
	sendFrame(t, channel, oversized)
	expectFailure(t, channel, http.StatusBadRequest, "browser_control_invalid")
	sendFrame(t, channel, map[string]any{"op": "inspect"})
	if result := readResult(t, channel, 15*time.Second); result["supported"] != true {
		t.Fatalf("the channel did not continue after a refused command: %v", result)
	}
}

// The view ending under an open channel closes it with the daemon's own code,
// classified exactly as the visual stream classifies its finished record:
// the shell under the driver ending, or the driver itself exiting.
func TestBrowserControlChannelEndsWithTheView(t *testing.T) {
	for _, ending := range []struct {
		name string
		end  func(t *testing.T, workspace *browserWorkspace, supervisor, driver int)
	}{
		{"shell", func(t *testing.T, workspace *browserWorkspace, supervisor, driver int) {
			workspace.endShellUncleanly(t, "browser-owner", supervisor)
		}},
		{"driver", func(t *testing.T, workspace *browserWorkspace, supervisor, driver int) {
			if err := syscall.Kill(driver, syscall.SIGKILL); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(ending.name, func(t *testing.T) {
			workspace := newBrowserWorkspace(t)
			supervisor := workspace.open(t, "browser-owner")
			driver := workspace.runDriver(t, "browser-owner", "primary", "channel")
			id, _ := workspace.only(t, "browser-owner", "primary")
			channel := workspace.openChannel(t, workspace.serve(t), "browser-owner", id)
			sendFrame(t, channel, map[string]any{"op": "inspect"})
			if result := readResult(t, channel, 15*time.Second); result["supported"] != true {
				t.Fatalf("inspection is invalid: %v", result)
			}
			ending.end(t, workspace, supervisor, driver)
			expectClose(t, channel, browserChannelViewEnded, "browser_view_ended", 15*time.Second)
		})
	}
}

// A peer that answers pings keeps its channel; one that stops answering is
// dropped after two unanswered pings, with no close frame it would not read.
func TestBrowserControlChannelDropsAPeerThatStopsAnsweringPings(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel")
	id, _ := workspace.only(t, "browser-owner", "primary")
	workspace.controller.browserPingInterval = 200 * time.Millisecond
	server := workspace.serve(t)
	answering := workspace.openChannel(t, server, "browser-owner", id)
	// Pings are answered from a peer's reads, so the answering peer reads
	// throughout; its one reply is collected for the end of the test.
	answered := make(chan []byte, 1)
	go func() {
		_, frame, err := answering.ReadMessage()
		if err != nil {
			frame = nil
		}
		answered <- frame
	}()
	silent := workspace.openChannel(t, server, "browser-owner", id)
	silent.SetPingHandler(func(string) error { return nil })
	_ = silent.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, frame, err := silent.ReadMessage()
	// An abnormal closure is the peer's view of a connection dropped without
	// a close frame; a deadline would mean the peer was kept.
	var closed *websocket.CloseError
	if !errors.As(err, &closed) || closed.Code != websocket.CloseAbnormalClosure {
		t.Fatalf("a silent peer was kept or sent a close frame: frame=%s err=%v", frame, err)
	}
	// The answering peer has been pinged well past two intervals by now.
	sendFrame(t, answering, map[string]any{"op": "inspect"})
	select {
	case frame := <-answered:
		var reply browserChannelReply
		if frame == nil || json.Unmarshal(frame, &reply) != nil || !reply.OK {
			t.Fatalf("an answering peer lost its channel: %s", frame)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("an answering peer was never answered")
	}
}

// Two hundred sequential inputs through each transport, against the same
// driver stand-in, so the per-command cost of the channel is stated next to
// the POST route's. Correctness is asserted; the timings are reported.
func TestBrowserControlChannelPerCommandLatency(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel")
	id, _ := workspace.only(t, "browser-owner", "primary")
	server := workspace.serve(t)
	const commands = 200
	const first = browserFixtureRefuseSequence + 1
	target := server.URL + "/process/session/browser-owner/browser-views/" + id + "/control"
	client := server.Client()
	post := make([]time.Duration, 0, commands)
	for sequence := first; sequence < first+commands; sequence++ {
		body, _ := json.Marshal(browserInput(sequence))
		started := time.Now()
		response, err := client.Post(target, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil || response.StatusCode != http.StatusOK || result["lastSequence"] != float64(sequence) {
			t.Fatalf("POST %d = %d %v %v", sequence, response.StatusCode, result, err)
		}
		_ = response.Body.Close()
		post = append(post, time.Since(started))
	}
	channel := workspace.openChannel(t, server, "browser-owner", id)
	relayed := make([]time.Duration, 0, commands)
	for sequence := first; sequence < first+commands; sequence++ {
		started := time.Now()
		applied(t, channel, sequence)
		relayed = append(relayed, time.Since(started))
	}
	// The peer proof is paid once per link by the channel and once per
	// command by the POST route; state its cost beside the totals.
	views, err := workspace.controller.browserViews(t.Context(), "browser-owner")
	if err != nil || len(views) != 1 {
		t.Fatalf("view observation: %v %v", views, err)
	}
	link, failure := workspace.controller.dialBrowserControl(t.Context(), views[0])
	if link == nil {
		t.Fatalf("driver link: %v", failure)
	}
	defer link.Close()
	proofs := make([]time.Duration, 0, commands)
	for range commands {
		started := time.Now()
		if err := workspace.controller.proveBrowserControlPeer(link.connection, views[0]); err != nil {
			t.Fatal(err)
		}
		proofs = append(proofs, time.Since(started))
	}
	report := func(name string, samples []time.Duration) {
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		t.Logf("%s: p50 %v, p90 %v, max %v", name, samples[len(samples)/2], samples[len(samples)*9/10], samples[len(samples)-1])
	}
	report("POST per command", post)
	report("channel per command", relayed)
	report("peer proof", proofs)
}
