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
	"sort"
	"strings"
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

// channel opens one control channel. A refused upgrade is reported by its
// HTTP status; an open channel is closed with the test.
func (w *browserWorkspace) channel(t *testing.T, server *httptest.Server, sessionID, viewID string) (*websocket.Conn, int) {
	t.Helper()
	address := "ws" + strings.TrimPrefix(server.URL, "http") + "/process/session/" + sessionID + "/browser-views/" + viewID + "/control/channel"
	connection, response, err := websocket.DefaultDialer.Dial(address, nil)
	if err != nil {
		if response == nil {
			t.Fatalf("channel dial: %v", err)
		}
		return nil, response.StatusCode
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection, http.StatusSwitchingProtocols
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

// Every frame is answered in order by exactly what the POST route answers for
// the same document, failures included, and a failed command does not end the
// channel. Against a driver that hangs up after each command, the channel also
// replaces its lost link for every following command.
func TestBrowserControlChannelAnswersEachCommandAsThePostWould(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "control")
	id, _ := workspace.only(t, "browser-owner", "primary")
	server := workspace.serve(t)
	channel, status := workspace.channel(t, server, "browser-owner", id)
	if channel == nil {
		t.Fatalf("channel refused with %d", status)
	}
	documents := []map[string]any{
		{"op": "inspect"},
		{"op": "acquire", "controllerId": browserFixtureController, "expiresAt": time.Now().Add(20 * time.Second).UnixMilli()},
		browserInput(1),
		browserInput(2), // the driver reports an unknown outcome
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
		reply := readReply(t, channel, 10*time.Second)
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
}

// The driver link is dialled once and kept: commands on one channel arrive on
// one driver connection, while the POST route dials its own.
func TestBrowserControlChannelKeepsOneDriverLink(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel")
	id, _ := workspace.only(t, "browser-owner", "primary")
	server := workspace.serve(t)
	channel, status := workspace.channel(t, server, "browser-owner", id)
	if channel == nil {
		t.Fatalf("channel refused with %d", status)
	}
	connection := func(sequence int) float64 {
		t.Helper()
		sendFrame(t, channel, browserInput(sequence))
		result := readResult(t, channel, 10*time.Second)
		if result["status"] != "applied" || result["lastSequence"] != float64(sequence) {
			t.Fatalf("input %d acknowledgement is invalid: %v", sequence, result)
		}
		return result["expiresAt"].(float64)
	}
	first := connection(1)
	if connection(3) != first || connection(4) != first {
		t.Fatal("the channel redialled the driver between commands")
	}
	_, raw := call(t, workspace.engine, http.MethodPost, "/process/session/browser-owner/browser-views/"+id+"/control", browserInput(5))
	var posted map[string]any
	if err := json.Unmarshal(raw, &posted); err != nil || posted["expiresAt"] == first {
		t.Fatalf("the POST route shared the channel's driver link: %s", raw)
	}
	if connection(6) != first {
		t.Fatal("an interleaved POST cost the channel its driver link")
	}
}

// A frame that is not one text JSON document within the POST body limit ends
// the channel with 1008 and a reason. A well-formed command the relay refuses
// is that command's failure and nothing more.
func TestBrowserControlChannelClosesOnProtocolViolations(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel")
	id, _ := workspace.only(t, "browser-owner", "primary")
	server := workspace.serve(t)
	for _, violation := range []struct {
		reason string
		kind   int
		frame  []byte
	}{
		{"frame_not_text", websocket.BinaryMessage, []byte(`{"op":"inspect"}`)},
		{"frame_not_json", websocket.TextMessage, []byte(`inspect`)},
		{"frame_not_json", websocket.TextMessage, []byte(``)},
		{"frame_not_json", websocket.TextMessage, []byte(`{"op":"inspect"} {"op":"inspect"}`)},
		{"frame_too_large", websocket.TextMessage, append([]byte(`{"op":"`), bytes.Repeat([]byte("a"), browserPasteRequestLimit)...)},
	} {
		channel, status := workspace.channel(t, server, "browser-owner", id)
		if channel == nil {
			t.Fatalf("channel refused with %d", status)
		}
		if err := channel.WriteMessage(violation.kind, violation.frame); err != nil {
			t.Fatal(err)
		}
		expectClose(t, channel, websocket.ClosePolicyViolation, violation.reason, 10*time.Second)
	}
	channel, status := workspace.channel(t, server, "browser-owner", id)
	if channel == nil {
		t.Fatalf("channel refused with %d", status)
	}
	// Within the body limit but past the 64 KiB an ordinary batch may use:
	// the relay's own refusal, exactly as the POST states it.
	oversized := browserInput(1)
	oversized["events"] = []map[string]any{
		{"type": "input_keyboard", "eventType": "insertText", "text": strings.Repeat("a", 40<<10)},
		{"type": "input_keyboard", "eventType": "insertText", "text": strings.Repeat("a", 40<<10)},
	}
	sendFrame(t, channel, oversized)
	if reply := readReply(t, channel, 10*time.Second); reply.OK || reply.Status != http.StatusBadRequest || string(reply.Error) != `{"code":"browser_control_invalid"}` {
		t.Fatalf("oversized batch reply %+v, want the relay's 400", reply)
	}
	sendFrame(t, channel, map[string]any{"op": "inspect"})
	if result := readResult(t, channel, 10*time.Second); result["supported"] != true {
		t.Fatalf("the channel did not continue after a refused command: %v", result)
	}
}

// The view ending under an open channel closes it with the daemon's own code,
// classified exactly as the visual stream classifies its finished record.
func TestBrowserControlChannelEndsWithTheView(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	supervisor := workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel")
	id, _ := workspace.only(t, "browser-owner", "primary")
	channel, status := workspace.channel(t, workspace.serve(t), "browser-owner", id)
	if channel == nil {
		t.Fatalf("channel refused with %d", status)
	}
	sendFrame(t, channel, map[string]any{"op": "inspect"})
	if result := readResult(t, channel, 10*time.Second); result["supported"] != true {
		t.Fatalf("inspection is invalid: %v", result)
	}
	workspace.endShellUncleanly(t, "browser-owner", supervisor)
	expectClose(t, channel, browserChannelViewEnded, "browser_view_ended", 15*time.Second)
}

// A peer that answers pings keeps its channel; one that stops answering is
// dropped after two unanswered pings, with no close frame it would not read.
func TestBrowserControlChannelDropsAPeerThatStopsAnsweringPings(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "channel")
	id, _ := workspace.only(t, "browser-owner", "primary")
	workspace.controller.browserPingInterval = 50 * time.Millisecond
	server := workspace.serve(t)
	answering, status := workspace.channel(t, server, "browser-owner", id)
	if answering == nil {
		t.Fatalf("channel refused with %d", status)
	}
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
	silent, status := workspace.channel(t, server, "browser-owner", id)
	if silent == nil {
		t.Fatalf("channel refused with %d", status)
	}
	silent.SetPingHandler(func(string) error { return nil })
	_ = silent.SetReadDeadline(time.Now().Add(5 * time.Second))
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
	case <-time.After(10 * time.Second):
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
	target := server.URL + "/process/session/browser-owner/browser-views/" + id + "/control"
	client := server.Client()
	post := make([]time.Duration, 0, commands)
	for sequence := 3; sequence < 3+commands; sequence++ {
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
	channel, status := workspace.channel(t, server, "browser-owner", id)
	if channel == nil {
		t.Fatalf("channel refused with %d", status)
	}
	relayed := make([]time.Duration, 0, commands)
	for sequence := 3; sequence < 3+commands; sequence++ {
		started := time.Now()
		sendFrame(t, channel, browserInput(sequence))
		if result := readResult(t, channel, 10*time.Second); result["lastSequence"] != float64(sequence) {
			t.Fatalf("channel input %d acknowledgement is invalid: %v", sequence, result)
		}
		relayed = append(relayed, time.Since(started))
	}
	// The peer proof after every reply is the channel's one remaining
	// per-command custody cost; state it beside the totals.
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
