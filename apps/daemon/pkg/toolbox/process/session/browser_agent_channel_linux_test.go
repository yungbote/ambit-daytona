// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// The stand-in's scripted behaviour, keyed by frame id.
const (
	browserAgentFixtureHangUp      = 7  // hangs up without answering
	browserAgentFixtureOutOfStep   = 9  // answers under another id
	browserAgentFixtureSlow        = 11 // answers after 300 ms
	browserAgentFixtureEndView     = 13 // closes the view's stream listener, then answers
	browserAgentFixtureNotAnObject = 15 // answers with a line that is no reply
)

// Transport stand-in only: the real driver owns what an agent frame does. It
// answers one line per line, in order, and says which bytes it received, so a
// test can state that the toolbox changed nothing but the action.
func serveBrowserAgentFixture(connection net.Conn, mode string, endView func() error) {
	defer connection.Close()
	reader := bufio.NewReaderSize(connection, 64<<10)
	var paused uint64
	var custodySession bool
	if mode == "agent-unasked" {
		_, _ = connection.Write([]byte("{\"id\":1,\"success\":true}\n"))
	}
	for {
		_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return // ordinary view discovery only reads the peer credential
		}
		var frame struct {
			Action string `json:"action"`
			ID     uint64 `json:"id"`
			Type   string `json:"type"`
		}
		if json.Unmarshal(line, &frame) != nil || frame.Action != browserAgentAction {
			return
		}
		reply := map[string]any{"id": frame.ID, "success": true, "data": map[string]any{"received": base64.StdEncoding.EncodeToString(line)}}
		if frame.Type == "program.status" {
			reply["data"] = programFixtureStatus(line)
		}
		if browserAgentCustodyFrame(line) {
			custodySession = true
		}
		if custodySession {
			if frame.Type == "sequence" {
				paused = frame.ID
				_ = json.NewEncoder(connection).Encode(map[string]any{"type": "site_session.need", "requestId": "10000000-0000-4000-8000-000000000001", "site": "https://example.com", "pageGeneration": "page-1"})
				continue
			}
			if frame.Type == "site_session.export" {
				reply["data"] = map[string]any{"states": []any{map[string]any{"fixture": strings.Repeat("x", browserAgentReplyLimit+128)}}}
			}
		}
		if mode == "agent-old-driver" {
			// A driver without the endpoint answers an unknown command, without the id.
			reply = map[string]any{"success": false, "error": "Unknown action"}
		}
		switch frame.ID {
		case browserAgentFixtureHangUp:
			return
		case browserAgentFixtureOutOfStep:
			reply["id"] = frame.ID + 100
		case browserAgentFixtureSlow:
			time.Sleep(300 * time.Millisecond)
		case browserAgentFixtureEndView:
			_ = endView()
		case browserAgentFixtureNotAnObject:
			_, _ = connection.Write([]byte("[\"not a reply\"]\n"))
			continue
		}
		if json.NewEncoder(connection).Encode(reply) != nil {
			return
		}
		if custodySession && frame.Type == "site_session.attach" && paused != 0 {
			if json.NewEncoder(connection).Encode(map[string]any{"id": paused, "success": true, "data": map[string]any{"resumed": true}}) != nil {
				return
			}
			paused = 0
		}
	}
}

func TestBrowserAgentSiteNeedAndAttachDoNotWaitBehindPausedSequence(t *testing.T) {
	_, channel := openBrowserAgentChannel(t, "agent")
	if err := channel.WriteMessage(websocket.TextMessage, []byte(`{"type":"site_sessions.offer","id":1,"sites":[{"site":"https://example.com","mode":"act"}]}`)); err != nil {
		t.Fatal(err)
	}
	readBrowserAgentReply(t, channel)
	if err := channel.WriteMessage(websocket.TextMessage, []byte(`{"type":"sequence","id":2,"steps":[]}`)); err != nil {
		t.Fatal(err)
	}
	need, _ := readBrowserAgentReply(t, channel)
	if need["type"] != "site_session.need" || need["id"] != nil {
		t.Fatalf("unexpected site need: %v", need)
	}
	if err := channel.WriteMessage(websocket.TextMessage, []byte(`{"type":"site_session.attach","id":3,"requestId":"10000000-0000-4000-8000-000000000001","site":"https://example.com"}`)); err != nil {
		t.Fatal(err)
	}
	attached, _ := readBrowserAgentReply(t, channel)
	resumed, _ := readBrowserAgentReply(t, channel)
	if attached["id"] != float64(3) || resumed["id"] != float64(2) {
		t.Fatalf("custody/sequence ids: %v %v", attached["id"], resumed["id"])
	}
}

func TestBrowserAgentProgramStatusOvertakesSequenceWithNormalBounds(t *testing.T) {
	_, channel := openBrowserAgentChannelWithPing(t, "agent", browserAgentPingInterval)
	if channel.WriteMessage(websocket.TextMessage, []byte(`{"type":"site_sessions.offer","id":1,"sites":[]}`)) != nil {
		t.Fatal("offer write failed")
	}
	readBrowserAgentReply(t, channel)
	if channel.WriteMessage(websocket.TextMessage, []byte(`{"type":"sequence","id":2,"steps":[]}`)) != nil {
		t.Fatal("sequence write failed")
	}
	readBrowserAgentReply(t, channel)
	if channel.WriteJSON(map[string]any{"type": "program.status", "id": 3, "programId": programFixtureID, "actionId": programFixtureAction, "ownerGeneration": "41"}) != nil {
		t.Fatal("status write failed")
	}
	status, _ := readBrowserAgentReply(t, channel)
	if status["id"] != float64(3) {
		t.Fatal("program status waited behind sequence")
	}
	if channel.WriteMessage(websocket.TextMessage, []byte(`{"type":"site_session.attach","id":4,"site":"https://example.com"}`)) != nil {
		t.Fatal("attach write failed")
	}
	attached, _ := readBrowserAgentReply(t, channel)
	sequence, _ := readBrowserAgentReply(t, channel)
	if attached["id"] != float64(4) || sequence["id"] != float64(2) {
		t.Fatal("programme metadata changed ordinary sequence ownership")
	}
	large := []byte(`{"type":"program.status","id":5,"extra":"` + strings.Repeat("x", browserAgentRequestLimit) + `"}`)
	if channel.WriteMessage(websocket.TextMessage, large) != nil {
		t.Fatal("large status write failed")
	}
	expectBrowserAgentClose(t, channel, websocket.ClosePolicyViolation, "frame_too_large")
}

func TestBrowserAgentCustodyHasItsOwnBoundWithoutWideningNormalFrames(t *testing.T) {
	// This transfers multi-megabyte native JSON. Use the protocol heartbeat;
	// other tests shorten it to exercise absence quickly, unlike production.
	_, channel := openBrowserAgentChannelWithPing(t, "agent", browserAgentPingInterval)
	frame := []byte(`{"type":"site_session.attach","id":1,"state":"` + strings.Repeat("a", browserAgentRequestLimit+128) + `"}`)
	if err := channel.WriteMessage(websocket.TextMessage, frame); err != nil {
		t.Fatal(err)
	}
	reply, _ := readBrowserAgentReply(t, channel)
	if reply["id"] != float64(1) {
		t.Fatal("large custody request lost its identity")
	}
	if err := channel.WriteMessage(websocket.TextMessage, []byte(`{"type":"site_session.export","id":2,"sites":["https://example.com"]}`)); err != nil {
		t.Fatal(err)
	}
	_, raw := readBrowserAgentReply(t, channel)
	if len(raw) <= browserAgentReplyLimit || len(raw) > browserAgentCustodyLimit {
		t.Fatalf("custody reply size: %d", len(raw))
	}
	if err := channel.WriteMessage(websocket.TextMessage, []byte(`{"type":"site_session.attach","id":3,"state":"`+strings.Repeat("a", browserAgentCustodyLimit)+`"}`)); err != nil {
		t.Fatal(err)
	}
	expectBrowserAgentClose(t, channel, websocket.ClosePolicyViolation, "frame_too_large")
}

func TestBrowserAgentNeedEventHasOnlyItsBoundedNativeContract(t *testing.T) {
	valid := `{"type":"site_session.need","requestId":"10000000-0000-4000-8000-000000000001","site":"https://example.com","pageGeneration":"page-1"}`
	if !browserAgentSiteNeed([]byte(valid)) {
		t.Fatal("valid native need refused")
	}
	for _, bad := range []string{strings.Replace(valid, `"pageGeneration"`, `"id"`, 1), strings.Replace(valid, "10000000-0000-4000-8000-000000000001", "INVALID", 1), strings.Replace(valid, "https://example.com", "file:///etc/passwd", 1), strings.Replace(valid, "page-1", strings.Repeat("x", 257), 1), strings.Replace(valid, `}`, `,"extra":true}`, 1)} {
		if browserAgentSiteNeed([]byte(bad)) {
			t.Fatal("malformed native need admitted")
		}
	}
}

func openBrowserAgentChannel(t *testing.T, mode string) (*browserWorkspace, *websocket.Conn) {
	return openBrowserAgentChannelWithPing(t, mode, 200*time.Millisecond)
}

func openBrowserAgentChannelWithPing(t *testing.T, mode string, interval time.Duration) (*browserWorkspace, *websocket.Conn) {
	t.Helper()
	workspace := newBrowserWorkspace(t)
	workspace.controller.browserPingInterval = interval
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", mode)
	id, _ := workspace.only(t, "browser-owner", "primary")
	server := workspace.serve(t)
	address := "ws" + strings.TrimPrefix(server.URL, "http") + "/process/session/browser-owner/browser-views/" + id + "/agent/channel"
	channel, response, err := websocket.DefaultDialer.Dial(address, nil)
	if err != nil {
		t.Fatalf("agent channel dial: %v %v", err, response)
	}
	t.Cleanup(func() { _ = channel.Close() })
	return workspace, channel
}

func readBrowserAgentReply(t *testing.T, channel *websocket.Conn) (map[string]any, []byte) {
	t.Helper()
	_ = channel.SetReadDeadline(time.Now().Add(10 * time.Second))
	kind, frame, err := channel.ReadMessage()
	if err != nil || kind != websocket.TextMessage {
		t.Fatalf("agent reply: kind=%d err=%v", kind, err)
	}
	var reply map[string]any
	if err := json.Unmarshal(frame, &reply); err != nil {
		t.Fatal(err)
	}
	return reply, frame
}

func expectBrowserAgentClose(t *testing.T, channel *websocket.Conn, code int, reason string) {
	t.Helper()
	_ = channel.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		_, _, err := channel.ReadMessage()
		if err == nil {
			continue
		}
		closed, ok := err.(*websocket.CloseError)
		if !ok || closed.Code != code || closed.Text != reason {
			t.Fatalf("expected close %d %s, got %v", code, reason, err)
		}
		return
	}
}

func TestBrowserAgentLineKeepsEveryValueAndNamesTheAction(t *testing.T) {
	frame := []byte("{ \"type\" : \"sequence\",\n \"id\" : 12, \"ownerGeneration\":\"9007199254740993\", \"n\": 1.50e2,\n \"steps\":[ {\"op\":\"agent_browser_fill\",\"arguments\":{\"text\":\"line\\nbreak \\u00e9 <b>\"}} ] }")
	line, id, reason := browserAgentLine(frame, 11)
	if reason != "" || id != 12 {
		t.Fatalf("refused %s", reason)
	}
	expected := `{"action":"ambit_browser_agent","type":"sequence","id":12,"ownerGeneration":"9007199254740993","n":1.50e2,"steps":[{"op":"agent_browser_fill","arguments":{"text":"line\nbreak \u00e9 <b>"}}]}` + "\n"
	if string(line) != expected {
		t.Fatalf("values changed:\n%s\n%s", line, expected)
	}
	if strings.Count(string(line), "\n") != 1 {
		t.Fatal("a raw newline reached the line protocol")
	}
	for input, want := range map[string]string{
		`[1]`: "frame_not_json", `{"id":13`: "frame_not_json", `{"id":13} {}`: "frame_not_json", `"id"`: "frame_not_json", ``: "frame_not_json",
		`{"type":"hello"}`: "frame_invalid", `{"id":0}`: "frame_invalid", `{"id":12}`: "frame_invalid", `{"id":11}`: "frame_invalid", `{"id":-13}`: "frame_invalid",
		`{"id":13.0}`: "frame_invalid", `{"id":1e3}`: "frame_invalid", `{"id":"13"}`: "frame_invalid", `{"id":013}`: "frame_invalid", `{"id":9007199254740992}`: "frame_invalid",
		`{"id":13,"id":14}`: "frame_invalid", `{"id":13,"action":"ambit_browser_control"}`: "frame_invalid", `{"action":"ambit_browser_agent","id":13}`: "frame_invalid",
	} {
		if _, _, reason := browserAgentLine([]byte(input), 12); reason != want {
			t.Fatalf("%s: got %q, want %q", input, reason, want)
		}
	}
	if _, id, reason := browserAgentLine([]byte(`{"id":9007199254740991}`), 12); reason != "" || id != browserSafeInteger {
		t.Fatal("the largest exact id was refused")
	}
}

func TestBrowserAgentChannelRelaysFramesInOrderAndRepliesVerbatim(t *testing.T) {
	_, channel := openBrowserAgentChannel(t, "agent")
	// Four frames in flight behind a slow one: the replies keep the frames' order.
	frames := []string{
		`{"type":"hello","id":11,"protocol":1,"channel":"5b0c0b1e-6f0a-4c1c-9d59-0e3f2b7a9c11"}`,
		`{"type":"sequence","id":12,"ownerGeneration":"41","steps":[]}`,
		`{"type":"op_status","id":14,"ownerGeneration":"41"}`,
		`{"type":"op_status","id":16,"ownerGeneration":"41"}`,
		`{"type":"op_status","id":17,"ownerGeneration":"41"}`,
	}
	for _, frame := range frames {
		if err := channel.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
			t.Fatal(err)
		}
	}
	for index, want := range []float64{11, 12, 14, 16, 17} {
		reply, raw := readBrowserAgentReply(t, channel)
		if reply["id"] != want || reply["success"] != true {
			t.Fatalf("reply %d out of order: %s", index, raw)
		}
		received, _ := base64.StdEncoding.DecodeString(reply["data"].(map[string]any)["received"].(string))
		if string(received) != `{"action":"ambit_browser_agent",`+frames[index][1:]+"\n" {
			t.Fatalf("the driver received other bytes: %s", received)
		}
	}
}

func TestBrowserAgentChannelRefusesProtocolViolations(t *testing.T) {
	for _, violation := range []struct {
		kind   int
		frame  []byte
		reason string
	}{
		{websocket.BinaryMessage, []byte(`{"id":1}`), "frame_not_text"},
		{websocket.TextMessage, []byte(`not json`), "frame_not_json"},
		{websocket.TextMessage, []byte(`{"id":1,"action":"ambit_browser_control","op":"acquire"}`), "frame_invalid"},
		{websocket.TextMessage, []byte(`{"type":"hello"}`), "frame_invalid"},
		{websocket.TextMessage, append([]byte(`{"id":1,"pad":"`), append(make([]byte, 0), []byte(strings.Repeat("a", browserAgentRequestLimit))...)...), "frame_too_large"},
	} {
		_, channel := openBrowserAgentChannel(t, "agent")
		if err := channel.WriteMessage(violation.kind, violation.frame); err != nil {
			t.Fatal(err)
		}
		expectBrowserAgentClose(t, channel, websocket.ClosePolicyViolation, violation.reason)
	}
	// An id that does not increase is refused after a good frame was answered.
	_, channel := openBrowserAgentChannel(t, "agent")
	sendFrame(t, channel, map[string]any{"type": "hello", "id": 5})
	if reply, _ := readBrowserAgentReply(t, channel); reply["id"] != float64(5) {
		t.Fatal("hello unanswered")
	}
	sendFrame(t, channel, map[string]any{"type": "op_status", "id": 5})
	expectBrowserAgentClose(t, channel, websocket.ClosePolicyViolation, "frame_invalid")
}

func TestBrowserAgentChannelClosesOnALostOrOutOfStepLinkWithoutRedial(t *testing.T) {
	for _, id := range []int{browserAgentFixtureHangUp, browserAgentFixtureOutOfStep, browserAgentFixtureNotAnObject} {
		_, channel := openBrowserAgentChannel(t, "agent")
		sendFrame(t, channel, map[string]any{"type": "sequence", "id": id})
		expectBrowserAgentClose(t, channel, websocket.CloseInternalServerErr, "agent_channel_link_lost")
	}
	for _, mode := range []string{"agent-old-driver", "agent-unasked"} {
		_, channel := openBrowserAgentChannel(t, mode)
		sendFrame(t, channel, map[string]any{"type": "hello", "id": 1})
		expectBrowserAgentClose(t, channel, websocket.CloseInternalServerErr, "agent_channel_link_lost")
	}
}

func TestBrowserAgentChannelEndsWithItsView(t *testing.T) {
	_, channel := openBrowserAgentChannel(t, "agent")
	sendFrame(t, channel, map[string]any{"type": "sequence", "id": browserAgentFixtureEndView})
	expectBrowserAgentClose(t, channel, browserChannelViewEnded, "browser_view_ended")
}

func TestBrowserAgentChannelDropsASilentHostAndKeepsAnAnsweringOne(t *testing.T) {
	_, channel := openBrowserAgentChannel(t, "agent")
	// gorilla answers pings while the peer reads; this peer reads for a second.
	_ = channel.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := channel.ReadMessage(); err == nil || websocket.IsUnexpectedCloseError(err) {
		t.Fatalf("an answering host was dropped: %v", err)
	}
	workspace := newBrowserWorkspace(t)
	workspace.controller.browserPingInterval = 100 * time.Millisecond
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "agent")
	id, _ := workspace.only(t, "browser-owner", "primary")
	server := workspace.serve(t)
	silent, _, err := (&websocket.Dialer{}).Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/process/session/browser-owner/browser-views/"+id+"/agent/channel", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	// A host that never reads never answers a ping.
	silent.SetPingHandler(func(string) error { return nil })
	time.Sleep(600 * time.Millisecond)
	_ = silent.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := silent.ReadMessage(); err == nil {
		t.Fatal("a silent host kept its channel")
	}
}

func TestBrowserAgentChannelRefusesAnUnknownViewAndAPlainRequest(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "agent")
	id, _ := workspace.only(t, "browser-owner", "primary")
	if status, _ := call(t, workspace.engine, http.MethodGet, "/process/session/browser-owner/browser-views/"+id+"/agent/channel", nil); status != http.StatusUpgradeRequired {
		t.Fatalf("a plain request returned %d", status)
	}
	server := workspace.serve(t)
	_, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/process/session/browser-owner/browser-views/absent/agent/channel", nil)
	if err == nil || response == nil || response.StatusCode != http.StatusNotFound {
		t.Fatalf("an unknown view was not refused with 404: %v", err)
	}
}
