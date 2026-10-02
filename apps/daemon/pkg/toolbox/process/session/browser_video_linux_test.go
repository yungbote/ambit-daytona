// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const videoFixtureEpoch = "5b0c0b1e-6f0a-4c1c-9d59-0e3f2b7a9c11"
const videoFixtureNextEpoch = "9a1d7c42-3a55-4f0e-8a7b-5d2c8e6f4b20"

func videoFixtureHeader(seq int, key bool, payload int) map[string]any {
	header := map[string]any{"type": "media", "track": "video", "codec": "av1", "streamId": videoFixtureEpoch, "seq": seq, "ts": 1234567 + seq,
		"key": key, "coded": map[string]any{"width": 2048, "height": 2048}, "visible": map[string]any{"x": 0, "y": 0, "width": 1840, "height": 1888},
		"surface": browserFixtureSurface(), "inputSeq": 7, "quality": "motion", "byteLength": payload, "private": browserFixtureSecret}
	if key {
		header["codecString"] = "av01.0.12M.08"
	}
	return header
}

func TestBrowserVideoUnitProjectionAndBounds(t *testing.T) {
	payload := bytes.Repeat([]byte{0x12, 0x00, 0x0a}, 400)
	for _, key := range []bool{true, false} {
		value, projected, valid := parseBrowserVideoUnit(packBrowserFixtureFrame(videoFixtureHeader(1, key, len(payload)), payload))
		if !valid || value.Key != key || bytes.Contains(projected, []byte(browserFixtureSecret)) {
			t.Fatalf("unit not projected key=%v", key)
		}
		_, output, _ := browserBinaryParts(projected)
		if !bytes.Equal(output, payload) {
			t.Fatal("picture bytes changed")
		}
	}
	described := videoFixtureHeader(1, true, len(payload))
	described["description"] = "gQwMAA=="
	if value, _, valid := parseBrowserVideoUnit(packBrowserFixtureFrame(described, payload)); !valid || value.Description != "gQwMAA==" {
		t.Fatal("decoder configuration lost")
	}
	for _, change := range []map[string]any{
		{"seq": 0}, {"seq": browserSafeInteger + 1}, {"ts": -1}, {"ts": nil}, {"byteLength": 1}, {"codec": "h264"}, {"streamId": "foreign-path"}, {"track": "audio"},
		{"quality": "best"}, {"coded": map[string]any{"width": 0, "height": 2048}}, {"coded": map[string]any{"width": 4097, "height": 2048}},
		{"visible": map[string]any{"x": 0, "y": 0, "width": 2049, "height": 10}}, {"visible": map[string]any{"x": 2048, "y": 0, "width": 1, "height": 1}},
		{"visible": map[string]any{"x": 0, "y": 0, "width": 0, "height": 10}}, {"surface": map[string]any{"kind": "page"}}, {"inputSeq": browserSafeInteger + 1},
		{"codecString": "avc1.640033"}, {"codecString": "vp09.00.41.08"}, {"codecString": ""}, {"description": "not base64!"},
	} {
		header := videoFixtureHeader(1, true, len(payload))
		for key, value := range change {
			header[key] = value
		}
		if _, _, valid := parseBrowserVideoUnit(packBrowserFixtureFrame(header, payload)); valid {
			t.Fatalf("accepted %v", change)
		}
	}
	// Only a picture that needs no other carries a decoder configuration.
	for _, change := range []map[string]any{{"codecString": "av01.0.12M.08"}, {"description": "gQwMAA=="}} {
		header := videoFixtureHeader(2, false, len(payload))
		for key, value := range change {
			header[key] = value
		}
		if _, _, valid := parseBrowserVideoUnit(packBrowserFixtureFrame(header, payload)); valid {
			t.Fatalf("accepted %v on a dependent picture", change)
		}
	}
	for _, input := range [][]byte{nil, {0xff, 0xff, 0xff, 0xff}, packBrowserFixtureHeader(bytes.Repeat([]byte(" "), browserVideoHeaderLimit+1), payload),
		packBrowserFixtureFrame(videoFixtureHeader(1, true, browserVideoPayloadLimit+1), make([]byte, browserVideoPayloadLimit+1)),
		packBrowserFixtureFrame(videoFixtureHeader(1, true, 0), nil)} {
		if _, _, valid := parseBrowserVideoUnit(input); valid {
			t.Fatal("accepted invalid picture envelope")
		}
	}
}

func TestBrowserVideoDeclarationsAndClosedViewerMessages(t *testing.T) {
	for _, query := range []string{"video=av1", "video=av1&video=vp9&frames=binary", "video=&frames=binary", "video=AV1&frames=binary", "video=h264&frames=binary",
		"video=av1,av1&frames=binary", "video=av1,&frames=binary", "video=av1%20,vp9&frames=binary"} {
		if _, valid := parseBrowserVideoDeclaration(httptest.NewRequest("GET", "/?"+query, nil)); valid {
			t.Fatalf("accepted %s", query)
		}
	}
	if codecs, valid := parseBrowserVideoDeclaration(httptest.NewRequest("GET", "/?frames=binary", nil)); !valid || codecs != nil {
		t.Fatal("a viewer without pictures was refused")
	}
	codecs, valid := parseBrowserVideoDeclaration(httptest.NewRequest("GET", "/?frames=binary&video=vp9-444,av1-444,vp9,av1", nil))
	if !valid || len(codecs) != 4 || codecs[0] != "vp9-444" || codecs[3] != "av1" {
		t.Fatalf("viewer order lost: %v", codecs)
	}
	for _, message := range []string{
		`{"type":"video"}`, `{"type":"video","enabled":true}`, `{"type":"video","enabled":"true","generation":1}`, `{"type":"video","enabled":true,"generation":0}`,
		`{"type":"video","keyframe":false,"generation":1}`, `{"type":"video","keyframe":true,"enabled":true,"generation":1}`,
		`{"type":"video","enabled":true,"generation":1,"controllerId":"foreign"}`, `{"type":"video","enabled":true,"generation":1,"seq":2}`,
		`{"type":"ack","track":"audio","streamId":"` + videoFixtureEpoch + `","seq":1}`, `{"type":"ack","track":"video","streamId":"other/session","seq":1}`,
		`{"type":"ack","track":"video","streamId":"` + videoFixtureEpoch + `","seq":0}`, `{"type":"ack","track":"video","seq":1}`,
		`{"type":"ack","track":"video","streamId":"` + videoFixtureEpoch + `","seq":1,"generation":1}`,
	} {
		if _, _, valid := browserViewerVideoMessage([]byte(message)); valid {
			t.Fatalf("accepted %s", message)
		}
	}
	for _, message := range []string{`{"type":"video","enabled":true,"generation":1}`, `{"type":"video","enabled":false,"generation":2}`,
		`{"type":"video","keyframe":true,"generation":2}`, `{"type":"ack","track":"video","streamId":"` + videoFixtureEpoch + `","seq":9}`} {
		_, projected, valid := browserViewerVideoMessage([]byte(message))
		if !valid || string(projected) != message {
			t.Fatalf("changed %s into %s", message, projected)
		}
	}
	// The frame acknowledgement keeps its own closed shape.
	if _, ack, valid := browserViewerMessage([]byte(`{"type":"ack","seq":4}`)); !valid || ack != 4 {
		t.Fatal("frame acknowledgement changed")
	}
}

func TestBrowserVideoMetadata(t *testing.T) {
	message, _ := json.Marshal(map[string]any{"type": "video", "state": "started", "generation": 1, "codec": "av1", "codecString": "av01.0.12M.08", "streamId": videoFixtureEpoch, "private": browserFixtureSecret})
	if _, projected, valid := parseBrowserVideoMetadata(message); !valid || bytes.Contains(projected, []byte(browserFixtureSecret)) {
		t.Fatal("invalid projection")
	}
	for _, message := range []string{`{"type":"video","state":"available","codec":"vp9-444"}`, `{"type":"video","state":"unavailable","generation":0}`,
		`{"type":"video","state":"stopped","codec":"av1","generation":3}`} {
		if _, projected, valid := parseBrowserVideoMetadata([]byte(message)); !valid || len(projected) == 0 {
			t.Fatalf("refused %s", message)
		}
	}
	for _, message := range []string{`{"type":"video","state":"started","codec":"av1"}`, `{"type":"video","state":"available"}`, `{"type":"video","state":"available","codec":"h264"}`,
		`{"type":"video","state":"playing","codec":"av1"}`, `{"type":"video","state":"stopped","codec":"av1"}`,
		`{"type":"video","state":"started","generation":1,"codec":"av1","codecString":"vp09.00.41.08","streamId":"` + videoFixtureEpoch + `"}`,
		`{"type":"video","state":"started","generation":0,"codec":"av1","codecString":"av01.0.12M.08","streamId":"` + videoFixtureEpoch + `"}`,
		`{"type":"video","state":"started","generation":1,"codec":"av1","codecString":"av01.0.12M.08","streamId":"foreign"}`} {
		if _, _, valid := parseBrowserVideoMetadata([]byte(message)); valid {
			t.Fatalf("admitted %s", message)
		}
	}
}

type videoFixtureIntent struct {
	Type       string `json:"type"`
	Enabled    *bool  `json:"enabled"`
	Keyframe   *bool  `json:"keyframe"`
	Generation uint64 `json:"generation"`
	Track      string `json:"track"`
	StreamID   string `json:"streamId"`
	Seq        uint64 `json:"seq"`
}

func videoFixtureUnit(epoch string, seq int, key bool) []byte {
	payload := bytes.Repeat([]byte{byte(seq)}, 64)
	header := videoFixtureHeader(seq, key, len(payload))
	header["streamId"] = epoch
	return packBrowserFixtureFrame(header, payload)
}

// The driver's side of one viewer. It offers, serves a subscription with its
// stream, and returns to frames when the viewer falls back.
func serveVideoFixture(connection *websocket.Conn, mode string) {
	_ = connection.WriteJSON(map[string]any{"type": "video", "state": "available", "codec": "av1", "private": browserFixtureSecret})
	frame, image := browserFixtureFrame(false)
	_ = connection.WriteMessage(websocket.BinaryMessage, packBrowserFixtureFrame(frame, image))
	var intent videoFixtureIntent
	if connection.ReadJSON(&intent) != nil || intent.Type != "ack" || intent.Seq != 10 || intent.Track != "" {
		return
	}
	intent = videoFixtureIntent{}
	if connection.ReadJSON(&intent) != nil || intent.Type != "video" || intent.Enabled == nil || !*intent.Enabled || intent.Generation != 1 {
		return
	}
	_ = connection.WriteJSON(map[string]any{"type": "video", "state": "started", "generation": 1, "codec": "av1", "codecString": "av01.0.12M.08", "streamId": videoFixtureEpoch, "private": browserFixtureSecret})
	_ = connection.WriteMessage(websocket.BinaryMessage, videoFixtureUnit(videoFixtureEpoch, 1, true))
	if mode == "view-channel-video-gap" {
		_ = connection.WriteMessage(websocket.BinaryMessage, videoFixtureUnit(videoFixtureEpoch, 3, false))
		drainBrowserFixture(connection)
		return
	}
	_ = connection.WriteMessage(websocket.BinaryMessage, videoFixtureUnit(videoFixtureEpoch, 2, false))
	intent = videoFixtureIntent{}
	if connection.ReadJSON(&intent) != nil || intent.Type != "ack" || intent.Track != "video" || intent.StreamID != videoFixtureEpoch || intent.Seq != 2 {
		return
	}
	intent = videoFixtureIntent{}
	if connection.ReadJSON(&intent) != nil || intent.Type != "video" || intent.Keyframe == nil || intent.Generation != 1 {
		return
	}
	_ = connection.WriteMessage(websocket.BinaryMessage, videoFixtureUnit(videoFixtureEpoch, 3, true))
	intent = videoFixtureIntent{}
	if connection.ReadJSON(&intent) != nil || intent.Type != "video" || intent.Enabled == nil || *intent.Enabled || intent.Generation != 2 {
		return
	}
	if mode == "view-channel-video-race" {
		intent = videoFixtureIntent{}
		if connection.ReadJSON(&intent) != nil || intent.Enabled == nil || !*intent.Enabled || intent.Generation != 3 {
			return
		}
		// What the old subscription still had in flight must never reach the viewer.
		_ = connection.WriteMessage(websocket.BinaryMessage, videoFixtureUnit(videoFixtureEpoch, 4, false))
		_ = connection.WriteJSON(map[string]any{"type": "video", "state": "stopped", "codec": "av1", "generation": 2})
		_ = connection.WriteJSON(map[string]any{"type": "video", "state": "started", "codec": "av1", "codecString": "av01.0.12M.08", "generation": 3, "streamId": videoFixtureNextEpoch})
		_ = connection.WriteMessage(websocket.BinaryMessage, videoFixtureUnit(videoFixtureNextEpoch, 1, true))
		drainBrowserFixture(connection)
		return
	}
	_ = connection.WriteJSON(map[string]any{"type": "video", "state": "stopped", "generation": 2, "codec": "av1"})
	frame, image = browserFixtureFrame(true)
	frame["baseSeq"] = nil
	delete(frame, "baseSeq")
	delete(frame, "patches")
	image = browserFixtureJPEG(640, 480)
	frame["seq"], frame["byteLength"] = 12, len(image)
	_ = connection.WriteMessage(websocket.BinaryMessage, packBrowserFixtureFrame(frame, image))
	drainBrowserFixture(connection)
}

func openVideoFixture(t *testing.T, mode string) *websocket.Conn {
	t.Helper()
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", mode)
	id, _ := workspace.only(t, "viewer-owner", "primary")
	address := browserViewerAddress(workspace.serve(t), "viewer-owner", id) + "?width=320&height=240&frames=binary&video=av1-444,av1"
	channel, _, err := websocket.DefaultDialer.Dial(address, http.Header{"X-Ambit-Browser-Viewer": []string{browserFixtureViewer}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = channel.Close() })
	if readViewerText(t, channel)["type"] != "status" {
		t.Fatal("status missing")
	}
	offer := readViewerText(t, channel)
	if len(offer) != 3 || offer["state"] != "available" || offer["codec"] != "av1" {
		t.Fatalf("bad offer %v", offer)
	}
	readViewerFrame(t, channel, false)
	sendFrame(t, channel, map[string]any{"type": "ack", "seq": 10})
	sendFrame(t, channel, map[string]any{"type": "video", "enabled": true, "generation": 1})
	started := readViewerText(t, channel)
	if started["state"] != "started" || started["private"] != nil || started["streamId"] != videoFixtureEpoch || started["codecString"] != "av01.0.12M.08" {
		t.Fatalf("bad start %v", started)
	}
	return channel
}

func readViewerUnit(t *testing.T, channel *websocket.Conn, epoch string, seq uint64, key bool) {
	t.Helper()
	_ = channel.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, message, err := channel.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || bytes.Contains(message, []byte(browserFixtureSecret)) {
		t.Fatalf("picture missing: kind=%d err=%v", kind, err)
	}
	header, _, valid := parseBrowserVideoUnit(message)
	if !valid || header.StreamID != epoch || header.Seq != seq || header.Key != key {
		t.Fatalf("unexpected picture %+v valid=%v", header, valid)
	}
}

func TestBrowserViewerVideoReplacesFramesAndReturnsToThem(t *testing.T) {
	channel := openVideoFixture(t, "view-channel-video")
	readViewerUnit(t, channel, videoFixtureEpoch, 1, true)
	readViewerUnit(t, channel, videoFixtureEpoch, 2, false)
	// A duplicate and a retired stream's acknowledgement are dropped; the
	// driver receives exactly the painted prefix.
	sendFrame(t, channel, map[string]any{"type": "ack", "track": "video", "streamId": videoFixtureNextEpoch, "seq": 1})
	sendFrame(t, channel, map[string]any{"type": "ack", "track": "video", "streamId": videoFixtureEpoch, "seq": 2})
	sendFrame(t, channel, map[string]any{"type": "ack", "track": "video", "streamId": videoFixtureEpoch, "seq": 1})
	sendFrame(t, channel, map[string]any{"type": "video", "keyframe": true, "generation": 1})
	readViewerUnit(t, channel, videoFixtureEpoch, 3, true)
	sendFrame(t, channel, map[string]any{"type": "video", "enabled": false, "generation": 2})
	if stopped := readViewerText(t, channel); stopped["state"] != "stopped" || stopped["generation"] != float64(2) {
		t.Fatalf("not stopped: %v", stopped)
	}
	_ = channel.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, message, err := channel.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage {
		t.Fatalf("frames did not return: %v", err)
	}
	if frame, err := parseBrowserBinaryFrame(message); err != nil || frame.header.Seq != 12 || frame.header.BaseSeq != 0 {
		t.Fatalf("expected a whole frame after the stream: %+v %v", frame.header, err)
	}
}

func TestBrowserViewerVideoResubscriptionDiscardsTheRetiredStream(t *testing.T) {
	channel := openVideoFixture(t, "view-channel-video-race")
	readViewerUnit(t, channel, videoFixtureEpoch, 1, true)
	readViewerUnit(t, channel, videoFixtureEpoch, 2, false)
	sendFrame(t, channel, map[string]any{"type": "ack", "track": "video", "streamId": videoFixtureEpoch, "seq": 2})
	sendFrame(t, channel, map[string]any{"type": "video", "keyframe": true, "generation": 1})
	readViewerUnit(t, channel, videoFixtureEpoch, 3, true)
	sendFrame(t, channel, map[string]any{"type": "video", "enabled": false, "generation": 2})
	sendFrame(t, channel, map[string]any{"type": "video", "enabled": true, "generation": 3})
	started := readViewerText(t, channel)
	if started["state"] != "started" || started["generation"] != float64(3) || started["streamId"] != videoFixtureNextEpoch {
		t.Fatalf("retired record leaked: %v", started)
	}
	readViewerUnit(t, channel, videoFixtureNextEpoch, 1, true)
}

func TestBrowserViewerVideoNeverSkipsAPicture(t *testing.T) {
	channel := openVideoFixture(t, "view-channel-video-gap")
	readViewerUnit(t, channel, videoFixtureEpoch, 1, true)
	_ = channel.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := channel.ReadMessage()
	closed, ok := err.(*websocket.CloseError)
	if !ok || closed.Code != websocket.CloseInternalServerErr || closed.Text != "browser_view_invalid_video" {
		t.Fatalf("a gap was forwarded: %v", err)
	}
}

func TestBrowserViewerVideoRefusesAnUnofferedSubscriptionAndAFutureAcknowledgement(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	workspace.runDriver(t, "viewer-owner", "primary", "view-channel-finished")
	id, _ := workspace.only(t, "viewer-owner", "primary")
	channel := openBrowserViewer(t, workspace.serve(t), "viewer-owner", id, true)
	readViewerFrame(t, channel, false)
	sendFrame(t, channel, map[string]any{"type": "video", "enabled": true, "generation": 1})
	_ = channel.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, _, err := channel.ReadMessage()
		if err == nil {
			continue
		}
		if closed, ok := err.(*websocket.CloseError); !ok || closed.Code != websocket.ClosePolicyViolation {
			t.Fatalf("unoffered subscription was not refused: %v", err)
		}
		break
	}
	offered := openVideoFixture(t, "view-channel-video")
	readViewerUnit(t, offered, videoFixtureEpoch, 1, true)
	readViewerUnit(t, offered, videoFixtureEpoch, 2, false)
	sendFrame(t, offered, map[string]any{"type": "ack", "track": "video", "streamId": videoFixtureEpoch, "seq": 9})
	_ = offered.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := offered.ReadMessage()
	if closed, ok := err.(*websocket.CloseError); !ok || closed.Code != websocket.ClosePolicyViolation {
		t.Fatalf("an acknowledgement of an unsent picture was accepted: %v", err)
	}
}
