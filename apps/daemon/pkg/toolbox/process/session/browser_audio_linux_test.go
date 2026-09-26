// Copyright 2026 Daytona Platforms Inc.
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

const audioFixtureEpoch = "849653a5-972a-4cb7-8eb1-4a78b00d18a8"

func audioFixtureHeader(codec string) map[string]any {
	return map[string]any{"type": "media", "track": "audio", "codec": codec, "streamId": audioFixtureEpoch, "seq": 1, "ts": 1234567, "samples": 480, "byteLength": 1920}
}

func TestBrowserAudioPacketProjectionAndBounds(t *testing.T) {
	payload := bytes.Repeat([]byte{1, 2}, 960)
	for _, codec := range []string{"opus", "pcm-s16le"} {
		header := audioFixtureHeader(codec)
		header["private"] = browserFixtureSecret
		value, projected, valid := parseBrowserAudioPacket(packBrowserFixtureFrame(header, payload))
		if !valid || value.Codec != codec || bytes.Contains(projected, []byte(browserFixtureSecret)) {
			t.Fatal("audio not projected")
		}
		_, output, _ := browserBinaryParts(projected)
		if !bytes.Equal(output, payload) {
			t.Fatal("audio bytes changed")
		}
	}
	for _, change := range []map[string]any{{"seq": 0}, {"seq": browserSafeInteger + 1}, {"ts": -1}, {"samples": 960}, {"byteLength": 1}, {"codec": "unknown"}, {"streamId": "foreign-path"}, {"track": "video"}} {
		header := audioFixtureHeader("opus")
		for key, value := range change {
			header[key] = value
		}
		if _, _, valid := parseBrowserAudioPacket(packBrowserFixtureFrame(header, payload)); valid {
			t.Fatalf("accepted %v", change)
		}
	}
	for _, input := range [][]byte{nil, {0xff, 0xff, 0xff, 0xff}, packBrowserFixtureHeader(bytes.Repeat([]byte(" "), browserAudioHeaderLimit+1), payload), packBrowserFixtureFrame(audioFixtureHeader("opus"), make([]byte, browserAudioPayloadLimit+1))} {
		if _, _, valid := parseBrowserAudioPacket(input); valid {
			t.Fatal("accepted invalid audio envelope")
		}
	}
	header := audioFixtureHeader("pcm-s16le")
	header["byteLength"] = 1919
	if _, _, valid := parseBrowserAudioPacket(packBrowserFixtureFrame(header, payload[:1919])); valid {
		t.Fatal("accepted partial PCM quantum")
	}
}

func TestBrowserAudioDeclarationsAndClosedViewerMessages(t *testing.T) {
	for _, query := range []string{"audio=opus", "audio=opus&audio=opus&frames=binary", "audio=&frames=binary", "audio=PCM&frames=binary"} {
		if _, valid := parseBrowserAudioDeclaration(httptest.NewRequest("GET", "/?"+query, nil)); valid {
			t.Fatalf("accepted %s", query)
		}
	}
	for _, codec := range []string{"opus", "pcm-s16le"} {
		if value, valid := parseBrowserAudioDeclaration(httptest.NewRequest("GET", "/?frames=binary&audio="+codec, nil)); !valid || value != codec {
			t.Fatal("codec missing")
		}
	}
	for _, message := range []string{`{"type":"audio"}`, `{"type":"audio","enabled":"true"}`, `{"type":"audio","enabled":true,"controllerId":"foreign"}`} {
		if _, _, valid := browserViewerMessage([]byte(message)); valid {
			t.Fatalf("accepted %s", message)
		}
	}
	for _, message := range []string{`{"type":"audio","enabled":true,"generation":1}`, `{"type":"audio","enabled":false,"generation":2}`} {
		if _, ack, valid := browserViewerMessage([]byte(message)); !valid || ack != 0 {
			t.Fatal("output consumed frame acknowledgement")
		}
	}
}

func serveAudioFixture(connection *websocket.Conn, rapid bool) {
	_ = connection.WriteJSON(map[string]any{"type": "audio", "state": "available", "codec": "pcm-s16le", "private": browserFixtureSecret})
	frame, image := browserFixtureFrame(false)
	_ = connection.WriteMessage(websocket.BinaryMessage, packBrowserFixtureFrame(frame, image))
	var enabled struct {
		Type    string `json:"type"`
		Enabled bool   `json:"enabled"`
	}
	if connection.ReadJSON(&enabled) != nil || enabled.Type != "audio" || !enabled.Enabled {
		return
	}
	_ = connection.WriteJSON(map[string]any{"type": "audio", "state": "started", "generation": 1, "codec": "pcm-s16le", "streamId": audioFixtureEpoch, "sampleRate": 48000, "channels": 2, "frameSamples": 480, "primingSamples": 0, "private": browserFixtureSecret})
	_ = connection.WriteMessage(websocket.BinaryMessage, packBrowserFixtureFrame(audioFixtureHeader("pcm-s16le"), make([]byte, 1920)))
	var ack struct {
		Type string `json:"type"`
		Seq  uint64 `json:"seq"`
	}
	if connection.ReadJSON(&ack) != nil || ack.Type != "ack" || ack.Seq != 10 {
		return
	}
	if connection.ReadJSON(&enabled) != nil || enabled.Type != "audio" || enabled.Enabled {
		return
	}
	if rapid {
		if connection.ReadJSON(&enabled) != nil || !enabled.Enabled {
			return
		}
		old := audioFixtureHeader("pcm-s16le")
		old["seq"] = 2
		_ = connection.WriteMessage(websocket.BinaryMessage, packBrowserFixtureFrame(old, make([]byte, 1920)))
		_ = connection.WriteJSON(map[string]any{"type": "audio", "state": "stopped", "codec": "pcm-s16le", "generation": 2})
		next := "cf744786-e37b-451a-b8ba-8d2d44c5249c"
		_ = connection.WriteJSON(map[string]any{"type": "audio", "state": "started", "codec": "pcm-s16le", "generation": 3, "streamId": next, "sampleRate": 48000, "channels": 2, "frameSamples": 480, "primingSamples": 0})
		header := audioFixtureHeader("pcm-s16le")
		header["streamId"] = next
		_ = connection.WriteMessage(websocket.BinaryMessage, packBrowserFixtureFrame(header, make([]byte, 1920)))
	} else {
		_ = connection.WriteJSON(map[string]any{"type": "audio", "state": "stopped", "generation": 2, "codec": "pcm-s16le"})
	}
	frame, image = browserFixtureFrame(true)
	_ = connection.WriteMessage(websocket.BinaryMessage, packBrowserFixtureFrame(frame, image))
	drainBrowserFixture(connection)
}

func TestBrowserViewerAudioUsesSameChannelWithoutConsumingFrameCredit(t *testing.T) {
	testBrowserAudioChannel(t, false)
}

func TestBrowserViewerAudioMuteUnmuteDiscardsOldEpochWithoutClosingPixels(t *testing.T) {
	testBrowserAudioChannel(t, true)
}

func testBrowserAudioChannel(t *testing.T, rapid bool) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "viewer-owner")
	mode := "view-channel-audio"
	if rapid {
		mode = "view-channel-audio-race"
	}
	workspace.runDriver(t, "viewer-owner", "primary", mode)
	id, _ := workspace.only(t, "viewer-owner", "primary")
	address := browserViewerAddress(workspace.serve(t), "viewer-owner", id) + "?width=320&height=240&frames=binary&audio=pcm-s16le"
	channel, _, err := websocket.DefaultDialer.Dial(address, http.Header{"X-Ambit-Browser-Viewer": []string{browserFixtureViewer}})
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	if readViewerText(t, channel)["type"] != "status" {
		t.Fatal("status missing")
	}
	offer := readViewerText(t, channel)
	if len(offer) != 3 || offer["state"] != "available" {
		t.Fatalf("bad offer %v", offer)
	}
	readViewerFrame(t, channel, false)
	sendFrame(t, channel, map[string]any{"type": "audio", "enabled": true, "generation": 1})
	started := readViewerText(t, channel)
	if started["state"] != "started" || started["private"] != nil {
		t.Fatalf("bad start %v", started)
	}
	_ = channel.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, message, err := channel.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage {
		t.Fatalf("audio missing %v", err)
	}
	if header, _, valid := parseBrowserAudioPacket(message); !valid || header.Seq != 1 {
		t.Fatal("invalid audio packet")
	}
	sendFrame(t, channel, map[string]any{"type": "ack", "seq": 10})
	sendFrame(t, channel, map[string]any{"type": "audio", "enabled": false, "generation": 2})
	if rapid {
		sendFrame(t, channel, map[string]any{"type": "audio", "enabled": true, "generation": 3})
		metadata := readViewerText(t, channel)
		if metadata["state"] != "started" || metadata["generation"] != float64(3) {
			t.Fatalf("retired metadata leaked %v", metadata)
		}
		kind, body, err := channel.ReadMessage()
		if err != nil || kind != websocket.BinaryMessage {
			t.Fatalf("replacement audio missing %v", err)
		}
		if header, _, valid := parseBrowserAudioPacket(body); !valid || header.Seq != 1 || header.StreamID == audioFixtureEpoch {
			t.Fatal("retired audio leaked")
		}
	} else {
		if readViewerText(t, channel)["state"] != "stopped" {
			t.Fatal("audio not stopped")
		}
	}
	readViewerFrame(t, channel, true)
}

func TestBrowserAudioMetadata(t *testing.T) {
	for _, codec := range []string{"opus", "pcm-s16le"} {
		message, _ := json.Marshal(map[string]any{"type": "audio", "state": "started", "generation": 1, "codec": codec, "streamId": audioFixtureEpoch, "sampleRate": 48000, "channels": 2, "frameSamples": 480, "primingSamples": 0, "private": browserFixtureSecret})
		_, projected, valid := parseBrowserAudioMetadata(message)
		if !valid || bytes.Contains(projected, []byte(browserFixtureSecret)) {
			t.Fatal("invalid projection")
		}
	}
	for _, message := range []string{`{"type":"audio","state":"started","codec":"opus"}`, `{"type":"audio","state":"available","codec":"h264"}`, `{"type":"audio","state":"playing","codec":"opus"}`} {
		if _, _, valid := parseBrowserAudioMetadata([]byte(message)); valid {
			t.Fatal("invalid metadata admitted")
		}
	}
}
