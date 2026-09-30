// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Ported from the toolbox's browser_video_linux_test.go and
// browser_audio_linux_test.go.

func TestVideoUnitProjectionAndBounds(t *testing.T) {
	payload := bytes.Repeat([]byte{0x12, 0x00, 0x0a}, 400)
	for _, key := range []bool{true, false} {
		value, projected, output, valid := parseVideoUnit(pack(videoHeaderFixture(1, key, len(payload)), payload))
		if !valid || value.Key != key || bytes.Contains(projected, []byte(fixtureSecret)) {
			t.Fatalf("unit not projected key=%v", key)
		}
		if !bytes.Equal(output, payload) {
			t.Fatal("picture bytes changed")
		}
		if _, again, _, _ := parseVideoUnit(packHeader(projected, output)); !bytes.Equal(again, projected) {
			t.Fatal("the unit projection is not idempotent")
		}
	}
	described := videoHeaderFixture(1, true, len(payload))
	described["description"] = "gQwMAA=="
	if value, _, _, valid := parseVideoUnit(pack(described, payload)); !valid || value.Description != "gQwMAA==" {
		t.Fatal("decoder configuration lost")
	}
	for _, change := range []map[string]any{
		{"seq": 0}, {"seq": safeInteger + 1}, {"ts": -1}, {"ts": nil}, {"byteLength": 1}, {"codec": "h264"}, {"streamId": "foreign-path"}, {"track": "audio"},
		{"quality": "best"}, {"coded": map[string]any{"width": 0, "height": 2048}}, {"coded": map[string]any{"width": 4097, "height": 2048}},
		{"visible": map[string]any{"x": 0, "y": 0, "width": 2049, "height": 10}}, {"visible": map[string]any{"x": 2048, "y": 0, "width": 1, "height": 1}},
		{"visible": map[string]any{"x": 0, "y": 0, "width": 0, "height": 10}}, {"surface": map[string]any{"kind": "page"}}, {"inputSeq": safeInteger + 1},
		{"codecString": "avc1.640033"}, {"codecString": "vp09.00.41.08"}, {"codecString": ""}, {"description": "not base64!"},
	} {
		header := videoHeaderFixture(1, true, len(payload))
		for key, value := range change {
			header[key] = value
		}
		if _, _, _, valid := parseVideoUnit(pack(header, payload)); valid {
			t.Fatalf("accepted %v", change)
		}
	}
	// Only a picture that needs no other carries a decoder configuration.
	for _, change := range []map[string]any{{"codecString": "av01.0.12M.08"}, {"description": "gQwMAA=="}} {
		header := videoHeaderFixture(2, false, len(payload))
		for key, value := range change {
			header[key] = value
		}
		if _, _, _, valid := parseVideoUnit(pack(header, payload)); valid {
			t.Fatalf("accepted %v on a dependent picture", change)
		}
	}
	fixture := videoHeaderFixture(1, true, len(payload))
	delete(fixture, "private")
	delete(fixture["surface"].(map[string]any), "private")
	encoded := jsonOf(fixture)
	atLimit := append(encoded, bytes.Repeat([]byte(" "), videoHeaderLimit-len(encoded))...)
	if _, _, _, valid := parseVideoUnit(packHeader(atLimit, payload)); !valid {
		t.Fatal("a header at the bound was refused")
	}
	if _, _, _, valid := parseVideoUnit(packHeader(append(atLimit, ' '), payload)); valid {
		t.Fatal("a header past the bound was accepted")
	}
	for _, input := range [][]byte{nil, {0xff, 0xff, 0xff, 0xff}, packHeader(bytes.Repeat([]byte(" "), videoHeaderLimit+1), payload),
		pack(videoHeaderFixture(1, true, 0), nil)} {
		if _, _, _, valid := parseVideoUnit(input); valid {
			t.Fatal("accepted invalid picture envelope")
		}
	}
	bounded := videoHeaderFixture(1, true, 12289)
	bounded["coded"] = map[string]any{"width": 16, "height": 16}
	bounded["visible"] = map[string]any{"x": 0, "y": 0, "width": 16, "height": 16}
	bounded["surface"].(map[string]any)["width"] = 16
	bounded["surface"].(map[string]any)["height"] = 16
	if _, _, _, valid := parseVideoUnit(pack(bounded, make([]byte, 12289))); valid {
		t.Fatal("picture exceeded its coded format's source allowance")
	}
}

func TestVideoMetadata(t *testing.T) {
	message, _ := json.Marshal(map[string]any{"type": "video", "state": "started", "generation": 1, "codec": "av1", "codecString": "av01.0.12M.08", "streamId": videoEpoch, "private": fixtureSecret})
	if _, projected, valid := parseVideoMetadata(message); !valid || bytes.Contains(projected, []byte(fixtureSecret)) {
		t.Fatal("invalid projection")
	}
	for _, message := range []string{`{"type":"video","state":"available","codec":"vp9-444"}`, `{"type":"video","state":"unavailable","generation":0}`,
		`{"type":"video","state":"stopped","codec":"av1","generation":3}`} {
		if _, projected, valid := parseVideoMetadata([]byte(message)); !valid || len(projected) == 0 {
			t.Fatalf("refused %s", message)
		}
	}
	for _, message := range []string{`{"type":"video","state":"started","codec":"av1"}`, `{"type":"video","state":"available"}`, `{"type":"video","state":"available","codec":"h264"}`,
		`{"type":"video","state":"playing","codec":"av1"}`, `{"type":"video","state":"stopped","codec":"av1"}`,
		`{"type":"video","state":"started","generation":1,"codec":"av1","codecString":"vp09.00.41.08","streamId":"` + videoEpoch + `"}`,
		`{"type":"video","state":"started","generation":0,"codec":"av1","codecString":"av01.0.12M.08","streamId":"` + videoEpoch + `"}`,
		`{"type":"video","state":"started","generation":1,"codec":"av1","codecString":"av01.0.12M.08","streamId":"foreign"}`} {
		if _, _, valid := parseVideoMetadata([]byte(message)); valid {
			t.Fatalf("admitted %s", message)
		}
	}
}

func TestAudioPacketProjectionAndBounds(t *testing.T) {
	payload := bytes.Repeat([]byte{1, 2}, 960)
	for _, codec := range []string{"opus", "pcm-s16le"} {
		header := audioHeaderFixture(codec)
		header["private"] = fixtureSecret
		value, projected, output, valid := parseAudioPacket(pack(header, payload))
		if !valid || value.Codec != codec || bytes.Contains(projected, []byte(fixtureSecret)) {
			t.Fatal("audio not projected")
		}
		if !bytes.Equal(output, payload) {
			t.Fatal("audio bytes changed")
		}
	}
	for _, change := range []map[string]any{{"seq": 0}, {"seq": safeInteger + 1}, {"ts": -1}, {"samples": 960}, {"byteLength": 1}, {"codec": "unknown"}, {"streamId": "foreign-path"}, {"track": "video"}} {
		header := audioHeaderFixture("opus")
		for key, value := range change {
			header[key] = value
		}
		if _, _, _, valid := parseAudioPacket(pack(header, payload)); valid {
			t.Fatalf("accepted %v", change)
		}
	}
	for _, input := range [][]byte{nil, {0xff, 0xff, 0xff, 0xff}, packHeader(bytes.Repeat([]byte(" "), audioHeaderLimit+1), payload), pack(audioHeaderFixture("opus"), make([]byte, audioPayloadLimit+1))} {
		if _, _, _, valid := parseAudioPacket(input); valid {
			t.Fatal("accepted invalid audio envelope")
		}
	}
	// The header bound itself: a valid header at exactly the limit is taken,
	// one byte more is refused.
	encoded := jsonOf(audioHeaderFixture("opus"))
	atLimit := append(encoded, bytes.Repeat([]byte(" "), audioHeaderLimit-len(encoded))...)
	if _, _, _, valid := parseAudioPacket(packHeader(atLimit, payload)); !valid {
		t.Fatal("a header at the bound was refused")
	}
	if _, _, _, valid := parseAudioPacket(packHeader(append(atLimit, ' '), payload)); valid {
		t.Fatal("a header past the bound was accepted")
	}
	header := audioHeaderFixture("pcm-s16le")
	header["byteLength"] = 1919
	if _, _, _, valid := parseAudioPacket(pack(header, payload[:1919])); valid {
		t.Fatal("accepted partial PCM quantum")
	}
}

func TestAudioMetadata(t *testing.T) {
	for _, codec := range []string{"opus", "pcm-s16le"} {
		message, _ := json.Marshal(map[string]any{"type": "audio", "state": "started", "generation": 1, "codec": codec, "streamId": audioEpoch, "sampleRate": 48000, "channels": 2, "frameSamples": 480, "primingSamples": 0, "private": fixtureSecret})
		_, projected, valid := parseAudioMetadata(message)
		if !valid || bytes.Contains(projected, []byte(fixtureSecret)) {
			t.Fatal("invalid projection")
		}
	}
	for _, message := range []string{`{"type":"audio","state":"started","codec":"opus"}`, `{"type":"audio","state":"available","codec":"h264"}`, `{"type":"audio","state":"playing","codec":"opus"}`} {
		if _, _, valid := parseAudioMetadata([]byte(message)); valid {
			t.Fatal("invalid metadata admitted")
		}
	}
}
