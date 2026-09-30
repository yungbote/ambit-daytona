// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"encoding/json"
	"testing"
)

func TestWideVideoUnitIsAdmittedWithoutChangingItsGeometryOrBytes(t *testing.T) {
	const size = 21734926 // recorded native4096² Q32 key, not a replacement ceiling
	header := videoHeaderFixture(1, true, size)
	header["codec"], header["codecString"] = "av1-444", "av01.1.16M.08"
	header["coded"] = map[string]any{"width": 4096, "height": 4096}
	header["visible"] = map[string]any{"x": 0, "y": 0, "width": 4096, "height": 4096}
	header["surface"].(map[string]any)["width"] = 4096
	header["surface"].(map[string]any)["height"] = 4096
	_, projected, body, valid := parseVideoUnit(pack(header, make([]byte, size)))
	if !valid || len(body) != size {
		t.Fatal("valid wide logical unit was refused by a fixed body/envelope limit")
	}
	var output videoHeader
	if json.Unmarshal(projected, &output) != nil || output.Coded != (videoSize{4096, 4096}) || int(output.ByteLength) != size {
		t.Fatal("wide picture geometry or exact byte accounting changed")
	}
}

func TestVideoCapacityFollowsAlignedGeometryAndChroma(t *testing.T) {
	for _, test := range []struct {
		coded videoSize
		codec string
		want  uint64
	}{
		{videoSize{1, 1}, "av1", 12288},
		{videoSize{32, 32}, "av1-444", 24576},
		{videoSize{33, 32}, "av1", 24576},
		{videoSize{33, 32}, "av1-444", 49152},
		{videoSize{4096, 4096}, "av1-444", 402653184},
		{videoSize{4096, 4096}, "vp9", 201326592},
		{videoSize{0, 32}, "av1", 0},
		{videoSize{4097, 32}, "av1", 0},
		{videoSize{32, 32}, "h264", 0},
	} {
		if got := videoPayloadBytes(test.codec, test.coded); got != test.want {
			t.Fatalf("%s %v capacity%d, want%d", test.codec, test.coded, got, test.want)
		}
	}
}

func TestLegacyVideoLimitRefusesOnlyItsTrackOnceWhileCapablePeerContinues(t *testing.T) {
	payload := make([]byte, (4<<20)+1)
	header := videoHeaderFixture(2, true, len(payload))
	message := pack(header, payload)
	legacyDeclaration := videoDeclaration()
	legacyDeclaration.Audio = "pcm-s16le"
	legacy := newScript(t, legacyDeclaration)
	legacy.offerVideo()
	legacy.record(map[string]any{"type": "audio", "state": "available", "codec": "pcm-s16le"})
	legacy.forward(`{"type":"audio","enabled":true,"generation":1}`, SlotAudio)
	legacy.record(map[string]any{"type": "audio", "state": "started", "codec": "pcm-s16le", "generation": 1, "streamId": audioEpoch,
		"sampleRate": 48000, "channels": 2, "frameSamples": 480, "primingSamples": 0})
	legacy.deliver(false, audioPacket(audioEpoch, 1))
	capability := videoDeclaration()
	capability.VideoCapacity = true
	capable := newScript(t, capability)
	capable.offerVideo()
	unit, closing := legacy.c.Upstream(false, message)
	if closing != nil || unit == nil || unit.Kind != Record {
		t.Fatal("legacy capability failure terminated the attachment")
	}
	var refused videoMetadata
	if json.Unmarshal(unit.Text, &refused) != nil || refused.State != "unavailable" || refused.Generation == nil || *refused.Generation != 1 {
		t.Fatal("legacy peer did not receive the existing track refusal")
	}
	legacy.drop(false, message) // No repeated refusal/huge unit for this epoch.
	if video, end := capable.c.Upstream(false, message); end != nil || video == nil || video.Kind != Video || len(video.Payload) != len(payload) {
		t.Fatal("legacy refusal changed the capable peer")
	}
	legacy.forward(`{"type":"video","enabled":false,"generation":2}`, SlotVideo)
	legacy.deliver(false, frameAt(12, 0))
	legacy.deliver(false, audioPacket(audioEpoch, 2))
	legacy.forward(`{"type":"presentation","width":400,"height":300}`, SlotPresentation)
	legacy.record(map[string]any{"type": "cursor", "ts": 1234567890, "serial": 1, "css": "text"})
}
