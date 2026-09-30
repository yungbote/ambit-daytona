// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Ported from the toolbox's browser_frames_linux_test.go and
// browser_window_linux_test.go.

func TestBinaryFramesProjectHeadersAndPreservePixels(t *testing.T) {
	for _, patched := range []bool{false, true} {
		header, payload := fixtureFrame(patched)
		message := pack(header, payload)
		frame, err := parseBinaryFrame(message)
		if err != nil {
			t.Fatal(err)
		}
		projected := packHeader(frame.projected, frame.payload)
		if bytes.Contains(projected, []byte(fixtureSecret)) {
			t.Fatal("private metadata reached binary output")
		}
		again, err := parseBinaryFrame(projected)
		if err != nil || !bytes.Equal(again.payload, payload) || again.header.Seq != frame.header.Seq {
			t.Fatalf("frame changed: %v", err)
		}
		// Projecting a projection changes nothing: the toolbox's own output
		// passes the edge byte for byte.
		if !bytes.Equal(packHeader(again.projected, again.payload), projected) {
			t.Fatal("the projection is not idempotent")
		}
		// The parser borrows the read buffer instead of allocating another JPEG.
		if &frame.payload[0] != &message[len(message)-len(payload)] {
			t.Fatal("parser copied JPEG payload")
		}
	}
}

func TestBinaryFramesRejectInvalidEnvelopeAndRaster(t *testing.T) {
	cases := []struct {
		name    string
		patched bool
		mutate  func(map[string]any, []byte) (map[string]any, []byte)
	}{
		{"wrong type", false, func(h map[string]any, p []byte) (map[string]any, []byte) { h["type"] = "result"; return h, p }},
		{"zero sequence", false, func(h map[string]any, p []byte) (map[string]any, []byte) { h["seq"] = 0; return h, p }},
		{"non jpeg", false, func(h map[string]any, p []byte) (map[string]any, []byte) { h["encoding"] = "png"; return h, p }},
		{"truncated", false, func(h map[string]any, p []byte) (map[string]any, []byte) { return h, p[:len(p)-1] }},
		{"trailing", false, func(h map[string]any, p []byte) (map[string]any, []byte) { return h, append(p, 0) }},
		{"whole with base", false, func(h map[string]any, p []byte) (map[string]any, []byte) { h["baseSeq"] = 9; return h, p }},
		{"whole with empty patches", false, func(h map[string]any, p []byte) (map[string]any, []byte) { h["patches"] = []any{}; return h, p }},
		{"foreign geometry", false, func(h map[string]any, p []byte) (map[string]any, []byte) {
			h["surface"].(map[string]any)["width"] = 641
			return h, p
		}},
		{"invalid jpeg", false, func(h map[string]any, p []byte) (map[string]any, []byte) { p[0] = 0; return h, p }},
		{"invalid surface", false, func(h map[string]any, p []byte) (map[string]any, []byte) {
			h["surface"].(map[string]any)["deviceScaleFactor"] = 3
			return h, p
		}},
		{"patch without base", true, func(h map[string]any, p []byte) (map[string]any, []byte) { delete(h, "baseSeq"); return h, p }},
		{"patch future base", true, func(h map[string]any, p []byte) (map[string]any, []byte) { h["baseSeq"] = 12; return h, p }},
		{"mixed payload kinds", true, func(h map[string]any, p []byte) (map[string]any, []byte) { h["byteLength"] = len(p); return h, p }},
		{"patch trailing", true, func(h map[string]any, p []byte) (map[string]any, []byte) { return h, append(p, 0) }},
		{"short crop image", true, func(h map[string]any, p []byte) (map[string]any, []byte) {
			p = fixtureJPEG(31, 32)
			h["patches"].([]any)[0].(map[string]any)["byteLength"] = len(p)
			return h, p
		}},
		{"too much padding", true, func(h map[string]any, p []byte) (map[string]any, []byte) {
			p = fixtureJPEG(49, 32)
			h["patches"].([]any)[0].(map[string]any)["byteLength"] = len(p)
			return h, p
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			header, payload := fixtureFrame(test.patched)
			header, payload = test.mutate(header, payload)
			if _, err := parseBinaryFrame(pack(header, payload)); err == nil {
				t.Fatal("invalid frame admitted")
			}
		})
	}
	for field, values := range map[string][]any{"sourceX": {-1, 17}, "sourceY": {-1, 17}, "x": {1, 640}, "y": {1, 480}, "width": {0, 17, 513}, "height": {0, 17, 513}, "byteLength": {0, -1, 1 << 32}} {
		for _, value := range values {
			header, payload := fixtureFrame(true)
			header["patches"].([]any)[0].(map[string]any)[field] = value
			if _, err := parseBinaryFrame(pack(header, payload)); err == nil {
				t.Fatalf("admitted patch %s=%v", field, value)
			}
		}
	}
}

func TestBinaryFrameBudgetsAndPatchCount(t *testing.T) {
	header, payload := fixtureFrame(false)
	encoded, _ := json.Marshal(header)
	bounded := append(encoded, bytes.Repeat([]byte(" "), maxFrameHeaderBytes-len(encoded))...)
	if _, err := parseBinaryFrame(packHeader(bounded, payload)); err != nil {
		t.Fatal("exact header bound rejected", err)
	}
	for _, invalid := range [][]byte{nil, {0, 0, 0}, {0, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff}, packHeader(append(bounded, ' '), payload), packHeader([]byte{0xff}, payload), packHeader([]byte(`{"type":`), payload), make([]byte, maxFrameMessageBytes+1)} {
		if _, err := parseBinaryFrame(invalid); err == nil {
			t.Fatal("invalid prefix or bound admitted")
		}
	}
	for _, count := range []int{64, 65} {
		header, payload = fixtureFrame(true)
		patch := header["patches"].([]any)[0]
		patches := make([]any, count)
		for i := range patches {
			patches[i] = patch
		}
		header["patches"] = patches
		_, err := parseBinaryFrame(pack(header, bytes.Repeat(payload, count)))
		if (err == nil) != (count == 64) {
			t.Fatalf("patch count %d: %v", count, err)
		}
	}
}

func TestLegacyRecognitionRequiresAWholePageImage(t *testing.T) {
	makeFrame := func() (map[string]any, []byte) {
		header, payload := fixtureFrame(false)
		delete(header, "surface")
		header["metadata"] = map[string]any{"deviceWidth": 640, "deviceHeight": 480}
		return header, payload
	}
	header, payload := makeFrame()
	if !legacyBinaryFrame(pack(header, payload)) {
		t.Fatal("valid legacy binary JPEG was not recognized")
	}
	for field, value := range map[string]any{"type": "result", "seq": 0, "baseSeq": 1, "encoding": "png", "metadata": nil, "surface": nil, "patches": []any{}, "byteLength": 1} {
		header, payload := makeFrame()
		header[field] = value
		if legacyBinaryFrame(pack(header, payload)) {
			t.Fatalf("invalid legacy %s=%v admitted", field, value)
		}
	}
	header, payload = makeFrame()
	delete(header, "metadata")
	if legacyBinaryFrame(pack(header, payload)) {
		t.Fatal("missing metadata admitted")
	}
	for _, input := range [][]byte{nil, {0xff, 0xff, 0xff, 0xff}, make([]byte, maxFrameMessageBytes+1)} {
		if legacyBinaryFrame(input) {
			t.Fatal("unbounded or malformed framing admitted")
		}
	}
}

func TestFrameWindowCountsWireBytesAndExactCumulativeACKs(t *testing.T) {
	w := frameWindow{limit: 8}
	if !w.reserve(10, maxFrameMessageBytes/2) || !w.reserve(12, maxFrameMessageBytes/2) || w.reserve(14, 1) {
		t.Fatal("aggregate wire budget was not enforced")
	}
	if forward, valid := w.acknowledge(11); forward || valid || len(w.frames) != 2 {
		t.Fatal("unknown sequence consumed credit")
	}
	if forward, valid := w.acknowledge(12); !forward || !valid || w.bytes != 0 || len(w.frames) != 0 {
		t.Fatal("cumulative ACK did not release the exact prefix")
	}
	if forward, valid := w.acknowledge(10); forward || !valid {
		t.Fatal("stale ACK was not ignored")
	}
	for seq := uint64(14); seq < 22; seq++ {
		if !w.reserve(seq, 1) {
			t.Fatal("window filled early")
		}
	}
	if w.reserve(22, 1) {
		t.Fatal("negotiated frame count exceeded")
	}
	if forward, valid := w.acknowledge(17); !forward || !valid || w.bytes != 4 || len(w.frames) != 4 || w.frames[0].sequence != 18 {
		t.Fatal("partial cumulative ACK lost later frames")
	}
	if forward, valid := w.acknowledge(30); forward || valid {
		t.Fatal("future ACK admitted")
	}
}

// The toolbox held its delivery lock across the socket write so that an ACK
// could not consume credit for a frame still being written. The edge counts a
// frame before it is written instead, so an ACK is never queued behind a
// write; a failed write ends the session, so credit for an undelivered frame
// is never passed on.
func TestFrameCreditIsCountedBeforeTheWrite(t *testing.T) {
	c := NewChannel(Declaration{Width: 320, Height: 240, FrameWindow: 1})
	if d, end := c.Upstream(false, frameAt(10, 0)); d == nil || end != nil {
		t.Fatalf("frame: %v %v", d, end)
	}
	if f, end := c.Viewer(true, []byte(`{"type":"ack","seq":10}`)); f == nil || end != nil {
		t.Fatal("an acknowledgement of a counted frame is valid at once")
	}
	if _, end := c.Viewer(true, []byte(`{"type":"ack","seq":12}`)); end == nil {
		t.Fatal("an acknowledgement of a frame never counted is refused")
	}
}

func TestVisualStateProjectsDocumentedFields(t *testing.T) {
	for _, body := range []string{
		`{"type":"status","connected":false,"screencasting":true,"viewportWidth":640,"viewportHeight":480,"engine":"chromium","recording":false}`,
		`{"type":"url","url":"https://example.test","title":"Page","timestamp":123,"canGoBack":false,"canGoForward":true}`,
	} {
		input := body[:len(body)-1] + `,"private":"secret"}`
		projected, sequence, kind := projectRecord([]byte(input))
		if string(projected) != body || sequence != 0 || kind != recordVisual {
			t.Fatalf("visual metadata projection changed known fields: %s", projected)
		}
	}
}

func FuzzBinaryFrameNeverPanics(f *testing.F) {
	header, payload := fixtureFrame(true)
	f.Add(pack(header, payload))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add(videoUnit(videoEpoch, 1, true))
	f.Add(audioPacket(audioEpoch, 1))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > MaxMessageBytes+1 {
			return
		}
		_, _ = parseBinaryFrame(input)
		_ = legacyBinaryFrame(input)
		_, _, _, _ = parseVideoUnit(input)
		_, _, _, _ = parseAudioPacket(input)
		c := NewChannel(Declaration{Width: 320, Height: 240, FrameWindow: 8, Audio: "opus", Video: []string{"av1"}})
		_, _ = c.Upstream(false, input)
		_, _ = c.Upstream(true, input)
		_, _ = c.Viewer(true, input)
	})
}

// A frame's capture clock, input causality and window rectangle reach the
// viewer; nothing else joins them.
func TestFramesCarryCaptureClockInputSequenceAndVisibleWindow(t *testing.T) {
	clock := map[string]any{"ts": 912345678, "inputSeq": 4411, "visible": map[string]any{"x": 0, "y": 0, "width": 600, "height": 480, "private": fixtureSecret}}
	expect := func(t *testing.T, projected []byte) {
		t.Helper()
		var value struct {
			Ts       uint64         `json:"ts"`
			InputSeq uint64         `json:"inputSeq"`
			Visible  map[string]any `json:"visible"`
		}
		if json.Unmarshal(projected, &value) != nil || value.Ts != 912345678 || value.InputSeq != 4411 ||
			len(value.Visible) != 4 || value.Visible["width"] != float64(600) || value.Visible["height"] != float64(480) {
			t.Fatalf("capture clock was not projected: %s", projected)
		}
		if bytes.Contains(projected, []byte(fixtureSecret)) {
			t.Fatal("private metadata reached the viewer")
		}
	}
	for _, patched := range []bool{false, true} {
		header, payload := fixtureFrame(patched)
		for field, value := range clock {
			header[field] = value
		}
		frame, err := parseBinaryFrame(pack(header, payload))
		if err != nil {
			t.Fatal(err)
		}
		expect(t, frame.projected)
	}
	text := map[string]any{"type": "frame", "seq": 3, "encoding": "jpeg", "data": "AAAA", "surface": fixtureSurface()}
	for field, value := range clock {
		text[field] = value
	}
	projected, sequence, kind := projectRecord(jsonOf(text))
	if kind != recordVisual || sequence != 3 {
		t.Fatalf("text frame refused: %s", projected)
	}
	expect(t, projected)
}

func TestFramesRefuseAnUnboundedClockOrAVisibleWindowOutsideTheRaster(t *testing.T) {
	cases := []struct {
		field string
		value any
	}{
		{"ts", float64(1 << 53)},
		{"ts", -1},
		{"inputSeq", float64(1 << 53)},
		{"visible", map[string]any{"x": 0, "y": 0, "width": 641, "height": 480}},
		{"visible", map[string]any{"x": 40, "y": 0, "width": 601, "height": 480}},
		{"visible", map[string]any{"x": 0, "y": 0, "width": 0, "height": 480}},
		{"visible", map[string]any{"x": 0, "y": 481, "width": 1, "height": 1}},
		{"visible", map[string]any{"x": -1, "y": 0, "width": 1, "height": 1}},
	}
	for _, test := range cases {
		header, payload := fixtureFrame(false)
		header[test.field] = test.value
		if _, err := parseBinaryFrame(pack(header, payload)); err == nil {
			t.Fatalf("admitted binary %s=%v", test.field, test.value)
		}
		text := map[string]any{"type": "frame", "seq": 3, "encoding": "jpeg", "data": "AAAA", "surface": fixtureSurface(), test.field: test.value}
		if _, _, kind := projectRecord(jsonOf(text)); kind != recordFailed {
			t.Fatalf("admitted text %s=%v", test.field, test.value)
		}
	}
}

func TestWindowFramesProjectOnlyTheVisualContract(t *testing.T) {
	surface := map[string]any{"kind": "browser-window", "coordinateSpace": "display-pixels", "generation": "11111111-1111-4111-8111-111111111111", "width": 780, "height": 1688, "originX": 0, "originY": 0, "deviceScaleFactor": 2, "cursorIncluded": true}
	projected, sequence, kind := projectRecord(jsonOf(map[string]any{"type": "frame", "seq": 4, "encoding": "jpeg", "data": "image", "surface": surface, "clipboard": "private", "helperPid": 42}))
	if kind != recordVisual || sequence != 4 || bytes.Contains(projected, []byte("private")) || bytes.Contains(projected, []byte("helperPid")) {
		t.Fatalf("frame projection: %s/%d/%v", projected, sequence, kind)
	}
	surface["width"] = 4097
	if _, _, kind := projectRecord(jsonOf(map[string]any{"type": "frame", "seq": 5, "encoding": "jpeg", "data": "image", "surface": surface})); kind != recordFailed {
		t.Fatal("invalid window raster was admitted")
	}
}

func TestWindowPatchesRequireAnExactBase(t *testing.T) {
	surface := map[string]any{"kind": "browser-window", "coordinateSpace": "display-pixels", "generation": "11111111-1111-4111-8111-111111111111", "width": 780, "height": 1688, "originX": 0, "originY": 0, "deviceScaleFactor": 2, "cursorIncluded": false}
	patch := map[string]any{"x": 768, "y": 1680, "width": 12, "height": 8, "data": "jpeg", "sourceX": 16, "sourceY": 16, "private": "omit"}
	frame := map[string]any{"type": "frame", "seq": 5, "baseSeq": 4, "encoding": "jpeg", "patches": []any{patch}, "surface": surface, "private": "omit"}
	check := func(want recordKind) {
		t.Helper()
		out, seq, kind := projectRecord(jsonOf(frame))
		if kind != want {
			t.Fatalf("kind=%v want=%v for %s", kind, want, jsonOf(frame))
		}
		if want == recordVisual && (seq != 5 || bytes.Contains(out, []byte("omit")) || !bytes.Contains(out, []byte(`"baseSeq":4`)) || !bytes.Contains(out, []byte(`"cursorIncluded":false`))) {
			t.Fatalf("bad projection %s", out)
		}
	}
	check(recordVisual)
	for _, base := range []any{0, 5, 6, "4", nil} {
		frame["baseSeq"] = base
		check(recordFailed)
	}
	frame["baseSeq"] = 4
	frame["data"] = "whole"
	check(recordFailed)
	delete(frame, "data")
	for _, value := range []any{513, 13, 0, -1} {
		patch["width"] = value
		check(recordFailed)
	}
	patch["width"] = 12
	patch["sourceX"] = 17
	check(recordFailed)
	patch["sourceX"] = 16
	patch["x"] = 767
	check(recordFailed)
	patch["x"] = 768
	delete(surface, "cursorIncluded")
	check(recordFailed)
	surface["cursorIncluded"] = false
	frame["patches"] = []any{}
	check(recordFailed)
}
