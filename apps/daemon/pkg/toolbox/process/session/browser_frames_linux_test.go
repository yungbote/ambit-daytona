// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"strings"
	"testing"
	"time"
)

func browserFixtureJPEG(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.SetRGBA(x, y, color.RGBA{R: byte(x), G: byte(y), B: 90, A: 255})
		}
	}
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, img, &jpeg.Options{Quality: 85}); err != nil {
		panic(err)
	}
	return encoded.Bytes()
}

func browserFixtureSurface() map[string]any {
	return map[string]any{"kind": "browser-window", "coordinateSpace": "display-pixels", "generation": "11111111-1111-4111-8111-111111111111", "width": 640, "height": 480, "originX": 0, "originY": 0, "deviceScaleFactor": 2, "cursorIncluded": false, "private": browserFixtureSecret}
}

func browserFixtureFrame(patched bool) (map[string]any, []byte) {
	header := map[string]any{"type": "frame", "seq": 10, "encoding": "jpeg", "surface": browserFixtureSurface(), "private": browserFixtureSecret}
	if !patched {
		payload := browserFixtureJPEG(640, 480)
		header["byteLength"] = len(payload)
		return header, payload
	}
	payload := browserFixtureJPEG(32, 32)
	header["seq"], header["baseSeq"] = 12, 10
	header["patches"] = []any{map[string]any{"x": 624, "y": 464, "width": 16, "height": 16, "sourceX": 16, "sourceY": 16, "byteLength": len(payload), "private": browserFixtureSecret}}
	return header, payload
}

func packBrowserFixtureFrame(header map[string]any, payload []byte) []byte {
	encoded, err := json.Marshal(header)
	if err != nil {
		panic(err)
	}
	return packBrowserFixtureHeader(encoded, payload)
}

func packBrowserFixtureHeader(header, payload []byte) []byte {
	result := make([]byte, 4, 4+len(header)+len(payload))
	binary.BigEndian.PutUint32(result, uint32(len(header)))
	result = append(result, header...)
	return append(result, payload...)
}

func TestBrowserBinaryFramesProjectHeadersAndPreservePixels(t *testing.T) {
	for _, patched := range []bool{false, true} {
		header, payload := browserFixtureFrame(patched)
		message := packBrowserFixtureFrame(header, payload)
		frame, err := parseBrowserBinaryFrame(message)
		if err != nil {
			t.Fatal(err)
		}
		var projected bytes.Buffer
		if err := frame.writeTo(&projected); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(projected.Bytes(), []byte(browserFixtureSecret)) {
			t.Fatal("private metadata reached binary output")
		}
		again, err := parseBrowserBinaryFrame(projected.Bytes())
		if err != nil || !bytes.Equal(again.payload, payload) || again.header.Seq != frame.header.Seq {
			t.Fatalf("frame changed: %v", err)
		}
		// The parser borrows the read buffer instead of allocating another JPEG.
		if &frame.payload[0] != &message[len(message)-len(payload)] {
			t.Fatal("parser copied JPEG payload")
		}
	}
}

func TestBrowserBinaryFramesRejectInvalidEnvelopeAndRaster(t *testing.T) {
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
			p = browserFixtureJPEG(31, 32)
			h["patches"].([]any)[0].(map[string]any)["byteLength"] = len(p)
			return h, p
		}},
		{"too much padding", true, func(h map[string]any, p []byte) (map[string]any, []byte) {
			p = browserFixtureJPEG(49, 32)
			h["patches"].([]any)[0].(map[string]any)["byteLength"] = len(p)
			return h, p
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			header, payload := browserFixtureFrame(test.patched)
			header, payload = test.mutate(header, payload)
			if _, err := parseBrowserBinaryFrame(packBrowserFixtureFrame(header, payload)); err == nil {
				t.Fatal("invalid frame admitted")
			}
		})
	}
	for field, values := range map[string][]any{"sourceX": {-1, 17}, "sourceY": {-1, 17}, "x": {1, 640}, "y": {1, 480}, "width": {0, 17, 513}, "height": {0, 17, 513}, "byteLength": {0, -1, 1 << 32}} {
		for _, value := range values {
			header, payload := browserFixtureFrame(true)
			header["patches"].([]any)[0].(map[string]any)[field] = value
			if _, err := parseBrowserBinaryFrame(packBrowserFixtureFrame(header, payload)); err == nil {
				t.Fatalf("admitted patch %s=%v", field, value)
			}
		}
	}
}

func TestBrowserBinaryFrameBudgetsAndPatchCount(t *testing.T) {
	header, payload := browserFixtureFrame(false)
	encoded, _ := json.Marshal(header)
	bounded := append(encoded, bytes.Repeat([]byte(" "), browserBinaryHeaderLimit-len(encoded))...)
	if _, err := parseBrowserBinaryFrame(packBrowserFixtureHeader(bounded, payload)); err != nil {
		t.Fatal("exact header bound rejected", err)
	}
	for _, invalid := range [][]byte{nil, {0, 0, 0}, {0, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff}, packBrowserFixtureHeader(append(bounded, ' '), payload), packBrowserFixtureHeader([]byte{0xff}, payload), packBrowserFixtureHeader([]byte(`{"type":`), payload), make([]byte, browserBinaryFrameLimit+1)} {
		if _, err := parseBrowserBinaryFrame(invalid); err == nil {
			t.Fatal("invalid prefix or bound admitted")
		}
	}
	for _, count := range []int{64, 65} {
		header, payload = browserFixtureFrame(true)
		patch := header["patches"].([]any)[0]
		patches := make([]any, count)
		for i := range patches {
			patches[i] = patch
		}
		header["patches"] = patches
		_, err := parseBrowserBinaryFrame(packBrowserFixtureFrame(header, bytes.Repeat(payload, count)))
		if (err == nil) != (count == 64) {
			t.Fatalf("patch count %d: %v", count, err)
		}
	}
}

func TestBrowserBinaryLegacyRecognitionRequiresAWholePageImage(t *testing.T) {
	makeFrame := func() (map[string]any, []byte) {
		header, payload := browserFixtureFrame(false)
		delete(header, "surface")
		header["metadata"] = map[string]any{"deviceWidth": 640, "deviceHeight": 480}
		return header, payload
	}
	header, payload := makeFrame()
	if !browserLegacyBinaryFrame(packBrowserFixtureFrame(header, payload)) {
		t.Fatal("valid legacy binary JPEG was not recognized")
	}
	for field, value := range map[string]any{"type": "result", "seq": 0, "baseSeq": 1, "encoding": "png", "metadata": nil, "surface": nil, "patches": []any{}, "byteLength": 1} {
		header, payload := makeFrame()
		header[field] = value
		if browserLegacyBinaryFrame(packBrowserFixtureFrame(header, payload)) {
			t.Fatalf("invalid legacy %s=%v admitted", field, value)
		}
	}
	header, payload = makeFrame()
	delete(header, "metadata")
	if browserLegacyBinaryFrame(packBrowserFixtureFrame(header, payload)) {
		t.Fatal("missing metadata admitted")
	}
	for _, input := range [][]byte{nil, {0xff, 0xff, 0xff, 0xff}, make([]byte, browserBinaryFrameLimit+1)} {
		if browserLegacyBinaryFrame(input) {
			t.Fatal("unbounded or malformed framing admitted")
		}
	}
}

func TestBrowserViewerMessagesHaveClosedSchemas(t *testing.T) {
	for _, input := range []string{`{"type":"ack","seq":10}`, `{"type":"presentation","width":1,"height":2048}`} {
		if _, _, valid := browserViewerMessage([]byte(input)); !valid {
			t.Fatalf("valid message refused: %s", input)
		}
	}
	for _, input := range []string{`null`, `[]`, `{`, `{"type":"ack","seq":0}`, `{"type":"ack","seq":1.5}`, `{"type":"ack","seq":-1}`, `{"type":"ack","seq":10,"width":null}`, `{"type":"presentation","width":0,"height":1}`, `{"type":"presentation","width":2049,"height":1}`, `{"type":"presentation","width":1,"height":1,"viewerId":"changed"}`, `{"type":"presentation","width":1,"height":1,"seq":10}`, `{"type":"input","events":[]}`, `{"type":"cdp","method":"Runtime.evaluate"}`, `{"type":"ack","seq":1}{}`, strings.Repeat(" ", browserViewerMessageLimit+1), "\xff"} {
		if _, _, valid := browserViewerMessage([]byte(input)); valid {
			t.Fatalf("invalid message admitted: %s", input)
		}
	}
}

func TestBrowserFrameWindowCountsWireBytesAndExactCumulativeACKs(t *testing.T) {
	w := browserFrameWindow{limit: 8}
	if !w.reserve(10, browserBinaryFrameLimit/2) || !w.reserve(12, browserBinaryFrameLimit/2) || w.reserve(14, 1) {
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

func TestBrowserFrameACKWaitsForDeliveryCompletion(t *testing.T) {
	header, payload := browserFixtureFrame(false)
	frame, err := parseBrowserBinaryFrame(packBrowserFixtureFrame(header, payload))
	if err != nil {
		t.Fatal(err)
	}
	ch := browserViewChannel{pending: browserFrameWindow{limit: 1}}
	entered, release, delivered := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(delivered)
		_, _ = ch.deliverFrame(frame.header.browserFrameHeader, frame.wireSize(), func() error { close(entered); <-release; return nil })
	}()
	<-entered
	attempted := make(chan struct{})
	ack := make(chan bool, 1)
	go func() { close(attempted); forward, valid := ch.acknowledgeFrame(10); ack <- forward && valid }()
	<-attempted
	select {
	case <-ack:
		close(release)
		<-delivered
		t.Fatal("ACK consumed credit before the blocked frame write completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-delivered
	select {
	case valid := <-ack:
		if !valid {
			t.Fatal("ACK after delivery rejected")
		}
	case <-time.After(time.Second):
		t.Fatal("ACK stayed blocked after delivery")
	}
}

func TestBrowserVisualStateProjectsDocumentedFields(t *testing.T) {
	for _, body := range []string{
		`{"type":"status","connected":false,"screencasting":true,"viewportWidth":640,"viewportHeight":480,"engine":"chromium","recording":false}`,
		`{"type":"url","url":"https://example.test","title":"Page","timestamp":123,"canGoBack":false,"canGoForward":true}`,
	} {
		input := body[:len(body)-1] + `,"private":"secret"}`
		projected, sequence, kind := browserViewMessage([]byte(input), true)
		if string(projected) != body || sequence != 0 || kind != browserRecordVisual {
			t.Fatalf("visual metadata projection changed known fields: %s", projected)
		}
	}
}

func FuzzBrowserBinaryFrameNeverPanics(f *testing.F) {
	header, payload := browserFixtureFrame(true)
	f.Add(packBrowserFixtureFrame(header, payload))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > browserBinaryFrameLimit+1 {
			return
		}
		_, _ = parseBrowserBinaryFrame(input)
		_ = browserLegacyBinaryFrame(input)
	})
}
