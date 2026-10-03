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
	"testing"
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

// browserFixtureFrame is a picture as the driver builds it: its header carries
// the picture's own facts only.
func browserFixtureFrame(patched bool) (map[string]any, []byte) {
	surface := browserFixtureSurface()
	delete(surface, "private")
	header := map[string]any{"type": "frame", "seq": 10, "encoding": "jpeg", "surface": surface}
	if !patched {
		payload := browserFixtureJPEG(640, 480)
		header["byteLength"] = len(payload)
		return header, payload
	}
	payload := browserFixtureJPEG(32, 32)
	header["seq"], header["baseSeq"] = 12, 10
	header["patches"] = []any{map[string]any{"x": 624, "y": 464, "width": 16, "height": 16, "sourceX": 16, "sourceY": 16, "byteLength": len(payload)}}
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

func FuzzBrowserLegacyBinaryFrameNeverPanics(f *testing.F) {
	header, payload := browserFixtureFrame(false)
	delete(header, "surface")
	header["metadata"] = map[string]any{"deviceWidth": 640, "deviceHeight": 480}
	f.Add(packBrowserFixtureFrame(header, payload))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > browserBinaryFrameLimit+1 {
			return
		}
		_ = browserLegacyBinaryFrame(input)
	})
}

// A text frame's capture clock, input causality and window rectangle reach
// the compatible reader; nothing else joins them.
func TestBrowserFramesCarryCaptureClockInputSequenceAndVisibleWindow(t *testing.T) {
	text := map[string]any{"type": "frame", "seq": 3, "encoding": "jpeg", "data": "AAAA", "surface": browserFixtureSurface(),
		"ts": 912345678, "inputSeq": 4411, "visible": map[string]any{"x": 0, "y": 0, "width": 600, "height": 480, "private": browserFixtureSecret}}
	encoded, _ := json.Marshal(text)
	projected, sequence, kind := browserViewMessage(encoded, false)
	if kind != browserRecordVisual || sequence != 3 {
		t.Fatalf("text frame refused: %s", projected)
	}
	var value struct {
		Ts       uint64         `json:"ts"`
		InputSeq uint64         `json:"inputSeq"`
		Visible  map[string]any `json:"visible"`
	}
	if json.Unmarshal(projected, &value) != nil || value.Ts != 912345678 || value.InputSeq != 4411 ||
		len(value.Visible) != 4 || value.Visible["width"] != float64(600) || value.Visible["height"] != float64(480) {
		t.Fatalf("capture clock was not projected: %s", projected)
	}
	if bytes.Contains(projected, []byte(browserFixtureSecret)) {
		t.Fatal("private metadata reached the viewer")
	}
}

func TestBrowserFramesRefuseAnUnboundedClockOrAVisibleWindowOutsideTheRaster(t *testing.T) {
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
		text := map[string]any{"type": "frame", "seq": 3, "encoding": "jpeg", "data": "AAAA", "surface": browserFixtureSurface(), test.field: test.value}
		encoded, _ := json.Marshal(text)
		if _, _, kind := browserViewMessage(encoded, false); kind != browserRecordFailed {
			t.Fatalf("admitted text %s=%v", test.field, test.value)
		}
	}
}
