// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrowserWindowPresentationBoundsAndIdentity(t *testing.T) {
	for _, test := range []struct {
		query, viewer string
		valid         bool
	}{
		{"", "", true},
		{"?width=390&height=844", "11111111-1111-4111-8111-111111111111", true},
		{"?width=2048&height=2048", "11111111-1111-4111-8111-111111111111", true},
		{"?width=2049&height=100", "11111111-1111-4111-8111-111111111111", false},
		{"?width=390&width=800&height=844", "11111111-1111-4111-8111-111111111111", false},
		{"?width=390&height=844", "00000000-0000-0000-0000-000000000000", false},
		{"?width=390&height=844", "", false},
	} {
		r := httptest.NewRequest("GET", "/stream"+test.query, nil)
		r.Header.Set("X-Ambit-Browser-Viewer", test.viewer)
		_, valid := parseBrowserPresentation(r)
		if valid != test.valid {
			t.Fatalf("%s/%s valid=%v", test.query, test.viewer, valid)
		}
	}
}

func TestBrowserWindowFramesProjectOnlyTheVisualContract(t *testing.T) {
	surface := map[string]any{"kind": "browser-window", "coordinateSpace": "display-pixels", "generation": "11111111-1111-4111-8111-111111111111", "width": 780, "height": 1688, "originX": 0, "originY": 0, "deviceScaleFactor": 2, "cursorIncluded": true}
	frame, _ := json.Marshal(map[string]any{"type": "frame", "seq": 4, "encoding": "jpeg", "data": "image", "surface": surface, "clipboard": "private", "helperPid": 42})
	projected, sequence, kind := browserViewMessage(frame, false)
	if kind != browserRecordVisual || sequence != 4 || bytes.Contains(projected, []byte("private")) || bytes.Contains(projected, []byte("helperPid")) {
		t.Fatalf("frame projection: %s/%d/%v", projected, sequence, kind)
	}
	surface["width"] = 4097
	frame, _ = json.Marshal(map[string]any{"type": "frame", "seq": 5, "encoding": "jpeg", "data": "image", "surface": surface})
	if _, _, kind := browserViewMessage(frame, false); kind != browserRecordFailed {
		t.Fatal("invalid window raster was admitted")
	}
}

func TestBrowserWindowLargePasteIsOneExplicitIntent(t *testing.T) {
	event, _ := json.Marshal(map[string]any{"type": "input_keyboard", "eventType": "insertText", "text": strings.Repeat("\u0001", browserCopyTextLimit)})
	request := browserControlRequest{Op: "input", ControllerID: "11111111-1111-4111-8111-111111111111", Sequence: 1, ExpectedSurfaceGeneration: "22222222-2222-4222-8222-222222222222", Events: []json.RawMessage{event}}
	if !validBrowserControlRequest(request) || browserControlRequestLimit(request) != browserPasteRequestLimit {
		t.Fatal("exact UTF-8 paste bound rejected")
	}
	request.Events = append(request.Events, event)
	if browserControlRequestLimit(request) != browserControlLimit {
		t.Fatal("multiple pastes received an enlarged batch limit")
	}
	request.Events = request.Events[:1]
	request.ExpectedSurfaceGeneration = ""
	if browserControlRequestLimit(request) != browserControlLimit {
		t.Fatal("legacy page input received the window paste exception")
	}
	request.ExpectedSurfaceGeneration = "22222222-2222-4222-8222-222222222222"
	event, _ = json.Marshal(map[string]any{"type": "input_keyboard", "eventType": "insertText", "text": strings.Repeat("x", browserCopyTextLimit+1)})
	request.Events[0] = event
	if browserControlRequestLimit(request) != browserControlLimit {
		t.Fatal("oversize paste received the enlarged limit")
	}
}

func TestBrowserWindowPatchesRequireNegotiationAndExactBase(t *testing.T) {
	surface := map[string]any{"kind": "browser-window", "coordinateSpace": "display-pixels", "generation": "11111111-1111-4111-8111-111111111111", "width": 780, "height": 1688, "originX": 0, "originY": 0, "deviceScaleFactor": 2, "cursorIncluded": false}
	patch := map[string]any{"x": 768, "y": 1680, "width": 12, "height": 8, "data": "jpeg", "sourceX": 16, "sourceY": 16, "private": "omit"}
	frame := map[string]any{"type": "frame", "seq": 5, "baseSeq": 4, "encoding": "jpeg", "patches": []any{patch}, "surface": surface, "private": "omit"}
	check := func(want browserRecordKind) {
		t.Helper()
		raw, _ := json.Marshal(frame)
		out, seq, kind := browserViewMessage(raw, true)
		if kind != want {
			t.Fatalf("kind=%v want=%v for %s", kind, want, raw)
		}
		if want == browserRecordVisual && (seq != 5 || bytes.Contains(out, []byte("omit")) || !bytes.Contains(out, []byte(`"baseSeq":4`)) || !bytes.Contains(out, []byte(`"cursorIncluded":false`))) {
			t.Fatalf("bad projection %s", out)
		}
	}
	check(browserRecordVisual)
	raw, _ := json.Marshal(frame)
	if _, _, kind := browserViewMessage(raw, false); kind != browserRecordFailed {
		t.Fatal("unnegotiated patches accepted")
	}
	for _, base := range []any{0, 5, 6, "4", nil} {
		frame["baseSeq"] = base
		check(browserRecordFailed)
	}
	frame["baseSeq"] = 4
	frame["data"] = "whole"
	check(browserRecordFailed)
	delete(frame, "data")
	for _, value := range []any{513, 13, 0, -1} {
		patch["width"] = value
		check(browserRecordFailed)
	}
	patch["width"] = 12
	patch["sourceX"] = 17
	check(browserRecordFailed)
	patch["sourceX"] = 16
	patch["x"] = 767
	check(browserRecordFailed)
	patch["x"] = 768
	delete(surface, "cursorIncluded")
	check(browserRecordFailed)
	surface["cursorIncluded"] = false
	frame["patches"] = []any{}
	check(browserRecordFailed)
}
