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
	projected, sequence, kind := browserViewMessage(frame)
	if kind != browserRecordVisual || sequence != 4 || bytes.Contains(projected, []byte("private")) || bytes.Contains(projected, []byte("helperPid")) {
		t.Fatalf("frame projection: %s/%d/%v", projected, sequence, kind)
	}
	surface["width"] = 4097
	frame, _ = json.Marshal(map[string]any{"type": "frame", "seq": 5, "encoding": "jpeg", "data": "image", "surface": surface})
	if _, _, kind := browserViewMessage(frame); kind != browserRecordFailed {
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
