// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"encoding/json"
	"testing"
)

func TestBrowserFileControlAuthorityAndProjection(t *testing.T) {
	controller := "17cc0f0a-c9d7-4b71-bae8-e6f65c9574a5"
	destination := "e61ad83a-0cef-4095-8a7c-06bb94447b88"
	point := 0.0
	if result, ok := browserFileResponse(json.RawMessage(`{}`), browserControlRequest{Op: "drop"}, "duplicate"); !ok || len(result) != 0 {
		t.Fatal("duplicate drop must not create another destination")
	}
	if !validBrowserControlRequest(browserControlRequest{Op: "downloads"}) || validBrowserControlRequest(browserControlRequest{Op: "downloads", ControllerID: controller}) {
		t.Fatal("download observation must be readonly and cannot borrow a controller")
	}
	requests := []browserControlRequest{
		{Op: "files", ControllerID: controller},
		{Op: "drop", ControllerID: controller, Sequence: 1, X: &point, Y: &point},
		{Op: "setfiles", ControllerID: controller, Sequence: 2, DestinationID: destination, Files: []string{"/workspace/.ambit/artifacts/file.csv"}},
		{Op: "dismissfiles", ControllerID: controller, DestinationID: destination},
	}
	for _, request := range requests {
		if !validBrowserControlRequest(request) {
			t.Fatalf("valid %s refused", request.Op)
		}
		request.ControllerID = ""
		if validBrowserControlRequest(request) {
			t.Fatalf("%s lacks controller proof", request.Op)
		}
	}
	for _, path := range []string{"../file", "/workspace/../secret", "/workspace/file\x00suffix"} {
		if validBrowserControlRequest(browserControlRequest{Op: "setfiles", ControllerID: controller, Sequence: 1, DestinationID: destination, Files: []string{path}}) {
			t.Fatalf("invalid path accepted: %q", path)
		}
	}
	body, _ := json.Marshal(map[string]any{"chooser": nil, "downloads": []any{map[string]any{
		"id": destination, "guid": destination, "frameId": "frame", "suggestedFilename": "report.csv", "status": "completed", "receivedBytes": 12, "path": "/workspace/outputs/downloads/report.csv", "private": "must not escape",
	}}, "secret": "must not escape"})
	projected, ok := browserFileResponse(body, requests[0], "files")
	if !ok {
		t.Fatal("valid completed download refused")
	}
	encoded, _ := json.Marshal(projected)
	var result map[string]any
	_ = json.Unmarshal(encoded, &result)
	if _, exists := result["secret"]; exists {
		t.Fatal("unrelated native metadata escaped")
	}
	record := result["downloads"].([]any)[0].(map[string]any)
	if _, exists := record["private"]; exists {
		t.Fatal("unrelated download metadata escaped")
	}
	if _, ok := browserFileResponse(body, requests[0], "applied"); ok {
		t.Fatal("unrelated successful operation accepted as file observation")
	}
}
