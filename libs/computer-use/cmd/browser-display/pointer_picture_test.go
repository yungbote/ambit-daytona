// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"encoding/json"
	"testing"

	"github.com/robotn/xgb/xfixes"
)

func TestPicturePointerUsesOnlyThisReplyAndPreservesDeviceCoordinates(t *testing.T) {
	if picturePointer(nil) != nil {
		t.Fatal("missing observation invented a point")
	}
	for _, point := range [][2]int16{{0, 0}, {1535, 1999}, {-10, 32000}} {
		reply := &xfixes.GetCursorImageReply{X: point[0], Y: point[1], Xhot: 15, Yhot: 20}
		got := picturePointer(reply)
		if got.X != int(point[0]) || got.Y != int(point[1]) {
			t.Fatalf("pointer changed coordinate spaces: %+v", got)
		}
		encoded, err := json.Marshal(pictureFrame{Pointer: got})
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err := json.Unmarshal(encoded, &wire); err != nil {
			t.Fatal(err)
		}
		value := wire["pointer"].(map[string]any)
		if value["x"] != float64(point[0]) || value["y"] != float64(point[1]) {
			t.Fatalf("wire point %v", value)
		}
	}
	for _, value := range []any{pictureFrame{}, unchangedFrame{}, capturedFrame{}} {
		encoded, _ := json.Marshal(value)
		var wire map[string]any
		_ = json.Unmarshal(encoded, &wire)
		if _, exists := wire["pointer"]; exists {
			t.Fatalf("missing pointer/JPEG added wire field: %s", encoded)
		}
	}
}

func TestCursorIdentityNotificationRaceKeepsTheNextObjectDue(t *testing.T) {
	var tracker cursorTracker
	tracker.note(7, 1, 1, 0, 0, []uint32{0xffffffff})
	tracker.notify(8)
	if !tracker.imageNeeded() {
		t.Fatal("changed object was treated as stable")
	}
	// A query started for8 can answer9 while the observed notification is8;
	// the following capture still asks once to reconcile the actual object.
	tracker.note(9, 1, 1, 0, 0, []uint32{0xffffffff})
	if !tracker.imageNeeded() {
		t.Fatal("in-flight identity race swallowed the next refresh")
	}
	tracker.notify(9)
	if tracker.imageNeeded() {
		t.Fatal("settled identity keeps transferring its bitmap")
	}
	tracker.notify(7)
	if !tracker.imageNeeded() {
		t.Fatal("reentering an older actual cursor object was missed")
	}
}
