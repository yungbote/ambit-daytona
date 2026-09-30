// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"net/url"
	"testing"
)

// Uses only the pre-chunk public API, so the same test exercises the old
// whole-unit implementation and fails at its actual first-key boundary.
func TestAReceivedPrefixCanAdvanceFirstKeyWithoutPaint(t *testing.T) {
	d, err := ParseDeclaration(url.Values{"frames": {"binary"}, "patches": {"1"}, "video": {"av1"}, "videoCapacity": {"coded"}, "videoFraming": {"chunks"}})
	if err != nil {
		t.Fatal(err)
	}
	c := NewChannel(d)
	if _, end := c.Upstream(true, []byte(`{"type":"video","state":"available","codec":"av1"}`)); end != nil {
		t.Fatal(end)
	}
	if _, end := c.Viewer(true, []byte(`{"type":"video","enabled":true,"generation":1}`)); end != nil {
		t.Fatal(end)
	}
	if _, end := c.Upstream(true, []byte(`{"type":"video","state":"started","codec":"av1","codecString":"av01.0.12M.08","generation":1,"streamId":"`+videoEpoch+`"}`)); end != nil {
		t.Fatal(end)
	}
	header := videoHeaderFixture(1, true, 128)
	header["offset"] = 0
	if part, end := c.Upstream(false, pack(header, make([]byte, 64))); end != nil || part == nil {
		t.Fatalf("first logical picture could not advance a bounded prefix: delivery%v close%v", part, end)
	}
	if prefix, end := c.Viewer(true, []byte(`{"type":"received","track":"video","streamId":"`+videoEpoch+`","seq":1,"offset":64}`)); end != nil || prefix == nil {
		t.Fatalf("received bytes needed a paint ACK: prefix%v close%v", prefix, end)
	}
	continuation := map[string]any{"type": "media", "track": "video", "streamId": videoEpoch, "seq": 1, "offset": 64}
	if part, end := c.Upstream(false, pack(continuation, make([]byte, 64))); end != nil || part == nil {
		t.Fatalf("first key deadlocked before complete assembly: delivery%v close%v", part, end)
	}
}
