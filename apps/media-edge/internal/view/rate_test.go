// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"bytes"
	"net/url"
	"testing"
)

func TestRateIsHostAuthoredAndFollowsOnlyTheCurrentEnabledGeneration(t *testing.T) {
	d, _ := ParseDeclaration(url.Values{"frames": {"binary"}, "patches": {"1"}, "video": {"av1"}})
	c := NewChannel(d)
	if c.Rate(1, 4000000, 125000) != nil {
		t.Fatal("rate before video demand")
	}
	if _, closed := c.Upstream(true, []byte(`{"type":"video","state":"available","codec":"av1"}`)); closed != nil {
		t.Fatal(closed)
	}
	_, closed := c.Viewer(true, []byte(`{"type":"video","enabled":true,"generation":1}`))
	if closed != nil {
		t.Fatal(closed)
	}
	message := c.Rate(1, 4000000, 125000)
	if message == nil || message.Generation != 1 || !bytes.Equal(message.Message, []byte(`{"type":"rate","generation":1,"bitsPerSecond":4000000,"burstBytes":125000}`)) {
		t.Fatalf("rate: %+v", message)
	}
	if _, closed := c.Viewer(true, message.Message); closed == nil {
		t.Fatal("viewer gained a second rate authority")
	}
	_, _ = c.Viewer(true, []byte(`{"type":"video","enabled":false,"generation":2}`))
	if c.Rate(2, 4000000, 125000) != nil || c.VideoGeneration() != 0 {
		t.Fatal("retired subscription retained rate demand")
	}
	_, _ = c.Viewer(true, []byte(`{"type":"video","enabled":true,"generation":3}`))
	if c.Rate(1, 4000000, 125000) != nil || c.Rate(3, 4000000, 125000) == nil {
		t.Fatal("an estimate raced with a subscription and was retagged")
	}
}

func TestLatestRateCannotReenterAfterANewerSubscription(t *testing.T) {
	p := NewPending()
	p.Put(Forward{Slot: SlotVideo, Generation: 1, Message: []byte("video1")})
	p.Put(Forward{Slot: SlotRate, Generation: 1, Message: []byte("rate-old")})
	p.Put(Forward{Slot: SlotRate, Generation: 1, Message: []byte("rate-latest")})
	first, _ := p.Next()
	second, _ := p.Next()
	if string(first) != "video1" || string(second) != "rate-latest" {
		t.Fatal("rate was not coalesced behind its subscription")
	}
	p.Put(Forward{Slot: SlotVideo, Generation: 2, Message: []byte("video2")})
	p.Put(Forward{Slot: SlotRate, Generation: 1, Message: []byte("stale-race")})
	first, _ = p.Next()
	if string(first) != "video2" {
		t.Fatal("subscription was not first")
	}
	if _, ok := p.Next(); ok {
		t.Fatal("stale rate survived its generation fence")
	}
}
