// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package rate

import (
	"testing"
	"time"
)

func TestPaintUsesEdgeSendAndPrefixBytesNotProducerClock(t *testing.T) {
	now := time.Unix(100, 0)
	p := &PaintTracker{}
	p.Sent("video-a", 1, 1000, now)
	p.Sent("video-a", 2, 1000, now.Add(10*time.Millisecond))
	p.Acknowledge("video-a", 2, now.Add(50*time.Millisecond))
	sample := p.Snapshot()
	if sample.DeliveryBytesPerSecond != 40000 || sample.RTT != 40*time.Millisecond {
		t.Fatalf("paint units: %+v", sample)
	}
	p.Acknowledge("video-a", 2, now.Add(100*time.Millisecond))
	if p.Snapshot() != sample {
		t.Fatal("duplicate ACK changed measurement")
	}
	p.Acknowledge("video-a", 3, now.Add(100*time.Millisecond))
	if p.Snapshot() != sample {
		t.Fatal("unsent ACK changed measurement")
	}
}

func TestPaintHistoryIsBoundedAndRetiredStreamsDoNotMeasure(t *testing.T) {
	now := time.Unix(100, 0)
	p := &PaintTracker{}
	for n := uint64(1); n <= 10000; n++ {
		p.Sent("video-a", n, 10, now)
	}
	if len(p.pictures) != retainedPaintReceipts {
		t.Fatal("paint history grew beyond its bound")
	}
	p.Acknowledge("video-a", 1, now.Add(time.Second))
	if p.Snapshot().Known {
		t.Fatal("evicted receipt invented a RTT")
	}
	p.Acknowledge("video-a", 10000, now.Add(time.Second))
	if p.Snapshot().DeliveryBytesPerSecond != 100000 {
		t.Fatal("eviction lost acknowledged byte-prefix accounting")
	}
	p.Sent("video-b", 1, 20, now.Add(2*time.Second))
	p.Acknowledge("video-a", 10000, now.Add(3*time.Second))
	if p.Snapshot().Known {
		t.Fatal("retired stream affected current measurement")
	}
}
