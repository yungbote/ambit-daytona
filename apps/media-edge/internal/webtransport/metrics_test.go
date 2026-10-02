// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"context"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

func TestQUICMetricsMeasureAckedPacketsOnceAndReleaseSharedViewers(t *testing.T) {
	r := newMetricsRegistry()
	ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(12))
	tracer := r.tracer(ctx, logging.PerspectiveServer, quic.ConnectionID{})
	m, release1 := r.attach(ctx)
	_, release2 := r.attach(ctx)
	rtt := &logging.RTTStats{}
	rtt.UpdateRTT(20*time.Millisecond, 0)
	tracer.UpdatedMetrics(rtt, 10000, 9000, 8)
	tracer.SentShortHeaderPacket(&logging.ShortHeader{PacketNumber: 1}, 1200, 0, nil, nil)
	tracer.SentShortHeaderPacket(&logging.ShortHeader{PacketNumber: 2}, 1200, 0, nil, nil)
	tracer.AcknowledgedPacket(logging.Encryption1RTT, 1)
	tracer.AcknowledgedPacket(logging.Encryption1RTT, 1)
	tracer.LostPacket(logging.Encryption1RTT, 2, logging.PacketLossTimeThreshold)
	tracer.AcknowledgedPacket(logging.Encryption1RTT, 2)
	sample := m.snapshot(time.Now().Add(time.Second))
	if !sample.Known || sample.AckedBytes != 1200 || sample.MinimumRTT != 20*time.Millisecond || sample.Shares != 2 {
		t.Fatalf("QUIC sample: %+v", sample)
	}
	release1()
	release1()
	if m.snapshot(time.Now()).Shares != 1 {
		t.Fatal("viewer release was not idempotent")
	}
	release2()
	tracer.Close()
	if m.snapshot(time.Now()).Known || len(r.connections) != 0 {
		t.Fatal("closed connection retained measurements")
	}
}

func TestQUICObservationHistoryIsBoundedWithoutConstrainingTheConnection(t *testing.T) {
	r := newMetricsRegistry()
	ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(13))
	tracer := r.tracer(ctx, logging.PerspectiveServer, quic.ConnectionID{})
	m, _ := r.attach(ctx)
	for n := logging.PacketNumber(0); n < retainedPackets+100; n++ {
		tracer.SentShortHeaderPacket(&logging.ShortHeader{PacketNumber: n}, 1200, 0, nil, nil)
	}
	if len(m.packets) != retainedPackets {
		t.Fatalf("packet observations grew to %d", len(m.packets))
	}
	tracer.Close()
}

func TestQUICDemandUsesTheObservationIntervalInsteadOfTheLastACK(t *testing.T) {
	r := newMetricsRegistry()
	ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(14))
	tracer := r.tracer(ctx, logging.PerspectiveServer, quic.ConnectionID{})
	m, release := r.attach(ctx)
	defer release()
	defer tracer.Close()
	rtt := &logging.RTTStats{}
	rtt.UpdateRTT(20*time.Millisecond, 0)
	tracer.UpdatedMetrics(rtt, 10000, 9000, 8)
	tracer.UpdatedMetrics(rtt, 10000, 0, 0)
	at := m.at.Add(200 * time.Millisecond)
	if m.snapshot(at).ApplicationLimited {
		t.Fatal("a final ACK hid the saturated interval")
	}
	if !m.snapshot(at.Add(200 * time.Millisecond)).ApplicationLimited {
		t.Fatal("idle interval retained prior demand")
	}
}
