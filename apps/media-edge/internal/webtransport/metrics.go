// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"context"
	"sync"
	"time"

	"github.com/daytonaio/media-edge/internal/rate"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

const retainedPackets = 16384

// One QUIC connection can carry several WT sessions. Its transport budget is
// divided among attached viewers rather than granted in full to each one.
type connectionMetrics struct {
	mu             sync.Mutex
	packets        map[logging.PacketNumber]uint64
	acked          uint64
	rtt, minimum   time.Duration
	window, flight uint64
	views          uint64
	closed         bool
	at             time.Time
	previous       uint64
	delivery       float64
	loaded         bool
	limited        bool
}

type metricsRegistry struct {
	mu          sync.Mutex
	connections map[quic.ConnectionTracingID]*connectionMetrics
}

func newMetricsRegistry() *metricsRegistry {
	return &metricsRegistry{connections: map[quic.ConnectionTracingID]*connectionMetrics{}}
}

func (r *metricsRegistry) tracer(ctx context.Context, _ logging.Perspective, _ quic.ConnectionID) *logging.ConnectionTracer {
	id, ok := ctx.Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
	if !ok {
		return nil
	}
	m := &connectionMetrics{packets: map[logging.PacketNumber]uint64{}, at: time.Now()}
	r.mu.Lock()
	r.connections[id] = m
	r.mu.Unlock()
	return &logging.ConnectionTracer{
		SentShortHeaderPacket: func(header *logging.ShortHeader, size logging.ByteCount, _ logging.ECN, _ *logging.AckFrame, _ []logging.Frame) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if len(m.packets) >= retainedPackets {
				// This observer never constrains the connection. Missing an old
				// sample under extreme pressure underestimates useful delivery.
				for number := range m.packets {
					delete(m.packets, number)
					break
				}
			}
			if size > 0 {
				m.packets[header.PacketNumber] = uint64(size)
			}
		},
		AcknowledgedPacket: func(level logging.EncryptionLevel, number logging.PacketNumber) {
			if level != logging.Encryption1RTT {
				return
			}
			m.mu.Lock()
			m.acked += m.packets[number]
			delete(m.packets, number)
			m.mu.Unlock()
		},
		LostPacket: func(level logging.EncryptionLevel, number logging.PacketNumber, _ logging.PacketLossReason) {
			if level != logging.Encryption1RTT {
				return
			}
			m.mu.Lock()
			delete(m.packets, number)
			m.mu.Unlock()
		},
		UpdatedMetrics: func(rtt *logging.RTTStats, window, flight logging.ByteCount, _ int) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.rtt, m.minimum = rtt.SmoothedRTT(), rtt.MinRTT()
			if window > 0 {
				m.window = uint64(window)
			}
			if flight >= 0 {
				m.flight = uint64(flight)
			}
			m.loaded = m.loaded || (window > 0 && flight >= window/2)
		},
		Close: func() {
			m.mu.Lock()
			m.closed = true
			m.packets = nil
			m.mu.Unlock()
			r.mu.Lock()
			delete(r.connections, id)
			r.mu.Unlock()
		},
	}
}

func (r *metricsRegistry) attach(ctx context.Context) (*connectionMetrics, func()) {
	id, ok := ctx.Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
	if !ok {
		return nil, func() {}
	}
	r.mu.Lock()
	m := r.connections[id]
	r.mu.Unlock()
	if m == nil {
		return nil, func() {}
	}
	m.mu.Lock()
	m.views++
	m.mu.Unlock()
	var once sync.Once
	return m, func() {
		once.Do(func() {
			m.mu.Lock()
			if m.views > 0 {
				m.views--
			}
			m.mu.Unlock()
		})
	}
}

func (m *connectionMetrics) snapshot(now time.Time) rate.Network {
	if m == nil {
		return rate.Network{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return rate.Network{}
	}
	if elapsed := now.Sub(m.at); elapsed >= 100*time.Millisecond {
		sample := float64(m.acked-m.previous) / elapsed.Seconds()
		if m.delivery == 0 {
			m.delivery = sample
		} else {
			m.delivery = m.delivery*0.8 + sample*0.2
		}
		m.at, m.previous = now, m.acked
		m.limited, m.loaded = !m.loaded, false
	}
	return rate.Network{Known: m.minimum > 0, AckedBytes: m.acked, DeliveryBytesPerSecond: m.delivery, RTT: m.rtt, MinimumRTT: m.minimum, WindowBytes: m.window, InFlightBytes: m.flight, ApplicationLimited: m.limited, ObservedAt: m.at, Shares: m.views}
}
