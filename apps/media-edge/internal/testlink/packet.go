// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package testlink contains the calibrated task-only UDP bottleneck used by
// transport tests. Production handlers do not import it.
package testlink

import (
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
)

type PacketConfig struct {
	Bits, SwitchAfter, NextBits uint64
	Delay                       time.Duration
	Queue                       int
	Loss                        float64
	Seed                        int64
}

type PacketStats struct {
	Bits, Bytes      uint64
	Switched         bool
	Packets, Dropped [2]int
}

type PacketLink struct {
	mu     sync.Mutex
	config PacketConfig
	stats  PacketStats
	next   [2]time.Time
	random *rand.Rand
}

func NewPacket(config PacketConfig) *PacketLink {
	return &PacketLink{config: config, stats: PacketStats{Bits: config.Bits}, random: rand.New(rand.NewSource(config.Seed))}
}

func (l *PacketLink) SetBits(bits uint64) {
	l.mu.Lock()
	l.stats.Bits = bits
	l.mu.Unlock()
}

func (l *PacketLink) Stats() PacketStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stats
}

func (l *PacketLink) drop(direction quicproxy.Direction, _, _ net.Addr, packet []byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stats.Packets[direction]++
	if direction == quicproxy.DirectionOutgoing && (l.random.Float64() < l.config.Loss || l.next[direction].Sub(time.Now()) > time.Duration(float64(l.config.Queue*1200*8)/float64(l.stats.Bits)*float64(time.Second))) {
		l.stats.Dropped[direction]++
		return true
	}
	return false
}

func (l *PacketLink) delayPacket(direction quicproxy.Direction, _, _ net.Addr, packet []byte) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if direction == quicproxy.DirectionOutgoing {
		l.stats.Bytes += uint64(len(packet))
		if !l.stats.Switched && l.config.NextBits > 0 && l.stats.Bytes >= l.config.SwitchAfter {
			l.stats.Bits, l.stats.Switched = l.config.NextBits, true
		}
	}
	bits := l.stats.Bits
	if direction == quicproxy.DirectionIncoming {
		bits = 20_000_000
	}
	if now.After(l.next[direction]) {
		l.next[direction] = now
	}
	l.next[direction] = l.next[direction].Add(time.Duration(float64(len(packet)*8) / float64(bits) * float64(time.Second)))
	return l.next[direction].Sub(now) + l.config.Delay
}

func (l *PacketLink) Path(t *testing.T, destination net.Addr) net.Addr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	proxy := &quicproxy.Proxy{Conn: conn, ServerAddr: destination.(*net.UDPAddr), DropPacket: l.drop, DelayPacket: l.delayPacket}
	if err := proxy.Start(); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close(); _ = conn.Close() })
	return proxy.LocalAddr()
}
