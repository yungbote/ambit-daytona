// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/view"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
)

// The packet path is task-local UDP, not a host qdisc or a second product
// pacer. QUIC packets, ACKs, retransmissions and congestion control are real;
// only this bounded bottleneck's propagation, serialization and loss are
// emulated. The native-key test below characterizes a one-time key, not glass.
type packetLink struct {
	mu               sync.Mutex
	next             [2]time.Time
	bitrate          uint64
	delay            time.Duration
	queue            int
	loss             float64
	random           *rand.Rand
	packets, dropped [2]int
}

func (l *packetLink) drop(direction quicproxy.Direction, _, _ net.Addr, packet []byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.packets[direction]++
	if direction == quicproxy.DirectionOutgoing && (l.random.Float64() < l.loss || l.next[direction].Sub(time.Now()) > time.Duration(float64(l.queue*1200*8)/float64(l.bitrate)*float64(time.Second))) {
		l.dropped[direction]++
		return true
	}
	return false
}

func (l *packetLink) delayPacket(direction quicproxy.Direction, _, _ net.Addr, packet []byte) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	bitrate := l.bitrate
	if direction == quicproxy.DirectionIncoming {
		bitrate = 20_000_000
	}
	if now.After(l.next[direction]) {
		l.next[direction] = now
	}
	l.next[direction] = l.next[direction].Add(time.Duration(float64(len(packet)*8) / float64(bitrate) * float64(time.Second)))
	return l.next[direction].Sub(now) + l.delay
}

func (l *packetLink) path(t *testing.T, destination net.Addr) net.Addr {
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

func TestPacketLinkSerializesAKnownDatagramTrain(t *testing.T) {
	destination, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	link := &packetLink{bitrate: 1_000_000, delay: 10 * time.Millisecond, queue: 100, random: rand.New(rand.NewSource(7))}
	address := link.path(t, destination.LocalAddr())
	client, err := net.DialUDP("udp", nil, address.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	const count = 20
	go func() {
		packet := make([]byte, 1000)
		for n := 0; n < count; n++ {
			_, from, err := destination.ReadFromUDP(packet)
			if err != nil {
				return
			}
			_, _ = destination.WriteToUDP(packet, from)
		}
	}()
	started := time.Now()
	for n := 0; n < count; n++ {
		if _, err := client.Write(make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	for n := 0; n < count; n++ {
		if _, err := client.Read(make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(started)
	// 160ms downlink serialization +20ms propagation; startup/uplink
	// adds a small amount. This falsifies a delay-only or wrong-unit path.
	if elapsed < 175*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Fatalf("known20KB/1Mbit/s path took%s, want~180ms", elapsed)
	}
	t.Logf("known20x1000B train: %s, model floor180ms", elapsed)
}

func TestRecordedNativeKeyOnConstrainedQUICLink(t *testing.T) {
	path := os.Getenv("MEDIA_EDGE_NATIVE_KEY_FILE")
	if path == "" {
		t.Skip("MEDIA_EDGE_NATIVE_KEY_FILE raw native AV1 key required")
	}
	payload, err := os.ReadFile(path)
	if err != nil || len(payload) == 0 || len(payload) > 12<<20 {
		t.Fatalf("native key unavailable/invalid size: %v %dB", err, len(payload))
	}
	hash := sha256.Sum256(payload)
	for _, scenario := range []struct {
		name  string
		bits  uint64
		delay time.Duration
		loss  float64
		queue int
	}{
		{"s3", 5_000_000, 20 * time.Millisecond, .01, 60},
		{"s4", 3_000_000, 30 * time.Millisecond, .02, 40},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			link := &packetLink{bitrate: scenario.bits, delay: scenario.delay, loss: scenario.loss, queue: scenario.queue, random: rand.New(rand.NewSource(19))}
			clock := time.Now()
			started := make(chan time.Time, 1)
			var audio sync.WaitGroup
			s, control, ctx, _, _ := pairThrough(t, func(address net.Addr) net.Addr { return link.path(t, address) }, 50*time.Second, func(c *carrier) {
				started <- time.Now()
				if err := c.Send(&view.Delivery{Kind: view.Video, Header: []byte(`{"track":"video"}`), Payload: payload}); err != nil {
					t.Error(err)
					return
				}
				audio.Add(1)
				go func() {
					defer audio.Done()
					ticker := time.NewTicker(20 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-c.session.Context().Done():
							return
						case <-ticker.C:
							packet := make([]byte, 160)
							binary.BigEndian.PutUint64(packet, uint64(time.Since(clock)))
							if err := c.Send(&view.Delivery{Kind: view.Audio, Header: []byte(`{"track":"audio"}`), Payload: packet}); err != nil {
								return
							}
						}
					}
				}()
				for {
					_, message, err := c.Receive()
					if err != nil {
						return
					}
					if err := c.Send(&view.Delivery{Kind: view.Record, Text: message}); err != nil {
						return
					}
				}
			})
			defer func() { _ = s.CloseWithError(0, ""); audio.Wait() }()
			keyStart := <-started
			picture, err := s.AcceptUniStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			type completion struct {
				at  time.Time
				err error
			}
			keyDone := make(chan completion, 1)
			go func() {
				data, err := io.ReadAll(picture)
				if err == nil && !bytes.HasSuffix(data, payload) {
					err = fmt.Errorf("native key changed")
				}
				keyDone <- completion{time.Now(), err}
			}()
			var measurements sync.Mutex
			type sample struct {
				at  time.Time
				age time.Duration
			}
			var audioSamples []sample
			var inputRTT []time.Duration
			go func() {
				for {
					packet, err := s.ReceiveDatagram(ctx)
					if err != nil {
						return
					}
					if len(packet) < 12 {
						continue
					}
					offset := 12 + int(binary.BigEndian.Uint32(packet[8:12]))
					if offset+8 > len(packet) {
						continue
					}
					at := time.Duration(binary.BigEndian.Uint64(packet[offset:]))
					measurements.Lock()
					audioSamples = append(audioSamples, sample{time.Now(), time.Since(clock) - at})
					measurements.Unlock()
				}
			}()
			var finished completion
			for n := 0; n < 100 && finished.at.IsZero(); n++ {
				message := []byte(fmt.Sprintf(`{"probe":%d}`, n))
				var prefix [4]byte
				binary.BigEndian.PutUint32(prefix[:], uint32(len(message)))
				at := time.Now()
				if _, err := control.Write(append(prefix[:], message...)); err != nil {
					t.Fatal(err)
				}
				if got := record(t, control); got != string(message) {
					t.Fatal("input echo changed")
				}
				inputRTT = append(inputRTT, time.Since(at))
				select {
				case finished = <-keyDone:
				default:
				}
			}
			if finished.at.IsZero() {
				select {
				case finished = <-keyDone:
				case <-ctx.Done():
					t.Fatal("native key transport timeout")
				}
			}
			if finished.err != nil {
				t.Fatal(finished.err)
			}
			keyTime := finished.at.Sub(keyStart)
			measurements.Lock()
			defer measurements.Unlock()
			var audioAge []time.Duration
			for _, sample := range audioSamples {
				if !sample.at.After(finished.at) {
					audioAge = append(audioAge, sample.age)
				}
			}
			percentile := func(values []time.Duration, q float64) time.Duration {
				sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
				if len(values) == 0 {
					return 0
				}
				return values[int(float64(len(values)-1)*q)]
			}
			if len(audioAge) == 0 {
				t.Fatal("audio made no progress while key drained")
			}
			link.mu.Lock()
			defer link.mu.Unlock()
			t.Logf("native key SHA256=%x bytes=%d link=%dbit/s RTT=%s loss=%.0f%% queue=%dpackets key=%s serializationfloor=%s audioN=%d audioP95=%s inputN=%d inputP95=%s downPackets=%d dropped=%d; transport completion/echo, not decoded paint or native input", hash, len(payload), scenario.bits, 2*scenario.delay, scenario.loss*100, scenario.queue, keyTime, time.Duration(float64(len(payload)*8)/float64(scenario.bits)*float64(time.Second)), len(audioAge), percentile(audioAge, .95), len(inputRTT), percentile(inputRTT, .95), link.packets[1], link.dropped[1])
		})
	}
}
