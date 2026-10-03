// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/testlink"
	"github.com/daytonaio/media-edge/internal/view"
)

func TestPacketLinkSerializesAKnownDatagramTrain(t *testing.T) {
	destination, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	link := testlink.NewPacket(testlink.PacketConfig{Bits: 1_000_000, Delay: 10 * time.Millisecond, Queue: 100, Seed: 7})
	address := link.Path(t, destination.LocalAddr())
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
	recordedNativeKeyLinks(t, []keyLink{
		{name: "s3", bits: 5_000_000, delay: 20 * time.Millisecond, loss: .01, queue: 60},
		{name: "s4", bits: 3_000_000, delay: 30 * time.Millisecond, loss: .02, queue: 40},
	})
}

func TestRecordedNativeKeyOnSlowAndChangingQUICLink(t *testing.T) {
	recordedNativeKeyLinks(t, []keyLink{
		{name: "slow500k", bits: 500_000, delay: 20 * time.Millisecond, queue: 60},
		{name: "drop3MTo500k", bits: 3_000_000, delay: 20 * time.Millisecond, queue: 60, switchAfter: 128 << 10, nextBits: 500_000},
	})
}

func TestPacedPictureTrafficOnConstrainedQUICLink(t *testing.T) {
	// This isolates a paced350kbit/s picture source plus the same audio/input
	// traffic from the saturating first-key case. Opaque transport units are
	// synthetic; neither native AV1 decoding nor producer Flow is asserted.
	pictureLinks(t, bytes.Repeat([]byte{43}, 875), []keyLink{
		{name: "paced350kOn500k", bits: 500_000, delay: 20 * time.Millisecond, queue: 60, units: 300, period: 20 * time.Millisecond},
	})
}

type keyLink struct {
	name                  string
	bits                  uint64
	delay                 time.Duration
	loss                  float64
	queue                 int
	switchAfter, nextBits uint64
	units                 int
	period                time.Duration
}

func recordedNativeKeyLinks(t *testing.T, scenarios []keyLink) {
	t.Helper()
	path := os.Getenv("MEDIA_EDGE_NATIVE_KEY_FILE")
	if path == "" {
		t.Skip("MEDIA_EDGE_NATIVE_KEY_FILE raw native AV1 key required")
	}
	payload, err := os.ReadFile(path)
	if err != nil || len(payload) == 0 || len(payload) > 12<<20 {
		t.Fatalf("native key unavailable/invalid size: %v %dB", err, len(payload))
	}
	pictureLinks(t, payload, scenarios)
}

func pictureLinks(t *testing.T, payload []byte, scenarios []keyLink) {
	t.Helper()
	hash := sha256.Sum256(payload)
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			units := max(1, scenario.units)
			link := testlink.NewPacket(testlink.PacketConfig{Bits: scenario.bits, Delay: scenario.delay, Loss: scenario.loss, Queue: scenario.queue, Seed: 19, SwitchAfter: scenario.switchAfter, NextBits: scenario.nextBits})
			clock := time.Now()
			started := make(chan time.Time, 1)
			var audio sync.WaitGroup
			s, control, ctx, _, _ := pairThrough(t, func(address net.Addr) net.Addr { return link.Path(t, address) }, 90*time.Second, func(c *carrier) {
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
				if units > 1 {
					audio.Add(1)
					go func() {
						defer audio.Done()
						ticker := time.NewTicker(scenario.period)
						defer ticker.Stop()
						for n := 1; n < units; n++ {
							select {
							case <-c.session.Context().Done():
								return
							case <-ticker.C:
								if err := c.Send(&view.Delivery{Kind: view.Video, Header: []byte(`{"track":"video"}`), Payload: payload}); err != nil {
									return
								}
							}
						}
					}()
				}
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
				var err error
				for n := 0; n < units && err == nil; n++ {
					if n > 0 {
						picture, err = s.AcceptUniStream(ctx)
					}
					if err == nil {
						var data []byte
						data, err = io.ReadAll(picture)
						if err == nil && !bytes.HasSuffix(data, payload) {
							err = fmt.Errorf("picture transport bytes changed")
						}
					}
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
			for n := 0; n < 4096 && finished.at.IsZero(); n++ {
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
			stats := link.Stats()
			if scenario.nextBits > 0 && !stats.Switched {
				t.Fatal("bandwidth change did not occur")
			}
			t.Logf("final bitrate=%dbit/s switched=%v forwarded path bytes=%d", stats.Bits, stats.Switched, stats.Bytes)
			label := "native key"
			if units > 1 {
				label = "synthetic paced transport units"
			}
			t.Logf("%s SHA256=%x bytesPerUnit=%d units=%d period=%s link=%dbit/s RTT=%s loss=%.0f%% queue=%dpackets completion=%s serializationfloor=%s audioN=%d audioP95=%s inputN=%d inputP95=%s downPackets=%d dropped=%d; transport completion/echo, not decoded paint or native input", label, hash, len(payload), units, scenario.period, scenario.bits, 2*scenario.delay, scenario.loss*100, scenario.queue, keyTime, time.Duration(float64(len(payload)*units*8)/float64(scenario.bits)*float64(time.Second)), len(audioAge), percentile(audioAge, .95), len(inputRTT), percentile(inputRTT, .95), stats.Packets[1], stats.Dropped[1])
		})
	}
}
