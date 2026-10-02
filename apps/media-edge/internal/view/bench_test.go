// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"bytes"
	"image"
	"image/jpeg"
	"math/rand"
	"testing"
)

// The edge's own cost per unit: validating and projecting what the view route
// sends, before the carrier writes it. The relay ladder (e1/cost) measures
// the same through the network stack.

func noiseFrame(b *testing.B, side int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, side, side))
	rand.New(rand.NewSource(1)).Read(img.Pix)
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, img, &jpeg.Options{Quality: 75}); err != nil {
		b.Fatal(err)
	}
	surface := fixtureSurface()
	surface["width"], surface["height"] = side, side
	delete(surface, "private")
	return pack(map[string]any{"type": "frame", "seq": 1, "encoding": "jpeg", "surface": surface, "ts": 912345678, "byteLength": encoded.Len()}, encoded.Bytes())
}

func BenchmarkUpstreamJPEGFrame200K(b *testing.B) {
	message := noiseFrame(b, 336)
	b.SetBytes(int64(len(message)))
	c := NewChannel(Declaration{Width: 320, Height: 240, FrameWindow: 8})
	b.ReportAllocs()
	b.ResetTimer()
	for seq := 1; seq <= b.N; seq++ {
		c.frames = frames{window: frameWindow{limit: 8}}
		if d, end := c.Upstream(false, message); d == nil || end != nil {
			b.Fatalf("%v %v", d, end)
		}
	}
}

func BenchmarkUpstreamVideoUnit8K(b *testing.B) {
	c := NewChannel(Declaration{Width: 320, Height: 240, FrameWindow: 8, Video: []string{"av1"}})
	c.Upstream(true, []byte(`{"type":"video","state":"available","codec":"av1"}`))
	c.Viewer(true, []byte(`{"type":"video","enabled":true,"generation":1}`))
	c.Upstream(true, []byte(`{"type":"video","state":"started","generation":1,"codec":"av1","codecString":"av01.0.12M.08","streamId":"`+videoEpoch+`"}`))
	payload := make([]byte, 8<<10)
	units := make([][]byte, 0, 1024)
	for seq := 1; seq <= 1024; seq++ {
		header := videoHeaderFixture(seq, seq == 1, len(payload))
		delete(header, "private")
		delete(header["surface"].(map[string]any), "private")
		units = append(units, pack(header, payload))
	}
	b.SetBytes(int64(len(units[1])))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % 1024
		if index == 0 {
			c.video.epoch = epoch{id: videoEpoch, generation: 1}
		}
		if d, end := c.Upstream(false, units[index]); d == nil || end != nil {
			b.Fatalf("%v %v", d, end)
		}
	}
}
