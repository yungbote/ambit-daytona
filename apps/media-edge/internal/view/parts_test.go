// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
)

func mustQuery(query string) url.Values {
	values, err := url.ParseQuery(query)
	if err != nil {
		panic(err)
	}
	return values
}

func chunkScript(t *testing.T) script {
	d := videoDeclaration()
	d.VideoCapacity, d.VideoChunks = true, true
	s := newScript(t, d)
	s.record(map[string]any{"type": "video", "state": "available", "codec": "av1"})
	s.forward(`{"type":"video","enabled":true,"generation":1}`, SlotVideo)
	s.record(map[string]any{"type": "video", "state": "started", "generation": 1, "codec": "av1", "codecString": "av01.0.12M.08", "streamId": videoEpoch})
	return s
}

func chunkAt(stream string, seq, offset, total, size int) []byte {
	var header map[string]any
	if offset == 0 {
		header = videoHeaderFixture(seq, true, total)
		header["streamId"] = stream
		header["offset"] = 0
	} else {
		header = map[string]any{"type": "media", "track": "video", "streamId": stream, "seq": seq, "offset": offset}
	}
	return pack(header, make([]byte, size))
}

func receipt(stream string, seq, offset int) string {
	return fmt.Sprintf(`{"type":"received","track":"video","streamId":%q,"seq":%d,"offset":%d}`, stream, seq, offset)
}

func TestChunksCompleteOnlyAtExactTotalAndPaintAdmitsSuccessor(t *testing.T) {
	s := chunkScript(t)
	first, end := s.c.Upstream(false, chunkAt(videoEpoch, 1, 0, 128, 64))
	if end != nil || first == nil || first.Paint.Sequence != 0 || first.Transfer.Offset != 64 || s.c.video.epoch.sequence != 0 {
		t.Fatal("partial picture became paintable")
	}
	// Receipt before any local write callback is valid: admission reserves it.
	f, end := s.c.Viewer(true, []byte(receipt(videoEpoch, 1, 64)))
	if end != nil || f == nil || f.Bytes != first.Size() || s.c.partial.bytes != 0 || len(s.c.partial.parts) != 0 {
		t.Fatal("early exact prefix did not prune/debit")
	}
	last, end := s.c.Upstream(false, chunkAt(videoEpoch, 1, 64, 128, 64))
	if end != nil || last == nil || last.Paint.Sequence != 1 || s.c.video.epoch.sequence != 1 {
		t.Fatal("complete picture was not admitted")
	}
	s.forward(receipt(videoEpoch, 1, 128), SlotVideoReceived)
	s.end(false, chunkAt(videoEpoch, 2, 0, 128, 64), 1011, "browser_view_invalid_video")
	s.forward(`{"type":"ack","track":"video","streamId":"`+videoEpoch+`","seq":1}`, SlotVideoAck)
	if s.c.partial != nil {
		t.Fatal("paint retained partial state")
	}
	s.deliver(false, chunkAt(videoEpoch, 2, 0, 128, 64))
}

func TestChunkBoundariesRejectGapsOverlapForgeryAndWrongTotal(t *testing.T) {
	for name, candidate := range map[string][]byte{
		"gap": chunkAt(videoEpoch, 1, 65, 128, 64), "overlap": chunkAt(videoEpoch, 1, 63, 128, 64),
		"sequence": chunkAt(videoEpoch, 2, 64, 128, 64), "beyond total": chunkAt(videoEpoch, 1, 64, 128, 65),
		"empty": chunkAt(videoEpoch, 1, 64, 128, 0), "duplicate start": chunkAt(videoEpoch, 1, 0, 128, 64),
	} {
		t.Run(name, func(t *testing.T) {
			s := chunkScript(t)
			s.deliver(false, chunkAt(videoEpoch, 1, 0, 128, 64))
			s.end(false, candidate, 1011, "browser_view_invalid_video")
		})
	}
	for _, offset := range []int{1, 63, 65, 128, 129} {
		s := chunkScript(t)
		s.deliver(false, chunkAt(videoEpoch, 1, 0, 128, 64))
		if f, end := s.c.Viewer(true, []byte(receipt(videoEpoch, 1, offset))); f != nil || end == nil {
			t.Fatalf("unissued prefix%d gained credit", offset)
		}
	}
	s := chunkScript(t)
	s.deliver(false, chunkAt(videoEpoch, 1, 0, 128, 64))
	if _, end := s.c.Viewer(true, []byte(`{"type":"ack","track":"video","streamId":"`+videoEpoch+`","seq":1}`)); end == nil {
		t.Fatal("partial paint gained credit")
	}
}

func TestChunkRetirementDropsOldPrefixesAndAllowsNewKey(t *testing.T) {
	s := chunkScript(t)
	s.deliver(false, chunkAt(videoEpoch, 1, 0, 128, 64))
	s.forward(`{"type":"video","enabled":true,"generation":2}`, SlotVideo)
	if s.c.partial != nil {
		t.Fatal("new demand retained old partial")
	}
	s.drop(false, chunkAt(videoEpoch, 1, 64, 128, 64))
	s.ignore(receipt(videoEpoch, 1, 64))
	s.record(map[string]any{"type": "video", "state": "started", "generation": 2, "codec": "av1", "codecString": "av01.0.12M.08", "streamId": videoNextEpoch})
	s.deliver(false, chunkAt(videoNextEpoch, 1, 0, 64, 64))
	s.drop(false, chunkAt(videoEpoch, 1, 64, 128, 64))
	s.ignore(receipt(videoEpoch, 1, 64))
	s.forward(receipt(videoNextEpoch, 1, 64), SlotVideoReceived)
}

func TestChunkNegotiationAndResourceBounds(t *testing.T) {
	base := "frames=binary&patches=1&video=av1&videoCapacity=coded"
	for _, query := range []string{base + "&videoFraming=chunks", base} {
		declaration, err := ParseDeclaration(mustQuery(query))
		if err != nil {
			t.Fatal(err)
		}
		if declaration.VideoChunks != (query != base) {
			t.Fatal("framing inferred from capacity")
		}
		if _, err := ParseDeclaration(mustQuery(declaration.Query())); err != nil {
			t.Fatal(err)
		}
	}
	for _, query := range []string{base + "&videoFraming=chunks&videoFraming=chunks", base + "&videoFraming=", "frames=binary&patches=1&video=av1&videoFraming=chunks"} {
		if _, err := ParseDeclaration(mustQuery(query)); err == nil {
			t.Fatal("invalid framing accepted")
		}
	}
	s := chunkScript(t)
	message := chunkAt(videoEpoch, 1, 0, 21734926, 64)
	var h map[string]any
	header, _, _ := envelope(message)
	_ = json.Unmarshal(header, &h)
	h["coded"] = map[string]any{"width": 4096, "height": 4096}
	message = pack(h, make([]byte, 64))
	limit, valid := BinaryPayloadLimit(jsonOf(h))
	if !valid || limit > MaxVideoPartBytes || limit < 1 {
		t.Fatal("part buffered at logical total")
	}
	s.deliver(false, message)
	// No full body is stored: even a stalled sender can only retain two
	// physical part quanta's worth of boundary charges.
	for offset := 64; ; offset += 15000 {
		d, end := s.c.Upstream(false, chunkAt(videoEpoch, 1, offset, 21734926, 15000))
		if end != nil {
			break
		}
		if d == nil || s.c.partial.bytes > 2*MaxVideoPartBytes {
			t.Fatal("unbounded outstanding ledger")
		}
	}
}
