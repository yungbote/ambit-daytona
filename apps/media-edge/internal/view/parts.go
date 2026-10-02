// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import "encoding/json"

type videoContinuation struct {
	Type     string  `json:"type"`
	Track    string  `json:"track"`
	StreamID string  `json:"streamId"`
	Seq      uint64  `json:"seq"`
	Offset   *uint64 `json:"offset"`
}

func videoPartOffset(header []byte) (uint64, bool) {
	var value map[string]json.RawMessage
	if json.Unmarshal(header, &value) != nil {
		return 0, false
	}
	raw, present := value["offset"]
	if !present {
		return 0, false
	}
	var offset uint64
	if json.Unmarshal(raw, &offset) != nil {
		return 0, true
	}
	return offset, true
}

// A start has the canonical logical descriptor. A continuation is closed
// and carries only identity and contiguous body offset.
func parseVideoPartHeader(header []byte) (videoHeader, uint64, bool) {
	var value videoHeader
	if len(header) > videoHeaderLimit {
		return value, 0, false
	}
	var part videoContinuation
	if json.Unmarshal(header, &part) != nil || part.Offset == nil || *part.Offset > safeInteger ||
		part.Type != "media" || part.Track != "video" || !validUUID(part.StreamID) || part.Seq == 0 || part.Seq > safeInteger {
		return value, 0, false
	}
	if *part.Offset == 0 {
		if json.Unmarshal(header, &value) != nil || !value.valid(int(value.ByteLength)) {
			return value, 0, false
		}
		return value, 0, true
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(header, &members) != nil || len(members) != 5 {
		return value, 0, false
	}
	for _, name := range []string{"type", "track", "streamId", "seq", "offset"} {
		if _, present := members[name]; !present {
			return value, 0, false
		}
	}
	return videoHeader{Type: part.Type, Track: part.Track, StreamID: part.StreamID, Seq: part.Seq, Offset: part.Offset}, *part.Offset, true
}

type sentVideoPart struct {
	offset uint64
	bytes  int
}

// Only metadata and unreceived boundary charges are retained here. The
// browser owns the sole full-body assembly; this hop retains one part.
type videoPartial struct {
	header           videoHeader
	offset, received uint64
	bytes            int
	parts            []sentVideoPart
}

func (c *Channel) videoPart(message []byte) (*Delivery, *Close) {
	header, payload, envelopeValid := envelope(message)
	value, offset, valid := parseVideoPartHeader(header)
	if !envelopeValid || !valid || len(payload) == 0 || len(message) > MaxVideoPartBytes || !c.declaration.VideoChunks || !c.video.offered {
		return nil, closeInvalidVideo
	}
	e := &c.video.epoch
	if !c.video.enabled || e.generation != c.video.generation || value.StreamID != e.id {
		return nil, nil
	}
	if offset == 0 {
		if c.partial != nil || value.Codec != c.videoCodec || value.Seq != e.sequence+1 ||
			e.sequence != e.acknowledged || *value.Ts < e.timestamp || (!value.Key && (e.sequence == 0 || value.Coded != e.coded)) {
			return nil, closeInvalidVideo
		}
		c.partial = &videoPartial{header: value}
	}
	p := c.partial
	if p == nil || p.header.StreamID != value.StreamID || p.header.Seq != value.Seq || offset != p.offset ||
		uint64(len(payload)) > uint64(p.header.ByteLength)-p.offset {
		return nil, closeInvalidVideo
	}
	var projected []byte
	if offset == 0 {
		projected, _ = json.Marshal(value)
	} else {
		projected, _ = json.Marshal(videoContinuation{"media", "video", value.StreamID, value.Seq, &offset})
	}
	delivery := &Delivery{Kind: Video, Header: projected, Payload: payload}
	if delivery.Size() > MaxVideoPartBytes || delivery.Size() > 2*MaxVideoPartBytes-p.bytes {
		return nil, closeInvalidVideo
	}
	p.offset += uint64(len(payload))
	p.bytes += delivery.Size()
	p.parts = append(p.parts, sentVideoPart{p.offset, delivery.Size()})
	delivery.Transfer = TransferIdentity{PictureIdentity{value.Seq, value.StreamID}, p.offset}
	if p.offset == uint64(p.header.ByteLength) {
		e.sequence, e.timestamp, e.coded = p.header.Seq, *p.header.Ts, p.header.Coded
		// Paint remains one logical event, emitted only at the final part.
		delivery.Paint = PictureIdentity{value.Seq, value.StreamID}
	}
	return delivery, nil
}

func (c *Channel) videoReceived(m viewerMessage) (*Forward, *Close) {
	if !c.declaration.VideoChunks || !c.video.offered {
		return nil, closeInvalidViewer
	}
	p := c.partial
	if p == nil || m.streamID != p.header.StreamID || m.seq != p.header.Seq {
		return nil, nil
	}
	if m.offset <= p.received {
		return nil, nil
	}
	for index, part := range p.parts {
		if part.offset != m.offset {
			continue
		}
		bytes := 0
		for _, received := range p.parts[:index+1] {
			bytes += received.bytes
		}
		p.bytes -= bytes
		p.parts = p.parts[:copy(p.parts, p.parts[index+1:])]
		p.received = m.offset
		return &Forward{Slot: SlotVideoReceived, Message: m.encode(), Transfer: TransferIdentity{PictureIdentity{m.seq, m.streamID}, m.offset}, Bytes: bytes}, nil
	}
	return nil, closeInvalidViewer
}
