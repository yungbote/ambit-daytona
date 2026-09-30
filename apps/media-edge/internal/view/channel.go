// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package view is the browser view channel's protocol at the edge: the one
// host hop that validates what the sandbox sends a person's browser and what
// the browser sends back. It composes the toolbox view route's projection
// (closed record and header shapes, bounds per kind, frame acceptance, the
// audio and video epochs) with the backend relay's rules (record bounds,
// negotiation, the viewer's closed messages). It does no I/O: a session feeds
// it messages and carries out what it answers.
package view

import (
	"encoding/json"
	"sync"
	"unicode/utf8"
)

// MaxRecordBytes bounds a record the page receives (the backend relay's and
// the page's own bound on metadata).
const MaxRecordBytes = 96 << 10

// Kind is what a delivery carries, for a carrier that maps kinds to its own
// streams.
type Kind uint8

const (
	// Record is a JSON text record.
	Record Kind = iota + 1
	// Frame is a JPEG frame or patch set in the binary envelope.
	Frame
	// Video is one encoded picture in the binary envelope.
	Video
	// Audio is one audio packet in the binary envelope.
	Audio
)

// Delivery is one message for the viewer. A record is Text; the binary kinds
// are the envelope's projected Header (without its length prefix) and the
// Payload, unchanged.
type Delivery struct {
	Kind    Kind
	Text    []byte
	Header  []byte
	Payload []byte
	// Paint identifies a picture measured on the edge's own send/ACK clock.
	Paint PictureIdentity
}

type PictureIdentity struct {
	Sequence uint64
	StreamID string
}

// Size is the delivery's size on the wire.
func (d *Delivery) Size() int {
	if d.Kind == Record {
		return len(d.Text)
	}
	return 4 + len(d.Header) + len(d.Payload)
}

// Close is how a channel ends: the close code and reason the viewer reads.
type Close struct {
	Code   int
	Reason string
}

// The closes this protocol decides, with the reasons the page reads today.
var (
	closeInvalidViewer = &Close{Code: 1008, Reason: "browser_view_invalid_message"}
	closeInvalidFrame  = &Close{Code: 1011, Reason: "browser_view_invalid_frame"}
	closeInvalidVideo  = &Close{Code: 1011, Reason: "browser_view_invalid_video"}
	closeInvalidAudio  = &Close{Code: 1011, Reason: "browser_view_invalid_audio"}
	closeUnsupported   = &Close{Code: 1003, Reason: "browser_view_channel_unsupported"}
	closeFailed        = &Close{Code: 1011, Reason: "screencast_failed"}
	closeEnded         = &Close{Code: 4410, Reason: "browser_view_ended"}
	closeUnavailable   = &Close{Code: 1011, Reason: "browser_view_unavailable"}
)

// Forward is a viewer message for the view route, in its coalescing slot.
type Forward struct {
	Slot       Slot
	Message    []byte
	Generation uint64
	Paint      PictureIdentity
}

// track is one output track's negotiation state and current epoch.
type track struct {
	offered    bool
	enabled    bool
	generation uint64
	epoch      epoch
}

// epoch is one subscription's stream: its sequence never skips, its clock
// never runs back, and a viewer acknowledges only what was sent.
type epoch struct {
	generation   uint64
	id           string
	sequence     uint64
	timestamp    uint64
	coded        videoSize
	acknowledged uint64
}

// Channel is one viewer's view channel. It is safe for one upstream reader
// and one viewer reader at a time.
type Channel struct {
	declaration Declaration
	mu          sync.Mutex
	frames      frames
	audio       track
	video       track
	// videoCodec is the codec the producer offered from the declaration.
	videoCodec string
}

// NewChannel starts a channel for what the viewer declared.
func NewChannel(declaration Declaration) *Channel {
	return &Channel{declaration: declaration, frames: frames{window: frameWindow{limit: declaration.FrameWindow}}}
}

// Upstream takes one message from the view route. It answers what to deliver
// to the viewer, if anything, and whether the channel ends after that.
// A delivered frame is counted against the window at once, so the viewer's
// acknowledgement of it is valid however soon it arrives.
func (c *Channel) Upstream(text bool, message []byte) (*Delivery, *Close) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !text {
		return c.binary(message)
	}
	return c.text(message)
}

func (c *Channel) binary(message []byte) (*Delivery, *Close) {
	if track, media := mediaTrack(message); media && track == "video" && len(c.declaration.Video) != 0 {
		return c.videoUnit(message)
	} else if media && c.declaration.Audio != "" {
		return c.audioPacket(message)
	}
	frame, err := parseBinaryFrame(message)
	if err != nil {
		if c.frames.previous.Seq == 0 && legacyBinaryFrame(message) {
			return nil, closeUnsupported
		}
		return nil, closeInvalidFrame
	}
	if !c.frames.accept(frame.header.frameHeader, frame.wireSize()) {
		return nil, closeInvalidFrame
	}
	return &Delivery{Kind: Frame, Header: frame.projected, Payload: frame.payload, Paint: PictureIdentity{Sequence: frame.header.Seq}}, nil
}

func (c *Channel) text(message []byte) (*Delivery, *Close) {
	var envelope struct {
		Type string `json:"type"`
	}
	if !utf8.Valid(message) || json.Unmarshal(message, &envelope) != nil {
		return nil, closeInvalidFrame
	}
	switch envelope.Type {
	case "audio":
		return c.audioRecord(message)
	case "video":
		return c.videoRecord(message)
	}
	projected, sequence, kind := projectRecord(message)
	switch kind {
	case recordDropped:
		if envelope.Type == "frame" {
			return nil, closeInvalidFrame
		}
		return nil, nil
	case recordFinished:
		return &Delivery{Kind: Record, Text: finishedRecord}, closeEnded
	case recordFailed:
		return &Delivery{Kind: Record, Text: unavailableRecord}, closeFailed
	}
	if sequence != 0 {
		// A JSON frame on a channel that negotiated binary frames: an older
		// driver's real image asks the viewer for its compatible reader.
		if c.frames.previous.Seq == 0 && textFrameHasJPEG(projected) {
			return nil, closeUnsupported
		}
		return nil, closeInvalidFrame
	}
	return record(projected)
}

// record delivers a record within the page's bound on metadata.
func record(text []byte) (*Delivery, *Close) {
	if len(text) > MaxRecordBytes {
		return nil, closeUnavailable
	}
	return &Delivery{Kind: Record, Text: text}, nil
}

func (c *Channel) audioRecord(message []byte) (*Delivery, *Close) {
	value, projected, valid := parseAudioMetadata(message)
	if !valid || c.declaration.Audio == "" || value.Codec != c.declaration.Audio {
		return nil, closeInvalidAudio
	}
	if value.State == "available" {
		c.audio.offered = true
	} else if *value.Generation != c.audio.generation {
		return nil, nil
	}
	switch value.State {
	case "started":
		if !c.audio.offered {
			return nil, closeInvalidAudio
		}
		if !c.audio.enabled {
			return nil, nil // A queued start raced the viewer's mute.
		}
		c.audio.epoch = epoch{id: value.StreamID, generation: *value.Generation}
	case "stopped", "unavailable":
		c.audio.epoch = epoch{}
	}
	return record(projected)
}

func (c *Channel) audioPacket(message []byte) (*Delivery, *Close) {
	value, projected, payload, valid := parseAudioPacket(message)
	if !valid || value.Codec != c.declaration.Audio {
		return nil, closeInvalidAudio
	}
	e := &c.audio.epoch
	if !c.audio.enabled || e.generation != c.audio.generation || value.StreamID != e.id {
		return nil, nil // Never queue sound after a mute, or of a retired stream.
	}
	if value.Seq != e.sequence+1 || *value.Ts < e.timestamp {
		return nil, closeInvalidAudio
	}
	e.sequence, e.timestamp = value.Seq, *value.Ts
	return &Delivery{Kind: Audio, Header: projected, Payload: payload}, nil
}

func (c *Channel) videoDeclared(codec string) bool {
	for _, declared := range c.declaration.Video {
		if declared == codec {
			return true
		}
	}
	return false
}

func (c *Channel) videoRecord(message []byte) (*Delivery, *Close) {
	value, projected, valid := parseVideoMetadata(message)
	if !valid || len(c.declaration.Video) == 0 || (value.Codec != "" && !c.videoDeclared(value.Codec)) {
		return nil, closeInvalidVideo
	}
	if value.State == "available" {
		if c.video.offered && c.videoCodec != value.Codec {
			return nil, closeInvalidVideo
		}
		c.videoCodec, c.video.offered = value.Codec, true
		return record(projected)
	}
	if *value.Generation != c.video.generation {
		return nil, nil
	}
	if value.State == "started" {
		if !c.video.offered || value.Codec != c.videoCodec {
			return nil, closeInvalidVideo
		}
		if !c.video.enabled {
			return nil, nil // A queued start raced the viewer's fallback.
		}
		c.video.epoch = epoch{id: value.StreamID, generation: *value.Generation}
	} else {
		c.video.epoch = epoch{}
	}
	return record(projected)
}

func (c *Channel) videoUnit(message []byte) (*Delivery, *Close) {
	value, projected, payload, valid := parseVideoUnit(message)
	if !valid || !c.video.offered || value.Codec != c.videoCodec {
		return nil, closeInvalidVideo
	}
	e := &c.video.epoch
	if !c.video.enabled || e.generation != c.video.generation || value.StreamID != e.id {
		return nil, nil
	}
	// A stream begins with a picture that needs no other, and so does every
	// change of the coded size. Pictures are never skipped or reordered.
	if value.Seq != e.sequence+1 || *value.Ts < e.timestamp || (!value.Key && (e.sequence == 0 || value.Coded != e.coded)) {
		return nil, closeInvalidVideo
	}
	if !c.declaration.VideoCapacity && len(payload) > 4<<20 {
		// Only an old peer's reader has this limit. Match the old producer's
		// track refusal once, preserving JPEG fallback, audio and control;
		// clearing the epoch drops any subsequent stale units until disable.
		message, _ := json.Marshal(videoMetadata{Type: "video", State: "unavailable", Codec: value.Codec, Generation: &c.video.generation})
		return c.videoRecord(message)
	}
	e.sequence, e.timestamp, e.coded = value.Seq, *value.Ts, value.Coded
	return &Delivery{Kind: Video, Header: projected, Payload: payload, Paint: PictureIdentity{Sequence: value.Seq, StreamID: value.StreamID}}, nil
}

// Viewer takes one message from the page. It answers the normalized message
// to forward to the view route, nothing (a stale or retired message), or the
// end of the channel for a message the page could never have sent honestly.
func (c *Channel) Viewer(text bool, message []byte) (*Forward, *Close) {
	m, valid := parseViewerMessage(message)
	if !text || !valid {
		return nil, closeInvalidViewer
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch m.kind {
	case viewerPresentation:
		if !c.declaration.Presents() {
			return nil, closeInvalidViewer // an observer has no presentation authority
		}
		return &Forward{Slot: SlotPresentation, Message: m.encode()}, nil
	case viewerAudio:
		if !c.audio.offered {
			return nil, closeInvalidViewer
		}
		if m.generation <= c.audio.generation {
			return nil, nil
		}
		c.audio.generation, c.audio.enabled = m.generation, m.enabled
		return &Forward{Slot: SlotAudio, Message: m.encode()}, nil
	case viewerVideo:
		if !c.video.offered {
			return nil, closeInvalidViewer
		}
		if m.generation <= c.video.generation {
			return nil, nil
		}
		c.video.generation, c.video.enabled = m.generation, m.enabled
		return &Forward{Slot: SlotVideo, Message: m.encode(), Generation: m.generation}, nil
	case viewerKeyframe:
		if !c.video.offered {
			return nil, closeInvalidViewer
		}
		if m.generation != c.video.generation || !c.video.enabled {
			return nil, nil // A request for a retired subscription has nothing to repair.
		}
		return &Forward{Slot: SlotKeyframe, Message: m.encode()}, nil
	case viewerVideoAck:
		if !c.video.offered {
			return nil, closeInvalidViewer
		}
		e := &c.video.epoch
		if m.streamID != e.id || m.seq <= e.acknowledged {
			return nil, nil
		}
		if m.seq > e.sequence {
			return nil, closeInvalidViewer // a picture never sent
		}
		e.acknowledged = m.seq
		return &Forward{Slot: SlotVideoAck, Message: m.encode(), Paint: PictureIdentity{Sequence: m.seq, StreamID: m.streamID}}, nil
	default: // viewerFrameAck
		forward, valid := c.frames.window.acknowledge(m.seq)
		if !valid {
			return nil, closeInvalidViewer
		}
		if !forward {
			return nil, nil
		}
		return &Forward{Slot: SlotFrameAck, Message: m.encode(), Paint: PictureIdentity{Sequence: m.seq}}, nil
	}
}

// Rate is host-authored feedback for the current enabled video generation.
// The viewer cannot create this message through Viewer; no second pacing
// authority is introduced on the client side.
func (c *Channel) Rate(generation, bitsPerSecond, burstBytes uint64) *Forward {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.video.offered || !c.video.enabled || generation == 0 || c.video.generation != generation || bitsPerSecond < 1000 || bitsPerSecond > 4294967295 || burstBytes < 1 || burstBytes > 12<<20 {
		return nil
	}
	value := struct {
		Type          string `json:"type"`
		Generation    uint64 `json:"generation"`
		BitsPerSecond uint64 `json:"bitsPerSecond"`
		BurstBytes    uint64 `json:"burstBytes"`
	}{"rate", generation, bitsPerSecond, burstBytes}
	message, _ := json.Marshal(value)
	return &Forward{Slot: SlotRate, Message: message, Generation: generation}
}

func (c *Channel) VideoGeneration() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.video.offered || !c.video.enabled {
		return 0
	}
	return c.video.generation
}
