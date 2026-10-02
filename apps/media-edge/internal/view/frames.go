// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image/jpeg"
	"unicode/utf8"
)

// The envelope and the frame projection are the toolbox's view route's
// (apps/daemon/pkg/toolbox/process/session: browser_frames_linux.go,
// browser_window_linux.go), ported unchanged so that the edge projects exactly
// what the toolbox projects: its own output passes through byte for byte, and
// a driver's raw output comes out as the toolbox would have shaped it.

const (
	// MaxMessageBytes is the largest supported logical video envelope, not
	// a retained buffer or a queue allowance. Per-unit geometry narrows it.
	MaxMessageBytes = MaxVideoPayloadBytes + 4 + videoHeaderLimit
	// MaxLegacyMessageBytes is the retained peer/JPEG reader's envelope.
	MaxLegacyMessageBytes = 12 << 20
	// Keep the existing JPEG frame/resource contract separate from video.
	maxFrameMessageBytes = MaxLegacyMessageBytes
	// maxFrameHeaderBytes bounds a binary message's header of any kind.
	maxFrameHeaderBytes = 64 << 10
)

// safeInteger is the largest integer a JavaScript viewer reads exactly.
const safeInteger = 1<<53 - 1

// surface is the browser's display raster. Only these finite fields cross the
// relay; native XIDs and helper paths do not belong in a viewer's contract.
type surface struct {
	Kind              string `json:"kind"`
	CoordinateSpace   string `json:"coordinateSpace"`
	Generation        string `json:"generation"`
	Width             uint32 `json:"width"`
	Height            uint32 `json:"height"`
	OriginX           int32  `json:"originX"`
	OriginY           int32  `json:"originY"`
	DeviceScaleFactor uint32 `json:"deviceScaleFactor"`
	CursorIncluded    *bool  `json:"cursorIncluded"`
}

func (s *surface) valid() bool {
	return s != nil && s.Kind == "browser-window" && s.CoordinateSpace == "display-pixels" &&
		validUUID(s.Generation) &&
		s.Width > 0 && s.Width <= 4096 && s.Height > 0 && s.Height <= 4096 &&
		s.OriginX == 0 && s.OriginY == 0 && s.DeviceScaleFactor == 2 && s.CursorIncluded != nil
}

// patchBounds is a region and its crop; it means the same in JSON and binary frames.
type patchBounds struct {
	SourceX uint32 `json:"sourceX"`
	SourceY uint32 `json:"sourceY"`
	X       uint32 `json:"x"`
	Y       uint32 `json:"y"`
	Width   uint32 `json:"width"`
	Height  uint32 `json:"height"`
}

func (p patchBounds) valid(s surface) bool {
	return p.SourceX <= 16 && p.SourceY <= 16 && p.X < s.Width && p.Y < s.Height &&
		p.X%16 == 0 && p.Y%16 == 0 && p.Width > 0 && p.Height > 0 &&
		p.Width <= 512 && p.Height <= 512 &&
		p.Width <= s.Width-p.X && p.Height <= s.Height-p.Y &&
		(p.Width%16 == 0 || p.X+p.Width == s.Width) &&
		(p.Height%16 == 0 || p.Y+p.Height == s.Height)
}

// textPatch is a JSON frame's patch, only ever recognized to refuse it.
type textPatch struct {
	patchBounds
	Data string `json:"data"`
}

func (p textPatch) valid(s surface) bool {
	return p.Data != "" && p.patchBounds.valid(s)
}

type visibleRect struct {
	X      uint32 `json:"x"`
	Y      uint32 `json:"y"`
	Width  uint32 `json:"width"`
	Height uint32 `json:"height"`
}

// frameClock places a frame in time and causality: ts is the sandbox's
// monotonic clock at capture in microseconds, inputSeq the last control input
// applied before the capture, visible the window's rectangle in the raster.
type frameClock struct {
	Ts       uint64       `json:"ts,omitempty"`
	InputSeq uint64       `json:"inputSeq,omitempty"`
	Visible  *visibleRect `json:"visible,omitempty"`
}

func (c frameClock) valid(s surface) bool {
	v := c.Visible
	return c.Ts <= safeInteger && c.InputSeq <= safeInteger &&
		(v == nil || (v.Width > 0 && v.Height > 0 && v.X < s.Width && v.Y < s.Height &&
			v.Width <= s.Width-v.X && v.Height <= s.Height-v.Y))
}

type frameHeader struct {
	Type     string  `json:"type"`
	Seq      uint64  `json:"seq"`
	BaseSeq  uint64  `json:"baseSeq,omitempty"`
	Encoding string  `json:"encoding"`
	Surface  surface `json:"surface"`
	frameClock
}

type binaryPatch struct {
	patchBounds
	ByteLength uint32 `json:"byteLength"`
}

type binaryHeader struct {
	frameHeader
	ByteLength uint32        `json:"byteLength,omitempty"`
	Patches    []binaryPatch `json:"patches,omitempty"`
}

// binaryFrame keeps its JPEG slices in the read buffer; only the small header
// is projected, and pixels are neither copied nor re-encoded.
type binaryFrame struct {
	header    binaryHeader
	payload   []byte
	projected []byte
}

var errBinaryFrame = errors.New("invalid binary browser frame")

// envelope splits a binary message: a four-byte big-endian header length, a
// UTF-8 JSON header, and the payload.
func envelope(message []byte) (header, payload []byte, valid bool) {
	if len(message) < 4 || len(message) > MaxMessageBytes {
		return nil, nil, false
	}
	length := binary.BigEndian.Uint32(message[:4])
	if length == 0 || length > maxFrameHeaderBytes || int(length) > len(message)-4 {
		return nil, nil, false
	}
	header = message[4 : 4+int(length)]
	return header, message[4+int(length):], utf8.Valid(header)
}

// mediaTrack names the track of a media unit ("type":"media"); media is false
// for anything else, which is then read as a frame.
func mediaTrack(message []byte) (track string, media bool) {
	header, _, valid := envelope(message)
	var value struct {
		Type  string `json:"type"`
		Track string `json:"track"`
	}
	if !valid || json.Unmarshal(header, &value) != nil || value.Type != "media" {
		return "", false
	}
	return value.Track, true
}

func parseBinaryFrame(message []byte) (binaryFrame, error) {
	var frame binaryFrame
	if len(message) > maxFrameMessageBytes {
		return frame, errBinaryFrame
	}
	header, payload, valid := envelope(message)
	if !valid || json.Unmarshal(header, &frame.header) != nil {
		return frame, errBinaryFrame
	}
	h := &frame.header
	if h.Type != "frame" || h.Seq == 0 || h.Encoding != "jpeg" || !h.Surface.valid() || !h.frameClock.valid(h.Surface) {
		return frame, errBinaryFrame
	}
	frame.payload = payload
	remaining := frame.payload
	if h.Patches == nil {
		if h.BaseSeq != 0 || h.ByteLength == 0 || uint64(h.ByteLength) != uint64(len(remaining)) {
			return frame, errBinaryFrame
		}
		config, err := jpeg.DecodeConfig(bytes.NewReader(remaining))
		if err != nil || config.Width != int(h.Surface.Width) || config.Height != int(h.Surface.Height) {
			return frame, errBinaryFrame
		}
		return frame.project()
	}
	if h.ByteLength != 0 || h.BaseSeq == 0 || h.BaseSeq >= h.Seq || len(h.Patches) == 0 || len(h.Patches) > 64 {
		return frame, errBinaryFrame
	}
	for _, patch := range h.Patches {
		if !patch.patchBounds.valid(h.Surface) || patch.ByteLength == 0 || uint64(patch.ByteLength) > uint64(len(remaining)) {
			return frame, errBinaryFrame
		}
		image := remaining[:int(patch.ByteLength)]
		remaining = remaining[int(patch.ByteLength):]
		config, err := jpeg.DecodeConfig(bytes.NewReader(image))
		if err != nil || config.Width > int(patch.Width)+32 || config.Height > int(patch.Height)+32 ||
			config.Width < int(patch.SourceX+patch.Width) || config.Height < int(patch.SourceY+patch.Height) {
			return frame, errBinaryFrame
		}
	}
	if len(remaining) != 0 {
		return frame, errBinaryFrame
	}
	return frame.project()
}

func (f binaryFrame) project() (binaryFrame, error) {
	var err error
	f.projected, err = json.Marshal(f.header)
	if err != nil || len(f.projected) > maxFrameHeaderBytes || f.wireSize() > maxFrameMessageBytes {
		return f, errBinaryFrame
	}
	return f, nil
}

func (f binaryFrame) wireSize() int { return 4 + len(f.projected) + len(f.payload) }

// legacyBinaryFrame recognizes an older page stream's whole-image binary
// frame, only so that the viewer is told to use its compatible reader.
func legacyBinaryFrame(message []byte) bool {
	header, payload, valid := envelope(message)
	if !valid {
		return false
	}
	var frame struct {
		Type       string                     `json:"type"`
		Seq        uint64                     `json:"seq"`
		BaseSeq    uint64                     `json:"baseSeq"`
		Encoding   string                     `json:"encoding"`
		ByteLength uint32                     `json:"byteLength"`
		Surface    json.RawMessage            `json:"surface"`
		Metadata   map[string]json.RawMessage `json:"metadata"`
		Patches    json.RawMessage            `json:"patches"`
	}
	if json.Unmarshal(header, &frame) != nil || frame.Type != "frame" || frame.Seq == 0 || frame.BaseSeq != 0 || frame.Encoding != "jpeg" ||
		frame.Surface != nil || frame.Metadata == nil || frame.Patches != nil || frame.ByteLength == 0 || uint64(frame.ByteLength) != uint64(len(payload)) ||
		len(payload) < 4 || payload[len(payload)-2] != 0xff || payload[len(payload)-1] != 0xd9 {
		return false
	}
	_, err := jpeg.DecodeConfig(bytes.NewReader(payload))
	return err == nil
}

// textFrameHasJPEG recognizes an older driver's JSON frame with a real image,
// only before the first native frame, so the viewer falls back.
func textFrameHasJPEG(message []byte) bool {
	var frame struct {
		Data string `json:"data"`
	}
	if json.Unmarshal(message, &frame) != nil || frame.Data == "" {
		return false
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(frame.Data)
	if err != nil {
		return false
	}
	_, err = jpeg.DecodeConfig(bytes.NewReader(payload))
	return err == nil
}
