// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"image/jpeg"
	"unicode/utf8"
)

const (
	// The largest message the driver may send a viewer: one picture, a unit
	// of sound or video, or a record.
	browserBinaryFrameLimit = 12 << 20
	// The largest header of a binary message the legacy recognizer reads.
	browserBinaryHeaderLimit = 64 << 10
)

// browserSafeInteger is the largest integer a JavaScript viewer reads exactly.
const browserSafeInteger = 1<<53 - 1

// browserFrameClock places a frame in time and causality: ts is the sandbox's
// monotonic clock at capture in microseconds, inputSeq the last control input
// applied before the capture, and visible the browser window's rectangle
// inside the raster. Each is optional and bounded when present.
type browserFrameClock struct {
	Ts       uint64          `json:"ts,omitempty"`
	InputSeq uint64          `json:"inputSeq,omitempty"`
	Visible  *browserVisible `json:"visible,omitempty"`
}

type browserVisible struct {
	X      uint32 `json:"x"`
	Y      uint32 `json:"y"`
	Width  uint32 `json:"width"`
	Height uint32 `json:"height"`
}

func (c browserFrameClock) valid(surface browserSurface) bool {
	v := c.Visible
	return c.Ts <= browserSafeInteger && c.InputSeq <= browserSafeInteger &&
		(v == nil || (v.Width > 0 && v.Height > 0 && v.X < surface.Width && v.Y < surface.Height &&
			v.Width <= surface.Width-v.X && v.Height <= surface.Height-v.Y))
}

// Capability fallback needs an actual old image record, not a malformed native
// frame. This check is used only before the first picture reached the viewer.
func browserTextFrameHasJPEG(message []byte) bool {
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

func browserBinaryParts(message []byte) (header, payload []byte, valid bool) {
	if len(message) < 4 || len(message) > browserBinaryFrameLimit {
		return nil, nil, false
	}
	length := binary.BigEndian.Uint32(message[:4])
	if length == 0 || length > browserBinaryHeaderLimit || int(length) > len(message)-4 {
		return nil, nil, false
	}
	headerLength := int(length)
	header = message[4 : 4+headerLength]
	return header, message[4+headerLength:], utf8.Valid(header)
}

// Older page streams can also negotiate the binary envelope. Recognize that
// bounded whole-image format only to choose HTTP fallback, never to relay it as
// a native window or broaden the surface schema.
func browserLegacyBinaryFrame(message []byte) bool {
	header, payload, valid := browserBinaryParts(message)
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
