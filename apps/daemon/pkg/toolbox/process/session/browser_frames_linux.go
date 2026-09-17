// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image/jpeg"
	"io"
	"unicode/utf8"
)

const (
	browserBinaryFrameLimit  = 12 << 20
	browserBinaryHeaderLimit = 64 << 10
)

type browserFrameHeader struct {
	Type     string         `json:"type"`
	Seq      uint64         `json:"seq"`
	BaseSeq  uint64         `json:"baseSeq,omitempty"`
	Encoding string         `json:"encoding"`
	Surface  browserSurface `json:"surface"`
}

type browserBinaryPatch struct {
	browserPatchBounds
	ByteLength uint32 `json:"byteLength"`
}

type browserBinaryHeader struct {
	browserFrameHeader
	ByteLength uint32               `json:"byteLength,omitempty"`
	Patches    []browserBinaryPatch `json:"patches,omitempty"`
}

// A binary record keeps its JPEG slices in the original read buffer. Only its
// small, finite header is projected; pixels are neither copied nor base64 encoded.
type browserBinaryFrame struct {
	header    browserBinaryHeader
	payload   []byte
	projected []byte
}

var errBrowserBinaryFrame = errors.New("invalid binary browser frame")

// Capability fallback needs an actual old image record, not a malformed native
// frame. This check is used only before the first native frame is admitted.
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

func parseBrowserBinaryFrame(message []byte) (browserBinaryFrame, error) {
	var frame browserBinaryFrame
	header, payload, valid := browserBinaryParts(message)
	if !valid || json.Unmarshal(header, &frame.header) != nil {
		return frame, errBrowserBinaryFrame
	}
	h := &frame.header
	if h.Type != "frame" || h.Seq == 0 || h.Encoding != "jpeg" || !h.Surface.valid() {
		return frame, errBrowserBinaryFrame
	}
	frame.payload = payload
	remaining := frame.payload
	if h.Patches == nil {
		if h.BaseSeq != 0 || h.ByteLength == 0 || uint64(h.ByteLength) != uint64(len(remaining)) {
			return frame, errBrowserBinaryFrame
		}
		config, err := jpeg.DecodeConfig(bytes.NewReader(remaining))
		if err != nil || config.Width != int(h.Surface.Width) || config.Height != int(h.Surface.Height) {
			return frame, errBrowserBinaryFrame
		}
		return frame.project()
	}
	if h.ByteLength != 0 || h.BaseSeq == 0 || h.BaseSeq >= h.Seq || len(h.Patches) == 0 || len(h.Patches) > 64 {
		return frame, errBrowserBinaryFrame
	}
	for _, patch := range h.Patches {
		if !patch.browserPatchBounds.valid(h.Surface) || patch.ByteLength == 0 || uint64(patch.ByteLength) > uint64(len(remaining)) {
			return frame, errBrowserBinaryFrame
		}
		image := remaining[:int(patch.ByteLength)]
		remaining = remaining[int(patch.ByteLength):]
		config, err := jpeg.DecodeConfig(bytes.NewReader(image))
		if err != nil || config.Width > int(patch.Width)+32 || config.Height > int(patch.Height)+32 ||
			config.Width < int(patch.SourceX+patch.Width) || config.Height < int(patch.SourceY+patch.Height) {
			return frame, errBrowserBinaryFrame
		}
	}
	if len(remaining) != 0 {
		return frame, errBrowserBinaryFrame
	}
	return frame.project()
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

func (f browserBinaryFrame) project() (browserBinaryFrame, error) {
	var err error
	f.projected, err = json.Marshal(f.header)
	if err != nil || len(f.projected) > browserBinaryHeaderLimit || f.wireSize() > browserBinaryFrameLimit {
		return f, errBrowserBinaryFrame
	}
	return f, nil
}

func (f browserBinaryFrame) wireSize() int { return 4 + len(f.projected) + len(f.payload) }

func (f browserBinaryFrame) writeTo(writer io.Writer) error {
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(f.projected)))
	for _, part := range [][]byte{prefix[:], f.projected, f.payload} {
		if n, err := writer.Write(part); err != nil {
			return err
		} else if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}
