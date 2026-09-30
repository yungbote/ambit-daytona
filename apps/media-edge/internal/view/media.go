// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// The audio and video tracks are the toolbox's (browser_audio_linux.go,
// browser_video_linux.go), ported unchanged: closed record and header shapes,
// bounds per kind, and per-stream epochs whose sequence never skips.

const (
	audioHeaderLimit  = 1024
	audioPayloadLimit = 4096
	videoHeaderLimit  = 4096
	// MaxVideoPayloadBytes is the current4096²8-bit4:4:4 source's capacity:
	// eight aligned decoded rasters. Allocation uses actual unit bytes.
	MaxVideoPayloadBytes = 8 * 4096 * 4096 * 3
)

// videoPayloadBytes is the negotiated source allowance for coded geometry
// and chroma. The current native libaom encoder uses this allocation bound;
// the VP9 vocabulary retains the same format allowance, not a claim about a
// different encoder's private allocation. Metadata/control have other bounds.
func videoPayloadBytes(codec string, coded videoSize) uint64 {
	if !validVideoCodec(codec) || coded.Width == 0 || coded.Width > 4096 || coded.Height == 0 || coded.Height > 4096 {
		return 0
	}
	width := (uint64(coded.Width) + 31) &^ 31
	height := (uint64(coded.Height) + 31) &^ 31
	bits := uint64(12)
	if strings.HasSuffix(codec, "-444") {
		bits = 24
	}
	return max(uint64(8192), 8*width*height*bits/8)
}

// BinaryPayloadLimit admits the small header before a route grows a body
// buffer. A large allowance belongs only to validated producer video.
// Audio and legacy/JPEG envelopes retain their own grammar/resource bounds.
func BinaryPayloadLimit(header []byte) (int, bool) {
	var kind struct{ Type, Track string }
	if len(header) == 0 || len(header) > maxFrameHeaderBytes || json.Unmarshal(header, &kind) != nil {
		return 0, false
	}
	if kind.Type == "media" && kind.Track == "video" {
		var value videoHeader
		if len(header) > videoHeaderLimit || json.Unmarshal(header, &value) != nil || !value.valid(int(value.ByteLength)) {
			return 0, false
		}
		return int(value.ByteLength), true
	}
	if kind.Type == "media" && kind.Track == "audio" {
		var value audioHeader
		if len(header) > audioHeaderLimit || json.Unmarshal(header, &value) != nil || value.ByteLength == 0 || value.ByteLength > audioPayloadLimit {
			return 0, false
		}
		return int(value.ByteLength), true
	}
	return maxFrameMessageBytes - 4 - len(header), true
}

func validAudioCodec(codec string) bool { return codec == "opus" || codec == "pcm-s16le" }

func validVideoCodec(codec string) bool {
	switch codec {
	case "av1-444", "av1", "vp9-444", "vp9":
		return true
	}
	return false
}

var videoCodecString = regexp.MustCompile(`^(?:av01|vp09)\.[0-9A-Za-z.]{1,40}$`)

func validVideoCodecString(codec, value string) bool {
	return videoCodecString.MatchString(value) && strings.HasPrefix(value, "av01") == strings.HasPrefix(codec, "av1")
}

type audioMetadata struct {
	Generation     *uint64 `json:"generation,omitempty"`
	Type           string  `json:"type"`
	State          string  `json:"state"`
	Codec          string  `json:"codec"`
	StreamID       string  `json:"streamId,omitempty"`
	SampleRate     uint32  `json:"sampleRate,omitempty"`
	Channels       uint32  `json:"channels,omitempty"`
	FrameSamples   uint32  `json:"frameSamples,omitempty"`
	PrimingSamples *uint32 `json:"primingSamples,omitempty"`
}

func parseAudioMetadata(message []byte) (audioMetadata, []byte, bool) {
	var value audioMetadata
	if len(message) > audioHeaderLimit || json.Unmarshal(message, &value) != nil || value.Type != "audio" || !validAudioCodec(value.Codec) {
		return value, nil, false
	}
	switch value.State {
	case "available":
		value = audioMetadata{Type: "audio", State: value.State, Codec: value.Codec}
	case "stopped", "unavailable":
		if value.Generation == nil || *value.Generation > safeInteger {
			return value, nil, false
		}
		value = audioMetadata{Type: "audio", State: value.State, Codec: value.Codec, Generation: value.Generation}
	case "started":
		if value.Generation == nil || *value.Generation == 0 || *value.Generation > safeInteger || !validUUID(value.StreamID) ||
			value.SampleRate != 48000 || value.Channels != 2 || value.FrameSamples != 480 || value.PrimingSamples == nil ||
			*value.PrimingSamples > 48000 || (value.Codec == "pcm-s16le" && *value.PrimingSamples != 0) {
			return value, nil, false
		}
	default:
		return value, nil, false
	}
	projected, _ := json.Marshal(value)
	return value, projected, true
}

type audioHeader struct {
	Type       string  `json:"type"`
	Track      string  `json:"track"`
	Codec      string  `json:"codec"`
	StreamID   string  `json:"streamId"`
	Seq        uint64  `json:"seq"`
	Ts         *uint64 `json:"ts"`
	Samples    uint32  `json:"samples"`
	ByteLength uint32  `json:"byteLength"`
}

// parseAudioPacket projects the small header; the source's media bytes pass
// through unchanged.
func parseAudioPacket(message []byte) (audioHeader, []byte, []byte, bool) {
	var value audioHeader
	header, payload, valid := envelope(message)
	if !valid || len(header) > audioHeaderLimit || len(payload) == 0 || len(payload) > audioPayloadLimit ||
		json.Unmarshal(header, &value) != nil || value.Type != "media" || value.Track != "audio" || !validAudioCodec(value.Codec) ||
		!validUUID(value.StreamID) || value.Seq == 0 || value.Seq > safeInteger || value.Ts == nil || *value.Ts > safeInteger ||
		value.Samples != 480 || uint64(value.ByteLength) != uint64(len(payload)) || (value.Codec == "pcm-s16le" && len(payload) != 1920) {
		return value, nil, nil, false
	}
	projected, _ := json.Marshal(value)
	return value, projected, payload, true
}

type videoMetadata struct {
	Generation  *uint64 `json:"generation,omitempty"`
	Type        string  `json:"type"`
	State       string  `json:"state"`
	Codec       string  `json:"codec,omitempty"`
	CodecString string  `json:"codecString,omitempty"`
	StreamID    string  `json:"streamId,omitempty"`
}

func parseVideoMetadata(message []byte) (videoMetadata, []byte, bool) {
	var value videoMetadata
	if len(message) > videoHeaderLimit || json.Unmarshal(message, &value) != nil || value.Type != "video" ||
		(value.Codec != "" && !validVideoCodec(value.Codec)) {
		return value, nil, false
	}
	switch value.State {
	case "available":
		if value.Codec == "" {
			return value, nil, false
		}
		value = videoMetadata{Type: "video", State: value.State, Codec: value.Codec}
	case "stopped", "unavailable":
		if value.Generation == nil || *value.Generation > safeInteger {
			return value, nil, false
		}
		value = videoMetadata{Type: "video", State: value.State, Codec: value.Codec, Generation: value.Generation}
	case "started":
		if value.Generation == nil || *value.Generation == 0 || *value.Generation > safeInteger || value.Codec == "" ||
			!validUUID(value.StreamID) || !validVideoCodecString(value.Codec, value.CodecString) {
			return value, nil, false
		}
	default:
		return value, nil, false
	}
	projected, _ := json.Marshal(value)
	return value, projected, true
}

type videoSize struct {
	Width  uint32 `json:"width"`
	Height uint32 `json:"height"`
}

type videoHeader struct {
	Type        string      `json:"type"`
	Track       string      `json:"track"`
	Codec       string      `json:"codec"`
	StreamID    string      `json:"streamId"`
	Seq         uint64      `json:"seq"`
	Ts          *uint64     `json:"ts"`
	Key         bool        `json:"key"`
	CodecString string      `json:"codecString,omitempty"`
	Description string      `json:"description,omitempty"`
	Coded       videoSize   `json:"coded"`
	Visible     visibleRect `json:"visible"`
	Surface     surface     `json:"surface"`
	InputSeq    uint64      `json:"inputSeq,omitempty"`
	Quality     string      `json:"quality"`
	ByteLength  uint32      `json:"byteLength"`
}

func (h videoHeader) valid(payload int) bool {
	v := h.Visible
	if h.Type != "media" || h.Track != "video" || !validVideoCodec(h.Codec) || !validUUID(h.StreamID) ||
		h.Seq == 0 || h.Seq > safeInteger || h.Ts == nil || *h.Ts > safeInteger || h.InputSeq > safeInteger ||
		h.Coded.Width == 0 || h.Coded.Width > 4096 || h.Coded.Height == 0 || h.Coded.Height > 4096 ||
		v.Width == 0 || v.Height == 0 || v.X >= h.Coded.Width || v.Y >= h.Coded.Height ||
		v.Width > h.Coded.Width-v.X || v.Height > h.Coded.Height-v.Y || !h.Surface.valid() ||
		(h.Quality != "motion" && h.Quality != "refine" && h.Quality != "final") ||
		payload <= 0 || uint64(payload) > videoPayloadBytes(h.Codec, h.Coded) || uint64(h.ByteLength) != uint64(payload) {
		return false
	}
	if !h.Key {
		return h.CodecString == "" && h.Description == ""
	}
	if !validVideoCodecString(h.Codec, h.CodecString) {
		return false
	}
	if h.Description == "" {
		return true
	}
	_, err := base64.StdEncoding.Strict().DecodeString(h.Description)
	return err == nil
}

// parseVideoUnit projects a unit's small header; the encoded picture passes
// through unchanged and is never decoded.
func parseVideoUnit(message []byte) (videoHeader, []byte, []byte, bool) {
	var value videoHeader
	header, payload, valid := envelope(message)
	if !valid || len(header) > videoHeaderLimit || json.Unmarshal(header, &value) != nil || !value.valid(len(payload)) {
		return value, nil, nil, false
	}
	projected, err := json.Marshal(value)
	if err != nil || len(projected) > videoHeaderLimit {
		return value, nil, nil, false
	}
	return value, projected, payload, true
}
