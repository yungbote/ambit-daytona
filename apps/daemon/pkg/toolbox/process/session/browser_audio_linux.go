// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

const browserAudioHeaderLimit = 1024
const browserAudioPayloadLimit = 4096

func validBrowserAudioCodec(codec string) bool { return codec == "opus" || codec == "pcm-s16le" }

func parseBrowserAudioDeclaration(request *http.Request) (string, bool) {
	values := request.URL.Query()["audio"]
	if len(values) == 0 {
		return "", true
	}
	return values[0], len(values) == 1 && validBrowserAudioCodec(values[0]) && request.URL.Query().Get("frames") == "binary"
}

type browserAudioMetadata struct {
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

func parseBrowserAudioMetadata(message []byte) (browserAudioMetadata, []byte, bool) {
	var value browserAudioMetadata
	if len(message) > browserAudioHeaderLimit || json.Unmarshal(message, &value) != nil || value.Type != "audio" || !validBrowserAudioCodec(value.Codec) {
		return value, nil, false
	}
	switch value.State {
	case "available":
		value = browserAudioMetadata{Type: "audio", State: value.State, Codec: value.Codec}
	case "stopped", "unavailable":
		if value.Generation == nil || *value.Generation > browserSafeInteger {
			return value, nil, false
		}
		value = browserAudioMetadata{Type: "audio", State: value.State, Codec: value.Codec, Generation: value.Generation}
	case "started":
		if value.Generation == nil || *value.Generation == 0 || *value.Generation > browserSafeInteger || !validBrowserUUID(value.StreamID) || value.SampleRate != 48000 || value.Channels != 2 || value.FrameSamples != 480 || value.PrimingSamples == nil || *value.PrimingSamples > 48000 || (value.Codec == "pcm-s16le" && *value.PrimingSamples != 0) {
			return value, nil, false
		}
	default:
		return value, nil, false
	}
	projected, _ := json.Marshal(value)
	return value, projected, true
}

type browserAudioHeader struct {
	Type       string  `json:"type"`
	Track      string  `json:"track"`
	Codec      string  `json:"codec"`
	StreamID   string  `json:"streamId"`
	Seq        uint64  `json:"seq"`
	Ts         *uint64 `json:"ts"`
	Samples    uint32  `json:"samples"`
	ByteLength uint32  `json:"byteLength"`
}

// Audio shares the envelope, never JPEG geometry or paint credit. Project the
// small header; only the source-produced media bytes pass through unchanged.
func parseBrowserAudioPacket(message []byte) (browserAudioHeader, []byte, bool) {
	var value browserAudioHeader
	header, payload, valid := browserBinaryParts(message)
	if !valid || len(header) > browserAudioHeaderLimit || len(payload) == 0 || len(payload) > browserAudioPayloadLimit || json.Unmarshal(header, &value) != nil || value.Type != "media" || value.Track != "audio" || !validBrowserAudioCodec(value.Codec) || !validBrowserUUID(value.StreamID) || value.Seq == 0 || value.Seq > browserSafeInteger || value.Ts == nil || *value.Ts > browserSafeInteger || value.Samples != 480 || uint64(value.ByteLength) != uint64(len(payload)) || (value.Codec == "pcm-s16le" && len(payload) != 1920) {
		return value, nil, false
	}
	projected, _ := json.Marshal(value)
	wire := make([]byte, 4+len(projected)+len(payload))
	binary.BigEndian.PutUint32(wire, uint32(len(projected)))
	copy(wire[4:], projected)
	copy(wire[4+len(projected):], payload)
	return value, wire, true
}

func browserBinaryMedia(message []byte) bool {
	header, _, valid := browserBinaryParts(message)
	var value struct {
		Type string `json:"type"`
	}
	return valid && json.Unmarshal(header, &value) == nil && value.Type == "media"
}

type browserAudioEpoch struct {
	generation uint64
	id         string
	sequence   uint64
	timestamp  uint64
}

func (ch *browserViewChannel) deliverAudioMetadata(message []byte) error {
	value, projected, valid := parseBrowserAudioMetadata(message)
	if !valid || ch.audioCodec == "" || value.Codec != ch.audioCodec {
		return errors.New("unnegotiated browser audio")
	}
	if value.State == "available" {
		ch.audioOffered.Store(true)
	} else if *value.Generation != ch.audioGeneration.Load() {
		return nil
	}
	if value.State == "started" {
		if !ch.audioOffered.Load() {
			return errors.New("browser audio started before offer")
		}
		if !ch.audioEnabled.Load() {
			return nil
		} // A queued start raced the user's mute.
		ch.audioEpoch = browserAudioEpoch{id: value.StreamID, generation: *value.Generation}
	} else if value.State == "stopped" || value.State == "unavailable" {
		ch.audioEpoch = browserAudioEpoch{}
	}
	return ch.writeText(projected)
}

func (ch *browserViewChannel) deliverAudioPacket(message []byte) error {
	value, projected, valid := parseBrowserAudioPacket(message)
	if !valid || ch.audioCodec == "" || value.Codec != ch.audioCodec {
		return errors.New("invalid browser audio packet")
	}
	if !ch.audioEnabled.Load() {
		return nil
	} // Never queue audio after a mute.
	if ch.audioEpoch.generation != ch.audioGeneration.Load() || value.StreamID != ch.audioEpoch.id {
		return nil
	}
	if value.Seq != ch.audioEpoch.sequence+1 || *value.Ts < ch.audioEpoch.timestamp {
		return errors.New("invalid browser audio epoch")
	}
	ch.audioEpoch.sequence, ch.audioEpoch.timestamp = value.Seq, *value.Ts
	ch.delivery.Lock()
	defer ch.delivery.Unlock()
	_ = ch.socket.SetWriteDeadline(time.Now().Add(browserViewerWriteTimeout))
	return ch.socket.WriteMessage(websocket.BinaryMessage, projected)
}
