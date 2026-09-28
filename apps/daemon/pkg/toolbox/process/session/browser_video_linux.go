// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

const browserVideoHeaderLimit = 4096
const browserVideoPayloadLimit = 4 << 20
const browserVideoDeclarationLimit = 64

var browserVideoCodecString = regexp.MustCompile(`^(?:av01|vp09)\.[0-9A-Za-z.]{1,40}$`)

func validBrowserVideoCodec(codec string) bool {
	switch codec {
	case "av1-444", "av1", "vp9-444", "vp9":
		return true
	}
	return false
}

func validBrowserVideoCodecString(codec, value string) bool {
	return browserVideoCodecString.MatchString(value) && strings.HasPrefix(value, "av01") == strings.HasPrefix(codec, "av1")
}

// What the viewer can decode, in its order of preference: distinct tokens of
// the closed vocabulary. The driver offers one of them or keeps sending frames.
func parseBrowserVideoDeclaration(request *http.Request) ([]string, bool) {
	values := request.URL.Query()["video"]
	if len(values) == 0 {
		return nil, true
	}
	if len(values) != 1 || len(values[0]) > browserVideoDeclarationLimit || request.URL.Query().Get("frames") != "binary" {
		return nil, false
	}
	codecs := strings.Split(values[0], ",")
	for index, codec := range codecs {
		if !validBrowserVideoCodec(codec) {
			return nil, false
		}
		for _, earlier := range codecs[:index] {
			if earlier == codec {
				return nil, false
			}
		}
	}
	return codecs, true
}

type browserVideoMetadata struct {
	Generation  *uint64 `json:"generation,omitempty"`
	Type        string  `json:"type"`
	State       string  `json:"state"`
	Codec       string  `json:"codec,omitempty"`
	CodecString string  `json:"codecString,omitempty"`
	StreamID    string  `json:"streamId,omitempty"`
}

func parseBrowserVideoMetadata(message []byte) (browserVideoMetadata, []byte, bool) {
	var value browserVideoMetadata
	if len(message) > browserVideoHeaderLimit || json.Unmarshal(message, &value) != nil || value.Type != "video" ||
		(value.Codec != "" && !validBrowserVideoCodec(value.Codec)) {
		return value, nil, false
	}
	switch value.State {
	case "available":
		if value.Codec == "" {
			return value, nil, false
		}
		value = browserVideoMetadata{Type: "video", State: value.State, Codec: value.Codec}
	case "stopped", "unavailable":
		if value.Generation == nil || *value.Generation > browserSafeInteger {
			return value, nil, false
		}
		value = browserVideoMetadata{Type: "video", State: value.State, Codec: value.Codec, Generation: value.Generation}
	case "started":
		if value.Generation == nil || *value.Generation == 0 || *value.Generation > browserSafeInteger || value.Codec == "" ||
			!validBrowserUUID(value.StreamID) || !validBrowserVideoCodecString(value.Codec, value.CodecString) {
			return value, nil, false
		}
	default:
		return value, nil, false
	}
	projected, _ := json.Marshal(value)
	return value, projected, true
}

type browserVideoSize struct {
	Width  uint32 `json:"width"`
	Height uint32 `json:"height"`
}

type browserVideoHeader struct {
	Type        string           `json:"type"`
	Track       string           `json:"track"`
	Codec       string           `json:"codec"`
	StreamID    string           `json:"streamId"`
	Seq         uint64           `json:"seq"`
	Ts          *uint64          `json:"ts"`
	Key         bool             `json:"key"`
	CodecString string           `json:"codecString,omitempty"`
	Description string           `json:"description,omitempty"`
	Coded       browserVideoSize `json:"coded"`
	Visible     browserVisible   `json:"visible"`
	Surface     browserSurface   `json:"surface"`
	InputSeq    uint64           `json:"inputSeq,omitempty"`
	Quality     string           `json:"quality"`
	ByteLength  uint32           `json:"byteLength"`
}

func (h browserVideoHeader) valid(payload int) bool {
	v := h.Visible
	if h.Type != "media" || h.Track != "video" || !validBrowserVideoCodec(h.Codec) || !validBrowserUUID(h.StreamID) ||
		h.Seq == 0 || h.Seq > browserSafeInteger || h.Ts == nil || *h.Ts > browserSafeInteger || h.InputSeq > browserSafeInteger ||
		h.Coded.Width == 0 || h.Coded.Width > 4096 || h.Coded.Height == 0 || h.Coded.Height > 4096 ||
		v.Width == 0 || v.Height == 0 || v.X >= h.Coded.Width || v.Y >= h.Coded.Height ||
		v.Width > h.Coded.Width-v.X || v.Height > h.Coded.Height-v.Y || !h.Surface.valid() ||
		(h.Quality != "motion" && h.Quality != "refine" && h.Quality != "final") ||
		payload == 0 || payload > browserVideoPayloadLimit || uint64(h.ByteLength) != uint64(payload) {
		return false
	}
	if !h.Key {
		return h.CodecString == "" && h.Description == ""
	}
	if !validBrowserVideoCodecString(h.Codec, h.CodecString) {
		return false
	}
	if h.Description == "" {
		return true
	}
	_, err := base64.StdEncoding.Strict().DecodeString(h.Description)
	return err == nil
}

// A unit is one encoded picture. Only its small header is projected; the
// encoded bytes pass through unchanged and no hop decodes them.
func parseBrowserVideoUnit(message []byte) (browserVideoHeader, []byte, bool) {
	var value browserVideoHeader
	header, payload, valid := browserBinaryParts(message)
	if !valid || len(header) > browserVideoHeaderLimit || json.Unmarshal(header, &value) != nil || !value.valid(len(payload)) {
		return value, nil, false
	}
	projected, err := json.Marshal(value)
	if err != nil || len(projected) > browserVideoHeaderLimit {
		return value, nil, false
	}
	wire := make([]byte, 4+len(projected)+len(payload))
	binary.BigEndian.PutUint32(wire, uint32(len(projected)))
	copy(wire[4:], projected)
	copy(wire[4+len(projected):], payload)
	return value, wire, true
}

func browserBinaryMediaTrack(message []byte) (string, bool) {
	header, _, valid := browserBinaryParts(message)
	var value struct {
		Type  string `json:"type"`
		Track string `json:"track"`
	}
	if !valid || json.Unmarshal(header, &value) != nil || value.Type != "media" {
		return "", false
	}
	return value.Track, true
}

// One subscription's stream. Guarded by the channel's delivery lock: the
// upstream reader advances it and the viewer's acknowledgements read it.
type browserVideoEpoch struct {
	generation   uint64
	id           string
	sequence     uint64
	timestamp    uint64
	coded        browserVideoSize
	acknowledged uint64
}

func (ch *browserViewChannel) videoDeclared(codec string) bool {
	for _, declared := range ch.videoCodecs {
		if declared == codec {
			return true
		}
	}
	return false
}

func (ch *browserViewChannel) deliverVideoMetadata(message []byte) error {
	value, projected, valid := parseBrowserVideoMetadata(message)
	if !valid || len(ch.videoCodecs) == 0 || (value.Codec != "" && !ch.videoDeclared(value.Codec)) {
		return errors.New("unnegotiated browser video")
	}
	if value.State == "available" {
		if ch.videoOffered.Load() && ch.videoCodec != value.Codec {
			return errors.New("browser video codec changed")
		}
		ch.videoCodec = value.Codec
		ch.videoOffered.Store(true)
		return ch.writeText(projected)
	}
	if *value.Generation != ch.videoGeneration.Load() {
		return nil
	}
	ch.delivery.Lock()
	if value.State == "started" {
		if !ch.videoOffered.Load() || value.Codec != ch.videoCodec {
			ch.delivery.Unlock()
			return errors.New("browser video started before offer")
		}
		if !ch.videoEnabled.Load() {
			ch.delivery.Unlock()
			return nil
		} // A queued start raced the viewer's fallback.
		ch.videoEpoch = browserVideoEpoch{id: value.StreamID, generation: *value.Generation}
	} else {
		ch.videoEpoch = browserVideoEpoch{}
	}
	ch.delivery.Unlock()
	return ch.writeText(projected)
}

func (ch *browserViewChannel) deliverVideoUnit(message []byte) error {
	value, projected, valid := parseBrowserVideoUnit(message)
	if !valid || !ch.videoOffered.Load() || value.Codec != ch.videoCodec {
		return errors.New("invalid browser video unit")
	}
	if !ch.videoEnabled.Load() {
		return nil
	}
	ch.delivery.Lock()
	defer ch.delivery.Unlock()
	epoch := &ch.videoEpoch
	if epoch.generation != ch.videoGeneration.Load() || value.StreamID != epoch.id {
		return nil
	}
	// A stream begins with a picture that needs no other, and so does every
	// change of the coded size. Pictures are never skipped or reordered.
	if value.Seq != epoch.sequence+1 || *value.Ts < epoch.timestamp || (!value.Key && (epoch.sequence == 0 || value.Coded != epoch.coded)) {
		return errors.New("invalid browser video epoch")
	}
	epoch.sequence, epoch.timestamp, epoch.coded = value.Seq, *value.Ts, value.Coded
	_ = ch.socket.SetWriteDeadline(time.Now().Add(browserViewerWriteTimeout))
	return ch.socket.WriteMessage(websocket.BinaryMessage, projected)
}

type browserViewerVideo struct {
	Type       string  `json:"type"`
	Enabled    *bool   `json:"enabled,omitempty"`
	Keyframe   *bool   `json:"keyframe,omitempty"`
	Generation *uint64 `json:"generation,omitempty"`
	Track      string  `json:"track,omitempty"`
	StreamID   string  `json:"streamId,omitempty"`
	Seq        uint64  `json:"seq,omitempty"`
}

// The viewer's three picture messages, each a closed shape: a subscription, a
// request for a picture that needs no other, and a painted acknowledgement.
func browserViewerVideoMessage(message []byte) (browserViewerVideo, []byte, bool) {
	var value browserViewerVideo
	if len(message) > browserViewerMessageLimit || !utf8.Valid(message) {
		return value, nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(message))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return value, nil, false
	}
	generation := value.Generation != nil && *value.Generation > 0 && *value.Generation <= browserSafeInteger
	switch {
	case value.Type == "video" && generation && value.Enabled != nil && value.Keyframe == nil && value.Track == "" && value.StreamID == "" && value.Seq == 0:
	case value.Type == "video" && generation && value.Enabled == nil && value.Keyframe != nil && *value.Keyframe && value.Track == "" && value.StreamID == "" && value.Seq == 0:
	case value.Type == "ack" && value.Track == "video" && value.Generation == nil && value.Enabled == nil && value.Keyframe == nil &&
		validBrowserUUID(value.StreamID) && value.Seq > 0 && value.Seq <= browserSafeInteger:
	default:
		return value, nil, false
	}
	projected, _ := json.Marshal(value)
	return value, projected, true
}

// Decides whether a viewer's picture message travels to the driver. A message
// about a retired subscription is dropped; one the viewer could never have
// sent honestly ends the channel.
func (ch *browserViewChannel) admitViewerVideo(value browserViewerVideo) (forward, valid bool) {
	if !ch.videoOffered.Load() {
		return false, false
	}
	if value.Type == "ack" {
		ch.delivery.Lock()
		defer ch.delivery.Unlock()
		epoch := &ch.videoEpoch
		if value.StreamID != epoch.id || value.Seq <= epoch.acknowledged {
			return false, true
		}
		if value.Seq > epoch.sequence {
			return false, false
		}
		epoch.acknowledged = value.Seq
		return true, true
	}
	if value.Keyframe != nil {
		return *value.Generation == ch.videoGeneration.Load() && ch.videoEnabled.Load(), true
	}
	if *value.Generation <= ch.videoGeneration.Load() {
		return false, true
	}
	ch.videoGeneration.Store(*value.Generation)
	ch.videoEnabled.Store(*value.Enabled)
	return true, true
}
