// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxViewerMessageBytes bounds one message from the page, as the backend
// relay and the toolbox bound it.
const MaxViewerMessageBytes = 4096

// maxCSSSize bounds a presentation, in CSS pixels.
const maxCSSSize = 2048

type viewerKind int

const (
	viewerFrameAck viewerKind = iota + 1
	viewerVideoAck
	viewerVideoReceived
	viewerAudio
	viewerVideo
	viewerKeyframe
	viewerPresentation
)

// viewerMessage is one of the page's six messages: presentation, output and
// picture subscriptions carry no input, clipboard or controller authority.
type viewerMessage struct {
	kind       viewerKind
	seq        uint64
	streamID   string
	enabled    bool
	generation uint64
	width      uint64
	height     uint64
	offset     uint64
}

var byteOrderMark = []byte("\xef\xbb\xbf")

// parseViewerMessage reads a page message the way the backend relay does
// (readBrowserViewClientMessage: JSON numbers as JavaScript reads them, exact
// member sets) and the toolbox then does (a video stream is a non-nil UUID).
func parseViewerMessage(message []byte) (viewerMessage, bool) {
	if len(message) > MaxViewerMessageBytes {
		return viewerMessage{}, false
	}
	// The backend decodes with TextDecoder, which drops one leading BOM.
	message = bytes.TrimPrefix(message, byteOrderMark)
	var record map[string]json.RawMessage
	if !utf8.Valid(message) || json.Unmarshal(message, &record) != nil || record == nil {
		return viewerMessage{}, false
	}
	names := make([]string, 0, len(record))
	for name := range record {
		names = append(names, name)
	}
	sort.Strings(names)
	text := func(name string) string {
		var value string
		if raw := record[name]; len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
			return "\x00"
		}
		return value
	}
	switch strings.Join(names, ",") {
	case "enabled,generation,type":
		generation, positive := safePositive(record["generation"])
		enabled, boolean := jsonBool(record["enabled"])
		switch kind := text("type"); {
		case !positive || !boolean:
		case kind == "audio":
			return viewerMessage{kind: viewerAudio, enabled: enabled, generation: generation}, true
		case kind == "video":
			return viewerMessage{kind: viewerVideo, enabled: enabled, generation: generation}, true
		}
	case "generation,keyframe,type":
		generation, positive := safePositive(record["generation"])
		if keyframe, boolean := jsonBool(record["keyframe"]); positive && boolean && keyframe && text("type") == "video" {
			return viewerMessage{kind: viewerKeyframe, generation: generation}, true
		}
	case "seq,streamId,track,type":
		seq, positive := safePositive(record["seq"])
		if streamID := text("streamId"); positive && text("type") == "ack" && text("track") == "video" && validUUID(streamID) {
			return viewerMessage{kind: viewerVideoAck, seq: seq, streamID: streamID}, true
		}
	case "offset,seq,streamId,track,type":
		seq, positive := safePositive(record["seq"])
		offset, prefix := safePositive(record["offset"])
		if streamID := text("streamId"); positive && prefix && text("type") == "received" && text("track") == "video" && validUUID(streamID) {
			return viewerMessage{kind: viewerVideoReceived, seq: seq, streamID: streamID, offset: offset}, true
		}
	case "seq,type":
		if seq, positive := safePositive(record["seq"]); positive && text("type") == "ack" {
			return viewerMessage{kind: viewerFrameAck, seq: seq}, true
		}
	case "height,type,width":
		width, widthPositive := safePositive(record["width"])
		height, heightPositive := safePositive(record["height"])
		if widthPositive && heightPositive && width <= maxCSSSize && height <= maxCSSSize && text("type") == "presentation" {
			return viewerMessage{kind: viewerPresentation, width: width, height: height}, true
		}
	}
	return viewerMessage{}, false
}

// safePositive reads a JSON number as JavaScript does (a double) and admits
// it when it is an integer from 1 to 2^53-1.
func safePositive(raw json.RawMessage) (uint64, bool) {
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return 0, false
	}
	value, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || value != math.Trunc(value) || value < 1 || value > safeInteger {
		return 0, false
	}
	return uint64(value), true
}

func jsonBool(raw json.RawMessage) (value, valid bool) {
	switch string(raw) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// encode is the message as the backend relay forwards it (JSON.stringify of
// its normalized object) and the toolbox projects it: one canonical text.
func (m viewerMessage) encode() []byte {
	generation := strconv.FormatUint(m.generation, 10)
	switch m.kind {
	case viewerFrameAck:
		return []byte(`{"type":"ack","seq":` + strconv.FormatUint(m.seq, 10) + `}`)
	case viewerVideoAck:
		return []byte(`{"type":"ack","track":"video","streamId":"` + m.streamID + `","seq":` + strconv.FormatUint(m.seq, 10) + `}`)
	case viewerVideoReceived:
		return []byte(`{"type":"received","track":"video","streamId":"` + m.streamID + `","seq":` + strconv.FormatUint(m.seq, 10) + `,"offset":` + strconv.FormatUint(m.offset, 10) + `}`)
	case viewerAudio:
		return []byte(`{"type":"audio","enabled":` + strconv.FormatBool(m.enabled) + `,"generation":` + generation + `}`)
	case viewerVideo:
		return []byte(`{"type":"video","enabled":` + strconv.FormatBool(m.enabled) + `,"generation":` + generation + `}`)
	case viewerKeyframe:
		return []byte(`{"type":"video","keyframe":true,"generation":` + generation + `}`)
	case viewerPresentation:
		return []byte(`{"type":"presentation","width":` + strconv.FormatUint(m.width, 10) + `,"height":` + strconv.FormatUint(m.height, 10) + `}`)
	}
	return nil
}

// Declaration is what a viewer declared on its upgrade: the size it presents
// (none for an observer), its frame window, what it draws itself, and the
// tracks it can play.
type Declaration struct {
	Width       int
	Height      int
	FrameWindow int
	// Cursor: the viewer draws the pointer (cursor=viewer).
	Cursor bool
	// Crop: the viewer draws frames 1:1 cropped to their visible rectangle.
	Crop  bool
	Audio string
	// Video is the viewer's decodable codecs in its order of preference.
	Video []string
	// VideoCapacity names a viewer with geometry/chroma-derived readers.
	// Absence preserves the cached legacy4MiB video reader's capability.
	VideoCapacity bool
	// VideoChunks explicitly opts into bounded parts and received-prefix credit.
	VideoChunks bool
}

// ErrDeclaration is a malformed viewer upgrade.
var ErrDeclaration = errors.New("view: invalid viewer declaration")

var positiveDecimal = regexp.MustCompile(`^[1-9][0-9]*$`)

// ParseDeclaration reads the viewer upgrade's members exactly as the
// backend's upgrade does: the first value of each member counts, except that
// audio and video may be stated once only.
func ParseDeclaration(query url.Values) (Declaration, error) {
	first := func(name string) (string, bool) {
		values, present := query[name]
		if !present || len(values) == 0 {
			return "", false
		}
		return values[0], true
	}
	d := Declaration{FrameWindow: 1}
	if frames, _ := first("frames"); frames != "binary" {
		return Declaration{}, ErrDeclaration
	}
	if patches, _ := first("patches"); patches != "1" {
		return Declaration{}, ErrDeclaration
	}
	if window, present := first("frameWindow"); present {
		if len(window) != 1 || window[0] < '1' || window[0] > '8' {
			return Declaration{}, ErrDeclaration
		}
		d.FrameWindow = int(window[0] - '0')
	}
	width, hasWidth := first("width")
	height, hasHeight := first("height")
	if hasWidth || hasHeight {
		dimension := func(value string) (int, bool) {
			if !positiveDecimal.MatchString(value) || len(value) > 4 {
				return 0, false
			}
			parsed, _ := strconv.Atoi(value)
			return parsed, parsed <= maxCSSSize
		}
		var widthValid, heightValid bool
		d.Width, widthValid = dimension(width)
		d.Height, heightValid = dimension(height)
		if !hasWidth || !hasHeight || !widthValid || !heightValid {
			return Declaration{}, ErrDeclaration
		}
	}
	if cursor, present := first("cursor"); present {
		if cursor != "viewer" {
			return Declaration{}, ErrDeclaration
		}
		d.Cursor = true
	}
	if visible, present := first("visible"); present {
		if visible != "crop" {
			return Declaration{}, ErrDeclaration
		}
		d.Crop = true
	}
	if values := query["audio"]; len(values) > 1 || (len(values) == 1 && !validAudioCodec(values[0])) {
		return Declaration{}, ErrDeclaration
	} else if len(values) == 1 {
		d.Audio = values[0]
	}
	if values := query["video"]; len(values) > 1 {
		return Declaration{}, ErrDeclaration
	} else if len(values) == 1 {
		if len(values[0]) > 64 {
			return Declaration{}, ErrDeclaration
		}
		codecs := strings.Split(values[0], ",")
		for index, codec := range codecs {
			if !validVideoCodec(codec) || slices.Contains(codecs[:index], codec) {
				return Declaration{}, ErrDeclaration
			}
		}
		d.Video = codecs
	}
	if values := query["videoCapacity"]; len(values) > 1 || (len(values) == 1 && (values[0] != "coded" || len(d.Video) == 0)) {
		return Declaration{}, ErrDeclaration
	} else if len(values) == 1 {
		d.VideoCapacity = true
	}
	if values := query["videoFraming"]; len(values) > 1 || (len(values) == 1 && (values[0] != "chunks" || !d.VideoCapacity)) {
		return Declaration{}, ErrDeclaration
	} else if len(values) == 1 {
		d.VideoChunks = true
	}
	return d, nil
}

// Presents reports whether this viewer owns a presentation size.
func (d Declaration) Presents() bool { return d.Width != 0 }

// Query is the declaration as the view route takes it, member for member in
// the order the backend's provider writes it.
func (d Declaration) Query() string {
	var query strings.Builder
	query.WriteString("frameWindow=" + strconv.Itoa(d.FrameWindow) + "&frames=binary&patches=1")
	if d.Presents() {
		query.WriteString("&width=" + strconv.Itoa(d.Width) + "&height=" + strconv.Itoa(d.Height))
	}
	if d.Cursor {
		query.WriteString("&cursor=viewer")
	}
	if d.Crop {
		query.WriteString("&visible=crop")
	}
	if d.Audio != "" {
		query.WriteString("&audio=" + url.QueryEscape(d.Audio))
	}
	if len(d.Video) != 0 {
		query.WriteString("&video=" + url.QueryEscape(strings.Join(d.Video, ",")))
	}
	if d.VideoCapacity {
		query.WriteString("&videoCapacity=coded")
	}
	if d.VideoChunks {
		query.WriteString("&videoFraming=chunks")
	}
	return query.String()
}
