// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"bytes"
	"encoding/json"
	"image/png"
	"math"
	"regexp"
	"slices"
)

// The record projection is the toolbox's (browser_views_linux.go
// browserViewMessage, browser_activity.go, browser_cursor.go,
// browser_window_linux.go browserPresentationMessage), ported unchanged, plus
// one case: the toolbox's own failure record is read as the failure it
// reports, so that the projection is idempotent on everything it emits.

type recordKind int

const (
	// recordDropped is anything outside the visual contract, including
	// command and result payloads that can carry task input.
	recordDropped recordKind = iota
	// recordVisual is a frame, or the view state frames are read against.
	recordVisual
	// recordFailed is the driver's own failure; its text never leaves the edge.
	recordFailed
	// recordFinished is the explicit end of the view.
	recordFinished
)

var (
	// finishedRecord and unavailableRecord are the terminal vocabulary the
	// viewer reads; neither carries upstream text.
	finishedRecord    = []byte(`{"type":"finished"}`)
	unavailableRecord = []byte(`{"type":"unavailable","reason":"screencast_failed"}`)
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// validUUID admits a canonical lower-case UUID other than the nil UUID.
func validUUID(value string) bool {
	return uuidPattern.MatchString(value) && value != "00000000-0000-0000-0000-000000000000"
}

func projectRecord(message []byte) ([]byte, uint64, recordKind) {
	var envelope struct {
		Type    string          `json:"type"`
		Seq     uint64          `json:"seq"`
		Surface json.RawMessage `json:"surface"`
	}
	if json.Unmarshal(message, &envelope) != nil {
		return nil, 0, recordDropped
	}
	body := bytes.TrimSpace(message)
	switch envelope.Type {
	case "frame":
		if envelope.Seq == 0 {
			return nil, 0, recordDropped
		}
		if envelope.Surface != nil {
			var frame struct {
				Type     string      `json:"type"`
				Seq      uint64      `json:"seq"`
				Encoding string      `json:"encoding"`
				Data     string      `json:"data,omitempty"`
				BaseSeq  uint64      `json:"baseSeq,omitempty"`
				Patches  []textPatch `json:"patches,omitempty"`
				Surface  surface     `json:"surface"`
				frameClock
			}
			if json.Unmarshal(message, &frame) != nil || !frame.Surface.valid() || frame.Encoding != "jpeg" || !frame.frameClock.valid(frame.Surface) {
				return nil, 0, recordFailed
			}
			if len(frame.Patches) > 0 {
				if frame.Data != "" || frame.BaseSeq == 0 || frame.BaseSeq >= frame.Seq || len(frame.Patches) > 64 {
					return nil, 0, recordFailed
				}
				for _, patch := range frame.Patches {
					if !patch.valid(frame.Surface) {
						return nil, 0, recordFailed
					}
				}
			} else if frame.Data == "" || frame.BaseSeq != 0 {
				return nil, 0, recordFailed
			}
			projected, err := json.Marshal(frame)
			if err != nil {
				return nil, 0, recordFailed
			}
			return projected, frame.Seq, recordVisual
		}
		return body, envelope.Seq, recordVisual
	case "status":
		var status struct {
			Type           string  `json:"type"`
			Connected      *bool   `json:"connected,omitempty"`
			Screencasting  *bool   `json:"screencasting,omitempty"`
			ViewportWidth  *uint32 `json:"viewportWidth,omitempty"`
			ViewportHeight *uint32 `json:"viewportHeight,omitempty"`
			Engine         *string `json:"engine,omitempty"`
			Recording      *bool   `json:"recording,omitempty"`
		}
		if json.Unmarshal(message, &status) != nil {
			return nil, 0, recordDropped
		}
		projected, _ := json.Marshal(status)
		return projected, 0, recordVisual
	case "url":
		var location struct {
			Type         string  `json:"type"`
			URL          string  `json:"url"`
			Title        *string `json:"title,omitempty"`
			Timestamp    *uint64 `json:"timestamp,omitempty"`
			CanGoBack    *bool   `json:"canGoBack,omitempty"`
			CanGoForward *bool   `json:"canGoForward,omitempty"`
		}
		if json.Unmarshal(message, &location) != nil {
			return nil, 0, recordDropped
		}
		projected, _ := json.Marshal(location)
		return projected, 0, recordVisual
	case "presentation":
		if projected, valid := presentationRecord(message); valid {
			return projected, 0, recordVisual
		}
		return nil, 0, recordDropped
	case "pointer", "activity":
		if projected, valid := activityRecord(message); valid {
			return projected, 0, recordVisual
		}
		return nil, 0, recordDropped
	case "cursor":
		if projected, valid := cursorRecord(message); valid {
			return projected, 0, recordVisual
		}
		return nil, 0, recordDropped
	case "files":
		// A file chooser opened or ended, or a download settled: only the
		// capture clock rides the doorbell.
		var doorbell struct {
			Type string  `json:"type"`
			Ts   *uint64 `json:"ts"`
		}
		if json.Unmarshal(message, &doorbell) != nil || doorbell.Ts == nil || *doorbell.Ts > safeInteger {
			return nil, 0, recordDropped
		}
		projected, _ := json.Marshal(doorbell)
		return projected, 0, recordVisual
	case "tabs":
		// A newly attached viewer receives the driver's tab snapshot; only
		// the active location enters the visual contract.
		var snapshot struct {
			Tabs []struct {
				Active       bool   `json:"active"`
				URL          string `json:"url"`
				Title        string `json:"title"`
				CanGoBack    *bool  `json:"canGoBack"`
				CanGoForward *bool  `json:"canGoForward"`
			} `json:"tabs"`
		}
		if json.Unmarshal(message, &snapshot) != nil {
			return nil, 0, recordDropped
		}
		active := -1
		for index, tab := range snapshot.Tabs {
			if !tab.Active {
				continue
			}
			if active != -1 || tab.URL == "" {
				return nil, 0, recordDropped
			}
			active = index
		}
		if active == -1 {
			return nil, 0, recordDropped
		}
		tab := snapshot.Tabs[active]
		location, _ := json.Marshal(struct {
			Type         string `json:"type"`
			URL          string `json:"url"`
			Title        string `json:"title,omitempty"`
			CanGoBack    *bool  `json:"canGoBack,omitempty"`
			CanGoForward *bool  `json:"canGoForward,omitempty"`
		}{Type: "url", URL: tab.URL, Title: tab.Title, CanGoBack: tab.CanGoBack, CanGoForward: tab.CanGoForward})
		return location, 0, recordVisual
	case "error":
		return nil, 0, recordFailed
	case "finished":
		return nil, 0, recordFinished
	case "unavailable":
		// The toolbox's own report of a driver failure, exactly as it writes it.
		if bytes.Equal(body, unavailableRecord) {
			return nil, 0, recordFailed
		}
		return nil, 0, recordDropped
	default:
		return nil, 0, recordDropped
	}
}

// presentationRecord is the driver's answer to a presentation request.
func presentationRecord(message []byte) ([]byte, bool) {
	if len(message) > 4096 {
		return nil, false
	}
	var value struct {
		Type      string `json:"type"`
		Role      string `json:"role"`
		Requested struct {
			Width  uint32 `json:"width"`
			Height uint32 `json:"height"`
		} `json:"requested"`
		Applied *surface `json:"applied,omitempty"`
		Error   string   `json:"error,omitempty"`
	}
	if json.Unmarshal(message, &value) != nil || value.Type != "presentation" ||
		(value.Role != "primary" && value.Role != "secondary") ||
		value.Requested.Width == 0 || value.Requested.Width > 2048 || value.Requested.Height == 0 || value.Requested.Height > 2048 ||
		(value.Applied != nil && !value.Applied.valid()) || (value.Error != "" && value.Error != "viewport_unavailable") {
		return nil, false
	}
	result, err := json.Marshal(value)
	return result, err == nil
}

// activityRecord projects the finite visual fields of acknowledged input,
// never keyboard data or task payloads.
func activityRecord(message []byte) ([]byte, bool) {
	if len(message) > 8192 {
		return nil, false
	}
	var value struct {
		Type              string   `json:"type"`
		PageGeneration    string   `json:"pageGeneration"`
		Source            string   `json:"source"`
		EventType         string   `json:"eventType"`
		Kind              string   `json:"kind"`
		Timestamp         *float64 `json:"timestamp"`
		Ts                *float64 `json:"ts"`
		X                 *float64 `json:"x"`
		Y                 *float64 `json:"y"`
		Buttons           *int     `json:"buttons"`
		Modifiers         *int     `json:"modifiers"`
		CoordinateSpace   string   `json:"coordinateSpace"`
		SurfaceGeneration string   `json:"surfaceGeneration"`
	}
	if json.Unmarshal(message, &value) != nil || len(value.PageGeneration) == 0 || len(value.PageGeneration) > 256 || !boundedNumber(value.Timestamp, 0, math.MaxFloat64) {
		return nil, false
	}
	projected := map[string]any{"type": value.Type, "pageGeneration": value.PageGeneration, "timestamp": *value.Timestamp}
	if value.Ts != nil {
		if !boundedNumber(value.Ts, 0, 1<<53-1) || *value.Ts != math.Trunc(*value.Ts) {
			return nil, false
		}
		projected["ts"] = *value.Ts
	}
	if value.CoordinateSpace != "" {
		if value.CoordinateSpace != "viewport-css" && value.CoordinateSpace != "display-pixels" {
			return nil, false
		}
		projected["coordinateSpace"] = value.CoordinateSpace
	}
	if value.CoordinateSpace == "display-pixels" {
		if value.Type != "pointer" || value.Source != "agent" || !validUUID(value.SurfaceGeneration) || !boundedNumber(value.X, 0, 4096) || !boundedNumber(value.Y, 0, 4096) {
			return nil, false
		}
		projected["surfaceGeneration"] = value.SurfaceGeneration
	}
	if value.Type == "pointer" && value.EventType == "reset" {
		projected["eventType"] = "reset"
	} else {
		if value.Source != "agent" && value.Source != "human" {
			return nil, false
		}
		projected["source"] = value.Source
		switch value.Type {
		case "pointer":
			switch value.EventType {
			case "move", "press", "release", "scroll":
			default:
				return nil, false
			}
			if !boundedNumber(value.X, 0, 32768) || !boundedNumber(value.Y, 0, 32768) || value.Buttons == nil || *value.Buttons < 0 || *value.Buttons > 31 || value.Modifiers == nil || *value.Modifiers < 0 || *value.Modifiers > 15 {
				return nil, false
			}
			projected["eventType"] = value.EventType
			projected["x"], projected["y"] = *value.X, *value.Y
			projected["buttons"], projected["modifiers"] = *value.Buttons, *value.Modifiers
		case "activity":
			if value.Kind != "typing" && value.Kind != "scrolling" {
				return nil, false
			}
			projected["kind"] = value.Kind
		default:
			return nil, false
		}
	}
	body, err := json.Marshal(projected)
	return body, err == nil
}

func boundedNumber(value *float64, minimum, maximum float64) bool {
	return value != nil && !math.IsNaN(*value) && !math.IsInf(*value, 0) && *value >= minimum && *value <= maximum
}

const (
	// cursorRecordLimit bounds one cursor record, image included.
	cursorRecordLimit = 96 << 10
	// cursorImageLimit bounds a page's own cursor image: Chromium draws custom
	// cursors of at most 128x128 CSS pixels, 256x256 at the stream's scale.
	cursorImageLimit = 64 << 10
	cursorSideLimit  = 256
)

// cursorKeywords are the CSS cursor keywords a remote cursor resolves to.
var cursorKeywords = []string{
	"default", "none", "context-menu", "help", "pointer", "progress", "wait", "cell", "crosshair", "text",
	"vertical-text", "alias", "copy", "move", "no-drop", "not-allowed", "grab", "grabbing", "all-scroll",
	"col-resize", "row-resize", "n-resize", "e-resize", "s-resize", "w-resize", "ne-resize", "nw-resize",
	"se-resize", "sw-resize", "ew-resize", "ns-resize", "nesw-resize", "nwse-resize", "zoom-in", "zoom-out",
}

type cursorImage struct {
	Hash   string `json:"hash"`
	Width  uint32 `json:"width"`
	Height uint32 `json:"height"`
	HotX   uint32 `json:"hotX"`
	HotY   uint32 `json:"hotY"`
	Scale  uint32 `json:"scale"`
	// A viewer caches images by hash, so a repeated image may omit its bytes.
	PNG []byte `json:"png,omitempty"`
}

// cursorRecord projects the remote pointer's state: one CSS keyword, or one
// page-supplied image with its hotspot and a null keyword.
func cursorRecord(message []byte) ([]byte, bool) {
	if len(message) > cursorRecordLimit {
		return nil, false
	}
	var value struct {
		Type   string       `json:"type"`
		Ts     *uint64      `json:"ts"`
		Serial *uint32      `json:"serial"`
		CSS    *string      `json:"css"`
		Image  *cursorImage `json:"image,omitempty"`
	}
	if json.Unmarshal(message, &value) != nil || value.Type != "cursor" || value.Ts == nil || *value.Ts > safeInteger || value.Serial == nil {
		return nil, false
	}
	if (value.CSS == nil) == (value.Image == nil) || (value.CSS != nil && !slices.Contains(cursorKeywords, *value.CSS)) || (value.Image != nil && !value.Image.valid()) {
		return nil, false
	}
	body, err := json.Marshal(value)
	return body, err == nil
}

func (i *cursorImage) valid() bool {
	if len(i.Hash) < 16 || len(i.Hash) > 64 || !lowerHex(i.Hash) ||
		i.Width == 0 || i.Width > cursorSideLimit || i.Height == 0 || i.Height > cursorSideLimit ||
		i.HotX >= i.Width || i.HotY >= i.Height || (i.Scale != 1 && i.Scale != 2) || len(i.PNG) > cursorImageLimit {
		return false
	}
	if i.PNG == nil {
		return true
	}
	config, err := png.DecodeConfig(bytes.NewReader(i.PNG))
	return err == nil && config.Width == int(i.Width) && config.Height == int(i.Height)
}

func lowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
