// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"bytes"
	"encoding/json"
	"image/png"
	"slices"
)

// browserCursorRecordLimit bounds one cursor record, image included.
const browserCursorRecordLimit = 96 << 10

// browserCursorImageLimit bounds a page's own cursor image. Chromium draws
// custom cursors of at most 128×128 CSS pixels, 256×256 at the stream's scale.
const (
	browserCursorImageLimit = 64 << 10
	browserCursorSideLimit  = 256
)

// browserCursorKeywords are the CSS cursor keywords a remote cursor can
// resolve to. "auto" is not among them: the remote display has already
// resolved it.
var browserCursorKeywords = []string{
	"default", "none", "context-menu", "help", "pointer", "progress", "wait", "cell", "crosshair", "text",
	"vertical-text", "alias", "copy", "move", "no-drop", "not-allowed", "grab", "grabbing", "all-scroll",
	"col-resize", "row-resize", "n-resize", "e-resize", "s-resize", "w-resize", "ne-resize", "nw-resize",
	"se-resize", "sw-resize", "ew-resize", "ns-resize", "nesw-resize", "nwse-resize", "zoom-in", "zoom-out",
}

type browserCursorImage struct {
	Hash   string `json:"hash"`
	Width  uint32 `json:"width"`
	Height uint32 `json:"height"`
	HotX   uint32 `json:"hotX"`
	HotY   uint32 `json:"hotY"`
	Scale  uint32 `json:"scale"`
	// A viewer caches images by hash, so a repeated image may omit its bytes.
	// encoding/json admits only valid base64 and re-encodes it.
	PNG []byte `json:"png,omitempty"`
}

// browserCursor projects the remote pointer's state: exactly one CSS keyword,
// or one page-supplied image with its hotspot and a null keyword, stamped with
// the capture clock and the display's cursor serial. Anything outside those
// bounds drops the whole record rather than any part of it.
func browserCursor(message []byte) ([]byte, bool) {
	if len(message) > browserCursorRecordLimit {
		return nil, false
	}
	var value struct {
		Type   string              `json:"type"`
		Ts     *uint64             `json:"ts"`
		Serial *uint32             `json:"serial"`
		CSS    *string             `json:"css"`
		Image  *browserCursorImage `json:"image,omitempty"`
	}
	if json.Unmarshal(message, &value) != nil || value.Type != "cursor" || value.Ts == nil || *value.Ts > browserSafeInteger || value.Serial == nil {
		return nil, false
	}
	if (value.CSS == nil) == (value.Image == nil) || (value.CSS != nil && !slices.Contains(browserCursorKeywords, *value.CSS)) || (value.Image != nil && !value.Image.valid()) {
		return nil, false
	}
	body, err := json.Marshal(value)
	return body, err == nil
}

func (i *browserCursorImage) valid() bool {
	if len(i.Hash) < 16 || len(i.Hash) > 64 || !lowerHex(i.Hash) ||
		i.Width == 0 || i.Width > browserCursorSideLimit || i.Height == 0 || i.Height > browserCursorSideLimit ||
		i.HotX >= i.Width || i.HotY >= i.Height || (i.Scale != 1 && i.Scale != 2) || len(i.PNG) > browserCursorImageLimit {
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
