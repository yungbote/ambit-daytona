// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// The browser's display raster is distinct from a CDP page viewport. Only
// these finite fields cross the visual relay; native XIDs and helper paths do
// not belong in a viewer's contract.
type browserSurface struct {
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

func (s *browserSurface) valid() bool {
	return s != nil && s.Kind == "browser-window" && s.CoordinateSpace == "display-pixels" &&
		validBrowserUUID(s.Generation) &&
		s.Width > 0 && s.Width <= 4096 && s.Height > 0 && s.Height <= 4096 &&
		s.OriginX == 0 && s.OriginY == 0 && s.DeviceScaleFactor == 2 && s.CursorIncluded != nil
}

type browserPresentation struct {
	Viewer string
	Width  uint32
	Height uint32
}

func parseBrowserPresentation(request *http.Request) (*browserPresentation, bool) {
	query := request.URL.Query()
	viewer := request.Header.Get("X-Ambit-Browser-Viewer")
	if viewer == "" && !query.Has("width") && !query.Has("height") {
		return nil, true
	}
	if !validBrowserUUID(viewer) ||
		len(query["width"]) != 1 || len(query["height"]) != 1 {
		return nil, false
	}
	width, widthError := strconv.ParseUint(query.Get("width"), 10, 32)
	height, heightError := strconv.ParseUint(query.Get("height"), 10, 32)
	if widthError != nil || heightError != nil || width == 0 || width > 2048 || height == 0 || height > 2048 {
		return nil, false
	}
	return &browserPresentation{Viewer: viewer, Width: uint32(width), Height: uint32(height)}, true
}

func browserPresentationMessage(message []byte) ([]byte, bool) {
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
		Applied *browserSurface `json:"applied,omitempty"`
		Error   string          `json:"error,omitempty"`
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

// Deltas remain bounded visual data. Their exact base is required so a viewer
// can reject a broken chain instead of silently retaining stale pixels.
type browserFramePatch struct {
	browserPatchBounds
	Data string `json:"data"`
}

func (p browserFramePatch) valid(s browserSurface) bool {
	return p.Data != "" && p.browserPatchBounds.valid(s)
}

// The region and crop have the same meaning for JSON and binary JPEG frames.
type browserPatchBounds struct {
	SourceX uint32 `json:"sourceX"`
	SourceY uint32 `json:"sourceY"`
	X       uint32 `json:"x"`
	Y       uint32 `json:"y"`
	Width   uint32 `json:"width"`
	Height  uint32 `json:"height"`
}

func (p browserPatchBounds) valid(s browserSurface) bool {
	return p.SourceX <= 16 && p.SourceY <= 16 && p.X < s.Width && p.Y < s.Height &&
		p.X%16 == 0 && p.Y%16 == 0 && p.Width > 0 && p.Height > 0 &&
		p.Width <= 512 && p.Height <= 512 &&
		p.Width <= s.Width-p.X && p.Height <= s.Height-p.Y &&
		(p.Width%16 == 0 || p.X+p.Width == s.Width) &&
		(p.Height%16 == 0 || p.Y+p.Height == s.Height)
}
