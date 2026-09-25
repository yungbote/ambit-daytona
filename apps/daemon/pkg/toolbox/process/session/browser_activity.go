// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"encoding/json"
	"github.com/google/uuid"
	"math"
)

func validBrowserUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// The driver emits these records only after acknowledged input. Project the
// finite visual fields instead of forwarding keyboard data or task payloads.
func browserActivity(message []byte) ([]byte, bool) {
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
	if json.Unmarshal(message, &value) != nil || len(value.PageGeneration) == 0 || len(value.PageGeneration) > 256 || !boundedBrowserNumber(value.Timestamp, 0, math.MaxFloat64) {
		return nil, false
	}
	projected := map[string]any{"type": value.Type, "pageGeneration": value.PageGeneration, "timestamp": *value.Timestamp}
	// The capture clock (sandbox monotonic microseconds) of the executed input.
	if value.Ts != nil {
		if !boundedBrowserNumber(value.Ts, 0, 1<<53-1) || *value.Ts != math.Trunc(*value.Ts) {
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
		if value.Type != "pointer" || value.Source != "agent" || !validBrowserUUID(value.SurfaceGeneration) || !boundedBrowserNumber(value.X, 0, 4096) || !boundedBrowserNumber(value.Y, 0, 4096) {
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
			if !boundedBrowserNumber(value.X, 0, 32768) || !boundedBrowserNumber(value.Y, 0, 32768) || value.Buttons == nil || *value.Buttons < 0 || *value.Buttons > 31 || value.Modifiers == nil || *value.Modifiers < 0 || *value.Modifiers > 15 {
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

func boundedBrowserNumber(value *float64, minimum, maximum float64) bool {
	return value != nil && !math.IsNaN(*value) && !math.IsInf(*value, 0) && *value >= minimum && *value <= maximum
}
