// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"encoding/json"
	"math"
)

// The driver emits these records only after acknowledged input. Project the
// finite visual fields instead of forwarding keyboard data or task payloads.
func browserActivity(message []byte) ([]byte, bool) {
	if len(message) > 8192 {
		return nil, false
	}
	var value struct {
		Type           string   `json:"type"`
		PageGeneration string   `json:"pageGeneration"`
		Source         string   `json:"source"`
		EventType      string   `json:"eventType"`
		Kind           string   `json:"kind"`
		Timestamp      *float64 `json:"timestamp"`
		X              *float64 `json:"x"`
		Y              *float64 `json:"y"`
		Buttons        *int     `json:"buttons"`
		Modifiers      *int     `json:"modifiers"`
	}
	if json.Unmarshal(message, &value) != nil || len(value.PageGeneration) == 0 || len(value.PageGeneration) > 256 || !boundedBrowserNumber(value.Timestamp, 0, math.MaxFloat64) {
		return nil, false
	}
	projected := map[string]any{"type": value.Type, "pageGeneration": value.PageGeneration, "timestamp": *value.Timestamp}
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
			if value.Kind != "typing" {
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
