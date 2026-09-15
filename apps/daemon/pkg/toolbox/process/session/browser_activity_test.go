// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBrowserActivityProjectsOnlyVisualInput(t *testing.T) {
	for _, input := range []string{
		`{"type":"pointer","pageGeneration":"page-2","source":"agent","eventType":"press","x":20,"y":30,"buttons":1,"modifiers":0,"timestamp":12,"text":"private-input"}`,
		`{"type":"activity","pageGeneration":"page-2","source":"human","kind":"typing","timestamp":13,"key":"private-input","code":"private-input","text":"private-input"}`,
		`{"type":"pointer","pageGeneration":"page-3","eventType":"reset","timestamp":14,"source":"private-input"}`,
	} {
		body, valid := browserActivity([]byte(input))
		if !valid || strings.Contains(string(body), "private-input") {
			t.Fatalf("invalid public activity projection: %s", body)
		}
		var value map[string]any
		if json.Unmarshal(body, &value) != nil || value["pageGeneration"] == nil || value["timestamp"] == nil {
			t.Fatalf("lost activity identity: %s", body)
		}
	}
}

func TestBrowserActivityRefusesUnidentifiedOrMalformedInput(t *testing.T) {
	for _, input := range []string{
		`{"type":"activity","source":"agent","kind":"typing","timestamp":1}`,
		`{"type":"activity","pageGeneration":"p","source":"website","kind":"typing","timestamp":1}`,
		`{"type":"activity","pageGeneration":"p","source":"agent","kind":"text","timestamp":1}`,
		`{"type":"pointer","pageGeneration":"p","source":"agent","eventType":"click","x":1,"y":2,"buttons":1,"modifiers":0,"timestamp":1}`,
		`{"type":"pointer","pageGeneration":"p","source":"agent","eventType":"press","x":-1,"y":2,"buttons":1,"modifiers":0,"timestamp":1}`,
		`{"type":"pointer","pageGeneration":"p","source":"agent","eventType":"press","x":1,"y":2,"buttons":1.5,"modifiers":0,"timestamp":1}`,
		`{"type":"pointer","pageGeneration":"p","source":"agent","eventType":"press","x":1,"y":2,"buttons":1,"modifiers":16,"timestamp":1}`,
		`{"type":"pointer","pageGeneration":"p","eventType":"reset","timestamp":-1}`,
	} {
		if _, valid := browserActivity([]byte(input)); valid {
			t.Fatalf("invalid activity was accepted: %s", input)
		}
	}
}
