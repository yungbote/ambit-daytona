// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package control

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func frame(event string) []byte {
	return []byte(`{"type":"control","op":"input","sequence":1,"events":[` + event + `]}`)
}

func TestInputVocabularyAndAuthorityFields(t *testing.T) {
	for _, event := range []string{
		`{"type":"input_mouse","eventType":"mouseMoved","x":0,"y":32768}`,
		`{"type":"input_mouse","eventType":"mouseWheel","x":1.5,"y":2,"deltaX":-32768,"deltaY":32768,"modifiers":15}`,
		`{"type":"input_keyboard","eventType":"char","text":"🙂a"}`,
		`{"type":"input_keyboard","eventType":"char","text":"\u0000"}`,
		`{"type":"input_keyboard","eventType":"insertText","text":"\u0000"}`,
		`{"type":"input_keyboard","eventType":"keyDown","key":"Enter","code":"Enter","windowsVirtualKeyCode":255}`,
		`{"type":"input_keyboard","eventType":"insertText","text":"<b>🙂\\</b>"}`,
		`{"type":"input_touch","eventType":"touchStart","touchPoints":[{"id":1,"x":0,"y":32768,"radiusX":3,"force":1,"rotationAngle":360}]}`,
		`{"type":"input_touch","eventType":"touchEnd","touchPoints":[]}`,
		`{"type":"viewport","width":1,"height":2048}`,
		`{"type":"navigation","action":"navigate","url":"https://example.test"}`,
		`{"type":"navigation","action":"navigate","url":"\u0085"}`,
		`{"type":"navigation","action":"back"}`,
	} {
		input, err := Read(frame(event))
		if err != nil {
			t.Fatalf("valid input %s: %v", event, err)
		}
		command := input.Command("controller-from-grant")
		var value map[string]any
		if json.Unmarshal(command, &value) != nil || value["op"] != "input" || value["controllerId"] != "controller-from-grant" || value["action"] != nil || value["expiresAt"] != nil {
			t.Fatalf("command crosses authority: %s", command)
		}
	}
	for _, event := range []string{
		`{"type":"sign_in","idleTimeoutMs":600000}`,
		`{"type":"input_mouse","eventType":"mouseMoved","x":-1,"y":0}`,
		`{"type":"input_mouse","eventType":"mouseMoved","x":0,"y":0,"modifiers":16}`,
		`{"type":"input_mouse","eventType":"mouseMoved","x":0,"y":0,"buttons":32}`,
		`{"type":"input_mouse","eventType":"mouseMoved","x":0,"y":0,"action":"acquire"}`,
		`{"type":"input_keyboard","eventType":"insertText","text":"x","modifiers":0}`,
		`{"type":"input_keyboard","eventType":"keyDown","key":"\ud800"}`,
		`{"type":"input_keyboard","eventType":"char","text":"🙂🙂"}`,
		`{"type":"input_keyboard","eventType":"keyDown","code":"Enter"}`,
		`{"type":"input_touch","eventType":"touchStart","touchPoints":[]}`,
		`{"type":"input_touch","eventType":"touchEnd","touchPoints":null}`,
		`{"type":"input_touch","eventType":"touchStart","touchPoints":[{"id":1,"x":0,"y":0},{"id":1,"x":0,"y":0}]}`,
		`{"type":"viewport","width":2049,"height":1}`,
		`{"type":"navigation","action":"back","url":"https://example.test"}`,
		`{"type":"navigation","action":"navigate","url":" \uFEFF "}`,
	} {
		if _, err := Read(frame(event)); err == nil {
			t.Fatalf("invalid event admitted: %s", event)
		}
	}
	valid := string(frame(`{"type":"navigation","action":"reload"}`))
	for _, raw := range []string{
		valid + `null`, valid + `!`, strings.Replace(valid, `"sequence":1`, `"sequence":1,"sequence":2`, 1),
		strings.Replace(valid, `"sequence":1`, `"sequence":0`, 1), strings.Replace(valid, `"sequence":1`, `"sequence":9007199254740992`, 1),
		strings.Replace(valid, `"op":"input"`, `"op":"acquire"`, 1), strings.Replace(valid, `"op":"input"`, `"op":"input","controllerId":"forged"`, 1),
	} {
		if _, err := Read([]byte(raw)); err == nil {
			t.Fatalf("invalid frame admitted: %s", raw)
		}
	}
}

func TestOnlyOneBoundedWindowPasteMayExceedCommandLimit(t *testing.T) {
	value := func(text string, surface bool, events int) []byte {
		event, _ := json.Marshal(map[string]any{"type": "input_keyboard", "eventType": "insertText", "text": text})
		items := make([]json.RawMessage, events)
		for n := range items {
			items[n] = event
		}
		m := map[string]any{"type": "control", "op": "input", "sequence": 1, "events": items}
		if surface {
			m["expectedSurfaceGeneration"] = "00000000-1111-4222-8333-444444444444"
		}
		raw, _ := json.Marshal(m)
		return raw
	}
	for _, text := range []string{strings.Repeat("x", MaxPasteBytes), strings.Repeat("\x00", MaxPasteBytes)} {
		if _, err := Read(value(text, true, 1)); err != nil {
			t.Fatalf("maximum UTF-8 paste refused: %v", err)
		}
		if _, err := Read(value(text, false, 1)); err == nil {
			t.Fatal("oversized paste without painted window admitted")
		}
		if _, err := Read(value(text, true, 2)); err == nil {
			t.Fatal("oversized multi-event command admitted")
		}
	}
	if _, err := Read(value(strings.Repeat("x", MaxPasteBytes+1), true, 1)); err == nil {
		t.Fatal("paste over1MiB admitted")
	}
	if _, err := Read(bytes.Repeat([]byte{' '}, MaxRequestBytes+1)); err == nil {
		t.Fatal("request bound ignored")
	}
}

func FuzzReadNeverPanics(f *testing.F) {
	f.Add(frame(`{"type":"input_keyboard","eventType":"char","text":"x"}`))
	f.Add(frame(`{"type":"input_keyboard","eventType":"char","text":"\ud800"}`))
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = Read(raw) })
}

func TestBackendInputContractVectors(t *testing.T) {
	path := os.Getenv("MEDIA_EDGE_CONTROL_VECTORS")
	if path == "" {
		t.Skip("MEDIA_EDGE_CONTROL_VECTORS required for the cross-language gate")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name  string
		Valid bool
		Body  map[string]json.RawMessage
	}
	if err := json.Unmarshal(raw, &vectors); err != nil || len(vectors) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			vector.Body["type"], vector.Body["op"] = json.RawMessage(`"control"`), json.RawMessage(`"input"`)
			raw, _ := json.Marshal(vector.Body)
			_, err := Read(raw)
			if (err == nil) != vector.Valid {
				t.Fatalf("admitted %v, expected %v: %s", err == nil, vector.Valid, raw)
			}
		})
	}
}
