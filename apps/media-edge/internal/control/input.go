// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package control admits only the person's input vocabulary. Lease changes,
// sign-in, files and clipboard reads remain backend-authored operations.
package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	MaxPending      = 64
	MaxPasteBytes   = 1 << 20
	MaxRequestBytes = 6*MaxPasteBytes + 8192
	MaxReplyBytes   = 8192
	MaxCommandBytes = 65536
)

var ErrInvalid = errors.New("control: invalid input frame")
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const javascriptWhitespace = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"

// IsFrame distinguishes the control vocabulary before its full validation;
// the wider paste bound never applies to ordinary viewer messages.
func IsFrame(raw []byte) bool {
	var v struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(raw, &v) == nil && v.Type == "control"
}

// Attach asks to open the already-granted control route, without input.
func Attach(raw []byte) bool {
	m, ok := object(raw, []string{"type", "op"})
	return ok && len(m) == 2 && text(m["type"]) == "control" && text(m["op"]) == "attach"
}

// Input is input whose controller is supplied by the session's grant.
type Input struct {
	Sequence uint64
	Events   []json.RawMessage
	Surface  string
}

// Read accepts the same closed input vocabulary as the backend input DTO.
// Large input is only one full-window paste; every other command fits 64KiB.
func Read(raw []byte) (Input, error) {
	if len(raw) > MaxRequestBytes || !utf8.Valid(raw) {
		return Input{}, ErrInvalid
	}
	m, ok := object(raw, []string{"type", "op", "sequence", "events", "expectedSurfaceGeneration"})
	if !ok || text(m["type"]) != "control" || text(m["op"]) != "input" {
		return Input{}, ErrInvalid
	}
	seq, ok := number(m["sequence"], 1, 9007199254740991, true)
	if !ok {
		return Input{}, ErrInvalid
	}
	var events []json.RawMessage
	if json.Unmarshal(m["events"], &events) != nil || len(events) == 0 || len(events) > 64 {
		return Input{}, ErrInvalid
	}
	surface := ""
	if v, present := m["expectedSurfaceGeneration"]; present {
		surface = text(v)
		if !uuid.MatchString(surface) {
			return Input{}, ErrInvalid
		}
	}
	for _, e := range events {
		if !event(e) {
			return Input{}, ErrInvalid
		}
	}
	i := Input{uint64(seq), events, surface}
	// Include the native writer's action member and newline in the bound.
	command := i.Command("ffffffff-ffff-4fff-8fff-ffffffffffff")
	if len(command)+len(`,"action":"ambit_browser_control"`)+1 > MaxCommandBytes {
		if surface == "" || len(events) != 1 {
			return Input{}, ErrInvalid
		}
		m, _ := object(events[0], []string{"type", "eventType", "text"})
		if text(m["type"]) != "input_keyboard" || text(m["eventType"]) != "insertText" {
			return Input{}, ErrInvalid
		}
	}
	return i, nil
}

// Command constructs the only operation this path permits, using the grant's
// controller. No client field can acquire, release or extend a lease.
func (i Input) Command(controller string) []byte {
	v := struct {
		Op         string            `json:"op"`
		Controller string            `json:"controllerId"`
		Sequence   uint64            `json:"sequence"`
		Events     []json.RawMessage `json:"events"`
		Surface    string            `json:"expectedSurfaceGeneration,omitempty"`
	}{"input", controller, i.Sequence, i.Events, i.Surface}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}

func object(raw []byte, keys []string) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	m := map[string]json.RawMessage{}
	for d.More() {
		key, err := d.Token()
		k, ok := key.(string)
		if err != nil || !ok || !slices.Contains(keys, k) {
			return nil, false
		}
		if _, exists := m[k]; exists {
			return nil, false
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return nil, false
		}
		m[k] = v
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	return m, true
}

func text(raw []byte) string { value, _ := readText(raw); return value }

func readText(raw []byte) (string, bool) {
	var value string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	// encoding/json replaces unpaired UTF-16 escapes; input must be lossless.
	for n := 1; n < len(raw)-1; n++ {
		if raw[n] != '\\' {
			continue
		}
		n++
		if raw[n] != 'u' {
			continue
		}
		v, err := strconv.ParseUint(string(raw[n+1:n+5]), 16, 16)
		if err != nil {
			return "", false
		}
		n += 4
		if 0xdc00 <= v && v <= 0xdfff {
			return "", false
		}
		if 0xd800 <= v && v <= 0xdbff {
			if n+6 >= len(raw) || raw[n+1] != '\\' || raw[n+2] != 'u' {
				return "", false
			}
			low, err := strconv.ParseUint(string(raw[n+3:n+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return "", false
			}
			n += 6
		}
	}
	return value, true
}

func number(raw []byte, min, max float64, integer bool) (float64, bool) {
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return 0, false
	}
	v, err := strconv.ParseFloat(string(raw), 64)
	return v, err == nil && !math.IsNaN(v) && min <= v && v <= max && (!integer || math.Trunc(v) == v)
}

func optionalNumbers(m map[string]json.RawMessage, names []string, min, max float64, integer bool) bool {
	for _, name := range names {
		if raw, present := m[name]; present {
			if _, ok := number(raw, min, max, integer); !ok {
				return false
			}
		}
	}
	return true
}

func event(raw []byte) bool {
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil {
		return false
	}
	var keys []string
	switch kind.Type {
	case "input_mouse":
		keys = []string{"type", "eventType", "x", "y", "button", "buttons", "clickCount", "deltaX", "deltaY", "modifiers"}
	case "input_keyboard":
		keys = []string{"type", "eventType", "key", "code", "text", "windowsVirtualKeyCode", "modifiers"}
	case "input_touch":
		keys = []string{"type", "eventType", "touchPoints", "modifiers"}
	case "viewport":
		keys = []string{"type", "width", "height"}
	case "navigation":
		keys = []string{"type", "action", "url"}
	default:
		return false
	}
	m, ok := object(raw, keys)
	if !ok || !optionalNumbers(m, []string{"modifiers"}, 0, 15, true) {
		return false
	}
	e := text(m["eventType"])
	switch kind.Type {
	case "input_mouse":
		if !slices.Contains([]string{"mouseMoved", "mousePressed", "mouseReleased", "mouseWheel"}, e) {
			return false
		}
		for _, k := range []string{"x", "y"} {
			if _, ok := number(m[k], 0, 32768, false); !ok {
				return false
			}
		}
		if button, present := m["button"]; present && !slices.Contains([]string{"none", "left", "middle", "right", "back", "forward"}, text(button)) {
			return false
		}
		return optionalNumbers(m, []string{"buttons"}, 0, 31, true) && optionalNumbers(m, []string{"clickCount"}, 0, 3, true) && optionalNumbers(m, []string{"deltaX", "deltaY"}, -32768, 32768, false)
	case "input_keyboard":
		if e == "insertText" {
			value, valid := readText(m["text"])
			return len(m) == 3 && valid && len(value) > 0 && len(value) <= MaxPasteBytes
		}
		if !slices.Contains([]string{"keyDown", "keyUp", "rawKeyDown", "char"}, e) {
			return false
		}
		for _, k := range []string{"key", "code"} {
			if v, present := m[k]; present {
				value, valid := readText(v)
				if !valid || len(value) > 256 {
					return false
				}
			}
		}
		if v, present := m["text"]; present {
			value, valid := readText(v)
			if !valid || len(utf16.Encode([]rune(value))) > 3 {
				return false
			}
		}
		key, content := text(m["key"]), text(m["text"])
		return (key != "" || content != "") && optionalNumbers(m, []string{"windowsVirtualKeyCode"}, 0, 255, true)
	case "input_touch":
		if !slices.Contains([]string{"touchStart", "touchMove", "touchEnd", "touchCancel"}, e) {
			return false
		}
		var points []json.RawMessage
		if len(m["touchPoints"]) == 0 || m["touchPoints"][0] != '[' || json.Unmarshal(m["touchPoints"], &points) != nil || len(points) > 10 {
			return false
		}
		if (e == "touchStart" || e == "touchMove") != (len(points) > 0) {
			return false
		}
		ids := map[float64]bool{}
		for _, p := range points {
			point, ok := object(p, []string{"id", "x", "y", "radiusX", "radiusY", "rotationAngle", "force"})
			if !ok {
				return false
			}
			id, ok := number(point["id"], 0, 2147483647, true)
			if !ok || ids[id] {
				return false
			}
			ids[id] = true
			for _, k := range []string{"x", "y"} {
				if _, ok := number(point[k], 0, 32768, false); !ok {
					return false
				}
			}
			if !optionalNumbers(point, []string{"radiusX", "radiusY"}, 0, 32768, false) || !optionalNumbers(point, []string{"rotationAngle"}, 0, 360, false) || !optionalNumbers(point, []string{"force"}, 0, 1, false) {
				return false
			}
		}
		return true
	case "viewport":
		for _, k := range []string{"width", "height"} {
			if _, ok := number(m[k], 1, 2048, true); !ok {
				return false
			}
		}
		return true
	case "navigation":
		action := text(m["action"])
		if action == "navigate" {
			value, valid := readText(m["url"])
			return valid && len(strings.Trim(value, javascriptWhitespace)) > 0
		}
		_, url := m["url"]
		return !url && slices.Contains([]string{"back", "forward", "reload"}, action)
	}
	return false
}
