// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"math"
	"strings"
	"unicode/utf8"

	"github.com/robotn/xgb/xproto"
	"github.com/robotn/xgb/xtest"
	"github.com/robotn/xgbutil"
	"github.com/robotn/xgbutil/keybind"
)

type inputEvent struct {
	Type                  string  `json:"type"`
	EventType             string  `json:"eventType"`
	X                     float64 `json:"x,omitempty"`
	Y                     float64 `json:"y,omitempty"`
	Button                string  `json:"button,omitempty"`
	Buttons               int     `json:"buttons,omitempty"`
	ClickCount            int     `json:"clickCount,omitempty"`
	DeltaX                float64 `json:"deltaX,omitempty"`
	DeltaY                float64 `json:"deltaY,omitempty"`
	Modifiers             int     `json:"modifiers,omitempty"`
	Key                   string  `json:"key,omitempty"`
	Code                  string  `json:"code,omitempty"`
	Text                  string  `json:"text,omitempty"`
	WindowsVirtualKeyCode int     `json:"windowsVirtualKeyCode,omitempty"`
}

func (d *display) loadKeys() error {
	setup := xproto.Setup(d.conn)
	reply, err := xproto.GetKeyboardMapping(d.conn, setup.MinKeycode, byte(int(setup.MaxKeycode)-int(setup.MinKeycode)+1)).Reply()
	if err != nil {
		return err
	}
	keyboard, err := xgbutil.NewConnXgb(d.conn)
	if err != nil {
		return err
	}
	keybind.KeyMapSet(keyboard, reply)
	d.keyboard = keyboard
	d.keysyms = map[string]byte{}
	return nil
}

// Forward names are canonical. The library's reverse map deliberately chooses
// an arbitrary alias, so using it for input could lose F11 to L1 or period to '.'.
func (d *display) nativeKey(name string) byte {
	cacheName := strings.ToLower(name)
	if code := d.keysyms[cacheName]; code != 0 {
		return code
	}
	if d.keyboard == nil {
		return 0
	}
	codes := keybind.StrToKeycodes(d.keyboard, name)
	if len(codes) == 0 {
		return 0
	}
	code := byte(codes[0])
	d.keysyms[cacheName] = code
	return code
}

var physicalNames = map[string]string{
	"Backquote": "grave", "Minus": "minus", "Equal": "equal", "BracketLeft": "bracketleft", "BracketRight": "bracketright", "Backslash": "backslash", "Semicolon": "semicolon", "Quote": "apostrophe", "Comma": "comma", "Period": "period", "Slash": "slash", "Space": "space",
	"ShiftLeft": "Shift_L", "ShiftRight": "Shift_R", "ControlLeft": "Control_L", "ControlRight": "Control_R", "AltLeft": "Alt_L", "AltRight": "Alt_R", "MetaLeft": "Super_L", "MetaRight": "Super_R", "CapsLock": "Caps_Lock", "NumLock": "Num_Lock", "ScrollLock": "Scroll_Lock", "ContextMenu": "Menu",
	"Enter": "Return", "NumpadEnter": "KP_Enter", "Backspace": "BackSpace", "Escape": "Escape", "Tab": "Tab", "Delete": "Delete", "Insert": "Insert", "Home": "Home", "End": "End", "PageUp": "Prior", "PageDown": "Next", "ArrowLeft": "Left", "ArrowRight": "Right", "ArrowUp": "Up", "ArrowDown": "Down",
	"NumpadAdd": "KP_Add", "NumpadSubtract": "KP_Subtract", "NumpadMultiply": "KP_Multiply", "NumpadDivide": "KP_Divide", "NumpadDecimal": "KP_Decimal", "NumpadEqual": "KP_Equal",
}

func (d *display) keycode(event inputEvent) byte {
	name := event.Code
	if mapped, ok := physicalNames[name]; ok {
		name = mapped
	} else if len(name) == 4 && strings.HasPrefix(name, "Key") {
		name = name[3:]
	} else if len(name) == 6 && strings.HasPrefix(name, "Digit") {
		name = name[5:]
	} else if len(name) == 7 && strings.HasPrefix(name, "Numpad") {
		name = "KP_" + name[6:]
	} else if name == "" || name == "Unidentified" {
		name = event.Key
		if mapped, ok := physicalNames[name]; ok {
			name = mapped
		}
		if name == " " {
			name = "space"
		}
	}
	return d.nativeKey(name)
}
func (d *display) validateEvent(event inputEvent, width, height int) error {
	if event.Modifiers < 0 || event.Modifiers > 15 {
		return invalid()
	}
	switch event.Type {
	case "input_mouse":
		if math.IsNaN(event.X) || math.IsNaN(event.Y) || math.IsInf(event.X, 0) || math.IsInf(event.Y, 0) || event.X < 0 || event.Y < 0 || event.X >= float64(width) || event.Y >= float64(height) || math.Abs(event.DeltaX) > 32768 || math.Abs(event.DeltaY) > 32768 {
			return invalid()
		}
		switch event.EventType {
		case "mouseMoved":
		case "mousePressed", "mouseReleased":
			if mouseButton(event.Button) == 0 {
				return invalid()
			}
		case "mouseWheel":
		default:
			return invalid()
		}
	case "input_keyboard":
		switch event.EventType {
		case "insertText", "char":
			if event.Text == "" || len(event.Text) > maximumClipboard || !utf8.ValidString(event.Text) {
				return invalid()
			}
		case "keyDown", "rawKeyDown", "keyUp":
			if d.keycode(event) == 0 {
				return invalid()
			}
		default:
			return invalid()
		}
	default:
		return invalid()
	}
	return nil
}
func mouseButton(value string) byte {
	switch value {
	case "left":
		return 1
	case "middle":
		return 2
	case "right":
		return 3
	case "back":
		return 8
	case "forward":
		return 9
	}
	return 0
}
func (d *display) fake(typ, detail byte, x, y int) error {
	return xtest.FakeInputChecked(d.conn, typ, detail, 0, d.screen.Root, int16(x), int16(y), 0).Check()
}
func (d *display) key(code byte, down bool) error {
	typ := byte(xproto.KeyRelease)
	if down {
		typ = xproto.KeyPress
		// A lost acknowledgment cannot erase custody of a possibly held key.
		d.keys[code] = true
	}
	if err := d.fake(typ, code, 0, 0); err != nil {
		return unknown()
	}
	if !down {
		delete(d.keys, code)
	}
	return nil
}
func (d *display) button(button byte, down bool) error {
	typ := byte(xproto.ButtonRelease)
	if down {
		typ = xproto.ButtonPress
		d.buttons[button] = true
	}
	if err := d.fake(typ, button, 0, 0); err != nil {
		return unknown()
	}
	if !down {
		delete(d.buttons, button)
	}
	return nil
}

var modifierGroups = []struct {
	bit         int
	left, right string
}{
	{1, "Alt_L", "Alt_R"}, {2, "Control_L", "Control_R"}, {4, "Super_L", "Super_R"}, {8, "Shift_L", "Shift_R"},
}

func (d *display) modifierCodes() []byte {
	codes := make([]byte, 0, 8)
	for _, group := range modifierGroups {
		for _, name := range []string{group.left, group.right} {
			if code := d.nativeKey(name); code != 0 {
				codes = append(codes, code)
			}
		}
	}
	return codes
}
func (d *display) isModifier(code byte) bool {
	for _, candidate := range d.modifierCodes() {
		if candidate == code {
			return true
		}
	}
	return false
}
func (d *display) modifiers(mask int) error {
	for _, group := range modifierGroups {
		left, right := d.nativeKey(group.left), d.nativeKey(group.right)
		if left == 0 {
			return unavailable()
		}
		if mask&group.bit != 0 {
			if !d.keys[left] && !d.keys[right] {
				if err := d.key(left, true); err != nil {
					return err
				}
			}
		} else {
			for _, code := range []byte{left, right} {
				if code != 0 && d.keys[code] {
					if err := d.key(code, false); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
func (d *display) restoreModifiers(saved map[byte]bool) error {
	var first error
	for _, code := range d.modifierCodes() {
		if d.keys[code] != saved[code] {
			if err := d.key(code, saved[code]); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}
func (d *display) input(events []inputEvent) error {
	width, height, err := d.size()
	if err != nil {
		return err
	}
	// Validate the entire batch before the first external input effect.
	for _, event := range events {
		if err := d.validateEvent(event, width, height); err != nil {
			return err
		}
	}
	for _, event := range events {
		if event.EventType == "insertText" || event.EventType == "char" {
			if err := d.paste(event.Text); err != nil {
				return unknown()
			}
			continue
		}
		if event.Type == "input_keyboard" && d.isModifier(d.keycode(event)) {
			// Keep the actual side the user pressed. Adding a synthetic left
			// modifier first would create a second held key for a right key.
			if err := d.key(d.keycode(event), event.EventType != "keyUp"); err != nil {
				return err
			}
			if err := d.modifiers(event.Modifiers); err != nil {
				return unknown()
			}
			continue
		}
		if err := d.modifiers(event.Modifiers); err != nil {
			return unknown()
		}
		if event.Type == "input_keyboard" {
			if err := d.key(d.keycode(event), event.EventType != "keyUp"); err != nil {
				return err
			}
			continue
		}
		if err := d.fake(xproto.MotionNotify, 0, int(event.X), int(event.Y)); err != nil {
			return unknown()
		}
		switch event.EventType {
		case "mousePressed":
			err = d.button(mouseButton(event.Button), true)
		case "mouseReleased":
			err = d.button(mouseButton(event.Button), false)
		case "mouseWheel":
			for _, axis := range []struct {
				delta              float64
				negative, positive byte
				retained           *float64
			}{{event.DeltaY, 4, 5, &d.wheelY}, {event.DeltaX, 6, 7, &d.wheelX}} {
				steps := wheelSteps(axis.delta, axis.retained)
				button := axis.positive
				if steps < 0 {
					button = axis.negative
				}
				for count := 0; count < int(math.Abs(float64(steps))); count++ {
					if err = d.button(button, true); err != nil {
						break
					}
					if err = d.button(button, false); err != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
		}
		if err != nil {
			return unknown()
		}
	}
	return nil
}
func wheelSteps(delta float64, retained *float64) int {
	*retained += delta
	steps := int(*retained / 100)
	*retained -= float64(steps) * 100
	return steps
}
func (d *display) reset() error {
	d.wheelX, d.wheelY = 0, 0
	failed := false
	for code := range d.keys {
		if d.key(code, false) != nil {
			failed = true
		}
	}
	for button := range d.buttons {
		if d.button(button, false) != nil {
			failed = true
		}
	}
	if failed {
		return unknown()
	}
	return nil
}
func (d *display) chord(key string) error {
	code := d.nativeKey(key)
	if code == 0 {
		return invalid()
	}
	saved := map[byte]bool{}
	for _, modifier := range d.modifierCodes() {
		saved[modifier] = d.keys[modifier]
	}
	if err := d.modifiers(2); err != nil {
		_ = d.restoreModifiers(saved)
		return err
	}
	primary := d.key(code, true)
	// Even a lost press acknowledgment leaves possible held input to release.
	released := d.key(code, false)
	restored := d.restoreModifiers(saved)
	if primary != nil {
		return primary
	}
	if released != nil {
		return released
	}
	return restored
}
