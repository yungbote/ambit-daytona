// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"encoding/json"
	"image"
	"strings"
	"testing"

	"github.com/robotn/xgb/xfixes"
	"github.com/robotn/xgb/xproto"
)

func TestProtocolRejectsBeforeEffects(t *testing.T) {
	for _, value := range []string{
		`{"id":1,"op":"input","events":[]}`, `{"id":1,"op":"resize","width":4097,"height":1}`, `{"id":1,"op":"resize","width":1,"height":0}`,
		`{"id":1,"op":"capture","windowId":42}`, `{"id":0,"op":"info"}`, `{"id":1,"op":"capture","command":"rm"}`, `{"id":1,"op":"info"}{"id":2,"op":"copy"}`,
		`{"id":1,"op":"input","events":[{"type":"input_keyboard","eventType":"insertText","text":"hello","unknown":true}]}`,
	} {
		if _, err := decodeRequest([]byte(value)); err == nil {
			t.Errorf("accepted invalid request %q", value)
		}
	}
}
func TestProtocolAcceptsBoundedUnicodeWithoutTruncation(t *testing.T) {
	text := strings.Repeat("a界😀\n", 5000)
	raw, err := json.Marshal(request{ID: 1, Op: "input", Events: []inputEvent{{Type: "input_keyboard", EventType: "insertText", Text: text}}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := decodeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Events[0].Text != text {
		t.Fatal("text changed")
	}
	raw = append(raw, make([]byte, maximumRequest)...)
	if _, err = decodeRequest(raw); err == nil {
		t.Fatal("oversize accepted")
	}
}
func TestNativeImageByteOrdersAndPadding(t *testing.T) {
	visual := xproto.VisualInfo{RedMask: 0xff0000, GreenMask: 0xff00, BlueMask: 0xff}
	for _, test := range []struct {
		name        string
		raw         []byte
		bits, order byte
	}{
		{"little32", []byte{0x33, 0x22, 0x11, 0}, 32, xproto.ImageOrderLSBFirst},
		{"big32", []byte{0, 0x11, 0x22, 0x33}, 32, xproto.ImageOrderMSBFirst},
		{"little24padded", []byte{0x33, 0x22, 0x11, 0}, 24, xproto.ImageOrderLSBFirst},
	} {
		t.Run(test.name, func(t *testing.T) {
			img, err := decodeImage(test.raw, 1, 1, xproto.Format{BitsPerPixel: test.bits, ScanlinePad: 32}, visual, test.order)
			if err != nil {
				t.Fatal(err)
			}
			if got := img.RGBAAt(0, 0); got.R != 0x11 || got.G != 0x22 || got.B != 0x33 || got.A != 255 {
				t.Fatalf("wrong actual pixel: %v", got)
			}
		})
	}
	if _, err := decodeImage([]byte{1}, 1, 1, xproto.Format{BitsPerPixel: 32, ScanlinePad: 32}, visual, 0); err == nil {
		t.Fatal("short image accepted")
	}
}
func TestCursorClipsAtActualDisplayOriginAndBlendsPremultipliedARGB(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	for index := range img.Pix {
		img.Pix[index] = 255
	}
	compositeCursor(img, &xfixes.GetCursorImageReply{X: 0, Y: 0, Xhot: 1, Yhot: 1, Width: 2, Height: 2, CursorImage: []uint32{0xffffffff, 0xffffffff, 0xffffffff, 0x80800000}})
	pixel := img.RGBAAt(0, 0)
	if pixel.R != 255 || pixel.G != 127 || pixel.B != 127 {
		t.Fatalf("wrong composited cursor %v", pixel)
	}
	if img.RGBAAt(1, 1).R != 255 {
		t.Fatal("cursor modified unrelated pixels")
	}
}
func TestWholeInputValidationRejectsUnmappableKeysAndForeignCoordinates(t *testing.T) {
	d := &display{keysyms: map[string]byte{"a": 38, "left": 113, "return": 36}}
	valid := []inputEvent{{Type: "input_keyboard", EventType: "keyDown", Code: "KeyA"}, {Type: "input_mouse", EventType: "mousePressed", Button: "left", X: 10, Y: 20}}
	for _, event := range valid {
		if err := d.validateEvent(event, 100, 100); err != nil {
			t.Fatal(err)
		}
	}
	for _, event := range []inputEvent{{Type: "input_mouse", EventType: "mouseMoved", X: 100}, {Type: "input_keyboard", EventType: "keyDown", Code: "Unknown"}, {Type: "input_keyboard", EventType: "insertText", Text: "\xff"}, {Type: "input_keyboard", EventType: "keyDown", Code: "KeyA", Modifiers: 16}} {
		if d.validateEvent(event, 100, 100) == nil {
			t.Fatal("invalid input accepted")
		}
	}
}
func FuzzRequestNeverPanics(f *testing.F) {
	f.Add([]byte(`{"id":1,"op":"info"}`))
	f.Add([]byte(`{"id":2,"op":"resize","width":780,"height":1688,"windowId":7}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maximumRequest+100 {
			return
		}
		_, _ = decodeRequest(raw)
	})
}
