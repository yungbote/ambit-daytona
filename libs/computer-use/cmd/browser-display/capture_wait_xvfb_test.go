// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"encoding/json"
	"image"
	"os"
	"testing"
	"time"

	"github.com/robotn/xgb/xproto"
)

// call sends one protocol request exactly as the driver writes it and answers
// the reply document, so these specs hold the wire contract, not internals.
func call(t *testing.T, d *display, line string) (map[string]any, error) {
	t.Helper()
	request, err := decodeRequest([]byte(line))
	if err != nil {
		return nil, err
	}
	result, err := d.execute(request)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var reply map[string]any
	if err := json.Unmarshal(encoded, &reply); err != nil {
		t.Fatal(err)
	}
	return reply, nil
}
func mustCall(t *testing.T, d *display, line string) map[string]any {
	t.Helper()
	reply, err := call(t, d, line)
	if err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	return reply
}

func (p *painter) fontCursor(t *testing.T, glyph uint16) {
	t.Helper()
	font, err := xproto.NewFontId(p.conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := xproto.OpenFontChecked(p.conn, font, 6, "cursor").Check(); err != nil {
		t.Fatal(err)
	}
	cursor, err := xproto.NewCursorId(p.conn)
	if err != nil {
		t.Fatal(err)
	}
	// Black on white, as Xlib's XCreateFontCursor builds the browser's cursors.
	if err := xproto.CreateGlyphCursorChecked(p.conn, cursor, font, font, glyph, glyph+1, 0, 0, 0, 0xffff, 0xffff, 0xffff).Check(); err != nil {
		t.Fatal(err)
	}
	if err := xproto.ChangeWindowAttributesChecked(p.conn, p.root, xproto.CwCursor, []uint32{uint32(cursor)}).Check(); err != nil {
		t.Fatal(err)
	}
}

// pixmapCursor sets a cursor no browser keyword draws.
func (p *painter) pixmapCursor(t *testing.T) {
	t.Helper()
	pixmap, err := xproto.NewPixmapId(p.conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := xproto.CreatePixmapChecked(p.conn, 1, pixmap, xproto.Drawable(p.root), 16, 16).Check(); err != nil {
		t.Fatal(err)
	}
	gc, err := xproto.NewGcontextId(p.conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := xproto.CreateGCChecked(p.conn, gc, xproto.Drawable(pixmap), xproto.GcForeground, []uint32{1}).Check(); err != nil {
		t.Fatal(err)
	}
	if err := xproto.PolyFillRectangleChecked(p.conn, xproto.Drawable(pixmap), gc, []xproto.Rectangle{{X: 2, Y: 2, Width: 11, Height: 5}}).Check(); err != nil {
		t.Fatal(err)
	}
	cursor, err := xproto.NewCursorId(p.conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := xproto.CreateCursorChecked(p.conn, cursor, pixmap, pixmap, 0xffff, 0, 0, 0, 0, 0, 3, 4).Check(); err != nil {
		t.Fatal(err)
	}
	if err := xproto.ChangeWindowAttributesChecked(p.conn, p.root, xproto.CwCursor, []uint32{uint32(cursor)}).Check(); err != nil {
		t.Fatal(err)
	}
}

func TestXvfbInfoAdvertisesTheCaptureFeaturesAndTheirBounds(t *testing.T) {
	startXvfb(t, 800, 600)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	info := mustCall(t, d, `{"id":1,"op":"info"}`)
	features, _ := info["features"].([]any)
	want := map[string]bool{"captureWait": true, "cursorIdentity": true}
	for _, feature := range features {
		delete(want, feature.(string))
	}
	if len(want) != 0 {
		t.Fatalf("info features %v lack %v", features, want)
	}
	for _, line := range []string{
		`{"id":2,"op":"capture","waitMs":251}`,
		`{"id":2,"op":"capture","waitMs":-1}`,
		`{"id":2,"op":"info","cursorIdentity":true}`,
		`{"id":2,"op":"info","waitMs":10}`,
	} {
		if _, err := call(t, d, line); err == nil {
			t.Fatalf("accepted %s", line)
		}
	}
	if _, err := call(t, d, `{"id":3,"op":"capture","waitMs":250,"cursorIdentity":true,"cursor":false}`); err != nil {
		t.Fatalf("bounded wait refused: %v", err)
	}
}

// With a wait, an unchanged capture holds until the screen changes and then
// answers at once; with nothing to show it answers unchanged at the bound.
func TestXvfbCaptureWaitAnswersDamageOnArrival(t *testing.T) {
	startXvfb(t, 800, 600)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	page := newPainter(t)
	if first := mustCall(t, d, `{"id":1,"op":"capture","cursor":false}`); first["changed"] != true {
		t.Fatal("no first frame")
	}
	started := time.Now()
	idle := mustCall(t, d, `{"id":2,"op":"capture","cursor":false,"waitMs":80}`)
	if waited := time.Since(started); idle["changed"] != false || waited < 75*time.Millisecond || waited > 400*time.Millisecond {
		t.Fatalf("idle wait answered %v after %v", idle["changed"], waited)
	}
	filled := make(chan struct{})
	go func() {
		defer close(filled)
		time.Sleep(40 * time.Millisecond)
		page.fill(t, image.Rect(10, 10, 60, 60), 0xff0000)
	}()
	started = time.Now()
	woken := mustCall(t, d, `{"id":3,"op":"capture","cursor":false,"patches":true,"waitMs":250}`)
	waited := time.Since(started)
	<-filled
	if woken["changed"] != true || waited < 35*time.Millisecond || waited > 200*time.Millisecond {
		t.Fatalf("damage answered %v after %v", woken["changed"], waited)
	}
	timings, _ := woken["timings"].(map[string]any)
	if timings["waitUs"] == nil {
		t.Fatal("the wait is not measured")
	}
	// The input path wakes a capture that composites the pointer.
	mustCall(t, d, `{"id":4,"op":"capture","cursor":true}`)
	moved := make(chan struct{})
	go func() {
		defer close(moved)
		time.Sleep(40 * time.Millisecond)
		_ = d.input([]inputEvent{{Type: "input_mouse", EventType: "mouseMoved", X: 300, Y: 300}})
	}()
	started = time.Now()
	pointer := mustCall(t, d, `{"id":5,"op":"capture","cursor":true,"waitMs":250}`)
	waited = time.Since(started)
	<-moved
	if pointer["changed"] != true || waited < 35*time.Millisecond || waited > 200*time.Millisecond {
		t.Fatalf("pointer move answered %v after %v", pointer["changed"], waited)
	}
}

// The first identity is always reported, then only changes, each as soon as
// the server announces it. The keywords are those the browser's own cursors
// map to; any other cursor travels as an image.
func TestXvfbCursorIdentityFollowsTheDisplayedCursor(t *testing.T) {
	startXvfb(t, 800, 600)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	page := newPainter(t)
	page.warp(t, 400, 300)
	css := func(reply map[string]any) any {
		cursor, _ := reply["cursor"].(map[string]any)
		if cursor == nil {
			return nil
		}
		return cursor["css"]
	}
	first := mustCall(t, d, `{"id":1,"op":"capture","cursor":false,"cursorIdentity":true}`)
	if css(first) != "default" {
		t.Fatalf("first reply: %v", first["cursor"])
	}
	if again := mustCall(t, d, `{"id":2,"op":"capture","cursor":false,"cursorIdentity":true}`); again["cursor"] != nil || again["changed"] != false {
		t.Fatalf("repeated identity: %v", again)
	}
	for _, step := range []struct {
		glyph uint16
		css   string
	}{{60, "pointer"}, {152, "text"}, {68, "default"}, {150, "progress"}, {108, "ew-resize"}} {
		changed := make(chan struct{})
		go func() {
			defer close(changed)
			time.Sleep(30 * time.Millisecond)
			page.fontCursor(t, step.glyph)
		}()
		started := time.Now()
		reply := mustCall(t, d, `{"id":3,"op":"capture","cursor":false,"cursorIdentity":true,"waitMs":250}`)
		waited := time.Since(started)
		<-changed
		if css(reply) != step.css || waited > 200*time.Millisecond || waited < 25*time.Millisecond {
			t.Fatalf("glyph %d: identity %v after %v", step.glyph, reply["cursor"], waited)
		}
	}
	page.pixmapCursor(t)
	custom := mustCall(t, d, `{"id":4,"op":"capture","cursor":false,"cursorIdentity":true,"waitMs":250}`)
	cursor, _ := custom["cursor"].(map[string]any)
	imageField, _ := cursor["image"].(map[string]any)
	if cursor == nil || cursor["css"] != nil || imageField == nil || imageField["scale"] != float64(2) || imageField["hotX"] != float64(3) || imageField["hotY"] != float64(4) || imageField["png"] == "" {
		t.Fatalf("custom cursor identity: %v", custom["cursor"])
	}
	// An identity rides a frame too, and a capture without the request never
	// consumes it.
	page.fontCursor(t, 60)
	page.fill(t, image.Rect(0, 0, 40, 40), 0x00ff00)
	time.Sleep(20 * time.Millisecond)
	if plain := mustCall(t, d, `{"id":5,"op":"capture","cursor":false}`); plain["cursor"] != nil {
		t.Fatal("identity reported without being asked for")
	}
	page.fill(t, image.Rect(0, 0, 40, 40), 0x0000ff)
	if framed := mustCall(t, d, `{"id":6,"op":"capture","cursor":false,"cursorIdentity":true}`); framed["changed"] != true || css(framed) != "pointer" {
		t.Fatalf("identity on a frame: %v", framed)
	}
}
