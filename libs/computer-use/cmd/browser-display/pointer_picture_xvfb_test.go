// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"encoding/json"
	"fmt"
	"image"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/robotn/xgb/xproto"
)

func pictureReply(t *testing.T, d *display, options pictureOptions) map[string]any {
	t.Helper()
	value, err := d.frames.picture(options)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	return wire
}

func expectPointer(t *testing.T, wire map[string]any, x, y int) {
	t.Helper()
	point, ok := wire["pointer"].(map[string]any)
	if !ok || point["x"] != float64(x) || point["y"] != float64(y) {
		t.Fatalf("wanted device point %d,%d, got %v", x, y, wire["pointer"])
	}
}

func solidPointerCursor(t *testing.T, page *painter, side uint16) {
	t.Helper()
	pixmap, _ := xproto.NewPixmapId(page.conn)
	if err := xproto.CreatePixmapChecked(page.conn, 1, pixmap, xproto.Drawable(page.root), side, side).Check(); err != nil {
		t.Fatal(err)
	}
	gc, _ := xproto.NewGcontextId(page.conn)
	if err := xproto.CreateGCChecked(page.conn, gc, xproto.Drawable(pixmap), xproto.GcForeground, []uint32{1}).Check(); err != nil {
		t.Fatal(err)
	}
	if err := xproto.PolyFillRectangleChecked(page.conn, xproto.Drawable(pixmap), gc, []xproto.Rectangle{{Width: side, Height: side}}).Check(); err != nil {
		t.Fatal(err)
	}
	cursor, _ := xproto.NewCursorId(page.conn)
	if err := xproto.CreateCursorChecked(page.conn, cursor, pixmap, pixmap, 0xffff, 0, 0, 0, 0, 0, 3, 4).Check(); err != nil {
		t.Fatal(err)
	}
	page.useCursor(t, cursor)
}

// Scale2-style display/window dimensions and a cropped visible region never
// turn the pointer into CSS/window-relative coordinates. A hidden cursor's
// changing identity or hotspot never leaves cursor pixels in the slot.
func TestXvfbPicturePointerIsFreshWhilePixelsStayPointerFree(t *testing.T) {
	startXvfb(t, 1536, 2048)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	slot, _ := newSlot(t, 1536*2048*4)
	d.frames.attachPixels(slot)
	browser := newSyncBrowser(t, 800, 600, 5*time.Millisecond, 0x2060c0)
	if _, err := d.resize(1418, 1888, uint32(browser.window), true); err != nil {
		t.Fatal(err)
	}
	if width, height := rootSize(t, d); width != 1536 || height != 2048 {
		t.Fatalf("cropped framebuffer %dx%d", width, height)
	}
	page := newPainter(t)
	page.fill(t, image.Rect(0, 0, 1536, 2048), 0x2060c0)
	page.fontCursor(t, 68)
	page.warp(t, 600, 1000)
	first := pictureReply(t, d, pictureOptions{identity: true, force: true})
	expectPointer(t, first, 600, 1000)
	visible := first["visible"].(map[string]any)
	if visible["width"] != float64(1418) || visible["height"] != float64(1888) {
		t.Fatalf("visible %v", visible)
	}
	if first["cursorIncluded"] != false || slotPixel(slot, 1536, 600, 1000) != [3]byte{0x20, 0x60, 0xc0} {
		t.Fatal("identity-only picture drew the pointer")
	}
	for _, point := range [][2]int{{601, 1001}, {1400, 1800}, {1500, 2000}} {
		// Native XTEST motion on the input owner's connection; the metadata
		// must agree with the same display pixels, including outside visible.
		if err := d.input([]inputEvent{{Type: "input_mouse", EventType: "mouseMoved", X: float64(point[0]), Y: float64(point[1]), Button: "none"}}); err != nil {
			t.Fatal(err)
		}
		actual, err := xproto.QueryPointer(page.conn, page.root).Reply()
		if err != nil {
			t.Fatal(err)
		}
		unchanged := pictureReply(t, d, pictureOptions{identity: true})
		expectPointer(t, unchanged, int(actual.RootX), int(actual.RootY))
		if unchanged["changed"] != false {
			t.Fatalf("pointer-only move damaged pointer-free pixels: %v", unchanged)
		}
	}
	// Custom16 and32 objects retain their actual position and do not subtract
	// the hotspot. These are genuine X cursor objects, not mocked identities.
	for _, side := range []uint16{16, 32} {
		solidPointerCursor(t, page, side)
		page.warp(t, 900+int(side), 700+int(side))
		picture := pictureReply(t, d, pictureOptions{identity: true, force: true})
		expectPointer(t, picture, 900+int(side), 700+int(side))
		if slotPixel(slot, 1536, 900+int(side), 700+int(side)) != [3]byte{0x20, 0x60, 0xc0} {
			t.Fatal("custom identity drew cursor pixels")
		}
	}
	if err := xproto.ConfigureWindowChecked(browser.conn, browser.window, xproto.ConfigWindowX|xproto.ConfigWindowY, []uint32{100, 80}).Check(); err != nil {
		t.Fatal(err)
	}
	d.frames.endLayout(image.Rect(100, 80, 1518, 1968))
	page.warp(t, 400, 500)
	movedWindow := pictureReply(t, d, pictureOptions{identity: true, force: true})
	expectPointer(t, movedWindow, 400, 500)
	if visible := movedWindow["visible"].(map[string]any); visible["x"] != float64(100) || visible["y"] != float64(80) {
		t.Fatalf("nonzero window origin %v", visible)
	}
	without := pictureReply(t, d, pictureOptions{force: true})
	if _, ok := without["pointer"]; ok {
		t.Fatal("a no-query picture reused a pointer")
	}
	jpeg := mustCall(t, d, `{"id":1,"op":"capture","cursor":false,"cursorIdentity":true,"force":true}`)
	if _, ok := jpeg["pointer"]; ok {
		t.Fatal("JPEG capture changed its wire")
	}
}

// Baseline/head use this identical probe. It measures the actual private-Xvfb
// picture owner with unchanged cursor identity and native X pointer movement.
func TestXvfbPictureCursorQueryTiming(t *testing.T) {
	startXvfb(t, 1536, 2048)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	slot, _ := newSlot(t, 1536*2048*4)
	d.frames.attachPixels(slot)
	page := newPainter(t)
	page.fill(t, image.Rect(0, 0, 1536, 2048), 0x2060c0)
	page.fontCursor(t, 68)
	measure := func(name string, force bool, moving bool) {
		values := make([]float64, 0, 100)
		for i := 0; i < 110; i++ {
			if moving {
				page.warp(t, 600+i, 1000+i)
			}
			started := time.Now()
			if _, err := d.frames.picture(pictureOptions{identity: true, force: force}); err != nil {
				t.Fatal(err)
			}
			if i >= 10 {
				values = append(values, float64(time.Since(started).Microseconds())/1000)
			}
		}
		sort.Float64s(values)
		fmt.Printf("PICTURE_QUERY %s n=%d p50_ms=%.3f p95_ms=%.3f max_ms=%.3f\n", name, len(values), values[50], values[95], values[99])
	}
	measure("forced-static-identity", true, true)
	measure("unchanged-static-identity", false, true)
	solidPointerCursor(t, page, maximumCursorSide)
	measure("forced-max-custom-identity", true, true)
	measure("unchanged-max-custom-identity", false, true)
}
