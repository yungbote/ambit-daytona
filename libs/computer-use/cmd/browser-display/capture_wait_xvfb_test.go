// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"encoding/json"
	"image"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/robotn/xgb"
	"github.com/robotn/xgb/randr"
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
	want := map[string]bool{"captureWait": true, "cursorIdentity": true, "layoutGate": true, "sizeClass": true}
	for _, feature := range features {
		delete(want, feature.(string))
	}
	if len(want) != 0 {
		t.Fatalf("info features %v lack %v", features, want)
	}
	for _, line := range []string{
		`{"id":2,"op":"capture","waitMs":251}`,
		`{"id":2,"op":"capture","waitMs":-1}`,
		`{"id":2,"op":"capture","sizeClass":true}`,
		`{"id":2,"op":"info","cursorIdentity":true}`,
		`{"id":2,"op":"info","waitMs":10}`,
		`{"id":2,"op":"input","events":[{"type":"input_mouse","eventType":"mouseMoved","x":1,"y":1}],"sizeClass":true}`,
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

// syncBrowser is a top-level window that repaints like the browser: it
// acknowledges each _NET_WM_SYNC_REQUEST only after drawing the new geometry.
type syncBrowser struct {
	conn    *xgb.Conn
	window  xproto.Window
	counter uint32
	gc      xproto.Gcontext
	opcode  byte
	delay   time.Duration
	color   uint32
	mu      sync.Mutex
	painted []time.Time
}

func newSyncBrowser(t *testing.T, width, height int, delay time.Duration, color uint32) *syncBrowser {
	t.Helper()
	c, err := xgb.NewConn()
	if err != nil {
		t.Fatal(err)
	}
	b := &syncBrowser{conn: c, delay: delay, color: color}
	extension, err := xproto.QueryExtension(c, 4, "SYNC").Reply()
	if err != nil || !extension.Present {
		t.Fatal("SYNC is unavailable")
	}
	b.opcode = extension.MajorOpcode
	request := func(minor byte, values ...uint32) *xgb.Cookie {
		data := make([]byte, 4+4*len(values))
		data[0], data[1] = b.opcode, minor
		xgb.Put16(data[2:], uint16(len(data)/4))
		for index, value := range values {
			xgb.Put32(data[4+index*4:], value)
		}
		cookie := c.NewCookie(true, minor == 0)
		c.NewRequest(data, cookie)
		return cookie
	}
	if _, err := request(0, 3|1<<8).Reply(); err != nil {
		t.Fatal(err)
	}
	counter, err := c.NewId()
	if err != nil {
		t.Fatal(err)
	}
	b.counter = counter
	if err := request(2, counter, 0, 0).Check(); err != nil {
		t.Fatal(err)
	}
	screen := xproto.Setup(c).DefaultScreen(c)
	window, err := xproto.NewWindowId(c)
	if err != nil {
		t.Fatal(err)
	}
	b.window = window
	if err := xproto.CreateWindowChecked(c, screen.RootDepth, window, screen.Root, 0, 0, uint16(width), uint16(height), 0, xproto.WindowClassInputOutput, screen.RootVisual,
		xproto.CwBackPixel|xproto.CwEventMask, []uint32{0, xproto.EventMaskStructureNotify}).Check(); err != nil {
		t.Fatal(err)
	}
	atom := func(name string) xproto.Atom {
		reply, err := xproto.InternAtom(c, false, uint16(len(name)), name).Reply()
		if err != nil {
			t.Fatal(err)
		}
		return reply.Atom
	}
	property := func(name string, kind xproto.Atom, value uint32) {
		data := make([]byte, 4)
		xgb.Put32(data, value)
		if err := xproto.ChangePropertyChecked(c, xproto.PropModeReplace, window, atom(name), kind, 32, 1, data).Check(); err != nil {
			t.Fatal(err)
		}
	}
	property("_NET_WM_PID", xproto.AtomCardinal, uint32(os.Getpid()))
	property("_NET_WM_WINDOW_TYPE", xproto.AtomAtom, uint32(atom("_NET_WM_WINDOW_TYPE_NORMAL")))
	property("_NET_WM_SYNC_REQUEST_COUNTER", xproto.AtomCardinal, counter)
	gc, err := xproto.NewGcontextId(c)
	if err != nil {
		t.Fatal(err)
	}
	b.gc = gc
	if err := xproto.CreateGCChecked(c, gc, xproto.Drawable(window), xproto.GcForeground, []uint32{color}).Check(); err != nil {
		t.Fatal(err)
	}
	if err := xproto.MapWindowChecked(c, window).Check(); err != nil {
		t.Fatal(err)
	}
	b.paint(width, height)
	syncRequest := atom("_NET_WM_SYNC_REQUEST")
	// The connection is closed and fully drained before the display goes
	// away: xgb cannot close a connection twice, and a server reset seen by
	// its reader after Close would be a second close.
	drained := make(chan struct{})
	t.Cleanup(func() {
		c.Close()
		<-drained
	})
	go func() {
		defer close(drained)
		var requested uint64
		for {
			event, err := c.WaitForEvent()
			if event == nil && err == nil {
				return
			}
			switch value := event.(type) {
			case xproto.ClientMessageEvent:
				if data := value.Data.Data32; value.Format == 32 && xproto.Atom(data[0]) == syncRequest {
					requested = uint64(data[3])<<32 | uint64(data[2])
				}
			case xproto.ConfigureNotifyEvent:
				if value.Window != window || requested == 0 {
					continue
				}
				value, target := value, requested
				requested = 0
				time.AfterFunc(b.delay, func() {
					b.paint(int(value.Width), int(value.Height))
					_ = request(3, counter, uint32(target>>32), uint32(target)).Check()
				})
			}
		}
	}()
	return b
}
func (b *syncBrowser) paint(width, height int) {
	_ = xproto.PolyFillRectangleChecked(b.conn, xproto.Drawable(b.window), b.gc, []xproto.Rectangle{{Width: uint16(width), Height: uint16(height)}}).Check()
	b.mu.Lock()
	b.painted = append(b.painted, time.Now())
	b.mu.Unlock()
}

func rootSize(t *testing.T, d *display) (int, int) {
	t.Helper()
	width, height, err := d.size()
	if err != nil {
		t.Fatal(err)
	}
	return width, height
}
func scanoutSize(t *testing.T, d *display) (int, int) {
	t.Helper()
	resources, err := randr.GetScreenResourcesCurrent(d.conn, d.screen.Root).Reply()
	if err != nil {
		t.Fatal(err)
	}
	output, err := randr.GetOutputInfo(d.conn, resources.Outputs[0], resources.ConfigTimestamp).Reply()
	if err != nil {
		t.Fatal(err)
	}
	crtc, err := randr.GetCrtcInfo(d.conn, output.Crtc, resources.ConfigTimestamp).Reply()
	if err != nil {
		t.Fatal(err)
	}
	return int(crtc.Width), int(crtc.Height)
}

// No frame shows a configure the browser has not painted: captures during the
// layout answer unchanged, a waiting capture answers with the painted frame.
func TestXvfbLayoutGateHoldsFramesUntilTheBrowserPaints(t *testing.T) {
	startXvfb(t, 1200, 900)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	browser := newSyncBrowser(t, 600, 400, 150*time.Millisecond, 0x2060c0)
	mustCall(t, d, `{"id":1,"op":"capture","cursor":false}`)
	resized := make(chan error, 1)
	finished := make(chan struct{})
	// A failed assertion must not close the display under the resize.
	defer func() { <-finished }()
	started := time.Now()
	go func() {
		defer close(finished)
		_, err := d.resize(900, 700, uint32(browser.window), false)
		resized <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if early := mustCall(t, d, `{"id":2,"op":"capture","cursor":false,"force":true}`); early["changed"] != false {
		t.Fatalf("a frame of the unpainted configure was captured %v after the resize began", time.Since(started))
	}
	held := mustCall(t, d, `{"id":3,"op":"capture","cursor":false,"waitMs":250}`)
	answered := time.Since(started)
	if err := <-resized; err != nil {
		t.Fatal(err)
	}
	if held["changed"] != true || held["width"] != float64(900) || answered < 140*time.Millisecond {
		t.Fatalf("held capture answered %v (%vx%v) after %v", held["changed"], held["width"], held["height"], answered)
	}
	frame := expectFrame(t, d, captureOptions{force: true}, "painted layout")
	if pixel := decodeJPEG(t, frame.Data).At(850, 650); !near(pixel, 0x20, 0x60, 0xc0) {
		t.Fatalf("the first frame after the layout is unpainted: %v", pixel)
	}
}

// With a size class, a resize inside the class changes only the output mode
// and the window; frames keep the framebuffer's size and name the window.
func TestXvfbSizeClassLaysOutOnlyTheModeAndWindow(t *testing.T) {
	startXvfb(t, 4096, 4096)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	browser := newSyncBrowser(t, 800, 600, 5*time.Millisecond, 0x2060c0)
	window := uint32(browser.window)
	layout := func(width, height int) map[string]any {
		t.Helper()
		reply, err := call(t, d, `{"id":1,"op":"resize","sizeClass":true,"windowId":`+itoa(int(window))+`,"width":`+itoa(width)+`,"height":`+itoa(height)+`}`)
		if err != nil {
			t.Fatalf("resize %dx%d: %v", width, height, err)
		}
		return reply
	}
	first := layout(1418, 1888)
	if first["width"] != float64(1536) || first["height"] != float64(2048) {
		t.Fatalf("first layout framebuffer %vx%v", first["width"], first["height"])
	}
	if w, h := scanoutSize(t, d); w != 1418 || h != 1888 {
		t.Fatalf("scanout %dx%d", w, h)
	}
	frame := mustCall(t, d, `{"id":2,"op":"capture","cursor":false,"force":true}`)
	visible, _ := frame["visible"].(map[string]any)
	if frame["width"] != float64(1536) || visible == nil || visible["width"] != float64(1418) || visible["height"] != float64(1888) || visible["x"] != float64(0) {
		t.Fatalf("frame %vx%v visible %v", frame["width"], frame["height"], frame["visible"])
	}
	changed := d.framebufferChanged
	layout(1300, 1700)
	if w, h := rootSize(t, d); w != 1536 || h != 2048 || d.framebufferChanged != changed {
		t.Fatalf("a resize inside the class changed the framebuffer to %dx%d", w, h)
	}
	if w, h := scanoutSize(t, d); w != 1300 || h != 1700 {
		t.Fatalf("scanout %dx%d", w, h)
	}
	layout(1600, 1700)
	if w, h := rootSize(t, d); w != 1792 || h != 2048 {
		t.Fatalf("growth: %dx%d", w, h)
	}
	layout(900, 1000)
	if w, h := rootSize(t, d); w != 1792 || h != 2048 {
		t.Fatalf("shrank before settling: %dx%d", w, h)
	}
	d.framebufferChanged = time.Now().Add(-sizeClassSettle)
	layout(900, 1000)
	if w, h := rootSize(t, d); w != 1024 || h != 1024 {
		t.Fatalf("settled shrink: %dx%d", w, h)
	}
	// The exact layout still owns the whole framebuffer and names no window.
	if _, err := d.resize(1000, 800, window, false); err != nil {
		t.Fatal(err)
	}
	whole := mustCall(t, d, `{"id":3,"op":"capture","cursor":false,"force":true}`)
	if whole["width"] != float64(1000) || whole["visible"] != nil {
		t.Fatalf("exact layout frame %vx%v visible %v", whole["width"], whole["height"], whole["visible"])
	}
}

func itoa(value int) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
