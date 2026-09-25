// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"fmt"
	"image"
	"time"

	"github.com/robotn/xgb"
	"github.com/robotn/xgb/randr"
	"github.com/robotn/xgb/xfixes"
	"github.com/robotn/xgb/xproto"
	"github.com/robotn/xgb/xtest"
	"github.com/robotn/xgbutil"
)

type display struct {
	conn        *xgb.Conn
	screen      *xproto.ScreenInfo
	chromePID   uint32
	atoms       map[string]xproto.Atom
	clipboard   *clipboard
	keys        map[byte]bool
	buttons     map[byte]bool
	keysyms     map[string]byte
	textKeys    map[rune][]textKey
	heldCodes   map[string]byte
	keyboard    *xgbutil.XUtil
	modes       map[string]randr.Mode
	wheelX      float64
	wheelY      float64
	syncOpcode  byte
	paintEvents chan paintAlarm
	paintSerial uint64
	paintLatest *paintRequest
	frames      *frameEngine
	// framebufferChanged is when this helper last changed the framebuffer
	// size; zero before it ever has.
	framebufferChanged time.Time
}
type windowInfo struct {
	ID               uint32 `json:"id"`
	PID              uint32 `json:"pid"`
	X                int    `json:"x"`
	Y                int    `json:"y"`
	Width            int    `json:"width"`
	Height           int    `json:"height"`
	Mapped           bool   `json:"mapped"`
	Focused          bool   `json:"focused"`
	OverrideRedirect bool   `json:"overrideRedirect"`
	WindowType       string `json:"windowType"`
}
type displayInfo struct {
	Width       int          `json:"width"`
	Height      int          `json:"height"`
	Windows     []windowInfo `json:"windows"`
	FocusWindow uint32       `json:"focusWindow,omitempty"`
	// Features lists the protocol extensions this helper serves; only info
	// answers it.
	Features []string `json:"features,omitempty"`
}

// A size-class framebuffer is the window rounded up to whole steps, so a dock
// resize inside the class changes only the output mode and the window. It
// grows at once when the window no longer fits and shrinks only when a resize
// finds it at least two steps larger than needed and unchanged for
// sizeClassSettle, so a drag never reallocates it on every step. A framebuffer
// that holds the window stays, whether or not it is a whole class.
const sizeClassStep = 256
const sizeClassSettle = 10 * time.Second

func sizeClass(value, limit int) int {
	return max(value, min(limit, (value+sizeClassStep-1)/sizeClassStep*sizeClassStep))
}

// framebufferFor is the framebuffer a window of width x height needs, given
// the current one.
func framebufferFor(width, height, currentWidth, currentHeight, limitWidth, limitHeight int, settled bool) (int, int) {
	pick := func(value, current, limit int) int {
		class := sizeClass(value, limit)
		if value > current || (settled && current-class >= 2*sizeClassStep) {
			return class
		}
		return min(current, limit)
	}
	return pick(width, currentWidth, limitWidth), pick(height, currentHeight, limitHeight)
}

func openDisplay(pid int) (*display, error) {
	c, err := xgb.NewConn()
	if err != nil {
		return nil, err
	}
	success := false
	var frames *frameEngine
	defer func() {
		if !success {
			if frames != nil {
				frames.close()
			}
			c.Close()
		}
	}()
	for _, init := range []func(*xgb.Conn) error{randr.Init, xfixes.Init, xtest.Init} {
		if err := init(c); err != nil {
			return nil, err
		}
	}
	if _, err := xfixes.QueryVersion(c, 5, 0).Reply(); err != nil {
		return nil, err
	}
	d := &display{conn: c, screen: xproto.Setup(c).DefaultScreen(c), chromePID: uint32(pid), atoms: map[string]xproto.Atom{}, keys: map[byte]bool{}, buttons: map[byte]bool{}, modes: map[string]randr.Mode{}}
	for _, name := range []string{"_NET_WM_PID", "WM_PROTOCOLS", "_NET_WM_SYNC_REQUEST", "_NET_WM_SYNC_REQUEST_COUNTER", "_NET_WM_WINDOW_TYPE", "_NET_WM_WINDOW_TYPE_NORMAL", "_NET_WM_WINDOW_TYPE_DIALOG", "CLIPBOARD", "UTF8_STRING", "TARGETS", "TEXT", "INCR", "AMB_BROWSER_SELECTION"} {
		a, err := xproto.InternAtom(c, false, uint16(len(name)), name).Reply()
		if err != nil {
			return nil, err
		}
		d.atoms[name] = a.Atom
	}
	if err := d.initPaint(); err != nil {
		return nil, err
	}
	if err := d.loadKeys(); err != nil {
		return nil, err
	}
	// Every extension registration precedes event delivery on either connection.
	if frames, err = openFrames(); err != nil {
		return nil, err
	}
	d.frames = frames
	if err := d.startClipboard(); err != nil {
		return nil, err
	}
	success = true
	return d, nil
}
func (d *display) close() {
	_ = d.reset()
	if d.clipboard != nil {
		d.clipboard.close()
	}
	d.frames.close()
	d.conn.Close()
	if d.clipboard != nil {
		<-d.clipboard.done
	}
}
func (d *display) size() (int, int, error) {
	r, err := xproto.GetGeometry(d.conn, xproto.Drawable(d.screen.Root)).Reply()
	if err != nil {
		return 0, 0, err
	}
	if !validSize(int(r.Width), int(r.Height)) {
		return 0, 0, unavailable()
	}
	return int(r.Width), int(r.Height), nil
}
func (d *display) describe() (displayInfo, error) {
	result, err := d.info()
	result.Features = captureFeatures
	return result, err
}
func (d *display) info() (displayInfo, error) {
	w, h, err := d.size()
	if err != nil {
		return displayInfo{}, err
	}
	result := displayInfo{Width: w, Height: h, Windows: []windowInfo{}}
	tree, err := xproto.QueryTree(d.conn, d.screen.Root).Reply()
	if err != nil {
		return result, err
	}
	focus, err := xproto.GetInputFocus(d.conn).Reply()
	if err != nil {
		return result, err
	}
	focused := focus.Focus
	// A toolkit child may own focus. Follow exact ancestry to the root window;
	// window titles and geometry are never used as identity.
	for count := 0; count < 64 && focused != 0 && focused != d.screen.Root; count++ {
		t, e := xproto.QueryTree(d.conn, focused).Reply()
		if e != nil {
			break
		}
		if t.Parent == d.screen.Root {
			break
		}
		focused = t.Parent
	}
	for _, id := range tree.Children {
		p, e := xproto.GetProperty(d.conn, false, id, d.atoms["_NET_WM_PID"], xproto.AtomCardinal, 0, 1).Reply()
		if e != nil || p.Format != 32 || len(p.Value) != 4 || xgb.Get32(p.Value) != d.chromePID {
			continue
		}
		g, e := xproto.GetGeometry(d.conn, xproto.Drawable(id)).Reply()
		if e != nil {
			continue
		}
		a, e := xproto.GetWindowAttributes(d.conn, id).Reply()
		if e != nil {
			continue
		}
		item := windowInfo{ID: uint32(id), PID: d.chromePID, X: int(g.X), Y: int(g.Y), Width: int(g.Width), Height: int(g.Height), Mapped: a.MapState == xproto.MapStateViewable, Focused: focused == id}
		item.OverrideRedirect = a.OverrideRedirect
		item.WindowType = "unknown"
		types, e := xproto.GetProperty(d.conn, false, id, d.atoms["_NET_WM_WINDOW_TYPE"], xproto.AtomAtom, 0, 16).Reply()
		if e == nil && types.Format == 32 {
			for offset := 0; offset+4 <= len(types.Value); offset += 4 {
				switch xproto.Atom(xgb.Get32(types.Value[offset:])) {
				case d.atoms["_NET_WM_WINDOW_TYPE_NORMAL"]:
					item.WindowType = "normal"
				case d.atoms["_NET_WM_WINDOW_TYPE_DIALOG"]:
					item.WindowType = "dialog"
				}
			}
		}
		if item.Focused {
			result.FocusWindow = uint32(id)
		}
		result.Windows = append(result.Windows, item)
	}
	return result, nil
}

// resize lays out the output mode and the browser window at width x height.
// With sizeClass the framebuffer is a size class holding them; without it,
// the framebuffer is exactly that size. Frames stop at the layout's start and
// resume once the browser has painted the new geometry (or the paint wait
// ends), so no frame shows a configure the browser has not drawn.
func (d *display) resize(width, height int, windowID uint32, sizeClass bool) (displayInfo, error) {
	if !validSize(width, height) {
		return displayInfo{}, invalid()
	}
	if windowID != 0 {
		before, err := d.info()
		if err != nil {
			return displayInfo{}, err
		}
		owned := false
		for _, window := range before.Windows {
			if window.ID == windowID && window.Mapped && !window.OverrideRedirect && window.WindowType == "normal" {
				owned = true
				break
			}
		}
		if !owned {
			return displayInfo{}, invalid()
		}
	}
	if err := d.finishPendingPaint(); err != nil {
		return displayInfo{}, err
	}
	oldW, oldH, err := d.size()
	if err != nil {
		return displayInfo{}, err
	}
	limits, err := randr.GetScreenSizeRange(d.conn, d.screen.Root).Reply()
	if err != nil || width > int(limits.MaxWidth) || height > int(limits.MaxHeight) {
		return displayInfo{}, invalid()
	}
	framebufferW, framebufferH := width, height
	if sizeClass {
		settled := d.framebufferChanged.IsZero() || time.Since(d.framebufferChanged) >= sizeClassSettle
		framebufferW, framebufferH = framebufferFor(width, height, oldW, oldH, int(limits.MaxWidth), int(limits.MaxHeight), settled)
	}
	d.frames.beginLayout()
	result, err := d.layout(width, height, framebufferW, framebufferH, oldW, oldH, windowID)
	visible := image.Rectangle{}
	if framebufferW != width || framebufferH != height {
		visible = image.Rect(0, 0, width, height)
	}
	d.frames.endLayout(visible, err == nil)
	return result, err
}
func (d *display) layout(width, height, framebufferW, framebufferH, oldW, oldH int, windowID uint32) (displayInfo, error) {
	resources, err := randr.GetScreenResourcesCurrent(d.conn, d.screen.Root).Reply()
	if err != nil || len(resources.Outputs) != 1 {
		return displayInfo{}, unavailable()
	}
	output := resources.Outputs[0]
	oi, err := randr.GetOutputInfo(d.conn, output, resources.ConfigTimestamp).Reply()
	if err != nil || oi.Crtc == 0 {
		return displayInfo{}, unavailable()
	}
	crtc := oi.Crtc
	scanout, err := randr.GetCrtcInfo(d.conn, crtc, resources.ConfigTimestamp).Reply()
	if err != nil {
		return displayInfo{}, unavailable()
	}
	framebufferChanges := framebufferW != oldW || framebufferH != oldH
	if !framebufferChanges && scanout.Mode != 0 && int(scanout.Width) == width && int(scanout.Height) == height {
		return d.resizeWindow(width, height, framebufferW, framebufferH, windowID)
	}
	name := fmt.Sprintf("ambit-%dx%d", width, height)
	mode, exists := d.modes[name]
	if !exists {
		// Xvfb uses timing only as an output mode descriptor. A valid bounded
		// blanking interval lets every dock size follow the same RandR operation.
		ht, vt := width+160, height+45
		created, e := randr.CreateMode(d.conn, d.screen.Root, randr.ModeInfo{Width: uint16(width), Height: uint16(height), DotClock: uint32(ht * vt * 60), HsyncStart: uint16(width + 48), HsyncEnd: uint16(width + 80), Htotal: uint16(ht), VsyncStart: uint16(height + 3), VsyncEnd: uint16(height + 6), Vtotal: uint16(vt), NameLen: uint16(len(name))}, name).Reply()
		if e != nil {
			return displayInfo{}, unavailable()
		}
		mode = created.Mode
		if e := randr.AddOutputModeChecked(d.conn, output, mode).Check(); e != nil {
			return displayInfo{}, unavailable()
		}
		d.modes[name] = mode
	}
	// Disable the old scanout before shrinking the framebuffer; grow first
	// when needed. Each request is checked. Any failure after scanout mutation
	// is an unknown outcome, never a reason to replay input against guessed
	// dimensions.
	if framebufferW < oldW || framebufferH < oldH {
		r, e := randr.SetCrtcConfig(d.conn, crtc, 0, 0, 0, 0, 0, randr.RotationRotate0, nil).Reply()
		if e != nil || r.Status != 0 {
			return displayInfo{}, unknown()
		}
	}
	if framebufferChanges {
		d.framebufferChanged = time.Now()
		if err := randr.SetScreenSizeChecked(d.conn, d.screen.Root, uint16(framebufferW), uint16(framebufferH), uint32(max(1, framebufferW*254/960)), uint32(max(1, framebufferH*254/960))).Check(); err != nil {
			return displayInfo{}, unknown()
		}
	}
	r, err := randr.SetCrtcConfig(d.conn, crtc, 0, 0, 0, 0, mode, randr.RotationRotate0, []randr.Output{output}).Reply()
	if err != nil || r.Status != 0 {
		return displayInfo{}, unknown()
	}
	// Only keep one dynamically generated mode; a long resize gesture cannot
	// grow server state indefinitely.
	for oldName, oldMode := range d.modes {
		if oldMode != mode {
			_ = randr.DeleteOutputModeChecked(d.conn, output, oldMode).Check()
			_ = randr.DestroyModeChecked(d.conn, oldMode).Check()
			delete(d.modes, oldName)
		}
	}
	return d.resizeWindow(width, height, framebufferW, framebufferH, windowID)
}
func (d *display) resizeWindow(width, height, framebufferW, framebufferH int, windowID uint32) (displayInfo, error) {
	if windowID != 0 {
		if err := d.paintAfterResize(xproto.Window(windowID), width, height); err != nil {
			return displayInfo{}, unknown()
		}
	}
	current, err := d.info()
	if err != nil || current.Width != framebufferW || current.Height != framebufferH {
		return displayInfo{}, unknown()
	}
	if windowID != 0 {
		for _, window := range current.Windows {
			if window.ID == windowID && window.X == 0 && window.Y == 0 && window.Width == width && window.Height == height {
				return current, nil
			}
		}
		return displayInfo{}, unknown()
	}
	return current, nil
}
