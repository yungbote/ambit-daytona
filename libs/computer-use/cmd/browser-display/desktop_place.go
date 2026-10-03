// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"github.com/robotn/xgb"
	"github.com/robotn/xgb/xproto"
)

// The private display has no window manager, so nothing places a toolkit's
// dialog: an owned GTK transient opens where the toolkit puts it, at its
// natural size, and on a phone-width dock that is wider than the Chrome
// window the viewer streams, with the chooser's buttons outside the picture.
// The helper places its owned transients as a window manager would: centred
// on their Chrome window and no larger than it, never below the minimum size
// the toolkit declares.

type placement struct {
	x, y          int32
	width, height uint32
}

// minimumSize is the PMinSize part of WM_NORMAL_HINTS; zero when absent.
type minimumSize struct {
	width, height uint32
}

// containedPlacement is where a window manager would put a transient of size
// `current` over `parent`. It shrinks only what does not fit and keeps the
// toolkit's minimum; when even the minimum is wider or taller than the
// parent, that edge starts at the parent's, so the toolkit's leading content
// stays in the picture.
func containedPlacement(parent placement, current placement, minimum minimumSize) placement {
	axis := func(origin int32, available, size, least uint32) (int32, uint32) {
		if size > available {
			size = available
		}
		if size < least {
			size = least
		}
		if size >= available {
			return origin, size
		}
		return origin + int32((available-size)/2), size
	}
	x, width := axis(parent.x, parent.width, current.width, minimum.width)
	y, height := axis(parent.y, parent.height, current.height, minimum.height)
	return placement{x: x, y: y, width: width, height: height}
}

// readMinimumSize reads the PMinSize fields of WM_NORMAL_HINTS: a flags word,
// four obsolete words, then the minimum width and height.
func readMinimumSize(value []byte) minimumSize {
	const pMinSize = 1 << 4
	if len(value) < 7*4 || xgb.Get32(value)&pMinSize == 0 {
		return minimumSize{}
	}
	return minimumSize{width: xgb.Get32(value[5*4:]), height: xgb.Get32(value[6*4:])}
}

func (d *display) windowPlacement(window xproto.Window) (placement, bool) {
	geometry, err := xproto.GetGeometry(d.conn, xproto.Drawable(window)).Reply()
	if err != nil || geometry.Width == 0 || geometry.Height == 0 {
		return placement{}, false
	}
	// Owned top-levels are children of the root: their geometry is in root
	// coordinates, which is the framebuffer the viewer streams from.
	return placement{x: int32(geometry.X), y: int32(geometry.Y), width: uint32(geometry.Width), height: uint32(geometry.Height)}, true
}

// desktopPlace contains one admitted owned transient in its Chrome window.
// Called only by the X11 event reader, after the transient's ownership proof.
func (d *display) desktopPlace(window xproto.Window, link desktopParent) {
	parent, ok := d.windowPlacement(link.chrome)
	if !ok {
		return
	}
	current, ok := d.windowPlacement(window)
	if !ok {
		return
	}
	var minimum minimumSize
	if hints, err := xproto.GetProperty(d.conn, false, window, xproto.AtomWmNormalHints, xproto.AtomWmSizeHints, 0, 18).Reply(); err == nil && hints.Format == 32 {
		minimum = readMinimumSize(hints.Value)
	}
	target := containedPlacement(parent, current, minimum)
	if target == current {
		return
	}
	_ = xproto.ConfigureWindowChecked(d.conn, window,
		xproto.ConfigWindowX|xproto.ConfigWindowY|xproto.ConfigWindowWidth|xproto.ConfigWindowHeight,
		[]uint32{uint32(target.x), uint32(target.y), target.width, target.height}).Check()
}

// desktopConfigured re-places what a geometry change can push out of the
// picture: every transient of a Chrome window that moved or resized, or an
// owned transient that the toolkit itself resized.
func (d *display) desktopConfigured(window xproto.Window) {
	if link, owned := d.desktopParents[window]; owned {
		d.desktopPlace(window, link)
		return
	}
	for child, link := range d.desktopParents {
		if link.chrome == window {
			d.desktopPlace(child, link)
		}
	}
}
