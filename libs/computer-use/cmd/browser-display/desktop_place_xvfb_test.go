// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"os"
	"testing"
	"time"

	"github.com/robotn/xgb"
	"github.com/robotn/xgb/xproto"
)

func placeTestConfigure(t *testing.T, peer *xgb.Conn, window xproto.Window, p placement) {
	t.Helper()
	if err := xproto.ConfigureWindowChecked(peer, window,
		xproto.ConfigWindowX|xproto.ConfigWindowY|xproto.ConfigWindowWidth|xproto.ConfigWindowHeight,
		[]uint32{uint32(p.x), uint32(p.y), p.width, p.height}).Check(); err != nil {
		t.Fatal(err)
	}
}

func placeTestMinimum(t *testing.T, peer *xgb.Conn, window xproto.Window, minimum minimumSize) {
	t.Helper()
	value := make([]byte, 18*4)
	xgb.Put32(value, 1<<4)
	xgb.Put32(value[5*4:], minimum.width)
	xgb.Put32(value[6*4:], minimum.height)
	if err := xproto.ChangePropertyChecked(peer, xproto.PropModeReplace, window, xproto.AtomWmNormalHints, xproto.AtomWmSizeHints, 32, 18, value).Check(); err != nil {
		t.Fatal(err)
	}
}

func waitTestPlacement(t *testing.T, peer *xgb.Conn, window xproto.Window, want placement) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		geometry, err := xproto.GetGeometry(peer, xproto.Drawable(window)).Reply()
		if err != nil {
			t.Fatal(err)
		}
		got := placement{x: int32(geometry.X), y: int32(geometry.Y), width: uint32(geometry.Width), height: uint32(geometry.Height)}
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("placement=%+v want=%+v", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// The measured GTK chooser (1096x845 device px, minimum 543x362) opens at
// the origin of a 390 CSS px dock's 780 px window: the helper fits it inside
// the window and centres it, follows the window when the dock widens, and
// leaves an unowned window where its client put it.
func TestXvfbOwnedDesktopTransientIsPlacedInsideItsChromeWindow(t *testing.T) {
	startXvfb(t, 3000, 1800)
	const chromePID = 4242
	peer := newPainter(t).conn
	pid := uint32(os.Getpid())
	started, _ := processStarted(pid)
	d, err := openDisplay(chromePID, &desktopProcess{PID: pid, Started: started})
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	parent := focusTestChrome(t, peer, d)
	placeTestConfigure(t, peer, parent, placement{0, 0, 780, 1688})

	modal := closeTestWindow(t, peer, pid, "_NET_WM_WINDOW_TYPE_DIALOG", false, false, false)
	focusTestTransient(t, peer, modal, parent)
	placeTestMinimum(t, peer, modal, minimumSize{543, 362})
	placeTestConfigure(t, peer, modal, placement{0, 0, 1096, 845})
	if err := xproto.MapWindowChecked(peer, modal).Check(); err != nil {
		t.Fatal(err)
	}
	waitTestDesktopOwner(t, d, modal, true)
	waitTestPlacement(t, peer, modal, placement{0, 421, 780, 845})

	// A wider dock re-centres the open dialog inside the window.
	placeTestConfigure(t, peer, parent, placement{0, 0, 1536, 1688})
	waitTestPlacement(t, peer, modal, placement{378, 421, 780, 845})

	// The toolkit growing its own dialog past the window is contained again.
	placeTestConfigure(t, peer, modal, placement{378, 421, 2000, 845})
	waitTestPlacement(t, peer, modal, placement{0, 421, 1536, 845})

	// A window of another process is not the helper's to place.
	stranger := closeTestWindow(t, peer, pid+1, "_NET_WM_WINDOW_TYPE_DIALOG", false, false, false)
	focusTestTransient(t, peer, stranger, parent)
	placeTestConfigure(t, peer, stranger, placement{0, 0, 2000, 900})
	if err := xproto.MapWindowChecked(peer, stranger).Check(); err != nil {
		t.Fatal(err)
	}
	// The reader handles events in order: once it has admitted an owned
	// window mapped after the stranger, it has already passed the stranger.
	marker := closeTestWindow(t, peer, pid, "_NET_WM_WINDOW_TYPE_DIALOG", false, false, false)
	focusTestTransient(t, peer, marker, parent)
	if err := xproto.MapWindowChecked(peer, marker).Check(); err != nil {
		t.Fatal(err)
	}
	waitTestDesktopOwner(t, d, marker, true)
	waitTestPlacement(t, peer, stranger, placement{0, 0, 2000, 900})
}
