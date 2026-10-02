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

func focusTestTransient(t *testing.T, peer *xgb.Conn, child, parent xproto.Window) {
	t.Helper()
	data := make([]byte, 4)
	xgb.Put32(data, uint32(parent))
	if err := xproto.ChangePropertyChecked(peer, xproto.PropModeReplace, child, closeTestAtom(t, peer, "WM_TRANSIENT_FOR"), xproto.AtomWindow, 32, 1, data).Check(); err != nil {
		t.Fatal(err)
	}
}

func waitTestFocus(t *testing.T, peer *xgb.Conn, expected xproto.Window) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		focus, err := xproto.GetInputFocus(peer).Reply()
		if err != nil {
			t.Fatal(err)
		}
		if focus.Focus == expected {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("focus=%d expected=%d", focus.Focus, expected)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitTestDesktopOwner(t *testing.T, d *display, window xproto.Window, modal bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		d.eventMu.Lock()
		_, linked := d.desktopParents[window]
		ready := d.desktopChrome == window
		if modal {
			ready = linked
		}
		d.eventMu.Unlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper never proved window %d (modal=%v)", window, modal)
		}
		time.Sleep(time.Millisecond)
	}
}

func focusTestChrome(t *testing.T, peer *xgb.Conn, d *display) xproto.Window {
	t.Helper()
	parent := closeTestWindow(t, peer, d.chromePID, "_NET_WM_WINDOW_TYPE_NORMAL", false, true, false)
	if err := xproto.SetInputFocusChecked(peer, xproto.InputFocusParent, parent, xproto.TimeCurrentTime).Check(); err != nil {
		t.Fatal(err)
	}
	waitTestDesktopOwner(t, d, parent, false)
	return parent
}

func focusTestModal(t *testing.T, peer *xgb.Conn, d *display, parent xproto.Window) xproto.Window {
	t.Helper()
	modal := closeTestWindow(t, peer, d.desktopProcess.PID, "_NET_WM_WINDOW_TYPE_DIALOG", false, false, false)
	focusTestTransient(t, peer, modal, parent)
	if err := xproto.MapWindowChecked(peer, modal).Check(); err != nil {
		t.Fatal(err)
	}
	waitTestDesktopOwner(t, d, modal, true)
	if err := xproto.SetInputFocusChecked(peer, xproto.InputFocusParent, modal, xproto.TimeCurrentTime).Check(); err != nil {
		t.Fatal(err)
	}
	return modal
}

func testCurrentFocus(t *testing.T, peer *xgb.Conn) xproto.Window {
	t.Helper()
	focus, err := xproto.GetInputFocus(peer).Reply()
	if err != nil {
		t.Fatal(err)
	}
	return focus.Focus
}

func TestXvfbOwnedDesktopTransientReturnsFocusToItsProvenParent(t *testing.T) {
	startXvfb(t, 800, 600)
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
	modal := closeTestWindow(t, peer, pid, "_NET_WM_WINDOW_TYPE_DIALOG", false, false, false)
	focusTestTransient(t, peer, modal, parent)
	if err := xproto.MapWindowChecked(peer, modal).Check(); err != nil {
		t.Fatal(err)
	}
	waitTestDesktopOwner(t, d, modal, true)
	if err := xproto.SetInputFocusChecked(peer, xproto.InputFocusParent, modal, xproto.TimeCurrentTime).Check(); err != nil {
		t.Fatal(err)
	}
	// The helper proved the actual PID, birth and transient before retirement.
	if _, err := xproto.GetWindowAttributes(peer, modal).Reply(); err != nil {
		t.Fatal(err)
	}
	if err := xproto.DestroyWindowChecked(peer, modal).Check(); err != nil {
		t.Fatal(err)
	}
	waitTestFocus(t, peer, parent)
}

func TestXvfbDesktopRetirementDoesNotStealAnotherLiveWindowFocus(t *testing.T) {
	startXvfb(t, 800, 600)
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
	other := closeTestWindow(t, peer, chromePID+1, "_NET_WM_WINDOW_TYPE_NORMAL", false, true, false)
	modal := closeTestWindow(t, peer, pid, "_NET_WM_WINDOW_TYPE_DIALOG", false, false, false)
	focusTestTransient(t, peer, modal, parent)
	if err := xproto.MapWindowChecked(peer, modal).Check(); err != nil {
		t.Fatal(err)
	}
	waitTestDesktopOwner(t, d, modal, true)
	if err := xproto.SetInputFocusChecked(peer, xproto.InputFocusParent, other, xproto.TimeCurrentTime).Check(); err != nil {
		t.Fatal(err)
	}
	if err := xproto.DestroyWindowChecked(peer, modal).Check(); err != nil {
		t.Fatal(err)
	}
	waitTestFocus(t, peer, other)
}

func TestXvfbUnobservedRapidDesktopRetirementCannotSupplyOwnership(t *testing.T) {
	startXvfb(t, 800, 600)
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
	d.eventMu.Lock()
	defer d.eventMu.Unlock()
	modal := closeTestWindow(t, peer, pid, "_NET_WM_WINDOW_TYPE_DIALOG", false, false, false)
	focusTestTransient(t, peer, modal, parent)
	if err := xproto.MapWindowChecked(peer, modal).Check(); err != nil {
		t.Fatal(err)
	}
	if err := xproto.SetInputFocusChecked(peer, xproto.InputFocusParent, modal, xproto.TimeCurrentTime).Check(); err != nil {
		t.Fatal(err)
	}
	if err := xproto.DestroyWindowChecked(peer, modal).Check(); err != nil {
		t.Fatal(err)
	}
	d.desktopMapped(modal)
	d.desktopRetired(modal)
	focus, err := xproto.GetInputFocus(peer).Reply()
	if err != nil {
		t.Fatal(err)
	}
	if focus.Focus == parent {
		t.Fatal("a vanished unobserved modal supplied parent authority")
	}
}

func TestXvfbUnownedRetirementDoesNotChooseChromeFromVacantFocus(t *testing.T) {
	startXvfb(t, 800, 600)
	const chromePID = 4242
	peer := newPainter(t).conn
	pid := uint32(os.Getpid())
	started, _ := processStarted(pid)
	d, err := openDisplay(chromePID, &desktopProcess{PID: pid, Started: started})
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	parent := closeTestWindow(t, peer, chromePID, "_NET_WM_WINDOW_TYPE_NORMAL", false, true, false)
	foreign := closeTestWindow(t, peer, chromePID+1, "_NET_WM_WINDOW_TYPE_DIALOG", false, true, false)
	if err := xproto.SetInputFocusChecked(peer, xproto.InputFocusParent, foreign, xproto.TimeCurrentTime).Check(); err != nil {
		t.Fatal(err)
	}
	d.eventMu.Lock()
	if err := xproto.DestroyWindowChecked(peer, foreign).Check(); err != nil {
		d.eventMu.Unlock()
		t.Fatal(err)
	}
	d.desktopRetired(foreign)
	focus, err := xproto.GetInputFocus(peer).Reply()
	d.eventMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if focus.Focus == parent {
		t.Fatal("unowned retirement guessed the Chrome parent")
	}
}

func TestXvfbOwnedDesktopRetirementRevalidatesBirthAndParent(t *testing.T) {
	for _, state := range []string{"stale-birth", "destroyed-parent", "unmapped-parent", "remapped-transient", "duplicate-retirement"} {
		t.Run(state, func(t *testing.T) {
			startXvfb(t, 800, 600)
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
			modal := focusTestModal(t, peer, d, parent)
			d.eventMu.Lock()
			defer d.eventMu.Unlock()
			switch state {
			case "stale-birth":
				d.desktopProcess.Started++
			case "destroyed-parent":
				if err := xproto.DestroyWindowChecked(peer, parent).Check(); err != nil {
					t.Fatal(err)
				}
				d.desktopRetired(parent)
			case "unmapped-parent":
				if err := xproto.UnmapWindowChecked(peer, parent).Check(); err != nil {
					t.Fatal(err)
				}
			case "remapped-transient":
				if err := xproto.UnmapWindowChecked(peer, modal).Check(); err != nil {
					t.Fatal(err)
				}
				if err := xproto.MapWindowChecked(peer, modal).Check(); err != nil {
					t.Fatal(err)
				}
			}
			if state != "remapped-transient" {
				if err := xproto.DestroyWindowChecked(peer, modal).Check(); err != nil {
					t.Fatal(err)
				}
			}
			d.desktopRetired(modal)
			if state == "duplicate-retirement" {
				if got := testCurrentFocus(t, peer); got != parent {
					t.Fatalf("first owned retirement focus=%d expected=%d", got, parent)
				}
				if err := xproto.SetInputFocusChecked(peer, xproto.InputFocusPointerRoot, d.screen.Root, xproto.TimeCurrentTime).Check(); err != nil {
					t.Fatal(err)
				}
				d.desktopRetired(modal)
			}
			if got := testCurrentFocus(t, peer); got == parent {
				t.Fatalf("%s supplied stale restoration authority", state)
			}
		})
	}
}

func TestXvfbNestedDesktopRetirementReturnsThroughItsOwnedParents(t *testing.T) {
	startXvfb(t, 800, 600)
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
	outer := focusTestModal(t, peer, d, parent)
	inner := focusTestModal(t, peer, d, outer)
	if err := xproto.DestroyWindowChecked(peer, inner).Check(); err != nil {
		t.Fatal(err)
	}
	waitTestFocus(t, peer, outer)
	if err := xproto.DestroyWindowChecked(peer, outer).Check(); err != nil {
		t.Fatal(err)
	}
	waitTestFocus(t, peer, parent)
}

func TestXvfbDesktopOwnerSeedsOnlyActuallyFocusedChromeAtStartup(t *testing.T) {
	startXvfb(t, 800, 600)
	const chromePID = 4242
	peer := newPainter(t).conn
	parent := closeTestWindow(t, peer, chromePID, "_NET_WM_WINDOW_TYPE_NORMAL", false, true, false)
	if err := xproto.SetInputFocusChecked(peer, xproto.InputFocusParent, parent, xproto.TimeCurrentTime).Check(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(os.Getpid())
	started, _ := processStarted(pid)
	d, err := openDisplay(chromePID, &desktopProcess{PID: pid, Started: started})
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	waitTestDesktopOwner(t, d, parent, false)
	modal := focusTestModal(t, peer, d, parent)
	if err := xproto.DestroyWindowChecked(peer, modal).Check(); err != nil {
		t.Fatal(err)
	}
	waitTestFocus(t, peer, parent)
}
