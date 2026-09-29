// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/robotn/xgb"
	"github.com/robotn/xgb/xproto"
)

func closeTestWindow(t *testing.T, peer *xgb.Conn, pid uint32, kind string, override, mapped, supportsClose bool) xproto.Window {
	t.Helper()
	screen := xproto.Setup(peer).DefaultScreen(peer)
	window, err := xproto.NewWindowId(peer)
	if err != nil {
		t.Fatal(err)
	}
	overrideValue := uint32(0)
	if override {
		overrideValue = 1
	}
	if err := xproto.CreateWindowChecked(peer, screen.RootDepth, window, screen.Root, 0, 0, 200, 100, 0,
		xproto.WindowClassInputOutput, screen.RootVisual, xproto.CwOverrideRedirect|xproto.CwEventMask,
		[]uint32{overrideValue, xproto.EventMaskStructureNotify}).Check(); err != nil {
		t.Fatal(err)
	}
	property := func(name string, propertyType xproto.Atom, value uint32) {
		bytes := make([]byte, 4)
		xgb.Put32(bytes, value)
		if err := xproto.ChangePropertyChecked(peer, xproto.PropModeReplace, window, closeTestAtom(t, peer, name), propertyType, 32, 1, bytes).Check(); err != nil {
			t.Fatal(err)
		}
	}
	property("_NET_WM_PID", xproto.AtomCardinal, pid)
	property("_NET_WM_WINDOW_TYPE", xproto.AtomAtom, uint32(closeTestAtom(t, peer, kind)))
	if supportsClose {
		property("WM_PROTOCOLS", xproto.AtomAtom, uint32(closeTestAtom(t, peer, "WM_DELETE_WINDOW")))
	}
	if mapped {
		if err := xproto.MapWindowChecked(peer, window).Check(); err != nil {
			t.Fatal(err)
		}
	}
	return window
}

func closeTestAtom(t *testing.T, peer *xgb.Conn, name string) xproto.Atom {
	t.Helper()
	atom, err := xproto.InternAtom(peer, false, uint16(len(name)), name).Reply()
	if err != nil {
		t.Fatal(err)
	}
	return atom.Atom
}

func closeTestMessages(t *testing.T, peer *xgb.Conn) []uint32 {
	t.Helper()
	// A reply behind the sent close messages is a transport barrier, not a
	// delay: the reader has received every earlier event before this reply.
	if _, err := xproto.GetInputFocus(peer).Reply(); err != nil {
		t.Fatal(err)
	}
	closed := []uint32{}
	for {
		event, err := peer.PollForEvent()
		if err != nil {
			t.Fatal(err)
		}
		if event == nil {
			break
		}
		if message, ok := event.(xproto.ClientMessageEvent); ok {
			if message.Format != 32 || message.Type != closeTestAtom(t, peer, "WM_PROTOCOLS") ||
				xproto.Atom(message.Data.Data32[0]) != closeTestAtom(t, peer, "WM_DELETE_WINDOW") {
				t.Fatalf("another client message: %#v", message)
			}
			closed = append(closed, uint32(message.Window))
		}
	}
	sort.Slice(closed, func(i, j int) bool { return closed[i] < closed[j] })
	return closed
}

func TestXvfbCloseWindowsAddressesOnlyEveryNormalWindowOfTheOwnedPID(t *testing.T) {
	startXvfb(t, 800, 600)
	peer := newPainter(t).conn
	pid := uint32(os.Getpid())
	wanted := []uint32{
		uint32(closeTestWindow(t, peer, pid, "_NET_WM_WINDOW_TYPE_NORMAL", false, true, true)),
		uint32(closeTestWindow(t, peer, pid, "_NET_WM_WINDOW_TYPE_NORMAL", false, false, true)),
	}
	closeTestWindow(t, peer, pid+1, "_NET_WM_WINDOW_TYPE_NORMAL", false, true, true)
	closeTestWindow(t, peer, pid, "_NET_WM_WINDOW_TYPE_DIALOG", false, true, true)
	closeTestWindow(t, peer, pid, "_NET_WM_WINDOW_TYPE_NORMAL", true, true, true)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	mustCall(t, d, `{"id":1,"op":"close_windows"}`)
	sort.Slice(wanted, func(i, j int) bool { return wanted[i] < wanted[j] })
	if got := closeTestMessages(t, peer); !reflect.DeepEqual(got, wanted) {
		t.Fatalf("close messages to %v, want only %v", got, wanted)
	}
}

func TestXvfbCloseWindowsValidatesEveryProtocolBeforeClosingAnyWindow(t *testing.T) {
	startXvfb(t, 800, 600)
	peer := newPainter(t).conn
	pid := uint32(os.Getpid())
	closeTestWindow(t, peer, pid, "_NET_WM_WINDOW_TYPE_NORMAL", false, true, true)
	closeTestWindow(t, peer, pid, "_NET_WM_WINDOW_TYPE_NORMAL", false, true, false)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	if _, err := call(t, d, `{"id":1,"op":"close_windows"}`); err == nil {
		t.Fatal("a window without the close protocol was admitted")
	}
	if got := closeTestMessages(t, peer); len(got) != 0 {
		t.Fatalf("closed a window before every protocol was admitted: %v", got)
	}
}

func TestXvfbCloseWindowsAdvertisesItsCapabilityAndAdmitsAnEndedBrowser(t *testing.T) {
	startXvfb(t, 800, 600)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	info, err := d.describe()
	if err != nil {
		t.Fatal(err)
	}
	advertised := false
	for _, feature := range info.Features {
		advertised = advertised || feature == "closeWindows"
	}
	if !advertised {
		t.Fatal("native close is not advertised")
	}
	mustCall(t, d, `{"id":1,"op":"close_windows"}`)
	mustCall(t, d, `{"id":2,"op":"close_windows"}`)
	for _, invalid := range []string{
		`{"id":3,"op":"close_windows","windowId":1}`,
		`{"id":4,"op":"close_windows","events":[]}`,
		`{"id":5,"op":"close_windows","width":100}`,
	} {
		if _, err := decodeRequest([]byte(invalid)); err == nil {
			t.Fatalf("close may not select a caller's window or carry input: %s", invalid)
		}
	}
}
