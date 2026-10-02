// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/robotn/xgb"
	"github.com/robotn/xgb/xproto"
)

// The native display owner supplies its already-owned desktop child. A PID
// alone cannot admit a later process that reuses it after service retirement.
type desktopProcess struct {
	PID     uint32 `json:"pid"`
	Started uint64 `json:"started"`
}

type desktopParent struct {
	parent xproto.Window
	chrome xproto.Window
}

func processStarted(pid uint32) (uint64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	at := strings.LastIndexByte(string(data), ')')
	if at < 0 {
		return 0, false
	}
	fields := strings.Fields(string(data[at+1:]))
	if len(fields) <= 19 || fields[0] == "Z" || fields[0] == "X" {
		return 0, false
	}
	started, err := strconv.ParseUint(fields[19], 10, 64)
	return started, err == nil && started > 0
}

func desktopBinding(raw string) (*desktopProcess, error) {
	if raw == "" {
		return nil, nil
	}
	var process desktopProcess
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&process) != nil || process.PID == 0 || process.Started == 0 {
		return nil, invalid()
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, invalid()
	}
	started, live := processStarted(process.PID)
	if !live || started != process.Started {
		return nil, unavailable()
	}
	return &process, nil
}

func (d *display) startDesktopFocus(process *desktopProcess) error {
	if process == nil {
		return nil
	}
	attributes, err := xproto.GetWindowAttributes(d.conn, d.screen.Root).Reply()
	if err != nil {
		return err
	}
	if err := xproto.ChangeWindowAttributesChecked(d.conn, d.screen.Root, xproto.CwEventMask,
		[]uint32{attributes.YourEventMask | xproto.EventMaskSubstructureNotify}).Check(); err != nil {
		return err
	}
	d.desktopProcess = process
	d.desktopParents = map[xproto.Window]desktopParent{}
	d.desktopFocused()
	tree, err := xproto.QueryTree(d.conn, d.screen.Root).Reply()
	if err != nil {
		return err
	}
	for _, child := range tree.Children {
		d.desktopMapped(child)
	}
	return nil
}

func (d *display) desktopLive() bool {
	process := d.desktopProcess
	if process == nil {
		return false
	}
	started, live := processStarted(process.PID)
	return live && started == process.Started
}

// Focus observations establish the parent; an empty display never supplies one.
func (d *display) desktopFocused() {
	if d.desktopProcess == nil {
		return
	}
	info, err := d.info()
	if err != nil {
		return
	}
	for _, window := range info.Windows {
		if window.Focused && window.Mapped && !window.OverrideRedirect && window.WindowType == "normal" {
			d.desktopChrome = xproto.Window(window.ID)
			return
		}
	}
}

func (d *display) desktopWatch(window xproto.Window) bool {
	attributes, err := xproto.GetWindowAttributes(d.conn, window).Reply()
	return err == nil && xproto.ChangeWindowAttributesChecked(d.conn, window, xproto.CwEventMask,
		[]uint32{attributes.YourEventMask | xproto.EventMaskFocusChange | xproto.EventMaskPropertyChange}).Check() == nil
}

func (d *display) windowPID(window xproto.Window) uint32 {
	property, err := xproto.GetProperty(d.conn, false, window, d.atoms["_NET_WM_PID"], xproto.AtomCardinal, 0, 1).Reply()
	if err != nil || property.Format != 32 || len(property.Value) != 4 {
		return 0
	}
	return xgb.Get32(property.Value)
}

// Called only by the existing X11 event reader. Transient links are retained
// while mapped because a destroyed window can no longer disclose its parent.
func (d *display) desktopMapped(window xproto.Window) {
	process := d.desktopProcess
	if process == nil {
		return
	}
	pid := d.windowPID(window)
	if pid == d.chromePID {
		if d.desktopWatch(window) {
			d.desktopFocused()
		}
		return
	}
	if pid != process.PID || !d.desktopLive() || !d.mappedOwner(window, process.PID) || !d.desktopWatch(window) {
		return
	}
	property, err := xproto.GetProperty(d.conn, false, window, d.atoms["WM_TRANSIENT_FOR"], xproto.AtomWindow, 0, 1).Reply()
	if err != nil || property.Format != 32 || len(property.Value) != 4 {
		return
	}
	parent := xproto.Window(xgb.Get32(property.Value))
	chrome := parent
	if d.windowPID(parent) != d.chromePID {
		link, owned := d.desktopParents[parent]
		if !owned || d.windowPID(parent) != process.PID {
			return
		}
		chrome = link.chrome
	}
	if chrome == d.desktopChrome && d.normalChrome(chrome) {
		d.desktopParents[window] = desktopParent{parent: parent, chrome: chrome}
	}
}

func (d *display) mappedOwner(window xproto.Window, pid uint32) bool {
	if d.windowPID(window) != pid {
		return false
	}
	attributes, err := xproto.GetWindowAttributes(d.conn, window).Reply()
	return err == nil && attributes.MapState == xproto.MapStateViewable
}

func (d *display) desktopRetired(window xproto.Window) {
	if window == d.desktopChrome {
		d.desktopChrome = 0
	}
	link, owned := d.desktopParents[window]
	delete(d.desktopParents, window)
	if !owned || !d.desktopLive() {
		return
	}
	// No client can replace the target or choose focus between this final
	// observation and the restoration. Process IO happened before the grab.
	if xproto.GrabServerChecked(d.conn).Check() != nil {
		return
	}
	defer xproto.UngrabServerChecked(d.conn).Check()
	if attributes, err := xproto.GetWindowAttributes(d.conn, window).Reply(); err == nil && attributes.MapState == xproto.MapStateViewable {
		return // An unmap event for a window already remapped is not retirement.
	}
	focus, err := xproto.GetInputFocus(d.conn).Reply()
	if err != nil || focus.Focus != xproto.WindowNone && focus.Focus != xproto.InputFocusPointerRoot && focus.Focus != d.screen.Root {
		return // A live window chosen by the user keeps focus.
	}
	parent := link.chrome
	if d.desktopProcess != nil && d.mappedOwner(link.parent, d.desktopProcess.PID) {
		if retained, found := d.desktopParents[link.parent]; found && retained.chrome == link.chrome {
			parent = link.parent
		}
	}
	if link.chrome != d.desktopChrome || !d.normalChrome(link.chrome) {
		return
	}
	_ = xproto.SetInputFocusChecked(d.conn, xproto.InputFocusParent, parent, xproto.TimeCurrentTime).Check()
}

func (d *display) normalChrome(window xproto.Window) bool {
	if d.windowPID(window) != d.chromePID {
		return false
	}
	attributes, err := xproto.GetWindowAttributes(d.conn, window).Reply()
	if err != nil || attributes.MapState != xproto.MapStateViewable || attributes.OverrideRedirect {
		return false
	}
	types, err := xproto.GetProperty(d.conn, false, window, d.atoms["_NET_WM_WINDOW_TYPE"], xproto.AtomAtom, 0, 16).Reply()
	if err != nil || types.Format != 32 {
		return false
	}
	kind := ""
	for offset := 0; offset+4 <= len(types.Value); offset += 4 {
		switch xproto.Atom(xgb.Get32(types.Value[offset:])) {
		case d.atoms["_NET_WM_WINDOW_TYPE_NORMAL"]:
			kind = "normal"
		case d.atoms["_NET_WM_WINDOW_TYPE_DIALOG"]:
			kind = "dialog"
		}
	}
	return kind == "normal"
}
