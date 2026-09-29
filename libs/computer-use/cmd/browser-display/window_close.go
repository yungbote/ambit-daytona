// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"github.com/robotn/xgb"
	"github.com/robotn/xgb/xproto"
)

// closeWindows asks every normal window of this exact owned browser to close
// as a person closing it would. Chrome's shutdown then flushes the profile;
// SIGTERM alone can end it before its cookie store writes a recent sign-in.
// The driver owns the exit deadline and cleanup. This helper never signals
// another process or acts on another PID's window, a dialog or a popup.
func (d *display) closeWindows() error {
	info, err := d.info()
	if err != nil {
		return unavailable()
	}
	windows := []xproto.Window{}
	for _, window := range info.Windows {
		if window.PID != d.chromePID || window.OverrideRedirect || window.WindowType != "normal" {
			continue
		}
		id := xproto.Window(window.ID)
		protocols, err := xproto.GetProperty(d.conn, false, id, d.atoms["WM_PROTOCOLS"], xproto.AtomAtom, 0, 128).Reply()
		if err != nil || protocols.Format != 32 {
			return unavailable()
		}
		closes := false
		for offset := 0; offset+4 <= len(protocols.Value); offset += 4 {
			closes = closes || xproto.Atom(xgb.Get32(protocols.Value[offset:])) == d.atoms["WM_DELETE_WINDOW"]
		}
		if !closes {
			return unavailable()
		}
		windows = append(windows, id)
	}
	// Validate every protocol before the first effect. A vanished window or
	// failed send after that is an unknown outcome; never replay a close.
	for _, window := range windows {
		message := xproto.ClientMessageEvent{
			Format: 32, Window: window, Type: d.atoms["WM_PROTOCOLS"],
			Data: xproto.ClientMessageDataUnionData32New([]uint32{uint32(d.atoms["WM_DELETE_WINDOW"]), uint32(xproto.TimeCurrentTime), 0, 0, 0}),
		}
		if err := xproto.SendEventChecked(d.conn, false, window, 0, string(message.Bytes())).Check(); err != nil {
			return unknown()
		}
	}
	return nil
}
