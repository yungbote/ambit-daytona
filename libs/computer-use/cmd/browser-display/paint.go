// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"time"

	"github.com/robotn/xgb"
	"github.com/robotn/xgb/xproto"
)

// The pinned xgb version has no generated SYNC binding. These bounded standard
// requests use its existing connection/cookie transport, not another X client.
// Wire layout: X11 extensions/syncproto.h; resize contract: EWMH section6.2.
type paintAlarm struct {
	sequence uint16
	alarm    uint32
	value    uint64
	state    byte
	raw      [32]byte
}

func (e paintAlarm) Bytes() []byte      { return append([]byte(nil), e.raw[:]...) }
func (e paintAlarm) SequenceId() uint16 { return e.sequence }
func (e paintAlarm) String() string     { return "SYNC paint acknowledgment" }

type paintError struct {
	sequence uint16
	resource uint32
}

func (e paintError) SequenceId() uint16 { return e.sequence }
func (e paintError) BadId() uint32      { return e.resource }
func (e paintError) Error() string      { return "The native paint counter is unavailable." }
func (d *display) initPaint() error {
	extension, err := xproto.QueryExtension(d.conn, 4, "SYNC").Reply()
	if err != nil || !extension.Present {
		return unavailable()
	}
	d.syncOpcode = extension.MajorOpcode
	d.paintEvents = make(chan paintAlarm, 4)
	xgb.NewEventFuncs[int(extension.FirstEvent)+1] = func(data []byte) xgb.Event {
		value := paintAlarm{sequence: xgb.Get16(data[2:]), alarm: xgb.Get32(data[4:]), value: uint64(xgb.Get32(data[8:]))<<32 | uint64(xgb.Get32(data[12:])), state: data[28]}
		copy(value.raw[:], data)
		return value
	}
	for offset := 0; offset < 3; offset++ {
		xgb.NewErrorFuncs[int(extension.FirstError)+offset] = func(data []byte) xgb.Error { return paintError{xgb.Get16(data[2:]), xgb.Get32(data[4:])} }
	}
	reply, err := d.syncRequest(0, []uint32{3 | (1 << 8)}, true).Reply()
	if err != nil || len(reply) < 10 || reply[8] < 3 {
		return unavailable()
	}
	return nil
}
func (d *display) syncRequest(operation byte, values []uint32, reply bool) *xgb.Cookie {
	data := make([]byte, 4+4*len(values))
	data[0] = d.syncOpcode
	data[1] = operation
	xgb.Put16(data[2:], uint16(len(data)/4))
	for index, value := range values {
		xgb.Put32(data[4+index*4:], value)
	}
	cookie := d.conn.NewCookie(true, reply)
	d.conn.NewRequest(data, cookie)
	return cookie
}
func (d *display) paintAfterResize(window xproto.Window, width, height int) error {
	geometry, err := xproto.GetGeometry(d.conn, xproto.Drawable(window)).Reply()
	if err != nil {
		return unknown()
	}
	// Moving an already painted, unchanged-size window requires no resize paint.
	if int(geometry.Width) == width && int(geometry.Height) == height {
		return xproto.ConfigureWindowChecked(d.conn, window, xproto.ConfigWindowX|xproto.ConfigWindowY, []uint32{0, 0}).Check()
	}
	property, err := xproto.GetProperty(d.conn, false, window, d.atoms["_NET_WM_SYNC_REQUEST_COUNTER"], xproto.AtomCardinal, 0, 1).Reply()
	if err != nil || property.Format != 32 || len(property.Value) != 4 {
		return unavailable()
	}
	counter := xgb.Get32(property.Value)
	queried, err := d.syncRequest(5, []uint32{counter}, true).Reply()
	if err != nil || len(queried) < 16 {
		return unavailable()
	}
	target := (uint64(xgb.Get32(queried[8:]))<<32 | uint64(xgb.Get32(queried[12:]))) + 1
	if target == 0 || target>>63 != 0 {
		return unavailable()
	}
	id, err := d.conn.NewId()
	if err != nil {
		return unavailable()
	}
	alarm := uint32(id)
	// Counter, Absolute, target, PositiveComparison, zero delta, events enabled.
	if err := d.syncRequest(8, []uint32{alarm, 63, counter, 0, uint32(target >> 32), uint32(target), 2, 0, 0, 1}, false).Check(); err != nil {
		return unavailable()
	}
	defer func() { _ = d.syncRequest(11, []uint32{alarm}, false).Check() }()
	data := xproto.ClientMessageDataUnionData32New([]uint32{uint32(d.atoms["_NET_WM_SYNC_REQUEST"]), 0, uint32(target), uint32(target >> 32), 0})
	event := xproto.ClientMessageEvent{Format: 32, Window: window, Type: d.atoms["WM_PROTOCOLS"], Data: data}
	if err := xproto.SendEventChecked(d.conn, false, window, 0, string(event.Bytes())).Check(); err != nil {
		return unknown()
	}
	if err := xproto.ConfigureWindowChecked(d.conn, window, xproto.ConfigWindowX|xproto.ConfigWindowY|xproto.ConfigWindowWidth|xproto.ConfigWindowHeight, []uint32{0, 0, uint32(width), uint32(height)}).Check(); err != nil {
		return unknown()
	}
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return unknown()
		case <-d.clipboard.done:
			return unknown()
		case painted := <-d.paintEvents:
			if painted.alarm != alarm {
				continue
			}
			if painted.value >= target && painted.state != 2 {
				return nil
			}
			return unknown()
		}
	}
}
