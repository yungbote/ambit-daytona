// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"errors"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/robotn/xgb"
	"github.com/robotn/xgb/xfixes"
	"github.com/robotn/xgb/xproto"
)

const selectionChunk = 60 * 1024
const selectionDeadline = 3 * time.Second

type clipboard struct {
	display  *display
	window   xproto.Window
	mu       sync.Mutex
	value    []byte
	served   chan struct{}
	notice   chan xgb.Event
	changes  chan xfixes.SelectionNotifyEvent
	done     chan struct{}
	outgoing map[selectionKey]*selectionTransfer
}
type selectionKey struct {
	window   xproto.Window
	property xproto.Atom
}
type selectionTransfer struct {
	data             []byte
	target           xproto.Atom
	deadline         time.Time
	served           chan struct{}
	completeOnDelete bool
}

func (d *display) startClipboard() error {
	id, err := xproto.NewWindowId(d.conn)
	if err != nil {
		return err
	}
	if err := xproto.CreateWindowChecked(d.conn, 0, id, d.screen.Root, 0, 0, 1, 1, 0, xproto.WindowClassInputOnly, 0, xproto.CwEventMask, []uint32{xproto.EventMaskPropertyChange}).Check(); err != nil {
		return err
	}
	if err := xfixes.SelectSelectionInputChecked(d.conn, id, d.atoms["CLIPBOARD"], xfixes.SelectionEventMaskSetSelectionOwner).Check(); err != nil {
		return err
	}
	d.clipboard = &clipboard{display: d, window: id, notice: make(chan xgb.Event, 16), changes: make(chan xfixes.SelectionNotifyEvent, 1), done: make(chan struct{}), outgoing: map[selectionKey]*selectionTransfer{}}
	go d.clipboard.events()
	return nil
}
func (c *clipboard) close() { _ = xproto.DestroyWindowChecked(c.display.conn, c.window).Check() }
func (c *clipboard) events() {
	defer close(c.done)
	for {
		event, err := c.display.conn.WaitForEvent()
		if err != nil || event == nil {
			return
		}
		switch value := event.(type) {
		case xfixes.SelectionNotifyEvent:
			if value.Selection == c.display.atoms["CLIPBOARD"] {
				// Selection ownership is a current observation, not a backlog.
				select {
				case <-c.changes:
				default:
				}
				select {
				case c.changes <- value:
				default:
				}
			}
		case xproto.SelectionRequestEvent:
			c.serve(value)
		case xproto.PropertyNotifyEvent:
			c.advance(value)
			if value.Window == c.window && value.Atom == c.display.atoms["AMB_BROWSER_SELECTION"] {
				select {
				case c.notice <- event:
				default:
				}
			}
		case xproto.SelectionNotifyEvent:
			if value.Requestor == c.window {
				select {
				case c.notice <- event:
				default:
				}
			}
		}
	}
}
func (c *clipboard) own(value []byte) (<-chan struct{}, error) {
	if len(value) > maximumClipboard || !utf8.Valid(value) {
		return nil, invalid()
	}
	c.mu.Lock()
	c.value = append([]byte(nil), value...)
	c.served = make(chan struct{}, 1)
	served := c.served
	c.mu.Unlock()
	if err := xproto.SetSelectionOwnerChecked(c.display.conn, c.window, c.display.atoms["CLIPBOARD"], xproto.TimeCurrentTime).Check(); err != nil {
		return nil, unknown()
	}
	owner, err := xproto.GetSelectionOwner(c.display.conn, c.display.atoms["CLIPBOARD"]).Reply()
	if err != nil || owner.Owner != c.window {
		return nil, unknown()
	}
	return served, nil
}
func (c *clipboard) serve(request xproto.SelectionRequestEvent) {
	d := c.display
	property := request.Property
	if property == 0 {
		property = request.Target
	}
	notify := xproto.SelectionNotifyEvent{Time: request.Time, Requestor: request.Requestor, Selection: request.Selection, Target: request.Target, Property: 0}
	if request.Selection != d.atoms["CLIPBOARD"] {
		_ = xproto.SendEventChecked(d.conn, false, request.Requestor, 0, string(notify.Bytes())).Check()
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for key, transfer := range c.outgoing {
		if now.After(transfer.deadline) {
			delete(c.outgoing, key)
		}
	}
	var err error
	switch request.Target {
	case d.atoms["TARGETS"]:
		data := make([]byte, 12)
		for i, atom := range []xproto.Atom{d.atoms["TARGETS"], d.atoms["UTF8_STRING"], d.atoms["TEXT"]} {
			xgb.Put32(data[i*4:], uint32(atom))
		}
		err = xproto.ChangePropertyChecked(d.conn, xproto.PropModeReplace, request.Requestor, property, xproto.AtomAtom, 32, 3, data).Check()
	case d.atoms["UTF8_STRING"], d.atoms["TEXT"]:
		key := selectionKey{request.Requestor, property}
		if len(c.outgoing) >= 8 {
			err = errors.New("selection busy")
			break
		}
		err = xproto.ChangeWindowAttributesChecked(d.conn, request.Requestor, xproto.CwEventMask, []uint32{xproto.EventMaskPropertyChange}).Check()
		if err != nil {
			break
		}
		if len(c.value) > selectionChunk {
			data := make([]byte, 4)
			xgb.Put32(data, uint32(len(c.value)))
			err = xproto.ChangePropertyChecked(d.conn, xproto.PropModeReplace, request.Requestor, property, d.atoms["INCR"], 32, 1, data).Check()
			if err == nil {
				c.outgoing[key] = &selectionTransfer{data: append([]byte(nil), c.value...), target: d.atoms["UTF8_STRING"], deadline: now.Add(selectionDeadline), served: c.served}
			}
		} else {
			err = xproto.ChangePropertyChecked(d.conn, xproto.PropModeReplace, request.Requestor, property, d.atoms["UTF8_STRING"], 8, uint32(len(c.value)), c.value).Check()
			if err == nil {
				c.outgoing[key] = &selectionTransfer{target: d.atoms["UTF8_STRING"], deadline: now.Add(selectionDeadline), served: c.served, completeOnDelete: true}
			}
		}
	default:
		err = errors.New("unsupported selection target")
	}
	if err == nil {
		notify.Property = property
	}
	_ = xproto.SendEventChecked(d.conn, false, request.Requestor, 0, string(notify.Bytes())).Check()
}
func (c *clipboard) advance(event xproto.PropertyNotifyEvent) {
	if event.State != xproto.PropertyDelete {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := selectionKey{event.Window, event.Atom}
	transfer := c.outgoing[key]
	if transfer == nil {
		return
	}
	if time.Now().After(transfer.deadline) {
		delete(c.outgoing, key)
		return
	}
	if transfer.completeOnDelete {
		delete(c.outgoing, key)
		select {
		case transfer.served <- struct{}{}:
		default:
		}
		return
	}
	chunk := transfer.data[:min(len(transfer.data), selectionChunk)]
	err := xproto.ChangePropertyChecked(c.display.conn, xproto.PropModeReplace, event.Window, event.Atom, transfer.target, 8, uint32(len(chunk)), chunk).Check()
	if err != nil {
		delete(c.outgoing, key)
		return
	}
	transfer.data = transfer.data[len(chunk):]
	if len(chunk) == 0 {
		transfer.completeOnDelete = true
	}
}
func (c *clipboard) read() (string, error) {
	d := c.display
	property := d.atoms["AMB_BROWSER_SELECTION"]
	draining := true
	for draining {
		select {
		case <-c.notice:
		default:
			draining = false
		}
	}
	if err := xproto.DeletePropertyChecked(d.conn, c.window, property).Check(); err != nil {
		return "", err
	}
	if err := xproto.ConvertSelectionChecked(d.conn, c.window, d.atoms["CLIPBOARD"], d.atoms["UTF8_STRING"], property, xproto.TimeCurrentTime).Check(); err != nil {
		return "", err
	}
	timer := time.NewTimer(selectionDeadline)
	defer timer.Stop()
	incremental := false
	converted := false
	data := []byte{}
	for {
		select {
		case <-timer.C:
			return "", unavailable()
		case <-c.done:
			return "", unavailable()
		case event := <-c.notice:
			read := false
			switch value := event.(type) {
			case xproto.SelectionNotifyEvent:
				if value.Selection != d.atoms["CLIPBOARD"] || value.Target != d.atoms["UTF8_STRING"] {
					continue
				}
				if value.Property == 0 {
					return "", unavailable()
				}
				converted = true
				read = true
			case xproto.PropertyNotifyEvent:
				read = converted && incremental && value.State == xproto.PropertyNewValue
			}
			if !read {
				continue
			}
			reply, err := xproto.GetProperty(d.conn, true, c.window, property, xproto.GetPropertyTypeAny, 0, maximumClipboard/4+1).Reply()
			if err != nil {
				return "", err
			}
			if reply.BytesAfter != 0 || len(data)+len(reply.Value) > maximumClipboard {
				return "", copyTooLarge()
			}
			if !incremental && reply.Type == d.atoms["INCR"] {
				if reply.Format != 32 || len(reply.Value) != 4 || xgb.Get32(reply.Value) > maximumClipboard {
					return "", copyTooLarge()
				}
				incremental = true
				continue
			}
			if reply.Format != 8 || reply.Type != d.atoms["UTF8_STRING"] {
				return "", unavailable()
			}
			data = append(data, reply.Value...)
			if !incremental || len(reply.Value) == 0 {
				if !utf8.Valid(data) {
					return "", unavailable()
				}
				return string(data), nil
			}
		}
	}
}
func copyTooLarge() error {
	return &failure{"display_copy_too_large", "Select less text to copy. The limit is 1 MiB.", true}
}
func (d *display) paste(text string) error {
	served, err := d.clipboard.own([]byte(text))
	if err != nil {
		return err
	}
	if err := d.chord("v"); err != nil {
		return err
	}
	timer := time.NewTimer(selectionDeadline)
	defer timer.Stop()
	select {
	case <-served:
		return nil
	case <-timer.C:
		return unknown()
	case <-d.clipboard.done:
		return unknown()
	}
}
func (d *display) copy() (any, error) {
	// Observe an actual native Copy publication after this connection's barrier.
	// Do not overwrite the remote clipboard to discover whether copying worked:
	// no-selection/password Copy must preserve both remote and local clipboards.
	baseline, err := xproto.GetSelectionOwner(d.conn, d.atoms["CLIPBOARD"]).Reply()
	if err != nil {
		return nil, unavailable()
	}
	if err := d.chord("c"); err != nil {
		return nil, err
	}
	timer := time.NewTimer(350 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return map[string]any{"text": "", "bytes": 0, "complete": true}, nil
		case <-d.clipboard.done:
			return nil, unknown()
		case event := <-d.clipboard.changes:
			if int16(event.Sequence-baseline.Sequence) <= 0 || event.Owner == 0 || event.Owner == d.clipboard.window {
				continue
			}
			text, err := d.clipboard.read()
			if err != nil {
				return nil, err
			}
			return map[string]any{"text": text, "bytes": len(text), "complete": true}, nil
		}
	}
}
