// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import "sync"

// Slot is a kind of viewer message on its way to the view route. Only the
// newest message of a slot matters, so a viewer dragging the dock divider
// never builds a backlog. Slots are listed in the order they are sent:
// subscriptions first, because they decide which units the rest refer to.
type Slot uint8

const (
	SlotAudio Slot = iota
	SlotVideo
	SlotKeyframe
	SlotPresentation
	SlotVideoAck
	SlotFrameAck
	slotCount
)

// Pending holds the newest message of each slot until the upstream writer
// takes it (the backend relay's BrowserViewRelay.flush). Ready is signalled
// whenever a message is put; the writer drains with Next until it is empty.
type Pending struct {
	mu    sync.Mutex
	slots [slotCount][]byte
	ready chan struct{}
}

// NewPending returns an empty mailbox.
func NewPending() *Pending { return &Pending{ready: make(chan struct{}, 1)} }

// Put replaces the slot's message. A new video subscription retires any
// pending keyframe request and video acknowledgement: they name the old one.
func (p *Pending) Put(forward Forward) (superseded bool) {
	p.mu.Lock()
	superseded = p.slots[forward.Slot] != nil
	p.slots[forward.Slot] = forward.Message
	if forward.Slot == SlotVideo {
		p.slots[SlotKeyframe], p.slots[SlotVideoAck] = nil, nil
	}
	p.mu.Unlock()
	select {
	case p.ready <- struct{}{}:
	default:
	}
	return superseded
}

// Next removes and returns the first message in slot order.
func (p *Pending) Next() ([]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for slot := range p.slots {
		if message := p.slots[slot]; message != nil {
			p.slots[slot] = nil
			return message, true
		}
	}
	return nil, false
}

// Ready is signalled after a Put.
func (p *Pending) Ready() <-chan struct{} { return p.ready }
