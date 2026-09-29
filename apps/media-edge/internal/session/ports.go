// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package session is the edge's session core: one viewer's grant authority,
// its view channel protocol, and the three flows between a carrier (how the
// person's browser is reached) and an upstream (how the sandbox's view is
// reached). Carriers and upstreams are adapters; nothing here knows a wire.
package session

import (
	"context"
	"fmt"

	"github.com/daytonaio/media-edge/internal/view"
)

// Carrier is one viewer's connection to the person's browser.
type Carrier interface {
	// Receive blocks for the viewer's next message; text is false for a
	// binary message. An error means the viewer is gone.
	Receive() (text bool, message []byte, err error)
	// Send writes one delivery and blocks while the viewer's path is full.
	Send(delivery *view.Delivery) error
	// Close ends the connection with the close the viewer reads; code 0
	// drops the transport without one. It is safe to call more than once.
	Close(code int, reason string)
}

// Target is the view a grant names, in terms any sandbox provider has.
type Target struct {
	SandboxID string
	SessionID string
	ViewID    string
}

// Upstream reaches a sandbox's browser view.
type Upstream interface {
	DialView(ctx context.Context, target Target, viewerID string, declaration view.Declaration) (Conn, error)
}

// Conn is one open view route.
type Conn interface {
	// Read blocks for the route's next message. When the route closed with
	// a close frame the error is a *Closed.
	Read() (text bool, message []byte, err error)
	// Write sends one text message to the route.
	Write(message []byte) error
	// Close drops the route; it is safe to call more than once.
	Close()
}

// Closed is how the view route ended.
type Closed struct {
	Code   int
	Reason string
}

func (c *Closed) Error() string { return fmt.Sprintf("view route closed: %d %s", c.Code, c.Reason) }
