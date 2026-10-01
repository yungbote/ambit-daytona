// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package websocket

import (
	"context"
	"net"
)

type PacedTrace = pacedTrace

// Reuses the calibrated task TCP serializer in external edge/browser gates.
// The returned controls change only this listener, never a host interface.
func PaceBrowserTestListener(listener net.Listener, ctx context.Context) (net.Listener, func(int64), func() int64, func() pacedTrace) {
	link := &pacedListener{Listener: listener, ctx: ctx, progress: make(chan struct{})}
	return link, link.rate.Store, link.bytes.Load, link.writeTrace
}
