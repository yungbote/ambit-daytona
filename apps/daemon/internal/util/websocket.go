// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package util

import (
	"net/http"

	"github.com/gorilla/websocket"
)

// UpgradeToWebSocket is a toolbox utility function that upgrades an HTTP connection to a WebSocket connection.
// It selects a subprotocol from those the client offered (gorilla picks the first offered), so strict
// clients that offer any subprotocol receive a server selection and pass the handshake.
// It uses a permissive CORS (CheckOrigin always returns true) to allow connections from any origin.
func UpgradeToWebSocket(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	// Echo back the client's offered subprotocols. gorilla selects the first
	// client-offered entry, so this preserves the previous behavior of echoing
	// the SDK-version token when the client lists it, while also selecting a
	// subprotocol for clients that only offer others (e.g. the PTY env token).
	// Without a server selection, strict clients (Node's `ws`) fail the
	// handshake per RFC 6455 §4.2.2 when they offered any subprotocol.
	upgrader := websocket.Upgrader{
		CheckOrigin:  func(r *http.Request) bool { return true },
		Subprotocols: websocket.Subprotocols(r),
	}

	// Upgrade the connection to a WebSocket protocol
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}

	return ws, nil
}
