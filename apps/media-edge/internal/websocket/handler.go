// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package websocket

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/daytonaio/media-edge/internal/session"
)

// Path is where the page opens its view channel on the edge.
const Path = "/v1/channel"

// Handler admits a viewer's upgrade and carries its session.
type Handler struct {
	Edge *session.Edge
	// Keepalive is the ping interval (zero: KeepaliveInterval).
	Keepalive time.Duration
	upgrader  websocket.Upgrader
}

// NewHandler serves the WebSocket carrier for the edge.
func NewHandler(edge *session.Edge) *Handler {
	return &Handler{Edge: edge, upgrader: websocket.Upgrader{
		ReadBufferSize:  4 << 10,
		WriteBufferSize: 64 << 10,
		// Admission checks the origin; the grant, not a cookie, is the authority.
		CheckOrigin: func(*http.Request) bool { return true },
	}}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != Path {
		http.NotFound(w, r)
		return
	}
	if !websocket.IsWebSocketUpgrade(r) {
		http.Error(w, "upgrade required", http.StatusUpgradeRequired)
		return
	}
	admission, refusal := h.Edge.Admit(r.URL.Query(), r.Header.Get("Origin"))
	if refusal != nil {
		h.refuse(w, refusal)
		return
	}
	s, err := h.Edge.Open(r.Context(), admission, "websocket")
	if errors.Is(err, session.ErrRevoked) {
		h.refuse(w, &session.Refusal{Status: http.StatusForbidden, Reason: "revoked"})
		return
	}
	conn, upgradeErr := h.upgrader.Upgrade(w, r, nil)
	if upgradeErr != nil {
		if s != nil {
			s.Abort()
		}
		return
	}
	keepalive := h.Keepalive
	if keepalive == 0 {
		keepalive = KeepaliveInterval
	}
	viewer := newCarrier(conn, keepalive)
	if err != nil {
		// The view route could not be dialed: the viewer learns to try
		// again, as it does from the backend today.
		viewer.Close(1013, "browser_view_unavailable")
		for {
			if _, _, err := viewer.Receive(); err != nil {
				return
			}
		}
	}
	s.Run(viewer)
}

func (h *Handler) refuse(w http.ResponseWriter, refusal *session.Refusal) {
	h.Edge.Log.Info("admission.refused", slog.Int("status", refusal.Status), slog.String("reason", refusal.Reason))
	http.Error(w, refusal.Reason, refusal.Status)
}
