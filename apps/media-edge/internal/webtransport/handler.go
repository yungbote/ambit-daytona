// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"errors"
	"net/http"

	"github.com/daytonaio/media-edge/internal/session"
	"github.com/quic-go/quic-go"
	wt "github.com/quic-go/webtransport-go"
)

const Path = "/v1/channel"

// NewServer uses the same authority and session core as the WebSocket adapter.
// The caller owns its listener and TLS configuration.
func NewServer(edge *session.Edge) *wt.Server {
	metrics := newMetricsRegistry()
	server := &wt.Server{CheckOrigin: func(*http.Request) bool { return true }}
	server.H3.QUICConfig = &quic.Config{EnableDatagrams: true, Tracer: metrics.tracer}
	server.H3.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodConnect || r.Proto != "webtransport" {
			http.Error(w, "WebTransport required", http.StatusBadRequest)
			return
		}
		admission, refusal := edge.Admit(r.URL.Query(), r.Header.Get("Origin"))
		if refusal != nil {
			edge.Log.Info("admission.refused", "carrier", "webtransport", "status", refusal.Status, "reason", refusal.Reason)
			http.Error(w, refusal.Reason, refusal.Status)
			return
		}
		s, openErr := edge.Open(r.Context(), admission, "webtransport")
		if errors.Is(openErr, session.ErrRevoked) {
			http.Error(w, "revoked", http.StatusForbidden)
			return
		}
		transport, err := server.Upgrade(w, r)
		if err != nil {
			if s != nil {
				s.Abort()
			}
			return
		}
		viewer, err := newCarrier(transport, metrics)
		if err != nil {
			if s != nil {
				s.Abort()
			}
			_ = transport.CloseWithError(1011, "browser_view_unavailable")
			return
		}
		if openErr != nil {
			viewer.Close(1013, "browser_view_unavailable")
			return
		}
		s.Run(viewer)
	})
	return server
}
