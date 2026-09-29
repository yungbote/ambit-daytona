// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/daytonaio/media-edge/internal/grant"
	"github.com/daytonaio/media-edge/internal/session"
	"github.com/quic-go/quic-go/http3"
)

func TestWebTransportRefusesAuthorityBeforeUpgradeOrUpstreamDial(t *testing.T) {
	// No upstream is configured: any dial before refusal would panic rather
	// than make a failed authority case look like a refused connection.
	edge := &session.Edge{Verifier: grant.Verifier{Audience: "edge-a"}, Hub: session.NewHub(nil), Origins: []string{"https://ambit.test"}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	server := NewServer(edge, http3.Server{})
	for _, item := range []struct {
		method, path, origin string
		status               int
	}{
		{http.MethodConnect, "/v1/channel", "", 401},
		{http.MethodConnect, "/v1/channel?grant=malformed", "", 401},
		{http.MethodConnect, "/v1/channel?grant=malformed", "https://other.test", 403},
		{http.MethodPost, "/v1/channel", "", 400},
		{http.MethodConnect, "/other", "", 404},
	} {
		t.Run(item.method+item.path+item.origin, func(t *testing.T) {
			r := httptest.NewRequest(item.method, "https://edge.test"+item.path, nil)
			// Ordinary HTTP/1 CONNECT uses an authority target; extended HTTP/3
			// CONNECT carries :path and :protocol separately.
			r.URL, _ = url.Parse("https://edge.test" + item.path)
			r.Proto = "webtransport"
			r.Header.Set("Origin", item.origin)
			response := httptest.NewRecorder()
			server.H3.Handler.ServeHTTP(response, r)
			if response.Code != item.status {
				t.Fatalf("status %d: %s", response.Code, response.Body.String())
			}
			if edge.Hub.Len() != 0 {
				t.Fatal("refused authority opened a session")
			}
		})
	}
}
