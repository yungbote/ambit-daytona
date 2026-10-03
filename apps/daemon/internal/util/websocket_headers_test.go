// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package util

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestOptionalUpgradeHeadersPreserveLegacyAndAdvertiseOnlyExplicitCapabilities(t *testing.T) {
	for _, pipe := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "pipe"}[pipe], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var conn *websocket.Conn
				var err error
				if pipe {
					conn, err = UpgradeToWebSocket(w, r, http.Header{"X-Ambit-Browser-View-Pipe": {"1"}})
				} else {
					conn, err = UpgradeToWebSocket(w, r)
				}
				if err != nil {
					return
				}
				defer conn.Close()
				_, _, _ = conn.ReadMessage()
			}))
			defer server.Close()
			conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			want := ""
			if pipe {
				want = "1"
			}
			if response.Header.Get("X-Ambit-Browser-View-Pipe") != want {
				t.Fatal("upgrade lost capability or asserted it for legacy")
			}
		})
	}
}
