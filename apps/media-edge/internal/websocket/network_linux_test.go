// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package websocket

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/rate"
	"github.com/daytonaio/media-edge/internal/view"
	ws "github.com/gorilla/websocket"
)

func TestRealTCPInfoIsAlwaysMarkedAsTheProxyHop(t *testing.T) {
	measured := make(chan rate.Network, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&ws.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		carrier := newCarrier(conn, time.Hour)
		defer carrier.Close(0, "")
		_ = carrier.Send(&view.Delivery{Kind: view.Record, Text: []byte(`{"type":"status"}`)})
		_, _, _ = carrier.Receive()
		measured <- carrier.Network()
	}))
	defer server.Close()
	conn, _, err := ws.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(ws.TextMessage, []byte(`{"type":"ack","seq":1}`)); err != nil {
		t.Fatal(err)
	}
	sample := <-measured
	if !sample.Known || !sample.ProxyHop || sample.WindowBytes == 0 || sample.Shares != 1 {
		t.Fatalf("TCP_INFO boundary: %+v", sample)
	}
	t.Logf("real TCP_INFO proxy hop: acked=%dB RTT=%s window=%dB", sample.AckedBytes, sample.RTT, sample.WindowBytes)
}
