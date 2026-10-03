// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package websocket

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/view"
	ws "github.com/gorilla/websocket"
)

// Characterizes the physical fallback boundary: a shared TCP media channel
// cannot preserve the old dedicated input channel's reply isolation.
func TestAnUnreadWebSocketPictureHoldsSharedInputButNotDedicatedInput(t *testing.T) {
	inputReceived := make(chan struct{})
	sharedWritten := make(chan time.Duration, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&ws.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if err := conn.UnderlyingConn().(*net.TCPConn).SetWriteBuffer(32 << 10); err != nil {
			t.Error(err)
			return
		}
		carrier := newCarrier(conn, time.Hour)
		defer carrier.Close(0, "")
		if r.URL.Path == "/dedicated" {
			if _, _, err := carrier.Receive(); err != nil {
				return
			}
			_ = carrier.Send(&view.Delivery{Kind: view.Record, Text: []byte(`{"type":"control","ok":true}`)})
			return
		}
		if err := carrier.Send(&view.Delivery{Kind: view.Record, Text: []byte(`{"type":"status"}`)}); err != nil {
			return
		}
		go func() {
			_ = carrier.Send(&view.Delivery{Kind: view.Video, Header: []byte(`{"track":"video"}`), Payload: bytes.Repeat([]byte{37}, 2<<20)})
		}()
		if _, _, err := carrier.Receive(); err != nil {
			return
		}
		close(inputReceived)
		started := time.Now()
		if err := carrier.Send(&view.Delivery{Kind: view.Record, Text: []byte(`{"type":"control","ok":true}`)}); err != nil {
			return
		}
		sharedWritten <- time.Since(started)
		_, _, _ = carrier.Receive()
	}))
	defer server.Close()
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	media, _, err := ws.DefaultDialer.Dial(url+"/shared", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer media.Close()
	if err := media.UnderlyingConn().(*net.TCPConn).SetReadBuffer(32 << 10); err != nil {
		t.Fatal(err)
	}
	_, _, err = media.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	// Read only the actual binary frame header. Its body is still unread,
	// so the server's picture writer demonstrably owns the TCP write path.
	kind, picture, err := media.NextReader()
	if err != nil || kind != ws.BinaryMessage {
		t.Fatalf("picture header: %d %v", kind, err)
	}
	if err := media.WriteMessage(ws.TextMessage, []byte(`{"type":"control","op":"input"}`)); err != nil {
		t.Fatal(err)
	}
	<-inputReceived
	dedicated, _, err := ws.DefaultDialer.Dial(url+"/dedicated", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dedicated.Close()
	started := time.Now()
	if err := dedicated.WriteMessage(ws.TextMessage, []byte(`{"type":"control","op":"input"}`)); err != nil {
		t.Fatal(err)
	}
	_ = dedicated.SetReadDeadline(time.Now().Add(time.Second))
	_, acknowledgement, err := dedicated.ReadMessage()
	if err != nil || string(acknowledgement) != `{"type":"control","ok":true}` {
		t.Fatalf("dedicated reply: %q %v", acknowledgement, err)
	}
	dedicatedTime := time.Since(started)
	window, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	select {
	case elapsed := <-sharedWritten:
		t.Fatalf("shared reply unexpectedly passed unread picture in %s", elapsed)
	case <-window.Done():
	}
	_ = media.SetReadDeadline(time.Now().Add(3 * time.Second))
	drained, err := io.Copy(io.Discard, picture)
	if err != nil || drained < 2<<20 {
		t.Fatalf("picture drain: %d %v", drained, err)
	}
	_, acknowledgement, err = media.ReadMessage()
	if err != nil || string(acknowledgement) != `{"type":"control","ok":true}` {
		t.Fatalf("shared reply after drain: %q %v", acknowledgement, err)
	}
	sharedTime := <-sharedWritten
	t.Logf("unread2MiB picture/requested32KiB socket buffers: dedicated ACK=%s shared ACK write held=%s (until picture drain)", dedicatedTime, sharedTime)
}
