// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package websocket

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/view"
	ws "github.com/gorilla/websocket"
)

type wireCountListener struct {
	net.Listener
	bytes atomic.Uint64
}
type wireCountConn struct {
	net.Conn
	bytes *atomic.Uint64
}

func (l *wireCountListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &wireCountConn{conn, &l.bytes}, nil
}
func (c *wireCountConn) Write(data []byte) (int, error) {
	written, err := c.Conn.Write(data)
	c.bytes.Add(uint64(written))
	return written, err
}

func TestOrderedPriorityCostMatchesRealServerFramesAtHeaderBoundaries(t *testing.T) {
	var link *wireCountListener
	result := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&ws.Upgrader{WriteBufferSize: 64 << 10}).Upgrade(w, r, nil)
		if err != nil {
			result <- err
			return
		}
		c := newCarrier(conn, time.Hour)
		defer c.Close(0, "")
		for _, length := range []int{125, 126, 65535, 65536, view.MaxRecordBytes} {
			delivery := &view.Delivery{Kind: view.Record, Text: []byte(strings.Repeat("x", length))}
			before := link.bytes.Load()
			if err := c.Send(delivery); err != nil {
				result <- err
				return
			}
			actual := int(link.bytes.Load() - before)
			if actual != c.OrderedPriorityBytes(delivery) {
				t.Errorf("record%d actualwire%d charged%d", length, actual, c.OrderedPriorityBytes(delivery))
			}
		}
		audio := &view.Delivery{Kind: view.Audio, Header: []byte(`{"track":"audio"}`), Payload: make([]byte, 321)}
		before := link.bytes.Load()
		if err := c.Send(audio); err != nil {
			result <- err
			return
		}
		if actual := int(link.bytes.Load() - before); actual != c.OrderedPriorityBytes(audio) {
			t.Errorf("audio actualwire%d charged%d", actual, c.OrderedPriorityBytes(audio))
		}
		result <- nil
	}))
	link = &wireCountListener{Listener: server.Listener}
	server.Listener = link
	server.Start()
	defer server.Close()
	client, _, err := ws.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	for count := 0; count < 6; count++ {
		if _, _, err := client.ReadMessage(); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
