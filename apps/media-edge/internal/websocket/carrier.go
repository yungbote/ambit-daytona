// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package websocket is the edge's WebSocket carrier: the page's existing
// view channel, served byte for byte as the backend relay serves it today.
package websocket

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/daytonaio/media-edge/internal/view"
)

const (
	// KeepaliveInterval and MaxUnansweredPings are the backend relay's: a
	// ping keeps NAT mappings alive, and a peer that stops answering
	// releases the view instead of holding it until a write stalls.
	KeepaliveInterval  = 25 * time.Second
	MaxUnansweredPings = 2
	// closingGrace is how long a close waits for the viewer's answer, so the
	// close frame is read before the connection goes away.
	closingGrace  = time.Second
	controlWrites = 5 * time.Second
)

// carrier is one viewer's WebSocket.
type carrier struct {
	conn       *websocket.Conn
	unanswered atomic.Int32
	closing    atomic.Bool
	once       sync.Once
	stop       chan struct{}
	writing    sync.Mutex
}

func newCarrier(conn *websocket.Conn, keepalive time.Duration) *carrier {
	c := &carrier{conn: conn, stop: make(chan struct{})}
	conn.SetReadLimit(view.MaxViewerMessageBytes)
	conn.SetPongHandler(func(string) error { c.unanswered.Store(0); return nil })
	go c.keepalive(keepalive)
	return c
}

func (c *carrier) Receive() (bool, []byte, error) {
	kind, message, err := c.conn.ReadMessage()
	if err != nil {
		if c.closing.Load() {
			_ = c.conn.Close()
		}
		return false, nil, err
	}
	return kind == websocket.TextMessage, message, nil
}

// Send writes a record as a text message and a binary kind as one binary
// message: the length prefix, the header and the payload, without copying
// the payload.
func (c *carrier) Send(d *view.Delivery) error {
	c.writing.Lock()
	defer c.writing.Unlock()
	if d.Kind == view.Record {
		return c.conn.WriteMessage(websocket.TextMessage, d.Text)
	}
	writer, err := c.conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return err
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(d.Header)))
	for _, part := range [][]byte{prefix[:], d.Header, d.Payload} {
		if _, err := writer.Write(part); err != nil {
			_ = writer.Close()
			return err
		}
	}
	return writer.Close()
}

// Close sends the close and waits briefly for the viewer's answer before the
// connection goes, so the close is never lost to a reset. Code 0 drops the
// connection at once.
func (c *carrier) Close(code int, reason string) {
	c.once.Do(func() {
		close(c.stop)
		if code == 0 {
			_ = c.conn.Close()
			return
		}
		c.closing.Store(true)
		_ = c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(controlWrites))
		_ = c.conn.SetReadDeadline(time.Now().Add(closingGrace))
		time.AfterFunc(closingGrace, func() { _ = c.conn.Close() })
	})
}

func (c *carrier) keepalive(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
		}
		if c.unanswered.Add(1) > MaxUnansweredPings {
			c.Close(0, "")
			return
		}
		// A ping queued behind a large write counts as unanswered.
		_ = c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(controlWrites))
	}
}
