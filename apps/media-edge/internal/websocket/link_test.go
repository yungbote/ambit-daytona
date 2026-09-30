// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package websocket

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/view"
	ws "github.com/gorilla/websocket"
)

// The task-only listener serializes actual TCP writes; no host qdisc or
// network interface changes. Small writes expose progress during a logical
// WebSocket message, without changing that message's application framing.
type pacedListener struct {
	net.Listener
	ctx      context.Context
	bytes    atomic.Int64
	progress chan struct{}
	once     sync.Once
}

type pacedConnection struct {
	net.Conn
	owner *pacedListener
}

func (l *pacedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &pacedConnection{Conn: c, owner: l}, nil
}

func (c *pacedConnection) Write(data []byte) (int, error) {
	written := 0
	for len(data) > 0 {
		part := min(len(data), 4096)
		timer := time.NewTimer(time.Duration(part*8) * time.Second / 500000)
		select {
		case <-timer.C:
		case <-c.owner.ctx.Done():
			timer.Stop()
			return written, c.owner.ctx.Err()
		}
		n, err := c.Conn.Write(data[:part])
		written += n
		data = data[n:]
		if c.owner.bytes.Add(int64(n)) >= 64<<10 {
			c.owner.once.Do(func() { close(c.owner.progress) })
		}
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func TestPacedTCPLinkSerializesAKnownByteTrain(t *testing.T) {
	writer, reader := net.Pipe()
	defer writer.Close()
	defer reader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	link := &pacedListener{ctx: ctx, progress: make(chan struct{})}
	conn := &pacedConnection{Conn: writer, owner: link}
	read := make(chan error, 1)
	go func() { _, err := io.CopyN(io.Discard, reader, 20000); read <- err }()
	started := time.Now()
	for n := 0; n < 20; n++ {
		if _, err := conn.Write(make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if elapsed < 320*time.Millisecond || elapsed > 800*time.Millisecond || link.bytes.Load() != 20000 {
		t.Fatalf("20KB at500kbit/s took%s, bytes%d; expected320ms floor", elapsed, link.bytes.Load())
	}
	t.Logf("actual known20x1000B TCP train: %s vs320ms serialization floor", elapsed)
}

func TestRecordedNativeKeyShowsWholeMessageWebSocketAudioHOL(t *testing.T) {
	path := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_KEY_FILE")
	if path == "" {
		t.Skip("recorded native key required")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan *carrier, 1)
	keyDone := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&ws.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := newCarrier(conn, time.Hour)
		defer c.Close(0, "")
		ready <- c
		keyDone <- c.Send(&view.Delivery{Kind: view.Video, Header: []byte(`{"track":"video"}`), Payload: payload})
		<-ctx.Done()
	}))
	link := &pacedListener{Listener: server.Listener, ctx: ctx, progress: make(chan struct{})}
	server.Listener = link
	server.Start()
	defer server.Close()
	client, _, err := ws.DefaultDialer.Dial("ws"+server.URL[4:], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Drain real bytes without waiting for the browser's whole-message event.
	// Even this streaming consumer cannot pass the current logical unit.
	reading := make(chan struct{})
	go func() {
		_, reader, err := client.NextReader()
		if err == nil {
			_, _ = io.Copy(io.Discard, reader)
		}
		close(reading)
	}()
	c := <-ready
	select {
	case <-link.progress:
	case <-time.After(5 * time.Second):
		t.Fatal("no actual TCP picture progress")
	}
	audioDone := make(chan error, 1)
	started := time.Now()
	go func() {
		audioDone <- c.Send(&view.Delivery{Kind: view.Audio, Header: []byte(`{"track":"audio"}`), Payload: make([]byte, 160)})
	}()
	observation := time.NewTimer(200 * time.Millisecond)
	select {
	case <-audioDone:
		t.Fatal("whole-message apparatus did not expose audio serialization")
	case <-keyDone:
		t.Fatal("large key finished before the HOL observation")
	case <-observation.C:
	}
	bytes := link.bytes.Load()
	hash := sha256.Sum256(payload)
	t.Logf("actual WS native key SHA256=%x body%dB at500kbit/s: partial TCP progress%dB; audio write blocked%s before whole-picture completion; key serialization floor%s. This is protocol HOL characterization, not native input/glass acceptance", hash, len(payload), bytes, time.Since(started), time.Duration(len(payload)*8)*time.Second/500000)
	cancel()
	c.Close(0, "")
	_ = client.Close()
	select {
	case <-keyDone:
	case <-time.After(time.Second):
		t.Fatal("key writer did not cancel")
	}
	select {
	case <-audioDone:
	case <-time.After(time.Second):
		t.Fatal("queued audio writer did not cancel")
	}
	<-reading
}
