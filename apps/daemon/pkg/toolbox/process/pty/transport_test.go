// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package pty

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	creackpty "github.com/creack/pty"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	cmap "github.com/orcaman/concurrent-map/v2"
)

type boundedShortWriter struct {
	maximum int
	buffer  bytes.Buffer
}

func (w *boundedShortWriter) Write(payload []byte) (int, error) {
	limit := min(w.maximum, len(payload))
	return w.buffer.Write(payload[:limit])
}

type zeroProgressWriter struct{}

func (zeroProgressWriter) Write([]byte) (int, error) { return 0, nil }

type overrunWriter struct{}

func (overrunWriter) Write(payload []byte) (int, error) { return len(payload) + 1, nil }

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWritePTYInputPreservesShortWriteSuffixAndFailsClosed(t *testing.T) {
	t.Parallel()
	payload := make([]byte, maxPTYWebSocketInputBytes)
	for index := range payload {
		payload[index] = byte(index)
	}
	short := &boundedShortWriter{maximum: 7}
	if err := writePTYInput(context.Background(), short, payload); err != nil {
		t.Fatalf("writePTYInput(short writer): %v", err)
	}
	if !bytes.Equal(short.buffer.Bytes(), payload) {
		t.Fatal("short writer lost or reordered a suffix")
	}
	if err := writePTYInput(context.Background(), zeroProgressWriter{}, payload); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("writePTYInput(zero progress) = %v, want io.ErrNoProgress", err)
	}
	if err := writePTYInput(context.Background(), overrunWriter{}, payload); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writePTYInput(overrun) = %v, want io.ErrShortWrite", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writePTYInput(canceled, short, payload); !errors.Is(err, context.Canceled) {
		t.Fatalf("writePTYInput(canceled) = %v, want context.Canceled", err)
	}
}

func TestInputWriteLoopPropagatesWriterFailureByCancelingSession(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	expected := errors.New("deliberate writer failure")
	session := &PTYSession{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		ctx:         ctx,
		cancel:      cancel,
		inCh:        make(chan []byte, 1),
		inputWriter: failingWriter{err: expected},
	}
	go session.inputWriteLoop()
	session.inCh <- []byte("payload")
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("inputWriteLoop did not propagate writer failure through cancellation")
	}
}

func TestControllerWebSocketToRealPTYPreservesBinaryBoundaryAndReconnect(t *testing.T) {
	harness := newRealPTYHarness(t)
	first := harness.connect(t)

	allBytes := make([]byte, 256)
	for index := range allBytes {
		allBytes[index] = byte(index)
	}
	writeBinary(t, first, allBytes)
	if actual := readBinaryBytes(t, first, len(allBytes)); !bytes.Equal(actual, allBytes) {
		t.Fatal("all-byte payload changed across WebSocket and PTY")
	}

	maximum := make([]byte, maxPTYWebSocketInputBytes)
	for index := range maximum {
		maximum[index] = byte(index)
	}
	writeBinary(t, first, maximum)
	if actual := readBinaryBytes(t, first, len(maximum)); !bytes.Equal(actual, maximum) {
		t.Fatal("maximum admitted WebSocket message changed across PTY")
	}

	ordered := [][]byte{
		[]byte("AMATREQ1"),
		{0, 4, '\n', 0xff},
		[]byte("AMATDAT1-slow"),
		[]byte("AMATEND1"),
	}
	var expected bytes.Buffer
	for _, part := range ordered {
		writeBinary(t, first, part)
		expected.Write(part)
		time.Sleep(time.Millisecond)
	}
	if actual := readBinaryBytes(t, first, expected.Len()); !bytes.Equal(actual, expected.Bytes()) {
		t.Fatal("split PTY input messages were reordered")
	}

	_ = first.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "detach"))
	_ = first.Close()
	second := harness.connect(t)
	reconnected := []byte("reconnected-without-replay\x00\xff")
	writeBinary(t, second, reconnected)
	if actual := readBinaryBytes(t, second, len(reconnected)); !bytes.Equal(actual, reconnected) {
		t.Fatal("reconnected PTY session changed bytes")
	}

	oversized := make([]byte, maxPTYWebSocketInputBytes+1)
	writeBinary(t, second, oversized)
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := second.ReadMessage(); err == nil {
		t.Fatal("oversized WebSocket input was not rejected")
	}
	_ = second.Close()

	third := harness.connect(t)
	marker := []byte("after-oversize-boundary")
	writeBinary(t, third, marker)
	if actual := readBinaryBytes(t, third, len(marker)); !bytes.Equal(actual, marker) {
		t.Fatal("oversized message leaked a prefix into the PTY")
	}
	_ = third.Close()
}

func TestClientWriterFlushesOutputTailBeforeExitControlAndClose(t *testing.T) {
	t.Parallel()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	ready := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client := &wsClient{
			id:                  "tail-client",
			conn:                connection,
			send:                make(chan []byte, 4),
			done:                make(chan struct{}),
			exit:                make(chan *ptyExitInfo, 1),
			supportsExitControl: true,
		}
		session := &PTYSession{ctx: ctx}
		client.send <- []byte("tail-one")
		client.send <- []byte("tail-two")
		exitJSON := []byte(`{"type":"control","status":"exited","exitCode":0}`)
		client.exit <- &ptyExitInfo{exitJSON: exitJSON, closeCode: websocket.CloseNormalClosure, closeReason: `{"exitCode":0}`}
		close(ready)
		session.clientWriter(client)
	}))
	defer server.Close()

	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	<-ready
	for _, expected := range [][]byte{[]byte("tail-one"), []byte("tail-two")} {
		messageType, payload, err := connection.ReadMessage()
		if err != nil || messageType != websocket.BinaryMessage || !bytes.Equal(payload, expected) {
			t.Fatalf("tail frame = type %d payload %q err %v; want %q", messageType, payload, err, expected)
		}
	}
	messageType, control, err := connection.ReadMessage()
	if err != nil || messageType != websocket.TextMessage {
		t.Fatalf("exit control = type %d payload %q err %v", messageType, control, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(control, &decoded); err != nil || decoded["status"] != "exited" {
		t.Fatalf("exit control = %q err %v", control, err)
	}
	if _, _, err := connection.ReadMessage(); err == nil {
		t.Fatal("expected terminal close frame after exit control")
	}
}

type realPTYHarness struct {
	server  *httptest.Server
	session *PTYSession
	manager *PTYManager
}

func newRealPTYHarness(t *testing.T) *realPTYHarness {
	t.Helper()
	command := exec.Command("/bin/sh", "-c", "stty raw -echo; printf READY; exec cat")
	master, err := creackpty.Start(command)
	if err != nil {
		t.Skipf("real PTY unavailable: %v", err)
	}
	ready := make([]byte, len("READY"))
	readyResult := make(chan error, 1)
	go func() {
		_, readErr := io.ReadFull(master, ready)
		readyResult <- readErr
	}()
	select {
	case err := <-readyResult:
		if err != nil || string(ready) != "READY" {
			_ = master.Close()
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("real PTY readiness = %q, %v", ready, err)
		}
	case <-time.After(3 * time.Second):
		_ = master.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("real PTY readiness timed out")
	}

	ctx, cancel := context.WithCancel(context.Background())
	session := &PTYSession{
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		info:         PTYSessionInfo{ID: "transport-test", Cwd: "/tmp", Cols: 80, Rows: 24, Active: true},
		cmd:          command,
		ptmx:         master,
		inputWriter:  master,
		ctx:          ctx,
		cancel:       cancel,
		clients:      cmap.New[*wsClient](),
		inCh:         make(chan []byte, 1024),
		readLoopDone: make(chan struct{}),
	}
	manager := NewPTYManager()
	manager.Add(session)
	previousManager := ptyManager
	ptyManager = manager
	gin.SetMode(gin.TestMode)
	router := gin.New()
	controller := NewPTYController(session.logger, "/tmp")
	router.GET("/process/pty/:sessionId/connect", controller.ConnectPTYSession)
	server := httptest.NewServer(router)
	go session.ptyReadLoop()
	go session.inputWriteLoop()

	t.Cleanup(func() {
		ptyManager = previousManager
		server.Close()
		cancel()
		_ = master.Close()
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	})
	return &realPTYHarness{server: server, session: session, manager: manager}
}

func (h *realPTYHarness) connect(t *testing.T) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(h.server.URL, "http") + "/process/pty/transport-test/connect"
	connection, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	messageType, payload, err := connection.ReadMessage()
	if err != nil || messageType != websocket.TextMessage || !bytes.Contains(payload, []byte(`"status":"connected"`)) {
		_ = connection.Close()
		t.Fatalf("connected control = type %d payload %q err %v", messageType, payload, err)
	}
	return connection
}

func writeBinary(t *testing.T, connection *websocket.Conn, payload []byte) {
	t.Helper()
	_ = connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := connection.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatal(err)
	}
}

func readBinaryBytes(t *testing.T, connection *websocket.Conn, length int) []byte {
	t.Helper()
	result := make([]byte, 0, length)
	deadline := time.Now().Add(10 * time.Second)
	for len(result) < length {
		_ = connection.SetReadDeadline(deadline)
		messageType, payload, err := connection.ReadMessage()
		if err != nil {
			t.Fatalf("read %d of %d PTY bytes: %v", len(result), length, err)
		}
		if messageType != websocket.BinaryMessage {
			t.Fatalf("unexpected PTY message type %d payload %q", messageType, payload)
		}
		result = append(result, payload...)
		if len(result) > length {
			t.Fatalf("PTY produced %d bytes, want %d", len(result), length)
		}
	}
	return result
}
