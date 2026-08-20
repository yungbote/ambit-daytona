// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package pty

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// attachWebSocket connects a new WebSocket client to the PTY session
func (s *PTYSession) attachWebSocket(ws *websocket.Conn, supportsExitControl bool) {
	cl := &wsClient{
		id:                  uuid.NewString(),
		conn:                ws,
		send:                make(chan []byte, 256), // if full, drop slow client
		done:                make(chan struct{}),
		exit:                make(chan *ptyExitInfo, 1),
		supportsExitControl: supportsExitControl,
	}

	// Register client FIRST so it can receive PTY output via broadcast
	s.clients.Set(cl.id, cl)
	count := s.clients.Count()
	s.logger.Debug("Client attached to PTY session", "clientId", cl.id, "sessionId", s.info.ID, "clientCount", count)

	// Start PTY data flow - writer (PTY -> this client)
	go s.clientWriter(cl)

	// Send success control message after client is registered and ready
	successMsg := map[string]interface{}{
		"type":   "control",
		"status": "connected",
	}
	if successJSON, err := json.Marshal(successMsg); err == nil {
		_ = cl.writeMessage(websocket.TextMessage, successJSON)
	}

	// reader (this client -> PTY); blocks until disconnect
	s.clientReader(cl)

	// on exit, unregister
	s.clients.Remove(cl.id)

	cl.close()

	remaining := s.clients.Count()
	s.logger.Debug("Client detached from PTY session", "clientId", cl.id, "sessionId", s.info.ID, "clientCount", remaining)
}

// clientWriter sends PTY output to a specific WebSocket client
func (s *PTYSession) clientWriter(cl *wsClient) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-cl.done:
			return
		case ex := <-cl.exit:
			s.flushAndClose(cl, ex)
			return
		case b := <-cl.send:
			if !s.writeBinary(cl, b) {
				return
			}
		}
	}
}

// writeBinary writes a single PTY output frame to the client. Returns false on error.
func (s *PTYSession) writeBinary(cl *wsClient, b []byte) bool {
	cl.writeMu.Lock()
	_ = cl.conn.SetWriteDeadline(time.Now().Add(writeWait))
	err := cl.conn.WriteMessage(websocket.BinaryMessage, b)
	cl.writeMu.Unlock()
	return err == nil
}

// flushAndClose drains any still-buffered PTY output, then emits the "exited"
// control message (for opted-in clients) followed by the close frame. Draining
// first guarantees the tail output reaches the client before the terminal frames,
// fixing the race where a fast exit closed the socket while output was still queued.
func (s *PTYSession) flushAndClose(cl *wsClient, ex *ptyExitInfo) {
drain:
	for {
		select {
		case b := <-cl.send:
			if !s.writeBinary(cl, b) {
				cl.close()
				return
			}
		default:
			break drain
		}
	}
	if ex != nil {
		if cl.supportsExitControl && ex.exitJSON != nil {
			_ = cl.writeMessage(websocket.TextMessage, ex.exitJSON)
		}
		_ = cl.writeMessage(websocket.CloseMessage, websocket.FormatCloseMessage(ex.closeCode, ex.closeReason))
	}
	cl.close()
}

// clientReader reads input from a WebSocket client and sends to PTY
func (s *PTYSession) clientReader(cl *wsClient) {
	conn := cl.conn
	conn.SetReadLimit(maxPTYWebSocketInputBytes)

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				s.logger.Debug("ws read error", "error", err)
			}
			return
		}
		// Send all message data to PTY (text or binary)
		if err := s.sendToPTY(data); err != nil {
			// Send error to client and close connection
			_ = cl.writeMessage(websocket.CloseMessage, websocket.FormatCloseMessage(
				websocket.CloseInternalServerErr, "PTY session unavailable",
			))
			return
		}
	}
}

// broadcast sends data to all connected WebSocket clients
func (s *PTYSession) broadcast(b []byte) {
	// send to each client; drop slow clients to avoid stalling the PTY
	s.clientsMu.RLock()
	for id, cl := range s.clients.Items() {
		select {
		case cl.send <- b:
		case <-cl.done:
			// client is shutting down, skip
		default:
			// client's outbound queue is full -> drop the client
			go func(id string, cl *wsClient) {
				_ = cl.writeMessage(websocket.CloseMessage, websocket.FormatCloseMessage(
					websocket.ClosePolicyViolation, "slow consumer",
				))
				cl.close()
			}(id, cl)
		}
	}
	s.clientsMu.RUnlock()
}

// exitReasonText returns the human-readable, paren-free reason for a PTY exit
// code (empty for a clean exit). It is the single source of truth shared by the
// "exited" control message and the close frame so both report identical strings.
func exitReasonText(exitCode int) string {
	switch {
	case exitCode == 0:
		return ""
	case exitCode == 130:
		return "Ctrl+C"
	case exitCode == 137:
		return "SIGKILL"
	case exitCode == 143:
		return "SIGTERM"
	case exitCode > 128:
		return fmt.Sprintf("signal %d", exitCode-128)
	default:
		return "non-zero exit"
	}
}

// exitCloseFrame maps a PTY exit code and its (paren-free) reason to the WebSocket
// close code and the JSON close-frame payload (structured {exitCode, exitReason?});
// exitReason is omitted for a clean (code 0) exit.
func exitCloseFrame(exitCode int, reason string) (int, string) {
	wsCloseCode := websocket.CloseNormalClosure
	var exitReasonStr *string
	if exitCode != 0 {
		wsCloseCode = websocket.CloseInternalServerErr
		if reason != "" {
			r := reason
			exitReasonStr = &r
		}
	}

	type CloseData struct {
		ExitCode   int     `json:"exitCode"`
		ExitReason *string `json:"exitReason,omitempty"`
	}
	closeJSON, _ := json.Marshal(CloseData{ExitCode: exitCode, ExitReason: exitReasonStr})
	return wsCloseCode, string(closeJSON)
}

// gracefulCloseClientsWithExitCode is the normal (process-exit) close path. It waits
// for all PTY output to be queued, then hands each client's writer the terminal
// frames (the optional "exited" control message in exitJSON, then the close frame)
// so buffered output is flushed before them. A nil exitJSON sends only the close
// frame.
func (s *PTYSession) gracefulCloseClientsWithExitCode(exitCode int, reason string, exitJSON []byte) {
	// Wait until ptyReadLoop has read and queued all output, bounded so a lingering
	// child holding the PTY open cannot stall teardown indefinitely.
	if s.readLoopDone != nil {
		select {
		case <-s.readLoopDone:
		case <-time.After(readDrainTimeout):
		}
	}

	closeCode, closeReason := exitCloseFrame(exitCode, reason)
	ex := &ptyExitInfo{exitJSON: exitJSON, closeCode: closeCode, closeReason: closeReason}

	s.clientsMu.Lock()
	for id, cl := range s.clients.Items() {
		select {
		case cl.exit <- ex:
			// writer drains queued output, emits terminal frames, and closes.
		default:
			// No writer consuming (already gone) — close directly as a fallback.
			_ = cl.writeMessage(websocket.CloseMessage, websocket.FormatCloseMessage(closeCode, closeReason))
			cl.close()
		}
		s.clients.Remove(id)
	}
	s.clientsMu.Unlock()
}

// closeClientsWithExitCode force-closes all WebSocket connections with the structured
// close frame. Used by the kill path, where truncating any still-queued output is
// acceptable because the session is being torn down forcefully.
func (s *PTYSession) closeClientsWithExitCode(exitCode int) {
	wsCloseCode, closeJSON := exitCloseFrame(exitCode, exitReasonText(exitCode))

	s.clientsMu.Lock()
	for id, cl := range s.clients.Items() {
		_ = cl.writeMessage(websocket.CloseMessage, websocket.FormatCloseMessage(wsCloseCode, closeJSON))
		cl.close()
		s.clients.Remove(id)
	}
	s.clientsMu.Unlock()
}
