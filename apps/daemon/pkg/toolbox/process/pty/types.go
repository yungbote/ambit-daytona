// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package pty

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	cmap "github.com/orcaman/concurrent-map/v2"
)

// Constants
const (
	writeWait = 10 * time.Second
	// maxPTYWebSocketInputBytes is the exact maximum for one ordered PTY input
	// message: a 64 KiB binary payload plus a bounded 12-byte application frame.
	// Keeping the envelope in one WebSocket message avoids transport-level
	// fragmentation and preserves binary command boundaries.
	maxPTYWebSocketInputBytes = (64 * 1024) + 12
	// readDrainTimeout bounds how long the exit path waits for ptyReadLoop to
	// finish queuing output before closing, so a lingering child that keeps the
	// PTY open cannot stall teardown indefinitely.
	readDrainTimeout = 5 * time.Second
)

// ptyExitInfo carries the terminal frames a client writer emits once the PTY has
// exited: the optional "exited" control message, then the WebSocket close frame.
type ptyExitInfo struct {
	exitJSON    []byte
	closeCode   int
	closeReason string
}

// PTYController handles PTY-related HTTP endpoints
type PTYController struct {
	logger  *slog.Logger
	workDir string
}

// PTYManager manages multiple PTY sessions
type PTYManager struct {
	sessions cmap.ConcurrentMap[string, *PTYSession]
}

// wsClient represents a WebSocket client connection
type wsClient struct {
	id        string
	conn      *websocket.Conn
	send      chan []byte   // outbound queue for this client (PTY -> WS)
	done      chan struct{} // closed when the client is shutting down
	closeOnce sync.Once
	writeMu   sync.Mutex // serializes all writes to conn

	// supportsExitControl is set when the client advertised the exit-control
	// capability token; only such clients receive the "exited" control message.
	supportsExitControl bool

	// exit hands this client's writer the terminal frames on PTY exit. The writer
	// drains any buffered output first, so queued tail output is delivered before
	// the "exited" message and close frame (fixes the exit/close truncation race).
	exit chan *ptyExitInfo
}

// PTYSession represents a single PTY session with multi-client support
type PTYSession struct {
	logger *slog.Logger

	info PTYSessionInfo

	cmd  *exec.Cmd
	ptmx *os.File
	// inputWriter normally aliases ptmx. Keeping the narrow io.Writer boundary
	// makes short-write behavior testable without weakening PTY ownership.
	inputWriter io.Writer
	ctx         context.Context
	cancel      context.CancelFunc

	// multi-attach
	clients   cmap.ConcurrentMap[string, *wsClient]
	clientsMu sync.RWMutex

	// funnel of all client inputs -> single PTY writer (preserves ordering)
	inCh chan []byte

	// readLoopDone is closed when ptyReadLoop returns, i.e. all PTY output has been
	// read and queued to clients. The exit path waits on it before closing so the
	// tail is flushed first.
	readLoopDone chan struct{}

	// guards general session fields (info/cmd/ptmx)
	mu sync.Mutex
}

// PTYSessionInfo contains metadata about a PTY session
type PTYSessionInfo struct {
	ID        string            `json:"id" validate:"required"`
	Cwd       string            `json:"cwd" validate:"required"`
	Envs      map[string]string `json:"envs" validate:"required"`
	Cols      uint16            `json:"cols" validate:"required"`
	Rows      uint16            `json:"rows" validate:"required"`
	CreatedAt time.Time         `json:"createdAt" validate:"required"`
	Active    bool              `json:"active" validate:"required"`
	LazyStart bool              `json:"lazyStart" validate:"required"` // Whether this session uses lazy start
} //	@name	PtySessionInfo

// API Request/Response types

// PTYCreateRequest represents a request to create a new PTY session
type PTYCreateRequest struct {
	ID        string            `json:"id"`
	Cwd       string            `json:"cwd,omitempty"`
	Envs      map[string]string `json:"envs,omitempty"`
	Cols      *uint16           `json:"cols" validate:"optional"`
	Rows      *uint16           `json:"rows" validate:"optional"`
	LazyStart bool              `json:"lazyStart,omitempty"` // Don't start PTY until first client connects
} //	@name	PtyCreateRequest

// PTYCreateResponse represents the response when creating a PTY session
type PTYCreateResponse struct {
	SessionID string `json:"sessionId" validate:"required"`
} //	@name	PtyCreateResponse

// PTYListResponse represents the response when listing PTY sessions
type PTYListResponse struct {
	Sessions []PTYSessionInfo `json:"sessions" validate:"required"`
} //	@name	PtyListResponse

// PTYResizeRequest represents a request to resize a PTY session
type PTYResizeRequest struct {
	Cols uint16 `json:"cols" binding:"required,min=1,max=1000"`
	Rows uint16 `json:"rows" binding:"required,min=1,max=1000"`
} //	@name	PtyResizeRequest
