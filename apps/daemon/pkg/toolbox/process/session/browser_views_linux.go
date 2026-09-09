// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	nativesession "github.com/daytonaio/daemon/pkg/session"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

const browserSocketDirectory = "/workspace/.ambit/browser/sockets"
const browserExecutable = "/opt/ambit/browser/bin/agent-browser"
const browserFrameLimit = 12 << 20

type browserView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	pid  int
	born string
	port uint16
}

// browserViewAt speaks only the driver's read-only stream_status command over
// its Unix socket. SO_PEERCRED and native process custody bind that response to
// this session before its loopback port can be used by the read-only relay.
func (s *SessionController) browserViewAt(ctx context.Context, sessionID, name, socketPath string) (browserView, error) {
	connection, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return browserView{}, err
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	raw, err := connection.(*net.UnixConn).SyscallConn()
	if err != nil {
		return browserView{}, err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return browserView{}, err
	}
	if peerErr != nil {
		return browserView{}, peerErr
	}
	identity, err := s.sessionService.ObserveOwnedProcess(sessionID, int(peer.Pid))
	if err != nil {
		return browserView{}, err
	}
	executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", peer.Pid))
	if err != nil || executable != browserExecutable {
		return browserView{}, errors.New("socket is not the workspace browser driver")
	}
	if _, err := io.WriteString(connection, "{\"id\":\"ambit-live-view\",\"action\":\"stream_status\"}\n"); err != nil {
		return browserView{}, err
	}
	line, err := bufio.NewReader(io.LimitReader(connection, 64<<10)).ReadBytes('\n')
	if err != nil {
		return browserView{}, err
	}
	var response struct {
		ID      string `json:"id"`
		Success bool   `json:"success"`
		Data    struct {
			Enabled   bool   `json:"enabled"`
			Connected bool   `json:"connected"`
			Port      uint16 `json:"port"`
		} `json:"data"`
	}
	if json.Unmarshal(line, &response) != nil || response.ID != "ambit-live-view" || !response.Success || !response.Data.Enabled || !response.Data.Connected || response.Data.Port == 0 {
		return browserView{}, errors.New("browser stream is not available")
	}
	current, err := s.sessionService.ObserveOwnedProcess(sessionID, identity.PID)
	if err != nil || current != identity {
		return browserView{}, errors.New("browser process custody changed")
	}
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", sessionID, name, identity.PID, identity.StartTime)))
	return browserView{ID: hex.EncodeToString(hash[:]), Name: name, pid: identity.PID, born: identity.StartTime, port: response.Data.Port}, nil
}

func (s *SessionController) browserViews(ctx context.Context, sessionID string) ([]browserView, error) {
	if _, err := s.sessionService.Get(sessionID); err != nil {
		return nil, err
	}
	views := []browserView{}
	entries, err := os.ReadDir(browserSocketDirectory)
	if os.IsNotExist(err) {
		return views, nil
	}
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		name, socket := strings.CutSuffix(entry.Name(), ".sock")
		if !socket || entry.Type()&os.ModeSocket == 0 {
			continue
		}
		view, err := s.browserViewAt(ctx, sessionID, name, filepath.Join(browserSocketDirectory, entry.Name()))
		if err == nil {
			views = append(views, view)
		}
	}
	return views, nil
}

// ListBrowserViews exposes observed views, never daemon paths or loopback ports.
func (s *SessionController) ListBrowserViews(c *gin.Context) {
	views, err := s.browserViews(c.Request.Context(), c.Param("sessionId"))
	if err != nil {
		c.Error(err)
		return
	}
	c.JSON(http.StatusOK, views)
}

// StreamBrowserView is output-only. Only protocol acknowledgements are sent to
// the driver; application clients cannot send browser input or CDP commands.
func (s *SessionController) StreamBrowserView(c *gin.Context) {
	sessionID := c.Param("sessionId")
	views, err := s.browserViews(c.Request.Context(), sessionID)
	if err != nil {
		c.Error(err)
		return
	}
	var selected *browserView
	for index := range views {
		if views[index].ID == c.Param("viewId") {
			selected = &views[index]
			break
		}
	}
	if selected == nil {
		c.Status(http.StatusNotFound)
		return
	}
	address := fmt.Sprintf("ws://127.0.0.1:%d/?pacing=ack&maxFps=10", selected.port)
	upstream, _, err := (&websocket.Dialer{HandshakeTimeout: 5 * time.Second}).DialContext(c.Request.Context(), address, nil)
	if err != nil {
		c.Status(http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	upstream.SetReadLimit(browserFrameLimit)
	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()
	var finished atomic.Bool
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				upstream.Close()
				return
			case <-ticker.C:
				observed, err := s.sessionService.ObserveOwnedProcess(sessionID, selected.pid)
				if err != nil || observed.StartTime != selected.born {
					finished.Store(browserCustodyEnded(err) || err == nil)
					upstream.Close()
					return
				}
			}
		}
	}()
	c.Header("Content-Type", "application/x-ndjson")
	c.Header("Cache-Control", "no-store")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)
	c.Writer.Flush()
	for {
		_, message, err := upstream.ReadMessage()
		if err != nil {
			// Browser exit closes its socket before the periodic observation
			// necessarily runs. Reobserve this owner before classifying EOF.
			observed, custodyErr := s.sessionService.ObserveOwnedProcess(sessionID, selected.pid)
			if browserCustodyEnded(custodyErr) || (custodyErr == nil && observed.StartTime != selected.born) {
				finished.Store(true)
			}
			if finished.Load() && ctx.Err() == nil {
				io.WriteString(c.Writer, "{\"type\":\"finished\"}\n")
				c.Writer.Flush()
			}
			return
		}
		filtered, sequence, ok := browserViewMessage(message)
		if !ok {
			continue
		}
		// Exactly one upstream frame remains unacknowledged while HTTP output
		// is backpressured. No queue of stale frames is accumulated here.
		if _, err := c.Writer.Write(append(filtered, '\n')); err != nil {
			return
		}
		c.Writer.Flush()
		if sequence != 0 {
			upstream.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := upstream.WriteJSON(map[string]any{"type": "ack", "seq": sequence}); err != nil {
				return
			}
		}
	}
}

func browserCustodyEnded(err error) bool {
	return errors.Is(err, nativesession.ErrProcessCustodyEnded) || errors.Is(err, os.ErrNotExist)
}

func browserViewMessage(message []byte) ([]byte, uint64, bool) {
	var envelope struct {
		Type string `json:"type"`
		Seq  uint64 `json:"seq"`
	}
	if json.Unmarshal(message, &envelope) != nil {
		return nil, 0, false
	}
	switch envelope.Type {
	case "frame":
		return message, envelope.Seq, envelope.Seq != 0
	case "status", "url":
		return message, 0, true
	default:
		// In particular, upstream command events and errors can contain task
		// input. They are not part of the visual stream contract.
		return nil, 0, false
	}
}
