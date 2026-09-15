// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sys/unix"
)

const browserControlLimit = 64 << 10

var browserControllerID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type browserControlRequest struct {
	Op           string            `json:"op"`
	ControllerID string            `json:"controllerId,omitempty"`
	ExpiresAt    int64             `json:"expiresAt,omitempty"`
	Sequence     uint64            `json:"sequence,omitempty"`
	Events       []json.RawMessage `json:"events,omitempty"`
}

// ControlBrowserView addresses the same proved native instance as the visual
// stream. Product owns current user/interaction authority; the driver owns
// command serialization, lease expiry and input acknowledgements. Neither the
// driver's socket nor arbitrary CDP commands are exposed to the browser client.
func (s *SessionController) ControlBrowserView(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, browserControlLimit)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var request browserControlRequest
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !validBrowserControlRequest(request) {
		c.JSON(http.StatusBadRequest, gin.H{"code": "browser_control_invalid"})
		return
	}
	views, err := s.browserViews(c.Request.Context(), c.Param("sessionId"))
	if err != nil {
		browserObservationError(c, err)
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
	connection, err := (&net.Dialer{Timeout: browserDialTimeout}).DialContext(c.Request.Context(), "unix", selected.socketPath)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": "browser_control_unavailable"})
		return
	}
	defer connection.Close()
	stop := context.AfterFunc(c.Request.Context(), func() { _ = connection.Close() })
	defer stop()
	// The connection that receives the command must be the observed process,
	// not a replacement that reused the advertised socket name.
	if err := s.proveBrowserControlPeer(connection.(*net.UnixConn), *selected); err != nil {
		c.JSON(http.StatusConflict, gin.H{"code": "browser_control_stale"})
		return
	}
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	var command bytes.Buffer
	commandEncoder := json.NewEncoder(&command)
	// This is a JSON socket, not HTML. Preserve the already-bounded raw event
	// strings so pasted markup is not expanded sixfold by HTML escaping.
	commandEncoder.SetEscapeHTML(false)
	if err := commandEncoder.Encode(struct {
		Action string `json:"action"`
		browserControlRequest
	}{Action: "ambit_browser_control", browserControlRequest: request}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "browser_control_invalid"})
		return
	}
	if command.Len() > browserControlLimit {
		c.JSON(http.StatusBadRequest, gin.H{"code": "browser_control_invalid"})
		return
	}
	if _, err := io.Copy(connection, &command); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"code": "browser_control_outcome_unknown"})
		return
	}
	line, err := bufio.NewReader(io.LimitReader(connection, browserControlLimit+1)).ReadBytes('\n')
	if err != nil || len(line) > browserControlLimit {
		c.JSON(http.StatusBadGateway, gin.H{"code": "browser_control_outcome_unknown"})
		return
	}
	var response struct {
		Success bool            `json:"success"`
		Code    string          `json:"code"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(line, &response) != nil {
		c.JSON(http.StatusBadGateway, gin.H{"code": "browser_control_outcome_unknown"})
		return
	}
	if !response.Success {
		code := response.Code
		switch code {
		case "browser_control_invalid", "browser_control_conflict", "browser_control_expired", "browser_control_stale", "browser_control_sequence_gap", "browser_control_outcome_unknown", "browser_controlled_by_user":
		default:
			code = "browser_control_unavailable"
		}
		c.JSON(http.StatusConflict, gin.H{"code": code})
		return
	}
	if err := s.proveBrowserControlPeer(connection.(*net.UnixConn), *selected); err != nil {
		c.JSON(http.StatusConflict, gin.H{"code": "browser_control_outcome_unknown"})
		return
	}
	if request.Op == "inspect" {
		var inspection struct {
			Supported  bool `json:"supported"`
			Controlled bool `json:"controlled"`
		}
		if json.Unmarshal(response.Data, &inspection) != nil || !inspection.Supported {
			c.JSON(http.StatusServiceUnavailable, gin.H{"code": "browser_control_unavailable"})
			return
		}
		c.JSON(http.StatusOK, inspection)
		return
	}
	// Do not forward upstream error strings, request data or unrelated metadata.
	var data struct {
		ControllerID string `json:"controllerId"`
		ExpiresAt    int64  `json:"expiresAt"`
		LastSequence uint64 `json:"lastSequence"`
		Status       string `json:"status"`
	}
	if json.Unmarshal(response.Data, &data) != nil || data.ControllerID != request.ControllerID || data.LastSequence > 9_007_199_254_740_991 {
		c.JSON(http.StatusBadGateway, gin.H{"code": "browser_control_outcome_unknown"})
		return
	}
	switch data.Status {
	case "controlled", "released", "applied", "duplicate":
		c.JSON(http.StatusOK, data)
	default:
		c.JSON(http.StatusBadGateway, gin.H{"code": "browser_control_outcome_unknown"})
	}
}

func validBrowserControlRequest(request browserControlRequest) bool {
	if request.Op == "inspect" {
		return request.ControllerID == "" && request.ExpiresAt == 0 && request.Sequence == 0 && len(request.Events) == 0
	}
	if !browserControllerID.MatchString(request.ControllerID) {
		return false
	}
	switch request.Op {
	case "acquire", "renew":
		return request.ExpiresAt > 0 && request.Sequence == 0 && len(request.Events) == 0
	case "release":
		return request.ExpiresAt == 0 && request.Sequence == 0 && len(request.Events) == 0
	case "input":
		return request.ExpiresAt == 0 && request.Sequence > 0 && request.Sequence <= 9_007_199_254_740_991 && len(request.Events) > 0 && len(request.Events) <= 64
	default:
		return false
	}
}

func (s *SessionController) proveBrowserControlPeer(connection *net.UnixConn, selected browserView) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}
	if int(peer.Pid) != selected.pid {
		return errors.New("browser control peer changed")
	}
	identity, err := s.sessionService.ObserveOwnedProcess(selected.SessionID, selected.pid)
	if err != nil {
		return err
	}
	if identity.StartTime != selected.born {
		return errors.New("browser control instance changed")
	}
	listener, err := processBrowserListener(selected.pid, selected.port)
	if err != nil || listener != selected.listener {
		return errors.New("browser control view changed")
	}
	return nil
}
