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
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"golang.org/x/sys/unix"
)

const browserControlLimit = 64 << 10
const browserCopyTextLimit = 1 << 20
const browserCopyResponseLimit = 6*browserCopyTextLimit + 4096
const browserPasteRequestLimit = 6*browserCopyTextLimit + 8192

type browserControlRequest struct {
	Op                        string            `json:"op"`
	ControllerID              string            `json:"controllerId,omitempty"`
	ExpiresAt                 int64             `json:"expiresAt,omitempty"`
	Sequence                  uint64            `json:"sequence,omitempty"`
	Events                    []json.RawMessage `json:"events,omitempty"`
	ExpectedSurfaceGeneration string            `json:"expectedSurfaceGeneration,omitempty"`
}

// ControlBrowserView addresses the same proved native instance as the visual
// stream. Product owns current user/interaction authority; the driver owns
// command serialization, lease expiry and input acknowledgements. Neither the
// driver's socket nor arbitrary CDP commands are exposed to the browser client.
func (s *SessionController) ControlBrowserView(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, browserPasteRequestLimit)
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
	if command.Len() > browserControlRequestLimit(request) {
		c.JSON(http.StatusBadRequest, gin.H{"code": "browser_control_invalid"})
		return
	}
	if _, err := io.Copy(connection, &command); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"code": "browser_control_outcome_unknown"})
		return
	}
	responseLimit := browserControlLimit
	if request.Op == "copy" {
		responseLimit = browserCopyResponseLimit
	}
	line, err := bufio.NewReader(io.LimitReader(connection, int64(responseLimit+1))).ReadBytes('\n')
	if err != nil || len(line) > responseLimit {
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
		case "browser_control_invalid", "browser_control_conflict", "browser_control_expired", "browser_control_stale", "browser_control_sequence_gap", "browser_control_outcome_unknown", "browser_controlled_by_user", "browser_control_copy_too_large", "browser_control_surface_stale":
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
			Supported  bool            `json:"supported"`
			Controlled bool            `json:"controlled"`
			Surface    *browserSurface `json:"surface,omitempty"`
		}
		if json.Unmarshal(response.Data, &inspection) != nil || !inspection.Supported || (inspection.Surface != nil && !inspection.Surface.valid()) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"code": "browser_control_unavailable"})
			return
		}
		c.JSON(http.StatusOK, inspection)
		return
	}
	// Do not forward upstream error strings, request data or unrelated metadata.
	var data struct {
		ControllerID string          `json:"controllerId"`
		ExpiresAt    int64           `json:"expiresAt"`
		LastSequence uint64          `json:"lastSequence"`
		Status       string          `json:"status"`
		Surface      *browserSurface `json:"surface,omitempty"`
	}
	if json.Unmarshal(response.Data, &data) != nil || data.ControllerID != request.ControllerID || data.LastSequence > 9_007_199_254_740_991 || (data.Surface != nil && !data.Surface.valid()) {
		c.JSON(http.StatusBadGateway, gin.H{"code": "browser_control_outcome_unknown"})
		return
	}
	if request.Op == "copy" {
		var copy struct {
			Clipboard struct {
				Text     string `json:"text"`
				Bytes    int    `json:"bytes"`
				Complete bool   `json:"complete"`
			} `json:"clipboard"`
		}
		if data.Status != "copied" || json.Unmarshal(response.Data, &copy) != nil || !copy.Clipboard.Complete ||
			!utf8.ValidString(copy.Clipboard.Text) || len(copy.Clipboard.Text) > browserCopyTextLimit || copy.Clipboard.Bytes != len(copy.Clipboard.Text) {
			c.JSON(http.StatusBadGateway, gin.H{"code": "browser_control_unavailable"})
			return
		}
		result := gin.H{"controllerId": data.ControllerID, "expiresAt": data.ExpiresAt,
			"lastSequence": data.LastSequence, "status": data.Status, "clipboard": copy.Clipboard}
		if data.Surface != nil {
			result["surface"] = data.Surface
		}
		c.JSON(http.StatusOK, result)
		return
	}
	switch data.Status {
	case "controlled", "released", "applied", "duplicate":
		c.JSON(http.StatusOK, data)
	default:
		c.JSON(http.StatusBadGateway, gin.H{"code": "browser_control_outcome_unknown"})
	}
}

func browserControlRequestLimit(request browserControlRequest) int {
	if request.Op != "input" || len(request.Events) != 1 || request.ExpectedSurfaceGeneration == "" {
		return browserControlLimit
	}
	var event struct {
		Type      string `json:"type"`
		EventType string `json:"eventType"`
		Text      string `json:"text"`
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Events[0]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&event) != nil || decoder.Decode(new(any)) != io.EOF ||
		event.Type != "input_keyboard" || event.EventType != "insertText" ||
		len(event.Text) == 0 || len(event.Text) > browserCopyTextLimit || !utf8.ValidString(event.Text) {
		return browserControlLimit
	}
	return browserPasteRequestLimit
}

func validBrowserControlRequest(request browserControlRequest) bool {
	if request.ExpectedSurfaceGeneration != "" && (request.Op != "input" || !validBrowserUUID(request.ExpectedSurfaceGeneration)) {
		return false
	}
	if request.Op == "inspect" {
		return request.ControllerID == "" && request.ExpiresAt == 0 && request.Sequence == 0 && len(request.Events) == 0
	}
	if !validBrowserUUID(request.ControllerID) {
		return false
	}
	switch request.Op {
	case "acquire", "renew":
		return request.ExpiresAt > 0 && request.Sequence == 0 && len(request.Events) == 0
	case "release", "copy":
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
