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

// One command is sent and answered within this long, whichever transport
// carried it to the daemon.
const browserControlDeadline = 10 * time.Second

type browserControlRequest struct {
	Op                        string            `json:"op"`
	ControllerID              string            `json:"controllerId,omitempty"`
	ExpiresAt                 int64             `json:"expiresAt,omitempty"`
	Sequence                  uint64            `json:"sequence,omitempty"`
	Events                    []json.RawMessage `json:"events,omitempty"`
	ExpectedSurfaceGeneration string            `json:"expectedSurfaceGeneration,omitempty"`
	DestinationID             string            `json:"destinationId,omitempty"`
	Files                     []string          `json:"files,omitempty"`
	X                         *float64          `json:"x,omitempty"`
	Y                         *float64          `json:"y,omitempty"`
}

// browserControlOutcome is one command's answer as the POST route states it:
// the HTTP status and the JSON document. The channel relays the same pair, so
// its reply is exactly what the POST would have returned.
type browserControlOutcome struct {
	status int
	body   any
}

func browserControlFailure(status int, code string) browserControlOutcome {
	return browserControlOutcome{status: status, body: gin.H{"code": code}}
}

var (
	// The body is not exactly one JSON document.
	errBrowserControlNotJSON = errors.New("browser control body is not one JSON document")
	// The document is not a command this relay accepts.
	errBrowserControlInvalid = errors.New("browser control command is invalid")
)

// decodeBrowserControlRequest reads exactly one command document and applies
// the relay's own validation. The POST answers 400 to either failure; the
// channel treats a body that is not one JSON document as a protocol violation
// and an unacceptable command as that command's failure.
func decodeBrowserControlRequest(body io.Reader) (browserControlRequest, error) {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request browserControlRequest
	if err := decoder.Decode(&request); err != nil {
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return browserControlRequest{}, errBrowserControlNotJSON
		}
		return browserControlRequest{}, errBrowserControlInvalid
	}
	if decoder.Decode(new(any)) != io.EOF {
		return browserControlRequest{}, errBrowserControlNotJSON
	}
	if !validBrowserControlRequest(request) {
		return browserControlRequest{}, errBrowserControlInvalid
	}
	return request, nil
}

// ControlBrowserView addresses the same proved native instance as the visual
// stream. Product owns current user/interaction authority; the driver owns
// command serialization, lease expiry and input acknowledgements. Neither the
// driver's socket nor arbitrary CDP commands are exposed to the browser client.
func (s *SessionController) ControlBrowserView(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, browserPasteRequestLimit)
	request, err := decodeBrowserControlRequest(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "browser_control_invalid"})
		return
	}
	selected, ok := s.selectBrowserView(c)
	if !ok {
		return
	}
	link, failure := s.dialBrowserControl(c.Request.Context(), *selected)
	if link == nil {
		c.JSON(failure.status, failure.body)
		return
	}
	defer link.Close()
	stop := context.AfterFunc(c.Request.Context(), func() { _ = link.Close() })
	defer stop()
	outcome := s.executeBrowserControl(link, request)
	c.JSON(outcome.status, outcome.body)
}

// selectBrowserView resolves the addressed view under the addressed session's
// custody. Every route that addresses one view answers a failed observation
// and an unproven view the same way, so this answers them itself.
func (s *SessionController) selectBrowserView(c *gin.Context) (*browserView, bool) {
	views, err := s.browserViews(c.Request.Context(), c.Param("sessionId"))
	if err != nil {
		browserObservationError(c, err)
		return nil, false
	}
	for index := range views {
		if views[index].ID == c.Param("viewId") {
			return &views[index], true
		}
	}
	c.Status(http.StatusNotFound)
	return nil, false
}

// browserControlLink is one proved connection to the observed driver
// instance. The POST route holds it for one command; the channel keeps it for
// its lifetime and replaces it once it is lost.
type browserControlLink struct {
	connection *net.UnixConn
	view       browserView
	// lost records that the connection can no longer carry a command: the
	// transport failed, a reply could not be read, or the instance changed
	// under it. One line per command is then no longer in step, so nothing
	// further is sent on it.
	lost bool
	// undelivered records that the last command never reached the driver:
	// not one byte of it was accepted, so the driver had already closed the
	// connection, which a kept link only learns when it next writes.
	undelivered bool
}

func (l *browserControlLink) Close() error { return l.connection.Close() }

// unknown answers a command whose outcome this relay cannot vouch for and
// retires the link that carried it.
func (l *browserControlLink) unknown() browserControlOutcome {
	l.lost = true
	return browserControlFailure(http.StatusBadGateway, "browser_control_outcome_unknown")
}

// dialBrowserControl connects to the observed instance's command socket and
// proves the peer before any command is sent. A nil link is explained by the
// failure the POST route would answer with.
func (s *SessionController) dialBrowserControl(ctx context.Context, view browserView) (*browserControlLink, browserControlOutcome) {
	connection, err := (&net.Dialer{Timeout: browserDialTimeout}).DialContext(ctx, "unix", view.socketPath)
	if err != nil {
		return nil, browserControlFailure(http.StatusServiceUnavailable, "browser_control_unavailable")
	}
	link := &browserControlLink{connection: connection.(*net.UnixConn), view: view}
	// The connection that receives commands must be the observed process,
	// not a replacement that reused the advertised socket name.
	if err := s.proveBrowserControlPeer(link.connection, view); err != nil {
		_ = link.Close()
		return nil, browserControlFailure(http.StatusConflict, "browser_control_stale")
	}
	return link, browserControlOutcome{}
}

// executeBrowserControl sends one validated command on the link and answers
// exactly as the POST route does. The driver answers one line per command and
// only after receiving it, so with commands sent one at a time nothing but
// this command's reply can be waiting on the link.
func (s *SessionController) executeBrowserControl(link *browserControlLink, request browserControlRequest) browserControlOutcome {
	var command bytes.Buffer
	commandEncoder := json.NewEncoder(&command)
	// This is a JSON socket, not HTML. Preserve the already-bounded raw event
	// strings so pasted markup is not expanded sixfold by HTML escaping.
	commandEncoder.SetEscapeHTML(false)
	if err := commandEncoder.Encode(struct {
		Action string `json:"action"`
		browserControlRequest
	}{Action: "ambit_browser_control", browserControlRequest: request}); err != nil {
		return browserControlFailure(http.StatusBadRequest, "browser_control_invalid")
	}
	if command.Len() > browserControlRequestLimit(request) {
		return browserControlFailure(http.StatusBadRequest, "browser_control_invalid")
	}
	_ = link.connection.SetDeadline(time.Now().Add(browserControlDeadline))
	if written, err := io.Copy(link.connection, &command); err != nil {
		link.undelivered = written == 0
		return link.unknown()
	}
	responseLimit := browserControlLimit
	if request.Op == "copy" || request.Op == "files" || request.Op == "downloads" {
		responseLimit = browserCopyResponseLimit
	}
	line, err := bufio.NewReader(io.LimitReader(link.connection, int64(responseLimit+1))).ReadBytes('\n')
	if err != nil || len(line) > responseLimit {
		return link.unknown()
	}
	var response struct {
		Success bool            `json:"success"`
		Code    string          `json:"code"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(line, &response) != nil {
		return link.unknown()
	}
	if !response.Success {
		code := response.Code
		switch code {
		case "browser_control_invalid", "browser_control_conflict", "browser_control_expired", "browser_control_stale", "browser_control_sequence_gap", "browser_control_outcome_unknown", "browser_controlled_by_user", "browser_control_copy_too_large", "browser_control_surface_stale", "browser_control_file_stale", "browser_control_file_unsupported", "browser_control_files_unavailable", "browser_control_drop_rejected":
		default:
			code = "browser_control_unavailable"
		}
		return browserControlFailure(http.StatusConflict, code)
	}
	if err := s.proveBrowserControlPeer(link.connection, link.view); err != nil {
		link.lost = true
		return browserControlFailure(http.StatusConflict, "browser_control_outcome_unknown")
	}
	if request.Op == "inspect" || request.Op == "downloads" {
		var inspection struct {
			Supported      bool            `json:"supported"`
			Controlled     bool            `json:"controlled"`
			FilesSupported bool            `json:"filesSupported,omitempty"`
			Surface        *browserSurface `json:"surface,omitempty"`
		}
		if json.Unmarshal(response.Data, &inspection) != nil || !inspection.Supported || (inspection.Surface != nil && !inspection.Surface.valid()) {
			return browserControlFailure(http.StatusServiceUnavailable, "browser_control_unavailable")
		}
		if request.Op == "downloads" {
			files, ok := browserFileResponse(response.Data, request, "files")
			if !ok {
				return browserControlFailure(http.StatusBadGateway, "browser_control_unavailable")
			}
			return browserControlOutcome{status: http.StatusOK, body: gin.H{"supported": true, "controlled": inspection.Controlled, "downloads": files["downloads"]}}
		}
		return browserControlOutcome{status: http.StatusOK, body: inspection}
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
		return browserControlFailure(http.StatusBadGateway, "browser_control_outcome_unknown")
	}
	if request.Op == "files" || request.Op == "drop" {
		files, ok := browserFileResponse(response.Data, request, data.Status)
		if !ok {
			return browserControlFailure(http.StatusBadGateway, "browser_control_outcome_unknown")
		}
		files["controllerId"], files["expiresAt"] = data.ControllerID, data.ExpiresAt
		files["lastSequence"], files["status"] = data.LastSequence, data.Status
		if data.Surface != nil {
			files["surface"] = data.Surface
		}
		return browserControlOutcome{status: http.StatusOK, body: files}
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
			return browserControlFailure(http.StatusBadGateway, "browser_control_unavailable")
		}
		result := gin.H{"controllerId": data.ControllerID, "expiresAt": data.ExpiresAt,
			"lastSequence": data.LastSequence, "status": data.Status, "clipboard": copy.Clipboard}
		if data.Surface != nil {
			result["surface"] = data.Surface
		}
		return browserControlOutcome{status: http.StatusOK, body: result}
	}
	switch data.Status {
	case "controlled", "released", "applied", "duplicate", "dismissed":
		return browserControlOutcome{status: http.StatusOK, body: data}
	default:
		return browserControlFailure(http.StatusBadGateway, "browser_control_outcome_unknown")
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
	if request.ExpectedSurfaceGeneration != "" && ((request.Op != "input" && request.Op != "drop") || !validBrowserUUID(request.ExpectedSurfaceGeneration)) {
		return false
	}
	if request.Op == "files" || request.Op == "drop" || request.Op == "setfiles" || request.Op == "dismissfiles" {
		return validBrowserFileRequest(request)
	}
	if request.DestinationID != "" || len(request.Files) != 0 || request.X != nil || request.Y != nil {
		return false
	}
	if request.Op == "inspect" || request.Op == "downloads" {
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
