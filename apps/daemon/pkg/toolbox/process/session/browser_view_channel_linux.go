// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/daytonaio/daemon/internal/util"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

const (
	// One viewer message: an acknowledgement, a presentation size or a
	// subscription, and whatever small message the view contract adds next.
	browserViewerMessageLimit = 4096
	// The whole upgrade query. With the route's own members and headers the
	// driver's upgrade stays far inside the one read in which it parses it.
	browserViewDeclarationLimit = 1024
)

// ViewBrowserChannel carries one native view between a viewer and the driver
// that owns it. This route owns which process is the view, the viewer's
// identity and presentation authority, the custody watch, liveness and the
// bounds. The driver and the viewer own the picture and sound contract
// between them: pictures, sound and their records pass as the driver sends
// them, and what the viewer sends reaches the driver as it was sent, so a new
// codec, header member or viewer message needs neither side of this route.
//
// The upgrade binds the viewer identity for its lifetime, and a size makes the
// viewer the presenter. Every other member of the upgrade is the viewer's
// declaration of what it draws and plays, which reaches the driver as made.
func (s *SessionController) ViewBrowserChannel(c *gin.Context) {
	if !websocket.IsWebSocketUpgrade(c.Request) {
		c.Status(http.StatusUpgradeRequired)
		return
	}
	presentation, valid := parseBrowserChannelPresentation(c.Request)
	declaration, declared := parseBrowserViewDeclaration(c.Request.URL.RawQuery)
	if !valid || !declared {
		c.JSON(http.StatusBadRequest, gin.H{"code": "browser_view_invalid"})
		return
	}
	selected, ok := s.selectBrowserView(c)
	if !ok {
		return
	}
	address, headers := browserViewDriverUpgrade(selected.port, presentation, declaration)
	upstream, _, err := (&websocket.Dialer{HandshakeTimeout: browserDriverWriteTimeout}).DialContext(c.Request.Context(), address, headers)
	if err != nil {
		c.Status(http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	if ended, err := s.browserViewCurrent(*selected); ended || err != nil {
		if ended {
			c.Status(http.StatusNotFound)
		} else {
			browserObservationError(c, err)
		}
		return
	}
	socket, err := util.UpgradeToWebSocket(c.Writer, c.Request)
	if err != nil {
		return
	}
	channel := &browserViewChannel{controller: s, view: *selected, socket: socket, upstream: upstream}
	channel.run(c.Request.Context())
}

func parseBrowserChannelPresentation(request *http.Request) (*browserPresentation, bool) {
	if !validBrowserUUID(request.Header.Get("X-Ambit-Browser-Viewer")) {
		return nil, false
	}
	query := request.URL.Query()
	if !query.Has("width") && !query.Has("height") {
		return nil, true
	}
	return parseBrowserPresentation(request)
}

// The members of the driver's upgrade that belong to this route: ack pacing,
// the presenter's rate, patch compositing and the presentation size. A viewer
// cannot declare them; the route sets them.
func browserViewRouteMember(key string) bool {
	switch key {
	case "pacing", "maxFps", "patches", "width", "height":
		return true
	}
	return false
}

// parseBrowserViewDeclaration returns the viewer's declaration: every member
// of its upgrade query the route does not own, in the order it was made, and
// spelled as the driver reads it. The driver splits its request line on '&'
// and '=' and decodes nothing, so each name and value must be one that reads
// the same in both spellings; one that does not, or a query past the bound,
// is refused rather than forwarded as something else.
func parseBrowserViewDeclaration(query string) (string, bool) {
	if len(query) > browserViewDeclarationLimit {
		return "", false
	}
	var members []string
	for _, member := range strings.Split(query, "&") {
		if member == "" {
			continue
		}
		key, value, assigned := strings.Cut(member, "=")
		key, keyErr := url.QueryUnescape(key)
		value, valueErr := url.QueryUnescape(value)
		if keyErr != nil || valueErr != nil || key == "" || !browserViewDeclarationText(key) || !browserViewDeclarationText(value) {
			return "", false
		}
		if browserViewRouteMember(key) {
			continue
		}
		if assigned {
			key += "=" + value
		}
		members = append(members, key)
	}
	return strings.Join(members, "&"), true
}

// The characters a declaration member may use: those that mean the same
// escaped or not, and that the driver's query splitting never reads as a
// separator.
func browserViewDeclarationText(text string) bool {
	for _, character := range []byte(text) {
		switch {
		case 'a' <= character && character <= 'z', 'A' <= character && character <= 'Z', '0' <= character && character <= '9':
		case character == '-', character == '.', character == '_', character == '~', character == ',', character == ':':
		default:
			return false
		}
	}
	return true
}

// The driver's upgrade: the route's own members, then the viewer's
// declaration. Only a presenter names itself to the driver.
func browserViewDriverUpgrade(port uint16, presentation *browserPresentation, declaration string) (string, http.Header) {
	maxFps := 10
	var headers http.Header
	if presentation != nil {
		maxFps = 60
		headers = http.Header{"X-Ambit-Browser-Viewer": []string{presentation.Viewer}}
	}
	address := fmt.Sprintf("ws://127.0.0.1:%d/?pacing=ack&maxFps=%d&patches=1", port, maxFps)
	if presentation != nil {
		address += fmt.Sprintf("&width=%d&height=%d", presentation.Width, presentation.Height)
	}
	if declaration != "" {
		address += "&" + declaration
	}
	return address, headers
}

// Reuse the process and listener identities that define the selected view;
// a replacement listener in the same live process cannot inherit this channel.
func (s *SessionController) browserViewCurrent(view browserView) (ended bool, err error) {
	observed, err := s.sessionService.ObserveOwnedProcess(view.SessionID, view.pid)
	if err != nil || observed.StartTime != view.born {
		if browserViewEnded(observed, view.born, err) {
			return true, nil
		}
		return false, err
	}
	held, err := processHoldsSocket(view.pid, view.listener)
	if browserCustodyEnded(err) {
		return true, nil
	}
	return !held && err == nil, err
}

type browserViewChannel struct {
	controller *SessionController
	view       browserView
	socket     *websocket.Conn
	upstream   *websocket.Conn
	unanswered atomic.Int32
	closeOnce  sync.Once
	// Whether a picture has reached the viewer. Only the upstream reader,
	// which is also the viewer's only writer, reads and sets it.
	pictured bool
}

func (ch *browserViewChannel) run(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		_ = ch.socket.Close()
		_ = ch.upstream.Close()
		workers.Wait()
	}()
	stop := context.AfterFunc(ctx, func() {
		_ = ch.socket.Close()
		_ = ch.upstream.Close()
	})
	defer stop()
	ch.upstream.SetReadLimit(browserBinaryFrameLimit)
	ch.socket.SetPongHandler(func(string) error { ch.unanswered.Store(0); return nil })
	workers.Add(2)
	go func() { defer workers.Done(); defer cancel(); ch.readViewer() }()
	go func() { defer workers.Done(); ch.watch(ctx) }()
	// Store and forward, one message at a time: the next message is read only
	// once the viewer took the last, so a slow viewer holds the driver back
	// through the transport and nothing queues here.
	for {
		kind, message, err := ch.upstream.ReadMessage()
		if err != nil {
			if ctx.Err() == nil {
				if ended, _ := ch.controller.browserViewCurrent(ch.view); ended {
					ch.close(browserChannelViewEnded, "browser_view_ended")
				} else {
					ch.close(websocket.CloseInternalServerErr, "screencast_failed")
				}
			}
			return
		}
		if !ch.deliver(kind, message) {
			return
		}
	}
}

// deliver passes one driver message to the viewer, and reports whether the
// channel goes on. Binary messages are pictures and sound and pass as sent;
// the records of the sound and picture tracks pass as sent. The route keeps
// what is its own: a view that cannot speak this channel is sent to the
// compatible reader, and the driver's other records are projected to the
// view's own vocabulary, which is also what keeps its command, result and
// console records, and its failure text, out of every viewer's stream.
func (ch *browserViewChannel) deliver(kind int, message []byte) bool {
	if kind == websocket.BinaryMessage {
		if !ch.pictured {
			if browserLegacyBinaryFrame(message) {
				ch.close(websocket.CloseUnsupportedData, "browser_view_channel_unsupported")
				return false
			}
			ch.pictured = true
		}
		return ch.write(websocket.BinaryMessage, message)
	}
	var envelope struct {
		Type string `json:"type"`
	}
	if kind != websocket.TextMessage || !utf8.Valid(message) || json.Unmarshal(message, &envelope) != nil {
		ch.close(websocket.CloseInternalServerErr, "browser_view_invalid_frame")
		return false
	}
	if envelope.Type == "audio" || envelope.Type == "video" {
		return ch.write(websocket.TextMessage, message)
	}
	projected, sequence, record := browserViewMessage(message, true)
	switch record {
	case browserRecordDropped:
		if envelope.Type == "frame" {
			ch.close(websocket.CloseInternalServerErr, "browser_view_invalid_frame")
			return false
		}
		return true
	case browserRecordFinished:
		_ = ch.write(websocket.TextMessage, bytes.TrimSpace(browserFinishedRecord))
		ch.close(browserChannelViewEnded, "browser_view_ended")
		return false
	case browserRecordFailed:
		_ = ch.write(websocket.TextMessage, bytes.TrimSpace(browserUnavailableRecord))
		ch.close(websocket.CloseInternalServerErr, "screencast_failed")
		return false
	}
	if sequence != 0 {
		// This channel carries pictures only as binary messages. A driver
		// whose first picture is a text record cannot serve it, and the
		// viewer takes the compatible reader instead.
		if !ch.pictured && browserTextFrameHasJPEG(projected) {
			ch.close(websocket.CloseUnsupportedData, "browser_view_channel_unsupported")
		} else {
			ch.close(websocket.CloseInternalServerErr, "browser_view_invalid_frame")
		}
		return false
	}
	return ch.write(websocket.TextMessage, projected)
}

// Only the upstream reader writes messages to the viewer.
func (ch *browserViewChannel) write(kind int, message []byte) bool {
	_ = ch.socket.SetWriteDeadline(time.Now().Add(browserViewerWriteTimeout))
	return ch.socket.WriteMessage(kind, message) == nil
}

// browserViewMessageAdmitted reports whether a viewer message may travel to
// the driver: one bounded JSON object, which is how every message of the view
// contract is spelled. Its shape and meaning belong to the viewer and the
// driver. The one thing this route decides is its own authority: it is the
// view route, so the driver's input vocabulary never travels on it, even to a
// driver that would inject it without a controller. Input has its own route.
// The type is read by its exact name, as the driver reads it.
func browserViewMessageAdmitted(message []byte) bool {
	if len(message) > browserViewerMessageLimit || !utf8.Valid(message) {
		return false
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(message, &members) != nil || members == nil {
		return false
	}
	var kind string
	if raw, found := members["type"]; found && json.Unmarshal(raw, &kind) == nil {
		return !strings.HasPrefix(kind, "input_")
	}
	return true
}

func (ch *browserViewChannel) readViewer() {
	for {
		kind, reader, err := ch.socket.NextReader()
		if err != nil {
			return
		}
		if kind != websocket.TextMessage {
			ch.close(websocket.ClosePolicyViolation, "frame_not_text")
			return
		}
		message, err := io.ReadAll(io.LimitReader(reader, browserViewerMessageLimit+1))
		if err != nil {
			return
		}
		if !browserViewMessageAdmitted(message) {
			ch.close(websocket.ClosePolicyViolation, "browser_view_invalid_message")
			return
		}
		if !ch.writeUpstream(message) {
			return
		}
	}
}

// Only the viewer's reader writes to the driver.
func (ch *browserViewChannel) writeUpstream(message []byte) bool {
	_ = ch.upstream.SetWriteDeadline(time.Now().Add(browserDriverWriteTimeout))
	if ch.upstream.WriteMessage(websocket.TextMessage, message) != nil {
		ch.close(websocket.CloseInternalServerErr, "screencast_failed")
		return false
	}
	return true
}

func (ch *browserViewChannel) watch(ctx context.Context) {
	custody := time.NewTicker(browserCustodyInterval)
	defer custody.Stop()
	pings := time.NewTicker(ch.controller.browserPingInterval)
	defer pings.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-custody.C:
			ended, err := ch.controller.browserViewCurrent(ch.view)
			if ended {
				ch.close(browserChannelViewEnded, "browser_view_ended")
				return
			}
			if err != nil {
				ch.close(websocket.CloseInternalServerErr, "browser_view_unobservable")
				return
			}
		case <-pings.C:
			if int(ch.unanswered.Add(1)) > browserChannelUnansweredPings {
				_ = ch.socket.Close()
				return
			}
			if ch.socket.WriteControl(websocket.PingMessage, nil, time.Now().Add(browserChannelControlTimeout)) != nil {
				_ = ch.socket.Close()
				return
			}
		}
	}
}

func (ch *browserViewChannel) close(code int, reason string) {
	ch.closeOnce.Do(func() {
		_ = ch.socket.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(browserChannelControlTimeout))
		_ = ch.socket.Close()
		_ = ch.upstream.Close()
	})
}
