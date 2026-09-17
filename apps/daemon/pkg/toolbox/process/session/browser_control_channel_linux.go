// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/daytonaio/daemon/internal/util"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

const (
	// A peer that leaves this many pings unanswered is dropped, so a vanished
	// client holds its driver link for at most three ping intervals.
	browserChannelUnansweredPings = 2
	// One control frame to the peer is bounded so a stalled peer cannot pin
	// the goroutine that watches custody for it.
	browserChannelControlTimeout = 5 * time.Second
	// The daemon's own close code: the addressed view ended while the channel
	// was open.
	browserChannelViewEnded = 4410
)

// ControlBrowserViewChannel carries control commands over one WebSocket to the
// same proved native instance the POST route addresses. Each text frame is
// exactly one command document, the same one the POST accepts. Commands run
// strictly in arrival order through the POST route's own decoding, execution
// and projection, and each is answered by one text frame in that order:
// {"ok":true,"result":<POST body>} or
// {"ok":false,"status":<POST status>,"error":<POST error body>}. A failed
// command leaves the channel open. A frame that is not text, not one JSON
// document, or larger than the POST body limit is a protocol violation and
// closes the channel with 1008. The view ending closes it with 4410
// (browser_view_ended). The driver link is dialled and proved once, before the
// upgrade, and kept for the channel's lifetime.
func (s *SessionController) ControlBrowserViewChannel(c *gin.Context) {
	selected, ok := s.selectBrowserView(c)
	if !ok {
		return
	}
	link, failure := s.dialBrowserControl(c.Request.Context(), *selected)
	if link == nil {
		c.JSON(failure.status, failure.body)
		return
	}
	socket, err := util.UpgradeToWebSocket(c.Writer, c.Request)
	if err != nil {
		_ = link.Close()
		return
	}
	channel := &browserControlChannel{controller: s, socket: socket, view: *selected, link: link}
	channel.run(c.Request.Context())
}

type browserControlChannel struct {
	controller *SessionController
	socket     *websocket.Conn
	view       browserView
	// link is owned by the command loop alone.
	link *browserControlLink
	// unanswered counts pings sent since the peer last answered one.
	unanswered atomic.Int32
}

// run is the command loop. It ends when the peer closes, violates the
// protocol, or is closed by the watcher; a hijacked request's context does not
// observe the peer, so the loop cancels the watcher itself.
func (ch *browserControlChannel) run(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer ch.socket.Close()
	defer ch.dropLink()
	ch.socket.SetPongHandler(func(string) error {
		ch.unanswered.Store(0)
		return nil
	})
	go ch.watch(ctx)
	for {
		kind, reader, err := ch.socket.NextReader()
		if err != nil {
			return
		}
		if kind != websocket.TextMessage {
			ch.close(websocket.ClosePolicyViolation, "frame_not_text")
			return
		}
		// The frame is bounded here rather than by the socket's read limit,
		// which would answer with 1009 and no reason. Only one byte past the
		// limit is ever read; the rest of the frame stays unread and the
		// connection is closed under it.
		frame, err := io.ReadAll(io.LimitReader(reader, browserPasteRequestLimit+1))
		if err != nil {
			return
		}
		if len(frame) > browserPasteRequestLimit {
			ch.close(websocket.ClosePolicyViolation, "frame_too_large")
			return
		}
		var outcome browserControlOutcome
		request, err := decodeBrowserControlRequest(bytes.NewReader(frame))
		switch {
		case errors.Is(err, errBrowserControlNotJSON):
			ch.close(websocket.ClosePolicyViolation, "frame_not_json")
			return
		case err != nil:
			outcome = browserControlFailure(http.StatusBadRequest, "browser_control_invalid")
		default:
			outcome = ch.command(ctx, request)
		}
		if ch.reply(outcome) != nil {
			return
		}
	}
}

// command runs one command on the driver link, dialling a new link when the
// last one was lost. Nothing reaches the driver before the previous command
// has been answered, so the driver sees the frames' order and one command in
// flight. A kept link that the driver had already closed is only found out by
// the command's first write; that command reached nothing and is sent once
// more on a new link.
func (ch *browserControlChannel) command(ctx context.Context, request browserControlRequest) browserControlOutcome {
	outcome, resend := ch.attempt(ctx, request)
	if resend {
		outcome, _ = ch.attempt(ctx, request)
	}
	return outcome
}

func (ch *browserControlChannel) attempt(ctx context.Context, request browserControlRequest) (outcome browserControlOutcome, resend bool) {
	kept := ch.link != nil
	if !kept {
		link, failure := ch.controller.dialBrowserControl(ctx, ch.view)
		if link == nil {
			return failure, false
		}
		ch.link = link
	}
	outcome = ch.controller.executeBrowserControl(ch.link, request)
	resend = kept && ch.link.undelivered
	if ch.link.lost {
		ch.dropLink()
	}
	return outcome, resend
}

func (ch *browserControlChannel) dropLink() {
	if ch.link != nil {
		_ = ch.link.Close()
		ch.link = nil
	}
}

func (ch *browserControlChannel) reply(outcome browserControlOutcome) error {
	var envelope any
	if outcome.status == http.StatusOK {
		envelope = struct {
			OK     bool `json:"ok"`
			Result any  `json:"result"`
		}{true, outcome.body}
	} else {
		envelope = struct {
			OK     bool `json:"ok"`
			Status int  `json:"status"`
			Error  any  `json:"error"`
		}{false, outcome.status, outcome.body}
	}
	// The same encoder the POST route renders with, so the relayed document
	// is byte for byte the one the POST would have returned.
	frame, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	_ = ch.socket.SetWriteDeadline(time.Now().Add(browserViewerWriteTimeout))
	return ch.socket.WriteMessage(websocket.TextMessage, frame)
}

// watch re-observes custody every second, as the visual stream does, and
// pings the peer. Either ending closes the socket, which ends the command
// loop. Pongs are only seen by the loop's reads, and a command holds the loop
// for at most the control deadline, which is well inside one ping interval.
func (ch *browserControlChannel) watch(ctx context.Context) {
	custody := time.NewTicker(browserCustodyInterval)
	defer custody.Stop()
	pings := time.NewTicker(ch.controller.browserPingInterval)
	defer pings.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-custody.C:
			observed, err := ch.controller.sessionService.ObserveOwnedProcess(ch.view.SessionID, ch.view.pid)
			if err == nil && observed.StartTime == ch.view.born {
				continue
			}
			if browserViewEnded(observed, ch.view.born, err) {
				ch.close(browserChannelViewEnded, "browser_view_ended")
			} else {
				ch.close(websocket.CloseInternalServerErr, "browser_view_unobservable")
			}
			return
		case <-pings.C:
			if int(ch.unanswered.Add(1)) > browserChannelUnansweredPings {
				// The peer has not answered for two intervals. A close frame
				// would only join the pings it is not reading.
				_ = ch.socket.Close()
				return
			}
			_ = ch.socket.WriteControl(websocket.PingMessage, nil, time.Now().Add(browserChannelControlTimeout))
		}
	}
}

func (ch *browserControlChannel) close(code int, reason string) {
	_ = ch.socket.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(browserChannelControlTimeout))
	_ = ch.socket.Close()
}
