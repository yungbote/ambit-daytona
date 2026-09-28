// Copyright 2026 Ambit
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
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daytonaio/daemon/internal/util"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

const (
	// The driver's action for the agent principal. The route is the principal:
	// the toolbox names the action itself and a frame may not carry one.
	browserAgentAction = "ambit_browser_agent"
	// Frames written to the driver and not yet answered. Past it the channel
	// stops forwarding, which holds the host back through its own transport.
	browserAgentPipeline = 4
	// The browser request bound and the driver's read-ahead bound.
	browserAgentRequestLimit = 2 << 20
	browserAgentReplyLimit   = 4 << 20
	// A dead host is dropped within three intervals, which bounds how long its
	// unfinished sequence can keep starting steps.
	browserAgentPingInterval = 2 * time.Second
	browserAgentWriteTimeout = 10 * time.Second
)

// AgentBrowserViewChannel carries the host's browser operations over one
// WebSocket to the same proved native instance the control routes address,
// under the agent principal. Each text frame is one JSON object with a
// strictly increasing integer id; it reaches the driver as one line with the
// agent action added and every member value unchanged. The driver answers one
// line per frame, in order, and each line is relayed verbatim as one text
// frame: the reader is the host, as a command's output is today. A frame that
// is not text, not one JSON object, too large, or carries an action or a bad
// id is a protocol violation and closes the channel with 1008. The driver
// link is dialled and proved before the upgrade and is never replaced: the
// driver's side of the channel belongs to its connection, so a lost or
// out-of-step link closes the channel with 1011 agent_channel_link_lost and
// the host reopens and asks what became of its frames.
func (s *SessionController) AgentBrowserViewChannel(c *gin.Context) {
	if !websocket.IsWebSocketUpgrade(c.Request) {
		c.Status(http.StatusUpgradeRequired)
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
	socket, err := util.UpgradeToWebSocket(c.Writer, c.Request)
	if err != nil {
		_ = link.Close()
		return
	}
	channel := &browserAgentChannel{controller: s, socket: socket, view: *selected, link: link, room: make(chan struct{}, browserAgentPipeline), sent: make(chan uint64, browserAgentPipeline)}
	channel.run(c.Request.Context())
}

type browserAgentChannel struct {
	controller *SessionController
	socket     *websocket.Conn
	view       browserView
	link       *browserControlLink
	// room holds one token per frame written and unanswered.
	room chan struct{}
	// sent carries the ids of written frames to the reply reader, in order.
	sent chan uint64
	// parked is set while the frame loop waits for room. The peer's pongs are
	// only seen by that loop's reads, so its silence then is not its absence.
	parked     atomic.Bool
	unanswered atomic.Int32
	closing    sync.Once
}

var errBrowserAgentFrame = errors.New("invalid agent frame")

// browserAgentLine turns one frame into the driver's line. Member values pass
// as the bytes they arrived in, compacted so that no raw newline reaches the
// line protocol; nothing is decoded and encoded again.
func browserAgentLine(frame []byte, previous uint64) (line []byte, id uint64, reason string) {
	decoder := json.NewDecoder(bytes.NewReader(frame))
	opening, err := decoder.Token()
	if delimiter, object := opening.(json.Delim); err != nil || !object || delimiter != '{' {
		return nil, 0, "frame_not_json"
	}
	var out bytes.Buffer
	out.WriteString(`{"action":"` + browserAgentAction + `"`)
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, named := token.(string)
		if err != nil || !named {
			return nil, 0, "frame_not_json"
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, 0, "frame_not_json"
		}
		if seen[key] || key == "action" {
			return nil, 0, "frame_invalid"
		}
		seen[key] = true
		if key == "id" {
			// An integer as written: no sign, fraction or exponent.
			id, err = strconv.ParseUint(string(value), 10, 64)
			if err != nil || id == 0 || id > browserSafeInteger || id <= previous || (len(value) > 1 && value[0] == '0') {
				return nil, 0, "frame_invalid"
			}
		}
		name, _ := json.Marshal(key)
		out.WriteByte(',')
		out.Write(name)
		out.WriteByte(':')
		if json.Compact(&out, value) != nil {
			return nil, 0, "frame_not_json"
		}
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, 0, "frame_not_json"
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, 0, "frame_not_json"
	}
	if !seen["id"] {
		return nil, 0, "frame_invalid"
	}
	out.WriteString("}\n")
	return out.Bytes(), id, ""
}

func (ch *browserAgentChannel) run(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	var replying sync.WaitGroup
	defer func() {
		cancel()
		_ = ch.socket.Close()
		_ = ch.link.Close()
		replying.Wait()
	}()
	ch.socket.SetPongHandler(func(string) error {
		ch.unanswered.Store(0)
		return nil
	})
	go ch.watch(ctx)
	replying.Add(1)
	go func() {
		defer replying.Done()
		defer cancel()
		ch.relay(ctx)
	}()
	var previous uint64
	for {
		kind, reader, err := ch.socket.NextReader()
		if err != nil {
			return
		}
		if kind != websocket.TextMessage {
			ch.close(websocket.ClosePolicyViolation, "frame_not_text")
			return
		}
		frame, err := io.ReadAll(io.LimitReader(reader, browserAgentRequestLimit+1))
		if err != nil {
			return
		}
		if len(frame) > browserAgentRequestLimit {
			ch.close(websocket.ClosePolicyViolation, "frame_too_large")
			return
		}
		line, id, reason := browserAgentLine(frame, previous)
		if reason != "" {
			ch.close(websocket.ClosePolicyViolation, reason)
			return
		}
		previous = id
		ch.parked.Store(true)
		select {
		case ch.room <- struct{}{}:
			ch.parked.Store(false)
		case <-ctx.Done():
			return
		}
		// The reply reader learns the id before the driver can answer it.
		ch.sent <- id
		_ = ch.link.connection.SetWriteDeadline(time.Now().Add(browserAgentWriteTimeout))
		if _, err := ch.link.connection.Write(line); err != nil {
			ch.close(websocket.CloseInternalServerErr, "agent_channel_link_lost")
			return
		}
	}
}

// relay reads the driver's lines and relays each as one text frame. A line
// answers the oldest unanswered frame or the link is out of step.
func (ch *browserAgentChannel) relay(ctx context.Context) {
	reader := bufio.NewReaderSize(ch.link.connection, 64<<10)
	for {
		line, err := readBrowserControlReply(reader, browserAgentReplyLimit)
		if err != nil {
			if ctx.Err() == nil {
				ch.close(websocket.CloseInternalServerErr, "agent_channel_link_lost")
			}
			return
		}
		var expected uint64
		select {
		case expected = <-ch.sent:
		default:
			// The driver spoke without having been asked.
			ch.close(websocket.CloseInternalServerErr, "agent_channel_link_lost")
			return
		}
		var reply struct {
			ID json.RawMessage `json:"id"`
		}
		line = bytes.TrimRight(line, "\r\n")
		intact := len(line) > 0 && line[0] == '{' && json.Unmarshal(line, &reply) == nil
		id, err := strconv.ParseUint(string(reply.ID), 10, 64)
		if !intact || err != nil || id != expected {
			ch.close(websocket.CloseInternalServerErr, "agent_channel_link_lost")
			return
		}
		_ = ch.socket.SetWriteDeadline(time.Now().Add(browserViewerWriteTimeout))
		if err = ch.socket.WriteMessage(websocket.TextMessage, line); err != nil {
			_ = ch.socket.Close()
			return
		}
		<-ch.room
	}
}

// watch re-observes the view every second and pings the host every two.
func (ch *browserAgentChannel) watch(ctx context.Context) {
	custody := time.NewTicker(browserCustodyInterval)
	defer custody.Stop()
	interval := browserAgentPingInterval
	if ch.controller.browserPingInterval < interval {
		interval = ch.controller.browserPingInterval
	}
	pings := time.NewTicker(interval)
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
			if ch.parked.Load() {
				ch.unanswered.Store(0)
			} else if int(ch.unanswered.Add(1)) > browserChannelUnansweredPings {
				_ = ch.socket.Close()
				_ = ch.link.Close()
				return
			}
			_ = ch.socket.WriteControl(websocket.PingMessage, nil, time.Now().Add(browserChannelControlTimeout))
		}
	}
}

func (ch *browserAgentChannel) close(code int, reason string) {
	ch.closing.Do(func() {
		_ = ch.socket.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(browserChannelControlTimeout))
		_ = ch.socket.Close()
		_ = ch.link.Close()
	})
}
