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
	"sync"
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
// exactly one command document, the same one the POST accepts. Commands reach
// the driver as their frames arrive, up to browserControlPipeline unanswered at
// once, through the POST route's own decoding and projection; the driver
// answers them one at a time in the order it received them, and each is
// answered on the channel by one text frame in the frames' order:
// {"ok":true,"result":<POST body>} or
// {"ok":false,"status":<POST status>,"error":<POST error body>}. A failed
// command leaves the channel open. A frame that is not text, not one JSON
// document, or larger than the POST body limit is a protocol violation and
// closes the channel with 1008. The view ending closes it with 4410
// (browser_view_ended). The driver link is dialled and proved before the
// upgrade and kept across commands. A connected Unix socket keeps its peer for
// its lifetime, so the link is proved once; the custody watch re-observes the
// view itself, its process and its stream listener, every second. A lost link
// fails its unanswered commands as unknown and is replaced for the next.
func (s *SessionController) ControlBrowserViewChannel(c *gin.Context) {
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
	channel := &browserControlChannel{controller: s, socket: socket, view: *selected, pipe: newBrowserControlPipe(link)}
	channel.run(c.Request.Context())
}

// browserControlPipeline bounds the commands a channel has sent or queued and
// not yet answered. Past it the channel stops reading frames, which holds the
// peer back through its own transport.
const browserControlPipeline = 64

type browserControlChannel struct {
	controller *SessionController
	socket     *websocket.Conn
	view       browserView
	// pipe is replaced by the command loop alone.
	pipe *browserControlPipe
	// unanswered counts pings sent since the peer last answered one.
	unanswered atomic.Int32
}

// run is the command loop. It ends when the peer closes, violates the
// protocol, or is closed by the watcher; a hijacked request's context does not
// observe the peer, so the loop cancels the watcher itself. Replies are
// written by one goroutine in the frames' order as each command settles.
func (ch *browserControlChannel) run(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	replies := make(chan *browserControlPending, browserControlPipeline)
	var replying sync.WaitGroup
	defer func() {
		cancel()
		_ = ch.socket.Close()
		ch.dropPipe()
		close(replies)
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
		for pending := range replies {
			select {
			case <-pending.done:
			case <-ctx.Done():
				return
			}
			if ch.reply(pending.outcome) != nil {
				// The peer is gone. The loop may be waiting for pipeline room
				// that only these replies would make, so it is let go too.
				cancel()
				_ = ch.socket.Close()
				return
			}
		}
	}()
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
		request, err := decodeBrowserControlRequest(bytes.NewReader(frame))
		if errors.Is(err, errBrowserControlNotJSON) {
			ch.close(websocket.ClosePolicyViolation, "frame_not_json")
			return
		}
		pending := &browserControlPending{request: request, done: make(chan struct{})}
		select {
		case replies <- pending:
		case <-ctx.Done():
			return
		}
		if err != nil {
			pending.settle(browserControlFailure(http.StatusBadRequest, "browser_control_invalid"))
			continue
		}
		ch.dispatch(ctx, pending)
	}
}

// dispatch sends one command on the kept link, dialling a new link when the
// last one was lost. A kept link that the driver had already closed is only
// found out by the command's first write; that command reached nothing and is
// sent once more on a new link.
func (ch *browserControlChannel) dispatch(ctx context.Context, pending *browserControlPending) {
	command, refused := browserControlCommand(pending.request)
	if refused != nil {
		pending.settle(*refused)
		return
	}
	for attempt := 0; attempt < 2; attempt++ {
		if ch.pipe != nil && ch.pipe.retired() {
			ch.dropPipe()
		}
		kept := ch.pipe != nil
		if !kept {
			link, failure := ch.controller.dialBrowserControl(ctx, ch.view)
			if link == nil {
				pending.settle(failure)
				return
			}
			ch.pipe = newBrowserControlPipe(link)
		}
		undelivered, err := ch.pipe.send(pending, command)
		if err == nil {
			return
		}
		// A command the retired pipe still held is settled by it.
		ch.dropPipe()
		if !kept || !undelivered {
			break
		}
	}
	pending.settle(browserControlFailure(http.StatusBadGateway, "browser_control_outcome_unknown"))
}

func (ch *browserControlChannel) dropPipe() {
	if ch.pipe != nil {
		ch.pipe.retire()
		ch.pipe = nil
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

// watch re-observes the view every second, as the visual stream does, and
// pings the peer. Either ending closes the socket, which ends the command
// loop. Pongs are only seen by the loop's reads, and the loop reads between
// frames, so a drop needs three ticks with no frame read between them, more
// than 30 seconds.
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

// browserControlPending is one frame's command until its outcome is known.
type browserControlPending struct {
	request browserControlRequest
	outcome browserControlOutcome
	// sentAt and delivered belong to the pipe's lock.
	sentAt    time.Time
	delivered bool
	once      sync.Once
	done      chan struct{}
}

func (p *browserControlPending) settle(outcome browserControlOutcome) {
	p.once.Do(func() {
		p.outcome = outcome
		close(p.done)
	})
}

// browserControlPipe carries one channel's commands on one proved driver
// link: commands are written as they arrive, and one reader matches the
// driver's replies to them in order. Once the link cannot carry a command
// the pipe is retired and every unanswered command's outcome is unknown.
type browserControlPipe struct {
	link   *browserControlLink
	mu     sync.Mutex
	wake   *sync.Cond
	queue  []*browserControlPending // sent, unanswered, in order
	closed bool
}

func newBrowserControlPipe(link *browserControlLink) *browserControlPipe {
	p := &browserControlPipe{link: link}
	p.wake = sync.NewCond(&p.mu)
	go p.read(bufio.NewReader(link.connection))
	return p
}

// send writes one command. undelivered reports that none of it reached the
// driver and that it is still this caller's to send again or settle.
func (p *browserControlPipe) send(pending *browserControlPending, command []byte) (undelivered bool, err error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return true, net.ErrClosed
	}
	pending.sentAt = time.Now()
	p.queue = append(p.queue, pending)
	p.wake.Signal()
	p.mu.Unlock()
	_ = p.link.connection.SetWriteDeadline(time.Now().Add(browserControlDeadline))
	written, err := p.link.connection.Write(command)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil {
		pending.delivered = true
		if p.closed {
			// Retired while this was written: it reached the driver and its
			// reply can no longer be read.
			pending.settle(browserControlFailure(http.StatusBadGateway, "browser_control_outcome_unknown"))
		}
		return false, nil
	}
	for index, queued := range p.queue {
		if queued == pending {
			p.queue = append(p.queue[:index], p.queue[index+1:]...)
			break
		}
	}
	if written == 0 {
		return true, err
	}
	pending.settle(browserControlFailure(http.StatusBadGateway, "browser_control_outcome_unknown"))
	return false, err
}

// read settles the unanswered commands in order. Each command is answered
// within browserControlDeadline of the driver becoming free for it: of its
// own write, or of the reply before it, whichever is later.
func (p *browserControlPipe) read(reader *bufio.Reader) {
	defer p.retire()
	var answered time.Time
	for {
		p.mu.Lock()
		for len(p.queue) == 0 && !p.closed {
			p.wake.Wait()
		}
		if p.closed {
			p.mu.Unlock()
			return
		}
		head := p.queue[0]
		p.mu.Unlock()
		started := head.sentAt
		if answered.After(started) {
			started = answered
		}
		_ = p.link.connection.SetReadDeadline(started.Add(browserControlDeadline))
		line, err := readBrowserControlReply(reader, browserControlResponseLimit(head.request))
		if err != nil {
			return
		}
		outcome, _, intact := projectBrowserControlReply(line, head.request)
		if !intact {
			return
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		p.queue = p.queue[1:]
		p.mu.Unlock()
		head.settle(outcome)
		answered = time.Now()
	}
}

func (p *browserControlPipe) retired() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// retire closes the link and settles every delivered, unanswered command as
// unknown: each may or may not have been applied. A command still being
// written is left to its sender, which learns from its write whether any of
// it reached the driver.
func (p *browserControlPipe) retire() {
	p.mu.Lock()
	var delivered []*browserControlPending
	for _, pending := range p.queue {
		if pending.delivered {
			delivered = append(delivered, pending)
		}
	}
	p.queue, p.closed = nil, true
	p.wake.Broadcast()
	p.mu.Unlock()
	_ = p.link.Close()
	for _, pending := range delivered {
		pending.settle(browserControlFailure(http.StatusBadGateway, "browser_control_outcome_unknown"))
	}
}
