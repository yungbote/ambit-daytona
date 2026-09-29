// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/daytonaio/media-edge/internal/control"
	"github.com/daytonaio/media-edge/internal/view"
)

// controlLine transports input under an already-held lease. It adds no
// lease authority, retries no sent input, and leaves pictures attached when
// its control route fails. The existing client settles unknown outcomes.
type controlLine struct {
	s        *Session
	target   Target
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	route    Conn
	bytes    int
	count    int
	requests chan controlRequest
	pending  chan controlRequest
	once     sync.Once
	failed   sync.Once
}

type controlRequest struct {
	input      *control.Input
	controller string
	bytes      int
}

func newControlLine(s *Session, target Target) *controlLine {
	ctx, cancel := context.WithCancel(context.Background())
	return &controlLine{s: s, target: target, ctx: ctx, cancel: cancel, requests: make(chan controlRequest, control.MaxPending), pending: make(chan controlRequest, control.MaxPending)}
}

func isControl(raw []byte) bool {
	return control.IsFrame(raw)
}

func (c *controlLine) authority() (string, bool) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	g, ok := c.s.authority.Control(c.s.edge.now().UnixMilli())
	return g.ControllerID, ok && !c.s.ended
}

func (c *controlLine) record(v any) {
	raw, err := json.Marshal(v)
	if err == nil {
		err = c.s.viewer.Send(&view.Delivery{Kind: view.Record, Text: raw})
	}
	if err != nil {
		c.s.end(1011, reasonUnavailable, causeWrite)
	} else {
		c.s.counters.down[view.Record].add(len(raw))
	}
}

func (c *controlLine) refuse(status int, code string) {
	c.record(map[string]any{"type": "control", "ok": false, "status": status, "error": map[string]string{"code": code}})
}

func (c *controlLine) refuseRequest(input *control.Input, status int, code string) {
	if input == nil {
		closeCode := 1013
		if status == 409 {
			closeCode = 4409
		}
		c.record(map[string]any{"type": "control", "state": "closed", "code": closeCode, "reason": code})
		return
	}
	c.refuse(status, code)
}

func (c *controlLine) receive(raw []byte) {
	if c.ctx.Err() != nil {
		return
	}
	var input *control.Input
	if control.Attach(raw) {
		// The controller comes from the grant, including on attach.
	} else {
		frame, err := control.Read(raw)
		if err != nil {
			c.s.end(1008, "browser_control_invalid", causeProtocol)
			return
		}
		input = &frame
	}
	controller, ok := c.authority()
	if !ok {
		c.refuseRequest(input, 409, "browser_control_expired")
		return
	}
	if c.s.edge.Controls == nil {
		c.refuseRequest(input, 502, "browser_control_unavailable")
		return
	}
	request := controlRequest{input: input, controller: controller, bytes: len(raw)}
	c.mu.Lock()
	if c.count >= control.MaxPending || c.bytes+request.bytes > control.MaxRequestBytes {
		c.mu.Unlock()
		c.fail()
		return
	}
	c.bytes += request.bytes
	c.count++
	c.mu.Unlock()
	select {
	case c.requests <- request:
	case <-c.ctx.Done():
		c.release(request.bytes)
	default:
		c.release(request.bytes)
		c.fail()
	}
}

func (c *controlLine) release(size int) { c.mu.Lock(); c.bytes -= size; c.count--; c.mu.Unlock() }

func (c *controlLine) close() {
	c.once.Do(func() {
		c.cancel()
		c.mu.Lock()
		route := c.route
		c.mu.Unlock()
		if route != nil {
			route.Close()
		}
	})
}

func (c *controlLine) fail() {
	c.failed.Do(func() {
		c.close()
		c.record(map[string]any{"type": "control", "state": "closed", "code": 1011, "reason": "browser_control_outcome_unknown"})
	})
}

func (c *controlLine) run() {
	var reader sync.WaitGroup
	defer func() {
		reader.Wait()
		for _, queue := range []chan controlRequest{c.requests, c.pending} {
			for {
				select {
				case request := <-queue:
					c.release(request.bytes)
				default:
					goto nextQueue
				}
			}
		nextQueue:
		}
	}()
	for {
		var request controlRequest
		select {
		case <-c.ctx.Done():
			return
		case request = <-c.requests:
		}
		controller, ok := c.authority()
		if !ok || controller != request.controller {
			c.release(request.bytes)
			c.refuseRequest(request.input, 409, "browser_control_stale")
			continue
		}
		c.mu.Lock()
		route := c.route
		c.mu.Unlock()
		if route == nil {
			var err error
			route, err = c.s.edge.Controls.DialControl(c.ctx, c.target)
			if err != nil {
				c.release(request.bytes)
				c.refuseRequest(request.input, 502, "browser_control_unavailable")
				continue
			}
			c.mu.Lock()
			c.route = route
			c.mu.Unlock()
			if c.ctx.Err() != nil {
				route.Close()
				c.release(request.bytes)
				return
			}
			reader.Add(1)
			go func() { defer reader.Done(); c.read(route) }()
		}
		// Re-check after a dial. A grant can expire or be revoked while the
		// network opens; no queued input inherits an earlier admission.
		controller, ok = c.authority()
		if !ok || controller != request.controller {
			c.release(request.bytes)
			c.refuseRequest(request.input, 409, "browser_control_stale")
			continue
		}
		if request.input == nil {
			c.release(request.bytes)
			c.record(map[string]any{"type": "control", "state": "ready", "controllerId": controller})
			continue
		}
		select {
		case c.pending <- request:
		case <-c.ctx.Done():
			c.release(request.bytes)
			return
		}
		if err := route.Write(request.input.Command(controller)); err != nil {
			c.fail()
			return
		}
		c.s.counters.forwarded.Add(1)
	}
}

func (c *controlLine) read(route Conn) {
	for {
		text, raw, err := route.Read()
		if err != nil {
			if c.ctx.Err() == nil {
				c.fail()
			}
			return
		}
		var request controlRequest
		select {
		case request = <-c.pending:
		case <-c.ctx.Done():
			return
		default:
			c.fail()
			return
		}
		c.release(request.bytes)
		reply, err := controlReply(raw, request)
		if !text || err != nil {
			c.fail()
			return
		}
		c.record(reply)
	}
}

func controlReply(raw []byte, request controlRequest) (map[string]any, error) {
	if len(raw) > control.MaxReplyBytes {
		return nil, errors.New("control reply exceeds its bound")
	}
	var reply struct {
		OK     bool                       `json:"ok"`
		Result map[string]json.RawMessage `json:"result"`
		Status int                        `json:"status"`
		Error  map[string]json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		return nil, errors.New("invalid control reply")
	}
	if !reply.OK {
		var code string
		if reply.Status < 400 || reply.Status > 599 || json.Unmarshal(reply.Error["code"], &code) != nil || !closeReason.MatchString(code) {
			return nil, errors.New("invalid control refusal")
		}
		return map[string]any{"type": "control", "ok": false, "status": reply.Status, "error": map[string]string{"code": code}}, nil
	}
	var controller, status string
	var sequence, expires uint64
	if json.Unmarshal(reply.Result["controllerId"], &controller) != nil || controller != request.controller || json.Unmarshal(reply.Result["status"], &status) != nil || json.Unmarshal(reply.Result["lastSequence"], &sequence) != nil || json.Unmarshal(reply.Result["expiresAt"], &expires) != nil || expires > 9007199254740991 || sequence > 9007199254740991 || (status != "applied" && status != "duplicate") || (status == "applied" && sequence != request.input.Sequence) || (status == "duplicate" && sequence < request.input.Sequence) {
		return nil, errors.New("invalid control acknowledgement")
	}
	ack := map[string]json.RawMessage{}
	for _, name := range []string{"controllerId", "expiresAt", "lastSequence", "status", "surface", "timing"} {
		if value, ok := reply.Result[name]; ok {
			ack[name] = value
		}
	}
	return map[string]any{"type": "control", "ok": true, "acknowledgement": ack}, nil
}
