// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/daytonaio/media-edge/internal/grant"
	"github.com/daytonaio/media-edge/internal/view"
)

// Why a session ended, for its report.
const (
	causeViewer    = "viewer"
	causeUpstream  = "upstream"
	causeProtocol  = "protocol"
	causeRevoked   = "revoked"
	causeExpired   = "expired"
	causeShutdown  = "shutdown"
	causeWrite     = "write"
	causeTransport = "transport"
)

// The closes the session itself decides, with the reasons the page reads.
const (
	reasonUnavailable  = "browser_view_unavailable"
	reasonInvalid      = "browser_view_invalid_message"
	reasonGrantExpired = "browser_view_grant_expired"
	reasonViewEnded    = "browser_view_ended"
)

// ReportInterval is how often a live session reports its counters.
const ReportInterval = time.Minute

// Session is one viewer of one browser view through one carrier.
type Session struct {
	id       string
	edge     *Edge
	carrier  string
	fallback string
	binding  grant.Binding
	channel  *view.Channel
	pending  *view.Pending
	upstream Conn
	opened   time.Time
	dialed   time.Duration
	counters counters
	log      *slog.Logger

	mu        sync.Mutex
	authority *grant.Authority
	expiry    *time.Timer
	viewer    Carrier
	ended     bool
	close     struct {
		code          int
		reason, cause string
	}
	done chan struct{}
}

// add takes a verified renewal. A grant for another binding is a violation;
// one that expired adds nothing.
func (s *Session) add(g grant.Grant) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.edge.now().UnixMilli()
	if err := s.authority.Add(g, now); err != nil {
		return false, err
	}
	s.armLocked(now)
	return now < g.ExpiresAt, nil
}

// revoke withdraws what the revocation covers and ends the session when no
// grant is left. It answers whether it ended the session.
func (s *Session) revoke(r grant.Revocation) bool {
	s.mu.Lock()
	viewing := s.authority.Revoke(r)
	s.mu.Unlock()
	if viewing {
		return false
	}
	return s.end(r.Code, grant.RevocationReasons[r.Code], causeRevoked)
}

// armLocked sets the timer for the moment viewing lapses without renewal.
func (s *Session) armLocked(now int64) {
	until, ok := s.authority.ViewUntil(now)
	if !ok {
		until = now
	}
	delay := time.Duration(until-now) * time.Millisecond
	if s.expiry == nil {
		s.expiry = time.AfterFunc(delay, s.lapse)
	} else {
		s.expiry.Reset(delay)
	}
}

func (s *Session) lapse() {
	s.mu.Lock()
	now := s.edge.now().UnixMilli()
	s.authority.Prune(now)
	if _, viewing := s.authority.ViewUntil(now); viewing {
		s.armLocked(now)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.end(1013, reasonGrantExpired, causeExpired)
}

// end closes the session once, with the close the viewer reads (code 0:
// the viewer is already gone). It answers whether this call ended it.
func (s *Session) end(code int, reason, cause string) bool {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return false
	}
	s.ended = true
	s.close.code, s.close.reason, s.close.cause = code, reason, cause
	if s.expiry != nil {
		s.expiry.Stop()
	}
	viewer, upstream := s.viewer, s.upstream
	s.mu.Unlock()
	close(s.done)
	if viewer != nil {
		viewer.Close(code, reason)
	}
	if upstream != nil {
		upstream.Close()
	}
	return true
}

// Run carries the session over the viewer's carrier until it ends, and
// reports it. It returns when every flow has stopped.
func (s *Session) Run(viewer Carrier) {
	defer s.edge.Hub.remove(s)
	s.mu.Lock()
	if s.ended {
		code, reason := s.close.code, s.close.reason
		s.mu.Unlock()
		viewer.Close(code, reason)
		s.report("session.closed")
		return
	}
	s.viewer = viewer
	s.mu.Unlock()
	s.log.Info("session.opened", "dialMs", s.dialed.Milliseconds())
	var flows sync.WaitGroup
	flows.Add(3)
	go func() { defer flows.Done(); s.pump(viewer) }()
	go func() { defer flows.Done(); s.forward() }()
	go func() { defer flows.Done(); s.periodicReports() }()
	s.read(viewer)
	flows.Wait()
	s.report("session.closed")
}

// pump carries the view route's messages to the viewer, one at a time, so
// the viewer's backpressure reaches the producer.
func (s *Session) pump(viewer Carrier) {
	for {
		text, message, err := s.upstream.Read()
		read := time.Now()
		if err != nil {
			code, reason := viewerClose(err)
			s.end(code, reason, causeUpstream)
			return
		}
		s.counters.upstreamRead.add(len(message))
		delivery, closing := s.channel.Upstream(text, message)
		if delivery != nil {
			start := time.Now()
			s.counters.hold.observe(start.Sub(read))
			if err := viewer.Send(delivery); err != nil {
				s.end(1011, reasonUnavailable, causeWrite)
				return
			}
			s.counters.write.observe(time.Since(start))
			s.counters.down[delivery.Kind].add(delivery.Size())
		} else {
			s.counters.down[0].add(len(message))
		}
		if closing != nil {
			s.end(closing.Code, closing.Reason, causeProtocol)
			return
		}
	}
}

// viewerClose maps how the view route ended to the close the viewer reads,
// exactly as the backend relay maps it today.
func viewerClose(err error) (int, string) {
	var closed *Closed
	if !errors.As(err, &closed) {
		return 1011, reasonUnavailable
	}
	code := 1011
	switch closed.Code {
	case 1000, 1003, 1008, 4410:
		code = closed.Code
	}
	if closeReason.MatchString(closed.Reason) {
		return code, closed.Reason
	}
	return code, reasonViewEnded
}

var closeReason = regexp.MustCompile(`^[a-z_]{1,64}$`)

// forward sends the newest pending viewer message of each slot to the view
// route, in slot order, one at a time.
func (s *Session) forward() {
	for {
		select {
		case <-s.done:
			return
		case <-s.pending.Ready():
		}
		for message, ok := s.pending.Next(); ok; message, ok = s.pending.Next() {
			if err := s.upstream.Write(message); err != nil {
				s.end(1011, reasonUnavailable, causeUpstream)
				return
			}
			s.counters.forwarded.Add(1)
		}
	}
}

// read takes the viewer's messages until the carrier ends; after the
// session ended it only drains, so a close the viewer is answering is read.
func (s *Session) read(viewer Carrier) {
	for {
		text, message, err := viewer.Receive()
		if err != nil {
			s.end(0, "", causeViewer)
			return
		}
		select {
		case <-s.done:
			continue
		default:
		}
		s.counters.received.Add(1)
		if text && isRenewal(message) {
			s.renewal(message)
			continue
		}
		forward, closing := s.channel.Viewer(text, message)
		switch {
		case closing != nil:
			s.end(closing.Code, closing.Reason, causeProtocol)
		case forward == nil:
			s.counters.ignored.Add(1)
		case s.pending.Put(*forward):
			s.counters.superseded.Add(1)
		}
	}
}

// isRenewal recognizes the one message the session itself answers.
func isRenewal(message []byte) bool {
	var envelope struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(message, &envelope) == nil && envelope.Type == "grant"
}

// renewal takes {"type":"grant","token":...}: a grant that verifies joins
// the session's authority; an expired or revoked one adds nothing; anything
// else ends the session as an invalid message.
func (s *Session) renewal(message []byte) {
	var value struct {
		Type  string `json:"type"`
		Token string `json:"token"`
	}
	decoder := json.NewDecoder(bytes.NewReader(message))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.More() || value.Type != "grant" {
		s.end(1008, reasonInvalid, causeProtocol)
		return
	}
	g, err := s.edge.Verifier.Grant(value.Token)
	switch {
	case errors.Is(err, grant.ErrExpired):
		s.counters.renewalsIgnored.Add(1)
		return
	case err != nil:
		s.log.Warn("session.renewal_refused", "reason", err.Error())
		s.end(1008, reasonInvalid, causeProtocol)
		return
	}
	added, err := s.edge.Hub.renew(s, g)
	switch {
	case err != nil:
		s.log.Warn("session.renewal_refused", "reason", err.Error())
		s.end(1008, reasonInvalid, causeProtocol)
	case added:
		s.counters.renewed.Add(1)
	default:
		s.counters.renewalsIgnored.Add(1)
	}
}

func (s *Session) periodicReports() {
	ticker := time.NewTicker(ReportInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.report("session.report")
		}
	}
}

func (s *Session) report(event string) {
	s.mu.Lock()
	closing := s.close
	s.mu.Unlock()
	now := time.Now()
	attrs := append([]any{"ageMs", now.Sub(s.opened).Milliseconds()}, s.counters.attrs(now)...)
	if event == "session.closed" {
		attrs = append(attrs, slog.Group("close", "code", closing.code, "reason", closing.reason, "cause", closing.cause))
	}
	s.log.Info(event, attrs...)
}
