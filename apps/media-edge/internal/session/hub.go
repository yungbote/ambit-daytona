// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"sync"
	"time"

	"github.com/daytonaio/media-edge/internal/grant"
)

// Hub knows every live session of this process and the revocations still in
// force, so that a revocation and an admission can never miss each other.
type Hub struct {
	mu          sync.Mutex
	sessions    map[*Session]struct{}
	revocations []grant.Revocation
	now         func() time.Time
}

// NewHub returns an empty hub on the given clock (nil: time.Now).
func NewHub(now func() time.Time) *Hub {
	if now == nil {
		now = time.Now
	}
	return &Hub{sessions: map[*Session]struct{}{}, now: now}
}

// admit registers a session unless a revocation in force covers its grant.
func (h *Hub) admit(s *Session, g grant.Grant) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.covered(g) {
		return false
	}
	h.sessions[s] = struct{}{}
	return true
}

// renew adds a verified grant to a live session unless a revocation in
// force covers it. It answers whether the grant was added.
func (h *Hub) renew(s *Session, g grant.Grant) (added bool, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.covered(g) {
		return false, nil
	}
	return s.add(g)
}

func (h *Hub) remove(s *Session) {
	h.mu.Lock()
	delete(h.sessions, s)
	h.mu.Unlock()
}

// Revoke puts a revocation in force: it withdraws the grants it covers from
// every live session, closing each session it leaves without one, and it
// refuses covered grants presented later for as long as any could be valid.
// It answers how many sessions it closed.
func (h *Hub) Revoke(r grant.Revocation) int {
	h.mu.Lock()
	h.prune()
	if r.IssuedAt+(grant.MaxLifetime+grant.ClockSkew).Milliseconds() > h.now().UnixMilli() {
		h.revocations = append(h.revocations, r)
	}
	var emptied []*Session
	for s := range h.sessions {
		if s.withdraw(r) {
			emptied = append(emptied, s)
		}
	}
	h.mu.Unlock()
	// Closing writes to viewers, which may be slow: never under the lock.
	closed := 0
	for _, s := range emptied {
		if s.end(r.Code, grant.RevocationReasons[r.Code], causeRevoked) {
			closed++
		}
	}
	return closed
}

// Revoked reports whether a revocation in force covers the grant.
func (h *Hub) Revoked(g grant.Grant) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.covered(g)
}

func (h *Hub) covered(g grant.Grant) bool {
	h.prune()
	for _, r := range h.revocations {
		if r.Covers(g) {
			return true
		}
	}
	return false
}

// prune forgets revocations older than any grant they could cover.
func (h *Hub) prune() {
	horizon := h.now().UnixMilli() - (grant.MaxLifetime + grant.ClockSkew).Milliseconds()
	kept := h.revocations[:0]
	for _, r := range h.revocations {
		if r.IssuedAt >= horizon {
			kept = append(kept, r)
		}
	}
	h.revocations = kept
}

// Shutdown ends every live session with the given close.
func (h *Hub) Shutdown(code int, reason string) {
	h.mu.Lock()
	sessions := make([]*Session, 0, len(h.sessions))
	for s := range h.sessions {
		sessions = append(sessions, s)
	}
	h.mu.Unlock()
	for _, s := range sessions {
		s.end(code, reason, causeShutdown)
	}
}

// Len is the number of live sessions.
func (h *Hub) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sessions)
}
