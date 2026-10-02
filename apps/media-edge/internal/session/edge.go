// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/daytonaio/media-edge/internal/grant"
	"github.com/daytonaio/media-edge/internal/view"
)

// Edge admits viewers and opens their sessions. Every carrier admits
// through it, so a grant means the same on each.
type Edge struct {
	Verifier grant.Verifier
	Hub      *Hub
	Upstream Upstream
	// Origins, when set, are the page origins a browser may connect from.
	Origins []string
	Log     *slog.Logger
	// Now is the clock (nil: time.Now); the verifier and hub share it.
	Now func() time.Time
}

func (e *Edge) now() time.Time {
	if e.Now == nil {
		return time.Now()
	}
	return e.Now()
}

// Admission is a viewer the edge will serve: what its grant proves and what
// it declared.
type Admission struct {
	Grant       grant.Grant
	Declaration view.Declaration
	// Fallback says why the page is on this carrier (telemetry only).
	Fallback string
}

// Refusal is an upgrade the edge refuses before any connection exists. A
// browser cannot read it; it falls back to its next carrier.
type Refusal struct {
	Status int
	Reason string
}

var fallbackReason = regexp.MustCompile(`^[a-z_]{1,64}$`)

// Admit checks an upgrade's origin, grant and declarations. The query is the
// upgrade's: grant, the viewer's declarations as the backend's upgrade takes
// them, and optionally tenantId and viewerId (which must be the grant's) and
// fallback.
func (e *Edge) Admit(query url.Values, origin string) (Admission, *Refusal) {
	if origin != "" && len(e.Origins) > 0 && !slices.Contains(e.Origins, origin) {
		return Admission{}, &Refusal{http.StatusForbidden, "origin"}
	}
	tokens := query["grant"]
	if len(tokens) != 1 {
		return Admission{}, &Refusal{http.StatusUnauthorized, "grant_missing"}
	}
	g, err := e.Verifier.Grant(tokens[0])
	if err != nil {
		return Admission{}, &Refusal{http.StatusUnauthorized, refusalReason(err)}
	}
	declaration, err := view.ParseDeclaration(query)
	if err != nil {
		return Admission{}, &Refusal{http.StatusBadRequest, "declaration"}
	}
	for name, bound := range map[string]string{"tenantId": g.TenantID, "viewerId": g.ViewerID} {
		if values, present := query[name]; present && (len(values) == 0 || values[0] != bound) {
			return Admission{}, &Refusal{http.StatusBadRequest, name}
		}
	}
	fallback := query.Get("fallback")
	if query.Has("fallback") && !fallbackReason.MatchString(fallback) {
		return Admission{}, &Refusal{http.StatusBadRequest, "fallback"}
	}
	if e.Hub.Revoked(g) {
		return Admission{}, &Refusal{http.StatusForbidden, "revoked"}
	}
	return Admission{Grant: g, Declaration: declaration, Fallback: fallback}, nil
}

func refusalReason(err error) string {
	for _, known := range []struct {
		err    error
		reason string
	}{
		{grant.ErrSignature, "grant_signature"}, {grant.ErrAudience, "grant_audience"}, {grant.ErrExpired, "grant_expired"},
		{grant.ErrLifetime, "grant_lifetime"}, {grant.ErrMalformed, "grant_malformed"},
	} {
		if errors.Is(err, known.err) {
			return known.reason
		}
	}
	return "grant"
}

// ErrRevoked is an admission a revocation overtook before its session opened.
var ErrRevoked = errors.New("session: the grant was revoked")

// Open registers the admitted viewer's session and dials its view route. A
// session is registered before the dial, so a revocation that arrives while
// it opens still reaches it.
func (e *Edge) Open(ctx context.Context, admission Admission, carrier string) (*Session, error) {
	g := admission.Grant
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	s := &Session{
		id:        hex.EncodeToString(id),
		edge:      e,
		carrier:   carrier,
		fallback:  admission.Fallback,
		binding:   g.Binding,
		channel:   view.NewChannel(admission.Declaration),
		pending:   view.NewPending(),
		opened:    time.Now(),
		authority: grant.NewAuthority(g),
		done:      make(chan struct{}),
	}
	s.counters.lastAt = s.opened
	s.log = e.Log.With(slog.Group("session", "id", s.id, "carrier", carrier, "fallback", admission.Fallback,
		"tenantId", g.TenantID, "userId", g.UserID, "viewerId", g.ViewerID, "sandboxId", g.SandboxID,
		"nativeViewId", g.NativeViewID, "scope", string(g.Scope)))
	if !e.Hub.admit(s, g) {
		return nil, ErrRevoked
	}
	s.mu.Lock()
	s.armLocked(e.now().UnixMilli())
	s.mu.Unlock()
	target := Target{SandboxID: g.SandboxID, SessionID: g.SessionID, ViewID: g.NativeViewID}
	conn, err := e.Upstream.DialView(ctx, target, g.ViewerID, admission.Declaration)
	s.dialed = time.Since(s.opened)
	if err != nil {
		s.end(0, "", causeTransport)
		e.Hub.remove(s)
		s.log.Warn("session.dial_failed", "dialMs", s.dialed.Milliseconds(), "error", err.Error())
		return nil, err
	}
	s.mu.Lock()
	s.upstream = conn
	ended := s.ended
	s.mu.Unlock()
	if ended {
		conn.Close()
	}
	return s, nil
}

// Abort ends a session whose carrier never opened.
func (s *Session) Abort() {
	s.end(0, "", causeTransport)
	s.edge.Hub.remove(s)
}
