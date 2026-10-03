// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package grant

import (
	"regexp"
	"time"
)

const (
	// MaxLifetime bounds expiresAt - issuedAt.
	MaxLifetime = 60 * time.Second
	// ClockSkew is how far a signer's clock may run ahead of the edge's.
	ClockSkew = 5 * time.Second
)

// Scope is what a grant lets its session do. Control includes view.
type Scope string

const (
	ScopeView    Scope = "view"
	ScopeControl Scope = "control"
)

// Binding is what a session is. Every grant a session holds names the same
// binding; scope, controller and times may differ between them.
type Binding struct {
	Audience     string
	TenantID     string
	UserID       string
	ThreadID     string
	ViewID       string
	ViewerID     string
	SandboxID    string
	SessionID    string
	NativeViewID string
}

// Grant admits one viewer to one browser view until ExpiresAt. Times are
// milliseconds since the Unix epoch; IssuedAt is when the access proof behind
// the grant started, which is what a revocation is ordered against.
type Grant struct {
	Binding
	IssuedAt     int64
	ExpiresAt    int64
	Scope        Scope
	ControllerID string
}

// Selector names the grants a revocation covers: every non-empty member must
// equal the grant's. TenantID is always present.
type Selector struct {
	TenantID     string
	UserID       string
	ThreadID     string
	ViewID       string
	ViewerID     string
	SandboxID    string
	SessionID    string
	NativeViewID string
}

// Revocation withdraws the grants its selector covers that were issued at or
// before it. A session left with no grant closes with Code.
type Revocation struct {
	Selector
	IssuedAt int64
	Code     int
}

// RevocationReasons are the closes a revocation may ask for, with the reason
// the page reads for each (as the backend's browserViewClose maps them).
var RevocationReasons = map[int]string{
	4401: "browser_view_signed_out",
	4403: "browser_view_forbidden",
	4404: "browser_view_not_found",
	4410: "browser_view_ended",
}

// Covers reports whether the revocation withdraws the grant.
func (r Revocation) Covers(g Grant) bool {
	return g.IssuedAt <= r.IssuedAt && r.Selector.matches(g.Binding)
}

func (s Selector) matches(b Binding) bool {
	for _, pair := range [...][2]string{
		{s.TenantID, b.TenantID}, {s.UserID, b.UserID}, {s.ThreadID, b.ThreadID}, {s.ViewID, b.ViewID},
		{s.ViewerID, b.ViewerID}, {s.SandboxID, b.SandboxID}, {s.SessionID, b.SessionID}, {s.NativeViewID, b.NativeViewID},
	} {
		if pair[0] != "" && pair[0] != pair[1] {
			return false
		}
	}
	return true
}

var (
	canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	opaqueID      = regexp.MustCompile(`^[A-Za-z0-9._~:-]+$`)
	edgeID        = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	nativeViewID  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func isUUID(value string) bool { return canonicalUUID.MatchString(value) }

func isIdentity(value string) bool {
	return isUUID(value) && value != "00000000-0000-0000-0000-000000000000"
}

// isOpaque admits 1-1024 URL-safe characters; the edge escapes them anyway
// when it builds the view route.
func isOpaque(value string) bool {
	return len(value) <= 1024 && opaqueID.MatchString(value) && value != "." && value != ".."
}

// IsEdgeID reports whether value can name an edge (the grant's audience).
func IsEdgeID(value string) bool { return edgeID.MatchString(value) }

func isNativeView(value string) bool { return nativeViewID.MatchString(value) }

// Verifier checks tokens against the keys and the edge it serves.
type Verifier struct {
	Keys     KeySource
	Audience string
	// Now is the edge's clock; nil means time.Now.
	Now func() time.Time
}

func (v Verifier) now() int64 {
	if v.Now == nil {
		return time.Now().UnixMilli()
	}
	return v.Now().UnixMilli()
}

// Grant verifies a grant token and checks that it admits a session now.
func (v Verifier) Grant(token string) (Grant, error) {
	payload, err := verified(token, v.Keys)
	if err != nil {
		return Grant{}, err
	}
	g, err := parseGrant(payload)
	if err != nil {
		return Grant{}, err
	}
	if g.Audience != v.Audience {
		return Grant{}, ErrAudience
	}
	now := v.now()
	if g.ExpiresAt-g.IssuedAt > MaxLifetime.Milliseconds() || g.IssuedAt > now+ClockSkew.Milliseconds() {
		return Grant{}, ErrLifetime
	}
	if now >= g.ExpiresAt {
		return Grant{}, ErrExpired
	}
	return g, nil
}

// Revocation verifies a revocation token. Revocations name no audience: the
// same token is posted to every edge process.
func (v Verifier) Revocation(token string) (Revocation, error) {
	payload, err := verified(token, v.Keys)
	if err != nil {
		return Revocation{}, err
	}
	r, err := parseRevocation(payload)
	if err != nil {
		return Revocation{}, err
	}
	if r.IssuedAt > v.now()+ClockSkew.Milliseconds() {
		return Revocation{}, ErrLifetime
	}
	return r, nil
}

func parseGrant(payload []byte) (Grant, error) {
	members, err := object(payload)
	if err != nil {
		return Grant{}, err
	}
	f := fields{members: members}
	version := f.integer("v", true)
	kind := f.text("typ", true, func(value string) bool { return value == "grant" })
	g := Grant{
		Binding: Binding{
			Audience:     f.text("aud", true, IsEdgeID),
			TenantID:     f.text("tenantId", true, isUUID),
			UserID:       f.text("userId", true, isUUID),
			ThreadID:     f.text("threadId", true, isOpaque),
			ViewID:       f.text("viewId", true, isOpaque),
			ViewerID:     f.text("viewerId", true, isIdentity),
			SandboxID:    f.text("sandboxId", true, isOpaque),
			SessionID:    f.text("sessionId", true, isOpaque),
			NativeViewID: f.text("nativeViewId", true, isNativeView),
		},
		IssuedAt:  f.integer("issuedAt", true),
		ExpiresAt: f.integer("expiresAt", true),
		Scope: Scope(f.text("scope", true, func(value string) bool {
			return value == string(ScopeView) || value == string(ScopeControl)
		})),
	}
	g.ControllerID = f.text("controllerId", g.Scope == ScopeControl, isIdentity)
	if !f.closed() || version != 1 || kind != "grant" || g.ExpiresAt <= g.IssuedAt ||
		(g.Scope == ScopeView && g.ControllerID != "") {
		return Grant{}, ErrMalformed
	}
	return g, nil
}

func parseRevocation(payload []byte) (Revocation, error) {
	members, err := object(payload)
	if err != nil {
		return Revocation{}, err
	}
	f := fields{members: members}
	version := f.integer("v", true)
	kind := f.text("typ", true, func(value string) bool { return value == "revoke" })
	r := Revocation{
		Selector: Selector{
			TenantID:     f.text("tenantId", true, isUUID),
			UserID:       f.text("userId", false, isUUID),
			ThreadID:     f.text("threadId", false, isOpaque),
			ViewID:       f.text("viewId", false, isOpaque),
			ViewerID:     f.text("viewerId", false, isIdentity),
			SandboxID:    f.text("sandboxId", false, isOpaque),
			SessionID:    f.text("sessionId", false, isOpaque),
			NativeViewID: f.text("nativeViewId", false, isNativeView),
		},
		IssuedAt: f.integer("issuedAt", true),
		Code:     int(f.integer("code", true)),
	}
	if _, known := RevocationReasons[r.Code]; !f.closed() || version != 1 || kind != "revoke" || !known {
		return Revocation{}, ErrMalformed
	}
	return r, nil
}
