// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package grant

// Authority is the set of grants one session holds. The session may view
// while any of them is unexpired, and control with the newest control grant
// (by IssuedAt) while that one is unexpired. Because every rule is a function
// of the set, the order in which grants arrive never matters. It is not safe
// for concurrent use; its session guards it.
type Authority struct {
	binding Binding
	grants  []Grant
	// Expiry or pruning cannot restore a grant for an older controller.
	controlIssued     int64
	controlController string
	controlAmbiguous  bool
}

// NewAuthority starts a session's authority from the grant that admitted it.
func NewAuthority(first Grant) *Authority {
	a := &Authority{binding: first.Binding, grants: []Grant{first}}
	if first.Scope == ScopeControl {
		a.controlIssued = first.IssuedAt
		a.controlController = first.ControllerID
	}
	return a
}

// Binding is the session every grant of this authority names.
func (a *Authority) Binding() Binding { return a.binding }

// Add takes a verified grant. A grant for another binding is refused; one
// that is already expired adds nothing.
func (a *Authority) Add(g Grant, now int64) error {
	if g.Binding != a.binding {
		return ErrBinding
	}
	a.Prune(now)
	if now < g.ExpiresAt {
		if g.Scope == ScopeControl {
			if g.IssuedAt > a.controlIssued {
				a.controlIssued, a.controlController, a.controlAmbiguous = g.IssuedAt, g.ControllerID, false
			} else if g.IssuedAt == a.controlIssued && g.ControllerID != a.controlController {
				// Integer-millisecond proof starts are not unique. Neither
				// arrival order nor expiry may choose between tied controllers.
				a.controlAmbiguous = true
			}
		}
		for _, held := range a.grants {
			if held == g {
				return nil
			}
		}
		a.grants = append(a.grants, g)
	}
	return nil
}

// Prune forgets the grants that expired.
func (a *Authority) Prune(now int64) {
	kept := a.grants[:0]
	for _, g := range a.grants {
		if now < g.ExpiresAt {
			kept = append(kept, g)
		}
	}
	a.grants = kept
}

// Revoke removes the grants the revocation covers and reports whether the
// session may still view.
func (a *Authority) Revoke(r Revocation) bool {
	kept := a.grants[:0]
	for _, g := range a.grants {
		if !r.Covers(g) {
			kept = append(kept, g)
		}
	}
	a.grants = kept
	return len(kept) > 0
}

// ViewUntil is when viewing lapses without another grant: the latest expiry
// of the grants held; ok is false when none is unexpired.
func (a *Authority) ViewUntil(now int64) (until int64, ok bool) {
	for _, g := range a.grants {
		if now < g.ExpiresAt && g.ExpiresAt > until {
			until, ok = g.ExpiresAt, true
		}
	}
	return until, ok
}

// Control is the newest control grant while it is unexpired. Older grants
// may still permit viewing, but never become control authority again.
func (a *Authority) Control(now int64) (Grant, bool) {
	if a.controlAmbiguous {
		return Grant{}, false
	}
	var newest Grant
	found := false
	for _, g := range a.grants {
		if g.Scope == ScopeControl && g.IssuedAt >= a.controlIssued && now < g.ExpiresAt && (!found || g.IssuedAt >= newest.IssuedAt) {
			newest, found = g, true
		}
	}
	return newest, found
}

// Newest is the latest-issued grant held, for logs.
func (a *Authority) Newest() (Grant, bool) {
	var newest Grant
	for index, g := range a.grants {
		if index == 0 || g.IssuedAt >= newest.IssuedAt {
			newest = g
		}
	}
	return newest, len(a.grants) > 0
}
