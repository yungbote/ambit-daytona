// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/grant"
)

const controllerID = "00000000-1111-4222-8333-444444444444"

type fakeControlUpstream struct {
	mu     sync.Mutex
	route  *fakeRoute
	dials  int
	gate   chan struct{}
	target Target
}

func (u *fakeControlUpstream) DialControl(ctx context.Context, target Target) (Conn, error) {
	u.mu.Lock()
	u.dials++
	u.target = target
	u.mu.Unlock()
	if u.gate != nil {
		select {
		case <-u.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return u.route, nil
}

func (u *fakeControlUpstream) count() int { u.mu.Lock(); defer u.mu.Unlock(); return u.dials }

func controlRecord(c *fakeCarrier, state string) bool {
	for _, record := range c.delivered() {
		var value struct {
			Type, State string
			OK          bool
		}
		_ = json.Unmarshal(record.Text, &value)
		if value.Type == "control" && ((state == "applied" && value.OK) || value.State == state) {
			return true
		}
	}
	return false
}

func attachControl(t *testing.T, viewer *fakeCarrier, edits map[string]any) {
	t.Helper()
	if edits == nil {
		edits = map[string]any{}
	}
	edits["scope"], edits["controllerId"] = "control", controllerID
	raw, _ := json.Marshal(map[string]string{"type": "grant", "token": token(t, edits)})
	viewer.send(string(raw))
	viewer.send(`{"type":"control","op":"attach"}`)
}

func inputControl(viewer *fakeCarrier, sequence int) {
	raw, _ := json.Marshal(map[string]any{"type": "control", "op": "input", "sequence": sequence, "events": []any{map[string]any{"type": "input_keyboard", "eventType": "char", "text": "x"}}})
	viewer.send(string(raw))
}

func TestControlNeedsCurrentGrantAndWritesOnlyGrantedInput(t *testing.T) {
	edge, _, viewer, _, finished := open(t, nil)
	defer func() { viewer.Close(0, ""); <-finished }()
	route := newFakeRoute()
	upstream := &fakeControlUpstream{route: route}
	edge.Controls = upstream
	viewer.send(`{"type":"control","op":"attach"}`)
	await(t, "view grant control refusal", func() bool { return len(viewer.delivered()) == 1 })
	if upstream.count() != 0 {
		t.Fatal("view grant dialed control")
	}
	attachControl(t, viewer, nil)
	await(t, "control ready", func() bool { return controlRecord(viewer, "ready") })
	for sequence := 1; sequence <= 3; sequence++ {
		inputControl(viewer, sequence)
	}
	await(t, "all input pipelined before replies", func() bool { return len(route.messages()) == 3 })
	for sequence, raw := range route.messages() {
		var command struct {
			Op, ControllerID string
			Sequence         int
			ExpiresAt        *int
		}
		if json.Unmarshal([]byte(raw), &command) != nil || command.Op != "input" || command.ControllerID != controllerID || command.Sequence != sequence+1 || command.ExpiresAt != nil {
			t.Fatalf("wrong command: %s", raw)
		}
		route.out <- inbound{true, []byte(`{"ok":true,"result":{"controllerId":"` + controllerID + `","expiresAt":9000000000000,"lastSequence":` + string(rune('1'+sequence)) + `,"status":"applied","timing":{"queueUs":2,"injectUs":3}}}`)}
	}
	await(t, "input acknowledgement", func() bool { return controlRecord(viewer, "applied") })
	if upstream.count() != 1 || upstream.target.SandboxID != "sandbox-1" || upstream.target.SessionID != "session:1" || upstream.target.ViewID != native {
		t.Fatalf("control target/dials: %+v", upstream)
	}
}

func TestControlRechecksAuthorityAfterTheDial(t *testing.T) {
	edge, _, viewer, _, finished := open(t, nil)
	defer func() { viewer.Close(0, ""); <-finished }()
	route := newFakeRoute()
	gate := make(chan struct{})
	upstream := &fakeControlUpstream{route: route, gate: gate}
	edge.Controls = upstream
	now := time.Now().UnixMilli()
	attachControl(t, viewer, map[string]any{"issuedAt": now, "expiresAt": now + 100})
	inputControl(viewer, 1)
	await(t, "control dial started", func() bool { return upstream.count() == 1 })
	// Keep the view grant, but withdraw the control proof before the dial
	// returns. The queued key must reach nothing.
	edge.Hub.Revoke(grant.Revocation{Selector: grant.Selector{TenantID: tenant, ViewerID: viewerID}, IssuedAt: now, Code: 4403})
	close(gate)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("revocation did not close session")
	}
	if len(route.messages()) != 0 {
		t.Fatalf("revoked control wrote: %v", route.messages())
	}
}

func TestControlFailureKeepsViewingAndNeverRetriesSentInput(t *testing.T) {
	edge, _, viewer, viewRoute, finished := open(t, nil)
	defer func() { viewer.Close(0, ""); <-finished }()
	route := newFakeRoute()
	upstream := &fakeControlUpstream{route: route}
	edge.Controls = upstream
	attachControl(t, viewer, nil)
	await(t, "control ready", func() bool { return controlRecord(viewer, "ready") })
	inputControl(viewer, 1)
	await(t, "input sent", func() bool { return len(route.messages()) == 1 })
	route.end <- io.EOF
	await(t, "control ended", func() bool { return controlRecord(viewer, "closed") })
	viewRoute.out <- inbound{true, []byte(`{"type":"url","url":"https://example.test","title":"still viewing"}`)}
	await(t, "view remains attached", func() bool { return len(viewer.delivered()) >= 3 })
	if upstream.count() != 1 || len(route.messages()) != 1 {
		t.Fatal("unknown input retried")
	}
}
