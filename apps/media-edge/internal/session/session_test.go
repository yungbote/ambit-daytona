// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/grant"
	"github.com/daytonaio/media-edge/internal/view"
)

// --- fakes ---------------------------------------------------------------

type inbound struct {
	text    bool
	message []byte
}

// fakeCarrier is a viewer: tests push its messages and read what it got.
type fakeCarrier struct {
	in     chan inbound
	mu     sync.Mutex
	got    []*view.Delivery
	closed chan [2]any
	once   sync.Once
	gone   chan struct{}
}

func newFakeCarrier() *fakeCarrier {
	return &fakeCarrier{in: make(chan inbound, 64), closed: make(chan [2]any, 1), gone: make(chan struct{})}
}

func (c *fakeCarrier) Receive() (bool, []byte, error) {
	select {
	case m := <-c.in:
		return m.text, m.message, nil
	case <-c.gone:
		return false, nil, io.EOF
	}
}

func (c *fakeCarrier) Send(d *view.Delivery) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, d)
	return nil
}

func (c *fakeCarrier) Close(code int, reason string) {
	c.once.Do(func() {
		c.closed <- [2]any{code, reason}
		close(c.gone)
	})
}

func (c *fakeCarrier) send(message string) { c.in <- inbound{true, []byte(message)} }

func (c *fakeCarrier) awaitClose(t *testing.T) (int, string) {
	t.Helper()
	select {
	case closed := <-c.closed:
		return closed[0].(int), closed[1].(string)
	case <-time.After(3 * time.Second):
		t.Fatal("the viewer was not closed")
		return 0, ""
	}
}

func (c *fakeCarrier) delivered() []*view.Delivery {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*view.Delivery(nil), c.got...)
}

// fakeRoute is the view route: tests feed it and read what it was sent.
type fakeRoute struct {
	out     chan inbound
	end     chan error
	mu      sync.Mutex
	written []string
	gate    chan struct{} // when set, each Write waits for a token
	wrote   chan struct{}
	once    sync.Once
	closed  chan struct{}
}

func newFakeRoute() *fakeRoute {
	return &fakeRoute{out: make(chan inbound, 64), end: make(chan error, 1), wrote: make(chan struct{}, 64), closed: make(chan struct{})}
}

func (r *fakeRoute) Read() (bool, []byte, error) {
	select {
	case m := <-r.out:
		return m.text, m.message, nil
	case err := <-r.end:
		return false, nil, err
	case <-r.closed:
		return false, nil, io.EOF
	}
}

func (r *fakeRoute) Write(message []byte) error {
	if r.gate != nil {
		select {
		case <-r.gate:
		case <-r.closed:
			return io.EOF
		}
	}
	r.mu.Lock()
	r.written = append(r.written, string(message))
	r.mu.Unlock()
	r.wrote <- struct{}{}
	return nil
}

func (r *fakeRoute) Close() { r.once.Do(func() { close(r.closed) }) }

func (r *fakeRoute) messages() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.written...)
}

type fakeUpstream struct {
	route  *fakeRoute
	err    error
	target Target
	viewer string
}

func (u *fakeUpstream) DialView(_ context.Context, target Target, viewerID string, _ view.Declaration) (Conn, error) {
	u.target, u.viewer = target, viewerID
	if u.err != nil {
		return nil, u.err
	}
	return u.route, nil
}

// --- grants --------------------------------------------------------------

type staticKeys []ed25519.PublicKey

func (k staticKeys) PublicKeys() []ed25519.PublicKey { return k }

var signer = func() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("session test backend"))
	return ed25519.NewKeyFromSeed(seed[:])
}()

const (
	tenant   = "85086ad0-dab6-4cab-a0dc-6d029be8be75"
	user     = "11111111-2222-4333-8444-555555555555"
	viewerID = "baaaaabb-cccc-4ddd-8eee-ffff00000301"
	native   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func token(t *testing.T, edits map[string]any) string {
	t.Helper()
	now := time.Now().UnixMilli()
	members := map[string]any{"v": 1, "typ": "grant", "aud": "edge-a", "issuedAt": now - 1000, "expiresAt": now + 59000, "scope": "view",
		"tenantId": tenant, "userId": user, "threadId": "thread-1", "viewId": "bv1_view", "viewerId": viewerID,
		"sandboxId": "sandbox-1", "sessionId": "session:1", "nativeViewId": native}
	for name, value := range edits {
		if value == nil {
			delete(members, name)
		} else {
			members[name] = value
		}
	}
	payload, _ := json.Marshal(members)
	segment := base64.RawURLEncoding.EncodeToString(payload)
	return segment + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, []byte(segment)))
}

func testEdge(upstream Upstream) *Edge {
	return &Edge{
		Verifier: grant.Verifier{Keys: staticKeys{signer.Public().(ed25519.PublicKey)}, Audience: "edge-a"},
		Hub:      NewHub(nil),
		Upstream: upstream,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func admit(t *testing.T, edge *Edge, query string) Admission {
	t.Helper()
	values, _ := url.ParseQuery(query)
	admission, refusal := edge.Admit(values, "")
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	return admission
}

// open runs a session for a presenting viewer and returns its fakes.
func open(t *testing.T, grantEdits map[string]any) (*Edge, *Session, *fakeCarrier, *fakeRoute, chan struct{}) {
	t.Helper()
	route := newFakeRoute()
	edge := testEdge(&fakeUpstream{route: route})
	admission := admit(t, edge, "grant="+token(t, grantEdits)+"&frames=binary&patches=1&frameWindow=8&width=320&height=240")
	s, err := edge.Open(context.Background(), admission, "fake")
	if err != nil {
		t.Fatal(err)
	}
	viewer := newFakeCarrier()
	finished := make(chan struct{})
	go func() { s.Run(viewer); close(finished) }()
	t.Cleanup(func() { s.end(0, "", "test"); <-finished })
	return edge, s, viewer, route, finished
}

func awaitWrites(t *testing.T, route *fakeRoute, count int) []string {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for len(route.messages()) < count {
		select {
		case <-route.wrote:
		case <-deadline:
			t.Fatalf("the route got %v", route.messages())
		}
	}
	return route.messages()
}

// --- tests ---------------------------------------------------------------

func TestOpenDialsTheTargetTheGrantNames(t *testing.T) {
	upstream := &fakeUpstream{route: newFakeRoute()}
	edge := testEdge(upstream)
	if _, err := edge.Open(context.Background(), admit(t, edge, "grant="+token(t, nil)+"&frames=binary&patches=1"), "fake"); err != nil {
		t.Fatal(err)
	}
	if upstream.target != (Target{SandboxID: "sandbox-1", SessionID: "session:1", ViewID: native}) || upstream.viewer != viewerID {
		t.Fatalf("dialed %+v as %s", upstream.target, upstream.viewer)
	}
	if edge.Hub.Len() != 1 {
		t.Fatal("an open session is registered")
	}
	upstream = &fakeUpstream{err: errors.New("route answered 404")}
	edge = testEdge(upstream)
	if _, err := edge.Open(context.Background(), admit(t, edge, "grant="+token(t, nil)+"&frames=binary&patches=1"), "fake"); err == nil || edge.Hub.Len() != 0 {
		t.Fatal("a failed dial leaves nothing registered")
	}
}

func TestAdmissionRefusals(t *testing.T) {
	edge := testEdge(&fakeUpstream{route: newFakeRoute()})
	edge.Origins = []string{"https://ambit.sh"}
	good := "grant=" + token(t, nil) + "&frames=binary&patches=1"
	for name, test := range map[string]struct {
		query, origin string
		status        int
		reason        string
	}{
		"no grant":             {"frames=binary&patches=1", "", 401, "grant_missing"},
		"two grants":           {good + "&grant=x", "", 401, "grant_missing"},
		"a forged grant":       {"grant=" + token(t, nil)[:40] + "&frames=binary&patches=1", "", 401, "grant_malformed"},
		"another edge's grant": {"grant=" + token(t, map[string]any{"aud": "edge-b"}) + "&frames=binary&patches=1", "", 401, "grant_audience"},
		"an expired grant":     {"grant=" + token(t, map[string]any{"expiresAt": time.Now().UnixMilli() - 1}) + "&frames=binary&patches=1", "", 401, "grant_expired"},
		"a foreign origin":     {good, "https://evil.example", 403, "origin"},
		"no frames":            {"grant=" + token(t, nil) + "&patches=1", "", 400, "declaration"},
		"another tenant":       {good + "&tenantId=85086ad0-dab6-4cab-a0dc-6d029be8be76", "", 400, "tenantId"},
		"another viewer":       {good + "&viewerId=baaaaabb-cccc-4ddd-8eee-ffff00000302", "", 400, "viewerId"},
		"a malformed fallback": {good + "&fallback=Web Transport", "", 400, "fallback"},
	} {
		t.Run(name, func(t *testing.T) {
			values, _ := url.ParseQuery(test.query)
			if _, refusal := edge.Admit(values, test.origin); refusal == nil || refusal.Status != test.status || refusal.Reason != test.reason {
				t.Fatalf("got %+v", refusal)
			}
		})
	}
	values, _ := url.ParseQuery(good + "&tenantId=" + tenant + "&viewerId=" + viewerID + "&fallback=webtransport_failed")
	if admission, refusal := edge.Admit(values, "https://ambit.sh"); refusal != nil || admission.Fallback != "webtransport_failed" {
		t.Fatalf("a consistent upgrade was refused: %+v", refusal)
	}
}

func TestRelayCarriesTheRouteToTheViewerAndCoalescesTheViewer(t *testing.T) {
	_, _, viewer, route, _ := open(t, nil)
	route.gate = make(chan struct{})
	status := []byte(`{"type":"status","connected":true}`)
	route.out <- inbound{true, status}
	deadline := time.Now().Add(3 * time.Second)
	for len(viewer.delivered()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := viewer.delivered(); len(got) != 1 || !bytes.Equal(got[0].Text, status) {
		t.Fatalf("delivered %v", got)
	}
	// The first presentation leaves and its write blocks; everything after
	// it waits in its slot, and only the newest of each slot goes.
	viewer.send(`{"type":"presentation","width":100,"height":100}`)
	time.Sleep(20 * time.Millisecond)
	for size := 101; size <= 140; size++ {
		viewer.send(`{"type":"presentation","width":` + strings.Repeat("1", 0) + itoa(size) + `,"height":100}`)
	}
	time.Sleep(20 * time.Millisecond)
	close(route.gate)
	written := awaitWrites(t, route, 2)
	time.Sleep(20 * time.Millisecond)
	written = route.messages()
	if len(written) != 2 || written[0] != `{"type":"presentation","width":100,"height":100}` || written[1] != `{"type":"presentation","width":140,"height":100}` {
		t.Fatalf("the route got %v", written)
	}
}

func itoa(n int) string {
	return strings.TrimSpace(strings.Repeat(" ", 0) + func() string { b, _ := json.Marshal(n); return string(b) }())
}

func TestRevocationClosesWithItsCodeAndOutlivesTheSession(t *testing.T) {
	edge, _, viewer, _, finished := open(t, nil)
	now := time.Now().UnixMilli()
	// A revocation of another view or of older access touches nothing.
	if closed := edge.Hub.Revoke(grant.Revocation{Selector: grant.Selector{TenantID: tenant, ViewID: "bv1_other"}, IssuedAt: now, Code: 4403}); closed != 0 {
		t.Fatal("another view's revocation closed this session")
	}
	if closed := edge.Hub.Revoke(grant.Revocation{Selector: grant.Selector{TenantID: tenant}, IssuedAt: now - 5000, Code: 4403}); closed != 0 {
		t.Fatal("a revocation older than the grant closed the session")
	}
	if closed := edge.Hub.Revoke(grant.Revocation{Selector: grant.Selector{TenantID: tenant, UserID: user, ThreadID: "thread-1", ViewID: "bv1_view"}, IssuedAt: now, Code: 4410}); closed != 1 {
		t.Fatalf("closed %d", closed)
	}
	if code, reason := viewer.awaitClose(t); code != 4410 || reason != "browser_view_ended" {
		t.Fatalf("closed %d %s", code, reason)
	}
	<-finished
	if edge.Hub.Len() != 0 {
		t.Fatal("an ended session stays registered")
	}
	// The revoked grant cannot open another session; access proven after
	// the revocation can.
	values, _ := url.ParseQuery("grant=" + token(t, nil) + "&frames=binary&patches=1")
	if _, refusal := edge.Admit(values, ""); refusal == nil || refusal.Status != 403 {
		t.Fatalf("a revoked grant was admitted: %+v", refusal)
	}
	values, _ = url.ParseQuery("grant=" + token(t, map[string]any{"issuedAt": now + 1, "expiresAt": now + 30000}) + "&frames=binary&patches=1")
	if _, refusal := edge.Admit(values, ""); refusal != nil {
		t.Fatalf("access proven after the revocation was refused: %+v", refusal)
	}
}

func TestGrantsExpireUnlessRenewedAndRenewalsNeverNarrowTheSession(t *testing.T) {
	now := time.Now().UnixMilli()
	_, _, viewer, _, _ := open(t, map[string]any{"expiresAt": now + 300})
	// A renewal extends viewing past the first grant's expiry.
	viewer.send(`{"type":"grant","token":"` + token(t, map[string]any{"expiresAt": now + 900}) + `"}`)
	// An older, shorter grant arriving late changes nothing.
	viewer.send(`{"type":"grant","token":"` + token(t, map[string]any{"issuedAt": now - 5000, "expiresAt": now + 400}) + `"}`)
	select {
	case closed := <-viewer.closed:
		t.Fatalf("closed at the first grant's expiry: %v", closed)
	case <-time.After(600 * time.Millisecond):
	}
	if code, reason := viewer.awaitClose(t); code != 1013 || reason != "browser_view_grant_expired" {
		t.Fatalf("closed %d %s", code, reason)
	}
}

func TestRenewalsThatNameAnotherSessionEndIt(t *testing.T) {
	for name, message := range map[string]string{
		"another viewer": `{"type":"grant","token":"` + token(t, map[string]any{"viewerId": "baaaaabb-cccc-4ddd-8eee-ffff00000302"}) + `"}`,
		"a forged grant": `{"type":"grant","token":"` + token(t, nil)[:50] + `"}`,
		"another member": `{"type":"grant","token":"` + token(t, nil) + `","scope":"control"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, viewer, _, _ := open(t, nil)
			viewer.send(message)
			if code, reason := viewer.awaitClose(t); code != 1008 || reason != "browser_view_invalid_message" {
				t.Fatalf("closed %d %s", code, reason)
			}
		})
	}
	// An expired renewal adds nothing and ends nothing.
	_, s, viewer, _, _ := open(t, nil)
	viewer.send(`{"type":"grant","token":"` + token(t, map[string]any{"issuedAt": time.Now().UnixMilli() - 50000, "expiresAt": time.Now().UnixMilli() - 1}) + `"}`)
	deadline := time.Now().Add(time.Second)
	for s.counters.renewalsIgnored.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.counters.renewalsIgnored.Load() != 1 {
		t.Fatal("an expired renewal was not ignored")
	}
}

func TestTheViewRoutesEndMapsToWhatThePageUnderstands(t *testing.T) {
	for _, test := range []struct {
		end    error
		code   int
		reason string
	}{
		{&Closed{4410, "browser_view_ended"}, 4410, "browser_view_ended"},
		{&Closed{1000, ""}, 1000, "browser_view_ended"},
		{&Closed{1003, "browser_view_channel_unsupported"}, 1003, "browser_view_channel_unsupported"},
		{&Closed{1008, "browser_view_invalid_message"}, 1008, "browser_view_invalid_message"},
		{&Closed{1011, "screencast_failed"}, 1011, "screencast_failed"},
		{&Closed{4000, "Not A Reason"}, 1011, "browser_view_ended"},
		{&Closed{1006, ""}, 1011, "browser_view_ended"},
		{io.ErrUnexpectedEOF, 1011, "browser_view_unavailable"},
	} {
		_, _, viewer, route, _ := open(t, nil)
		route.end <- test.end
		if code, reason := viewer.awaitClose(t); code != test.code || reason != test.reason {
			t.Fatalf("%v: closed %d %s", test.end, code, reason)
		}
	}
}

func TestProtocolFaultsEndTheSessionAfterTheirTerminalRecord(t *testing.T) {
	_, _, viewer, route, _ := open(t, nil)
	route.out <- inbound{true, []byte(`{"type":"error","message":"secret"}`)}
	if code, reason := viewer.awaitClose(t); code != 1011 || reason != "screencast_failed" {
		t.Fatalf("closed %d %s", code, reason)
	}
	if got := viewer.delivered(); len(got) != 1 || string(got[0].Text) != `{"type":"unavailable","reason":"screencast_failed"}` {
		t.Fatalf("delivered %v", got)
	}
	_, _, viewer, _, _ = open(t, nil)
	viewer.send(`{"type":"ack","seq":1}`)
	if code, reason := viewer.awaitClose(t); code != 1008 || reason != "browser_view_invalid_message" {
		t.Fatalf("closed %d %s", code, reason)
	}
}

func TestShutdownAsksViewersToReconnect(t *testing.T) {
	edge, _, viewer, _, finished := open(t, nil)
	edge.Hub.Shutdown(1012, "browser_view_restarting")
	if code, reason := viewer.awaitClose(t); code != 1012 || reason != "browser_view_restarting" {
		t.Fatalf("closed %d %s", code, reason)
	}
	<-finished
}

func TestHistogramQuantiles(t *testing.T) {
	var h histogram
	for _, us := range []int{0, 1, 3, 4, 5, 7, 8, 9, 100, 1000, 1500} {
		h.observe(time.Duration(us) * time.Microsecond)
	}
	if h.quantile(0.5) < 7 || h.quantile(0.5) > 9 || h.quantile(1) != 1500 || h.max.Load() != 1500 {
		t.Fatalf("p50 %d p100 %d", h.quantile(0.5), h.quantile(1))
	}
	for us := uint64(4); us < 1<<20; us = us*5/4 + 1 {
		if bucket := bucketOf(us); upper(bucket) < us || (bucket > 8 && upper(bucket-1) >= us) {
			t.Fatalf("%d µs in bucket %d (upper %d)", us, bucket, upper(bucket))
		}
	}
}
