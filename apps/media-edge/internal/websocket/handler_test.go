// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package websocket_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/daytonaio/media-edge/internal/daytona"
	"github.com/daytonaio/media-edge/internal/grant"
	"github.com/daytonaio/media-edge/internal/session"
	edgews "github.com/daytonaio/media-edge/internal/websocket"
)

// The edge end to end over real sockets: a fake toolbox view route, the
// Daytona adapter, the session core, the WebSocket carrier, and a page.

const (
	tenant   = "85086ad0-dab6-4cab-a0dc-6d029be8be75"
	user     = "11111111-2222-4333-8444-555555555555"
	viewerID = "baaaaabb-cccc-4ddd-8eee-ffff00000301"
	native   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var signer = func() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("websocket test backend"))
	return ed25519.NewKeyFromSeed(seed[:])
}()

type staticKeys []ed25519.PublicKey

func (k staticKeys) PublicKeys() []ed25519.PublicKey { return k }

func token(edits map[string]any) string {
	now := time.Now().UnixMilli()
	members := map[string]any{"v": 1, "typ": "grant", "aud": "edge-a", "issuedAt": now - 1000, "expiresAt": now + 59000, "scope": "view",
		"tenantId": tenant, "userId": user, "threadId": "thread-1", "viewId": "bv1_view", "viewerId": viewerID,
		"sandboxId": "sandbox-1", "sessionId": "session:1", "nativeViewId": native}
	for name, value := range edits {
		members[name] = value
	}
	payload, _ := json.Marshal(members)
	segment := base64.RawURLEncoding.EncodeToString(payload)
	return segment + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, []byte(segment)))
}

// toolbox is the view route: it records each upgrade and runs a script.
type toolbox struct {
	server   *httptest.Server
	requests chan *http.Request
	refuse   int
	script   func(*websocket.Conn)
}

func newToolbox(t *testing.T, script func(*websocket.Conn)) *toolbox {
	tb := &toolbox{requests: make(chan *http.Request, 8), script: script}
	tb.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tb.requests <- r.Clone(r.Context())
		if tb.refuse != 0 {
			w.WriteHeader(tb.refuse)
			return
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		tb.script(conn)
	}))
	t.Cleanup(tb.server.Close)
	return tb
}

type edge struct {
	server *httptest.Server
	edge   *session.Edge
}

func newEdge(t *testing.T, tb *toolbox, keepalive time.Duration) *edge {
	upstream, err := daytona.New(tb.server.URL+"/toolbox", "secret-key", "org-1")
	if err != nil {
		t.Fatal(err)
	}
	e := &session.Edge{
		Verifier: grant.Verifier{Keys: staticKeys{signer.Public().(ed25519.PublicKey)}, Audience: "edge-a"},
		Hub:      session.NewHub(nil),
		Upstream: upstream,
		Origins:  []string{"https://ambit.sh"},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := edgews.NewHandler(e)
	handler.Keepalive = keepalive
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &edge{server: server, edge: e}
}

const declarations = "frames=binary&patches=1&frameWindow=8&width=320&height=240&cursor=viewer&visible=crop&audio=opus&video=av1-444,av1"

func (e *edge) address(grantToken, query string) string {
	return "ws" + strings.TrimPrefix(e.server.URL, "http") + edgews.Path + "?grant=" + grantToken + "&" + query
}

func (e *edge) dial(t *testing.T, grantToken, query string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(e.address(grantToken, query), http.Header{"Origin": {"https://ambit.sh"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func expectClose(t *testing.T, conn *websocket.Conn, code int, reason string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, _, err := conn.ReadMessage()
		if err == nil {
			continue
		}
		var closed *websocket.CloseError
		if !errors.As(err, &closed) || closed.Code != code || closed.Text != reason {
			t.Fatalf("closed with %v, want %d %s", err, code, reason)
		}
		return
	}
}

// Holding the route open until the test ends.
func hold(conn *websocket.Conn) {
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func TestTheEdgeDialsTheViewRouteAsTheBackendDoes(t *testing.T) {
	tb := newToolbox(t, hold)
	e := newEdge(t, tb, 0)
	e.dial(t, token(nil), declarations+"&tenantId="+tenant+"&viewerId="+viewerID+"&fallback=webtransport_failed")
	request := <-tb.requests
	if want := "/toolbox/sandbox-1/process/session/session%3A1/browser-views/" + native +
		"/channel?frameWindow=8&frames=binary&patches=1&width=320&height=240&cursor=viewer&visible=crop&audio=opus&video=av1-444%2Cav1"; request.RequestURI != want {
		t.Fatalf("dialed %s\nwant   %s", request.RequestURI, want)
	}
	for name, want := range map[string]string{
		"Authorization": "Bearer secret-key", "X-Daytona-Organization-Id": "org-1", "X-Ambit-Browser-Viewer": viewerID,
		"X-Daytona-Source": "ambit-media-edge", "Accept": "application/octet-stream", "Content-Type": "application/json",
	} {
		if got := request.Header.Get(name); got != want {
			t.Fatalf("%s: %q, want %q", name, got, want)
		}
	}
	if request.Header.Get("Sec-Websocket-Extensions") != "" {
		t.Fatal("the dial offers compression")
	}
}

func frame(seq int) []byte {
	header := []byte(`{"type":"frame","seq":` + itoa(seq) + `,"encoding":"jpeg","surface":{"kind":"browser-window","coordinateSpace":"display-pixels","generation":"11111111-1111-4111-8111-111111111111","width":16,"height":16,"originX":0,"originY":0,"deviceScaleFactor":2,"cursorIncluded":false},"byteLength":` + itoa(len(jpeg16)) + `}`)
	message := make([]byte, 4, 4+len(header)+len(jpeg16))
	binary.BigEndian.PutUint32(message, uint32(len(header)))
	return append(append(message, header...), jpeg16...)
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestTheStreamReachesThePageByteForByte(t *testing.T) {
	status := []byte(`{"type":"status","connected":true,"screencasting":true}`)
	cursor := []byte(`{"type":"cursor","ts":1234568,"serial":17,"css":"text"}`)
	received := make(chan []byte, 8)
	tb := newToolbox(t, func(conn *websocket.Conn) {
		_ = conn.WriteMessage(websocket.TextMessage, status)
		_ = conn.WriteMessage(websocket.BinaryMessage, frame(10))
		_ = conn.WriteMessage(websocket.TextMessage, cursor)
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				return
			}
			received <- message
		}
	})
	e := newEdge(t, tb, 0)
	page := e.dial(t, token(nil), declarations)
	for _, want := range []struct {
		kind    int
		message []byte
	}{{websocket.TextMessage, status}, {websocket.BinaryMessage, frame(10)}, {websocket.TextMessage, cursor}} {
		kind, message, err := page.ReadMessage()
		if err != nil || kind != want.kind || string(message) != string(want.message) {
			t.Fatalf("got %d %.80q %v, want %d %.80q", kind, message, err, want.kind, want.message)
		}
	}
	for sent, want := range map[string]string{
		`{"type":"ack","seq":10}`:                          `{"type":"ack","seq":10}`,
		`{"height":300,"width":400,"type":"presentation"}`: `{"type":"presentation","width":400,"height":300}`,
	} {
		if err := page.WriteMessage(websocket.TextMessage, []byte(sent)); err != nil {
			t.Fatal(err)
		}
		select {
		case message := <-received:
			if string(message) != want {
				t.Fatalf("the route got %s, want %s", message, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the route got nothing")
		}
	}
}

func TestTheViewRoutesEndReachesThePage(t *testing.T) {
	for _, test := range []struct {
		name   string
		end    func(*websocket.Conn)
		code   int
		reason string
	}{
		{"an ended view", func(c *websocket.Conn) {
			_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(4410, "browser_view_ended"), time.Now().Add(time.Second))
			hold(c)
		}, 4410, "browser_view_ended"},
		{"a failed screencast", func(c *websocket.Conn) {
			_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(1011, "screencast_failed"), time.Now().Add(time.Second))
			hold(c)
		}, 1011, "screencast_failed"},
		{"a dropped connection", func(c *websocket.Conn) { _ = c.NetConn().Close() }, 1011, "browser_view_ended"},
		{"an oversized message", func(c *websocket.Conn) {
			_ = c.WriteMessage(websocket.BinaryMessage, make([]byte, 12<<20+1))
			hold(c)
		}, 1011, "browser_view_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := newEdge(t, newToolbox(t, test.end), 0)
			expectClose(t, e.dial(t, token(nil), declarations), test.code, test.reason)
		})
	}
}

func TestADialFailureAsksThePageToTryAgain(t *testing.T) {
	tb := newToolbox(t, hold)
	tb.refuse = http.StatusNotFound
	e := newEdge(t, tb, 0)
	expectClose(t, e.dial(t, token(nil), declarations), 1013, "browser_view_unavailable")
	if e.edge.Hub.Len() != 0 {
		t.Fatal("a session that never opened stays registered")
	}
}

func TestRefusalsComeBeforeAnySocket(t *testing.T) {
	e := newEdge(t, newToolbox(t, hold), 0)
	e.edge.Hub.Revoke(grant.Revocation{Selector: grant.Selector{TenantID: tenant, ViewID: "bv1_revoked"}, IssuedAt: time.Now().UnixMilli(), Code: 4403})
	for name, test := range map[string]struct {
		address string
		origin  string
		status  int
	}{
		"no grant":             {e.address("", declarations), "https://ambit.sh", http.StatusUnauthorized},
		"another edge's grant": {e.address(token(map[string]any{"aud": "edge-b"}), declarations), "https://ambit.sh", http.StatusUnauthorized},
		"a revoked grant":      {e.address(token(map[string]any{"viewId": "bv1_revoked"}), declarations), "https://ambit.sh", http.StatusForbidden},
		"a foreign origin":     {e.address(token(nil), declarations), "https://evil.example", http.StatusForbidden},
		"a bad declaration":    {e.address(token(nil), "frames=binary&patches=1&width=320"), "https://ambit.sh", http.StatusBadRequest},
		"another path":         {strings.Replace(e.address(token(nil), declarations), edgews.Path, "/v1/other", 1), "https://ambit.sh", http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			_, response, err := websocket.DefaultDialer.Dial(test.address, http.Header{"Origin": {test.origin}})
			if err == nil || response == nil || response.StatusCode != test.status {
				t.Fatalf("response %v, error %v", response, err)
			}
		})
	}
	response, err := http.Get(e.server.URL + edgews.Path + "?grant=" + url.QueryEscape(token(nil)) + "&" + declarations)
	if err != nil || response.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("a plain GET: %v %v", response, err)
	}
	_ = response.Body.Close()
}

func TestRevocationAndShutdownCloseThePageWithTheirCodes(t *testing.T) {
	e := newEdge(t, newToolbox(t, hold), 0)
	revoked := e.dial(t, token(nil), declarations)
	restarted := e.dial(t, token(map[string]any{"viewerId": "baaaaabb-cccc-4ddd-8eee-ffff00000302"}), strings.Replace(declarations, "width=320&height=240&", "", 1))
	deadline := time.Now().Add(5 * time.Second)
	for e.edge.Hub.Len() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if closed := e.edge.Hub.Revoke(grant.Revocation{Selector: grant.Selector{TenantID: tenant, ViewerID: viewerID}, IssuedAt: time.Now().UnixMilli(), Code: 4403}); closed != 1 {
		t.Fatalf("closed %d", closed)
	}
	expectClose(t, revoked, 4403, "browser_view_forbidden")
	e.edge.Hub.Shutdown(1012, "browser_view_restarting")
	expectClose(t, restarted, 1012, "browser_view_restarting")
}

func TestViewerMessagesAreBounded(t *testing.T) {
	e := newEdge(t, newToolbox(t, hold), 0)
	page := e.dial(t, token(nil), declarations)
	_ = page.WriteMessage(websocket.TextMessage, []byte(`{"type":"presentation","width":400,"height":300,"pad":"`+strings.Repeat("x", 4096)+`"}`))
	expectClose(t, page, websocket.CloseMessageTooBig, "")
	page = e.dial(t, token(nil), declarations)
	_ = page.WriteMessage(websocket.TextMessage, []byte(`{"type":"cdp","method":"Runtime.evaluate"}`))
	expectClose(t, page, 1008, "browser_view_invalid_message")
}

func TestARenewedGrantKeepsThePageAndAnExpiredOneEndsIt(t *testing.T) {
	e := newEdge(t, newToolbox(t, hold), 0)
	now := time.Now().UnixMilli()
	page := e.dial(t, token(map[string]any{"expiresAt": now + 1500}), declarations)
	renewal, _ := json.Marshal(map[string]string{"type": "grant", "token": token(map[string]any{"expiresAt": now + 30000})})
	if err := page.WriteMessage(websocket.TextMessage, renewal); err != nil {
		t.Fatal(err)
	}
	// Well past the first grant's expiry, the page is still served.
	_ = page.SetReadDeadline(time.UnixMilli(now + 2500))
	var timeout net.Error
	if _, _, err := page.ReadMessage(); !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("the page closed before its renewed grant expired: %v", err)
	}
	page = e.dial(t, token(map[string]any{"expiresAt": time.Now().UnixMilli() + 500}), declarations)
	expectClose(t, page, 1013, "browser_view_grant_expired")
}

func TestSilentPagesAreDroppedAndAnsweringPagesKept(t *testing.T) {
	e := newEdge(t, newToolbox(t, hold), 200*time.Millisecond)
	answering := e.dial(t, token(nil), declarations)
	read := make(chan error, 1)
	go func() { _, _, err := answering.ReadMessage(); read <- err }()
	silent := e.dial(t, token(map[string]any{"viewerId": "baaaaabb-cccc-4ddd-8eee-ffff00000302"}), declarations)
	silent.SetPingHandler(func(string) error { return nil })
	_ = silent.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := silent.ReadMessage()
	var closed *websocket.CloseError
	if !errors.As(err, &closed) || closed.Code != websocket.CloseAbnormalClosure {
		t.Fatalf("a silent page: %v", err)
	}
	select {
	case err := <-read:
		t.Fatalf("an answering page was dropped: %v", err)
	case <-time.After(time.Second):
	}
}
