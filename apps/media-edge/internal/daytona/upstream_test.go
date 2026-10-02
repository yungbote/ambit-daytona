// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package daytona

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/daytonaio/media-edge/internal/session"
	"github.com/daytonaio/media-edge/internal/view"
)

func TestTheProxyURLIsAnHTTPURLWithAPathAndNothingElse(t *testing.T) {
	declaration, err := view.ParseDeclaration(url.Values{"frames": {"binary"}, "patches": {"1"}})
	if err != nil {
		t.Fatal(err)
	}
	target := session.Target{SandboxID: "sandbox-1", SessionID: "session:1", ViewID: "view-1"}
	route := "sandbox-1/process/session/session%3A1/browser-views/view-1/channel?" + declaration.Query()
	for proxy, want := range map[string]string{
		"http://daytona-proxy.daytona-system.svc.cluster.local:4000/toolbox": "ws://daytona-proxy.daytona-system.svc.cluster.local:4000/toolbox/",
		"https://proxy.example/toolbox/":                                     "wss://proxy.example/toolbox/",
		"http://proxy:4000":                                                  "ws://proxy:4000/",
	} {
		upstream, err := New(proxy, "key", "")
		if err != nil {
			t.Fatalf("%s: %v", proxy, err)
		}
		if got := upstream.Address(target, declaration); got != want+route {
			t.Errorf("%s dials %s, want %s", proxy, got, want+route)
		}
	}
	for _, proxy := range []string{
		"", "proxy:4000/toolbox", "ftp://proxy/toolbox", "ws://proxy/toolbox", "http:///toolbox", "http://proxy:port/toolbox",
		"http://user:secret@proxy/toolbox", "http://proxy/toolbox?region=eu", "http://proxy/toolbox#top",
		"http://proxy//toolbox", "http://proxy/toolbox//",
	} {
		if _, err := New(proxy, "key", ""); err == nil {
			t.Errorf("%q was taken", proxy)
		}
	}
	if _, err := New("http://proxy/toolbox", "", ""); err == nil {
		t.Error("an empty credential was taken")
	}
}

// A usual unit is read into the buffer the previous one used; a large one is
// read, and its buffer let go at the next Read.
func TestARouteKeepsAUsualReadBufferAndLetsALargeOneGo(t *testing.T) {
	sizes := []int{200 << 10, 200 << 10, 3 << 20, 200 << 10, 200 << 10}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for index, size := range sizes {
			if conn.WriteMessage(websocket.BinaryMessage, bytes.Repeat([]byte{byte(index + 1)}, size)) != nil {
				return
			}
		}
		_, _, _ = conn.ReadMessage()
	}))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &route{conn: conn}
	defer r.Close()
	var previous []byte
	for index, size := range sizes {
		text, message, err := r.Read()
		if err != nil || text || !bytes.Equal(message, bytes.Repeat([]byte{byte(index + 1)}, size)) {
			t.Fatalf("message %d: %v, text %v, %d bytes", index, err, text, len(message))
		}
		reused := previous != nil && &message[0] == &previous[0]
		if usualAfterUsual := index > 0 && size <= retainedReadBytes && len(previous) <= retainedReadBytes; reused != usualAfterUsual {
			t.Fatalf("message %d of %d bytes after %d: buffer reused %v", index, size, len(previous), reused)
		}
		if size <= retainedReadBytes && r.buffer.Cap() > retainedReadBytes {
			t.Fatalf("message %d of %d bytes is held in a buffer of %d", index, size, r.buffer.Cap())
		}
		previous = message
	}
}
