// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const browserFixtureController = "aaaabbbb-cccc-4ddd-8eee-ffff00001111"

// The stand-in's scripted misbehaviour, keyed by input sequence.
const (
	browserFixtureUnknownSequence = 2 // answers browser_control_outcome_unknown
	browserFixtureHangUpSequence  = 7 // hangs up without answering
	browserFixtureRefuseSequence  = 9 // stops accepting connections, then hangs up
	// answers with the driver's timing account; the second one out of range
	browserFixtureTimedSequence     = 901
	browserFixtureUnboundedSequence = 902
	// closes the view's stream listener, then applies the input
	browserFixtureEndViewSequence = 1000
)

// browserFixtureConnections counts the command-carrying connections the
// stand-in has finished with, in a file beside its socket, so a test can tell
// a kept link from a redial without the wire carrying anything for it. The
// count is written only after the connection is closed.
type browserFixtureConnections struct {
	mu   sync.Mutex
	done int
	path string
}

func (c *browserFixtureConnections) finished() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.done++
	_ = os.WriteFile(c.path, []byte(strconv.Itoa(c.done)), 0600)
}

// Transport stand-in only. The real Rust driver tests own input semantics;
// this fixture proves our relays reach the exact observed Unix peer and
// project its public reply without forwarding private data. Like the real
// driver it answers one line per command line, in order, and leaves commands
// that arrive meanwhile queued on the connection. Persistent, it keeps
// answering on the connection; otherwise it hangs up after one command, like a
// driver that closed the connection under the relay.
type browserControlFixture struct {
	persistent    bool
	finished      *browserFixtureConnections
	stopAccepting func() error
	// endView closes the view's stream listener while the process lives on.
	endView func() error
	// replyDelay holds each reply; overlaps then counts, in a file, the
	// replies sent while a later command was already waiting.
	replyDelay time.Duration
	overlaps   string
}

func (f browserControlFixture) serve(connection net.Conn) {
	carried := false
	defer func() {
		_ = connection.Close()
		if carried {
			f.finished.finished()
		}
	}()
	reader := bufio.NewReader(connection)
	overlapped := 0
	for {
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return // ordinary view discovery only reads the peer credential
		}
		carried = true
		reply := browserControlFixtureReply(line, f.stopAccepting, f.endView)
		if f.replyDelay > 0 {
			time.Sleep(f.replyDelay)
			if reader.Buffered() > 0 {
				overlapped++
				_ = os.WriteFile(f.overlaps, []byte(strconv.Itoa(overlapped)), 0600)
			}
		}
		if reply == nil || json.NewEncoder(connection).Encode(reply) != nil || !f.persistent {
			return
		}
	}
}

// browserControlFixtureReply answers one command line; nil hangs up.
func browserControlFixtureReply(line []byte, stop, endView func() error) map[string]any {
	if len(line) > browserControlLimit {
		return map[string]any{"success": false, "code": "browser_control_invalid"}
	}
	var command struct {
		Action string `json:"action"`
		browserControlRequest
	}
	if json.Unmarshal(line, &command) != nil || command.Action != "ambit_browser_control" {
		return nil
	}
	if command.Op == "inspect" {
		return map[string]any{"success": true, "data": map[string]any{"supported": true, "controlled": false, "secret": browserFixtureSecret}}
	}
	if command.ControllerID != browserFixtureController {
		return map[string]any{"success": false, "code": "browser_control_stale", "error": browserFixtureSecret}
	}
	status := "controlled"
	if command.Op == "release" {
		status = "released"
	}
	var timing map[string]any
	if command.Op == "input" {
		switch command.Sequence {
		case browserFixtureUnknownSequence:
			return map[string]any{"success": false, "code": "browser_control_outcome_unknown", "error": browserFixtureSecret}
		case browserFixtureHangUpSequence:
			return nil
		case browserFixtureRefuseSequence:
			_ = stop()
			return nil
		case browserFixtureTimedSequence:
			timing = map[string]any{"queueUs": 12, "injectUs": 3}
		case browserFixtureUnboundedSequence:
			timing = map[string]any{"queueUs": uint64(1) << 53, "injectUs": 3}
		case browserFixtureEndViewSequence:
			_ = endView()
		}
		status = "applied"
	}
	data := map[string]any{"controllerId": command.ControllerID, "expiresAt": command.ExpiresAt, "lastSequence": command.Sequence, "status": status, "secret": browserFixtureSecret}
	if timing != nil {
		data["timing"] = timing
	}
	return map[string]any{"success": true, "data": data}
}

func TestBrowserControlRelayUsesTheObservedSessionAndProjectsReplies(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "control")
	id, _ := workspace.only(t, "browser-owner", "primary")
	target := "/process/session/browser-owner/browser-views/" + id + "/control"
	request := func(body any, expected int) map[string]any {
		t.Helper()
		status, raw := call(t, workspace.engine, http.MethodPost, target, body)
		if status != expected || strings.Contains(string(raw), browserFixtureSecret) {
			t.Fatalf("control response %d %s", status, raw)
		}
		var parsed map[string]any
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	inspection := request(map[string]any{"op": "inspect"}, http.StatusOK)
	if inspection["supported"] != true || inspection["controlled"] != false || len(inspection) != 2 {
		t.Fatalf("inspection disclosed unrelated data: %v", inspection)
	}
	acquired := request(map[string]any{"op": "acquire", "controllerId": browserFixtureController, "expiresAt": time.Now().Add(20 * time.Second).UnixMilli()}, http.StatusOK)
	if acquired["controllerId"] != browserFixtureController || acquired["status"] != "controlled" || len(acquired) != 4 {
		t.Fatalf("control acknowledgement is invalid: %v", acquired)
	}
	events := []map[string]any{{"type": "input_mouse", "eventType": "mouseMoved", "x": 12, "y": 34}}
	if reply := request(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": 1, "events": events}, http.StatusOK); reply["status"] != "applied" || reply["lastSequence"] != float64(1) {
		t.Fatalf("input acknowledgement is invalid: %v", reply)
	}
	if reply := request(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": 2, "events": events}, http.StatusConflict); reply["code"] != "browser_control_outcome_unknown" || len(reply) != 1 {
		t.Fatalf("uncertain input was obscured: %v", reply)
	}
	if reply := request(map[string]any{"op": "release", "controllerId": "aaaabbbb-cccc-4ddd-8eee-ffff00002222"}, http.StatusConflict); reply["code"] != "browser_control_stale" {
		t.Fatalf("stale control was not refused: %v", reply)
	}
	workspace.open(t, "other-owner")
	if status, _ := call(t, workspace.engine, http.MethodPost, "/process/session/other-owner/browser-views/"+id+"/control", map[string]any{"op": "inspect"}); status != http.StatusNotFound {
		t.Fatalf("cross-session browser control returned %d", status)
	}
}

func TestBrowserControlRejectsMalformedInputBeforeDiscovery(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	for _, body := range []map[string]any{
		{"op": "cdp", "method": "Runtime.evaluate"},
		{"op": "inspect", "controllerId": browserFixtureController},
		{"op": "acquire", "controllerId": browserFixtureController},
		{"op": "input", "controllerId": browserFixtureController, "sequence": 0, "events": []any{}},
		{"op": "release", "controllerId": "../another"},
		{"op": "release", "controllerId": browserFixtureController, "extra": "ignored?"},
		{"op": "inspect", "extra": strings.Repeat("a", browserControlLimit)},
	} {
		if status, _ := call(t, workspace.engine, http.MethodPost, "/process/session/absent/browser-views/absent/control", body); status != http.StatusBadRequest {
			t.Fatalf("malformed control request reached discovery: %d", status)
		}
	}
}

func TestBrowserNamespaceControl(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	for _, owner := range []string{"legacy", "first", "second"} {
		workspace.open(t, owner)
		directory := workspace.socketDir
		if owner != "legacy" {
			directory = filepath.Join(directory, "namespaces", owner, "run")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
		}
		workspace.runDriverAt(t, owner, "primary", "control", directory)
	}
	if err := os.MkdirAll(filepath.Join(workspace.socketDir, "namespaces", "partial"), 0700); err != nil {
		t.Fatal(err)
	}
	views, _ := workspace.views(t)
	if len(views) != 3 {
		t.Fatalf("namespaced and legacy views should coexist: %v", views)
	}
	ids := map[string]bool{}
	for _, view := range views {
		owner := view["sessionId"].(string)
		id := view["id"].(string)
		if ids[id] {
			t.Fatal("separate namespace peers shared a view identity")
		}
		ids[id] = true
		if owner == "legacy" {
			if _, present := view["namespace"]; present {
				t.Fatal("legacy view gained a namespace")
			}
		} else if view["namespace"] != owner {
			t.Fatalf("wrong observed namespace: %v", view)
		}
		if status, body := call(t, workspace.engine, http.MethodPost, "/process/session/"+owner+"/browser-views/"+id+"/control", map[string]any{"op": "inspect"}); status != http.StatusOK {
			t.Fatalf("namespace control did not reach its exact peer: %d %s", status, body)
		}
		if owner != "legacy" {
			if status, _ := call(t, workspace.engine, http.MethodPost, "/process/session/legacy/browser-views/"+id+"/control", map[string]any{"op": "inspect"}); status != http.StatusNotFound {
				t.Fatalf("legacy session controlled another namespace: %d", status)
			}
		}
	}
}

func TestBrowserControlPreservesBoundedMarkupBytes(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "control")
	id, _ := workspace.only(t, "browser-owner", "primary")
	events := make([]map[string]any, 10)
	for index := range events {
		events[index] = map[string]any{"type": "input_keyboard", "eventType": "insertText", "text": strings.Repeat("<>&\u2028", 500)}
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(map[string]any{"op": "input", "controllerId": browserFixtureController, "sequence": 1, "events": events}); err != nil {
		t.Fatal(err)
	}
	if body.Len() >= browserControlLimit {
		t.Fatal("the fixture itself exceeds the input contract")
	}
	request := httptest.NewRequest(http.MethodPost, "/process/session/browser-owner/browser-views/"+id+"/control", &body)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	workspace.engine.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("bounded pasted markup grew past the native wire limit: %d %s", response.Code, response.Body.String())
	}
}
