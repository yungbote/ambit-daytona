// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

const browserFixtureController = "aaaabbbb-cccc-4ddd-8eee-ffff00001111"

// Transport stand-in only. The real Rust driver tests own input semantics;
// this fixture proves our HTTP relay reaches the exact observed Unix peer and
// projects its public reply without forwarding private data.
func serveBrowserControlFixture(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		return // ordinary view discovery only reads the peer credential
	}
	var command struct {
		Action string `json:"action"`
		browserControlRequest
	}
	if json.Unmarshal(line, &command) != nil || command.Action != "ambit_browser_control" {
		return
	}
	if command.Op == "inspect" {
		_ = json.NewEncoder(connection).Encode(map[string]any{"success": true, "data": map[string]any{"supported": true, "controlled": false, "secret": browserFixtureSecret}})
		return
	}
	if command.ControllerID != browserFixtureController {
		_ = json.NewEncoder(connection).Encode(map[string]any{"success": false, "code": "browser_control_stale", "error": browserFixtureSecret})
		return
	}
	status := "controlled"
	if command.Op == "release" {
		status = "released"
	}
	if command.Op == "input" {
		if command.Sequence == 2 {
			_ = json.NewEncoder(connection).Encode(map[string]any{"success": false, "code": "browser_control_outcome_unknown", "error": browserFixtureSecret})
			return
		}
		status = "applied"
	}
	_ = json.NewEncoder(connection).Encode(map[string]any{"success": true, "data": map[string]any{"controllerId": command.ControllerID, "expiresAt": command.ExpiresAt, "lastSequence": command.Sequence, "status": status, "secret": browserFixtureSecret}})
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
