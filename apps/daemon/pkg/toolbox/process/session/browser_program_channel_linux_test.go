// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const programFixtureID = "10000000-0000-4000-8000-000000000001"
const programFixtureAction = "20000000-0000-4000-8000-000000000001"
const programFixturePath = "/0123456789abcdef0123456789abcdef"

var programFixtureOnce sync.Once
var programFixtureServer *httptest.Server

// Runs in the existing driver stand-in process, so the route must prove its
// real listener belongs to the same Unix peer, rather than a test stub.
func programFixtureStatus(line []byte) map[string]any {
	var request struct {
		ProgramID  string `json:"programId"`
		ActionID   string `json:"actionId"`
		Generation string `json:"ownerGeneration"`
	}
	if json.Unmarshal(line, &request) != nil || request.ProgramID != programFixtureID || request.ActionID != programFixtureAction || request.Generation != "41" {
		return map[string]any{"programId": request.ProgramID, "state": "closed", "nativeInputSettled": true, "reason": "disconnected"}
	}
	programFixtureOnce.Do(func() {
		programFixtureServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != programFixturePath {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			connection, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer connection.Close()
			for {
				kind, frame, err := connection.ReadMessage()
				if err != nil || connection.WriteMessage(kind, frame) != nil {
					return
				}
			}
		}))
	})
	return map[string]any{"programId": request.ProgramID, "state": "active", "nativeInputSettled": false, "endpoint": "ws" + strings.TrimPrefix(programFixtureServer.URL, "http") + programFixturePath, "remainingTimeoutMs": 120000}
}

func TestBrowserProgramEndpointRejectsCallerAddressShapes(t *testing.T) {
	valid := "ws://127.0.0.1:12345" + programFixturePath
	endpoint, port, ok := nativeProgramEndpoint(valid)
	if !ok || endpoint.String() != valid || port != 12345 {
		t.Fatal("native endpoint refused")
	}
	for _, invalid := range []string{
		"ws://localhost:12345" + programFixturePath,
		"ws://192.0.2.1:12345" + programFixturePath,
		"wss://127.0.0.1:12345" + programFixturePath,
		"ws://user@127.0.0.1:12345" + programFixturePath,
		valid + "?endpoint=ws://192.0.2.1:99",
		valid + "#fragment", strings.Replace(valid, "12345", "012345", 1),
		strings.Replace(valid, "12345", "0", 1), strings.Replace(valid, "12345", "65536", 1),
		"ws://127.0.0.1:12345/%30" + programFixturePath[2:],
	} {
		if _, _, ok := nativeProgramEndpoint(invalid); ok {
			t.Fatal("non-native endpoint admitted")
		}
	}
}

func TestBrowserProgramOwnerGenerationIsExact(t *testing.T) {
	for _, valid := range []string{"1", "41", "9223372036854775807"} {
		if !validProgramGeneration(valid) {
			t.Fatalf("generation %s refused", valid)
		}
	}
	for _, invalid := range []string{"", "0", "01", "-1", "+1", "1.0", "1e1", "9223372036854775808"} {
		if validProgramGeneration(invalid) {
			t.Fatal("invalid generation admitted")
		}
	}
}

func TestBrowserProgramRouteRelaysOnlyTheExactNativeLease(t *testing.T) {
	workspace, owner := openBrowserAgentChannelWithPing(t, "agent", browserAgentPingInterval)
	_ = owner.Close()
	view, _ := workspace.only(t, "browser-owner", "primary")
	server := workspace.serve(t)
	address := "ws" + strings.TrimPrefix(server.URL, "http") + "/process/session/browser-owner/browser-views/" + view + "/program/" + programFixtureID + "/channel"
	for _, query := range []string{
		"?actionId=" + programFixtureAction + "&ownerGeneration=41&endpoint=ws://127.0.0.1:99",
		"?actionId=" + programFixtureAction + "&actionId=" + programFixtureAction + "&ownerGeneration=41",
		"?actionId=" + programFixtureAction + "&ownerGeneration=0",
	} {
		connection, response, err := websocket.DefaultDialer.Dial(address+query, nil)
		if connection != nil {
			_ = connection.Close()
		}
		if err == nil || response == nil || response.StatusCode != http.StatusBadRequest {
			t.Fatal("invalid lease request did not fail before dialing")
		}
		_ = response.Body.Close()
	}
	connection, response, err := websocket.DefaultDialer.Dial(address+"?actionId="+programFixtureAction+"&ownerGeneration=42", nil)
	if connection != nil {
		_ = connection.Close()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusConflict {
		t.Fatal("foreign lease admitted")
	}
	_ = response.Body.Close()
	connection, response, err = websocket.DefaultDialer.Dial(address+"?actionId="+programFixtureAction+"&ownerGeneration=41", nil)
	if err != nil {
		t.Fatalf("native lease dial: %v %v", err, response)
	}
	defer connection.Close()
	for _, message := range []struct {
		kind  int
		bytes []byte
	}{
		{websocket.TextMessage, []byte(`{"id":1,"method":"Page.getLayoutMetrics"}`)},
		{websocket.TextMessage, bytes.Repeat([]byte("x"), 5<<20)},
		{websocket.BinaryMessage, []byte{0, 1, 2, 255}},
	} {
		if connection.WriteMessage(message.kind, message.bytes) != nil {
			t.Fatal("program relay write failed")
		}
		_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
		kind, frame, err := connection.ReadMessage()
		if err != nil || kind != message.kind || !bytes.Equal(frame, message.bytes) {
			t.Fatal("program relay changed bytes or lost ordinary screenshot-sized output")
		}
	}
}
