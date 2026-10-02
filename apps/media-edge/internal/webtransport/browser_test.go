// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/view"
)

// This optional gate exercises a fresh real Chrome and the exact built
// frontend worker. Unit/race tests never stand in for browser interoperability.
func TestBuiltWorkerAgainstRealChrome(t *testing.T) {
	script := os.Getenv("MEDIA_EDGE_BROWSER_INTEROP_SCRIPT")
	worker := os.Getenv("MEDIA_EDGE_BROWSER_INTEROP_WORKER")
	if script == "" || worker == "" {
		t.Skip("MEDIA_EDGE_BROWSER_INTEROP_SCRIPT and MEDIA_EDGE_BROWSER_INTEROP_WORKER required")
	}
	payload := bytes.Repeat([]byte{37}, 1<<20)
	coded := 1024
	proof := "transport"
	if path := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_KEY_FILE"); path != "" {
		var err error
		payload, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		coded, proof = 4096, "native"
	}
	header, _ := json.Marshal(map[string]any{"type": "media", "track": "video", "codec": "av1-444",
		"streamId": "11111111-1111-4111-8111-111111111111", "seq": 1, "ts": 1, "key": true, "codecString": "av01.1.16M.08",
		"coded": map[string]int{"width": coded, "height": coded}, "visible": map[string]int{"x": 0, "y": 0, "width": coded, "height": coded},
		"surface": map[string]any{"kind": "browser-window", "coordinateSpace": "display-pixels", "generation": "22222222-2222-4222-8222-222222222222",
			"width": coded, "height": coded, "originX": 0, "originY": 0, "deviceScaleFactor": 2, "cursorIncluded": false},
		"quality": "motion", "byteLength": len(payload)})
	s, control, ctx, url, spki := pairThrough(t, nil, 60*time.Second, func(c *carrier) {
		for _, d := range []*view.Delivery{
			{Kind: view.Record, Text: []byte(`{"type":"status"}`)},
			{Kind: view.Video, Header: header, Payload: payload},
			{Kind: view.Record, Text: []byte(`{"type":"cursor"}`)},
			{Kind: view.Audio, Header: []byte(`{"track":"audio"}`), Payload: []byte{1, 2, 3}},
		} {
			if err := c.Send(d); err != nil {
				t.Error(err)
				return
			}
		}
		_, message, err := c.Receive()
		if err != nil {
			return
		}
		var value any
		if err := json.Unmarshal(message, &value); err != nil {
			t.Error(err)
			return
		}
		encoded, _ := json.Marshal(map[string]any{"type": "received", "message": value})
		if err := c.Send(&view.Delivery{Kind: view.Record, Text: encoded}); err != nil {
			t.Error(err)
		}
	})
	// Drain the fixture's Go handshake client; the second client below is the
	// browser, with its own session and independent unit/control counters.
	_ = record(t, control)
	_ = record(t, control)
	picture, err := s.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, picture)
	_, _ = s.ReceiveDatagram(ctx)
	commandCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hash := sha256.Sum256(payload)
	output, err := exec.CommandContext(commandCtx, "node", script, worker, url, spki, proof, fmt.Sprintf("%x", hash)).CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("real browser interop: %v", err)
	}
}
