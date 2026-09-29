// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"bytes"
	"context"
	"encoding/json"
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
	s, control, ctx, url, spki := pair(t, func(c *carrier) {
		for _, d := range []*view.Delivery{
			{Kind: view.Record, Text: []byte(`{"type":"status"}`)},
			{Kind: view.Video, Header: []byte(`{"track":"video"}`), Payload: bytes.Repeat([]byte{37}, 1<<20)},
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
	output, err := exec.CommandContext(commandCtx, "node", script, worker, url, spki).CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("real browser interop: %v", err)
	}
}
