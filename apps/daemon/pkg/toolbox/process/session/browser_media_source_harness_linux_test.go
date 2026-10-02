// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Reuses one separately owned native source. The task bridge is the process
// discovered by T1; this proves actual route forwarding, not sandbox custody
// or native source discovery. No browser or native driver is launched here.
func TestExistingMediaSourceThroughActualT1Harness(t *testing.T) {
	source, output := os.Getenv("AMBIT_TEST_EXISTING_MEDIA_SOURCE"), os.Getenv("AMBIT_TEST_EXISTING_MEDIA_OUTPUT")
	if source == "" || output == "" {
		t.Skip("existing local source and unique harness output required")
	}
	address, err := url.Parse(source)
	if err != nil || address.Scheme != "ws" || address.Hostname() != "127.0.0.1" || address.User != nil || address.RawQuery != "" {
		t.Fatal("source must be an existing bare loopback WebSocket endpoint")
	}
	w := newBrowserWorkspace(t)
	w.open(t, "media-source")
	if err := os.WriteFile(filepath.Join(w.socketDir, "primary.source"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	w.runDriver(t, "media-source", "primary", "view-channel-source")
	id, _ := w.only(t, "media-source", "primary")
	server := httptest.NewServer(w.engine)
	defer server.Close()
	metadata, _ := json.MarshalIndent(map[string]any{"baseUrl": server.URL, "sessionId": "media-source", "viewId": id,
		"source": source, "pid": os.Getpid(), "ownership": "task bridge; existing native source externally owned"}, "", "  ")
	if err := os.WriteFile(output, metadata, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual T1 existing-media harness ready: %s", output)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	select {
	case <-ctx.Done():
	case <-time.After(20 * time.Minute):
	}
}

func serveBrowserExistingMediaSource(w http.ResponseWriter, r *http.Request, dir, name string) {
	data, err := os.ReadFile(filepath.Join(dir, name+".source"))
	if err != nil {
		http.Error(w, "missing task media source", http.StatusBadGateway)
		return
	}
	address, err := url.Parse(string(data))
	if err != nil || address.Scheme != "ws" || address.Hostname() != "127.0.0.1" {
		http.Error(w, "invalid task media source", http.StatusBadGateway)
		return
	}
	address.Scheme = "http"
	httputil.NewSingleHostReverseProxy(address).ServeHTTP(w, r)
}
