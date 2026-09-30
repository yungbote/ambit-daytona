// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package websocket_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/daytona"
	"github.com/daytonaio/media-edge/internal/grant"
	"github.com/daytonaio/media-edge/internal/session"
	edgews "github.com/daytonaio/media-edge/internal/websocket"
	edgewt "github.com/daytonaio/media-edge/internal/webtransport"
)

// Native source lifecycle is owned outside this test. T1's task bridge owns
// discovery/custody; real T1 and edge paths and production browser consumers
// run here, without claiming Product authentication or live sandbox custody.
func TestExistingNativeSourceThroughT1EdgeAndBrowser(t *testing.T) {
	metadata, script, worker := os.Getenv("MEDIA_EDGE_BROWSER_T1_SOURCE_FILE"), os.Getenv("MEDIA_EDGE_BROWSER_CHUNKS_SCRIPT"), os.Getenv("MEDIA_EDGE_BROWSER_INTEROP_WORKER")
	if metadata == "" || script == "" || worker == "" {
		t.Skip("existing T1 harness metadata, production browser script and built worker required")
	}
	data, err := os.ReadFile(metadata)
	if err != nil {
		t.Fatal(err)
	}
	var source struct{ BaseURL, SessionID, ViewID string }
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	address, err := url.Parse(source.BaseURL)
	if err != nil || address.Hostname() != "127.0.0.1" {
		t.Fatal("T1 source fixture must be loopback")
	}
	proxy := httputil.NewSingleHostReverseProxy(address)
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/sandbox-1")
		r.URL.RawPath = ""
		proxy.ServeHTTP(w, r)
	}))
	defer proxyServer.Close()
	upstream, err := daytona.New(proxyServer.URL, "task-fixture.nosecret", "")
	if err != nil {
		t.Fatal(err)
	}
	e := &session.Edge{Verifier: grant.Verifier{Keys: staticKeys{signer.Public().(ed25519.PublicKey)}, Audience: "edge-a"},
		Hub: session.NewHub(nil), Upstream: upstream, Log: slog.New(slog.NewTextHandler(os.Stdout, nil))}
	wsServer := httptest.NewServer(edgews.NewHandler(e))
	defer wsServer.Close()
	wtServer := edgewt.NewServer(e)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	wtServer.H3.TLSConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer wtServer.Close()
	go func() { _ = wtServer.Serve(listener) }()
	hash := sha256.Sum256(der)
	for _, carrier := range []string{"websocket", "webtransport"} {
		t.Run(carrier, func(t *testing.T) {
			options := map[string]any{"tenantId": tenant, "viewerId": viewerID,
				"token": token(map[string]any{"sessionId": source.SessionID, "nativeViewId": source.ViewID})}
			timeout := 45 * time.Second
			if os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_WIDE") == "1" {
				options["size"] = map[string]int{"width": 2048, "height": 2048}
				options["timeoutMs"] = 90000
				timeout = 100 * time.Second
			}
			settings, _ := json.Marshal(options)
			settingsPath := filepath.Join(t.TempDir(), "settings.json")
			if err := os.WriteFile(settingsPath, settings, 0600); err != nil {
				t.Fatal(err)
			}
			endpoint := "ws" + strings.TrimPrefix(wsServer.URL, "http") + edgews.Path
			if carrier == "webtransport" {
				endpoint = "https://" + listener.LocalAddr().String() + edgewt.Path
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, "node", script, endpoint, "live", carrier, worker, base64.StdEncoding.EncodeToString(hash[:]))
			cmd.Env = append(os.Environ(), "MEDIA_EDGE_BROWSER_SETTINGS_FILE="+settingsPath)
			if prefix := os.Getenv("MEDIA_EDGE_BROWSER_SCREENSHOT_PREFIX"); prefix != "" {
				cmd.Env = append(cmd.Env, "MEDIA_EDGE_BROWSER_SCREENSHOT_FILE="+prefix+"-"+carrier+".png")
			}
			output, err := cmd.CombinedOutput()
			t.Log(string(output))
			if err != nil {
				t.Fatalf("actual T1/edge/%s native consumer: %v", carrier, err)
			}
		})
	}
	t.Logf("source composition completed with exact live T1 fixture %s/%s; bridge forwarding, not Product auth", source.SessionID, source.ViewID)
}
