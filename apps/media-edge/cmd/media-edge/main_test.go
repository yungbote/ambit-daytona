// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/grant"
	"github.com/daytonaio/media-edge/internal/session"
)

type staticKeys []ed25519.PublicKey

func (k staticKeys) PublicKeys() []ed25519.PublicKey { return k }

func key(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func signed(signer ed25519.PrivateKey, payload map[string]any) string {
	encoded, _ := json.Marshal(payload)
	segment := base64.RawURLEncoding.EncodeToString(encoded)
	return segment + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, []byte(segment)))
}

func TestInternalRoutes(t *testing.T) {
	backend := key("backend")
	edge := &session.Edge{
		Verifier: grant.Verifier{Keys: staticKeys{backend.Public().(ed25519.PublicKey)}, Audience: "edge-a"},
		Hub:      session.NewHub(nil),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	var ready atomic.Bool
	server := httptest.NewServer(internalRoutes(edge, &ready))
	defer server.Close()
	revocation := map[string]any{"v": 1, "typ": "revoke", "issuedAt": time.Now().UnixMilli(), "code": 4403, "tenantId": "85086ad0-dab6-4cab-a0dc-6d029be8be75"}
	post := func(body string) (int, string) {
		response, err := http.Post(server.URL+"/internal/revoke", "text/plain", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		content, _ := io.ReadAll(response.Body)
		return response.StatusCode, strings.TrimSpace(string(content))
	}
	if status, body := post(signed(backend, revocation) + "\n"); status != 200 || body != `{"closed":0}` {
		t.Fatalf("revocation: %d %s", status, body)
	}
	if status, _ := post(signed(key("sandbox"), revocation)); status != http.StatusUnauthorized {
		t.Fatalf("an unsigned revocation: %d", status)
	}
	revocation["code"] = 1000
	if status, _ := post(signed(backend, revocation)); status != http.StatusBadRequest {
		t.Fatalf("a malformed revocation: %d", status)
	}
	if status, _ := post(strings.Repeat("a", grant.MaxTokenBytes+10)); status != http.StatusBadRequest {
		t.Fatalf("an oversized body: %d", status)
	}
	response, _ := http.Get(server.URL + "/internal/revoke")
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET revoke: %d", response.StatusCode)
	}
	_ = response.Body.Close()
	for _, check := range []struct {
		path   string
		ready  bool
		status int
	}{{"/healthz", false, 200}, {"/readyz", false, 503}, {"/readyz", true, 200}} {
		ready.Store(check.ready)
		response, err := http.Get(server.URL + check.path)
		if err != nil || response.StatusCode != check.status {
			t.Fatalf("%s ready=%v: %v %v", check.path, check.ready, response, err)
		}
		_ = response.Body.Close()
	}
}

func TestTheCredentialIsOneValueFromTheEnvironmentOrItsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daytona-admin-api-key")
	if err := os.WriteFile(path, []byte("secret-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEDIA_EDGE_TEST_KEY_FILE", path)
	if value, err := fileBacked("MEDIA_EDGE_TEST_KEY"); err != nil || value != "secret-key" {
		t.Fatalf("from its file: %q %v", value, err)
	}
	t.Setenv("MEDIA_EDGE_TEST_KEY", "direct")
	if _, err := fileBacked("MEDIA_EDGE_TEST_KEY"); err == nil {
		t.Fatal("both forms were accepted")
	}
	os.Unsetenv("MEDIA_EDGE_TEST_KEY_FILE")
	if value, err := fileBacked("MEDIA_EDGE_TEST_KEY"); err != nil || value != "direct" {
		t.Fatalf("direct: %q %v", value, err)
	}
	os.Unsetenv("MEDIA_EDGE_TEST_KEY")
	if _, err := fileBacked("MEDIA_EDGE_TEST_KEY"); err == nil {
		t.Fatal("a missing credential was accepted")
	}
	if err := os.WriteFile(path, []byte("two\nlines\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEDIA_EDGE_TEST_KEY_FILE", path)
	if _, err := fileBacked("MEDIA_EDGE_TEST_KEY"); err == nil {
		t.Fatal("a multi-line credential was accepted")
	}
}

func TestConfigurationNamesTheEdgeAndItsKeys(t *testing.T) {
	for name, value := range map[string]string{"MEDIA_EDGE_ID": "", "MEDIA_EDGE_GRANT_KEYS_FILE": "", "DAYTONA_API_KEY": "", "DAYTONA_API_KEY_FILE": ""} {
		t.Setenv(name, value)
		os.Unsetenv(name)
	}
	if _, err := loadConfig(); err == nil {
		t.Fatal("an unnamed edge started")
	}
	t.Setenv("MEDIA_EDGE_ID", "mwcc-node-01")
	if _, err := loadConfig(); err == nil {
		t.Fatal("an edge without grant keys started")
	}
	t.Setenv("MEDIA_EDGE_GRANT_KEYS_FILE", "/keys/grant.pem")
	t.Setenv("DAYTONA_API_KEY", "secret-key")
	t.Setenv("MEDIA_EDGE_ALLOWED_ORIGINS", "https://ambit.sh,https://app.ambit.sh")
	c, err := loadConfig()
	if err != nil || c.listen != ":8080" || c.internalListen != ":8081" || len(c.origins) != 2 || c.credential != "secret-key" {
		t.Fatalf("%+v %v", c, err)
	}
	t.Setenv("MEDIA_EDGE_QUIC_LISTEN", ":8443")
	if _, err := loadConfig(); err == nil {
		t.Fatal("QUIC started without certificate paths")
	}
	t.Setenv("MEDIA_EDGE_TLS_CERT_FILE", "/tls/tls.crt")
	if _, err := loadConfig(); err == nil {
		t.Fatal("QUIC started without a TLS key path")
	}
	t.Setenv("MEDIA_EDGE_TLS_KEY_FILE", "/tls/tls.key")
	c, err = loadConfig()
	if err != nil || c.quicListen != ":8443" || c.certFile != "/tls/tls.crt" || c.tlsKeyFile != "/tls/tls.key" {
		t.Fatalf("QUIC config: %+v %v", c, err)
	}
}
