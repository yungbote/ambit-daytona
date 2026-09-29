// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Command media-edge serves browser views to people's browsers from the node
// that runs their sandboxes, admitting each viewer with a grant the backend
// signed. Configuration is the environment and mounted files only.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daytonaio/media-edge/internal/daytona"
	"github.com/daytonaio/media-edge/internal/filewatch"
	"github.com/daytonaio/media-edge/internal/grant"
	"github.com/daytonaio/media-edge/internal/session"
	"github.com/daytonaio/media-edge/internal/websocket"
	edgewt "github.com/daytonaio/media-edge/internal/webtransport"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	keyFileCheck  = 10 * time.Second
	shutdownGrace = 5 * time.Second
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("media_edge.failed", "error", err.Error())
		os.Exit(1)
	}
}

type config struct {
	edgeID, listen, internalListen, keysFile, proxy, credential, organization string
	quicListen, certFile, tlsKeyFile                                          string
	origins                                                                   []string
}

func loadConfig() (config, error) {
	c := config{
		edgeID:         os.Getenv("MEDIA_EDGE_ID"),
		listen:         envOr("MEDIA_EDGE_LISTEN", ":8080"),
		internalListen: envOr("MEDIA_EDGE_INTERNAL_LISTEN", ":8081"),
		keysFile:       os.Getenv("MEDIA_EDGE_GRANT_KEYS_FILE"),
		proxy:          os.Getenv("DAYTONA_TOOLBOX_PROXY_URL"),
		organization:   os.Getenv("DAYTONA_ORGANIZATION_ID"),
		quicListen:     os.Getenv("MEDIA_EDGE_QUIC_LISTEN"),
		certFile:       os.Getenv("MEDIA_EDGE_TLS_CERT_FILE"),
		tlsKeyFile:     os.Getenv("MEDIA_EDGE_TLS_KEY_FILE"),
	}
	if origins := os.Getenv("MEDIA_EDGE_ALLOWED_ORIGINS"); origins != "" {
		c.origins = strings.Split(origins, ",")
	}
	if !grant.IsEdgeID(c.edgeID) {
		return c, errors.New("MEDIA_EDGE_ID must name this edge ([A-Za-z0-9._-]{1,64})")
	}
	if c.keysFile == "" {
		return c, errors.New("MEDIA_EDGE_GRANT_KEYS_FILE must name the grant public key file")
	}
	if c.quicListen != "" && (c.certFile == "" || c.tlsKeyFile == "") {
		return c, errors.New("MEDIA_EDGE_QUIC_LISTEN requires MEDIA_EDGE_TLS_CERT_FILE and MEDIA_EDGE_TLS_KEY_FILE")
	}
	credential, err := fileBacked("DAYTONA_API_KEY")
	if err != nil {
		return c, err
	}
	c.credential = credential
	return c, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// fileBacked reads NAME, or the file NAME_FILE names, exactly one of them, as
// the backend's file-backed environment does: one terminal line ending is
// not part of the value.
func fileBacked(name string) (string, error) {
	value, direct := os.LookupEnv(name)
	path, fromFile := os.LookupEnv(name + "_FILE")
	switch {
	case direct && fromFile:
		return "", fmt.Errorf("set %s or %s_FILE, not both", name, name)
	case fromFile:
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", name, err)
		}
		value = strings.TrimSuffix(strings.TrimSuffix(string(content), "\n"), "\r")
	case !direct:
		return "", fmt.Errorf("%s or %s_FILE is required", name, name)
	}
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("%s is empty or not one line", name)
	}
	return value, nil
}

func run(log *slog.Logger) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var keys grant.KeyRing
	if err := filewatch.Watch(ctx, c.keysFile, keyFileCheck, keys.Apply, func(err error) {
		log.Error("grant_keys.rejected", "error", err.Error())
	}); err != nil {
		return fmt.Errorf("grant keys: %w", err)
	}
	upstream, err := daytona.New(c.proxy, c.credential, c.organization)
	if err != nil {
		return err
	}
	hub := session.NewHub(nil)
	edge := &session.Edge{
		Verifier: grant.Verifier{Keys: &keys, Audience: c.edgeID},
		Hub:      hub,
		Upstream: upstream,
		Origins:  c.origins,
		Log:      log,
	}
	var ready atomic.Bool
	public := &http.Server{Addr: c.listen, Handler: websocket.NewHandler(edge), ReadHeaderTimeout: 10 * time.Second}
	internal := &http.Server{Addr: c.internalListen, Handler: internalRoutes(edge, &ready), ReadHeaderTimeout: 10 * time.Second}
	failed := make(chan error, 3)
	var quicServer interface{ Close() error }
	if c.quicListen != "" {
		var certificate atomic.Pointer[tls.Certificate]
		apply := func([]byte) error {
			pair, err := tls.LoadX509KeyPair(c.certFile, c.tlsKeyFile)
			if err == nil {
				certificate.Store(&pair)
			}
			return err
		}
		for _, path := range []string{c.certFile, c.tlsKeyFile} {
			if err := filewatch.Watch(ctx, path, keyFileCheck, apply, func(err error) {
				log.Error("tls_certificate.rejected", "error", err.Error())
			}); err != nil {
				return fmt.Errorf("QUIC certificate: %w", err)
			}
		}
		server := edgewt.NewServer(edge, http3.Server{
			Addr: c.quicListen,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return certificate.Load(), nil
			}},
			QUICConfig: &quic.Config{EnableDatagrams: true, MaxIncomingStreams: 4, MaxIncomingUniStreams: 0, MaxIdleTimeout: 60 * time.Second},
		})
		quicServer = server
		defer server.Close()
		go func() {
			if err := server.ListenAndServe(); err != nil && ctx.Err() == nil {
				failed <- err
			}
		}()
	}
	for _, server := range []*http.Server{public, internal} {
		go func() {
			if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				failed <- err
			}
		}()
	}
	ready.Store(true)
	log.Info("media_edge.started", "edgeId", c.edgeID, "listen", c.listen, "internalListen", c.internalListen, "keys", len(keys.PublicKeys()))
	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}
	// A restart is not an ended view: viewers reconnect and resynchronize.
	ready.Store(false)
	deadline, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	_ = public.Shutdown(deadline)
	hub.Shutdown(1012, "browser_view_restarting")
	if quicServer != nil {
		_ = quicServer.Close()
	}
	for hub.Len() > 0 && deadline.Err() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	_ = internal.Shutdown(deadline)
	log.Info("media_edge.stopped", "sessionsLeft", hub.Len())
	return nil
}

// internalRoutes are reachable inside the cluster only: revocation (which
// its signature authorizes, since sandbox code runs in the cluster too),
// health and readiness.
func internalRoutes(edge *session.Edge, ready *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/revoke", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, grant.MaxTokenBytes+1))
		if err != nil {
			http.Error(w, "unreadable", http.StatusBadRequest)
			return
		}
		revocation, err := edge.Verifier.Revocation(strings.TrimSpace(string(body)))
		switch {
		case errors.Is(err, grant.ErrSignature):
			http.Error(w, "signature", http.StatusUnauthorized)
			return
		case err != nil:
			http.Error(w, "malformed", http.StatusBadRequest)
			return
		}
		closed := edge.Hub.Revoke(revocation)
		edge.Log.Info("revocation.applied", "tenantId", revocation.TenantID, "code", revocation.Code, "closed", closed)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"closed": closed})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ready")
	})
	return mux
}
