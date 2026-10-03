package manager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daytonaio/daytona/libs/netleash/pkg/proxy"
)

func quietManager() *Manager {
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, "")
}

// startHTTPSBackend starts a local HTTPS server with a cert signed by ca and
// returns the listener and its "localhost:<port>" address.
func startHTTPSBackend(t *testing.T, ca *proxy.CA, handler http.Handler) (net.Listener, string) {
	t.Helper()
	cert, err := ca.MintCert("localhost")
	if err != nil {
		t.Fatalf("MintCert failed: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}})
	if err != nil {
		t.Fatalf("backend tls.Listen failed: %v", err)
	}
	go http.Serve(ln, handler)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return ln, "localhost:" + port
}

func TestStartSecretProxy_InjectsResolvedSecret(t *testing.T) {
	// Backend signed by its own CA; the proxy's upstream connection must trust it.
	backendCA, err := proxy.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	var gotAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	backendLn, backendAddr := startHTTPSBackend(t, backendCA, mux)
	defer backendLn.Close()

	// The proxy uses http.DefaultTransport for upstream requests; make it trust
	// the backend's CA for the duration of the test.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(backendCA.PEM)
	orig := http.DefaultTransport
	http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	t.Cleanup(func() { http.DefaultTransport = orig })

	m := quietManager()
	defer m.Close()

	resolver := proxy.ResolverFunc(func(ctx context.Context) ([]proxy.SecretConfig, error) {
		return []proxy.SecretConfig{{
			Name:        "ANTHROPIC_API_KEY",
			Placeholder: "dtn_secret_abc123",
			Value:       "sk-ant-real",
			Hosts:       []string{"localhost"},
		}}, nil
	})

	handle, err := m.StartSecretProxy("sb-1", SecretProxyConfig{
		ListenAddr:        "127.0.0.1:0",
		AllowedDomains:    []string{"localhost"},
		Resolver:          resolver,
		PlaceholderMarker: "dtn_secret_",
	})
	if err != nil {
		t.Fatalf("StartSecretProxy failed: %v", err)
	}

	// The client trusts the proxy's minted CA (from the handle) and routes
	// through the proxy.
	caPEM, err := os.ReadFile(handle.CACertFile)
	if err != nil {
		t.Fatalf("reading CA cert file: %v", err)
	}
	clientPool := x509.NewCertPool()
	if !clientPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to load proxy CA cert")
	}
	proxyURL, _ := url.Parse("http://" + handle.Addr)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: clientPool},
	}}

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s/api", backendAddr), nil)
	req.Header.Set("Authorization", "Bearer dtn_secret_abc123")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer sk-ant-real" {
		t.Fatalf("expected placeholder replaced with real secret, backend saw %q", gotAuth)
	}

	// Stopping the proxy closes the listener and removes the temp CA cert file.
	m.StopSecretProxy("sb-1")
	if _, err := os.Stat(handle.CACertFile); !os.IsNotExist(err) {
		t.Fatalf("expected CA cert file removed after stop, stat err=%v", err)
	}
	if conn, err := net.DialTimeout("tcp", handle.Addr, 500*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("expected proxy to refuse connections after stop")
	}
}

func TestSharedSecretInjection_EndToEnd(t *testing.T) {
	backendCA, err := proxy.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	var gotAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	backendLn, backendAddr := startHTTPSBackend(t, backendCA, mux)
	defer backendLn.Close()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(backendCA.PEM)
	orig := http.DefaultTransport
	http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	t.Cleanup(func() { http.DefaultTransport = orig })

	m := quietManager()
	defer m.Close()

	dir := t.TempDir()
	handle, err := m.EnableEgressProxy(EgressProxyConfig{
		ListenAddr: "127.0.0.1:0",
		CACertPath: filepath.Join(dir, "ca.crt"),
		CAKeyPath:  filepath.Join(dir, "ca.key"),
	})
	if err != nil {
		t.Fatalf("EnableEgressProxy failed: %v", err)
	}
	// Idempotent: a second call returns the same running proxy.
	again, err := m.EnableEgressProxy(EgressProxyConfig{
		ListenAddr: "127.0.0.1:0",
		CACertPath: filepath.Join(dir, "ca.crt"),
		CAKeyPath:  filepath.Join(dir, "ca.key"),
	})
	if err != nil || again.Addr != handle.Addr {
		t.Fatalf("EnableEgressProxy not idempotent: addr1=%s addr2=%s err=%v", handle.Addr, again.Addr, err)
	}

	if err := m.RegisterSandboxPolicy("sb-1", SandboxPolicyConfig{
		ClientIP:       "127.0.0.1",
		AllowedDomains: []string{"localhost"},
		Resolver: proxy.ResolverFunc(func(ctx context.Context) ([]proxy.SecretConfig, error) {
			return []proxy.SecretConfig{{Placeholder: "dtn_secret_abc", Value: "sk-real", Hosts: []string{"localhost"}}}, nil
		}),
		PlaceholderMarker: "dtn_secret_",
	}); err != nil {
		t.Fatalf("RegisterSandboxPolicy failed: %v", err)
	}

	caPEM, err := os.ReadFile(handle.CACertFile)
	if err != nil {
		t.Fatalf("reading CA bundle: %v", err)
	}
	clientPool := x509.NewCertPool()
	clientPool.AppendCertsFromPEM(caPEM)
	proxyURL, _ := url.Parse("http://" + handle.Addr)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: clientPool},
	}}

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s/api", backendAddr), nil)
	req.Header.Set("Authorization", "Bearer dtn_secret_abc")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through shared proxy failed: %v", err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer sk-real" {
		t.Fatalf("expected injected secret, backend saw %q", gotAuth)
	}

	// Remove drops the binding: the same client is now rejected (plain HTTP → 403).
	m.Remove("sb-1")
	httpOnly := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp2, err := httpOnly.Get("http://localhost/api")
	if err != nil {
		t.Fatalf("post-remove request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 after Remove unregistered the binding, got %d", resp2.StatusCode)
	}
}

func TestRegisterSandboxPolicy_RequiresEgressProxy(t *testing.T) {
	m := quietManager()
	defer m.Close()
	err := m.RegisterSandboxPolicy("sb", SandboxPolicyConfig{
		ClientIP: "127.0.0.1",
		Resolver: proxy.ResolverFunc(func(ctx context.Context) ([]proxy.SecretConfig, error) { return nil, nil }),
	})
	if err == nil {
		t.Fatal("expected error when the egress proxy is not enabled")
	}
}

func TestStartSecretProxy_RequiresResolver(t *testing.T) {
	m := quietManager()
	defer m.Close()
	if _, err := m.StartSecretProxy("x", SecretProxyConfig{ListenAddr: "127.0.0.1:0"}); err == nil {
		t.Fatal("expected error when resolver is nil")
	}
}

func TestRemove_StopsSecretProxy(t *testing.T) {
	m := quietManager()
	defer m.Close()

	handle, err := m.StartSecretProxy("sb", SecretProxyConfig{
		ListenAddr: "127.0.0.1:0",
		Resolver: proxy.ResolverFunc(func(ctx context.Context) ([]proxy.SecretConfig, error) {
			return nil, nil
		}),
	})
	if err != nil {
		t.Fatalf("StartSecretProxy failed: %v", err)
	}

	// Remove must tear the proxy down even though no eBPF firewall exists for it.
	m.Remove("sb")
	if _, err := os.Stat(handle.CACertFile); !os.IsNotExist(err) {
		t.Fatalf("expected CA cert file removed after Remove, stat err=%v", err)
	}
}

func TestStartSecretProxy_ReplaceClosesOld(t *testing.T) {
	m := quietManager()
	defer m.Close()

	resolver := proxy.ResolverFunc(func(ctx context.Context) ([]proxy.SecretConfig, error) {
		return nil, nil
	})
	first, err := m.StartSecretProxy("sb", SecretProxyConfig{ListenAddr: "127.0.0.1:0", Resolver: resolver})
	if err != nil {
		t.Fatalf("first StartSecretProxy failed: %v", err)
	}
	second, err := m.StartSecretProxy("sb", SecretProxyConfig{ListenAddr: "127.0.0.1:0", Resolver: resolver})
	if err != nil {
		t.Fatalf("second StartSecretProxy failed: %v", err)
	}

	// The replaced proxy's listener and CA cert file should be gone.
	if _, err := os.Stat(first.CACertFile); !os.IsNotExist(err) {
		t.Fatalf("expected old CA cert file removed after replace, stat err=%v", err)
	}
	if first.Addr == second.Addr {
		t.Fatal("expected the replacement proxy to bind a fresh ephemeral port")
	}
}
