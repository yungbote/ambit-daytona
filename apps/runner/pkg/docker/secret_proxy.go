// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/daytonaio/daytona/libs/netleash/pkg/manager"
	"github.com/daytonaio/daytona/libs/netleash/pkg/proxy"
	"github.com/daytonaio/daytona/libs/netleash/pkg/secrets"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

// secretCAContainerPath is where the shared proxy's CA bundle is mounted inside
// every secret-using sandbox; the injected SSL_CERT_FILE / *_CA_BUNDLE env vars
// point HTTP clients at it so they trust the proxy's MITM certificates. The
// in-sandbox daemon also installs it into the system trust store at startup
// (apps/daemon/pkg/cacert) for clients that ignore those env vars, e.g. GnuTLS
// builds of wget. Keep the path in sync with cacert.DefaultProxyCAPath.
const secretCAContainerPath = "/etc/daytona/netleash/ca.crt"

// EnableEgressProxy brings up the runner's shared egress proxy — the
// hostname-aware MITM proxy that injects secrets and, for proxy-enforced
// sandboxes, is the mandatory path for web-port egress: it resolves the sandbox
// bridge gateway, starts the netleash shared proxy bound to "<gateway>:<port>",
// and records the proxy address and CA bundle path so they can be injected into
// proxy-wired sandboxes. Idempotent and a no-op when neither secret injection
// nor proxy enforcement is enabled. Once enabled, it is an admission dependency:
// all startup and partial-reconciliation failures are returned to the runner.
func (d *DockerClient) EnableEgressProxy(ctx context.Context) error {
	if !d.egressProxyEnabled {
		return nil
	}
	if d.netleashManager == nil {
		return fmt.Errorf("netleash manager is unavailable")
	}

	gatewayIP, err := d.resolveSandboxGatewayIP(ctx)
	if err != nil {
		return fmt.Errorf("resolving sandbox bridge gateway: %w", err)
	}

	port := d.secretProxyPort
	if port == 0 {
		port = 18080
	}
	caDir := d.secretCADir
	if caDir == "" {
		caDir = "/var/lib/netleash"
	}

	handle, err := d.netleashManager.EnableEgressProxy(manager.EgressProxyConfig{
		ListenAddr: net.JoinHostPort(gatewayIP, fmt.Sprintf("%d", port)),
		CACertPath: filepath.Join(caDir, "secret-ca.crt"),
		CAKeyPath:  filepath.Join(caDir, "secret-ca.key"),
		// Co-locate the mounted CA bundle with the daemon binary: that directory
		// is already bind-mounted into sandboxes, so the same host path resolves
		// for the mount (a temp/CA-dir path may not be visible to the Docker
		// daemon when the runner itself runs in a container).
		CABundlePath: d.secretCABundleHostPath(),
	})
	if handle == nil || err != nil {
		if err == nil {
			err = fmt.Errorf("egress proxy returned no handle")
		}
		return err
	}

	// Record the proxy only after every existing firewall accepted it. This keeps
	// the client-wide readiness state honest: a non-nil address means hostname
	// enforcement is available for every subsequently admitted sandbox.
	d.secretProxyAddr = handle.Addr
	d.secretProxyCACert = handle.CACertFile
	d.logger.InfoContext(ctx, "Egress proxy enabled", "addr", handle.Addr, "gateway", gatewayIP,
		"secretInjection", d.secretProxyEnabled, "proxyEnforcement", d.proxyEnforcementEnabled)
	return nil
}

// secretCABundleHostPath returns the host path where the combined CA bundle is
// written for mounting into sandboxes. It is placed next to the daemon binary
// (already proven bind-mountable into sandboxes) so the same host path resolves
// for the bind mount even when the runner itself runs in a container; it falls
// back to the CA dir if the daemon binary path is unknown.
func (d *DockerClient) secretCABundleHostPath() string {
	if d.daemonPath != "" {
		return filepath.Join(filepath.Dir(d.daemonPath), "netleash-secret-ca.crt")
	}
	caDir := d.secretCADir
	if caDir == "" {
		caDir = "/var/lib/netleash"
	}
	return filepath.Join(caDir, "secret-ca-bundle.crt")
}

// sandboxNetworkName returns the Docker network sandboxes primarily egress
// through — the same one GetContainerIpAddress reports an IP from — so the
// shared proxy binds to that network's gateway.
func (d *DockerClient) sandboxNetworkName() string {
	if !d.interSandboxNetworkEnabled {
		return RUNNER_BRIDGE_NETWORK_NAME
	}
	if n := d.containerNetwork; n != "" {
		return n
	}
	return "bridge"
}

// resolveSandboxGatewayIP returns the IPv4 gateway of the sandbox network. The
// proxy binds here (a host-side bridge address) and the eBPF firewall allows it,
// so a sandbox reaches the proxy at its default-route gateway.
func (d *DockerClient) resolveSandboxGatewayIP(ctx context.Context) (string, error) {
	name := d.sandboxNetworkName()
	net, err := d.apiClient.NetworkInspect(ctx, name, network.InspectOptions{})
	if err != nil {
		return "", fmt.Errorf("inspecting network %q: %w", name, err)
	}
	for _, cfg := range net.IPAM.Config {
		if cfg.Gateway != "" && isIPv4(cfg.Gateway) {
			return cfg.Gateway, nil
		}
	}
	// Docker usually reports the gateway, but if IPAM only carries the subnet,
	// fall back to its first host address (the conventional bridge gateway).
	for _, cfg := range net.IPAM.Config {
		if cfg.Subnet != "" {
			if gw := firstHostIP(cfg.Subnet); gw != "" {
				return gw, nil
			}
		}
	}
	return "", fmt.Errorf("network %q has no IPv4 gateway/subnet", name)
}

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// firstHostIP returns the first usable host address of an IPv4 CIDR (e.g.
// "172.20.0.0/16" → "172.20.0.1"), which Docker uses as the bridge gateway.
func firstHostIP(cidr string) string {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	host := make(net.IP, len(ip4))
	copy(host, ip4)
	host[3]++
	return host.String()
}

// sandboxUsesSecrets reports whether any of the sandbox's env values is a
// Daytona secret placeholder — the signal that the sandbox needs the egress
// proxy wired in (HTTP(S)_PROXY + CA) and a per-sandbox binding registered.
func sandboxUsesSecrets(env map[string]string) bool {
	for _, v := range env {
		if strings.HasPrefix(v, secrets.DaytonaPlaceholderPrefix) {
			return true
		}
	}
	return false
}

// sandboxNeedsProxyWiring reports whether a sandbox must be wired through the
// shared egress proxy (HTTP(S)_PROXY env + trusted CA): it uses secrets, or
// proxy enforcement is on and it has a domain allow list — in which case the
// proxy is the mandatory path for its web traffic and enforces the allow list
// on the requested hostname.
func (d *DockerClient) sandboxNeedsProxyWiring(env map[string]string, domainAllowList string) bool {
	if sandboxUsesSecrets(env) {
		return true
	}
	return d.proxyEnforcementEnabled && len(splitDomainAllowList(domainAllowList)) > 0
}

// sandboxProxyEnforced reports whether a sandbox's web-port egress must be gated
// through the shared proxy (hostname-level allow-list enforcement) — i.e. the
// eBPF connect4 hook should transparently redirect its TCP 80/443 to the proxy,
// which enforces the allow list on the requested SNI/Host.
//
// Crucially this does NOT require the sandbox to carry the proxy wiring
// (HTTP(S)_PROXY env + mounted CA): connect4 redirects transparently without the
// workload's cooperation, and connections to allowed hosts with no secret are
// spliced end-to-end (the client validates the real server certificate, so no
// proxy CA is needed). This lets enforcement also cover a sandbox whose domain
// allow list was applied AFTER creation — when the wiring can no longer be
// injected — which would otherwise be left on the spoofable IP-based allow list:
// a sandbox that resolved an allowed domain on a shared CDN IP could reach any
// co-hosted domain by dialing that IP with a forged Host/SNI.
//
// A secret-using sandbox is the one exception: its secret-injection hosts are
// MITM'd, so it must trust the proxy CA (present only with the wiring) or its TLS
// to those hosts would break. Such sandboxes always receive the wiring at
// creation, so gating them on it costs nothing.
func (d *DockerClient) sandboxProxyEnforced(env map[string]string, domainAllowList string) bool {
	if !d.proxyEnforcementEnabled || d.secretProxyAddr == "" {
		return false
	}
	if len(splitDomainAllowList(domainAllowList)) == 0 {
		return false
	}
	return d.hasProxyWiring(env) || !sandboxUsesSecrets(env)
}

// proxyWiringEnvVars returns the env vars that route a sandbox's HTTP(S)
// traffic through the shared proxy and trust its CA. Empty when the proxy is
// off or the sandbox needs no wiring, so unaffected sandboxes are untouched.
func (d *DockerClient) proxyWiringEnvVars(env map[string]string, domainAllowList string) []string {
	if !d.sandboxNeedsProxyWiring(env, domainAllowList) {
		return nil
	}
	return d.secretProxyWiringEnvVars()
}

// hasProxyWiring reports whether a container's env carries the proxy wiring the
// runner injects (HTTPS_PROXY pointing at the shared proxy). It is the signal
// that eBPF web-port gating is safe to enforce for this container — a sandbox
// created before the proxy existed (or before enforcement was enabled) has no
// wiring, and gating it would break its web egress instead of redirecting it.
func (d *DockerClient) hasProxyWiring(env map[string]string) bool {
	return d.secretProxyAddr != "" && env["HTTPS_PROXY"] == "http://"+d.secretProxyAddr
}

// secretProxyWiringEnvVars returns the wiring env entries injected into
// proxy-wired sandboxes, regardless of whether a particular sandbox needs
// them. Empty when the shared proxy is off.
func (d *DockerClient) secretProxyWiringEnvVars() []string {
	if d.secretProxyAddr == "" {
		return nil
	}
	proxyURL := "http://" + d.secretProxyAddr
	return []string{
		"HTTP_PROXY=" + proxyURL,
		"HTTPS_PROXY=" + proxyURL,
		"http_proxy=" + proxyURL,
		"https_proxy=" + proxyURL,
		// Keep loopback off the proxy so the in-sandbox daemon and local tools
		// aren't routed through it.
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
		// Point common TLS stacks at the proxy CA bundle so MITM'd connections verify.
		// (Connections to hosts with no secret are spliced end-to-end and validate the
		// real server cert, so they don't rely on these — only secret-injection hosts,
		// which the proxy MITMs, do.)
		"SSL_CERT_FILE=" + secretCAContainerPath,
		"NODE_EXTRA_CA_CERTS=" + secretCAContainerPath,
		"REQUESTS_CA_BUNDLE=" + secretCAContainerPath,
		"CURL_CA_BUNDLE=" + secretCAContainerPath,
		// Deno consults neither the system trust store nor the other CA-bundle vars;
		// DENO_CERT is its only env hook for an extra CA (bucket 6).
		"DENO_CERT=" + secretCAContainerPath,
	}
}

// secretProxyWiringEnv is the map form of secretProxyWiringEnvVars, used to
// identify (and strip) previously injected wiring entries when reconciling a
// container's env.
func (d *DockerClient) secretProxyWiringEnv() map[string]string {
	return envSliceToMap(d.secretProxyWiringEnvVars())
}

// proxyCABind returns the bind mount (host CA bundle → in-container path,
// read-only) for a proxy-wired sandbox, or "" when not applicable.
func (d *DockerClient) proxyCABind(env map[string]string, domainAllowList string) string {
	if d.secretProxyCACert == "" || !d.sandboxNeedsProxyWiring(env, domainAllowList) {
		return ""
	}
	return fmt.Sprintf("%s:%s:ro", d.secretProxyCACert, secretCAContainerPath)
}

// persistedSecretBinding is the durable record of a sandbox's proxy policy
// binding, written when the binding is registered. It lets the runner
// re-register bindings after a restart (the in-memory registry is lost, but the
// proxy address and CA are stable) — the sandbox secrets token isn't otherwise
// recoverable from a running container. SecretsToken is empty for
// enforcement-only bindings (domain allow list, no secrets).
type persistedSecretBinding struct {
	SandboxID    string   `json:"sandboxId"`
	SecretsToken string   `json:"secretsToken"`
	AllowAll     bool     `json:"allowAll"`
	Domains      []string `json:"domains,omitempty"`
}

// bindingResolver returns the secret resolver for a persisted binding, or nil
// for an enforcement-only binding (no secrets token).
func (d *DockerClient) bindingResolver(b persistedSecretBinding) proxy.SecretResolver {
	if b.SecretsToken == "" {
		return nil
	}
	return secrets.NewAPIResolver(d.daytonaApiUrl, b.SandboxID, b.SecretsToken)
}

// secretBindingsDir is where per-container binding records live (one JSON file
// per container ID), under the CA dir.
func (d *DockerClient) secretBindingsDir() string {
	caDir := d.secretCADir
	if caDir == "" {
		caDir = "/var/lib/netleash"
	}
	return filepath.Join(caDir, "secret-bindings")
}

// registerSandboxPolicy registers (and persists) the shared-proxy binding for a
// sandbox that is wired through the proxy: its host allow list and — for a
// secret-using sandbox — a resolver that fetches the sandbox's secrets from the
// API authenticating as that sandbox. Sandboxes without secrets get an
// enforcement-only binding when proxy enforcement is on and they have a domain
// allow list (the proxy is their mandatory web-egress path, so it must know
// their policy). No-op only when the sandbox has neither proxy wiring, secrets,
// nor a domain policy.
// containerID is the full Docker ID (the manager workload key, matching
// Remove); sandboxID is used for the API call. domainAllowList empty means
// unrestricted egress (allow-all).
func (d *DockerClient) registerSandboxPolicy(ctx context.Context, containerID, sandboxID string, secretsToken *string, containerIP, domainAllowList string, env map[string]string) error {
	needsPolicy := d.hasProxyWiring(env) || d.sandboxNeedsProxyWiring(env, domainAllowList) || d.sandboxProxyEnforced(env, domainAllowList)
	if !needsPolicy {
		if d.netleashManager != nil {
			d.netleashManager.UnregisterSandboxPolicy(containerID)
		}
		d.removeSecretBindingFile(containerID)
		return nil
	}
	if d.secretProxyAddr == "" || d.netleashManager == nil {
		return fmt.Errorf("sandbox %s requires the egress proxy but it is unavailable", sandboxID)
	}
	usesSecrets := sandboxUsesSecrets(env)
	if usesSecrets && !d.secretProxyEnabled {
		return fmt.Errorf("sandbox %s uses secrets but secret injection is disabled", sandboxID)
	}
	if usesSecrets && (secretsToken == nil || *secretsToken == "") {
		return fmt.Errorf("sandbox %s uses secrets but has no secrets token", sandboxID)
	}
	if containerIP == "" {
		return fmt.Errorf("sandbox %s requires a proxy policy but has no IP", sandboxID)
	}

	domains := splitDomainAllowList(domainAllowList)
	binding := persistedSecretBinding{
		SandboxID: sandboxID,
		AllowAll:  len(domains) == 0,
		Domains:   domains,
	}
	if usesSecrets {
		binding.SecretsToken = *secretsToken
	}

	return d.installSandboxPolicy(ctx, containerID, containerIP, binding)
}

// installSandboxPolicy establishes the source identity and durable/in-memory
// proxy binding as one admission unit. Any partial failure revokes the binding,
// leaving the shared proxy closed to the sandbox until a complete retry.
func (d *DockerClient) installSandboxPolicy(ctx context.Context, containerID, containerIP string, binding persistedSecretBinding) error {
	if err := d.ensureSecretSourceGuard(ctx, containerID, containerIP); err != nil {
		d.revokeSandboxPolicy(containerID)
		return fmt.Errorf("sandbox %s proxy source identity is not guarded: %w", binding.SandboxID, err)
	}
	if err := d.persistSecretBinding(containerID, binding); err != nil {
		d.revokeSandboxPolicy(containerID)
		return fmt.Errorf("persisting sandbox %s proxy policy: %w", binding.SandboxID, err)
	}
	if err := d.netleashManager.RegisterSandboxPolicy(containerID, manager.SandboxPolicyConfig{
		ClientIP:          containerIP,
		AllowAll:          binding.AllowAll,
		AllowedDomains:    binding.Domains,
		Resolver:          d.bindingResolver(binding),
		PlaceholderMarker: secrets.DaytonaPlaceholderPrefix,
	}); err != nil {
		d.revokeSandboxPolicy(containerID)
		return fmt.Errorf("registering sandbox %s proxy policy: %w", binding.SandboxID, err)
	}
	return nil
}

func (d *DockerClient) revokeSandboxPolicy(containerID string) {
	if d.netleashManager != nil {
		d.netleashManager.UnregisterSandboxPolicy(containerID)
	}
	d.removeSecretBindingFile(containerID)
}

// ensureSecretSourceGuard establishes the unspoofable host-veth identity used
// by the shared proxy's source-IP policy lookup. It is synchronous on every
// admission and policy update; Docker event reconciliation remains a backup.
func (d *DockerClient) ensureSecretSourceGuard(ctx context.Context, containerID, containerIP string) error {
	if d.netRulesManager == nil {
		return fmt.Errorf("network rules manager is unavailable")
	}
	info, err := d.ContainerInspect(ctx, containerID)
	if err != nil {
		return fmt.Errorf("inspecting container: %w", err)
	}
	veth := resolveHostVeth(d.logger, info, containerIP)
	if veth == "" {
		return fmt.Errorf("host veth could not be resolved")
	}
	shortID := info.ID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	if err := d.netRulesManager.SetSourceGuard(shortID, containerIP, veth); err != nil {
		return fmt.Errorf("installing source guard: %w", err)
	}
	guarded, err := d.netRulesManager.HasSourceGuard(shortID)
	if err != nil {
		return fmt.Errorf("verifying source guard: %w", err)
	}
	if !guarded {
		return fmt.Errorf("source guard verification failed")
	}
	return nil
}

func (d *DockerClient) persistSecretBinding(containerID string, b persistedSecretBinding) error {
	dir := d.secretBindingsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, containerID+".json"), data, 0o600)
}

func (d *DockerClient) removeSecretBindingFile(containerID string) {
	_ = os.Remove(filepath.Join(d.secretBindingsDir(), containerID+".json"))
}

// StartSecretReconcile re-registers persisted proxy policy bindings on startup
// and then periodically, and tears down bindings whose container is gone. This
// is what makes secret injection and proxy enforcement survive a runner
// restart: the shared proxy re-binds its fixed address and reloads its
// persisted CA, while this restores the per-sandbox bindings the in-memory
// registry lost. No-op when disabled.
func (d *DockerClient) StartSecretReconcile(ctx context.Context) {
	if d.secretProxyAddr == "" {
		return
	}
	d.ReconcileSecretBindings(ctx)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.ReconcileSecretBindings(ctx)
			}
		}
	}()
}

// ReconcileSecretBindings aligns the in-memory secret registry with the
// persisted binding records (the durable source of truth, analogous to the eBPF
// bpffs pins):
//
//   - a record whose container is gone/terminal is dropped (file + registry),
//   - a record whose container is alive but not registered is re-registered
//     using the persisted auth token and the container's current IP.
//
// Idempotent and safe to call repeatedly.
func (d *DockerClient) ReconcileSecretBindings(ctx context.Context) {
	if d.secretProxyAddr == "" {
		return
	}

	dir := d.secretBindingsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			d.logger.ErrorContext(ctx, "secret reconcile: failed to read bindings dir", "error", err)
		}
		return
	}

	containers, err := d.apiClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		d.logger.ErrorContext(ctx, "secret reconcile: failed to list containers", "error", err)
		return
	}
	state := make(map[string]string, len(containers))
	for _, c := range containers {
		state[c.ID] = c.State
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		containerID := strings.TrimSuffix(e.Name(), ".json")

		st, present := state[containerID]
		if !present || st == "exited" || st == "dead" || st == "removing" {
			d.netleashManager.UnregisterSandboxPolicy(containerID)
			d.removeSecretBindingFile(containerID)
			continue
		}
		// Re-inspect for the container's current IP rather than trusting a stale one.
		info, err := d.ContainerInspect(ctx, containerID)
		if err != nil {
			d.logger.ErrorContext(ctx, "secret reconcile: failed to inspect container", "containerId", containerID, "error", err)
			continue
		}
		ip := GetContainerIpAddress(ctx, info)
		if ip == "" {
			continue
		}
		b, err := d.readSecretBinding(containerID)
		if err != nil {
			containmentErr := d.rejectSandboxAdmission(ctx, info, fmt.Errorf("reading durable proxy policy: %w", err))
			d.logger.ErrorContext(ctx, "proxy reconcile: durable binding is unreadable; sandbox quarantined", "containerId", containerID, "error", containmentErr)
			continue
		}
		if err := d.ensureSecretSourceGuard(ctx, containerID, ip); err != nil {
			containmentErr := d.rejectSandboxAdmission(ctx, info, fmt.Errorf("restoring proxy source guard: %w", err))
			d.logger.ErrorContext(ctx, "proxy reconcile: source identity is not guarded; sandbox quarantined", "containerId", containerID, "error", containmentErr)
			continue
		}
		if d.netleashManager.HasSandboxPolicy(containerID) {
			continue // registered and source guard reasserted
		}

		if err := d.netleashManager.RegisterSandboxPolicy(containerID, manager.SandboxPolicyConfig{
			ClientIP:          ip,
			AllowAll:          b.AllowAll,
			AllowedDomains:    b.Domains,
			Resolver:          d.bindingResolver(b),
			PlaceholderMarker: secrets.DaytonaPlaceholderPrefix,
		}); err != nil {
			containmentErr := d.rejectSandboxAdmission(ctx, info, fmt.Errorf("restoring proxy policy binding: %w", err))
			d.logger.ErrorContext(ctx, "proxy reconcile: failed to re-register binding; sandbox quarantined", "containerId", containerID, "error", containmentErr)
			continue
		}
		d.logger.InfoContext(ctx, "secret reconcile: re-registered sandbox proxy policy", "containerId", containerID, "sandboxId", b.SandboxID)
	}
}

// updateSandboxPolicyDomains re-syncs a sandbox's proxy allow list when its
// domain allow list changes (via UpdateNetworkSettings), reusing any persisted
// auth token. A sandbox routed through the proxy but without a persisted binding
// (e.g. one whose record was lost, or one whose allow list was applied after
// creation) gets a fresh enforcement-only binding, since the proxy is its
// mandatory web-egress path and an unknown client would be rejected. No-op when
// the proxy is off or the sandbox neither carries the wiring nor is transparently
// enforced.
func (d *DockerClient) updateSandboxPolicyDomains(ctx context.Context, containerID, sandboxID, containerIP, domainAllowList string, env map[string]string) error {
	// Register the binding whenever the sandbox routes through the proxy: either
	// it carries the proxy wiring (secret-using / explicitly-proxied sandboxes) or
	// its web-port egress is transparently gated through the proxy by eBPF
	// (sandboxProxyEnforced — e.g. an allow list applied after creation). Without
	// the binding the proxy can't map the client IP to an allow list and would
	// reject its redirected traffic, so enforcement without registration would
	// break the sandbox's egress instead of scoping it.
	needsPolicy := d.hasProxyWiring(env) || d.sandboxNeedsProxyWiring(env, domainAllowList) || d.sandboxProxyEnforced(env, domainAllowList)
	if !needsPolicy {
		d.revokeSandboxPolicy(containerID)
		return nil
	}
	if d.secretProxyAddr == "" || d.netleashManager == nil {
		return fmt.Errorf("sandbox %s requires the egress proxy but it is unavailable", sandboxID)
	}
	b, err := d.readSecretBinding(containerID)
	if err != nil {
		if sandboxUsesSecrets(env) {
			return fmt.Errorf("sandbox %s uses secrets but its durable proxy binding is unavailable: %w", sandboxID, err)
		}
		// No persisted record is valid for a non-secret sandbox whose allow list
		// was added after creation; create an enforcement-only binding.
		b = persistedSecretBinding{SandboxID: sandboxID}
	}
	domains := splitDomainAllowList(domainAllowList)
	b.AllowAll = len(domains) == 0
	b.Domains = domains
	return d.installSandboxPolicy(ctx, containerID, containerIP, b)
}

// refreshSandboxSecretBinding re-registers an existing policy binding (same IP,
// domains and token) so the shared proxy's injector drops its cached resolution
// and re-fetches the sandbox's secrets immediately. No-op when the proxy is off
// or the sandbox has no persisted binding.
func (d *DockerClient) refreshSandboxSecretBinding(ctx context.Context, containerID, containerIP string) error {
	if d.secretProxyAddr == "" {
		return fmt.Errorf("egress proxy is unavailable")
	}
	b, err := d.readSecretBinding(containerID)
	if err != nil {
		return fmt.Errorf("reading sandbox proxy binding: %w", err)
	}
	return d.installSandboxPolicy(ctx, containerID, containerIP, b)
}

// derefString returns *s, or "" when s is nil — for optional DTO fields like
// DomainAllowList.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// envSliceToMap converts a container's "KEY=VALUE" env slice to a map, for the
// secret-usage check on lifecycle paths that only have the inspected container.
func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

func (d *DockerClient) readSecretBinding(containerID string) (persistedSecretBinding, error) {
	var b persistedSecretBinding
	data, err := os.ReadFile(filepath.Join(d.secretBindingsDir(), containerID+".json"))
	if err != nil {
		return b, err
	}
	err = json.Unmarshal(data, &b)
	return b, err
}
