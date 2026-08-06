// Package manager provides a single, long-lived service that multiplexes many
// independent eBPF egress firewalls — one per workload (e.g. a sandbox
// container).
//
// The pkg/jail and pkg/firewall APIs are designed around a single jailed
// process or cgroup with its own eBPF program set. Manager keeps that one-jail
// building block but wraps it in a registry so a host process (such as the
// Daytona runner) can run a single netleash service for its whole lifetime and
// attach/detach domain allow lists per workload on demand, instead of spawning
// a separate netleash process per workload.
//
// Each managed workload gets its own firewall.Firewall attached to the
// workload's existing cgroup, with its own eBPF maps — so domain allow lists
// are fully isolated between workloads.
//
// Requires root or CAP_BPF. Linux only (cgroup v2 + eBPF).
package manager

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daytonaio/daytona/libs/netleash/pkg/firewall"
	"github.com/daytonaio/daytona/libs/netleash/pkg/proxy"
)

// Manager maintains per-workload egress firewalls keyed by an opaque workload
// ID. It is safe for concurrent use.
type Manager struct {
	log     *slog.Logger
	mu      sync.Mutex
	entries map[string]*entry

	// proxies tracks the per-workload secret-injection MITM proxies started via
	// StartSecretProxy, keyed by the same workload ID as entries. A workload may
	// have a proxy without an eBPF firewall and vice versa, so they're tracked
	// separately; Remove and Close tear down both.
	proxies map[string]*proxyEntry

	// Shared egress proxy (EnableEgressProxy): a single hostname-aware MITM
	// proxy that serves every workload needing it, choosing the per-workload
	// policy (allow list + secrets) from the client's IP via proxyRegistry. It
	// has two jobs: secret injection, and — for workloads configured with
	// enforceProxy — being the mandatory path for web-port egress, enforcing the
	// domain allow list on the requested hostname instead of on DNS-learned IPs.
	// Unlike the per-workload proxies it has a fixed, restart-stable address —
	// required because a workload's HTTP(S)_PROXY is baked in at creation time.
	egressProxy     *proxy.Server
	proxyRegistry   *proxy.Registry
	proxyCACertFile string
	// egressProxyAddr is the shared proxy's listen address; it is also fed into
	// every firewall's Config.ProxyAddr (via Configure) so the eBPF egress filter
	// allows the workload to reach the proxy, and into the eBPF proxy gate for
	// enforcing workloads. Empty until EnableEgressProxy.
	egressProxyAddr string

	// internalDNSZones are cluster-internal DNS zones (e.g. "cluster.local")
	// applied to every managed workload: queries for subdomains of these zones
	// are passed through to the resolver instead of dropped, so search-domain
	// expansion in Kubernetes doesn't stall lookups of allowed external domains.
	internalDNSZones []string

	// pinRoot is the bpffs directory under which each workload's eBPF links and
	// maps are pinned (one subdir per workload ID). Pinning keeps the egress
	// filter attached across a restart of this process so domain filtering is
	// never lost mid-update; Adopt re-attaches management on startup. Empty
	// disables pinning (e.g. where bpffs isn't persistent across restarts).
	pinRoot string
}

// entry tracks one active firewall and the configuration it was built from, so
// repeated Configure calls can detect no-ops and changes.
type entry struct {
	domains []string // normalized + sorted; used to detect changes
	target  attachTarget
	// enforceProxy records whether the caller asked for web-port egress to be
	// gated through the shared proxy. It is the *requested* state; the effective
	// eBPF gate additionally requires the proxy to be running (EnableEgressProxy),
	// and is re-applied when the proxy comes up.
	enforceProxy bool
	fw           *firewall.Firewall
	cancel       context.CancelFunc
}

// attachTarget describes where a workload's egress firewall attaches.
//
// Exactly one mode is used per workload, fixed by the container runtime:
//
//   - cgroupPath (cgroup mode) — runc/sysbox containers, whose processes run in
//     this host cgroup, so cgroup_skb eBPF sees their socket traffic.
//   - iface (TC mode) — VM-isolated runtimes (kata-clh), where the workload runs
//     inside a guest and its traffic never traverses the host cgroup; it only
//     crosses the host-side veth, so the filter must attach there instead.
type attachTarget struct {
	cgroupPath string
	iface      string
	// hostVeth marks iface as the host side of a veth pair, so TC directions are
	// inverted: the workload's egress arrives as ingress on the host veth (and
	// vice versa). Maps to firewall.Config.Tap, which performs the same swap.
	hostVeth bool
}

// proxyEntry tracks one active secret-injection proxy and the temp CA cert file
// it minted (removed when the proxy is torn down).
type proxyEntry struct {
	server     *proxy.Server
	addr       string
	caCertFile string
}

// New creates a Manager. If logger is nil, slog.Default() is used.
// internalDNSZones lists cluster-internal DNS zones (e.g. "cluster.local") whose
// queries are passed through to the resolver for every managed workload; pass
// nil to keep the strict behavior of dropping every non-allowed DNS query.
// pinRoot is the bpffs directory under which per-workload eBPF objects are
// pinned so filters survive a restart of this process (e.g.
// "/sys/fs/bpf/netleash"); pass "" to disable pinning.
func New(logger *slog.Logger, internalDNSZones []string, pinRoot string) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		log:              logger.With(slog.String("component", "netleash_manager")),
		entries:          make(map[string]*entry),
		proxies:          make(map[string]*proxyEntry),
		internalDNSZones: internalDNSZones,
		pinRoot:          pinRoot,
	}
}

// pinPathFor returns the bpffs pin directory for a workload, or "" if pinning
// is disabled.
func (m *Manager) pinPathFor(id string) string {
	if m.pinRoot == "" {
		return ""
	}
	return filepath.Join(m.pinRoot, id)
}

// Configure ensures the workload identified by id has an egress firewall
// attached to cgroupPath that allows exactly the given domains (entries
// prefixed with "*." enable wildcard suffix matching). It is idempotent:
//
//   - empty domains  → any existing firewall is removed (unrestricted egress)
//   - same domains   → no-op (the working filter is left in place)
//   - changed domains → the existing filter's allow list is updated IN PLACE
//   - new workload    → a fresh firewall is attached and pinned
//
// Updating in place (rather than tearing down and rebuilding) is what keeps
// established connections alive across a domain change: the eBPF programs stay
// attached, so the inbound-connection tracking (inbound_conns) and the learned-
// IP cache (allowed_ips) are preserved. A rebuild would start those maps empty,
// silently dropping reply packets on already-open connections — terminal
// websockets, pooled toolbox connections, in-flight downloads — making them
// hang. The workload ID is the container ID, which maps to exactly one cgroup,
// so an existing entry is always the same workload and can be updated directly.
//
// enforceProxy additionally routes the standard web ports (TCP 80/443) through
// the shared egress proxy, which enforces the same allow list on the requested
// hostname (SNI/Host) — closing the shared-IP/domain-fronting gap of IP-based
// allowlisting. In cgroup mode an eBPF connect4 hook does this transparently
// (rewriting the connect() destination to the proxy), so the workload need not
// honor HTTP(S)_PROXY; the egress drop of un-redirected web ports (and all of TC
// mode) remains the backstop. QUIC (UDP 443) is always dropped. Connections the
// proxy MITMs (secret-injection hosts) require the workload to trust the proxy
// CA; connections to other allowed hosts are spliced end-to-end and need no CA.
// It takes effect while the shared proxy is running (EnableEgressProxy) and is
// re-applied automatically when the proxy comes up later.
func (m *Manager) Configure(id, cgroupPath string, domains []string, enforceProxy bool) error {
	return m.configure(id, attachTarget{cgroupPath: cgroupPath}, domains, enforceProxy)
}

// ConfigureInterface is the TC/interface-mode counterpart of Configure for
// VM-isolated runtimes (kata-clh): the workload runs inside a guest VM, so its
// traffic never traverses the host cgroup that cgroup_skb filters — only the
// host-side veth. Attaching there with cgroup mode would be a silent no-op
// (every domain reachable). iface is the host network interface carrying the
// workload's traffic (the host side of its veth pair); hostVeth must be true for
// such an interface so the TC directions are swapped (workload egress arrives as
// ingress on the host veth). Semantics otherwise match Configure exactly
// (idempotent; empty domains remove the filter; changes update in place;
// enforceProxy gates web ports through the shared egress proxy).
func (m *Manager) ConfigureInterface(id, iface string, hostVeth bool, domains []string, enforceProxy bool) error {
	if iface == "" && len(normalizeDomains(domains)) > 0 {
		return fmt.Errorf("netleash: ConfigureInterface for workload %s requires an interface name", id)
	}
	return m.configure(id, attachTarget{iface: iface, hostVeth: hostVeth}, domains, enforceProxy)
}

// configure is the shared implementation behind Configure (cgroup mode) and
// ConfigureInterface (TC mode); see Configure's doc for the idempotency rules.
func (m *Manager) configure(id string, target attachTarget, domains []string, enforceProxy bool) error {
	norm := normalizeDomains(domains)

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(norm) > 0 && enforceProxy && m.egressProxyAddr == "" {
		return fmt.Errorf("netleash: proxy enforcement requested for workload %s but the egress proxy is not running", id)
	}

	existing, ok := m.entries[id]

	// No domains → remove any existing restriction.
	if len(norm) == 0 {
		if ok {
			m.removeLocked(id, existing)
		}
		return nil
	}

	// Existing workload → update the allow list in place, preserving the live
	// inbound-connection tracking so open connections (terminal/toolbox) don't
	// hang. Drop the learned-IP cache only when a domain was removed (or when the
	// previous set is unknown — an adopted entry after a restart), so the removed
	// domain's already-resolved IPs stop being reachable. Pure additions keep the
	// cache so in-flight connections to still-allowed domains aren't disrupted.
	if ok {
		if equalDomains(existing.domains, norm) && existing.enforceProxy == enforceProxy {
			// Reassert the gate even when desired state is unchanged. A previous
			// map-write failure must remain retryable rather than being mistaken for
			// successful convergence on the next idempotent admission.
			return m.applyProxyEnforcementLocked(id, existing)
		}
		if !equalDomains(existing.domains, norm) {
			clearLearned := len(existing.domains) == 0 || domainsRemoved(existing.domains, norm)
			if err := existing.fw.UpdateDomains(norm, clearLearned); err != nil {
				return fmt.Errorf("netleash: updating workload %s: %w", id, err)
			}
			existing.domains = norm
			m.log.Info("domain allow list updated", "workload", id, "domains", norm, "cleared_learned_ips", clearLearned)
		}
		// Re-apply the web-port proxy gate idempotently and surface failures for
		// the runner to quarantine. Hostname enforcement is part of the policy
		// contract, not an optional layer over the IP allow list.
		existing.enforceProxy = enforceProxy
		return m.applyProxyEnforcementLocked(id, existing)
	}

	// New workload → attach a fresh firewall and pin it.
	ctx, cancel := context.WithCancel(context.Background())
	// The firewall logs every egress decision (with the reason) on this
	// workload-scoped logger: blocked requests at warn, allowed/learned
	// requests at debug. See firewall.StartEventReader.
	fw := firewall.New(firewall.Config{
		Domains:          norm,
		InternalDNSZones: m.internalDNSZones,
		// Exactly one of CgroupPath / Interface is set (see attachTarget). The empty
		// one selects the other mode in firewall.Setup.
		CgroupPath: target.cgroupPath,
		Interface:  target.iface,
		Tap:        target.hostVeth,
		// When the shared egress proxy is enabled, allow its IP through the egress
		// filter so a domain-restricted workload can still reach the proxy (the
		// proxy then enforces the same allow list on the workload's behalf for the
		// traffic it intercepts). Empty when the proxy is off.
		ProxyAddr:    m.egressProxyAddr,
		EnforceProxy: enforceProxy,
		Logger:       m.log.With(slog.String("workload", id)),
	})
	if err := fw.Setup(); err != nil {
		fw.Cleanup()
		cancel()
		return fmt.Errorf("netleash: configuring workload %s: %w", id, err)
	}
	fw.StartEventReader(ctx)

	// Pin the new filter so it survives a restart of this process (zero gap).
	// A configured pin root makes restart-safe enforcement part of admission.
	// Pin is atomic, so on failure no half-pinned state remains; tear down the
	// unpinned filter and surface the error rather than admitting a workload whose
	// policy would disappear during a runner restart.
	if pinPath := m.pinPathFor(id); pinPath != "" {
		if err := fw.Pin(pinPath); err != nil {
			fw.Cleanup()
			cancel()
			return fmt.Errorf("netleash: pinning workload %s firewall: %w", id, err)
		}
	}

	m.entries[id] = &entry{
		domains:      norm,
		target:       target,
		enforceProxy: enforceProxy,
		fw:           fw,
		cancel:       cancel,
	}
	m.log.Info("domain allow list applied", "workload", id, "domains", norm, "interface", target.iface, "enforce_proxy", enforceProxy)
	return nil
}

// applyProxyEnforcementLocked writes the entry's desired web-port proxy gate to
// its firewall: on when the entry requested enforcement AND the shared proxy is
// running, off otherwise. Hostname enforcement is a required policy boundary,
// so requested enforcement without a live proxy or writable gate is an error.
// Caller must hold m.mu.
func (m *Manager) applyProxyEnforcementLocked(id string, e *entry) error {
	effective := e.enforceProxy && m.egressProxyAddr != ""
	if e.enforceProxy && !effective {
		return fmt.Errorf("netleash: proxy enforcement requested for workload %s but the egress proxy is not running", id)
	}
	if err := e.fw.SetProxyEnforcement(m.egressProxyAddr, effective); err != nil {
		return fmt.Errorf("netleash: applying proxy enforcement for workload %s: %w", id, err)
	}
	return nil
}

// Adopt re-attaches management to a workload whose pinned firewall survived a
// restart of this process — the eBPF programs stayed attached to the cgroup the
// whole time (zero gap), so this only restores the userspace handles and event
// reader. The pinned maps remain the source of truth for the live allow list,
// so the caller needs no record of the domains or cgroup. No-op if already
// managed. A later Configure (e.g. a network-settings change) rebuilds the
// filter from the new desired list regardless of what was adopted.
func (m *Manager) Adopt(id string) error {
	pinPath := m.pinPathFor(id)
	if pinPath == "" {
		return fmt.Errorf("netleash: adopt requires pinning to be enabled")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.entries[id]; ok {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	fw := firewall.New(firewall.Config{
		PinPath: pinPath,
		Logger:  m.log.With(slog.String("workload", id)),
	})
	if err := fw.Adopt(); err != nil {
		cancel()
		return fmt.Errorf("netleash: adopting workload %s: %w", id, err)
	}
	// Recover hostname-enforcement intent from the pinned policy itself. This
	// keeps Manager generic while allowing the runner to reject legacy pin sets
	// that lack the map entirely. When enforcement is requested and the shared
	// proxy is already live (normal runner startup order), verify reachability and
	// the gate before declaring the entry managed. Cleanup leaves pins attached
	// on failure so the host can quarantine/stop the workload.
	enforceProxy, err := fw.ProxyEnforcementEnabled()
	if err != nil {
		fw.Cleanup()
		cancel()
		return fmt.Errorf("netleash: reading hostname policy for adopted workload %s: %w", id, err)
	}
	if enforceProxy && m.egressProxyAddr != "" {
		if err := fw.AllowIP(m.egressProxyAddr); err != nil {
			fw.Cleanup()
			cancel()
			return fmt.Errorf("netleash: allowing egress proxy for adopted workload %s: %w", id, err)
		}
		if err := fw.SetProxyEnforcement(m.egressProxyAddr, true); err != nil {
			fw.Cleanup()
			cancel()
			return fmt.Errorf("netleash: enabling hostname enforcement for adopted workload %s: %w", id, err)
		}
	}
	fw.StartEventReader(ctx)

	// domains/cgroupPath are intentionally left zero: the live allow list lives
	// in the adopted pinned maps, not in this record.
	m.entries[id] = &entry{
		enforceProxy: enforceProxy,
		fw:           fw,
		cancel:       cancel,
	}
	m.log.Info("domain allow list adopted after restart", "workload", id)
	return nil
}

// PinnedWorkloads returns the workload IDs that have a pinned firewall on bpffs,
// i.e. filters that were active before this process started. Used on startup to
// adopt them (if the workload still exists) or tear them down (if it's gone).
// Returns nil when pinning is disabled.
func (m *Manager) PinnedWorkloads() ([]string, error) {
	if m.pinRoot == "" {
		return nil, nil
	}
	dirents, err := os.ReadDir(m.pinRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	ids := make([]string, 0, len(dirents))
	for _, de := range dirents {
		if de.IsDir() {
			ids = append(ids, de.Name())
		}
	}
	return ids, nil
}

// IsManaged reports whether the workload currently has a live firewall entry.
func (m *Manager) IsManaged(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.entries[id]
	return ok
}

// Remove tears down the firewall for the workload, restoring unrestricted
// egress and removing its bpffs pins. Safe to call when no firewall exists for
// id; in that case it still clears any orphaned pins left by a previous process
// (e.g. the workload was removed while this process was down).
func (m *Manager) Remove(id string) {
	m.mu.Lock()
	// Drop any shared-proxy policy binding for this workload so its IP stops
	// resolving to a removed sandbox, and remember the IP + proxy so we can
	// terminate its active tunnels after releasing the lock (immediate
	// revocation). (Registry has its own lock; safe under m.mu.)
	var revokedIP net.IP
	if m.proxyRegistry != nil {
		revokedIP = m.proxyRegistry.Unregister(id)
	}
	revokedProxy := m.egressProxy
	// Detach the secret-injection proxy (if any) under the lock, but shut it down
	// after releasing it — server.Close blocks on in-flight connections and must
	// not stall other workloads' Manager operations. This is independent of
	// whether an eBPF firewall is also attached.
	p := m.detachProxyLocked(id)
	if e, ok := m.entries[id]; ok {
		m.removeLocked(id, e)
	} else if pinPath := m.pinPathFor(id); pinPath != "" {
		if err := os.RemoveAll(pinPath); err != nil && !os.IsNotExist(err) {
			m.log.Warn("netleash: failed to remove orphaned pin dir", "workload", id, "error", err)
		}
	}
	m.mu.Unlock()

	if revokedProxy != nil && revokedIP != nil {
		revokedProxy.CloseClient(revokedIP)
	}
	m.shutdownProxy(id, p)
}

// removeLocked tears down a single entry. Caller must hold m.mu.
func (m *Manager) removeLocked(id string, e *entry) {
	e.cancel()
	e.fw.Detach() // unpins the bpffs dir and detaches the eBPF programs
	delete(m.entries, id)
	m.log.Info("domain allow list removed", "workload", id)
}

// Close releases this process's handles to every managed firewall but LEAVES
// the bpffs pins in place, so the egress filters keep enforcing uninterrupted
// across a restart of this process (zero gap). On startup the next process
// calls PinnedWorkloads + Adopt to resume managing them. To actually tear a
// filter down, use Remove. After Close the Manager can be reused.
func (m *Manager) Close() {
	m.mu.Lock()
	for id, e := range m.entries {
		e.cancel()
		e.fw.Cleanup() // keeps pins → filter stays attached
		delete(m.entries, id)
	}
	// Secret-injection proxies live entirely in this process (no pinning), so
	// they must be stopped — they don't survive a restart the way pinned filters
	// do. The runner re-creates them on the next StartSecretProxy. Detach them
	// under the lock, then close them after releasing it (server.Close blocks on
	// in-flight connections).
	proxies := m.proxies
	m.proxies = make(map[string]*proxyEntry)

	// The shared egress proxy is also in-process only; stop it and drop its
	// registry. The runner re-enables it (same fixed address + persisted CA)
	// and re-registers running sandboxes on restart.
	sharedProxy := m.egressProxy
	sharedCACert := m.proxyCACertFile
	m.egressProxy = nil
	m.proxyRegistry = nil
	m.proxyCACertFile = ""
	m.egressProxyAddr = ""
	m.mu.Unlock()

	for id, p := range proxies {
		m.shutdownProxy(id, p)
	}
	if sharedProxy != nil {
		sharedProxy.Close()
		if sharedCACert != "" {
			if err := os.Remove(sharedCACert); err != nil && !os.IsNotExist(err) {
				m.log.Warn("netleash: failed to remove shared proxy CA bundle", "error", err)
			}
		}
		m.log.Info("egress proxy disabled")
	}
}

// SecretProxyConfig configures the per-workload MITM proxy started by
// StartSecretProxy.
type SecretProxyConfig struct {
	// ListenAddr is the address the proxy binds to, reachable by the workload —
	// e.g. the container's gateway IP with an ephemeral port ("172.17.0.1:0").
	// Use port 0 to let the kernel pick a free port (returned in the handle).
	ListenAddr string

	// ClientIP, when set, restricts the proxy to connections from this single IP
	// (the workload's own IP) for multitenant isolation; empty allows any client.
	ClientIP string

	// AllowedDomains is the domain allow list the proxy will forward to; requests
	// to any other host are rejected with 403. Callers should include both the
	// sandbox's allowed domains and the hosts its secrets may be sent to.
	AllowedDomains []string

	// AuthToken, when set, requires clients to present
	// "Proxy-Authorization: Bearer <token>".
	AuthToken string

	// Resolver supplies the secrets to inject, resolved dynamically per workload
	// (e.g. secrets.NewAPIResolver, which authenticates as the sandbox). Required.
	Resolver proxy.SecretResolver

	// CacheTTL is how long resolved secrets are cached before the resolver is
	// consulted again. Non-positive uses the injector's default.
	CacheTTL time.Duration

	// PlaceholderMarker is an optional cheap pre-check: outbound request data not
	// containing this substring is forwarded without consulting the resolver. Set
	// it to the known placeholder prefix (secrets.DaytonaPlaceholderPrefix) to
	// avoid resolving secrets for requests that obviously carry none.
	PlaceholderMarker string
}

// SecretProxyHandle describes a running secret-injection proxy. The workload
// must route its HTTP(S) traffic through Addr and trust CACertFile (e.g. via
// HTTPS_PROXY and SSL_CERT_FILE) for injection to take effect.
type SecretProxyHandle struct {
	Addr       string // actual listen address (host:port)
	CACertFile string // path to the combined CA bundle the workload must trust
}

// StartSecretProxy starts (or replaces) a per-workload MITM proxy that injects
// secrets — resolved dynamically via cfg.Resolver — in place of the placeholder
// tokens found in the workload's outbound requests to approved hosts. The proxy
// terminates TLS with an ephemeral CA and returns that CA's cert path so the
// caller can have the workload trust it.
//
// Replacing an existing proxy for the same id starts the new one first, then
// retires the old one, so there's no gap — this assumes an ephemeral listen port
// (ListenAddr host:0); to reuse a fixed port, call StopSecretProxy first.
//
// The proxy lives only in this process; unlike the eBPF firewall it is not
// pinned and does not survive a restart, so the caller re-establishes it after a
// runner restart.
func (m *Manager) StartSecretProxy(id string, cfg SecretProxyConfig) (*SecretProxyHandle, error) {
	if cfg.Resolver == nil {
		return nil, fmt.Errorf("netleash: StartSecretProxy for workload %s requires a resolver", id)
	}

	ca, err := proxy.GenerateCA()
	if err != nil {
		return nil, fmt.Errorf("netleash: generating proxy CA for workload %s: %w", id, err)
	}
	caCertFile, err := proxy.WriteCombinedCACert(ca.PEM)
	if err != nil {
		return nil, fmt.Errorf("netleash: writing proxy CA cert for workload %s: %w", id, err)
	}

	injector := proxy.NewResolvingInjector(cfg.Resolver, cfg.CacheTTL, cfg.PlaceholderMarker)

	opts := []proxy.Option{proxy.WithLogger(m.log.With(slog.String("workload", id)))}
	if cfg.AuthToken != "" {
		opts = append(opts, proxy.WithAuthToken(cfg.AuthToken))
	}

	server := proxy.NewServer(cfg.ListenAddr, ca, injector, cfg.AllowedDomains, cfg.ClientIP, opts...)
	addr, err := server.Start()
	if err != nil {
		os.Remove(caCertFile)
		return nil, fmt.Errorf("netleash: starting secret proxy for workload %s: %w", id, err)
	}

	m.mu.Lock()
	old := m.proxies[id]
	m.proxies[id] = &proxyEntry{server: server, addr: addr, caCertFile: caCertFile}
	m.mu.Unlock()

	// Retire the previous proxy (if any) only after the new one is live.
	if old != nil {
		old.server.Close()
		if old.caCertFile != "" {
			os.Remove(old.caCertFile)
		}
	}

	m.log.Info("secret injection proxy started", "workload", id, "addr", addr)
	return &SecretProxyHandle{Addr: addr, CACertFile: caCertFile}, nil
}

// StopSecretProxy stops the secret-injection proxy for the workload and removes
// its temp CA cert file. Safe to call when no proxy exists for id.
func (m *Manager) StopSecretProxy(id string) {
	m.mu.Lock()
	p := m.detachProxyLocked(id)
	m.mu.Unlock()
	m.shutdownProxy(id, p)
}

// detachProxyLocked removes the workload's proxy from the registry and returns
// it (nil if none), without closing it. Caller must hold m.mu. The returned
// proxy is shut down via shutdownProxy after the lock is released, since
// server.Close blocks on in-flight connections.
func (m *Manager) detachProxyLocked(id string) *proxyEntry {
	p := m.proxies[id]
	delete(m.proxies, id)
	return p
}

// shutdownProxy closes a detached proxy and removes its temp CA cert file. It
// must be called without holding m.mu (server.Close waits for in-flight
// connections). No-op when p is nil.
func (m *Manager) shutdownProxy(id string, p *proxyEntry) {
	if p == nil {
		return
	}
	p.server.Close()
	if p.caCertFile != "" {
		if err := os.Remove(p.caCertFile); err != nil && !os.IsNotExist(err) {
			m.log.Warn("netleash: failed to remove proxy CA cert", "workload", id, "error", err)
		}
	}
	m.log.Info("secret injection proxy stopped", "workload", id)
}

// EgressProxyConfig configures the shared egress proxy started by
// EnableEgressProxy.
type EgressProxyConfig struct {
	// ListenAddr is where the shared proxy binds. It must be a concrete address
	// reachable by every secret-using workload and stable across restarts —
	// typically the bridge gateway IP with a fixed port (e.g. "172.20.0.1:18080")
	// — because each workload's HTTP(S)_PROXY points at it and is fixed at
	// creation. The host IP is also added to every firewall's allow list so a
	// domain-restricted workload can reach the proxy. Do not use "0.0.0.0".
	ListenAddr string

	// CACertPath and CAKeyPath persist the proxy's CA so it survives restarts
	// (the CA cert mounted into workloads must keep validating the certs the
	// proxy mints). They are created on first use if absent.
	CACertPath string
	CAKeyPath  string

	// CABundlePath, when set, is where the combined CA bundle (system CAs + the
	// proxy CA) is written for workloads to mount and trust. It must be a stable,
	// workload-mountable path (the runner co-locates it with the daemon binary so
	// the same host path resolves for bind mounts) and is written world-readable.
	// When empty, a private temp file is used (suitable for non-mount callers).
	CABundlePath string

	// AuthToken, when set, additionally requires "Proxy-Authorization: Bearer
	// <token>". Usually empty — isolation is by client IP via the registry.
	AuthToken string
}

// EgressProxyHandle describes the running shared egress proxy.
type EgressProxyHandle struct {
	Addr       string // actual listen address (host:port)
	CACertFile string // combined CA bundle workloads must trust (e.g. via SSL_CERT_FILE)
}

// EnableEgressProxy starts the shared egress proxy — the hostname-aware MITM
// proxy that injects secrets and enforces domain allow lists for workloads
// configured with proxy enforcement — if it isn't already running, and returns
// its address and CA bundle path. It is idempotent: repeated calls return the
// existing handle. The proxy chooses each connection's policy (allow list +
// secrets) from the client IP via the bindings registered with
// RegisterSandboxPolicy.
//
// The returned handle is non-nil and usable whenever the proxy started, even if
// the error is non-nil: a non-nil error with a non-nil handle means the proxy is
// running but one or more already-managed workloads' egress filters could not be
// updated to allow it (those workloads won't reach the proxy until their
// firewall is rebuilt). A nil handle means the proxy failed to start at all.
func (m *Manager) EnableEgressProxy(cfg EgressProxyConfig) (*EgressProxyHandle, error) {
	m.mu.Lock()
	if m.egressProxy != nil {
		h := &EgressProxyHandle{Addr: m.egressProxyAddr, CACertFile: m.proxyCACertFile}
		m.mu.Unlock()
		return h, nil
	}
	m.mu.Unlock()

	ca, err := proxy.LoadOrCreateCA(cfg.CACertPath, cfg.CAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("netleash: loading secret proxy CA: %w", err)
	}
	var caCertFile string
	if cfg.CABundlePath != "" {
		if err := proxy.WriteCombinedCACertTo(ca.PEM, cfg.CABundlePath); err != nil {
			return nil, fmt.Errorf("netleash: writing secret proxy CA bundle: %w", err)
		}
		caCertFile = cfg.CABundlePath
	} else {
		caCertFile, err = proxy.WriteCombinedCACert(ca.PEM)
		if err != nil {
			return nil, fmt.Errorf("netleash: writing secret proxy CA bundle: %w", err)
		}
	}

	registry := proxy.NewRegistry()
	opts := []proxy.Option{
		proxy.WithLogger(m.log.With(slog.String("subcomponent", "egress_proxy"))),
		proxy.WithBindingResolver(registry.Lookup),
	}
	if cfg.AuthToken != "" {
		opts = append(opts, proxy.WithAuthToken(cfg.AuthToken))
	}
	// allowedDomains/injector/clientIP are unused in shared mode — the per-client
	// binding from the registry supplies them.
	server := proxy.NewServer(cfg.ListenAddr, ca, nil, nil, "", opts...)
	addr, err := server.Start()
	if err != nil {
		os.Remove(caCertFile)
		return nil, fmt.Errorf("netleash: starting egress proxy: %w", err)
	}

	m.mu.Lock()
	if m.egressProxy != nil {
		// Lost a race with a concurrent EnableEgressProxy; keep theirs.
		h := &EgressProxyHandle{Addr: m.egressProxyAddr, CACertFile: m.proxyCACertFile}
		m.mu.Unlock()
		server.Close()
		os.Remove(caCertFile)
		return h, nil
	}
	m.egressProxy = server
	m.proxyRegistry = registry
	m.proxyCACertFile = caCertFile
	m.egressProxyAddr = addr
	// Allow the proxy IP on firewalls that already exist (freshly attached or
	// adopted after a restart). Configure only sets ProxyAddr for new/rebuilt
	// firewalls, so without this a workload managed before the proxy was
	// enabled would have its egress filter block the proxy. For entries whose
	// caller requested proxy enforcement while the proxy was down (or that were
	// adopted mid-enforcement), also (re-)apply the web-port gate now that the
	// proxy is reachable.
	var failedFirewalls []string
	for id, e := range m.entries {
		if err := e.fw.AllowIP(addr); err != nil {
			m.log.Error("netleash: failed to allow egress proxy IP on existing firewall", "workload", id, "error", err)
			failedFirewalls = append(failedFirewalls, id)
			continue
		}
		if e.enforceProxy {
			if err := m.applyProxyEnforcementLocked(id, e); err != nil {
				m.log.Error("netleash: failed to enable proxy enforcement on existing firewall", "workload", id, "error", err)
				failedFirewalls = append(failedFirewalls, id)
			}
		}
	}
	m.mu.Unlock()

	m.log.Info("egress proxy enabled", "addr", addr)
	handle := &EgressProxyHandle{Addr: addr, CACertFile: caCertFile}
	if len(failedFirewalls) > 0 {
		// The proxy is up and serves every workload whose firewall was updated,
		// so the handle is returned for the caller to use. But these already-
		// managed workloads couldn't get the proxy IP added to their egress
		// filter, so their traffic to the proxy is dropped and secret injection
		// won't work for them until their firewall is next rebuilt (e.g. a
		// network-settings change re-runs Configure with ProxyAddr). Surface that
		// rather than reporting unqualified success.
		sort.Strings(failedFirewalls)
		return handle, fmt.Errorf("netleash: egress proxy enabled, but %d existing firewall(s) could not allow the proxy IP and won't reach the proxy until rebuilt: %s",
			len(failedFirewalls), strings.Join(failedFirewalls, ", "))
	}
	return handle, nil
}

// SandboxPolicyConfig describes one workload's policy for the shared egress
// proxy: which hosts it may reach through the proxy and (optionally) which
// secrets to inject.
type SandboxPolicyConfig struct {
	// ClientIP is the workload's IP — the demux key the shared proxy uses to find
	// this binding. Required.
	ClientIP string

	// AllowAll lets the workload reach any host through the proxy (for sandboxes
	// with no domain allow list). When false, only AllowedDomains are reachable —
	// callers should include the hosts the workload's secrets target.
	AllowAll       bool
	AllowedDomains []string

	// Resolver supplies the workload's secrets (e.g. secrets.NewAPIResolver,
	// authenticating as the sandbox). Optional: when nil, the binding does no
	// secret injection and only enforces the allow list — the shape used for
	// proxy-enforced workloads without secrets.
	Resolver proxy.SecretResolver

	// CacheTTL bounds how long resolved secrets are cached; non-positive uses the
	// injector default. PlaceholderMarker is the cheap pre-check substring (set to
	// the known placeholder prefix to skip resolution for requests without one).
	// Both are ignored when Resolver is nil.
	CacheTTL          time.Duration
	PlaceholderMarker string
}

// RegisterSandboxPolicy registers (or replaces) the shared proxy's binding for
// workload id, so connections from its ClientIP get that workload's host allow
// list and — when a Resolver is set — its secret injection. EnableEgressProxy
// must have been called first.
func (m *Manager) RegisterSandboxPolicy(id string, cfg SandboxPolicyConfig) error {
	ip := net.ParseIP(cfg.ClientIP)
	if ip == nil {
		return fmt.Errorf("netleash: RegisterSandboxPolicy for %s: invalid client IP %q", id, cfg.ClientIP)
	}

	m.mu.Lock()
	reg := m.proxyRegistry
	m.mu.Unlock()
	if reg == nil {
		return fmt.Errorf("netleash: RegisterSandboxPolicy for %s: egress proxy not enabled", id)
	}

	var injector *proxy.Injector
	if cfg.Resolver != nil {
		injector = proxy.NewResolvingInjector(cfg.Resolver, cfg.CacheTTL, cfg.PlaceholderMarker)
	}
	binding := proxy.NewBinding(id, cfg.AllowAll, cfg.AllowedDomains, injector)
	reg.Register(id, ip, binding)
	m.log.Info("registered sandbox proxy policy", "workload", id, "clientIP", cfg.ClientIP, "allowAll", cfg.AllowAll, "secrets", cfg.Resolver != nil)
	return nil
}

// HasSandboxPolicy reports whether a shared-proxy binding is currently
// registered for workload id. Returns false when the egress proxy is disabled.
func (m *Manager) HasSandboxPolicy(id string) bool {
	m.mu.Lock()
	reg := m.proxyRegistry
	m.mu.Unlock()
	return reg != nil && reg.Has(id)
}

// UnregisterSandboxPolicy removes the shared proxy's binding for workload id.
// Safe to call when id is unknown or the egress proxy is disabled. (Remove also
// does this, so an explicit call is only needed when a workload loses its
// binding without being removed.)
func (m *Manager) UnregisterSandboxPolicy(id string) {
	m.mu.Lock()
	reg := m.proxyRegistry
	srv := m.egressProxy
	m.mu.Unlock()
	if reg == nil {
		return
	}
	ip := reg.Unregister(id)
	// Terminate the workload's active tunnels so the old policy stops applying
	// immediately, not just for new connections.
	if srv != nil && ip != nil {
		srv.CloseClient(ip)
	}
}

// normalizeDomains trims, lowercases, de-duplicates and sorts the input,
// dropping empty entries. Sorting makes equalDomains order-independent.
func normalizeDomains(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// equalDomains reports whether two normalized (sorted) domain lists are equal.
func equalDomains(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// domainsRemoved reports whether any domain in old is absent from updated, i.e.
// the change drops at least one previously-allowed domain (as opposed to a pure
// addition). Used to decide whether the learned-IP cache must be flushed.
func domainsRemoved(old, updated []string) bool {
	set := make(map[string]struct{}, len(updated))
	for _, d := range updated {
		set[d] = struct{}{}
	}
	for _, d := range old {
		if _, ok := set[d]; !ok {
			return true
		}
	}
	return false
}
