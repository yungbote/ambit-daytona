# netleash

Kernel-level network containment for AI agents and sandboxed workloads. Netleash uses eBPF to enforce domain-based egress filtering, ensuring that untrusted code can only reach explicitly allowed destinations — and never sees real API secrets.

## How it works

Netleash attaches eBPF programs to filter all outbound network traffic at the kernel level. It supports two attachment modes:

- **Cgroup mode** (`cgroup_skb`) — attaches to a Linux cgroup, filtering traffic for all processes in that cgroup. Used for process wrapping, container attach, and cgroup attach.
- **Interface mode** (`TC/TCX`) — attaches to a network interface (veth, tap), filtering all traffic traversing that interface. Used for VMs running in network namespaces where cgroup-based filtering doesn't apply.

Both modes use the same filtering logic:

1. **Egress filter** — drops all outbound packets except those destined for allowed IPs. DNS queries for non-allowed domains are blocked before they leave the host (preventing DNS exfiltration). Two exceptions keep server workloads usable under an allow list: replies on connections a remote peer initiated _into_ the workload are allowed (so SSH/terminal, toolbox, and preview ports keep working — see the connection tracking below), and DNS queries for configured cluster-internal zones (`InternalDNSZones`, e.g. `cluster.local`) are passed through to the resolver rather than dropped.

2. **DNS response interceptor** — watches incoming DNS responses for allowed domains and dynamically populates the IP allowlist. This means you configure domains, not IPs — and the filter adapts as DNS records change.

3. **Inbound connection tracking** — the ingress program records connections a remote peer opens to the workload (inbound `SYN`). The egress program allows the workload's reply traffic on exactly those connections, so a workload acting as a server can answer without its peer's IP ever being DNS-learned. Workload-initiated outbound connections are unaffected (they go through the IP allowlist as usual).

4. **MITM proxy** (optional) — an ephemeral-CA HTTPS proxy that intercepts outbound requests and replaces placeholder values with real secrets on the wire. The sandboxed process sees `__LEASH_SECRET_a1b2c3...` in its environment; the proxy swaps it for `sk-real-key` before the request reaches the upstream API. The process never has access to the actual secret.

5. **Proxy-enforced allow list** (optional, `--enforce-proxy`) — hardens the domain allow list by making the hostname-aware proxy the _mandatory_ path for web traffic. IP-based allowlisting alone can be sidestepped when an allowed domain shares IPs with other sites (CDNs, shared hosting, domain fronting): once a DNS answer for an allowed domain populates `allowed_ips`, any traffic to those IPs passes, whatever hostname it actually targets. With enforcement on (cgroup mode), an eBPF `connect4` hook **transparently redirects** TCP 80/443 `connect()` calls to the proxy — the workload never has to honor `HTTP(S)_PROXY`, so clients that ignore proxy env vars (Node's `fetch`/undici, Deno, most gRPC stacks) route through it too. The proxy enforces the allow list on the hostname the connection actually names (TLS SNI, CONNECT host, or `Host` header). A `getpeername4` hook (Linux ≥ 5.8; skipped on older kernels) reports the workload's original destination so it isn't surprised to find it "connected" to the proxy. QUIC (UDP 443) is dropped so clients fall back to TCP; the egress-filter drop path remains the backstop for web-port packets that reach egress un-redirected (TC/VM mode, or sockets opened before the filter attached). Non-web protocols (SSH, databases, gRPC on non-web ports) keep the zero-overhead learned-IP path.

   **Security exception — local and link-local destinations.** Destinations the egress filter always passes directly are deliberately _not_ redirected through the proxy: loopback (`127.0.0.0/8`), the link-local range (`169.0.0.0/8` pass-through, which includes the cloud instance metadata endpoint `169.254.169.254`) and multicast (`224.0.0.0/4`). This keeps local services and infrastructure endpoints working, but it means hostname enforcement does **not** apply to them — in particular, a workload can reach the cloud metadata service directly. If the workload must not access instance metadata, block it at the infrastructure level (e.g. require IMDSv2 with a hop limit of 1, disable the instance metadata endpoint, or use provider network policy).

   **Splice vs. MITM.** The proxy only terminates TLS (MITM) for connections to hosts that have a secret mapped — where it must see the plaintext to inject. Every other allowed connection is **spliced** through end-to-end: the proxy verifies the SNI against the allow list, resolves and dials that hostname itself (defeating shared-IP/fronting), and copies bytes without decrypting. Because the client completes real TLS with the real origin, certificate pinning, ALPN/HTTP-2, and WebSockets all keep working on spliced connections — MITM (and its CA-trust requirement) is confined to secret-injection hosts.

```
┌─────────────────────────────────────────────────────────┐
│  Sandboxed Process                                      │
│  OPENAI_API_KEY=__LEASH_SECRET_a1b2c3__                 │
│  HTTPS_PROXY=http://127.0.0.1:18080                     │
│                                                         │
│  curl https://api.openai.com/v1/chat/completions        │
│       -H "Authorization: Bearer $OPENAI_API_KEY"        │
└──────────────────────┬──────────────────────────────────┘
                       │
              ┌────────▼────────┐
              │  eBPF egress    │  ← kernel-level, can't be bypassed
              │  filter (cgroup)│     from inside the cgroup
              │                 │
              │  ✓ api.openai.com (DNS resolved → IP allowed)
              │  ✗ evil.com     (blocked, event emitted)
              │  ✗ DNS exfil    (query for evil.com dropped)
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │  MITM Proxy     │  ← replaces placeholder with real secret
              │  (ephemeral CA) │     before forwarding to upstream
              │                 │
              │  Authorization: Bearer sk-real-key-here
              └────────┬────────┘
                       │
                       ▼
              api.openai.com
```

## Features

- **Domain-based egress filtering** — allow by domain name, not IP. Supports exact match and `*.example.com` wildcards
- **Proxy-enforced allow list** — `--enforce-proxy` gates web ports (TCP 80/443, UDP 443) in eBPF so HTTP(S) can only go through the MITM proxy, which enforces the allow list on the requested hostname — closing the shared-IP/domain-fronting gap of IP-based filtering (loopback, link-local incl. cloud metadata, and multicast destinations are exempt — see above)
- **DNS exfiltration prevention** — outbound DNS queries are filtered against the allowlist in the eBPF program itself; queries for unauthorized domains are dropped at the kernel level
- **Secret injection** — MITM proxy replaces placeholders with real secrets on the wire, scoped to specific hosts. The sandboxed process never sees real credentials
- **Interface mode (TC eBPF)** — attach to any network interface (veth, tap) using TC/TCX programs. Filters VM traffic in network namespaces where cgroup-based filtering doesn't apply
- **Multiple operation modes** — wrap a process, attach to a cgroup, attach to a Docker container, attach to a network interface, or run as a standalone proxy server
- **JVM support** — auto-generates PKCS12 truststores and sets `JAVA_TOOL_OPTIONS` for Java applications that ignore `*_PROXY` env vars
- **Proxy authentication** — optional `Proxy-Authorization: Bearer <token>` with constant-time comparison
- **Per-container IP ACL** — in container mode, proxy access is restricted to the container's IP address
- **Blocked connection events** — ring buffer events for every blocked packet, with callbacks or structured logging

## Requirements

- Linux with cgroup v2 (for cgroup/process/container modes)
- Root or `CAP_BPF` + `CAP_SYS_ADMIN` (for eBPF and cgroup operations)
- Kernel 5.7+ (for `CLONE_INTO_CGROUP` support in process wrapper mode)
- Kernel 6.6+ (for TCX support in interface mode)
- Server mode requires no special privileges

### Build dependencies

- Go 1.25+
- clang (for eBPF C compilation)
- libbpf-dev (or kernel headers with BPF helpers)

## Installation

```bash
git clone https://github.com/daytona/netleash.git
cd netleash
make build
# Binary at bin/netleash
```

## Usage

### Process wrapper mode

Run a command inside a network jail. Only traffic to allowed domains gets through:

```bash
sudo netleash --allow api.openai.com -- curl https://api.openai.com/v1/models
```

With wildcard domains:

```bash
sudo netleash --allow "*.github.com" --allow api.openai.com -- python agent.py
```

### Secret injection

Inject API keys without exposing them to the sandboxed process:

```bash
sudo netleash \
  --allow api.openai.com \
  --secret OPENAI_API_KEY=sk-real-key:api.openai.com \
  -- python agent.py
```

The process sees `OPENAI_API_KEY=__LEASH_SECRET_<random>__` in its environment. When it makes a request to `api.openai.com`, the MITM proxy swaps the placeholder for `sk-real-key` in headers and body before forwarding upstream.

### Secret file

Avoid exposing secrets in `/proc/<pid>/cmdline` by reading them from a file:

```bash
sudo netleash \
  --allow api.openai.com \
  --secret-file /etc/netleash/secrets.conf \
  -- python agent.py
```

Secret file format (`#` comments, one per line):

```
# secrets.conf
OPENAI_API_KEY=sk-real-key:api.openai.com
GITHUB_TOKEN=ghp-xxx:api.github.com,github.com
```

Read from stdin with `--secret-file -` for piping from a secret manager.

### Proxy-enforced allow list

By default, allowed traffic flows at kernel speed against the DNS-learned IP allowlist. `--enforce-proxy` trades that zero-overhead path (for web ports only) for hostname-level enforcement: the MITM proxy starts even without secrets, the child is wired to it via `HTTP(S)_PROXY` + `SSL_CERT_FILE`, and the eBPF filter drops any TCP 80/443 or UDP 443 packet that isn't addressed to the proxy — so a process that ignores the proxy env vars is blocked rather than able to reach an allowed domain's shared IP under a different hostname:

```bash
sudo netleash --allow api.openai.com --enforce-proxy -- python agent.py
```

In cgroup mode this no longer depends on the process honoring the proxy env vars: the `connect4` hook transparently redirects its web-port connections to the proxy. Connections to hosts without a mapped secret are spliced end-to-end, so certificate pinning, HTTP-2/gRPC and WebSockets keep working there; only secret-injection hosts are MITM'd (and only those require the workload to trust the proxy CA). Caveats: QUIC/HTTP3 is blocked (clients fall back to TCP); non-web ports are unaffected and still enforced by IP; certificate pinning still fails for a host that has a secret mapped (it is MITM'd). Because the allow list is IPv4-only (DNS A-record learning), enforcement also drops all non-local IPv6 egress — on a dual-stack host an allowed domain's AAAA record would otherwise bypass both the allow list and the gate entirely.

### Container mode

Attach to a running Docker container — the firewall applies instantly to all processes in the container:

```bash
sudo netleash --allow api.openai.com --container my-sandbox
```

With secret injection into the container:

```bash
sudo netleash \
  --allow api.openai.com \
  --secret OPENAI_API_KEY=sk-real-key:api.openai.com \
  --container my-sandbox
```

The proxy binds to the Docker bridge gateway IP, and the container receives env vars via an injected file at `/tmp/.netleash-env`. Run `source /tmp/.netleash-env` inside the container to activate.

### Interface mode (TC eBPF)

Attach to a network interface using TC/TCX eBPF programs. This filters all traffic traversing the interface — useful for VMs running in network namespaces where cgroup-based filtering doesn't apply.

netleash resolves the interface by name in its current network namespace, so **you must run netleash inside the netns where the target interface exists**. For VMs that run inside a dedicated network namespace (e.g., Firecracker with a tap device in a netns), use `ip netns exec` or `nsenter` to enter the namespace before launching netleash.

For a veth interface (standard direction semantics):

```bash
sudo netleash --allow api.openai.com --interface veth0
```

For a tap device (e.g., Firecracker VM tap), use `--tap` to swap TC directions since VM-originated traffic arrives as ingress on the tap:

```bash
sudo netleash --allow api.openai.com --interface tap0 --tap
```

With secret injection:

```bash
sudo netleash \
  --allow api.openai.com \
  --secret OPENAI_API_KEY=sk-real-key:api.openai.com \
  --interface veth0
```

#### VM in a network namespace

A typical Firecracker setup places each VM in its own netns with a bridge, veth pair, and tap device:

```
Host netns                          VM netns (e.g., fc-vm-1)
──────────                          ────────────────────────
fcbr0 (bridge)                      veth0 ←─── host-side veth
  └── host-veth ──────────────────→   │
                                    tap0 ──── Firecracker VM
                                      │         └── guest eth0
                                    iptables MASQUERADE
```

To filter VM traffic, run netleash inside the VM's netns and attach to either the veth or tap:

```bash
# Enter the netns and attach to tap0 (filters VM traffic directly)
sudo ip netns exec fc-vm-1 netleash --allow api.openai.com --interface tap0 --tap

# Or attach to veth0 (filters at the namespace boundary)
sudo ip netns exec fc-vm-1 netleash --allow api.openai.com --interface veth0
```

Use `--tap` only when attaching to a tap device — it swaps the TC egress/ingress directions because the kernel's perspective on tap traffic is inverted relative to the VM's. On a veth, standard directions apply.

If the netns was created with `ip netns add`, you can use `ip netns exec`. For namespaces created by a container runtime without a named entry, use `nsenter --net=/proc/<pid>/ns/net` where `<pid>` is a process running inside the namespace.

### Cgroup attach mode

Attach to any cgroup v2 path directly:

```bash
sudo netleash --allow example.com --cgroup /sys/fs/cgroup/my-scope
```

### Standalone proxy mode (no eBPF)

Run as a standalone HTTPS proxy — no root required, no eBPF. Applications configure their proxy settings to point at it:

```bash
netleash --server --listen 0.0.0.0:8080 \
  --allow api.openai.com \
  --secret-file secrets.conf
```

The proxy enforces the domain allowlist and injects secrets. A Bearer token is auto-generated when listening on non-localhost addresses:

```bash
# Client usage:
HTTPS_PROXY=http://proxy-host:8080 \
SSL_CERT_FILE=/path/to/ca.pem \
curl https://api.openai.com/v1/models
```

### Proxy authentication

Require a Bearer token for proxy access:

```bash
sudo netleash \
  --allow api.openai.com \
  --proxy-token my-secret-token \
  -- python agent.py
```

## CLI reference

```
Usage:
  netleash [options] -- <command> [args...]     (process wrapper mode)
  netleash [options] --cgroup <path>            (attach to cgroup)
  netleash [options] --container <id>           (attach to Docker container)
  netleash [options] --interface <name>         (attach to network interface)
  netleash [options] --server                   (standalone proxy mode)

Options:
  --allow <domain>       Domain to whitelist (repeatable, comma-separated)
  --secret <spec>        Secret in NAME=VALUE:host1,host2 format (repeatable)
  --secret-file <path>   Read secrets from file (use - for stdin)
  --proxy-token <token>  Require Bearer token for proxy authentication
  --enforce-proxy        Gate web ports (TCP 80/443, UDP 443) in eBPF so HTTP(S)
                         must go through the MITM proxy (hostname enforcement);
                         starts the proxy even without secrets
  --server               Run as standalone proxy (no eBPF, no root)
  --listen <addr>        Proxy listen address, server mode (default 127.0.0.1:8080)
  --cgroup <path>        Attach to existing cgroup path
  --container <id>       Attach to Docker container by ID or name
  --interface <name>     Attach TC eBPF to network interface (e.g., tap0, veth0)
  --tap                  Swap TC directions for tap devices (use with --interface)
  --dns <server>         Custom DNS server for proxy resolution (e.g., 8.8.8.8)
  -v                     Verbose output
```

## Go library

Netleash can be used as a Go library for programmatic control:

```go
import "github.com/daytonaio/daytona/libs/netleash/pkg/jail"

exitCode, err := jail.Exec(ctx, jail.Config{
    Domains: []string{"api.openai.com", "*.github.com"},
    Secrets: []jail.Secret{{
        Name:  "OPENAI_API_KEY",
        Value: "sk-real-key",
        Hosts: []string{"api.openai.com"},
    }},
    OnBlocked: func(dstIP string, dstPort uint16, proto string) {
        log.Printf("blocked: %s:%d (%s)", dstIP, dstPort, proto)
    },
}, []string{"python", "agent.py"})
```

## How DNS exfiltration prevention works

A common attack against domain-based firewalls is encoding data in DNS queries — e.g., querying `stolen-data.attacker.com`. Even if the IP is blocked, the DNS query itself reaches an attacker-controlled nameserver and leaks data.

Netleash prevents this by filtering DNS queries in the eBPF egress program. Before any UDP port 53 packet leaves the cgroup (or interface in TC mode), the program:

1. Parses the DNS question section to extract the queried domain name
2. Checks it against the `allowed_domains` and `allowed_wildcards` eBPF maps
3. If the domain isn't allowed, drops the packet and emits a ring buffer event

This happens entirely in the kernel — no userspace DNS component, no race conditions.

## Architecture

```
pkg/
├── firewall/              # eBPF program management, map population, event reading
│   ├── bpf/
│   │   ├── common.h       # Shared eBPF structs, maps, constants (used by both programs)
│   │   ├── firewall.c     # Cgroup eBPF programs (cgroup_skb/egress + ingress)
│   │   └── firewall_tc.c  # TC eBPF programs (tc/egress + ingress for interfaces)
│   ├── firewall.go        # Cgroup + TC eBPF lifecycle, dual-mode setup
│   ├── maps.go            # Uniform map accessor for cgroup and TC modes
│   ├── resolver.go        # Domain → IP resolution for eBPF maps
│   └── events.go          # Ring buffer event reader
├── jail/                  # High-level jailing API (process wrapper mode)
│   └── jail.go            # Exec(), New(), Setup(), Run(), Close()
└── proxy/                 # MITM proxy with secret injection
    ├── proxy.go           # Forward proxy server (CONNECT + HTTP)
    ├── injector.go        # Placeholder → real secret replacement
    ├── certs.go           # Ephemeral CA, per-host cert minting, trust stores
    └── options.go         # Functional options (WithAuthToken, WithLogger)

internal/
└── container/             # Docker-specific operations (cgroup resolve, env inject)

cmd/
└── netleash/              # CLI entry point
```

## Development

```bash
# Generate eBPF Go bindings from C source
make generate

# Build
make build

# Run unit tests
make test-unit

# Run e2e tests (requires root)
make test-e2e
```

## License

[MIT](LICENSE)
