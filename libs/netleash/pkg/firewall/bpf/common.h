#ifndef COMMON_H
#define COMMON_H

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ---------------------------------------------------------------------------
// Shared structs and maps
// ---------------------------------------------------------------------------

// Max DNS name length in wire format (including final null label).
// Kept at 128 to stay within verifier complexity budget for nested loops.
// Covers domain names up to ~120 chars which handles virtually all real domains.
#define MAX_DNS_NAME_LEN 128

// event->action: was the packet let through or dropped.
#define EV_ALLOWED 1
#define EV_BLOCKED 0

// event->reason: why the decision was made. Lets userspace log every egress
// request (and DNS learning) with a human-readable cause.
#define EV_REASON_IP_ALLOWED 1           // dst IP was learned from an allowed domain's DNS answer
#define EV_REASON_IP_BLOCKED 2           // dst IP is not in the allow list
#define EV_REASON_DNS_ALLOWED_EXACT 3    // DNS query for an explicitly allowed domain
#define EV_REASON_DNS_ALLOWED_WILDCARD 4 // DNS query matched an allowed wildcard domain
#define EV_REASON_DNS_BLOCKED 5          // DNS query for a domain not in the allow list
#define EV_REASON_DNS_LEARNED 6          // ingress: learned an A-record IP for an allowed domain
#define EV_REASON_DNS_ALLOWED_INTERNAL 7 // DNS query for a cluster-internal zone, passed through to the resolver
#define EV_REASON_IP_ALLOWED_INBOUND 8   // egress reply on a connection a remote peer initiated into the workload
#define EV_REASON_PROXY_ALLOWED 9        // egress to the enforcement proxy itself
#define EV_REASON_WEB_NOT_PROXIED 10     // web-port egress that bypassed the mandatory proxy (dropped)
#define EV_REASON_IPV6_ENFORCED 11       // IPv6 egress dropped under proxy enforcement (IPv6 bypasses the IPv4-only allow list)

// Event sent to userspace describing one egress decision. `name` carries the
// queried domain in DNS wire format for DNS/learn events and is empty otherwise.
struct event {
	__u32 dst_ip;
	__u16 dst_port;
	__u8 protocol;
	__u8 action; // EV_ALLOWED / EV_BLOCKED
	__u8 reason; // EV_REASON_*
	char name[MAX_DNS_NAME_LEN];
} __attribute__((packed));

// Hash map of allowed destination IPv4 addresses.
// Key: IPv4 address in network byte order. Value: 1.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 10000);
} allowed_ips SEC(".maps");

// Ring buffer for sending egress-decision events to userspace.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Tracks the last decision reported per destination IP so verbose logging emits
// one event per (IP, verdict) instead of one per packet. LRU so it self-evicts
// under churn. Populated and read only by the eBPF egress program.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);  // dst IPv4 (network byte order)
	__type(value, __u8); // last reported EV_REASON_*
	__uint(max_entries, 10000);
} reported_ips SEC(".maps");

// Key for the allowed_domains map — DNS wire-format name, lowercased, zero-padded.
struct dns_name_key {
	char name[MAX_DNS_NAME_LEN];
} __attribute__((packed));

// Hash map of allowed domains in DNS wire format (lowercased).
// Key: DNS wire-format name (e.g., \x07example\x03com\x00), zero-padded.
// Value: 1 (presence = domain is allowed).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dns_name_key);
	__type(value, __u8);
	__uint(max_entries, 1000);
} allowed_domains SEC(".maps");

// Hash map of wildcard-allowed parent domains in DNS wire format.
// For "*.github.com", the key is the wire format of "github.com".
// Ingress program strips labels from the queried name and checks suffixes here.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dns_name_key);
	__type(value, __u8);
	__uint(max_entries, 1000);
} allowed_wildcards SEC(".maps");

// Key for the inbound_conns connection-tracking map. Identifies one TCP
// connection. The fields are filled so that an egress reply's
// (daddr, dest, source) produces the same key as the inbound SYN's
// (saddr, source, dest), letting egress match the connection the peer opened.
struct conn_key {
	__u32 remote_ip;   // peer IP, network byte order
	__u16 remote_port; // peer port, network byte order
	__u16 local_port;  // workload's listening port, network byte order
} __attribute__((packed));

// Tracks connections a remote peer initiated *into* the workload (it sent a
// SYN). The ingress program records them; the egress program allows reply
// traffic to these peers so workload-as-server services (SSH/terminal, toolbox,
// preview ports) keep working under a domain allow list. LRU self-evicts.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct conn_key);
	__type(value, __u8);
	__uint(max_entries, 65536);
} inbound_conns SEC(".maps");

// Cluster-internal DNS zones (e.g. "cluster.local"), in DNS wire format. DNS
// queries whose name is a subdomain of one of these are passed through to the
// resolver instead of dropped: such names resolve authoritatively inside the
// cluster and never recurse to the public internet, so allowing the query is
// exfil-safe — while dropping them breaks Kubernetes search-domain resolution of
// allowed external domains. Keyed like allowed_wildcards (suffix match).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dns_name_key);
	__type(value, __u8);
	__uint(max_entries, 64);
} internal_dns_zones SEC(".maps");

// Egress-proxy enforcement settings, written by userspace. When `enforce` is
// set, traffic on the standard web ports (TCP 80/443, UDP 443) may only go to
// the proxy itself — the hostname-aware MITM proxy becomes the mandatory path
// for HTTP(S), enforcing the domain allow list by SNI/Host instead of by
// DNS-learned IP (which is spoofable via shared IPs / domain fronting). All
// other protocols and ports keep the IP-allowlist behavior.
//
// In cgroup mode this is achieved primarily by the connect4 program, which
// transparently rewrites a web-port connect() to the proxy (so clients that
// ignore HTTP(S)_PROXY still route through it — see firewall.c). The egress
// program's drop path below is the backstop for any web-port packet that reaches
// egress without having been redirected (TC mode, which has no connect hook; or a
// socket already connected before the filter attached).
struct proxy_cfg {
	__u32 proxy_ip;   // proxy IPv4, network byte order (0 = none)
	__u16 proxy_port; // proxy port, network byte order
	__u8 enforce;     // 1 = web-port egress must go to the proxy
	__u8 pad;
} __attribute__((packed));

// Single-entry array holding the proxy enforcement settings (index 0).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct proxy_cfg);
	__uint(max_entries, 1);
} proxy_config SEC(".maps");

// DNS header (12 bytes) — RFC 1035 Section 4.1.1
struct dns_header {
	__u16 id;
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
};

// Max answer RRs to parse (verifier bound).
#define MAX_ANSWER_RRS 16

// Max label levels to check for wildcard suffix matching (e.g., a.b.c.example.com = 5).
#define MAX_WILDCARD_LABELS 10

static __always_inline char to_lower(__u8 c) {
	if (c >= 'A' && c <= 'Z')
		return c + ('a' - 'A');
	return c;
}

// emit_event pushes one decision event to userspace. When `name` is non-NULL
// (DNS / learn events) the queried domain is copied in; otherwise it is zeroed.
static __always_inline void emit_event(__u8 action, __u8 reason, __u32 dst_ip,
                                       __u16 dst_port, __u8 protocol,
                                       const struct dns_name_key *name) {
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->dst_ip = dst_ip;
	e->dst_port = dst_port;
	e->protocol = protocol;
	e->action = action;
	e->reason = reason;
	if (name)
		__builtin_memcpy(e->name, name->name, sizeof(e->name));
	else
		__builtin_memset(e->name, 0, sizeof(e->name));
	bpf_ringbuf_submit(e, 0);
}

// emit_ip_decision reports an IP-level egress verdict, de-duplicated per
// (dst_ip, verdict): a steady flow logs once instead of once per packet, and a
// changed verdict re-emits. `l3_off` is the byte offset of the IP header in skb
// (0 for cgroup_skb, ETH_HLEN for TC). The destination port is best-effort.
static __always_inline void emit_ip_decision(struct __sk_buff *skb, int l3_off,
                                             __u32 dst_ip, const struct iphdr *ip,
                                             __u8 action, __u8 reason) {
	__u8 *last = bpf_map_lookup_elem(&reported_ips, &dst_ip);
	if (last && *last == reason)
		return; // already reported this verdict for this destination
	bpf_map_update_elem(&reported_ips, &dst_ip, &reason, BPF_ANY);

	__u16 dst_port = 0;
	int l4_off = l3_off + ip->ihl * 4;
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr tcp;
		if (bpf_skb_load_bytes(skb, l4_off, &tcp, sizeof(tcp)) == 0)
			dst_port = tcp.dest;
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr udp;
		if (bpf_skb_load_bytes(skb, l4_off, &udp, sizeof(udp)) == 0)
			dst_port = udp.dest;
	}
	emit_event(action, reason, dst_ip, dst_port, ip->protocol, NULL);
}

// Proxy-gate verdicts returned by check_proxy_gate.
#define PROXY_GATE_NONE 0  // no decision — fall through to the IP allow list
#define PROXY_GATE_ALLOW 1 // traffic to the enforcement proxy itself
#define PROXY_GATE_DROP 2  // web-port traffic bypassing the mandatory proxy

// check_proxy_gate applies egress-proxy enforcement: when enabled (see struct
// proxy_cfg), traffic to the proxy's IP:port is allowed and traffic on the
// standard web ports — TCP 80/443 and UDP 443 (QUIC) — to anywhere else is
// dropped, even when the destination IP was DNS-learned. This forces HTTP(S)
// through the hostname-aware proxy, which enforces the domain allow list on
// the actual requested host, closing the shared-IP / domain-fronting gap of
// pure IP allowlisting. Everything else is left to the caller's IP checks.
static __always_inline int check_proxy_gate(struct __sk_buff *skb, int l3_off,
                                            const struct iphdr *ip, __u32 dst_ip) {
	__u32 zero = 0;
	struct proxy_cfg *cfg = bpf_map_lookup_elem(&proxy_config, &zero);
	if (!cfg || !cfg->enforce)
		return PROXY_GATE_NONE;

	__u16 dst_port;
	int l4_off = l3_off + ip->ihl * 4;
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr tcp;
		if (bpf_skb_load_bytes(skb, l4_off, &tcp, sizeof(tcp)) < 0)
			return PROXY_GATE_NONE;
		dst_port = tcp.dest;
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr udp;
		if (bpf_skb_load_bytes(skb, l4_off, &udp, sizeof(udp)) < 0)
			return PROXY_GATE_NONE;
		dst_port = udp.dest;
	} else {
		return PROXY_GATE_NONE;
	}

	// The proxy itself is always reachable (any protocol on its exact IP:port).
	if (cfg->proxy_ip && dst_ip == cfg->proxy_ip && dst_port == cfg->proxy_port)
		return PROXY_GATE_ALLOW;

	if (ip->protocol == IPPROTO_TCP &&
	    (dst_port == bpf_htons(80) || dst_port == bpf_htons(443)))
		return PROXY_GATE_DROP;
	// UDP 443 (QUIC/HTTP3) would tunnel HTTPS past the proxy; the proxy speaks
	// HTTP/1.1 CONNECT only, so drop it and let clients fall back to TCP.
	if (ip->protocol == IPPROTO_UDP && dst_port == bpf_htons(443))
		return PROXY_GATE_DROP;

	return PROXY_GATE_NONE;
}

// ipv6_gate_allows decides IPv6 egress under proxy enforcement. This firewall's
// domain allowlisting is IPv4-only (DNS A-record learning), which historically
// left IPv6 unfiltered — on a dual-stack host an allowed domain's AAAA record
// (or any raw IPv6 destination) is a complete bypass of the allow list AND the
// web-port proxy gate. With enforcement on we therefore fail closed: only
// loopback (::1), link-local (fe80::/10) and multicast (ff00::/8, needed for
// neighbor discovery) IPv6 egress is allowed; everything else is dropped. The
// workload reaches the proxy over IPv4, and the proxy may still dial IPv6
// upstreams from its own network context. With enforcement off, the legacy
// pass-through behavior is preserved. `l3_off` is the IPv6 header offset.
// Returns 1 to allow, 0 to drop.
static __always_inline int ipv6_gate_allows(struct __sk_buff *skb, int l3_off) {
	__u32 zero = 0;
	struct proxy_cfg *cfg = bpf_map_lookup_elem(&proxy_config, &zero);
	if (!cfg || !cfg->enforce)
		return 1;

	// IPv6 destination address sits at bytes 24..39 of the fixed header.
	__u8 dst[16];
	if (bpf_skb_load_bytes(skb, l3_off + 24, dst, sizeof(dst)) < 0)
		return 1; // can't parse → keep legacy allow (never break non-IP frames)

	// fe80::/10 link-local and ff00::/8 multicast (NDP, MLD).
	if (dst[0] == 0xff)
		return 1;
	if (dst[0] == 0xfe && (dst[1] & 0xc0) == 0x80)
		return 1;
	// ::1 loopback.
	int nonzero = 0;
	for (int i = 0; i < 15; i++)
		nonzero |= dst[i];
	if (!nonzero && dst[15] == 1)
		return 1;

	// Report once per verdict change (the event struct is IPv4-shaped, so a
	// sentinel key in reported_ips stands in for "IPv6 egress").
	__u32 key = 0xffffffff;
	__u8 reason = EV_REASON_IPV6_ENFORCED;
	__u8 *last = bpf_map_lookup_elem(&reported_ips, &key);
	if (!last || *last != reason) {
		bpf_map_update_elem(&reported_ips, &key, &reason, BPF_ANY);
		emit_event(EV_BLOCKED, EV_REASON_IPV6_ENFORCED, 0, 0, 0, NULL);
	}
	return 0;
}

#endif // COMMON_H
