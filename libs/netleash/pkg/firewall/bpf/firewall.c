//go:build ignore

#include "common.h"

// ---------------------------------------------------------------------------
// Egress program — domain-based firewall
// ---------------------------------------------------------------------------

// For cgroup_skb/egress, the packet data starts at the IP header (layer 3).
// Return 1 = allow, 0 = drop.
SEC("cgroup_skb/egress")
int firewall_egress(struct __sk_buff *skb) {
	struct iphdr ip;

	// Load the IP header from the socket buffer.
	if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0)
		return 1; // Can't parse → allow

	// IPv6: unfiltered by the IPv4-only allow list, but fail-closed under proxy
	// enforcement (see ipv6_gate_allows). Other versions pass.
	if (ip.version == 6)
		return ipv6_gate_allows(skb, 0);
	if (ip.version != 4)
		return 1;

	__u32 dst_ip = ip.daddr; // Network byte order

	// Always allow loopback (127.0.0.0/8).
	// In network byte order on little-endian: first byte is the lowest byte.
	if ((dst_ip & 0xFF) == 127)
		return 1;

	// Always allow link-local and multicast.
	__u8 first_byte = dst_ip & 0xFF;
	if (first_byte == 169 || (first_byte >= 224 && first_byte <= 239))
		return 1;

	// Filter DNS queries (UDP port 53): only allow queries for allowed domains.
	if (ip.protocol == IPPROTO_UDP) {
		struct udphdr udp;
		int ip_hdr_len = ip.ihl * 4;
		if (bpf_skb_load_bytes(skb, ip_hdr_len, &udp, sizeof(udp)) == 0) {
			if (udp.dest == bpf_htons(53)) {
				int dns_off = ip_hdr_len + sizeof(struct udphdr);

				// Load DNS header and verify it's a query (QR=0).
				struct dns_header dns;
				if (bpf_skb_load_bytes(skb, dns_off, &dns, sizeof(dns)) < 0)
					return 1; // Can't parse → allow

				__u16 flags = bpf_ntohs(dns.flags);
				if (flags & 0x8000)
					return 1; // Response, not query → allow (handled by ingress)

				// Parse QNAME from question section.
				int qname_off = dns_off + sizeof(struct dns_header);
				struct dns_name_key qname = {};

				for (int i = 0; i < MAX_DNS_NAME_LEN; i++) {
					__u8 byte;
					if (bpf_skb_load_bytes(skb, qname_off + i, &byte, 1) < 0)
						return 1;
					qname.name[i] = to_lower(byte);
					if (byte == 0)
						break;
				}

				// Check exact match in allowed_domains.
				if (bpf_map_lookup_elem(&allowed_domains, &qname)) {
					emit_event(EV_ALLOWED, EV_REASON_DNS_ALLOWED_EXACT, dst_ip, udp.dest, ip.protocol, &qname);
					return 1;
				}

				// Check wildcard suffix matching (strip labels progressively).
				// Read suffixes into a scratch buffer so qname keeps the full
				// queried name for logging.
				struct dns_name_key suffix = {};
				int pkt_pos = qname_off;
				for (int l = 0; l < MAX_WILDCARD_LABELS; l++) {
					__u8 llen;
					if (bpf_skb_load_bytes(skb, pkt_pos, &llen, 1) < 0)
						break;
					if (llen == 0)
						break;
					pkt_pos += 1 + llen;

					__u8 next;
					if (bpf_skb_load_bytes(skb, pkt_pos, &next, 1) < 0)
						break;
					if (next == 0)
						break;

					__builtin_memset(&suffix, 0, sizeof(suffix));
					for (int j = 0; j < MAX_DNS_NAME_LEN; j++) {
						__u8 b;
						if (bpf_skb_load_bytes(skb, pkt_pos + j, &b, 1) < 0)
							break;
						suffix.name[j] = to_lower(b);
						if (b == 0)
							break;
					}

					if (bpf_map_lookup_elem(&allowed_wildcards, &suffix)) {
						emit_event(EV_ALLOWED, EV_REASON_DNS_ALLOWED_WILDCARD, dst_ip, udp.dest, ip.protocol, &qname);
						return 1;
					}

					// Cluster-internal zone (e.g. *.cluster.local): pass the
					// query to the resolver. These names resolve inside the
					// cluster and never recurse externally, so allowing the
					// query is exfil-safe and lets Kubernetes search-domain
					// expansion fall through to the allowed bare name instead
					// of stalling on a silently dropped packet.
					if (bpf_map_lookup_elem(&internal_dns_zones, &suffix)) {
						emit_event(EV_ALLOWED, EV_REASON_DNS_ALLOWED_INTERNAL, dst_ip, udp.dest, ip.protocol, &qname);
						return 1;
					}
				}

				// DNS query for non-allowed domain → report and drop.
				emit_event(EV_BLOCKED, EV_REASON_DNS_BLOCKED, dst_ip, udp.dest, ip.protocol, &qname);
				return 0; // Drop
			}
		}
	}

	// Allow egress replies on connections a remote peer initiated into this
	// workload (recorded by the ingress program). Without this, a workload that
	// acts as a server — SSH/terminal (e.g. :22220), toolbox, preview ports —
	// can't answer inbound connections under a domain allow list, because the
	// peer's IP was never learned from a DNS answer.
	if (ip.protocol == IPPROTO_TCP) {
		struct tcphdr tcp;
		int tcp_off = ip.ihl * 4;
		if (bpf_skb_load_bytes(skb, tcp_off, &tcp, sizeof(tcp)) == 0) {
			struct conn_key key = {};
			key.remote_ip = ip.daddr;
			key.remote_port = tcp.dest;
			key.local_port = tcp.source;
			if (bpf_map_lookup_elem(&inbound_conns, &key)) {
				emit_ip_decision(skb, 0, dst_ip, &ip, EV_ALLOWED, EV_REASON_IP_ALLOWED_INBOUND);
				return 1;
			}
		}
	}

	// Egress-proxy enforcement: web ports must go through the hostname-aware
	// proxy (checked after inbound-conn replies, which are never gated, and
	// before the IP allow list, which it deliberately overrides for web ports).
	int gate = check_proxy_gate(skb, 0, &ip, dst_ip);
	if (gate == PROXY_GATE_ALLOW) {
		emit_ip_decision(skb, 0, dst_ip, &ip, EV_ALLOWED, EV_REASON_PROXY_ALLOWED);
		return 1;
	}
	if (gate == PROXY_GATE_DROP) {
		emit_ip_decision(skb, 0, dst_ip, &ip, EV_BLOCKED, EV_REASON_WEB_NOT_PROXIED);
		return 0; // Drop
	}

	// Check if the destination IP is in the whitelist.
	__u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &dst_ip);
	if (allowed) {
		emit_ip_decision(skb, 0, dst_ip, &ip, EV_ALLOWED, EV_REASON_IP_ALLOWED);
		return 1;
	}

	// Blocked — report (de-duplicated per destination) and drop.
	emit_ip_decision(skb, 0, dst_ip, &ip, EV_BLOCKED, EV_REASON_IP_BLOCKED);
	return 0; // Drop
}

// ---------------------------------------------------------------------------
// connect4 program — transparent redirect of web-port egress to the proxy
// ---------------------------------------------------------------------------
//
// Under proxy enforcement, redirecting the connect() destination — rather than
// dropping the packets in the egress program and relying on the workload to have
// set HTTP(S)_PROXY — makes the hostname-aware proxy the transparent path for
// web traffic. This is what lets clients that ignore proxy env vars (Node's
// undici global fetch, Deno, most gRPC/HTTP-2 stacks, JVM without -Dhttp.proxy*)
// keep reaching allowed hosts: their direct connect() to a learned IP:443 is
// rewritten to the proxy's IP:port before a packet leaves the socket, and the
// proxy enforces the allow list on the SNI/Host it observes. The workload never
// has to know a proxy exists. Only standard web ports (TCP 80/443) are
// redirected; every other port keeps the IP-allow-list behavior.
//
// Runs only in cgroup mode (VM/TC-mode workloads have no cgroup connect hook and
// keep the egress-program drop behavior — see check_proxy_gate).

// orig_dst records a redirected socket's original destination, keyed by socket
// cookie, so getpeername4 can report the real peer address back to the workload
// (some clients call getpeername() and would otherwise see the proxy's address).
// LRU self-evicts; entries are only read by getpeername4 on the same socket.
struct orig_dst {
	__u32 ip;   // original destination IPv4, network byte order
	__u16 port; // original destination port, network byte order
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64); // socket cookie
	__type(value, struct orig_dst);
	__uint(max_entries, 65536);
} orig_dst_map SEC(".maps");

SEC("cgroup/connect4")
int firewall_connect4(struct bpf_sock_addr *ctx) {
	// Only TCP is redirected; DNS (UDP 53) and QUIC (UDP 443) are handled by the
	// egress program (QUIC is dropped so clients fall back to TCP).
	if (ctx->protocol != IPPROTO_TCP)
		return 1;

	__u32 zero = 0;
	struct proxy_cfg *cfg = bpf_map_lookup_elem(&proxy_config, &zero);
	if (!cfg || !cfg->enforce || !cfg->proxy_ip)
		return 1; // enforcement off → leave the connect() untouched

	// user_port holds the destination port in network byte order (low 16 bits).
	__u32 dport = ctx->user_port;
	if (dport != bpf_htons(80) && dport != bpf_htons(443))
		return 1; // not a standard web port → not redirected

	// Leave the destinations the egress program always allows directly untouched,
	// so local services and infrastructure endpoints don't get bounced through the
	// proxy: loopback (127/8), link-local incl. cloud metadata (169.254/16) and
	// multicast (224–239). first_byte is the low byte of the network-order address.
	__u8 first_byte = ctx->user_ip4 & 0xFF;
	if (first_byte == 127 || first_byte == 169 ||
	    (first_byte >= 224 && first_byte <= 239))
		return 1;

	// A connect() already aimed at the proxy itself must not be rewritten (the
	// proxy's own upstream dials run outside this cgroup, but the workload may
	// legitimately talk to the proxy address directly).
	if (ctx->user_ip4 == cfg->proxy_ip && dport == cfg->proxy_port)
		return 1;

	// Remember where the workload meant to go so getpeername4 can restore it.
	__u64 cookie = bpf_get_socket_cookie(ctx);
	struct orig_dst d = {};
	d.ip = ctx->user_ip4;
	d.port = (__u16)dport;
	bpf_map_update_elem(&orig_dst_map, &cookie, &d, BPF_ANY);

	// Redirect to the proxy. Both fields are already in network byte order.
	ctx->user_ip4 = cfg->proxy_ip;
	ctx->user_port = cfg->proxy_port;
	return 1;
}

// Requires Linux >= 5.8 (BPF_CGROUP_INET4_GETPEERNAME). The Go setup
// feature-detects the attach type and strips this program on older kernels, so
// cgroup mode keeps working on the documented 5.7 minimum — redirected sockets
// there just observe the proxy's address from getpeername().
SEC("cgroup/getpeername4")
int firewall_getpeername4(struct bpf_sock_addr *ctx) {
	// Report the original destination (not the proxy) for sockets we redirected,
	// so a workload calling getpeername() sees the address it dialed. Sockets we
	// did not redirect have no entry and are left untouched.
	__u64 cookie = bpf_get_socket_cookie(ctx);
	struct orig_dst *d = bpf_map_lookup_elem(&orig_dst_map, &cookie);
	if (!d)
		return 1;
	ctx->user_ip4 = d->ip;
	ctx->user_port = d->port;
	return 1;
}

// ---------------------------------------------------------------------------
// Ingress program — DNS response interception
// ---------------------------------------------------------------------------

// Intercepts DNS responses (UDP src port 53) arriving into the cgroup.
// Parses A records and dynamically populates the allowed_ips map for
// domains that are in the allowed_domains map.
// Always returns 1 (never drops ingress packets).
SEC("cgroup_skb/ingress")
int firewall_dns_ingress(struct __sk_buff *skb) {
	struct iphdr ip;

	if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0)
		return 1;
	if (ip.version != 4)
		return 1;

	int ip_hdr_len = ip.ihl * 4;

	// Record connections a remote peer initiates *into* this workload (an inbound
	// SYN with no ACK) so the egress program can allow the workload's replies.
	// Matching only the bare SYN is deliberate and security-critical: every other
	// TCP packet has ACK set, including the SYN-ACK/ACK/data of workload-INITIATED
	// outbound connections AND the return traffic of an outbound connection to a
	// domain that was later dropped. Recording on those would let a dropped
	// domain's existing connection re-authorize its own egress via the peer's
	// reply packets, defeating the allow-list change. A genuine peer-initiated
	// inbound connection always begins with a bare SYN, so this still covers
	// terminal/SSH/toolbox/preview-port servers.
	if (ip.protocol == IPPROTO_TCP) {
		struct tcphdr tcp;
		if (bpf_skb_load_bytes(skb, ip_hdr_len, &tcp, sizeof(tcp)) == 0) {
			if (tcp.syn && !tcp.ack) {
				struct conn_key key = {};
				key.remote_ip = ip.saddr;
				key.remote_port = tcp.source;
				key.local_port = tcp.dest;
				__u8 one = 1;
				bpf_map_update_elem(&inbound_conns, &key, &one, BPF_ANY);
			}
		}
		return 1;
	}

	if (ip.protocol != IPPROTO_UDP)
		return 1;

	// Check UDP source port is 53 (DNS response).
	struct udphdr udp;
	if (bpf_skb_load_bytes(skb, ip_hdr_len, &udp, sizeof(udp)) < 0)
		return 1;
	if (udp.source != bpf_htons(53))
		return 1;

	int dns_offset = ip_hdr_len + sizeof(struct udphdr);

	// Load DNS header.
	struct dns_header dns;
	if (bpf_skb_load_bytes(skb, dns_offset, &dns, sizeof(dns)) < 0)
		return 1;

	__u16 flags = bpf_ntohs(dns.flags);

	// Must be a response (QR=1) with no error (RCODE=0).
	if (!(flags & 0x8000))
		return 1;
	if ((flags & 0x000F) != 0)
		return 1;

	__u16 qdcount = bpf_ntohs(dns.qdcount);
	__u16 ancount = bpf_ntohs(dns.ancount);

	if (qdcount == 0 || ancount == 0)
		return 1;

	// Parse the question section domain name (first question only).
	// DNS wire format: length-prefixed labels, e.g. \x07example\x03com\x00
	int offset = dns_offset + sizeof(struct dns_header);
	struct dns_name_key qname = {};
	int name_len = 0;

	for (int i = 0; i < MAX_DNS_NAME_LEN; i++) {
		__u8 byte;
		if (bpf_skb_load_bytes(skb, offset + i, &byte, 1) < 0)
			return 1;

		qname.name[i] = to_lower(byte);
		name_len = i + 1;

		if (byte == 0) // Root label — end of name
			break;
	}

	// Lookup domain in allowed_domains map (exact match).
	__u8 *allowed = bpf_map_lookup_elem(&allowed_domains, &qname);

	// If no exact match, try wildcard suffix matching.
	// Re-read labels from the packet (not the stack) to avoid variable-offset
	// stack reads that the BPF verifier rejects.
	// For "api.github.com", strip "api." and check "github.com" in allowed_wildcards,
	// then strip "github." and check "com", etc.
	if (!allowed) {
		int pkt_pos = offset; // packet offset where DNS name starts
		struct dns_name_key suffix = {};

		for (int l = 0; l < MAX_WILDCARD_LABELS; l++) {
			__u8 llen;
			if (bpf_skb_load_bytes(skb, pkt_pos, &llen, 1) < 0)
				break;
			if (llen == 0)
				break;

			// Advance past this label (1-byte length + label bytes).
			pkt_pos += 1 + llen;

			// Check if we've reached the root label (no suffix left).
			__u8 next;
			if (bpf_skb_load_bytes(skb, pkt_pos, &next, 1) < 0)
				break;
			if (next == 0)
				break;

			// Read the suffix into a scratch buffer so qname keeps the full
			// queried name for logging learn events.
			__builtin_memset(&suffix, 0, sizeof(suffix));
			for (int j = 0; j < MAX_DNS_NAME_LEN; j++) {
				__u8 b;
				if (bpf_skb_load_bytes(skb, pkt_pos + j, &b, 1) < 0)
					break;
				suffix.name[j] = to_lower(b);
				if (b == 0)
					break;
			}

			allowed = bpf_map_lookup_elem(&allowed_wildcards, &suffix);
			if (allowed)
				break;
		}

		if (!allowed)
			return 1; // Not in any allowlist, passthrough
	}

	// Skip past the question section: name + QTYPE(2) + QCLASS(2).
	int answer_offset = offset + name_len + 4;

	// Parse answer RRs to extract A record IPs.
	for (int i = 0; i < MAX_ANSWER_RRS; i++) {
		if (i >= ancount)
			break;

		// Skip the answer name (may be a compression pointer or inline).
		__u8 first_byte;
		if (bpf_skb_load_bytes(skb, answer_offset, &first_byte, 1) < 0)
			return 1;

		if ((first_byte & 0xC0) == 0xC0) {
			// Compression pointer — 2 bytes total.
			answer_offset += 2;
		} else {
			// Inline name — skip labels until null or pointer.
			// Use a tight bound (64) since inline answer names are rare
			// and short; most responses use compression pointers.
			for (int j = 0; j < 64; j++) {
				__u8 b;
				if (bpf_skb_load_bytes(skb, answer_offset, &b, 1) < 0)
					return 1;
				answer_offset++;
				if (b == 0)
					break;
				// Name might end with a compression pointer mid-way.
				if ((b & 0xC0) == 0xC0) {
					answer_offset++; // skip the second pointer byte
					break;
				}
			}
		}

		// Read RR fixed fields: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes.
		__u8 rr_fixed[10];
		if (bpf_skb_load_bytes(skb, answer_offset, rr_fixed, 10) < 0)
			return 1;

		__u16 rtype  = ((__u16)rr_fixed[0] << 8) | rr_fixed[1];
		__u16 rclass = ((__u16)rr_fixed[2] << 8) | rr_fixed[3];
		__u16 rdlen  = ((__u16)rr_fixed[8] << 8) | rr_fixed[9];

		answer_offset += 10;

		// A record: TYPE=1, CLASS=1 (IN), RDLENGTH=4.
		if (rtype == 1 && rclass == 1 && rdlen == 4) {
			__u32 addr;
			if (bpf_skb_load_bytes(skb, answer_offset, &addr, 4) < 0)
				return 1;

			// Learn the IP, emitting a learn event only the first time so
			// repeated DNS answers don't spam the log.
			if (!bpf_map_lookup_elem(&allowed_ips, &addr)) {
				__u8 val = 1;
				bpf_map_update_elem(&allowed_ips, &addr, &val, BPF_ANY);
				emit_event(EV_ALLOWED, EV_REASON_DNS_LEARNED, addr, 0, IPPROTO_UDP, &qname);
			}
		}

		// Bound rdlen to prevent verifier issues with large jumps.
		if (rdlen > 512)
			return 1;
		answer_offset += rdlen;
	}

	return 1; // Always allow ingress
}

char _license[] SEC("license") = "GPL";
