//go:build ignore

#include "common.h"
#include <linux/pkt_cls.h>

// TC programs operate on L2 frames — IP header starts after the ethernet header.
#define L3_OFF ETH_HLEN

// ---------------------------------------------------------------------------
// TC Egress program — domain-based firewall (interface attachment)
// ---------------------------------------------------------------------------

// For TC, the packet data starts at the ethernet header (layer 2).
// Return TC_ACT_OK = allow, TC_ACT_SHOT = drop.
SEC("tc")
int firewall_tc_egress(struct __sk_buff *skb) {
	struct iphdr ip;

	// Load the IP header (after ethernet header).
	if (bpf_skb_load_bytes(skb, L3_OFF, &ip, sizeof(ip)) < 0)
		return TC_ACT_OK; // Can't parse → allow

	// IPv6: unfiltered by the IPv4-only allow list, but fail-closed under proxy
	// enforcement (see ipv6_gate_allows). Other versions pass.
	if (ip.version == 6)
		return ipv6_gate_allows(skb, L3_OFF) ? TC_ACT_OK : TC_ACT_SHOT;
	if (ip.version != 4)
		return TC_ACT_OK;

	__u32 dst_ip = ip.daddr; // Network byte order

	// Always allow loopback (127.0.0.0/8).
	if ((dst_ip & 0xFF) == 127)
		return TC_ACT_OK;

	// Always allow link-local and multicast.
	__u8 first_byte = dst_ip & 0xFF;
	if (first_byte == 169 || (first_byte >= 224 && first_byte <= 239))
		return TC_ACT_OK;

	// Always allow RFC1918 private IPs — TC/interface mode filters exfiltration
	// to the public internet; internal traffic (management, hypervisor, SSH) must pass.
	// 10.0.0.0/8
	if (first_byte == 10)
		return TC_ACT_OK;
	// 172.16.0.0/12
	if (first_byte == 172) {
		__u8 second_byte = (dst_ip >> 8) & 0xFF;
		if (second_byte >= 16 && second_byte <= 31)
			return TC_ACT_OK;
	}
	// 192.168.0.0/16
	if (first_byte == 192 && ((dst_ip >> 8) & 0xFF) == 168)
		return TC_ACT_OK;

	int unrestricted = unrestricted_egress_enabled();

	// Filter DNS queries (UDP port 53): only allow queries for allowed domains.
	if (ip.protocol == IPPROTO_UDP) {
		struct udphdr udp;
		int ip_hdr_len = L3_OFF + ip.ihl * 4;
		if (bpf_skb_load_bytes(skb, ip_hdr_len, &udp, sizeof(udp)) == 0) {
			if (udp.dest == bpf_htons(53)) {
				// Open-network proxy policies do not restrict DNS.
				if (unrestricted)
					return TC_ACT_OK;

				int dns_off = ip_hdr_len + sizeof(struct udphdr);

				// Load DNS header and verify it's a query (QR=0).
				struct dns_header dns;
				if (bpf_skb_load_bytes(skb, dns_off, &dns, sizeof(dns)) < 0)
					return TC_ACT_OK; // Can't parse → allow

				__u16 flags = bpf_ntohs(dns.flags);
				if (flags & 0x8000)
					return TC_ACT_OK; // Response, not query → allow

				// Parse QNAME from question section.
				int qname_off = dns_off + sizeof(struct dns_header);
				struct dns_name_key qname = {};

				for (int i = 0; i < MAX_DNS_NAME_LEN; i++) {
					__u8 byte;
					if (bpf_skb_load_bytes(skb, qname_off + i, &byte, 1) < 0)
						return TC_ACT_OK;
					qname.name[i] = to_lower(byte);
					if (byte == 0)
						break;
				}

				// Check exact match in allowed_domains.
				if (bpf_map_lookup_elem(&allowed_domains, &qname)) {
					emit_event(EV_ALLOWED, EV_REASON_DNS_ALLOWED_EXACT, dst_ip, udp.dest, ip.protocol, &qname);
					return TC_ACT_OK;
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
						return TC_ACT_OK;
					}
				}

				// DNS query for non-allowed domain → report and drop.
				emit_event(EV_BLOCKED, EV_REASON_DNS_BLOCKED, dst_ip, udp.dest, ip.protocol, &qname);
				return TC_ACT_SHOT; // Drop
			}
		}
	}

	// Egress-proxy enforcement: web ports must go through the hostname-aware
	// proxy. Private/link-local ranges were already allowed above, so this only
	// gates traffic bound for the public internet; the proxy itself sits on an
	// RFC1918 gateway address and stays reachable regardless.
	int gate = check_proxy_gate(skb, L3_OFF, &ip, dst_ip);
	if (gate == PROXY_GATE_ALLOW) {
		emit_ip_decision(skb, L3_OFF, dst_ip, &ip, EV_ALLOWED, EV_REASON_PROXY_ALLOWED);
		return TC_ACT_OK;
	}
	if (gate == PROXY_GATE_DROP) {
		emit_ip_decision(skb, L3_OFF, dst_ip, &ip, EV_BLOCKED, EV_REASON_WEB_NOT_PROXIED);
		return TC_ACT_SHOT; // Drop
	}

	// TC cannot transparently redirect connects, but it still prevents a client
	// from bypassing the configured proxy on web ports. Non-web IPv4 remains open.
	if (unrestricted)
		return TC_ACT_OK;

	// Check if the destination IP is in the whitelist.
	__u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &dst_ip);
	if (allowed) {
		emit_ip_decision(skb, L3_OFF, dst_ip, &ip, EV_ALLOWED, EV_REASON_IP_ALLOWED);
		return TC_ACT_OK;
	}

	// Blocked — report (de-duplicated per destination) and drop.
	emit_ip_decision(skb, L3_OFF, dst_ip, &ip, EV_BLOCKED, EV_REASON_IP_BLOCKED);
	return TC_ACT_SHOT; // Drop
}

// ---------------------------------------------------------------------------
// TC Ingress program — DNS response interception (interface attachment)
// ---------------------------------------------------------------------------

// Intercepts DNS responses (UDP src port 53) arriving on the interface.
// Parses A records and dynamically populates the allowed_ips map for
// domains that are in the allowed_domains map.
// Always returns TC_ACT_OK (never drops packets).
SEC("tc")
int firewall_tc_dns_ingress(struct __sk_buff *skb) {
	struct iphdr ip;

	if (bpf_skb_load_bytes(skb, L3_OFF, &ip, sizeof(ip)) < 0)
		return TC_ACT_OK;
	if (ip.version != 4)
		return TC_ACT_OK;
	if (ip.protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	int ip_hdr_len = L3_OFF + ip.ihl * 4;

	// Check UDP source port is 53 (DNS response).
	struct udphdr udp;
	if (bpf_skb_load_bytes(skb, ip_hdr_len, &udp, sizeof(udp)) < 0)
		return TC_ACT_OK;
	if (udp.source != bpf_htons(53))
		return TC_ACT_OK;

	int dns_offset = ip_hdr_len + sizeof(struct udphdr);

	// Load DNS header.
	struct dns_header dns;
	if (bpf_skb_load_bytes(skb, dns_offset, &dns, sizeof(dns)) < 0)
		return TC_ACT_OK;

	__u16 flags = bpf_ntohs(dns.flags);

	// Must be a response (QR=1) with no error (RCODE=0).
	if (!(flags & 0x8000))
		return TC_ACT_OK;
	if ((flags & 0x000F) != 0)
		return TC_ACT_OK;

	__u16 qdcount = bpf_ntohs(dns.qdcount);
	__u16 ancount = bpf_ntohs(dns.ancount);

	if (qdcount == 0 || ancount == 0)
		return TC_ACT_OK;

	// Parse the question section domain name (first question only).
	int offset = dns_offset + sizeof(struct dns_header);
	struct dns_name_key qname = {};
	int name_len = 0;

	for (int i = 0; i < MAX_DNS_NAME_LEN; i++) {
		__u8 byte;
		if (bpf_skb_load_bytes(skb, offset + i, &byte, 1) < 0)
			return TC_ACT_OK;

		qname.name[i] = to_lower(byte);
		name_len = i + 1;

		if (byte == 0) // Root label — end of name
			break;
	}

	// Lookup domain in allowed_domains map (exact match).
	__u8 *allowed = bpf_map_lookup_elem(&allowed_domains, &qname);

	// If no exact match, try wildcard suffix matching.
	if (!allowed) {
		int pkt_pos = offset;
		struct dns_name_key suffix = {};

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

			allowed = bpf_map_lookup_elem(&allowed_wildcards, &suffix);
			if (allowed)
				break;
		}

		if (!allowed)
			return TC_ACT_OK; // Not in any allowlist, passthrough
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
			return TC_ACT_OK;

		if ((first_byte & 0xC0) == 0xC0) {
			answer_offset += 2;
		} else {
			for (int j = 0; j < 64; j++) {
				__u8 b;
				if (bpf_skb_load_bytes(skb, answer_offset, &b, 1) < 0)
					return TC_ACT_OK;
				answer_offset++;
				if (b == 0)
					break;
				if ((b & 0xC0) == 0xC0) {
					answer_offset++;
					break;
				}
			}
		}

		// Read RR fixed fields: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes.
		__u8 rr_fixed[10];
		if (bpf_skb_load_bytes(skb, answer_offset, rr_fixed, 10) < 0)
			return TC_ACT_OK;

		__u16 rtype  = ((__u16)rr_fixed[0] << 8) | rr_fixed[1];
		__u16 rclass = ((__u16)rr_fixed[2] << 8) | rr_fixed[3];
		__u16 rdlen  = ((__u16)rr_fixed[8] << 8) | rr_fixed[9];

		answer_offset += 10;

		// A record: TYPE=1, CLASS=1 (IN), RDLENGTH=4.
		if (rtype == 1 && rclass == 1 && rdlen == 4) {
			__u32 addr;
			if (bpf_skb_load_bytes(skb, answer_offset, &addr, 4) < 0)
				return TC_ACT_OK;

			// Learn the IP, emitting a learn event only the first time so
			// repeated DNS answers don't spam the log.
			if (!bpf_map_lookup_elem(&allowed_ips, &addr)) {
				__u8 val = 1;
				bpf_map_update_elem(&allowed_ips, &addr, &val, BPF_ANY);
				emit_event(EV_ALLOWED, EV_REASON_DNS_LEARNED, addr, 0, IPPROTO_UDP, &qname);
			}
		}

		if (rdlen > 512)
			return TC_ACT_OK;
		answer_offset += rdlen;
	}

	return TC_ACT_OK; // Always allow
}

char _license[] SEC("license") = "GPL";
