package firewall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// maxDNSNameLen must match MAX_DNS_NAME_LEN in bpf/firewall.c.
const maxDNSNameLen = 128

// domainToWireFormat converts a domain name to DNS wire format (lowercased, zero-padded).
// Example: "example.com" → \x07example\x03com\x00 (padded to maxDNSNameLen bytes).
func domainToWireFormat(domain string) ([maxDNSNameLen]byte, error) {
	var key [maxDNSNameLen]byte
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	labels := strings.Split(domain, ".")
	offset := 0
	for _, label := range labels {
		if len(label) == 0 {
			return key, fmt.Errorf("empty label in domain %q", domain)
		}
		if len(label) > 63 {
			return key, fmt.Errorf("label too long in domain %q", domain)
		}
		if offset+1+len(label) >= maxDNSNameLen-1 {
			return key, fmt.Errorf("domain too long: %q", domain)
		}
		key[offset] = byte(len(label))
		offset++
		copy(key[offset:], []byte(label))
		offset += len(label)
	}
	key[offset] = 0 // Root label terminator
	return key, nil
}

// populateAllowedDomains seeds the eBPF allowed_domains and allowed_wildcards maps.
// Domains prefixed with "*." (e.g., "*.github.com") are stored as wildcard entries:
// the parent domain goes into allowed_wildcards for suffix matching, and also into
// allowed_domains so the base domain itself is allowed.
func (fw *Firewall) populateAllowedDomains() error {
	for _, domain := range fw.cfg.Domains {
		isWildcard := strings.HasPrefix(domain, "*.")
		baseDomain := domain
		if isWildcard {
			baseDomain = domain[2:] // strip "*."
		}

		wireKey, err := domainToWireFormat(baseDomain)
		if err != nil {
			return fmt.Errorf("converting domain %q to wire format: %w", domain, err)
		}

		var key firewallDnsNameKey
		for i := 0; i < len(wireKey); i++ {
			key.Name[i] = int8(wireKey[i])
		}

		if isWildcard {
			if err := fw.maps.AllowedWildcards.Put(key, uint8(1)); err != nil {
				return fmt.Errorf("adding wildcard %q to allowed_wildcards map: %w", domain, err)
			}
			fw.log.Debug("allowed wildcard domain in eBPF map", "domain", domain)
		}

		// Always add the base domain to exact match (covers both explicit and wildcard base).
		if err := fw.maps.AllowedDomains.Put(key, uint8(1)); err != nil {
			return fmt.Errorf("adding domain %q to allowed_domains map: %w", baseDomain, err)
		}
		fw.log.Debug("allowed domain in eBPF map", "domain", baseDomain)
	}
	return nil
}

// UpdateDomains replaces the allow list in place — clearing allowed_domains and
// allowed_wildcards and repopulating them from the new list — without detaching
// or reloading the eBPF programs, so the peer-initiated connection tracking
// (inbound_conns) survives and inbound connections (terminal websockets, pooled
// toolbox connections) don't hang. Because the programs and their bpffs pins are
// untouched, the change is reflected in the pinned state for free.
//
// When clearLearnedIPs is set, the learned-IP cache (allowed_ips) is also
// dropped. This is required when a domain is *removed*: allowed_ips records no
// domain association, so the removed domain's already-resolved IPs would
// otherwise stay reachable by direct IP egress even though the domain is no
// longer allowed. Clearing rebuilds the cache from fresh DNS — still-allowed
// domains re-learn their IPs on the next lookup. The caller leaves it false for
// pure additions, so in-flight connections to still-allowed domains aren't
// disrupted. inbound_conns is never cleared here, so inbound connections keep
// working regardless.
//
// The clear+repopulate window only ever makes the allow list momentarily smaller
// (a fresh DNS query could be dropped and retried), never more permissive, so it
// is fail-closed and safe.
func (fw *Firewall) UpdateDomains(domains []string, clearLearnedIPs bool) error {
	fw.cfg.Domains = domains
	if err := clearDNSKeyMap(fw.maps.AllowedDomains); err != nil {
		return fmt.Errorf("clearing allowed_domains: %w", err)
	}
	if err := clearDNSKeyMap(fw.maps.AllowedWildcards); err != nil {
		return fmt.Errorf("clearing allowed_wildcards: %w", err)
	}
	if clearLearnedIPs {
		if err := clearU32KeyMap(fw.maps.AllowedIps); err != nil {
			return fmt.Errorf("clearing allowed_ips: %w", err)
		}
		// allowProxyIP re-adds the proxy's IP (a no-op when no proxy is
		// configured), since it lives in allowed_ips and was just cleared.
		if err := fw.allowProxyIP(); err != nil {
			return fmt.Errorf("restoring proxy IP after clearing allowed_ips: %w", err)
		}
	}
	return fw.populateAllowedDomains()
}

// clearDNSKeyMap deletes every entry from a DNS-name-keyed hash map (BPF maps
// have no bulk clear). Keys are collected before deleting, since deleting during
// iteration is undefined.
func clearDNSKeyMap(m *ebpf.Map) error {
	var keys []firewallDnsNameKey
	var k firewallDnsNameKey
	var v uint8
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

// clearU32KeyMap deletes every entry from a uint32-keyed hash map (e.g.
// allowed_ips). Keys are collected before deleting, since deleting during
// iteration is undefined.
func clearU32KeyMap(m *ebpf.Map) error {
	var keys []uint32
	var k uint32
	var v uint8
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

// populateInternalDNSZones seeds the eBPF internal_dns_zones map. DNS queries
// whose name is a subdomain of one of these zones (e.g. "cluster.local") are
// passed through to the resolver by the egress program instead of being dropped,
// so Kubernetes search-domain expansion doesn't stall an allowed external
// lookup. Zones are stored in DNS wire format, matching the suffix the egress
// program derives by stripping labels from the queried name.
func (fw *Firewall) populateInternalDNSZones() error {
	if fw.maps.InternalDNSZones == nil {
		return nil
	}
	for _, zone := range fw.cfg.InternalDNSZones {
		zone = strings.TrimSpace(zone)
		zone = strings.TrimPrefix(zone, "*.")
		zone = strings.Trim(zone, ".")
		if zone == "" {
			continue
		}
		wireKey, err := domainToWireFormat(zone)
		if err != nil {
			return fmt.Errorf("converting internal DNS zone %q to wire format: %w", zone, err)
		}
		var key firewallDnsNameKey
		for i := 0; i < len(wireKey); i++ {
			key.Name[i] = int8(wireKey[i])
		}
		if err := fw.maps.InternalDNSZones.Put(key, uint8(1)); err != nil {
			return fmt.Errorf("adding internal DNS zone %q to map: %w", zone, err)
		}
		fw.log.Debug("allowed internal DNS zone in eBPF map", "zone", zone)
	}
	return nil
}

// maxExecPathLen must match MAX_PATH_LEN in bpf/firewall_lsm.c.
const maxExecPathLen = 256

// populateAllowedExecs seeds the LSM allowed_execs map with whitelisted binary paths.
func (fw *Firewall) populateAllowedExecs() error {
	if fw.lsmObjs == nil {
		return nil
	}
	for _, path := range fw.cfg.AllowedExecs {
		if len(path) >= maxExecPathLen {
			return fmt.Errorf("exec path too long (%d >= %d): %q", len(path), maxExecPathLen, path)
		}
		var key firewallLsmExecPathKey
		for i := 0; i < len(path); i++ {
			key.Path[i] = int8(path[i])
		}
		if err := fw.lsmObjs.AllowedExecs.Put(key, uint8(1)); err != nil {
			return fmt.Errorf("adding exec path %q to allowed_execs map: %w", path, err)
		}
		fw.log.Debug("allowed exec in eBPF map", "path", path)
	}
	return nil
}

// allowProxyIP adds the proxy's IP address to the allowed_ips map so cgroup
// traffic can reach it (needed when proxy runs on the Docker bridge gateway).
func (fw *Firewall) allowProxyIP() error {
	if fw.cfg.ProxyAddr == "" {
		return nil
	}
	return fw.AllowIP(fw.cfg.ProxyAddr)
}

// populateProxyConfig seeds the eBPF proxy_config map from Config.ProxyAddr and
// Config.EnforceProxy during Setup. With enforcement on, the egress programs
// gate the standard web ports (TCP 80/443, UDP 443) so HTTP(S) can only reach
// the proxy — which then enforces the domain allow list on the requested
// hostname (SNI/Host) rather than on DNS-learned IPs. A zeroed map (the
// default) leaves the gate off.
func (fw *Firewall) populateProxyConfig() error {
	if !fw.cfg.EnforceProxy && fw.cfg.ProxyAddr == "" {
		return nil
	}
	return fw.SetProxyEnforcement(fw.cfg.ProxyAddr, fw.cfg.EnforceProxy)
}

// SetProxyEnforcement updates the egress-proxy gate of a live (or adopted)
// firewall in place: proxyAddr ("ip:port") is the hostname-aware proxy web
// traffic must use, and enforce turns the web-port gate on or off. Enabling
// enforcement requires a resolvable IPv4 proxy address — gating web ports with
// no reachable proxy would silently brick all HTTP(S) egress. Disabling always
// succeeds (for firewalls that have the map). Firewalls adopted from a pin set
// that predates proxy enforcement have no proxy_config map (and no gate in
// their programs); enabling on those returns an error.
func (fw *Firewall) SetProxyEnforcement(proxyAddr string, enforce bool) error {
	if fw.maps.ProxyConfig == nil {
		if enforce {
			return fmt.Errorf("firewall predates proxy enforcement (no proxy_config map); rebuild it to enable gating")
		}
		return nil
	}

	var val firewallProxyCfg
	if proxyAddr != "" {
		ip4, port, err := parseIPv4Port(proxyAddr)
		if err != nil {
			if enforce {
				return fmt.Errorf("proxy enforcement requires a valid IPv4 proxy address, got %q: %w", proxyAddr, err)
			}
		} else {
			// Store both fields exactly as the eBPF program reads them off the wire:
			// the raw network-byte-order bytes loaded as native integers (matching
			// AllowIP's key encoding for allowed_ips).
			val.ProxyIp = binary.LittleEndian.Uint32(ip4)
			val.ProxyPort = binary.LittleEndian.Uint16([]byte{byte(port >> 8), byte(port)})
		}
	} else if enforce {
		return fmt.Errorf("proxy enforcement requires a proxy address")
	}
	if enforce {
		val.Enforce = 1
	}

	if err := fw.maps.ProxyConfig.Put(uint32(0), &val); err != nil {
		return fmt.Errorf("updating proxy_config: %w", err)
	}
	fw.cfg.ProxyAddr = proxyAddr
	fw.cfg.EnforceProxy = enforce
	fw.log.Debug("proxy enforcement updated", "proxy", proxyAddr, "enforce", enforce)
	return nil
}

// ProxyEnforcementEnabled reads the durable gate state from a live or adopted
// firewall. The proxy_config map is pinned with the policy, so callers can
// recover intent without inventing a side-channel or assuming every Manager
// consumer uses hostname enforcement.
func (fw *Firewall) ProxyEnforcementEnabled() (bool, error) {
	if fw.maps.ProxyConfig == nil {
		return false, fmt.Errorf("firewall has no proxy_config map")
	}
	var val firewallProxyCfg
	if err := fw.maps.ProxyConfig.Lookup(uint32(0), &val); err != nil {
		return false, fmt.Errorf("reading proxy_config: %w", err)
	}
	return val.Enforce != 0, nil
}

// parseIPv4Port splits an "ip:port" address into its IPv4 bytes and port,
// erroring on hostnames, IPv6, or a missing/invalid port.
func parseIPv4Port(addr string) (net.IP, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return nil, 0, fmt.Errorf("not an IPv4 address: %q", host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return nil, 0, fmt.Errorf("invalid port: %q", portStr)
	}
	return ip.To4(), uint16(port), nil
}

// AllowIP adds addr (an "ip" or "ip:port") to the egress allow_ips map of a live
// or adopted firewall, so cgroup traffic can reach it. It is used to permit the
// shared secret-injection proxy on firewalls that were attached/adopted before
// secret injection was enabled — Setup only allows the proxy IP for firewalls
// built with a ProxyAddr. Non-IPv4 or unparseable addresses are a no-op.
func (fw *Firewall) AllowIP(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // tolerate a bare IP with no port
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	if fw.maps.AllowedIps == nil {
		return nil
	}
	key := binary.LittleEndian.Uint32(ip4)
	if err := fw.maps.AllowedIps.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("allowing IP %s: %w", host, err)
	}
	fw.log.Debug("allowed IP", "ip", ip4)
	return nil
}
