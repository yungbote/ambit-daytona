package firewall

import "github.com/cilium/ebpf"

// firewallMapsAccessor provides uniform access to eBPF maps regardless of
// whether they come from cgroup_skb or TC programs.
type firewallMapsAccessor struct {
	AllowedDomains   *ebpf.Map
	AllowedIps       *ebpf.Map
	AllowedWildcards *ebpf.Map
	InternalDNSZones *ebpf.Map
	Events           *ebpf.Map
	// ProxyConfig holds the egress-proxy enforcement settings (see struct
	// proxy_cfg in bpf/common.h). Nil when the firewall was adopted from a pin
	// set created before proxy enforcement existed.
	ProxyConfig *ebpf.Map
}
