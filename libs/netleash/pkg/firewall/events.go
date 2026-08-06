package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf/ringbuf"
)

// Binary layout of `struct event` in bpf/common.h (packed, little-endian):
//
//	dst_ip uint32 | dst_port uint16 | protocol uint8 | action uint8 | reason uint8 | name[MAX_DNS_NAME_LEN]
//
// dst_port is in network byte order; name is the queried domain in DNS wire
// format (length-prefixed labels) and is only meaningful for DNS/learn events.
const eventNameOffset = 9

// event.action values — must match EV_* in bpf/common.h.
const (
	actionBlocked = 0
	actionAllowed = 1
)

// event.reason values — must match EV_REASON_* in bpf/common.h.
const (
	reasonIPAllowed       = 1
	reasonIPBlocked       = 2
	reasonDNSAllowedExact = 3
	reasonDNSAllowedWild  = 4
	reasonDNSBlocked      = 5
	reasonDNSLearned      = 6
	reasonDNSAllowedInt   = 7  // DNS query for a cluster-internal zone, passed to the resolver
	reasonIPAllowedInbnd  = 8  // egress reply on a peer-initiated inbound connection
	reasonProxyAllowed    = 9  // egress to the enforcement proxy itself
	reasonWebNotProxied   = 10 // web-port egress bypassing the mandatory proxy (dropped)
	reasonIPv6Enforced    = 11 // IPv6 egress dropped under proxy enforcement
)

// StartEventReader reads egress-decision events from the ring buffer and logs
// every request together with why it was allowed or blocked. Allowed/learned
// requests are logged at debug level (high volume) and blocked requests at warn
// level, so a default-level log shows only denials while debug logging gives a
// full per-request trace of the domain allow list.
func (fw *Firewall) StartEventReader(ctx context.Context) {
	go func() {
		rd, err := ringbuf.NewReader(fw.maps.Events)
		if err != nil {
			fw.log.Error("failed to create ring buffer reader", "error", err)
			return
		}
		defer rd.Close()

		// Close the reader when context is cancelled.
		go func() {
			<-ctx.Done()
			rd.Close()
		}()

		for {
			record, err := rd.Read()
			if err != nil {
				return // Reader closed
			}
			if len(record.RawSample) < eventNameOffset {
				continue
			}
			fw.handleEvent(record.RawSample)
		}
	}()

	// Start exec event reader if LSM exec filtering is active.
	if fw.lsmObjs != nil {
		fw.startExecEventReader(ctx)
	}
}

// handleEvent decodes one raw event and logs the decision with its reason.
func (fw *Firewall) handleEvent(raw []byte) {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, binary.LittleEndian.Uint32(raw[0:4]))

	dstPort := binary.LittleEndian.Uint16(raw[4:6])
	port := (dstPort >> 8) | (dstPort << 8) // network byte order → host
	protocol := raw[6]
	action := raw[7]
	reason := raw[8]

	var domain string
	if len(raw) >= eventNameOffset+maxDNSNameLen {
		domain = wireNameToDotted(raw[eventNameOffset : eventNameOffset+maxDNSNameLen])
	}

	dst := fmt.Sprintf("%s:%d", ip, port)
	proto := protoName(protocol)

	switch reason {
	case reasonDNSAllowedExact:
		fw.log.Debug("netleash: allowed DNS query — domain is in the allow list",
			"domain", domain, "match", "exact", "resolver", dst)
	case reasonDNSAllowedWild:
		fw.log.Debug("netleash: allowed DNS query — domain matches an allowed wildcard",
			"domain", domain, "match", "wildcard", "resolver", dst)
	case reasonDNSLearned:
		fw.log.Debug("netleash: learned allowed IP from DNS answer for an allowed domain",
			"domain", domain, "ip", ip.String())
	case reasonDNSAllowedInt:
		fw.log.Debug("netleash: allowed DNS query — cluster-internal zone passed to resolver",
			"domain", domain, "match", "internal", "resolver", dst)
	case reasonIPAllowedInbnd:
		fw.log.Debug("netleash: allowed egress — reply on a peer-initiated inbound connection",
			"dst", dst, "proto", proto)
	case reasonIPAllowed:
		fw.log.Debug("netleash: allowed egress — destination IP was resolved from an allowed domain",
			"dst", dst, "proto", proto)
	case reasonProxyAllowed:
		fw.log.Debug("netleash: allowed egress — destination is the enforcement proxy",
			"dst", dst, "proto", proto)
	case reasonWebNotProxied:
		fw.log.Warn("netleash: blocked egress — web-port traffic must go through the egress proxy",
			"dst", dst, "proto", proto)
		if fw.cfg.OnBlocked != nil {
			fw.cfg.OnBlocked(ip.String(), port, proto)
		}
	case reasonIPv6Enforced:
		fw.log.Warn("netleash: blocked IPv6 egress — IPv6 bypasses the IPv4-only allow list and is disabled under proxy enforcement")
		if fw.cfg.OnBlocked != nil {
			fw.cfg.OnBlocked("::", 0, "IPv6")
		}
	case reasonDNSBlocked:
		fw.log.Warn("netleash: blocked DNS query — domain is not in the allow list",
			"domain", domain, "resolver", dst)
		if fw.cfg.OnBlocked != nil {
			fw.cfg.OnBlocked(ip.String(), port, "DNS")
		}
	case reasonIPBlocked:
		fw.log.Warn("netleash: blocked egress — no allowed domain resolved to this IP",
			"dst", dst, "proto", proto)
		if fw.cfg.OnBlocked != nil {
			fw.cfg.OnBlocked(ip.String(), port, proto)
		}
	default:
		verdict := "allowed"
		if action == actionBlocked {
			verdict = "blocked"
		}
		fw.log.Warn("netleash: egress decision with unknown reason",
			"verdict", verdict, "reason", reason, "dst", dst, "proto", proto)
	}
}

// protoName maps an IP protocol number to a short name for logging.
func protoName(protocol uint8) string {
	switch protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "unknown"
	}
}

// wireNameToDotted converts a DNS wire-format name (length-prefixed labels,
// e.g. \x03www\x06google\x03com\x00) to a dotted string ("www.google.com").
// Trailing zero padding is ignored.
func wireNameToDotted(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); {
		n := int(b[i])
		if n == 0 || n > 63 || i+1+n > len(b) {
			break
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(b[i+1 : i+1+n])
		i += 1 + n
	}
	return sb.String()
}

// startExecEventReader reads blocked-exec events from the LSM ring buffer.
func (fw *Firewall) startExecEventReader(ctx context.Context) {
	go func() {
		rd, err := ringbuf.NewReader(fw.lsmObjs.ExecEvents)
		if err != nil {
			fw.log.Error("failed to create exec event ring buffer reader", "error", err)
			return
		}
		defer rd.Close()

		go func() {
			<-ctx.Done()
			rd.Close()
		}()

		for {
			record, err := rd.Read()
			if err != nil {
				return
			}

			// exec_event: 256 bytes path + 1 byte action
			if len(record.RawSample) < maxExecPathLen+1 {
				continue
			}

			pathBytes := record.RawSample[:maxExecPathLen]
			if idx := bytes.IndexByte(pathBytes, 0); idx >= 0 {
				pathBytes = pathBytes[:idx]
			}
			path := string(pathBytes)

			if fw.cfg.OnExecBlocked != nil {
				fw.cfg.OnExecBlocked(path)
			} else {
				fw.log.Warn("BLOCKED exec", "path", path)
			}
		}
	}()
}
