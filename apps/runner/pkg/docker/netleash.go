// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types/container"
)

// kataRuntime is the Docker runtime name for Kata Containers on Cloud Hypervisor.
// Sandboxes on this runtime execute inside a guest VM (see create.go/start.go).
const kataRuntime = "kata-clh"

// isKataRuntime reports whether the container runs on the kata-clh VM runtime,
// whose workload traffic does not traverse the host cgroup and so cannot be
// filtered by cgroup_skb eBPF.
func isKataRuntime(info *container.InspectResponse) bool {
	return info != nil && info.ContainerJSONBase != nil && info.HostConfig != nil && info.HostConfig.Runtime == kataRuntime
}

// splitDomainAllowList parses a comma-separated domain allow list into a slice
// of trimmed, non-empty domains.
func splitDomainAllowList(domainAllowList string) []string {
	parts := strings.Split(domainAllowList, ",")
	domains := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			domains = append(domains, p)
		}
	}
	return domains
}

// applyDomainAllowList configures (or clears) the netleash domain allow list for
// a container's egress. It is keyed by the full container ID, which is stable
// across stop/start and available at every lifecycle call site. A blank/empty
// list clears any existing restriction (unrestricted egress). No-op when
// netleash is disabled.
//
// Policy installation is synchronous: returning success before eBPF and the
// hostname gate are live would admit unrestricted egress on setup failure.
func (d *DockerClient) applyDomainAllowList(ctx context.Context, containerId, domainAllowList string) error {
	if d.netleashManager == nil {
		if len(splitDomainAllowList(domainAllowList)) == 0 {
			return nil
		}
		return fmt.Errorf("netleash is unavailable for domain-restricted sandbox %s", containerId)
	}

	domains := splitDomainAllowList(domainAllowList)
	if len(domains) == 0 {
		d.netleashManager.Remove(containerId)
		return nil
	}
	if !d.proxyEnforcementEnabled || d.secretProxyAddr == "" {
		return fmt.Errorf("hostname-aware egress proxy is unavailable for domain-restricted sandbox %s", containerId)
	}

	info, err := d.ContainerInspect(ctx, containerId)
	if err != nil {
		return fmt.Errorf("inspecting sandbox %s for domain enforcement: %w", containerId, err)
	}

	env := envSliceToMap(info.Config.Env)

	// Gate web ports through the shared egress proxy so the allow list is enforced
	// on the requested hostname (SNI/Host) rather than on spoofable DNS-learned
	// IPs. In cgroup mode this must NOT hinge on the sandbox carrying the proxy
	// wiring: the eBPF connect4 hook redirects transparently and non-secret hosts
	// are spliced end-to-end (no proxy CA needed), so enforcement works even for an
	// allow list applied after creation (when the wiring could no longer be
	// injected). Requiring the wiring here is exactly what left such sandboxes open
	// to the shared-IP / domain-fronting bypass. See sandboxProxyEnforced for the
	// secret-using exception (MITM'd hosts need the mounted CA).
	enforce := d.sandboxProxyEnforced(env, domainAllowList)
	if !enforce {
		return fmt.Errorf("sandbox %s lacks the proxy prerequisites required for hostname enforcement", containerId)
	}

	// kata-clh runs the workload inside a guest VM. Its network traffic never
	// passes through the host cgroup that cgroup_skb eBPF filters — it only
	// crosses the host-side veth — so cgroup-mode filtering is a silent no-op and
	// every domain stays reachable. Attach the firewall in TC/interface mode on
	// that veth instead. runc/sysbox processes live in the host cgroup, so cgroup
	// mode applies to them as before.
	if isKataRuntime(info) {
		// TC/interface mode has no connect4 hook, so the proxy can only be the
		// egress path when the workload honors HTTP(S)_PROXY — i.e. it is wired.
		// Without the wiring, gating web ports would drop all web egress instead of
		// redirecting it. Reject admission instead of degrading to the spoofable IP
		// allow list; a stopped sandbox can be recreated with wiring on its next start.
		if enforce && !d.hasProxyWiring(env) {
			return fmt.Errorf("kata sandbox %s lacks required hostname-proxy wiring", containerId)
		}
		ip := GetContainerIpAddress(ctx, info)
		veth := resolveHostVeth(d.logger, info, ip)
		if veth == "" {
			return fmt.Errorf("resolving host veth for kata sandbox %s", containerId)
		}
		if err := d.netleashManager.ConfigureInterface(containerId, veth, true, domains, enforce); err != nil {
			return fmt.Errorf("applying hostname allow list to kata sandbox %s: %w", containerId, err)
		}
		return nil
	}

	cgroupPath, err := resolveContainerCgroup(info)
	if err != nil {
		return fmt.Errorf("resolving sandbox %s cgroup for domain enforcement: %w", containerId, err)
	}

	if err := d.netleashManager.Configure(containerId, cgroupPath, domains, enforce); err != nil {
		return fmt.Errorf("applying hostname allow list to sandbox %s: %w", containerId, err)
	}
	return nil
}
