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

// applyEgressPolicy converges the netleash policy for a running container. A
// domain allow list installs a restrictive hostname policy; a secret-using
// container with no domains installs an open-network policy whose standard web
// ports are still forced through the secret-injection proxy; a container with
// neither removes netleash entirely. The full container ID is the durable key.
//
// Policy installation is synchronous: returning success before eBPF and the
// mandatory proxy gate are live would admit bypassable egress on setup failure.
func (d *DockerClient) applyEgressPolicy(ctx context.Context, info *container.InspectResponse, domainAllowList string) error {
	if info == nil || info.ContainerJSONBase == nil || info.Config == nil {
		return fmt.Errorf("cannot apply egress policy to incomplete container metadata")
	}
	containerID := info.ID
	domains := splitDomainAllowList(domainAllowList)
	env := envSliceToMap(info.Config.Env)
	needsProxyGate := len(domains) > 0 || sandboxUsesSecrets(env)

	if d.netleashManager == nil {
		if !needsProxyGate {
			return nil
		}
		return fmt.Errorf("netleash is unavailable for proxy-gated sandbox %s", containerID)
	}

	if !needsProxyGate {
		d.netleashManager.Remove(containerID)
		return nil
	}
	if !d.proxyEnforcementEnabled || d.secretProxyAddr == "" {
		return fmt.Errorf("hostname-aware egress proxy is unavailable for proxy-gated sandbox %s", containerID)
	}

	// Gate web ports through the shared egress proxy so the allow list is enforced
	// on SNI/Host and every secret placeholder traverses the injector. In cgroup
	// mode connect4 redirects clients that ignore HTTP(S)_PROXY. Secret hosts are
	// MITM'd and therefore additionally require the mounted CA/wiring.
	enforce := d.sandboxProxyEnforced(env, domainAllowList)
	if !enforce {
		return fmt.Errorf("sandbox %s lacks the proxy prerequisites required for egress enforcement", containerID)
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
			return fmt.Errorf("kata sandbox %s lacks required hostname-proxy wiring", containerID)
		}
		ip := GetContainerIpAddress(ctx, info)
		veth := resolveHostVeth(d.logger, info, ip)
		if veth == "" {
			return fmt.Errorf("resolving host veth for kata sandbox %s", containerID)
		}
		if err := d.netleashManager.ConfigureInterface(containerID, veth, true, domains, enforce); err != nil {
			return fmt.Errorf("applying egress policy to kata sandbox %s: %w", containerID, err)
		}
		return nil
	}

	cgroupPath, err := resolveContainerCgroup(info)
	if err != nil {
		return fmt.Errorf("resolving sandbox %s cgroup for egress enforcement: %w", containerID, err)
	}

	if err := d.netleashManager.Configure(containerID, cgroupPath, domains, enforce); err != nil {
		return fmt.Errorf("applying egress policy to sandbox %s: %w", containerID, err)
	}
	return nil
}
