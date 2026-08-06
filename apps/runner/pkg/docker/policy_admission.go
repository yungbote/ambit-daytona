// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
)

const freshPolicyAdmissionMetadata = "daytona.freshPolicyAdmission"

// admitRunningSandboxPolicy is the single runner-side admission boundary for
// network and shared-proxy policy. It is called immediately after a container
// becomes reachable and before daemon/ADB readiness is reported. Every policy
// operation is synchronous; success therefore means the complete requested
// boundary is live, not merely scheduled.
func (d *DockerClient) admitRunningSandboxPolicy(
	ctx context.Context,
	info *container.InspectResponse,
	sandboxID string,
	secretsToken *string,
	metadata map[string]string,
) error {
	if info == nil || info.ContainerJSONBase == nil || info.Config == nil {
		return fmt.Errorf("sandbox %s has incomplete container metadata", sandboxID)
	}
	containerIP := GetContainerIpAddress(ctx, info)
	if containerIP == "" {
		return fmt.Errorf("sandbox %s has no IP address", sandboxID)
	}

	env := envSliceToMap(info.Config.Env)
	domainAllowList, domainSpecified := metadata["domainAllowList"]
	networkAllowList := strings.TrimSpace(metadata["networkAllowList"])
	blockAll := metadata["networkBlockAll"] == "true"
	hasDomains := len(splitDomainAllowList(domainAllowList)) > 0

	if blockAll && (networkAllowList != "" || hasDomains) {
		return fmt.Errorf("sandbox %s has contradictory block-all and allow-list policies", sandboxID)
	}
	if networkAllowList != "" && hasDomains {
		return fmt.Errorf("sandbox %s has both network and domain allow lists", sandboxID)
	}
	needsNetRules := blockAll || networkAllowList != "" || metadata["limitNetworkEgress"] == "true" || metadata[freshPolicyAdmissionMetadata] == "true"
	if needsNetRules && d.netRulesManager == nil {
		return fmt.Errorf("network rules manager is unavailable for sandbox %s", sandboxID)
	}

	containerID := info.ID
	containerShortID := containerID
	if len(containerShortID) > 12 {
		containerShortID = containerShortID[:12]
	}
	veth := resolveHostVeth(d.logger, info, containerIP)

	// A fresh create is quarantined while a domain or secret policy is assembled.
	// The temporary block is removed only after the durable proxy binding and eBPF
	// hostname gate are complete, eliminating an allow-all setup window.
	freshAdmission := metadata[freshPolicyAdmissionMetadata] == "true"
	clearNetworkRules := freshAdmission && !blockAll && networkAllowList == ""
	quarantined := clearNetworkRules && (hasDomains || sandboxUsesSecrets(env))
	needsUnspoofableAnchor := blockAll || networkAllowList != "" || metadata["limitNetworkEgress"] == "true" || quarantined
	if needsUnspoofableAnchor && veth == "" {
		return fmt.Errorf("sandbox %s network policy requires an unspoofable host-veth anchor", sandboxID)
	}
	if quarantined {
		if err := d.netRulesManager.SetNetworkRules(containerShortID, containerIP, veth, ""); err != nil {
			return fmt.Errorf("quarantining sandbox %s before policy admission: %w", sandboxID, err)
		}
	}

	switch {
	case blockAll:
		if err := d.netRulesManager.SetNetworkRules(containerShortID, containerIP, veth, ""); err != nil {
			return fmt.Errorf("applying block-all policy to sandbox %s: %w", sandboxID, err)
		}
	case networkAllowList != "":
		if err := d.netRulesManager.SetNetworkRules(containerShortID, containerIP, veth, networkAllowList); err != nil {
			return fmt.Errorf("applying network allow list to sandbox %s: %w", sandboxID, err)
		}
	}

	// Clearing a domain filter tears down the manager entry (including its proxy
	// binding), so perform that relaxation before installing the desired binding.
	// Non-empty policies take the inverse order: the proxy learns the restrictive
	// hostname policy before the eBPF gate begins redirecting traffic to it.
	if domainSpecified && !hasDomains {
		if err := d.applyDomainAllowList(ctx, containerID, domainAllowList); err != nil {
			return err
		}
	}
	if err := d.registerSandboxPolicy(ctx, containerID, sandboxID, secretsToken, containerIP, domainAllowList, env); err != nil {
		return err
	}
	if hasDomains {
		if err := d.applyDomainAllowList(ctx, containerID, domainAllowList); err != nil {
			return err
		}
	}

	if metadata["limitNetworkEgress"] == "true" {
		if err := d.netRulesManager.SetNetworkLimiter(containerShortID, containerIP, veth); err != nil {
			return fmt.Errorf("applying network limiter to sandbox %s: %w", sandboxID, err)
		}
	}

	if clearNetworkRules {
		if err := d.netRulesManager.DeleteNetworkRules(containerShortID); err != nil {
			return fmt.Errorf("converging sandbox %s to its open IP-network policy: %w", sandboxID, err)
		}
	}
	return nil
}

// rejectSandboxAdmission makes a failed admission terminal for the current run.
// It first installs a best-effort block-all rule, revokes proxy credentials, and
// then kills the container. Retrying Create/Start re-enters the same admission
// boundary from the stopped state; no idempotent success path can skip it.
func (d *DockerClient) rejectSandboxAdmission(ctx context.Context, info *container.InspectResponse, cause error) error {
	if info == nil || info.ContainerJSONBase == nil {
		return cause
	}
	containerID := info.ID

	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()

	// Pause first: it is the only containment mechanism that does not depend on
	// the policy subsystem that just failed. If kill later fails, a successful
	// pause still leaves the workload unable to execute or emit traffic.
	pauseErr := d.apiClient.ContainerPause(cleanupCtx, containerID)
	var pauseContainmentErr error
	if pauseErr != nil {
		pauseContainmentErr = fmt.Errorf("pausing unadmitted sandbox: %w", pauseErr)
	}
	d.revokeSandboxPolicy(containerID)

	var quarantineErr error
	if ip := GetContainerIpAddress(cleanupCtx, info); ip != "" && d.netRulesManager != nil {
		shortID := containerID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		veth := resolveHostVeth(d.logger, info, ip)
		if err := d.netRulesManager.SetNetworkRules(shortID, ip, veth, ""); err != nil {
			quarantineErr = fmt.Errorf("installing fail-closed quarantine: %w", err)
		}
	}
	if err := d.apiClient.ContainerKill(cleanupCtx, containerID, "KILL"); err != nil {
		return errors.Join(
			fmt.Errorf("sandbox policy admission failed: %w", cause),
			pauseContainmentErr,
			quarantineErr,
			fmt.Errorf("killing unadmitted sandbox: %w", err),
		)
	}
	return errors.Join(fmt.Errorf("sandbox policy admission failed: %w", cause), quarantineErr)
}
