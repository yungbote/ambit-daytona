// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"errors"
	"strings"

	"github.com/daytonaio/runner/pkg/api/dto"
)

func (d *DockerClient) UpdateNetworkSettings(ctx context.Context, containerId string, updateNetworkSettingsDto dto.UpdateNetworkSettingsDTO) error {
	info, err := d.ContainerInspect(ctx, containerId)
	if err != nil {
		return err
	}
	containerShortId := info.ID[:12]

	ipAddress := GetContainerIpAddress(ctx, info)

	// Return error if container does not have an IP address
	if ipAddress == "" {
		return errors.New("sandbox does not have an IP address")
	}

	veth := resolveHostVeth(d.logger, info, ipAddress)

	blockAll := updateNetworkSettingsDto.NetworkBlockAll != nil && *updateNetworkSettingsDto.NetworkBlockAll
	var allowListTrimmed string
	hasAllowList := false
	if updateNetworkSettingsDto.NetworkAllowList != nil {
		allowListTrimmed = strings.TrimSpace(*updateNetworkSettingsDto.NetworkAllowList)
		hasAllowList = allowListTrimmed != ""
	}
	needsUnspoofableAnchor := blockAll || hasAllowList ||
		(updateNetworkSettingsDto.NetworkLimitEgress != nil && *updateNetworkSettingsDto.NetworkLimitEgress)
	if needsUnspoofableAnchor && veth == "" {
		return d.rejectSandboxAdmission(ctx, info, errors.New("sandbox network policy requires an unspoofable host-veth anchor"))
	}

	switch {
	case blockAll:
		err = d.netRulesManager.SetNetworkRules(containerShortId, ipAddress, veth, "")
	case hasAllowList:
		err = d.netRulesManager.SetNetworkRules(containerShortId, ipAddress, veth, allowListTrimmed)
	case updateNetworkSettingsDto.NetworkBlockAll != nil && !*updateNetworkSettingsDto.NetworkBlockAll && !hasAllowList:
		// Restore general outbound access (clear Daytona filter rules for this sandbox)
		err = d.netRulesManager.DeleteNetworkRules(containerShortId)
	case updateNetworkSettingsDto.NetworkAllowList != nil && !hasAllowList:
		// Explicit empty allow list: treat as open network
		err = d.netRulesManager.DeleteNetworkRules(containerShortId)
	default:
		// No applicable filter change
		err = nil
	}
	if err != nil {
		// A failure while installing a restrictive policy may leave a partially
		// cleared iptables chain. Quarantine and stop instead of reporting an error
		// while the sandbox continues with ambiguous egress.
		if blockAll || hasAllowList {
			return d.rejectSandboxAdmission(ctx, info, err)
		}
		return err
	}

	if updateNetworkSettingsDto.NetworkLimitEgress != nil && *updateNetworkSettingsDto.NetworkLimitEgress {
		err = d.netRulesManager.SetNetworkLimiter(containerShortId, ipAddress, veth)
		if err != nil {
			return d.rejectSandboxAdmission(ctx, info, err)
		}
	} else if updateNetworkSettingsDto.NetworkLimitEgress != nil && !*updateNetworkSettingsDto.NetworkLimitEgress {
		err = d.netRulesManager.RemoveNetworkLimiter(containerShortId)
		if err != nil {
			return err
		}
	}

	// Apply (or clear) the eBPF domain allow list via netleash. Keyed by the
	// full container ID so it stays consistent across the sandbox lifecycle.
	// An empty list clears any existing restriction.
	if updateNetworkSettingsDto.DomainAllowList != nil {
		domainAllowList := *updateNetworkSettingsDto.DomainAllowList
		env := envSliceToMap(info.Config.Env)
		if len(splitDomainAllowList(domainAllowList)) > 0 {
			// Tighten the hostname policy before enabling/updating the eBPF gate.
			// If either half fails, rejectSandboxAdmission revokes the binding and
			// stops the workload rather than retaining an IP-only compatibility mode.
			if err := d.updateSandboxPolicyDomains(ctx, info.ID, containerId, ipAddress, domainAllowList, env); err != nil {
				return d.rejectSandboxAdmission(ctx, info, err)
			}
			if err := d.applyDomainAllowList(ctx, info.ID, domainAllowList); err != nil {
				return d.rejectSandboxAdmission(ctx, info, err)
			}
		} else {
			// Clearing a domain policy is intentionally relaxing. Remove the eBPF
			// gate first, then preserve an allow-all proxy binding only for containers
			// that still carry proxy wiring (for example secret-using sandboxes).
			if err := d.applyDomainAllowList(ctx, info.ID, domainAllowList); err != nil {
				return err
			}
			if err := d.updateSandboxPolicyDomains(ctx, info.ID, containerId, ipAddress, domainAllowList, env); err != nil {
				return err
			}
		}
	}

	return nil
}
