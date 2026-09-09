// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/containerd/errdefs"

	"github.com/daytonaio/runner/pkg/sandboxsecurity"
	"github.com/docker/docker/api/types/container"
)

const workspaceSecurityLegacy = "legacy"
const workspaceSecurityRestricted = "restricted-v1"
const workspaceSecurityProfileLabel = "daytona.workspace-security-profile"

func normalizeWorkspaceSecurityProfile(value string) (string, error) {
	switch value {
	case "", workspaceSecurityLegacy:
		return workspaceSecurityLegacy, nil
	case workspaceSecurityRestricted:
		if err := sandboxsecurity.ValidateRootlessSeccomp([]byte(sandboxsecurity.RootlessSeccomp())); err != nil {
			return "", err
		}
		return value, nil
	default:
		return "", fmt.Errorf("unsupported workspace security profile")
	}
}

// Applied after runtime-specific construction so a later Kata branch cannot
// restore ALL capabilities or an unconfined policy. No image-name routing.
func (d *DockerClient) applyWorkspaceSecurityProfile(config *container.Config, host *container.HostConfig) error {
	profile, err := normalizeWorkspaceSecurityProfile(d.workspaceSecurityProfile)
	if err != nil {
		return err
	}
	if profile == workspaceSecurityLegacy {
		return nil
	}
	if config == nil || host == nil {
		return fmt.Errorf("workspace security configuration is absent")
	}
	if host.NetworkMode.IsHost() || host.PidMode != "" ||
		(host.IpcMode != "" && host.IpcMode != "private") ||
		(host.CgroupnsMode != "" && host.CgroupnsMode != "private") {
		return fmt.Errorf("restricted workspaces require private process, IPC and cgroup namespaces and non-host networking")
	}
	host.Privileged = false
	host.CapAdd = nil
	host.CapDrop = []string{"ALL"}
	host.SecurityOpt = []string{"no-new-privileges", "seccomp=" + sandboxsecurity.RootlessSeccomp()}
	host.IpcMode = "private"
	host.CgroupnsMode = "private"
	if config.Labels == nil {
		config.Labels = make(map[string]string)
	}
	config.Labels[workspaceSecurityProfileLabel] = profile
	return nil
}

// This inspects actual configuration. A label is diagnostic, never proof.
func (d *DockerClient) validateWorkspaceSecurityConfiguration(info *container.InspectResponse) error {
	profile, err := normalizeWorkspaceSecurityProfile(d.workspaceSecurityProfile)
	if err != nil || profile == workspaceSecurityLegacy {
		return err
	}
	if info == nil || info.ContainerJSONBase == nil || info.HostConfig == nil || info.Config == nil {
		return fmt.Errorf("restricted workspace container configuration is absent")
	}
	host := info.HostConfig
	if host.Privileged || len(host.CapAdd) != 0 || len(host.CapDrop) != 1 ||
		host.CapDrop[0] != "ALL" || host.NetworkMode.IsHost() || host.PidMode != "" ||
		host.IpcMode != "private" || host.CgroupnsMode != "private" || len(host.SecurityOpt) != 2 {
		return fmt.Errorf("workspace does not satisfy restricted-v1; replace it through the existing workspace lifecycle")
	}
	noNewPrivileges, seccomp := false, false
	for _, option := range host.SecurityOpt {
		switch {
		case option == "no-new-privileges" || option == "no-new-privileges:true":
			noNewPrivileges = true
		case strings.HasPrefix(option, "seccomp="):
			if err := sandboxsecurity.ValidateRootlessSeccomp([]byte(strings.TrimPrefix(option, "seccomp="))); err != nil {
				return err
			}
			seccomp = true
		default:
			return fmt.Errorf("restricted workspace has an unexpected security override")
		}
	}
	if !noNewPrivileges || !seccomp {
		return fmt.Errorf("restricted workspace security configuration is incomplete")
	}
	return nil
}

func (d *DockerClient) admitRunningWorkspaceSecurity(ctx context.Context, info *container.InspectResponse) error {
	if err := d.validateWorkspaceSecurityConfiguration(info); err != nil {
		return err
	}
	if d.workspaceSecurityProfile != workspaceSecurityRestricted {
		return nil
	}
	if info.State == nil || !info.State.Running || info.State.Pid <= 0 {
		return fmt.Errorf("restricted workspace has no running process to inspect")
	}
	security, err := sandboxsecurity.ObserveProcess(info.State.Pid)
	if err != nil {
		return fmt.Errorf("restricted workspace process security is unavailable: %w", err)
	}
	if err := validateRestrictedProcessSecurity(security); err != nil {
		return err
	}
	current, err := d.ContainerInspect(ctx, info.ID)
	if err != nil {
		return err
	}
	if current.State == nil || !current.State.Running || current.State.Pid != info.State.Pid || current.State.StartedAt != info.State.StartedAt || current.ID != info.ID {
		return fmt.Errorf("restricted workspace generation changed during security admission")
	}
	if err := d.validateWorkspaceSecurityConfiguration(current); err != nil {
		return err
	}
	currentStartTicks, err := sandboxsecurity.ProcessStartTicks(current.State.Pid)
	if err != nil || currentStartTicks != security.StartTicks {
		return fmt.Errorf("restricted workspace process generation changed during security admission")
	}
	return nil
}

func validateRestrictedProcessSecurity(security sandboxsecurity.ProcessSecurity) error {
	if !security.NoNewPrivileges || security.SeccompMode != 2 {
		return fmt.Errorf("restricted workspace process security differs from its configuration")
	}
	for _, mask := range []string{security.EffectiveCapabilities, security.PermittedCapabilities,
		security.BoundingCapabilities, security.InheritableCapabilities, security.AmbientCapabilities} {
		if mask != "0000000000000000" {
			return fmt.Errorf("restricted workspace retains a process capability set")
		}
	}
	return nil
}

// The exact newly-created container belongs to this attempt until its
// configuration is admitted. A conflict-adopted container belongs to its
// original creator and must never be removed by this path.
func (d *DockerClient) validateCreatedWorkspaceSecurity(ctx context.Context, containerID string, createdHere bool) error {
	observed, err := d.ContainerInspect(ctx, containerID)
	if err == nil {
		err = d.validateWorkspaceSecurityConfiguration(observed)
	}
	if err == nil || !createdHere {
		return err
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if cleanupErr := d.apiClient.ContainerRemove(cleanupCtx, containerID, container.RemoveOptions{Force: true, RemoveVolumes: true}); cleanupErr != nil && !errdefs.IsNotFound(cleanupErr) {
		return errors.Join(err, fmt.Errorf("rejected new workspace %s remains pending cleanup: %w", containerID, cleanupErr))
	}
	return err
}
