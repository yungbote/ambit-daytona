// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/daytonaio/common-go/pkg/timer"
	"github.com/daytonaio/runner/pkg/api/dto"
	"github.com/daytonaio/runner/pkg/common"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/pkg/stdcopy"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func (d *DockerClient) Start(ctx context.Context, containerId string, authToken *string, secretsToken *string, metadata map[string]string) (*container.InspectResponse, string, error) {
	defer timer.Timer()()

	// Cancel a backup if it's already in progress
	backup_context, ok := backup_context_map.Get(containerId)
	if ok {
		backup_context.cancel()
	}

	c, err := d.ContainerInspect(ctx, containerId)
	if err != nil {
		return nil, "", err
	}

	if c.State.Running {
		containerIP := GetContainerIpAddress(ctx, c)
		if containerIP == "" {
			return nil, "", errors.New("sandbox IP not found? Is the sandbox started?")
		}
		if err := d.admitRunningSandboxPolicy(ctx, c, containerId, secretsToken, metadata); err != nil {
			return nil, "", d.rejectSandboxAdmission(ctx, c, err)
		}

		if isAndroidDeviceContainer(c) {
			if err := d.waitForAdbRunning(ctx, containerIP); err != nil {
				return nil, "", err
			}
			return c, "", nil
		}

		daemonVersion, err := d.waitForDaemonRunning(ctx, containerIP, authToken)
		if err != nil {
			return nil, "", err
		}

		return c, daemonVersion, nil
	}

	// Swap a non-kata container for a kata-clh one before starting. This happens for the
	// default runc->kata conversion (skippable via SKIP_KATA_CONVERSION) and unconditionally
	// when the org is kata-only (forceKata=true in metadata, sent by the API).
	forceKata := metadata["forceKata"] == "true"
	if c.HostConfig != nil && c.HostConfig.Runtime != "kata-clh" && !isAndroidDeviceContainer(c) {
		if forceKata || (os.Getenv("SKIP_KATA_CONVERSION") != "true" && c.HostConfig.Runtime == "runc") {
			converted, err := d.convertRuncToKata(ctx, containerId, c)
			if err != nil {
				return nil, "", err
			}
			c = converted
		}
	}

	// Apply secret changes made while the sandbox was not running (or applied only
	// to the daemon env while it was): when the desired secret env differs from the
	// container's, recreate it with matching placeholders and proxy wiring.
	if secretEnvsJSON, ok := metadata["secretEnvs"]; ok && !isAndroidDeviceContainer(c) {
		c, err = d.syncSecretEnvOnStart(ctx, containerId, c, secretEnvsJSON, metadata["domainAllowList"])
		if err != nil {
			return nil, "", fmt.Errorf("failed to apply updated sandbox secrets: %w", err)
		}
	}

	// Re-establish FUSE mounts that may have died since the container was last running.
	if volumesJSON, ok := metadata["volumes"]; ok {
		var volumes []dto.VolumeDTO
		if err := json.Unmarshal([]byte(volumesJSON), &volumes); err == nil && len(volumes) > 0 {
			_, err = d.getVolumesMountPathBinds(ctx, volumes)
			if err != nil {
				d.logger.ErrorContext(ctx, "Failed to ensure volume FUSE mounts", "error", err)
			}
		}
	}

	c, err = d.startContainerWithSysboxRecovery(ctx, containerId, c)
	if err != nil {
		return nil, "", err
	}

	// make sure container is running
	runningContainer, err := d.waitForContainerRunning(ctx, containerId)
	if err != nil {
		return nil, "", err
	}

	containerIP := GetContainerIpAddress(ctx, runningContainer)
	if containerIP == "" {
		return nil, "", errors.New("sandbox IP not found? Is the sandbox started?")
	}
	if err := d.admitRunningSandboxPolicy(ctx, runningContainer, containerId, secretsToken, metadata); err != nil {
		return nil, "", d.rejectSandboxAdmission(ctx, runningContainer, err)
	}

	// Android-device sandboxes do not run the daytona daemon. Readiness is signaled by
	// the ADB port accepting TCP connections inside the container.
	if isAndroidDeviceContainer(runningContainer) {
		if err := d.waitForAdbRunning(ctx, containerIP); err != nil {
			return nil, "", err
		}

		return runningContainer, "", nil
	}

	if c.HostConfig.Runtime != "kata-clh" && !slices.Equal(c.Config.Entrypoint, strslice.StrSlice{common.DAEMON_PATH}) {
		processesCtx := context.Background()
		go func() {
			if err := d.startDaytonaDaemon(processesCtx, containerId, c.Config.WorkingDir); err != nil {
				d.logger.ErrorContext(ctx, "Failed to start Daytona daemon", "error", err)
			}
		}()
	}

	// If daemon is the sandbox entrypoint (common.DAEMON_PATH), it is started as part of the sandbox;
	// Otherwise, the daemon is started separately above.
	// In either case, we wait for it here.
	daemonVersion, err := d.waitForDaemonRunning(ctx, containerIP, authToken)
	if err != nil {
		return nil, "", err
	}

	return runningContainer, daemonVersion, nil
}

// convertRuncToKata recreates a runc container under the kata-clh runtime.
func (d *DockerClient) convertRuncToKata(ctx context.Context, containerId string, original *container.InspectResponse) (*container.InspectResponse, error) {
	d.logger.InfoContext(ctx, "Converting runc container to kata-clh", "containerId", containerId)
	return d.recreateContainerUnderSameID(ctx, containerId, "daytona-runc-to-kata", original, nil, func(hc *container.HostConfig) {
		hc.Privileged = false
		hc.Runtime = "kata-clh"
		// Kata VM default size is 1vcpu and 2Gi RAM. Kata adds container resources on
		// top of its defaults, so subtract them to get the actual requested size.
		if hc.CPUQuota >= 100000 {
			hc.CPUQuota -= 100000
		}
		kataDefaultMemory := common.GBToBytes(1)
		if hc.Memory >= kataDefaultMemory {
			hc.Memory -= kataDefaultMemory
			hc.MemorySwap -= kataDefaultMemory
		}
		hc.CapAdd = []string{"ALL"}
		hc.SecurityOpt = []string{"seccomp=unconfined", "apparmor=unconfined"}
	})
}

// recreateContainerUnderSameID commits the stopped container to a throwaway image and
// recreates it under the same ID, applying mutateConfig/mutateHostConfig before create.
// The original is renamed aside (so a create failure can roll back) then removed, which
// clears any sysbox-mgr registration tied to it.
func (d *DockerClient) recreateContainerUnderSameID(ctx context.Context, containerId, imagePrefix string, original *container.InspectResponse, mutateConfig func(*container.Config), mutateHostConfig func(*container.HostConfig)) (*container.InspectResponse, error) {
	timestamp := time.Now().Unix()
	imageName := fmt.Sprintf("%s:%s-%d", imagePrefix, containerId, timestamp)
	oldName := fmt.Sprintf("%s-old-%d", containerId, timestamp)

	if err := d.commitContainer(ctx, containerId, imageName); err != nil {
		return nil, fmt.Errorf("failed to commit container: %w", err)
	}

	if err := d.apiClient.ContainerRename(ctx, containerId, oldName); err != nil {
		return nil, fmt.Errorf("failed to rename container: %w", err)
	}

	newContainerConfig := *original.Config
	newContainerConfig.Image = imageName
	if mutateConfig != nil {
		mutateConfig(&newContainerConfig)
	}

	newHostConfig := *original.HostConfig
	if mutateHostConfig != nil {
		mutateHostConfig(&newHostConfig)
	}

	// No need for a full CreateSandboxDTO here since it's used only for android sandboxes which won't take this path either way
	networkingConfig := d.getContainerNetworkingConfig(dto.CreateSandboxDTO{Id: containerId})

	if _, err := d.apiClient.ContainerCreate(ctx, &newContainerConfig, &newHostConfig, networkingConfig, &v1.Platform{
		Architecture: "amd64",
		OS:           "linux",
	}, containerId); err != nil {
		if rnErr := d.apiClient.ContainerRename(ctx, oldName, containerId); rnErr != nil {
			d.logger.ErrorContext(ctx, "Failed to roll back rename after recreate failure", "containerId", containerId, "oldName", oldName, "error", rnErr)
		}
		return nil, fmt.Errorf("failed to recreate container: %w", err)
	}

	if err := d.apiClient.ContainerRemove(ctx, oldName, container.RemoveOptions{Force: true}); err != nil {
		d.logger.WarnContext(ctx, "Failed to remove old container after recreate", "oldName", oldName, "error", err)
	}

	newInspect, err := d.ContainerInspect(ctx, containerId)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect recreated container: %w", err)
	}
	return newInspect, nil
}

// startContainerWithSysboxRecovery starts the container, healing a stale sysbox-mgr
// registration and retrying a one-off runtime failure (sysbox containers only).
func (d *DockerClient) startContainerWithSysboxRecovery(ctx context.Context, containerId string, c *container.InspectResponse) (*container.InspectResponse, error) {
	err := d.apiClient.ContainerStart(ctx, containerId, container.StartOptions{})
	if err == nil {
		return c, nil
	}
	if !isSysboxContainer(c) {
		return nil, err
	}

	// Stale registration = the container died without `runc delete`, so mgr still
	// holds it and the rootfs cleanup never ran; mgr's unregister performs that
	// missing cleanup, after which a plain start re-registers. Heal only with
	// healthy daemons (else it's a runner-wide outage, not per-container state).
	if isRedundantRegistrationError(err) && d.sysboxDaemonsHealthy(ctx) {
		d.logger.WarnContext(ctx, "Clearing stale sysbox-mgr registration", "containerId", containerId, "error", err)
		if unregErr := d.unregisterFromSysboxMgr(ctx, c.ID); unregErr != nil {
			return nil, fmt.Errorf("sysbox registration self-heal failed: %w", unregErr)
		}
		err = d.apiClient.ContainerStart(ctx, containerId, container.StartOptions{})
	}

	// Absorb a one-off blip; a genuine image/config issue fails again and falls through to kata.
	if isOCIRuntimeCreateError(err) {
		d.logger.WarnContext(ctx, "Retrying container start after sysbox runtime failure", "containerId", containerId, "error", err)
		err = d.apiClient.ContainerStart(ctx, containerId, container.StartOptions{})
	}

	if err != nil {
		return nil, err
	}
	return c, nil
}

func (d *DockerClient) waitForContainerRunning(ctx context.Context, containerId string) (*container.InspectResponse, error) {
	defer timer.Timer()()

	timeout := time.Duration(d.sandboxStartTimeoutSec) * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCtx.Done():
			return nil, errors.New("timeout waiting for the sandbox to start - please ensure that your entrypoint is long-running")
		case <-ticker.C:
			c, err := d.ContainerInspect(timeoutCtx, containerId)
			if err != nil {
				return nil, err
			}

			if c.State.Running {
				return c, nil
			}

			// Report an exited container immediately instead of polling it to
			// the generic timeout above. When PID 1 is the daytona daemon (the
			// standard setup — the user's entrypoint runs as a session inside
			// it), an early exit can only be a platform failure, so say that
			// instead of blaming the user's entrypoint; for sandboxes running
			// a custom entrypoint, keep the long-running guidance. Both get
			// the container's last log lines.
			if c.State.Status == container.StateExited {
				var msg string
				if c.Config != nil && slices.Equal(c.Config.Entrypoint, strslice.StrSlice{common.DAEMON_PATH}) {
					msg = fmt.Sprintf("sandbox exited with code %d before becoming ready", c.State.ExitCode)
				} else {
					msg = fmt.Sprintf("sandbox entrypoint exited with code %d - please ensure that your entrypoint is long-running", c.State.ExitCode)
				}
				if logs := d.containerLogTail(ctx, containerId, 5); logs != "" {
					msg = fmt.Sprintf("%s; last logs: %s", msg, logs)
				}
				return nil, errors.New(msg)
			}
		}
	}
}

// containerLogTail returns the last n log lines of a container as a single
// space-normalized string, or "" if the logs cannot be read. Best-effort: it is
// only used to enrich error messages.
func (d *DockerClient) containerLogTail(ctx context.Context, containerId string, n int) string {
	reader, err := d.apiClient.ContainerLogs(ctx, containerId, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       strconv.Itoa(n),
	})
	if err != nil {
		return ""
	}
	defer reader.Close()

	var buf bytes.Buffer
	_, _ = stdcopy.StdCopy(&buf, &buf, io.LimitReader(reader, 16*1024))

	return strings.Join(strings.Fields(buf.String()), " ")
}
