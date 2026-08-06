// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"
)

// StartNetleashReconcile runs an initial netleash reconcile and then repeats it
// periodically for the lifetime of ctx. No-op when netleash is disabled.
//
// This is what makes domain filtering survive a runner restart: the eBPF
// filters stay attached to the sandbox cgroups via their bpffs pins (zero gap),
// and the reconcile re-attaches this process's management to them (Adopt). It
// also self-heals: it tears down pins whose sandbox is gone.
func (d *DockerClient) StartNetleashReconcile(ctx context.Context) {
	if d.netleashManager == nil {
		return
	}
	d.ReconcileNetleash(ctx)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.ReconcileNetleash(ctx)
			}
		}
	}()
}

// ReconcileNetleash brings netleash management in line with the pinned eBPF
// filters, which are the single source of truth (they hold the live allow list
// and survive a restart of this process):
//
//   - A pinned filter whose sandbox is still alive but isn't yet managed by this
//     process is adopted (zero gap) — this is the post-restart recovery path.
//   - A pinned filter whose sandbox is gone or terminal is torn down, freeing
//     the eBPF programs and the bpffs pins.
//
// It deliberately does NOT (re)create filters from any external hint: a sandbox
// gets a filter only via the create/start/network-settings paths, and that
// filter is then pinned. So there is nothing to re-derive — if a pin exists the
// sandbox should be filtered, and if it doesn't it shouldn't. (A pin lost to a
// host reboot also loses the sandbox, which the control plane re-applies on
// restart.) Idempotent and safe to call repeatedly.
func (d *DockerClient) ReconcileNetleash(ctx context.Context) {
	if d.netleashManager == nil {
		return
	}

	pinned, err := d.netleashManager.PinnedWorkloads()
	if err != nil {
		d.logger.ErrorContext(ctx, "netleash reconcile: failed to list pinned workloads", "error", err)
		return
	}
	if len(pinned) == 0 {
		return
	}

	containers, err := d.apiClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		d.logger.ErrorContext(ctx, "netleash reconcile: failed to list containers", "error", err)
		return
	}
	state := make(map[string]string, len(containers))
	for _, c := range containers {
		state[c.ID] = c.State
	}

	for _, id := range pinned {
		st, present := state[id]
		// Tear down the filter once the sandbox is gone or terminal — its cgroup
		// is being torn down, so the pin is just leaked kernel state. Transient
		// states (paused, restarting, created) keep their filter.
		if !present || st == "exited" || st == "dead" || st == "removing" {
			d.logger.InfoContext(ctx, "netleash reconcile: removing filter for gone sandbox", "containerId", id, "state", st)
			d.netleashManager.Remove(id)
			continue
		}
		// Sandbox is alive and its filter survived — re-attach management (the
		// programs never detached, so this is a zero-gap adoption).
		if !d.netleashManager.IsManaged(id) {
			if err := d.netleashManager.Adopt(id); err != nil {
				// Never tear down an unadoptable filter while its workload is still
				// running: that converts a recovery error into unrestricted egress.
				// Quarantine and stop it; the surviving pin remains the backstop until
				// the next reconcile observes the terminal container and removes it.
				info, inspectErr := d.ContainerInspect(ctx, id)
				if inspectErr != nil {
					d.logger.ErrorContext(ctx, "netleash reconcile: pinned filter is not adoptable and container inspection failed; leaving filter attached", "containerId", id, "error", err, "inspectError", inspectErr)
					continue
				}
				containmentErr := d.rejectSandboxAdmission(ctx, info, fmt.Errorf("adopting persisted hostname policy: %w", err))
				d.logger.ErrorContext(ctx, "netleash reconcile: pinned filter is not adoptable; sandbox quarantined", "containerId", id, "error", containmentErr)
				continue
			}
			d.logger.InfoContext(ctx, "netleash reconcile: adopted pinned filter (zero gap)", "containerId", id)
		}
	}
}
