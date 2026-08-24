// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/daytonaio/daytona/libs/netleash/pkg/manager"
	"github.com/daytonaio/runner/pkg/netrules"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

type MonitorOptions struct {
	OnDestroyEvent func(ctx context.Context)
}

type DockerMonitor struct {
	apiClient       client.APIClient
	log             *slog.Logger
	ctx             context.Context
	cancel          context.CancelFunc
	netRulesManager *netrules.NetRulesManager
	netleashManager *manager.Manager
	opts            MonitorOptions
}

func NewDockerMonitor(logger *slog.Logger, apiClient client.APIClient, netRulesManager *netrules.NetRulesManager, netleashManager *manager.Manager, opts MonitorOptions) *DockerMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	return &DockerMonitor{
		apiClient:       apiClient,
		log:             logger.With(slog.String("component", "docker_monitor")),
		ctx:             ctx,
		cancel:          cancel,
		netRulesManager: netRulesManager,
		netleashManager: netleashManager,
		opts:            opts,
	}
}

func (dm *DockerMonitor) Stop() {
	dm.cancel()
}

func (dm *DockerMonitor) Start() error {
	// Start periodic reconciliation
	go dm.reconcilerLoop()

	// Main monitoring loop
	for {
		select {
		case <-dm.ctx.Done():
			dm.log.Info("Context cancelled, stopping monitor...")
			return dm.ctx.Err()

		default:
			if err := dm.monitorEvents(); err != nil {
				if isConnectionError(err) {
					dm.log.Warn("Events stream ended", "error", err)
					dm.log.Info("Reopening events stream in 2 seconds...")
					time.Sleep(2 * time.Second)
					continue
				} else {
					dm.log.Error("Fatal error in monitoring", "error", err)
					return err
				}
			}
		}
	}
}

// isConnectionError checks if the error is related to connection loss
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// io.EOF is the normal way the Docker Events stream ends
	if err == io.EOF {
		return true
	}

	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "context deadline exceeded") ||
		strings.Contains(errStr, "unexpected EOF") ||
		strings.Contains(errStr, "Cannot connect to the Docker daemon")
}

// monitorEvents handles the actual event monitoring with proper error handling
func (dm *DockerMonitor) monitorEvents() error {
	// Create event filters to monitor only container create and stop events
	eventFilters := events.ListOptions{
		Filters: filters.NewArgs(
			filters.Arg("type", "container"),
			filters.Arg("event", "start"),
			filters.Arg("event", "stop"),
			filters.Arg("event", "kill"),
			filters.Arg("event", "destroy"),
		),
	}

	// Start listening for events
	eventsChan, errsChan := dm.apiClient.Events(dm.ctx, eventFilters)

	// Reconnection established successfully
	dm.reconcileNetworkRules("filter", "DOCKER-USER")
	dm.reconcileNetworkRules("mangle", "PREROUTING")
	// Refresh every running sandbox's anti-spoof guard (forceRefresh) so guards
	// missed or left stale while the runner was down are re-anchored on the
	// current veth, and orphans are dropped.
	dm.reconcileSourceGuards(true)

	for {
		select {
		case event := <-eventsChan:
			dm.log.Debug("Received event", "event", event)
			dm.handleContainerEvent(event)

		case err := <-errsChan:
			if err != nil {
				dm.log.Warn("Events stream ended", "error", err)
				return err
			}

		case <-dm.ctx.Done():
			return dm.ctx.Err()
		}
	}
}

func (dm *DockerMonitor) handleContainerEvent(event events.Message) {
	containerID := event.Actor.ID
	action := event.Action
	if !IsSandboxContainer(event.Actor.Attributes) {
		return
	}

	switch action {
	case "start":
		ct, err := dm.apiClient.ContainerInspect(dm.ctx, containerID)
		if err != nil {
			dm.log.Error("Error inspecting container", "error", err)
			return
		}
		shortContainerID := containerID[:12]
		ip := GetContainerIpAddress(dm.ctx, &ct)
		veth := resolveHostVeth(dm.log, &ct, ip)
		err = dm.netRulesManager.AssignNetworkRules(shortContainerID, ip, veth)
		if err != nil {
			dm.log.Error("Error assigning network rules", "error", err)
		}
		dm.applySourceGuard(shortContainerID, ip, veth)
	case "stop":
		// The container's cgroup is torn down on stop, so detach netleash to
		// free its eBPF resources. A subsequent start re-applies the allow list.
		dm.removeNetleash(containerID)
	case "kill":
		shortContainerID := containerID[:12]
		err := dm.netRulesManager.UnassignNetworkRules(shortContainerID)
		if err != nil {
			dm.log.Error("Error unassigning network rules", "error", err)
		}
		err = dm.netRulesManager.RemoveNetworkLimiter(shortContainerID)
		if err != nil {
			dm.log.Error("Error removing network limiter", "error", err)
		}
		dm.removeNetleash(containerID)
	case "destroy":
		shortContainerID := containerID[:12]
		err := dm.netRulesManager.DeleteNetworkRules(shortContainerID)
		if err != nil {
			dm.log.Error("Error deleting network rules", "error", err)
		}
		if err := dm.netRulesManager.RemoveSourceGuard(shortContainerID); err != nil {
			dm.log.Error("Error removing source guard", "containerID", shortContainerID, "error", err)
		}
		dm.removeNetleash(containerID)
		if dm.opts.OnDestroyEvent != nil {
			go dm.opts.OnDestroyEvent(dm.ctx)
		}
	}
}

// removeNetleash detaches any netleash domain allow list for the container.
// The netleash manager keys entries by full container ID. No-op when netleash
// is disabled or no entry exists.
func (dm *DockerMonitor) removeNetleash(containerID string) {
	if dm.netleashManager == nil {
		return
	}
	dm.netleashManager.Remove(containerID)
}

// reconcileNetworkRules is called when reconnection is established
func (dm *DockerMonitor) reconcileNetworkRules(table string, chain string) {
	// List all DOCKER-USER rules that jump to Daytona chains
	rules, err := dm.netRulesManager.ListDaytonaRules(table, chain)
	if err != nil {
		dm.log.Error("Error listing Daytona rules", "error", err)
		return
	}

	for _, rule := range rules {
		// Parse the rule to extract the chain name and its anchor (host veth
		// and/or source IP).
		args, err := netrules.ParseRuleArguments(rule)
		if err != nil {
			dm.log.Error("Error parsing rule", "rule", rule, "error", err)
			continue
		}

		var chainName, sourceIP, physVeth string
		for i, arg := range args {
			if i+1 >= len(args) {
				continue
			}
			switch arg {
			case "-j":
				chainName = args[i+1]
			case "-s":
				sourceIP = args[i+1]
			case "--physdev-in":
				physVeth = args[i+1]
			}
		}

		if chainName == "" || (sourceIP == "" && physVeth == "") {
			dm.log.Warn("Could not extract chain name or anchor from rule", "rule", rule)
			continue
		}

		// Extract container ID from chain name (remove DAYTONA-SB- prefix)
		containerID := strings.TrimPrefix(chainName, "DAYTONA-SB-")
		if containerID == chainName {
			dm.log.Warn("Invalid chain name format", "chainName", chainName)
			continue
		}

		// Inspect the container to get its current network identity
		ct, err := dm.apiClient.ContainerInspect(dm.ctx, containerID)
		if err != nil {
			dm.log.Error("Error inspecting container", "containerID", containerID, "error", err)
			// Container doesn't exist, unassign the rules
			if err := dm.netRulesManager.UnassignNetworkRules(containerID); err != nil {
				dm.log.Error("Error unassigning rules for non-existent container", "containerID", containerID, "error", err)
			} else {
				dm.log.Info("Unassigned rules for non-existent container", "containerID", containerID)
			}
			continue
		}

		ipAddress := GetContainerIpAddress(dm.ctx, &ct)
		currentVeth := resolveHostVeth(dm.log, &ct, ipAddress)

		// Decide whether the existing rule's anchor is still correct.
		stale := false
		switch {
		case currentVeth != "":
			// Preferred, unspoofable anchor is available. The rule is stale if it
			// is a legacy source-IP rule (physVeth == "") or if the veth changed
			// across a container restart.
			stale = physVeth != currentVeth
		case physVeth == "":
			// Cannot resolve the current veth; fall back to the source-IP check so
			// rules left over from a previous container IP are still pruned.
			ruleIP := sourceIP
			if strings.Contains(sourceIP, "/") {
				ruleIP = strings.Split(sourceIP, "/")[0]
			}
			stale = ipAddress != ruleIP
		default:
			// Rule already uses a veth anchor but we can't resolve the current one;
			// leave it untouched rather than risk removing a valid rule.
			stale = false
		}

		if !stale {
			continue
		}

		// Without either a resolvable veth or an IP we cannot build a valid
		// replacement anchor; leave the existing rule in place.
		if currentVeth == "" && ipAddress == "" {
			continue
		}

		dm.log.Warn("Stale sandbox egress anchor; migrating", "containerID", containerID,
			"ruleVeth", physVeth, "currentVeth", currentVeth, "containerIP", ipAddress)

		// Re-add the correct anchor BEFORE deleting the stale one so the sandbox
		// is never transiently unfiltered. Skip the delete if re-add fails.
		var reassignErr error
		switch table {
		case "filter":
			reassignErr = dm.netRulesManager.AssignNetworkRules(containerID, ipAddress, currentVeth)
		case "mangle":
			reassignErr = dm.netRulesManager.SetNetworkLimiter(containerID, ipAddress, currentVeth)
		}
		if reassignErr != nil {
			dm.log.Error("Error re-assigning network rules; keeping existing rule", "containerID", containerID, "error", reassignErr)
			continue
		}

		// Delete the stale rule.
		if err := dm.netRulesManager.DeleteChainRule(table, chain, rule); err != nil {
			dm.log.Error("Error deleting stale rule for container", "containerID", containerID, "error", err)
		} else {
			dm.log.Info("Migrated sandbox egress rule to veth anchor", "containerID", containerID, "veth", currentVeth)
		}
	}
}

// reconcileChains removes orphaned chains for non-existent containers
func (dm *DockerMonitor) reconcileChains(table string) {
	// List all chains that start with DAYTONA-SB-
	chains, err := dm.netRulesManager.ListDaytonaChains(table)
	if err != nil {
		dm.log.Error("Error listing Daytona chains", "error", err)
		return
	}

	for _, chain := range chains {
		// Extract container ID from chain name (remove DAYTONA-SB- prefix)
		containerID := strings.TrimPrefix(chain, "DAYTONA-SB-")
		if containerID == chain {
			dm.log.Warn("Invalid chain name format", "chain", chain)
			continue
		}

		// Check if the container exists
		_, err := dm.apiClient.ContainerInspect(dm.ctx, containerID)
		if err != nil {
			dm.log.Info("Container does not exist, deleting chain", "containerID", containerID, "chain", chain)

			// Delete the orphaned chain
			if err := dm.netRulesManager.ClearAndDeleteChain(table, chain); err != nil {
				dm.log.Error("Error deleting orphaned chain", "chain", chain, "error", err)
			} else {
				dm.log.Info("Deleted orphaned chain", "chain", chain)
			}
		}
	}
}

// reconcilerLoop runs reconciliation every minute
func (dm *DockerMonitor) reconcilerLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-dm.ctx.Done():
			return
		case <-ticker.C:
			dm.log.Debug("Reconciling network rules")
			dm.reconcileNetworkRules("filter", "DOCKER-USER")
			dm.reconcileNetworkRules("mangle", "PREROUTING")
			dm.reconcileChains("filter")
			dm.reconcileChains("mangle")
			// Install guards for any running sandbox missing one, and GC guards
			// whose sandbox is gone. Already-guarded sandboxes are skipped (their
			// guard is kept current by the "start" event), keeping this cheap.
			dm.reconcileSourceGuards(false)
		}
	}
}

// reconcileSourceGuards keeps the per-sandbox anti-spoof guards in sync with the
// set of running containers. When forceRefresh is true every running sandbox's
// guard is rebuilt on its current veth (used on reconnect, where the runner may
// have missed start/restart events and a guard could be stale or absent); when
// false, only sandboxes that have no guard yet get one (the "start" event keeps
// the rest current, so this stays cheap). In both cases guards whose container
// is no longer running are removed.
//
// A running sandbox with no resolvable host veth cannot be guarded — its source
// IP is unverified, so the secret proxy must not trust it. That is logged loudly
// rather than silently leaving a gap.
func (dm *DockerMonitor) reconcileSourceGuards(forceRefresh bool) {
	containers, err := dm.apiClient.ContainerList(dm.ctx, container.ListOptions{All: true})
	if err != nil {
		dm.log.Error("source guard reconcile: failed to list containers", "error", err)
		return
	}

	// Ensure a guard for every running sandbox.
	for _, c := range containers {
		if c.State != "running" || len(c.ID) < 12 || !IsSandboxContainer(c.Labels) {
			continue
		}
		shortID := c.ID[:12]

		if !forceRefresh {
			if has, err := dm.netRulesManager.HasSourceGuard(shortID); err == nil && has {
				continue // already guarded; the start event keeps it current
			}
		}

		ct, err := dm.apiClient.ContainerInspect(dm.ctx, c.ID)
		if err != nil {
			dm.log.Error("source guard reconcile: failed to inspect container", "containerID", shortID, "error", err)
			continue
		}
		ip := GetContainerIpAddress(dm.ctx, &ct)
		veth := resolveHostVeth(dm.log, &ct, ip)
		dm.applySourceGuard(shortID, ip, veth)
	}

	// GC guards whose sandbox no longer exists. Each chain's container is
	// re-checked individually (rather than against a snapshot) so a sandbox that
	// starts mid-reconcile — its guard just installed by the start event — is not
	// mistaken for an orphan and torn down.
	chains, err := dm.netRulesManager.ListAntiSpoofChains()
	if err != nil {
		dm.log.Error("source guard reconcile: failed to list anti-spoof chains", "error", err)
		return
	}
	for _, chain := range chains {
		shortID := strings.TrimPrefix(chain, netrules.AntiSpoofChainPrefix)
		if shortID == chain {
			continue // not an anti-spoof chain
		}
		if _, err := dm.apiClient.ContainerInspect(dm.ctx, shortID); err == nil {
			continue // container still exists; keep its guard
		}
		if err := dm.netRulesManager.RemoveSourceGuard(shortID); err != nil {
			dm.log.Error("source guard reconcile: failed to remove orphan guard", "containerID", shortID, "error", err)
		}
	}
}

// applySourceGuard installs a sandbox's anti-spoof source guard, or logs loudly
// when it can't (no host veth / IP) — in which case the sandbox's source IP is
// unverified and the shared secret proxy must not trust it for tenant identity.
func (dm *DockerMonitor) applySourceGuard(shortContainerID, ip, veth string) {
	if veth == "" || ip == "" {
		dm.log.Warn("Cannot install anti-spoof source guard (no host veth/IP); sandbox source IP is unverified for secret-proxy identity",
			"containerID", shortContainerID, "ip", ip, "veth", veth)
		return
	}
	if err := dm.netRulesManager.SetSourceGuard(shortContainerID, ip, veth); err != nil {
		dm.log.Error("Error installing anti-spoof source guard", "containerID", shortContainerID, "error", err)
	}
}
