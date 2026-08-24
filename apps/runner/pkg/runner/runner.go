// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package runner

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/daytonaio/daytona/libs/netleash/pkg/manager"
	"github.com/daytonaio/runner/internal/metrics"
	"github.com/daytonaio/runner/pkg/cache"
	"github.com/daytonaio/runner/pkg/docker"
	"github.com/daytonaio/runner/pkg/models"
	"github.com/daytonaio/runner/pkg/netrules"
	"github.com/daytonaio/runner/pkg/services"
	"github.com/daytonaio/runner/pkg/sshgateway"
	"github.com/daytonaio/runner/pkg/workingcopy"
)

type RunnerInstanceConfig struct {
	Logger              *slog.Logger
	BackupInfoCache     *cache.BackupInfoCache
	SnapshotErrorCache  *cache.SnapshotErrorCache
	Docker              *docker.DockerClient
	MetricsCollector    *metrics.Collector
	SandboxService      *services.SandboxService
	NetRulesManager     *netrules.NetRulesManager
	NetleashManager     *manager.Manager
	SSHGatewayService   *sshgateway.Service
	WorkingCopyCaptures *workingcopy.Service
}

type Runner struct {
	Logger              *slog.Logger
	BackupInfoCache     *cache.BackupInfoCache
	SnapshotErrorCache  *cache.SnapshotErrorCache
	Docker              *docker.DockerClient
	MetricsCollector    *metrics.Collector
	SandboxService      *services.SandboxService
	NetRulesManager     *netrules.NetRulesManager
	NetleashManager     *manager.Manager
	SSHGatewayService   *sshgateway.Service
	WorkingCopyCaptures *workingcopy.Service
}

var runner *Runner

func GetInstance(config *RunnerInstanceConfig) (*Runner, error) {
	if config != nil && runner != nil {
		return nil, errors.New("runner instance already initialized")
	}

	if runner == nil {
		if config == nil {
			return nil, errors.New("runner instance not initialized and no config provided")
		}

		logger := slog.Default()
		if config.Logger != nil {
			logger = config.Logger
		}

		runner = &Runner{
			Logger:              logger.With(slog.String("component", "runner")),
			BackupInfoCache:     config.BackupInfoCache,
			SnapshotErrorCache:  config.SnapshotErrorCache,
			Docker:              config.Docker,
			SandboxService:      config.SandboxService,
			MetricsCollector:    config.MetricsCollector,
			NetRulesManager:     config.NetRulesManager,
			NetleashManager:     config.NetleashManager,
			SSHGatewayService:   config.SSHGatewayService,
			WorkingCopyCaptures: config.WorkingCopyCaptures,
		}
	}

	return runner, nil
}

func (r *Runner) InspectRunnerServices(ctx context.Context) []models.RunnerServiceInfo {
	serviceProbes := r.Docker.ServiceHealthProbes()

	runnerServicesInfo := make([]models.RunnerServiceInfo, 0, len(serviceProbes))
	for _, probe := range serviceProbes {
		info := models.RunnerServiceInfo{ServiceName: probe.Name, Healthy: true}

		// Each probe gets its own timeout so a slow one can't starve the others.
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := probe.Ping(probeCtx)
		cancel()
		if err != nil {
			r.Logger.WarnContext(ctx, "Service health check failed", "service", probe.Name, "error", err)
			info.Healthy = false
			info.Err = err
		}
		runnerServicesInfo = append(runnerServicesInfo, info)
	}

	return runnerServicesInfo
}
