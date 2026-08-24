// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daytonaio/common-go/pkg/log"
	"github.com/daytonaio/common-go/pkg/telemetry"
	"github.com/daytonaio/daytona/libs/netleash/pkg/manager"
	"github.com/daytonaio/runner/cmd/runner/config"
	"github.com/daytonaio/runner/internal"
	"github.com/daytonaio/runner/internal/metrics"
	"github.com/daytonaio/runner/pkg/api"
	"github.com/daytonaio/runner/pkg/cache"
	"github.com/daytonaio/runner/pkg/daemon"
	"github.com/daytonaio/runner/pkg/docker"
	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/generationstopdocker"
	"github.com/daytonaio/runner/pkg/netrules"
	"github.com/daytonaio/runner/pkg/runner"
	"github.com/daytonaio/runner/pkg/runner/v2/executor"
	"github.com/daytonaio/runner/pkg/runner/v2/healthcheck"
	"github.com/daytonaio/runner/pkg/runner/v2/poller"
	"github.com/daytonaio/runner/pkg/services"
	"github.com/daytonaio/runner/pkg/sshgateway"
	"github.com/daytonaio/runner/pkg/storage"
	"github.com/daytonaio/runner/pkg/telemetry/filters"
	"github.com/daytonaio/runner/pkg/workingcopy"
	"github.com/docker/docker/client"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	"go.opentelemetry.io/otel"
)

func main() {
	os.Exit(run())
}

func run() int {
	// Init slog logger
	logger := slog.New(tint.NewHandler(os.Stdout, &tint.Options{
		NoColor:    !isatty.IsTerminal(os.Stdout.Fd()),
		TimeFormat: time.RFC3339,
		Level:      log.ParseLogLevel(os.Getenv("LOG_LEVEL")),
	}))

	slog.SetDefault(logger)

	cfg, err := config.GetConfig()
	if err != nil {
		logger.Error("Failed to get config", "error", err)
		return 2
	}
	if cfg.NetleashSecretsEnabled && !cfg.NetleashEnabled {
		logger.Error("NETLEASH_SECRETS_ENABLED requires NETLEASH_ENABLED")
		return 2
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if cfg.OtelLoggingEnabled && cfg.OtelEndpoint != "" {
		logger.Info("OpenTelemetry logging is enabled")

		telemetryConfig := telemetry.Config{
			Endpoint:       cfg.OtelEndpoint,
			Headers:        cfg.GetOtelHeaders(),
			ServiceName:    "daytona-runner",
			ServiceVersion: internal.Version,
			Environment:    cfg.Environment,
		}

		// Initialize OpenTelemetry logging
		newLogger, lp, err := telemetry.InitLogger(ctx, logger, telemetryConfig)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to initialize logger", "error", err)
			return 2
		}

		// Reassign logger to the new OTEL-enabled logger returned by InitLogger.
		// This ensures that all subsequent code uses the logger instance that has OTEL support.
		logger = newLogger

		defer telemetry.ShutdownLogger(logger, lp)
	}

	if cfg.OtelTracingEnabled && cfg.OtelEndpoint != "" {
		logger.Info("OpenTelemetry tracing is enabled")

		telemetryConfig := telemetry.Config{
			Endpoint:       cfg.OtelEndpoint,
			Headers:        cfg.GetOtelHeaders(),
			ServiceName:    "daytona-runner",
			ServiceVersion: internal.Version,
			Environment:    cfg.Environment,
		}

		// Initialize OpenTelemetry tracing with a custom filter to ignore 404 errors
		tp, err := telemetry.InitTracer(ctx, telemetryConfig, &filters.NotFoundExporterFilter{})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to initialize tracer", "error", err)
			return 2
		}
		defer telemetry.ShutdownTracer(logger, tp)
	}

	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
		client.WithTraceProvider(otel.GetTracerProvider()),
	)
	if err != nil {
		logger.Error("Error creating Docker client", "error", err)
		return 2
	}

	// Initialize net rules manager
	persistent := cfg.Environment != "development"
	netRulesManager, err := netrules.NewNetRulesManager(logger, persistent)
	if err != nil {
		logger.Error("Failed to initialize net rules manager", "error", err)
		return 2
	}

	// Start net rules manager
	if err = netRulesManager.Start(); err != nil {
		logger.Error("Failed to start net rules manager", "error", err)
		return 2
	}
	defer netRulesManager.Stop()

	// Start the netleash service: a single, long-lived service that enforces
	// per-sandbox domain allow lists via eBPF egress filtering. It is created
	// once for the runner's lifetime and configured per sandbox on lifecycle
	// events. Disabled unless NETLEASH_ENABLED is set.
	var netleashManager *manager.Manager
	if cfg.NetleashEnabled {
		netleashManager = manager.New(logger, cfg.NetleashInternalDNSZones, cfg.NetleashPinPath)
		logger.Info("Netleash service started")
		// Close (not tear down): on shutdown the eBPF filters stay attached via
		// their bpffs pins so domain filtering survives the restart with no gap.
		defer netleashManager.Close()
	}

	daemonPath, err := daemon.WriteStaticBinary("daemon-amd64")
	if err != nil {
		logger.Error("Error writing daemon binary", "error", err)
		return 2
	}

	pluginPath, err := daemon.WriteStaticBinary("daytona-computer-use")
	if err != nil {
		logger.Error("Error writing plugin binary", "error", err)
		return 2
	}

	backupInfoCache := cache.NewBackupInfoCache(ctx, cfg.BackupInfoCacheRetention)

	dockerClient, err := docker.NewDockerClient(ctx, docker.DockerClientConfig{
		ApiClient:                    cli,
		BackupInfoCache:              backupInfoCache,
		Logger:                       logger,
		AWSRegion:                    cfg.AWSRegion,
		AWSEndpointUrl:               cfg.AWSEndpointUrl,
		AWSAccessKeyId:               cfg.AWSAccessKeyId,
		AWSSecretAccessKey:           cfg.AWSSecretAccessKey,
		DaemonPath:                   daemonPath,
		ComputerUsePluginPath:        pluginPath,
		NetRulesManager:              netRulesManager,
		NetleashManager:              netleashManager,
		ResourceLimitsDisabled:       cfg.ResourceLimitsDisabled,
		DaemonStartTimeoutSec:        cfg.DaemonStartTimeoutSec,
		SandboxStartTimeoutSec:       cfg.SandboxStartTimeoutSec,
		AndroidBootTimeoutSec:        cfg.AndroidBootTimeoutSec,
		UseSnapshotEntrypoint:        cfg.UseSnapshotEntrypoint,
		VolumeCleanupInterval:        cfg.VolumeCleanupInterval,
		VolumeCleanupDryRun:          cfg.VolumeCleanupDryRun,
		VolumeCleanupExclusionPeriod: cfg.VolumeCleanupExclusionPeriod,
		BackupTimeoutMin:             cfg.BackupTimeoutMin,
		SnapshotPullTimeout:          cfg.SnapshotPullTimeout,
		BuildTimeoutMin:              cfg.BuildTimeoutMin,
		BuildCPUCores:                cfg.BuildCPUCores,
		BuildMemoryGB:                cfg.BuildMemoryGB,
		InitializeDaemonTelemetry:    cfg.InitializeDaemonTelemetry,
		ContainerNetwork:             cfg.ContainerNetwork,
		InterSandboxNetworkEnabled:   cfg.InterSandboxNetworkEnabled,
		GpuEnabled:                   cfg.GpuEnabled,
		MountKvmToAndroidSandbox:     cfg.MountKvmToAndroidSandbox,
		SysboxHealthProbes:           cfg.SysboxHealthProbes,
		ContainerdAddress:            cfg.ContainerdAddress,
		ContainerdNamespace:          cfg.ContainerdNamespace,
		SecretProxyEnabled:           cfg.NetleashEnabled && cfg.NetleashSecretsEnabled,
		SecretProxyPort:              cfg.NetleashSecretProxyPort,
		SecretCADir:                  cfg.NetleashSecretCADir,
		DaytonaApiUrl:                cfg.DaytonaApiUrl,
	})
	if err != nil {
		logger.Error("Error creating Docker client wrapper", "error", err)
		return 2
	}
	defer dockerClient.Close()

	// Bring up the shared hostname-aware egress proxy before admitting work. It
	// is the mandatory web-egress path for every domain-restricted sandbox and,
	// when enabled, also injects secrets. Running netleash without this boundary
	// would silently degrade hostname policies to spoofable IP allow lists, so a
	// startup or reconciliation failure is fatal rather than fail-open.
	if cfg.NetleashEnabled {
		if err := dockerClient.EnableEgressProxy(ctx); err != nil {
			logger.Error("Failed to enable required egress proxy", "error", err)
			return 2
		}
		// Adopt surviving domain filters only after the proxy is live. Adoption
		// verifies the hostname gate; incompatible legacy pins are quarantined by
		// the reconcile path instead of being accepted as IP-only enforcement.
		dockerClient.StartNetleashReconcile(ctx)
		dockerClient.StartSecretReconcile(ctx)
	}

	// Start Docker events monitor
	monitorOpts := docker.MonitorOptions{
		OnDestroyEvent: func(ctx context.Context) {
			dockerClient.CleanupOrphanedVolumeMounts(ctx)
		},
	}
	monitor := docker.NewDockerMonitor(logger, cli, netRulesManager, netleashManager, monitorOpts)
	monitorErrChan := make(chan error)
	go func() {
		logger.Info("Starting Docker monitor")
		err = monitor.Start()
		if err != nil {
			monitorErrChan <- err
		}
	}()
	defer monitor.Stop()

	sandboxService := services.NewSandboxService(logger, backupInfoCache, dockerClient)

	// Initialize sandbox state synchronization service
	sandboxSyncService := services.NewSandboxSyncService(services.SandboxSyncServiceConfig{
		Logger:   logger,
		Docker:   dockerClient,
		Interval: 10 * time.Second, // Sync every 10 seconds
	})
	sandboxSyncService.StartSyncProcess(ctx)

	// Initialize SSH Gateway if enabled
	var sshGatewayService *sshgateway.Service
	if sshgateway.IsSSHGatewayEnabled() {
		sshGatewayService = sshgateway.NewService(logger, dockerClient)

		go func() {
			logger.Info("Starting SSH Gateway")
			if err := sshGatewayService.Start(ctx); err != nil {
				logger.Error("SSH Gateway error", "error", err)
			}
		}()
	} else {
		logger.Info("Gateway disabled - set SSH_GATEWAY_ENABLE=true to enable")
	}

	// Create metrics collector
	metricsCollector := metrics.NewCollector(metrics.CollectorConfig{
		Logger:                             logger,
		Docker:                             dockerClient,
		WindowSize:                         cfg.CollectorWindowSize,
		CPUUsageSnapshotInterval:           cfg.CPUUsageSnapshotInterval,
		AllocatedResourcesSnapshotInterval: cfg.AllocatedResourcesSnapshotInterval,
	})
	metricsCollector.Start(ctx)

	// Working-copy captures use Docker's archive API for the exact stopped
	// container generation and private object storage for durable custody. A
	// runner may still boot without object storage so unrelated lifecycle work
	// remains available; the capture routes then fail closed as unavailable.
	var workingCopyCaptures *workingcopy.Service
	var generationStops *generationstop.Service
	privateObjects, privateObjectsErr := storage.GetPrivateObjectStorageClient()
	if privateObjectsErr != nil {
		logger.Warn("Stopped-generation and working-copy custody are unavailable", "error", privateObjectsErr)
	} else {
		generationAdapter, adapterErr := generationstopdocker.New(cli)
		if adapterErr != nil {
			logger.Warn("Stopped-generation custody is unavailable", "error", adapterErr)
		} else {
			generationStops, adapterErr = generationstop.NewService(generationAdapter, privateObjects)
			if adapterErr != nil {
				logger.Warn("Stopped-generation custody is unavailable", "error", adapterErr)
				generationStops = nil
			}
		}
		captureAuthority, authorityErr := workingcopy.NewCaptureAuthority(
			cfg.WorkingCopyCaptureLineageRef,
			cfg.WorkingCopyCaptureProtocolDigest,
			cfg.WorkingCopyCaptureHelperDigest,
		)
		if authorityErr != nil {
			logger.Warn("Working-copy capture is unavailable", "error", authorityErr)
		} else {
			var captureErr error
			workingCopyCaptures, captureErr = workingcopy.NewService(
				cli,
				privateObjects,
				generationStops,
				captureAuthority,
			)
			if captureErr != nil {
				logger.Warn("Working-copy capture is unavailable", "error", captureErr)
				workingCopyCaptures = nil
			}
		}
	}

	_, err = runner.GetInstance(&runner.RunnerInstanceConfig{
		Logger:              logger,
		BackupInfoCache:     backupInfoCache,
		SnapshotErrorCache:  cache.NewSnapshotErrorCache(ctx, cfg.SnapshotErrorCacheRetention),
		Docker:              dockerClient,
		SandboxService:      sandboxService,
		MetricsCollector:    metricsCollector,
		NetRulesManager:     netRulesManager,
		NetleashManager:     netleashManager,
		SSHGatewayService:   sshGatewayService,
		WorkingCopyCaptures: workingCopyCaptures,
		GenerationStops:     generationStops,
	})
	if err != nil {
		logger.Error("Failed to initialize runner instance", "error", err)
		return 2
	}

	if cfg.ApiVersion == 2 {
		healthcheckService, err := healthcheck.NewService(&healthcheck.HealthcheckServiceConfig{
			Interval:   cfg.HealthcheckInterval,
			Timeout:    cfg.HealthcheckTimeout,
			Collector:  metricsCollector,
			Logger:     logger,
			Domain:     cfg.Domain,
			ApiPort:    cfg.ApiPort,
			ProxyPort:  cfg.ApiPort,
			TlsEnabled: cfg.EnableTLS,
			Docker:     dockerClient,
		})
		if err != nil {
			logger.Error("Failed to create healthcheck service", "error", err)
			return 2
		}

		go func() {
			logger.Info("Starting healthcheck service")
			healthcheckService.Start(ctx)
		}()

		executorService, err := executor.NewExecutor(&executor.ExecutorConfig{
			Logger:    logger,
			Docker:    dockerClient,
			Collector: metricsCollector,
		})
		if err != nil {
			logger.Error("Failed to create executor service", "error", err)
			return 2
		}

		pollerService, err := poller.NewService(&poller.PollerServiceConfig{
			PollTimeout: cfg.PollTimeout,
			PollLimit:   cfg.PollLimit,
			Logger:      logger,
			Executor:    executorService,
		})
		if err != nil {
			logger.Error("Failed to create poller service", "error", err)
			return 2
		}

		go func() {
			logger.Info("Starting poller service")
			pollerService.Start(ctx)
		}()
	}

	apiServer := api.NewApiServer(api.ApiServerConfig{
		Logger:      logger,
		ApiPort:     cfg.ApiPort,
		ApiToken:    cfg.ApiToken,
		TLSCertFile: cfg.TLSCertFile,
		TLSKeyFile:  cfg.TLSKeyFile,
		EnableTLS:   cfg.EnableTLS,
		LogRequests: cfg.ApiLogRequests,
	})

	apiServerErrChan := make(chan error)

	go func() {
		err := apiServer.Start(ctx)
		apiServerErrChan <- err
	}()

	interruptChannel := make(chan os.Signal, 1)
	signal.Notify(interruptChannel, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-apiServerErrChan:
		logger.Error("API server error", "error", err)
		return 1
	case <-interruptChannel:
		logger.Info("Signal received, shutting down")
		apiServer.Stop()
		logger.Info("Shutdown complete")
		return 143 // SIGTERM
	case err := <-monitorErrChan:
		logger.Error("Docker monitor error", "error", err)
		return 1
	}
}
