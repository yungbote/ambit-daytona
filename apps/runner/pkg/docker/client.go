// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/daytonaio/common-go/pkg/utils"
	"github.com/daytonaio/daytona/libs/netleash/pkg/manager"
	runnerconfig "github.com/daytonaio/runner/cmd/runner/config"
	"github.com/daytonaio/runner/pkg/cache"
	"github.com/daytonaio/runner/pkg/common"
	"github.com/daytonaio/runner/pkg/netrules"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/client"
	"google.golang.org/grpc"
)

type DockerClientConfig struct {
	ApiClient                    client.APIClient
	BackupInfoCache              *cache.BackupInfoCache
	Logger                       *slog.Logger
	AWSRegion                    string
	AWSEndpointUrl               string
	AWSAccessKeyId               string
	AWSSecretAccessKey           string
	DaemonPath                   string
	ComputerUsePluginPath        string
	NetRulesManager              *netrules.NetRulesManager
	NetleashManager              *manager.Manager
	ResourceLimitsDisabled       bool
	DaemonStartTimeoutSec        int
	SandboxStartTimeoutSec       int
	AndroidBootTimeoutSec        int
	UseSnapshotEntrypoint        bool
	VolumeCleanupInterval        time.Duration
	VolumeCleanupDryRun          bool
	VolumeCleanupExclusionPeriod time.Duration
	BackupTimeoutMin             int
	SnapshotPullTimeout          time.Duration
	BuildTimeoutMin              int
	BuildCPUCores                int64
	BuildMemoryGB                int64
	InitializeDaemonTelemetry    bool
	ContainerNetwork             string
	InterSandboxNetworkEnabled   bool
	GpuEnabled                   bool
	MountKvmToAndroidSandbox     bool

	// Sysbox health-probe mode (see sysbox.go).
	SysboxHealthProbes string

	// Containerd endpoint used to detect when a stopped sysbox container's
	// runtime cleanup has finished before committing a backup (see
	// backup_integrity.go). Empty ContainerdAddress means auto-detect.
	ContainerdAddress   string
	ContainerdNamespace string

	// Shared netleash egress proxy (hostname-aware MITM). Whenever a
	// NetleashManager is present the proxy runs, sandboxes with a domain allow
	// list are wired through it, and their web-port egress is gated in eBPF so
	// the allow list is enforced on the requested hostname (SNI/Host), not just
	// on DNS-learned IPs. When SecretProxyEnabled is additionally set, the proxy
	// also swaps secret placeholders for real values in sandboxes' outbound
	// requests.
	SecretProxyEnabled bool
	SecretProxyPort    int    // fixed port the shared proxy binds on the bridge gateway
	SecretCADir        string // dir for the proxy's persisted CA (survives restarts)
	DaytonaApiUrl      string // API base URL the per-sandbox resolver calls
}

func NewDockerClient(ctx context.Context, config DockerClientConfig) (*DockerClient, error) {
	logger := slog.Default().With(slog.String("component", "docker-client"))
	if config.Logger != nil {
		logger = config.Logger.With(slog.String("component", "docker-client"))
	}

	if config.DaemonStartTimeoutSec <= 0 {
		logger.Warn("Invalid daemon start timeout value. Using default value of 60 seconds")
		config.DaemonStartTimeoutSec = 60
	}

	if config.SandboxStartTimeoutSec <= 0 {
		logger.Warn("Invalid sandbox start timeout value. Using default value of 30 seconds")
		config.SandboxStartTimeoutSec = 30
	}

	// Android emulator cold boot can take well over a minute even on capable hosts,
	// so we allow a dedicated longer timeout for the ADB readiness probe.
	if config.AndroidBootTimeoutSec <= 0 {
		logger.Warn("Invalid android boot timeout value. Using default value of 300 seconds")
		config.AndroidBootTimeoutSec = 300
	}

	if config.BackupTimeoutMin <= 0 {
		logger.Warn("Invalid backup timeout value. Using default value of 60 minutes")
		config.BackupTimeoutMin = 60
	}

	var info system.Info
	err := utils.RetryWithExponentialBackoff(
		ctx,
		"get Docker info",
		8,
		1*time.Second,
		5*time.Second,
		func() error {
			var infoErr error
			info, infoErr = config.ApiClient.Info(ctx)
			return infoErr
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get Docker info: %w", err)
	}

	if !config.InterSandboxNetworkEnabled {
		if _, err := config.ApiClient.NetworkInspect(ctx, RUNNER_BRIDGE_NETWORK_NAME, network.InspectOptions{}); err != nil {
			_, err := config.ApiClient.NetworkCreate(ctx, RUNNER_BRIDGE_NETWORK_NAME, network.CreateOptions{
				Driver: "bridge",
				Options: map[string]string{
					"com.docker.network.bridge.enable_icc": "false",
				},
				IPAM: &network.IPAM{
					Driver: "default",
					Config: []network.IPAMConfig{
						{Subnet: "172.20.0.0/16"},
					},
				},
			})

			if err != nil {
				return nil, fmt.Errorf("failed to create %s network: %w", RUNNER_BRIDGE_NETWORK_NAME, err)
			}
		}
	}

	filesystem := ""

	for _, driver := range info.DriverStatus {
		if driver[0] == "Backing Filesystem" {
			filesystem = driver[1]
			break
		}
	}

	gpuCount := 0
	gpuType := ""
	if config.GpuEnabled {
		gpuCount, gpuType = detectGpus(ctx)
		if gpuCount == 0 {
			logger.Warn("GPU_ENABLED=true but nvidia-smi did not report any GPUs; runner will not host GPU sandboxes")
		} else {
			logger.Info("Detected GPUs", "count", gpuCount, "type", gpuType)
		}
	}

	// Backup ownership verification reads committed layers via overlay2's
	// UpperDir; surface unsupported storage drivers once at boot instead of
	// per failed backup.
	if runnerconfig.GetContainerRuntime() == sysboxRuntimeName && info.Driver != "overlay2" {
		logger.Error("Sysbox backups require the overlay2 storage driver; backups will fail on this runner", "driver", info.Driver)
	}

	containerdAddress := resolveContainerdAddress(config.ContainerdAddress)
	if containerdAddress == "" {
		logger.Warn("No containerd socket found; backups of stopped sysbox sandboxes will fail until CONTAINERD_ADDRESS is configured")
	} else {
		logger.Info("Using containerd socket for backup safety checks", "address", containerdAddress)
	}

	return &DockerClient{
		apiClient:                    config.ApiClient,
		backupInfoCache:              config.BackupInfoCache,
		pullTracker:                  &common.Tracker[string]{},
		logger:                       logger,
		awsRegion:                    config.AWSRegion,
		awsEndpointUrl:               config.AWSEndpointUrl,
		awsAccessKeyId:               config.AWSAccessKeyId,
		awsSecretAccessKey:           config.AWSSecretAccessKey,
		volumeMutexes:                make(map[string]*sync.Mutex),
		daemonPath:                   config.DaemonPath,
		computerUsePluginPath:        config.ComputerUsePluginPath,
		netRulesManager:              config.NetRulesManager,
		netleashManager:              config.NetleashManager,
		resourceLimitsDisabled:       config.ResourceLimitsDisabled,
		daemonStartTimeoutSec:        config.DaemonStartTimeoutSec,
		sandboxStartTimeoutSec:       config.SandboxStartTimeoutSec,
		androidBootTimeoutSec:        config.AndroidBootTimeoutSec,
		useSnapshotEntrypoint:        config.UseSnapshotEntrypoint,
		volumeCleanupInterval:        config.VolumeCleanupInterval,
		volumeCleanupDryRun:          config.VolumeCleanupDryRun,
		volumeCleanupExclusionPeriod: config.VolumeCleanupExclusionPeriod,
		backupTimeoutMin:             config.BackupTimeoutMin,
		snapshotPullTimeout:          config.SnapshotPullTimeout,
		buildTimeoutMin:              config.BuildTimeoutMin,
		buildCPUCores:                config.BuildCPUCores,
		buildMemoryGB:                config.BuildMemoryGB,
		initializeDaemonTelemetry:    config.InitializeDaemonTelemetry,
		containerNetwork:             config.ContainerNetwork,
		interSandboxNetworkEnabled:   config.InterSandboxNetworkEnabled,
		gpuEnabled:                   config.GpuEnabled,
		gpuCount:                     gpuCount,
		gpuType:                      gpuType,
		gpuAllocator:                 newGpuAllocator(gpuCount),
		filesystem:                   filesystem,
		mountKvmToAndroidSandbox:     config.MountKvmToAndroidSandbox,
		sysboxHealthProbes:           config.SysboxHealthProbes,
		containerdAddress:            containerdAddress,
		containerdNamespace:          config.ContainerdNamespace,
		secretProxyEnabled:           config.SecretProxyEnabled && config.NetleashManager != nil,
		proxyEnforcementEnabled:      config.NetleashManager != nil,
		egressProxyEnabled:           config.NetleashManager != nil,
		secretProxyPort:              config.SecretProxyPort,
		secretCADir:                  config.SecretCADir,
		daytonaApiUrl:                config.DaytonaApiUrl,
	}, nil
}

// GpuCount returns the number of NVIDIA GPUs detected on the host at startup.
// Returns 0 when GPU support is disabled or no GPU is present.
func (d *DockerClient) GpuCount() int {
	return d.gpuCount
}

// GpuType returns the human-readable name of the first GPU detected on the
// host at startup (e.g. "NVIDIA H100 80GB HBM3"). Returns "" when no GPU is
// present.
func (d *DockerClient) GpuType() string {
	return d.gpuType
}

func (d *DockerClient) ApiClient() client.APIClient {
	return d.apiClient
}

// Close releases long-lived connections held by the client (currently the
// lazily-created containerd connection used for backup safety checks).
func (d *DockerClient) Close() error {
	d.containerdConnMu.Lock()
	defer d.containerdConnMu.Unlock()
	if d.containerdConn == nil {
		return nil
	}
	err := d.containerdConn.Close()
	d.containerdConn = nil
	return err
}

const RUNNER_BRIDGE_NETWORK_NAME = "runner-bridge"

type DockerClient struct {
	apiClient                    client.APIClient
	backupInfoCache              *cache.BackupInfoCache
	pullTracker                  *common.Tracker[string]
	logger                       *slog.Logger
	awsRegion                    string
	awsEndpointUrl               string
	awsAccessKeyId               string
	awsSecretAccessKey           string
	volumeMutexes                map[string]*sync.Mutex
	volumeMutexesMutex           sync.Mutex
	daemonPath                   string
	computerUsePluginPath        string
	netRulesManager              *netrules.NetRulesManager
	netleashManager              *manager.Manager
	resourceLimitsDisabled       bool
	daemonStartTimeoutSec        int
	sandboxStartTimeoutSec       int
	androidBootTimeoutSec        int
	useSnapshotEntrypoint        bool
	volumeCleanupInterval        time.Duration
	volumeCleanupDryRun          bool
	volumeCleanupExclusionPeriod time.Duration
	backupTimeoutMin             int
	snapshotPullTimeout          time.Duration
	buildTimeoutMin              int
	buildCPUCores                int64
	buildMemoryGB                int64
	volumeCleanupMutex           sync.Mutex
	lastVolumeCleanup            time.Time
	initializeDaemonTelemetry    bool
	filesystem                   string
	containerNetwork             string
	interSandboxNetworkEnabled   bool
	gpuEnabled                   bool
	gpuCount                     int
	gpuType                      string
	gpuAllocator                 *gpuAllocator
	mountKvmToAndroidSandbox     bool

	// Sysbox health-probe mode (see sysbox.go).
	sysboxHealthProbes string

	// Containerd endpoint for backup safety checks (see backup_integrity.go).
	containerdAddress   string
	containerdNamespace string
	containerdConn      *grpc.ClientConn
	containerdConnMu    sync.Mutex

	// Shared egress proxy config (see DockerClientConfig).
	secretProxyEnabled      bool // register secret-injecting bindings
	proxyEnforcementEnabled bool // wire allowlisted sandboxes through the proxy + gate web ports in eBPF (on whenever netleash is)
	egressProxyEnabled      bool // run the shared proxy (on whenever netleash is)
	secretProxyPort         int
	secretCADir             string
	daytonaApiUrl           string
	// Set by EnableEgressProxy once the shared proxy is running.
	secretProxyAddr   string // "<gatewayIP>:<port>"; empty when the proxy is off
	secretProxyCACert string // host path to the CA bundle mounted into proxy-wired sandboxes
}
