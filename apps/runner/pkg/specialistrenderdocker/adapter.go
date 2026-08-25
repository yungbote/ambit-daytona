// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

// Package specialistrenderdocker is the Docker authority adapter for isolated
// specialist rendering. It never enters or execs in the product sandbox.
package specialistrenderdocker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/errdefs"
	runnerdocker "github.com/daytonaio/runner/pkg/docker"
	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
	types "github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	filtertypes "github.com/docker/docker/api/types/filters"
	imagetypes "github.com/docker/docker/api/types/image"
	networktypes "github.com/docker/docker/api/types/network"
	systemtypes "github.com/docker/docker/api/types/system"
	clienttypes "github.com/docker/docker/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	operationLabel          = "io.ambit.specialist-render.operation-id"
	fingerprintLabel        = "io.ambit.specialist-render.request-fingerprint"
	parentLabel             = "io.ambit.specialist-render.parent-container-id"
	nonceLabel              = "io.ambit.specialist-render.nonce"
	roleLabel               = "io.ambit.runtime-role"
	defaultExecutionTimeout = 20 * time.Minute
	cleanupTimeout          = 30 * time.Second
	cancellationGrace       = 10 * time.Second
)

type DockerAPI interface {
	Info(ctx context.Context) (systemtypes.Info, error)
	ImageInspect(ctx context.Context, image string, options ...clienttypes.ImageInspectOption) (imagetypes.InspectResponse, error)
	ContainerCreate(
		ctx context.Context,
		config *containertypes.Config,
		hostConfig *containertypes.HostConfig,
		networkingConfig *networktypes.NetworkingConfig,
		platform *ocispec.Platform,
		containerName string,
	) (containertypes.CreateResponse, error)
	ContainerAttach(ctx context.Context, containerID string, options containertypes.AttachOptions) (types.HijackedResponse, error)
	ContainerStart(ctx context.Context, containerID string, options containertypes.StartOptions) error
	ContainerInspect(ctx context.Context, containerID string) (containertypes.InspectResponse, error)
	ContainerTop(ctx context.Context, containerID string, arguments []string) (containertypes.TopResponse, error)
	ContainerWait(
		ctx context.Context,
		containerID string,
		condition containertypes.WaitCondition,
	) (<-chan containertypes.WaitResponse, <-chan error)
	ContainerStop(ctx context.Context, containerID string, options containertypes.StopOptions) error
	ContainerKill(ctx context.Context, containerID string, signal string) error
	ContainerRemove(ctx context.Context, containerID string, options containertypes.RemoveOptions) error
	ContainerList(ctx context.Context, options containertypes.ListOptions) ([]containertypes.Summary, error)
}

type ProcessObservation struct {
	StartTicks            string
	NamespacePID          int
	ExecutablePath        string
	ExecutableDigest      string
	NoNewPrivileges       bool
	SeccompKernelMode     int
	EffectiveCapabilities string
}

type ProcessObserver interface {
	Namespaces(pid int) (mountNamespace string, processNamespace string, err error)
	ObserveHelper(pid int, expectedPath string, expectedDigest string) (ProcessObservation, error)
}

type linuxProcessObserver struct{}

func (linuxProcessObserver) Namespaces(pid int) (string, string, error) {
	return processNamespaces(pid)
}

func (linuxProcessObserver) ObserveHelper(
	pid int,
	expectedPath string,
	expectedDigest string,
) (ProcessObservation, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ProcessObservation{}, err
	}
	digest, err := digestFile(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ProcessObservation{}, err
	}
	startTicks, namespacePID, err := processIdentity(pid)
	if err != nil {
		return ProcessObservation{}, err
	}
	if path != expectedPath || digest != expectedDigest {
		return ProcessObservation{}, errors.New("process executable differs from policy")
	}
	noNewPrivileges, seccompMode, capabilities, err := processSecurity(pid)
	if err != nil {
		return ProcessObservation{}, err
	}
	return ProcessObservation{
		StartTicks: startTicks, NamespacePID: namespacePID,
		ExecutablePath: path, ExecutableDigest: digest,
		NoNewPrivileges: noNewPrivileges, SeccompKernelMode: seccompMode,
		EffectiveCapabilities: capabilities,
	}, nil
}

type Adapter struct {
	api       DockerAPI
	processes ProcessObserver
	now       func() time.Time
}

func New(api DockerAPI) (*Adapter, error) {
	if api == nil {
		return nil, errors.New("Docker specialist-render API is not configured")
	}
	return &Adapter{api: api, processes: linuxProcessObserver{}, now: time.Now}, nil
}

func (adapter *Adapter) Execute(
	ctx context.Context,
	request specialistrender.ProviderExecutionRequest,
) (_ specialistrender.ProviderExecution, err error) {
	providerInfo, err := adapter.api.Info(ctx)
	if err != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: inspect Docker runtime: %v", specialistrender.ErrUnavailable, err)
	}
	runtimeStatus, exists := providerInfo.Runtimes[request.Policy.Runtime]
	runtimeStatusBytes, runtimeStatusErr := generationstop.CanonicalJSON(runtimeStatus.Status)
	if !exists || runtimeStatusErr != nil || digestBytes(runtimeStatusBytes) != request.Policy.RuntimeStatusDigest {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: Docker OCI runtime status differs from policy", specialistrender.ErrConflict)
	}
	image, err := adapter.api.ImageInspect(ctx, request.Policy.Image.Ref)
	if err != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: inspect specialist image: %v", specialistrender.ErrUnavailable, err)
	}
	if err := validateImage(image, request.Policy); err != nil {
		return specialistrender.ProviderExecution{}, err
	}
	parent, err := adapter.api.ContainerInspect(ctx, request.Authority.ExpectedParentGeneration.ContainerID)
	if err != nil || parent.State == nil || !parent.State.Running || parent.State.Pid <= 0 {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: exact parent container is not running", specialistrender.ErrConflict)
	}
	parentMount, parentPID, err := adapter.processes.Namespaces(parent.State.Pid)
	if err != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: observe parent namespaces: %v", specialistrender.ErrUnavailable, err)
	}
	parentRecheck, err := adapter.api.ContainerInspect(ctx, request.Authority.ExpectedParentGeneration.ContainerID)
	if err != nil || parentRecheck.State == nil || !parentRecheck.State.Running ||
		parentRecheck.State.Pid != parent.State.Pid || parentRecheck.ID != parent.ID {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: parent process generation changed during namespace observation", specialistrender.ErrConflict)
	}

	config, hostConfig, command, environmentDigest, err := containerConfiguration(request, image.Config.Env)
	if err != nil {
		return specialistrender.ProviderExecution{}, err
	}
	name := containerName(request.OperationID)
	created, err := adapter.api.ContainerCreate(
		ctx, config, hostConfig, &networktypes.NetworkingConfig{},
		&ocispec.Platform{Architecture: "amd64", OS: "linux"}, name,
	)
	if err != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: create isolated specialist container: %v", specialistrender.ErrUnavailable, err)
	}
	containerID := created.ID
	removed := false
	var collector *specialistrender.HelperSession
	defer func() {
		if err != nil {
			err = cleanupProviderFailure(err, collector, func() error {
				return adapter.cleanupContainer(containerID)
			})
		} else if !removed {
			err = fmt.Errorf("%w: provider returned before exact child removal", specialistrender.ErrOutcomeUnknown)
		}
	}()

	attach, err := adapter.api.ContainerAttach(ctx, containerID, containertypes.AttachOptions{
		Stream: true, Stdin: true, Stdout: true, Stderr: true,
	})
	if err != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: attach isolated specialist PTY: %v", specialistrender.ErrUnavailable, err)
	}
	defer attach.Close()
	if err := adapter.api.ContainerStart(ctx, containerID, containertypes.StartOptions{}); err != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: start isolated specialist container: %v", specialistrender.ErrUnavailable, err)
	}

	executionCtx, cancelExecution, settlementCtx, cancelSettlement := lifecycleContexts(ctx)
	defer cancelExecution()
	defer cancelSettlement()
	if deadline, ok := settlementCtx.Deadline(); ok {
		_ = attach.Conn.SetDeadline(deadline)
	}
	locked := &lockedWriter{writer: attach.Conn}
	cancelDone := make(chan struct{})
	cancelWatcherDone := make(chan struct{})
	ready := make(chan struct{})
	requestDone := make(chan struct{})
	var cancelOnce sync.Once
	cancelState := &helperCancellationState{}
	stopCancelWatcher := func() {
		cancelOnce.Do(func() { close(cancelDone) })
		<-cancelWatcherDone
	}
	defer stopCancelWatcher()
	go runHelperCancellationWatcher(
		executionCtx, attach.Conn, locked, request.Nonce, ready, requestDone,
		cancelDone, cancelWatcherDone, cancelState, time.Now,
	)
	launch, err := adapter.observeLaunch(
		settlementCtx, containerID, name, command, environmentDigest,
		digestBytes(runtimeStatusBytes), request, parentMount, parentPID,
	)
	if err != nil {
		return specialistrender.ProviderExecution{}, err
	}

	bridge, err := specialistrender.NewHelperSession(request, launch.ProcessIdentity)
	if err != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: initialize helper collector: %v", specialistrender.ErrUnavailable, err)
	}
	collector = bridge
	if err := bridge.ReadReady(attach.Reader); err != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: validate helper ready: %v", specialistrender.ErrOutcomeUnknown, err)
	}
	close(ready)

	writeErr := bridge.WriteRequest(&contextWriter{ctx: executionCtx, writer: locked}, request)
	cancelState.markRequest(writeErr == nil)
	close(requestDone)
	result, collectErr := bridge.Collect(attach.Reader)
	cancelState.markTerminal(collectErr == nil)
	stopCancelWatcher()
	if collectErr == nil {
		if deadline, ok := settlementCtx.Deadline(); ok {
			_ = attach.Conn.SetDeadline(deadline)
		}
	}
	if writeErr != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: write helper request: %v", specialistrender.ErrOutcomeUnknown, writeErr)
	}
	if collectErr != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: collect helper response: %v", specialistrender.ErrOutcomeUnknown, collectErr)
	}

	waitStatus, err := adapter.wait(settlementCtx, containerID)
	if err != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: wait for helper exit: %v", specialistrender.ErrOutcomeUnknown, err)
	}
	if int(waitStatus.StatusCode) != result.ExitCode || waitStatus.Error != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: helper terminal and Docker exit differ", specialistrender.ErrOutcomeUnknown)
	}
	exited, err := adapter.api.ContainerInspect(settlementCtx, containerID)
	if err != nil || exited.State == nil || exited.State.Running || exited.State.Pid != 0 ||
		exited.State.ExitCode != result.ExitCode || exited.State.OOMKilled || exited.State.FinishedAt == "" {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: exact exited child state differs", specialistrender.ErrOutcomeUnknown)
	}
	if err := requireAttachEOF(attach.Reader); err != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: %v", specialistrender.ErrOutcomeUnknown, err)
	}
	attach.Close()
	if err := adapter.api.ContainerRemove(settlementCtx, containerID, containertypes.RemoveOptions{}); err != nil {
		return specialistrender.ProviderExecution{}, fmt.Errorf("%w: remove exact specialist container: %v", specialistrender.ErrOutcomeUnknown, err)
	}
	if err := adapter.requireAbsent(settlementCtx, containerID); err != nil {
		return specialistrender.ProviderExecution{}, err
	}
	removed = true
	quiescence := specialistrender.QuiescenceReceipt{
		Schema: specialistrender.QuiescenceSchema, ContainerID: containerID,
		ContainerAbsent: true, ObservedAt: formatTime(adapter.now()),
	}
	return specialistrender.ProviderExecution{
		Launch: launch, ReadyDigest: result.ReadyDigest,
		TerminalDigest: result.TerminalDigest, TerminalKind: result.TerminalKind,
		TerminalOutcome: result.TerminalOutcome, HelperExitCode: result.ExitCode,
		Files: result.Files, Quiescence: quiescence,
	}, nil
}

type helperCancellationState struct {
	mu               sync.Mutex
	requestCoherent  bool
	terminalObserved bool
}

func (state *helperCancellationState) markRequest(coherent bool) {
	state.mu.Lock()
	state.requestCoherent = coherent
	state.mu.Unlock()
}

func (state *helperCancellationState) markTerminal(observed bool) {
	state.mu.Lock()
	state.terminalObserved = observed
	state.mu.Unlock()
}

func (state *helperCancellationState) snapshot() (requestCoherent, terminalObserved bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.requestCoherent, state.terminalObserved
}

func runHelperCancellationWatcher(
	executionCtx context.Context,
	connection net.Conn,
	writer io.Writer,
	nonce string,
	ready <-chan struct{},
	requestDone <-chan struct{},
	cancelDone <-chan struct{},
	watcherDone chan<- struct{},
	state *helperCancellationState,
	now func() time.Time,
) {
	defer close(watcherDone)
	select {
	case <-executionCtx.Done():
	case <-cancelDone:
		return
	}

	// Interrupt blocked request or cancel writes without acquiring the writer
	// mutex they may already hold. The single timer bounds this whole terminal
	// selection, rather than granting a fresh grace interval at each step.
	deadline := now().Add(cancellationGrace)
	if err := connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()
		return
	}
	timer := time.NewTimer(cancellationGrace)
	defer timer.Stop()
	wait := func(signal <-chan struct{}) bool {
		select {
		case <-signal:
			return true
		case <-timer.C:
			if err := connection.SetDeadline(now()); err != nil {
				_ = connection.Close()
			}
			return false
		case <-cancelDone:
			return false
		}
	}
	if !wait(ready) || !wait(requestDone) {
		return
	}
	requestCoherent, terminalObserved := state.snapshot()
	if terminalObserved {
		return
	}
	if !requestCoherent {
		if err := connection.SetDeadline(now()); err != nil {
			_ = connection.Close()
		}
		return
	}
	if err := specialistrender.WriteHelperCancel(writer, nonce); err != nil {
		_ = connection.SetDeadline(now())
		_ = connection.Close()
	}
}

func joinProviderCleanupErrors(primary, collector, container error) error {
	cleanupErr := errors.Join(collector, container)
	if cleanupErr == nil {
		return primary
	}
	return errors.Join(
		primary,
		fmt.Errorf("%w: clean specialist-render provider: %w", specialistrender.ErrOutcomeUnknown, cleanupErr),
	)
}

type providerFailureCleaner interface {
	Cleanup() error
}

func cleanupProviderFailure(
	primary error,
	collector providerFailureCleaner,
	cleanupContainer func() error,
) error {
	var collectorErr error
	if collector != nil {
		collectorErr = collector.Cleanup()
	}
	var containerErr error
	if cleanupContainer != nil {
		containerErr = cleanupContainer()
	}
	return joinProviderCleanupErrors(primary, collectorErr, containerErr)
}

func validateImage(image imagetypes.InspectResponse, policy specialistrender.Policy) error {
	if image.ID != policy.Image.ConfigDigest || image.Config == nil ||
		image.Config.Labels["io.ambit.runtime-pack"] != policy.Image.PackRef ||
		image.Config.Labels["io.ambit.activation"] != "provider-policy-and-composition-bound-only" ||
		image.Config.User != "1000:1000" {
		return fmt.Errorf("%w: specialist image identity, pack label, or user differs", specialistrender.ErrConflict)
	}
	if image.Config.Labels["io.ambit.source-set-sha256"] == "" ||
		image.Config.Labels["org.opencontainers.image.revision"] == "" {
		return fmt.Errorf("%w: specialist image provenance labels are incomplete", specialistrender.ErrConflict)
	}
	return nil
}

func containerConfiguration(
	request specialistrender.ProviderExecutionRequest,
	imageEnvironment []string,
) (*containertypes.Config, *containertypes.HostConfig, []string, string, error) {
	policy := request.Policy
	command := []string{
		"/bin/sh", "-c",
		`stty raw -echo -onlcr && exec "$1" --framed-jsonl --nonce "$2"`,
		specialistrender.RoleRef, policy.Executable, request.Nonce,
	}
	environment := append([]string(nil), imageEnvironment...)
	for _, value := range environment {
		name, _, found := strings.Cut(value, "=")
		upper := strings.ToUpper(name)
		if !found || name == "" || strings.Contains(upper, "SECRET") ||
			strings.Contains(upper, "TOKEN") || strings.Contains(upper, "PASSWORD") ||
			strings.Contains(upper, "PRIVATE_KEY") || strings.Contains(upper, "PRIVATE-KEY") ||
			strings.Contains(upper, "API_KEY") || strings.Contains(upper, "API-KEY") {
			return nil, nil, nil, "", fmt.Errorf("%w: specialist image environment contains a secret-shaped or invalid name", specialistrender.ErrConflict)
		}
	}
	environmentBytes, err := generationstop.CanonicalJSON(environment)
	if err != nil {
		return nil, nil, nil, "", err
	}
	environmentDigest := digestBytes(environmentBytes)
	if environmentDigest != policy.EnvironmentDigest {
		return nil, nil, nil, "", fmt.Errorf("%w: provider environment differs from policy", specialistrender.ErrConflict)
	}
	config := &containertypes.Config{
		Image: policy.Image.ConfigDigest, User: "1000:1000", WorkingDir: "/workspace",
		Entrypoint: command[:1], Cmd: command[1:], Env: environment,
		AttachStdin: true, AttachStdout: true, AttachStderr: true,
		OpenStdin: true, StdinOnce: true, Tty: true,
		Labels: map[string]string{
			runnerdocker.RunnerContainerKindLabel: runnerdocker.RunnerContainerKindSpecialistRender,
			operationLabel:                        request.OperationID,
			fingerprintLabel:                      request.Authority.RequestFingerprint,
			parentLabel:                           request.Authority.ExpectedParentGeneration.ContainerID,
			nonceLabel:                            request.Nonce, roleLabel: specialistrender.RoleRef,
		},
	}
	pids := policy.PIDsLimit
	securityOptions := []string{"no-new-privileges", "seccomp=" + string(policy.Seccomp)}
	tmpfs := map[string]string{
		"/workspace": fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,uid=1000,gid=1000,mode=0700", policy.WorkspaceSize),
		"/tmp":       fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,uid=0,gid=0,mode=1777", policy.ScratchSize),
	}
	host := &containertypes.HostConfig{
		NetworkMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"},
		SecurityOpt: securityOptions, Tmpfs: tmpfs, ShmSize: policy.ShmSize,
		AutoRemove: false, Privileged: false, IpcMode: "private", CgroupnsMode: "private",
		Runtime: policy.Runtime,
		Resources: containertypes.Resources{
			PidsLimit: &pids, Memory: policy.MemoryBytes, MemorySwap: policy.MemoryBytes,
			NanoCPUs: policy.NanoCPUs,
		},
	}
	return config, host, command, environmentDigest, nil
}

func (adapter *Adapter) observeLaunch(
	ctx context.Context,
	containerID string,
	name string,
	command []string,
	environmentDigest string,
	runtimeStatusDigest string,
	request specialistrender.ProviderExecutionRequest,
	parentMount string,
	parentPID string,
) (specialistrender.LaunchObservation, error) {
	deadline := time.Now().Add(30 * time.Second)
	var inspect containertypes.InspectResponse
	var observedPath string
	var observedDigest string
	for time.Now().Before(deadline) {
		value, err := adapter.api.ContainerInspect(ctx, containerID)
		if err != nil {
			return specialistrender.LaunchObservation{}, fmt.Errorf("%w: inspect launched child: %v", specialistrender.ErrUnavailable, err)
		}
		inspect = value
		if inspect.State != nil && inspect.State.Pid > 0 {
			observation, observeErr := adapter.processes.ObserveHelper(
				inspect.State.Pid,
				request.Policy.ProcessExecutablePath,
				request.Policy.ProcessExecutableDigest,
			)
			if observeErr == nil {
				observedPath, observedDigest = observation.ExecutablePath, observation.ExecutableDigest
				if observedPath == request.Policy.ProcessExecutablePath &&
					observedDigest == request.Policy.ProcessExecutableDigest {
					break
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if inspect.State == nil || inspect.State.Pid <= 0 ||
		observedPath != request.Policy.ProcessExecutablePath ||
		observedDigest != request.Policy.ProcessExecutableDigest {
		return specialistrender.LaunchObservation{}, fmt.Errorf("%w: exact helper process executable was not observed", specialistrender.ErrOutcomeUnknown)
	}
	hostPID := inspect.State.Pid
	processObservation, err := adapter.processes.ObserveHelper(
		hostPID,
		request.Policy.ProcessExecutablePath,
		request.Policy.ProcessExecutableDigest,
	)
	if err != nil || processObservation.NamespacePID != 1 {
		return specialistrender.LaunchObservation{}, fmt.Errorf("%w: observe helper process identity: %v", specialistrender.ErrOutcomeUnknown, err)
	}
	mountNamespace, processNamespace, err := adapter.processes.Namespaces(hostPID)
	if err != nil || mountNamespace == parentMount || processNamespace == parentPID {
		return specialistrender.LaunchObservation{}, fmt.Errorf("%w: helper namespace isolation differs", specialistrender.ErrOutcomeUnknown)
	}
	top, err := adapter.api.ContainerTop(ctx, containerID, []string{"-eo", "pid"})
	if err != nil || len(top.Processes) != 1 {
		return specialistrender.LaunchObservation{}, fmt.Errorf("%w: helper process census differs", specialistrender.ErrOutcomeUnknown)
	}
	recheck, err := adapter.api.ContainerInspect(ctx, containerID)
	if err != nil || recheck.State == nil || recheck.State.Pid != hostPID ||
		recheck.ID != containerID || strings.TrimPrefix(recheck.Name, "/") != name ||
		recheck.Image != request.Policy.Image.ConfigDigest || recheck.Config == nil || recheck.HostConfig == nil {
		return specialistrender.LaunchObservation{}, fmt.Errorf("%w: helper launch changed during observation", specialistrender.ErrOutcomeUnknown)
	}
	host := recheck.HostConfig
	observedEnvironment, environmentErr := generationstop.CanonicalJSON(recheck.Config.Env)
	labels := recheck.Config.Labels
	if environmentErr != nil || digestBytes(observedEnvironment) != environmentDigest ||
		recheck.Config.User != "1000:1000" || recheck.Config.WorkingDir != "/workspace" ||
		!recheck.Config.Tty || !recheck.Config.OpenStdin || !recheck.Config.StdinOnce ||
		!recheck.Config.AttachStdin || !recheck.Config.AttachStdout || !recheck.Config.AttachStderr ||
		!equalStrings(recheck.Config.Entrypoint, command[:1]) || !equalStrings(recheck.Config.Cmd, command[1:]) ||
		labels[runnerdocker.RunnerContainerKindLabel] != runnerdocker.RunnerContainerKindSpecialistRender ||
		labels[operationLabel] != request.OperationID ||
		labels[fingerprintLabel] != request.Authority.RequestFingerprint ||
		labels[parentLabel] != request.Authority.ExpectedParentGeneration.ContainerID ||
		labels[nonceLabel] != request.Nonce || labels[roleLabel] != specialistrender.RoleRef ||
		len(recheck.Mounts) != 0 || len(recheck.Config.Volumes) != 0 {
		return specialistrender.LaunchObservation{}, fmt.Errorf("%w: merged helper config, labels, or mounts differ", specialistrender.ErrOutcomeUnknown)
	}
	if host.PidsLimit == nil {
		return specialistrender.LaunchObservation{}, fmt.Errorf("%w: helper PID limit is absent", specialistrender.ErrOutcomeUnknown)
	}
	noNewPrivileges := false
	seccompMode := "docker-default"
	seccompDigest := ""
	for _, option := range host.SecurityOpt {
		switch {
		case option == "no-new-privileges":
			noNewPrivileges = true
		case strings.HasPrefix(option, "seccomp="):
			seccompMode = "custom"
			seccompDigest = digestBytes([]byte(strings.TrimPrefix(option, "seccomp=")))
		default:
			return specialistrender.LaunchObservation{}, fmt.Errorf("%w: unexpected helper security option", specialistrender.ErrOutcomeUnknown)
		}
	}
	if !noNewPrivileges || seccompMode != "custom" ||
		seccompDigest != digestBytes(request.Policy.Seccomp) || len(host.SecurityOpt) != 2 ||
		host.NetworkMode != "none" || !host.ReadonlyRootfs || host.Privileged || host.AutoRemove ||
		len(host.CapDrop) != 1 || host.CapDrop[0] != "ALL" || len(host.CapAdd) != 0 ||
		len(host.Mounts) != 0 || len(host.Binds) != 0 || len(host.VolumesFrom) != 0 ||
		host.Runtime != request.Policy.Runtime || host.PidsLimit == nil ||
		*host.PidsLimit != request.Policy.PIDsLimit || host.Memory != request.Policy.MemoryBytes ||
		host.MemorySwap != request.Policy.MemoryBytes || host.NanoCPUs != request.Policy.NanoCPUs ||
		host.ShmSize != request.Policy.ShmSize || !equalStringMaps(host.Tmpfs, policyTmpfs(request.Policy)) {
		return specialistrender.LaunchObservation{}, fmt.Errorf("%w: helper host isolation differs from policy", specialistrender.ErrOutcomeUnknown)
	}
	return specialistrender.LaunchObservation{
		ObservedAt: formatTime(adapter.now()), ContainerID: containerID, ContainerName: name,
		ImageID: recheck.Image, Command: append([]string(nil), command...),
		ProcessIdentity: specialistrender.ProcessIdentity{PID: 1, StartTicks: processObservation.StartTicks},
		HostPID:         hostPID, ExecutablePath: observedPath, ExecutableDigest: observedDigest,
		RoleRef: specialistrender.RoleRef, User: recheck.Config.User,
		EnvironmentDigest: environmentDigest,
		MountNamespace:    mountNamespace, ProcessNamespace: processNamespace,
		ParentMountNamespace: parentMount, ParentProcessNamespace: parentPID,
		ProcessCount: len(top.Processes), NetworkMode: string(host.NetworkMode),
		ReadonlyRootfs: host.ReadonlyRootfs, CapDrop: append([]string(nil), host.CapDrop...),
		NoNewPrivileges:       processObservation.NoNewPrivileges,
		SeccompKernelMode:     processObservation.SeccompKernelMode,
		EffectiveCapabilities: processObservation.EffectiveCapabilities,
		SeccompMode:           seccompMode, SeccompDigest: seccompDigest,
		Tmpfs: cloneMap(host.Tmpfs), MountCount: len(recheck.Mounts) + len(recheck.Config.Volumes) + len(host.Mounts) + len(host.Binds) + len(host.VolumesFrom),
		PIDsLimit: *host.PidsLimit, MemoryBytes: host.Memory, NanoCPUs: host.NanoCPUs,
		ShmSize: host.ShmSize, Runtime: host.Runtime,
		RuntimeStatusDigest: runtimeStatusDigest,
		ParentGeneration:    request.Authority.ExpectedParentGeneration,
	}, nil
}

func (adapter *Adapter) wait(ctx context.Context, containerID string) (containertypes.WaitResponse, error) {
	status, failures := adapter.api.ContainerWait(ctx, containerID, containertypes.WaitConditionNotRunning)
	select {
	case value := <-status:
		return value, nil
	case err := <-failures:
		return containertypes.WaitResponse{}, err
	case <-ctx.Done():
		return containertypes.WaitResponse{}, ctx.Err()
	}
}

func (adapter *Adapter) cleanupContainer(containerID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	inspect, err := adapter.api.ContainerInspect(ctx, containerID)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if inspect.State != nil && inspect.State.Running {
		zero := 0
		if err := adapter.api.ContainerStop(ctx, containerID, containertypes.StopOptions{Timeout: &zero}); err != nil && !errdefs.IsNotFound(err) {
			if killErr := adapter.api.ContainerKill(ctx, containerID, "SIGKILL"); killErr != nil && !errdefs.IsNotFound(killErr) {
				return errors.Join(err, killErr)
			}
		}
	}
	if err := adapter.api.ContainerRemove(ctx, containerID, containertypes.RemoveOptions{Force: true}); err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	return adapter.requireAbsent(ctx, containerID)
}

func (adapter *Adapter) requireAbsent(ctx context.Context, containerID string) error {
	_, err := adapter.api.ContainerInspect(ctx, containerID)
	if !errdefs.IsNotFound(err) {
		if err == nil {
			return fmt.Errorf("%w: specialist container remains after removal", specialistrender.ErrOutcomeUnknown)
		}
		return fmt.Errorf("%w: prove specialist container absence: %v", specialistrender.ErrOutcomeUnknown, err)
	}
	return nil
}

// ReconcileOrphans removes only containers carrying the provider-task kind
// label. It is safe to run before exposing the specialist service.
func (adapter *Adapter) ReconcileOrphans(ctx context.Context) error {
	values, err := adapter.api.ContainerList(ctx, containertypes.ListOptions{
		All: true, Filters: filtertypes.NewArgs(filtertypes.Arg("label", runnerdocker.RunnerContainerKindLabel+"="+runnerdocker.RunnerContainerKindSpecialistRender)),
	})
	if err != nil {
		return err
	}
	for _, value := range values {
		if value.Labels[runnerdocker.RunnerContainerKindLabel] != runnerdocker.RunnerContainerKindSpecialistRender {
			return errors.New("Docker returned a non-specialist container for the exact orphan filter")
		}
		if err := adapter.cleanupContainer(value.ID); err != nil {
			return fmt.Errorf("reconcile specialist-render orphan %s: %w", value.ID, err)
		}
	}
	return nil
}

func lifecycleContexts(ctx context.Context) (
	context.Context,
	context.CancelFunc,
	context.Context,
	context.CancelFunc,
) {
	deadline := time.Now().Add(defaultExecutionTimeout)
	if supplied, ok := ctx.Deadline(); ok && supplied.Before(deadline) {
		deadline = supplied
	}
	execution, cancelExecution := context.WithDeadline(ctx, deadline)
	settlement, cancelSettlement := context.WithDeadline(context.Background(), deadline.Add(cleanupTimeout))
	return execution, cancelExecution, settlement, cancelSettlement
}

func processIdentity(pid int) (startTicks string, namespacePID int, err error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", 0, err
	}
	closeIndex := strings.LastIndexByte(string(stat), ')')
	if closeIndex < 0 {
		return "", 0, errors.New("process stat command terminator is absent")
	}
	fields := strings.Fields(string(stat[closeIndex+1:]))
	if len(fields) <= 19 {
		return "", 0, errors.New("process stat is incomplete")
	}
	startTicks = fields[19]
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "", 0, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			values := strings.Fields(strings.TrimPrefix(line, "NSpid:"))
			if len(values) == 0 {
				break
			}
			namespacePID, err = strconv.Atoi(values[len(values)-1])
			return startTicks, namespacePID, err
		}
	}
	return "", 0, errors.New("process namespace PID is absent")
}

func processSecurity(pid int) (bool, int, string, error) {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false, 0, "", err
	}
	noNewPrivileges := ""
	seccomp := ""
	capabilities := ""
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "NoNewPrivs":
			noNewPrivileges = fields[1]
		case "Seccomp":
			seccomp = fields[1]
		case "CapEff":
			capabilities = strings.ToLower(fields[1])
		}
	}
	seccompMode, err := strconv.Atoi(seccomp)
	if err != nil || (noNewPrivileges != "0" && noNewPrivileges != "1") ||
		len(capabilities) != 16 {
		return false, 0, "", errors.New("process security status is incomplete")
	}
	return noNewPrivileges == "1", seccompMode, capabilities, nil
}

func processNamespaces(pid int) (string, string, error) {
	mountNamespace, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		return "", "", err
	}
	processNamespace, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		return "", "", err
	}
	return mountNamespace, processNamespace, nil
}

func requireAttachEOF(reader *bufio.Reader) error {
	_, err := reader.ReadByte()
	if err == nil {
		return errors.New("helper emitted bytes after its terminal frame")
	}
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("read helper stream tail: %w", err)
	}
	return nil
}

func containerName(operationID string) string {
	return "ambit-specialist-render-" + strings.ReplaceAll(operationID, "-", "")
}

func digestFile(path string) (string, error) {
	stream, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer stream.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, stream); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func formatTime(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

func cloneMap(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalStringMaps(left map[string]string, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func policyTmpfs(policy specialistrender.Policy) map[string]string {
	return map[string]string{
		"/workspace": fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,uid=1000,gid=1000,mode=0700", policy.WorkspaceSize),
		"/tmp":       fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,uid=0,gid=0,mode=1777", policy.ScratchSize),
	}
}

type lockedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (writer *lockedWriter) Write(value []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.writer.Write(value)
}

type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (writer *contextWriter) Write(value []byte) (int, error) {
	if err := writer.ctx.Err(); err != nil {
		return 0, err
	}
	return writer.writer.Write(value)
}
