// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrenderdocker

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

func TestContainerConfigurationIsProviderOwnedAndIsolated(t *testing.T) {
	environment := []string{
		"HOME=/workspace", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
		"PATH=/opt/ambit/runtime-pack/data-research/python/bin:/usr/local/bin:/usr/bin:/bin",
		"PYTHONHASHSEED=0", "PYTHONDONTWRITEBYTECODE=1", "TZ=UTC",
	}
	policy := dockerTestPolicy(t, "data-research", nil, environment)
	request := dockerTestRequest(policy)
	config, host, command, environmentDigest, err := containerConfiguration(request, environment)
	if err != nil {
		t.Fatal(err)
	}
	if config.Image != policy.Image.ConfigDigest || config.User != "1000:1000" ||
		!config.Tty || !config.OpenStdin || !config.AttachStdin || !config.AttachStdout || !config.AttachStderr ||
		config.WorkingDir != "/workspace" || environmentDigest != policy.EnvironmentDigest ||
		len(config.Entrypoint) != 1 || config.Entrypoint[0] != "/bin/sh" ||
		strings.Join(append(config.Entrypoint, config.Cmd...), "\x00") != strings.Join(command, "\x00") {
		t.Fatalf("container config differs: %#v", config)
	}
	if host.NetworkMode != "none" || !host.ReadonlyRootfs || host.Privileged || host.AutoRemove ||
		len(host.CapDrop) != 1 || host.CapDrop[0] != "ALL" || len(host.Mounts) != 0 ||
		len(host.Binds) != 0 || len(host.VolumesFrom) != 0 || len(host.SecurityOpt) != 2 ||
		host.SecurityOpt[0] != "no-new-privileges" || !strings.HasPrefix(host.SecurityOpt[1], "seccomp=") || host.PidsLimit == nil ||
		*host.PidsLimit != policy.PIDsLimit || host.Memory != policy.MemoryBytes ||
		host.MemorySwap != policy.MemoryBytes || host.NanoCPUs != policy.NanoCPUs ||
		host.Tmpfs["/workspace"] == "" || host.Tmpfs["/tmp"] == "" {
		t.Fatalf("host isolation differs: %#v", host)
	}
	if config.Labels["daytona.runner.container-kind"] != "specialist-render" ||
		config.Labels[operationLabel] != request.OperationID ||
		config.Labels[parentLabel] != request.Authority.ExpectedParentGeneration.ContainerID {
		t.Fatalf("provider labels differ: %#v", config.Labels)
	}
}

func TestContainerConfigurationRequiresWebSeccompAndRejectsSecretEnvironment(t *testing.T) {
	environment := []string{"HOME=/workspace", "PATH=/usr/bin:/bin"}
	policy := dockerTestPolicy(t, "web-browser", nil, environment)
	request := dockerTestRequest(policy)
	_, host, _, _, err := containerConfiguration(request, environment)
	if err != nil {
		t.Fatal(err)
	}
	if len(host.SecurityOpt) != 2 || !strings.HasPrefix(host.SecurityOpt[1], "seccomp=") {
		t.Fatalf("web seccomp was not applied exactly: %#v", host.SecurityOpt)
	}
	if _, _, _, _, err := containerConfiguration(request, append(environment, "API_TOKEN=forbidden")); err == nil {
		t.Fatal("secret-shaped environment reached the task container")
	}
}

func TestContextWriterStopsPayloadAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var target strings.Builder
	writer := &contextWriter{ctx: ctx, writer: &target}
	if _, err := writer.Write([]byte("payload")); err == nil || target.Len() != 0 {
		t.Fatalf("cancelled context wrote payload: len=%d err=%v", target.Len(), err)
	}
}

func TestCancellationInterruptsBlockedRequestWithoutSplicingCancelFrame(t *testing.T) {
	connection := newDeadlineBlockingConn()
	writer := &lockedWriter{writer: connection}
	requestWriteDone := make(chan struct{})
	go func() {
		_, _ = writer.Write([]byte("partial request frame"))
		close(requestWriteDone)
	}()
	awaitDockerSignal(t, connection.writeStarted)

	ctx, cancel := context.WithCancel(context.Background())
	ready := closedSignal()
	requestDone := make(chan struct{})
	cancelDone := make(chan struct{})
	watcherDone := make(chan struct{})
	state := &helperCancellationState{}
	go runHelperCancellationWatcher(
		ctx, connection, writer, strings.Repeat("a", 32), ready, requestDone,
		cancelDone, watcherDone, state, time.Now,
	)
	cancel()
	awaitDockerSignal(t, requestWriteDone)
	state.markRequest(false)
	close(requestDone)
	awaitDockerSignal(t, watcherDone)
	if connection.writeCount() != 1 {
		t.Fatalf("cancel frame was spliced after partial request: writes=%d", connection.writeCount())
	}
}

func TestCancellationBoundsBlockedCancelWriteAfterCompleteRequest(t *testing.T) {
	connection := newDeadlineBlockingConn()
	writer := &lockedWriter{writer: connection}
	ctx, cancel := context.WithCancel(context.Background())
	state := &helperCancellationState{}
	state.markRequest(true)
	ready := closedSignal()
	requestDone := closedSignal()
	cancelDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go runHelperCancellationWatcher(
		ctx, connection, writer, strings.Repeat("a", 32), ready, requestDone,
		cancelDone, watcherDone, state, time.Now,
	)
	cancel()
	awaitDockerSignal(t, watcherDone)
	if connection.writeCount() != 1 || connection.deadlineCount() < 1 {
		t.Fatalf("complete request cancellation was not bounded: writes=%d deadlines=%d", connection.writeCount(), connection.deadlineCount())
	}
}

func TestTerminalSelectionRestoresDeadlineOnlyAfterWatcherStops(t *testing.T) {
	connection := newDeadlineBlockingConn()
	ctx, cancel := context.WithCancel(context.Background())
	state := &helperCancellationState{}
	state.markRequest(true)
	state.markTerminal(true)
	watcherDone := make(chan struct{})
	go runHelperCancellationWatcher(
		ctx, connection, &lockedWriter{writer: connection}, strings.Repeat("a", 32),
		closedSignal(), closedSignal(), make(chan struct{}), watcherDone, state, time.Now,
	)
	cancel()
	awaitDockerSignal(t, watcherDone)
	settlementDeadline := time.Now().Add(time.Minute)
	if err := connection.SetDeadline(settlementDeadline); err != nil {
		t.Fatal(err)
	}
	if connection.writeCount() != 0 || !connection.lastDeadline().Equal(settlementDeadline) {
		t.Fatalf("terminal race left a stale cancellation deadline or cancel frame: writes=%d deadline=%v", connection.writeCount(), connection.lastDeadline())
	}
}

func TestJoinProviderCleanupErrorsPreservesPrimaryAndEveryCleanupFailure(t *testing.T) {
	primary := errors.New("primary execution failure")
	collector := errors.New("collector cleanup failure")
	container := errors.New("container cleanup failure")
	cleaner := &injectedProviderCleaner{err: collector}
	containerCalled := false
	err := cleanupProviderFailure(primary, cleaner, func() error {
		containerCalled = true
		return container
	})
	if !errors.Is(err, primary) || !errors.Is(err, collector) || !errors.Is(err, container) ||
		!errors.Is(err, specialistrender.ErrOutcomeUnknown) || !cleaner.called || !containerCalled {
		t.Fatalf("adapter discarded a primary or cleanup failure: %v", err)
	}
}

type injectedProviderCleaner struct {
	err    error
	called bool
}

func (cleaner *injectedProviderCleaner) Cleanup() error {
	cleaner.called = true
	return cleaner.err
}

type deadlineBlockingConn struct {
	writeStarted chan struct{}
	deadlineSet  chan struct{}
	writeOnce    sync.Once
	deadlineOnce sync.Once
	mu           sync.Mutex
	writes       int
	deadlines    int
	last         time.Time
}

func newDeadlineBlockingConn() *deadlineBlockingConn {
	return &deadlineBlockingConn{writeStarted: make(chan struct{}), deadlineSet: make(chan struct{})}
}

func (connection *deadlineBlockingConn) Read([]byte) (int, error) { return 0, io.EOF }

func (connection *deadlineBlockingConn) Write([]byte) (int, error) {
	connection.mu.Lock()
	connection.writes++
	connection.mu.Unlock()
	connection.writeOnce.Do(func() { close(connection.writeStarted) })
	<-connection.deadlineSet
	return 0, os.ErrDeadlineExceeded
}

func (*deadlineBlockingConn) Close() error { return nil }

func (*deadlineBlockingConn) LocalAddr() net.Addr  { return dockerTestAddr("local") }
func (*deadlineBlockingConn) RemoteAddr() net.Addr { return dockerTestAddr("remote") }

func (connection *deadlineBlockingConn) SetDeadline(deadline time.Time) error {
	return connection.setDeadline(deadline)
}

func (connection *deadlineBlockingConn) setDeadline(deadline time.Time) error {
	connection.mu.Lock()
	connection.deadlines++
	connection.last = deadline
	connection.mu.Unlock()
	connection.deadlineOnce.Do(func() { close(connection.deadlineSet) })
	return nil
}

func (connection *deadlineBlockingConn) SetReadDeadline(deadline time.Time) error {
	return connection.SetDeadline(deadline)
}

func (connection *deadlineBlockingConn) SetWriteDeadline(deadline time.Time) error {
	return connection.SetDeadline(deadline)
}

func (connection *deadlineBlockingConn) writeCount() int {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.writes
}

func (connection *deadlineBlockingConn) deadlineCount() int {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.deadlines
}

func (connection *deadlineBlockingConn) lastDeadline() time.Time {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.last
}

type dockerTestAddr string

func (address dockerTestAddr) Network() string { return string(address) }
func (address dockerTestAddr) String() string  { return string(address) }

func closedSignal() chan struct{} {
	result := make(chan struct{})
	close(result)
	return result
}

func awaitDockerSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("cancellation state machine leaked or exceeded its bound")
	}
}

func dockerTestPolicy(t *testing.T, pack string, seccomp []byte, environment []string) specialistrender.Policy {
	t.Helper()
	environmentBytes, err := generationstop.CanonicalJSON(environment)
	if err != nil {
		t.Fatal(err)
	}
	if len(seccomp) == 0 {
		_, current, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("caller path unavailable")
		}
		seccomp, err = os.ReadFile(filepath.Clean(filepath.Join(
			filepath.Dir(current),
			"../../../../images/ambit-agent-workspace/capabilities/c18-specialist-packs/policy/specialist-seccomp-v1.json",
		)))
		if err != nil {
			t.Fatal(err)
		}
	}
	policy := specialistrender.Policy{
		Authority:             specialistrender.Pin{Ref: "ambit.runtime-provider/specialist-render-" + pack + "@1"},
		Composition:           specialistrender.Pin{Ref: "ambit.runtime-composition/test@2", Digest: "sha256:" + strings.Repeat("b", 64)},
		Image:                 specialistrender.ImagePin{Ref: "registry.test/ambit/" + pack + "@sha256:" + strings.Repeat("1", 64), ConfigDigest: "sha256:" + strings.Repeat("1", 64), PackID: pack, PackRef: "ambit.runtime-pack/" + pack + "@1"},
		Interface:             specialistrender.Pin{Ref: specialistrender.InterfaceRef, Digest: "sha256:" + strings.Repeat("2", 64)},
		Executor:              specialistrender.Pin{Ref: "ambit://specialist-render-executors/" + pack + "@1", Digest: "sha256:" + strings.Repeat("3", 64)},
		Executable:            "/opt/ambit/runtime-pack/" + pack + "/bin/ambit-specialist-render",
		ProcessExecutablePath: "/usr/bin/python3", ProcessExecutableDigest: "sha256:" + strings.Repeat("4", 64),
		EnvironmentDigest: digestBytes(environmentBytes), Seccomp: seccomp,
		PIDsLimit: 512, MemoryBytes: 4 * 1024 * 1024 * 1024, NanoCPUs: 4_000_000_000,
		WorkspaceSize: 1024 * 1024 * 1024, ScratchSize: 2 * 1024 * 1024 * 1024,
		ShmSize:                  64 * 1024 * 1024,
		Runtime:                  "runc",
		RuntimeStatusDigest:      "sha256:" + strings.Repeat("c", 64),
		CustodyBytesPerSecond:    4 * 1024 * 1024,
		SettlementBaseSeconds:    30,
		SettlementMaximumSeconds: 180,
	}
	if pack == "web-browser" {
		policy.PIDsLimit = 1024
		policy.MemoryBytes = 6 * 1024 * 1024 * 1024
		policy.ShmSize = 1024 * 1024 * 1024
	}
	policy.Authority.Digest, err = specialistrender.ComputePolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func dockerTestRequest(policy specialistrender.Policy) specialistrender.ProviderExecutionRequest {
	authority := specialistrender.Request{
		OperationID:              "11111111-1111-4111-8111-111111111111",
		ExpectedParentGeneration: generationstop.ExpectedGeneration{ContainerID: strings.Repeat("7", 64)},
		RequestFingerprint:       strings.Repeat("8", 64),
	}
	return specialistrender.ProviderExecutionRequest{
		OperationID: authority.OperationID, Nonce: strings.Repeat("a", 32),
		Authority: authority, Policy: policy,
	}
}
