// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/storage"
)

func TestServiceExecutesOnceAndReplaysDurableResult(t *testing.T) {
	policy := testPolicy(t)
	request := testRequest(t, policy)
	provider := &fakeProvider{execution: testExecution(request, policy)}
	generations := &fakeGenerations{observation: testGenerationObservation(request)}
	objects := newFakeOperationStore()
	registry, err := NewStaticPolicyRegistry([]Policy{policy})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(provider, generations, registry, objects)
	if err != nil {
		t.Fatal(err)
	}
	service.nonce = func() (string, error) { return strings.Repeat("a", 32), nil }
	times := []time.Time{
		mustProviderTime(t, "2026-08-24T00:00:00.000Z"),
		mustProviderTime(t, "2026-08-24T00:00:01.000Z"),
	}
	service.now = func() time.Time {
		value := times[0]
		if len(times) > 1 {
			times = times[1:]
		}
		return value
	}
	command := []byte("canonical-command")
	source := []byte("source")
	request.RequestBytes = int64(len(command))
	request.RequestChunkCount = 1
	request.RequestDigest = sha256Digest(command)
	request.SourceBytes = int64(len(source))
	request.SourceChunkCount = 1
	request.SourceDigest = sha256Digest(source)
	request.RequestFingerprint, err = ComputeRequestFingerprint(request)
	if err != nil {
		t.Fatal(err)
	}
	provider.execution.Launch.ParentGeneration = request.ExpectedParentGeneration
	provider.execution.Launch.ImageID = request.Image.ConfigDigest
	generations.observation = testGenerationObservation(request)

	result, err := service.Execute(
		context.Background(), request, bytesInput(command), bytesInput(source),
	)
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 || result.Receipt.Outcome != "succeeded" {
		t.Fatalf("first execution was not committed exactly once: calls=%d outcome=%q", provider.calls, result.Receipt.Outcome)
	}
	firstDigest := result.Receipt.ReceiptDigest
	cleanupPayloads(result.Files)

	times = []time.Time{mustProviderTime(t, "2026-08-24T01:00:00.000Z")}
	replayed, err := service.Execute(
		context.Background(), request, bytesInput(command), bytesInput(source),
	)
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 || replayed.Receipt.ReceiptDigest != firstDigest {
		t.Fatalf("replay re-executed or changed receipt: calls=%d digest=%q", provider.calls, replayed.Receipt.ReceiptDigest)
	}
	reader, err := replayed.Files[0].Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(payload) != "result" {
		t.Fatalf("durable replay payload differs: %q %v", payload, err)
	}

	observation, err := service.Observe(context.Background(), ObserveRequest{
		Schema: ObserveRequestSchema, OperationID: request.OperationID,
		RequestFingerprint: request.RequestFingerprint, Source: request.Source,
		Owner: request.Owner, Fence: request.Fence,
	})
	if err != nil || observation.Status != "complete" || observation.Receipt == nil ||
		observation.Receipt.ReceiptDigest != firstDigest {
		t.Fatalf("complete observation differs: %#v %v", observation, err)
	}
}

func TestAdmissionBoundsInputSpoolingBeforeDecode(t *testing.T) {
	policy := testPolicy(t)
	registry, _ := NewStaticPolicyRegistry([]Policy{policy})
	service, err := NewServiceWithConcurrency(
		&fakeProvider{}, &fakeGenerations{}, registry, newFakeOperationStore(), 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := service.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second pre-spool admission was not bounded: %v", err)
	}
	first.Release()
	second, err := service.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second.Release()
}

func TestServiceRejectsOperationIDClaimConflict(t *testing.T) {
	policy := testPolicy(t)
	request := testRequest(t, policy)
	provider := &fakeProvider{execution: testExecution(request, policy)}
	generations := &fakeGenerations{observation: testGenerationObservation(request)}
	objects := newFakeOperationStore()
	registry, _ := NewStaticPolicyRegistry([]Policy{policy})
	service, _ := NewService(provider, generations, registry, objects)
	service.nonce = func() (string, error) { return strings.Repeat("a", 32), nil }
	service.now = func() time.Time { return mustProviderTime(t, "2026-08-24T00:00:00.000Z") }
	command := []byte("canonical-command")
	source := []byte("source")
	request.RequestBytes, request.SourceBytes = int64(len(command)), int64(len(source))
	request.RequestChunkCount, request.SourceChunkCount = 1, 1
	request.RequestDigest, request.SourceDigest = sha256Digest(command), sha256Digest(source)
	request.RequestFingerprint, _ = ComputeRequestFingerprint(request)
	provider.execution.Launch.ParentGeneration = request.ExpectedParentGeneration
	provider.execution.Launch.ImageID = request.Image.ConfigDigest
	generations.observation = testGenerationObservation(request)
	_, _ = service.Execute(context.Background(), request, bytesInput(command), bytesInput(source))

	conflict := request
	conflict.ArtifactRenderJobRef = "ambit://artifact-render-jobs/22222222-2222-4222-8222-222222222222"
	conflict.RequestFingerprint, _ = ComputeRequestFingerprint(conflict)
	_, err := service.Execute(context.Background(), conflict, bytesInput(command), bytesInput(source))
	if !errors.Is(err, ErrConflict) || provider.calls != 1 {
		t.Fatalf("claim conflict was not rejected before execution: %v calls=%d", err, provider.calls)
	}
}

func TestServiceRecoversPartialAttemptWithReceiptNamespacedOutputs(t *testing.T) {
	policy := testPolicy(t)
	request := testRequest(t, policy)
	command, source := []byte("canonical-command"), []byte("source")
	request.RequestBytes, request.SourceBytes = int64(len(command)), int64(len(source))
	request.RequestChunkCount, request.SourceChunkCount = 1, 1
	request.RequestDigest, request.SourceDigest = sha256Digest(command), sha256Digest(source)
	request.RequestFingerprint, _ = ComputeRequestFingerprint(request)
	first := testExecution(request, policy)
	provider := &fakeProvider{execution: first}
	generations := &fakeGenerations{observation: testGenerationObservation(request)}
	objects := newFakeOperationStore()
	objects.failReceiptCreates = 1
	registry, _ := NewStaticPolicyRegistry([]Policy{policy})
	service, _ := NewService(provider, generations, registry, objects)
	service.nonce = func() (string, error) { return strings.Repeat("a", 32), nil }
	times := []time.Time{
		mustProviderTime(t, "2026-08-24T00:00:00.000Z"),
		mustProviderTime(t, "2026-08-24T00:00:01.000Z"),
		mustProviderTime(t, "2026-08-24T00:00:02.000Z"),
		mustProviderTime(t, "2026-08-24T00:00:03.000Z"),
	}
	service.now = func() time.Time { value := times[0]; times = times[1:]; return value }
	if _, err := service.Execute(context.Background(), request, bytesInput(command), bytesInput(source)); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("interrupted receipt publication was not outcome-unknown: %v", err)
	}
	second := testExecution(request, policy)
	second.Launch.ObservedAt = "2026-08-24T00:00:02.000Z"
	second.Quiescence.ObservedAt = "2026-08-24T00:00:03.000Z"
	changed := []byte("result-with-new-execution-times")
	second.Files[0].File.ByteLength = int64(len(changed))
	second.Files[0].File.Digest = sha256Digest(changed)
	second.Files[0].Open = func(_ context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(changed)), nil }
	provider.execution = second
	result, err := service.Execute(context.Background(), request, bytesInput(command), bytesInput(source))
	if err != nil {
		t.Fatalf("partial operation did not recover through a new receipt namespace: %v", err)
	}
	if provider.calls != 2 || result.Receipt.Files[0].Digest != sha256Digest(changed) {
		t.Fatalf("recovered receipt differs: calls=%d receipt=%#v", provider.calls, result.Receipt)
	}
	objects.mu.Lock()
	attemptObjects := 0
	for key := range objects.objects {
		if strings.Contains(key, "/attempts/") {
			attemptObjects++
		}
	}
	objects.mu.Unlock()
	if attemptObjects != 1 {
		t.Fatalf("abandoned receipt attempt was not collected: objects=%d", attemptObjects)
	}
}

func TestServiceSettlesAndPersistsExactCancellationAfterCallerContextEnds(t *testing.T) {
	policy := testPolicy(t)
	request := testRequest(t, policy)
	command, source := []byte("canonical-command"), []byte("source")
	request.RequestBytes, request.SourceBytes = int64(len(command)), int64(len(source))
	request.RequestChunkCount, request.SourceChunkCount = 1, 1
	request.RequestDigest, request.SourceDigest = sha256Digest(command), sha256Digest(source)
	request.RequestFingerprint, _ = ComputeRequestFingerprint(request)
	execution := testExecution(request, policy)
	execution.TerminalKind = "cancelled"
	execution.TerminalOutcome = "cancelled"
	execution.HelperExitCode = 130
	execution.Files = nil
	ctx, cancel := context.WithCancel(context.Background())
	provider := &fakeProvider{execution: execution, beforeReturn: cancel}
	generations := &fakeGenerations{observation: testGenerationObservation(request)}
	objects := newFakeOperationStore()
	registry, _ := NewStaticPolicyRegistry([]Policy{policy})
	service, _ := NewService(provider, generations, registry, objects)
	service.nonce = func() (string, error) { return strings.Repeat("a", 32), nil }
	times := []time.Time{
		mustProviderTime(t, "2026-08-24T00:00:00.000Z"),
		mustProviderTime(t, "2026-08-24T00:00:01.000Z"),
	}
	service.now = func() time.Time { value := times[0]; times = times[1:]; return value }
	result, err := service.Execute(ctx, request, bytesInput(command), bytesInput(source))
	if !errors.Is(err, ErrRenderFailed) || result.Receipt.Outcome != "cancelled" {
		t.Fatalf("exact cancellation was not durably settled: outcome=%q err=%v", result.Receipt.Outcome, err)
	}
	if generations.cancelledObservations != 0 {
		t.Fatalf("post-terminal currentness reused cancelled caller context %d times", generations.cancelledObservations)
	}
	observation, err := service.Observe(context.Background(), ObserveRequest{
		Schema: ObserveRequestSchema, OperationID: request.OperationID,
		RequestFingerprint: request.RequestFingerprint, Source: request.Source,
		Owner: request.Owner, Fence: request.Fence,
	})
	if err != nil || observation.Status != "complete" || observation.Receipt == nil ||
		observation.Receipt.Outcome != "cancelled" {
		t.Fatalf("cancelled durable observation differs: %#v %v", observation, err)
	}
}

func TestValidateReceiptRejectsSelfConsistentLaunchForgery(t *testing.T) {
	policy := testPolicy(t)
	request := testRequest(t, policy)
	execution := testExecution(request, policy)
	receipt := receiptFromExecution(t, request, policy, execution)
	if err := ValidateReceiptWithPolicy(receipt, policy); err != nil {
		t.Fatal(err)
	}
	receipt.Launch.NetworkMode = "host"
	receipt.ReceiptDigest, _ = ComputeReceiptDigest(receipt)
	if err := ValidateReceipt(receipt); err == nil {
		t.Fatal("digest-consistent host-network launch was accepted")
	}
}

func TestProviderContractGoldenValues(t *testing.T) {
	policy := testPolicy(t)
	request := testRequest(t, policy)
	if policy.Authority.Digest != "sha256:f68b018ccb07c233e9e76941146579af73b62d3cd0ae6b10bba96cab8b36a4e9" {
		t.Fatalf("policy digest golden drifted: %s", policy.Authority.Digest)
	}
	if request.RequestFingerprint != "7447c92d0ca108e04ad5fd8d86f9c4dad32733b7b10f2bdea7492b7e3a97f3d5" {
		t.Fatalf("request fingerprint golden drifted: %s", request.RequestFingerprint)
	}
	receipt := receiptFromExecution(t, request, policy, testExecution(request, policy))
	encoded, err := generationstop.CanonicalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ReceiptDigest != "sha256:1f421f3b60aa13e5233380463c6bc1a231ffd2ac074932e0605626a567d42890" {
		t.Fatalf("receipt digest golden drifted: %s", receipt.ReceiptDigest)
	}
	fixture, err := os.ReadFile("testdata/provider-contract-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(fixture) != string(encoded)+"\n" {
		t.Fatal("canonical provider contract fixture drifted")
	}
}

func TestMaximumReceiptFitsOneProviderFrame(t *testing.T) {
	policy := testPolicy(t)
	request := testRequest(t, policy)
	request.Source.ProviderResourceID = strings.Repeat("s", 512)
	request.Source.ExpectedProfile = strings.Repeat("p", 128)
	request.Source.ExpectedRuntimeKind = strings.Repeat("r", 128)
	request.Fence.WorkspaceExecutionManifestRef = strings.Repeat("f", 2048)
	request.Image.Ref = "r/" + strings.Repeat("i", 438) + "@sha256:" + strings.Repeat("1", 64)
	request.Image.PackRef = "x:" + strings.Repeat("k", 510)
	request.Executor.Ref = "x:" + strings.Repeat("e", 510)
	request.ProviderPolicy.Ref = "x:" + strings.Repeat("q", 510)
	request.RequestFingerprint, _ = ComputeRequestFingerprint(request)
	execution := testExecution(request, policy)
	execution.Launch.ParentGeneration = request.ExpectedParentGeneration
	execution.Launch.ImageID = request.Image.ConfigDigest
	files := make([]Payload, MaximumOutputFiles)
	for index := range files {
		role := "artifact"
		mediaType := "application/octet-stream"
		if index == 0 {
			role = "result"
			mediaType = "application/vnd.ambit.c18-specialist-render-command-result+json"
		}
		path := fmt.Sprintf("outputs/%0116d-%03d", 0, index)
		payload := []byte{byte(index)}
		files[index] = Payload{File: OutputFile{
			Ordinal: index, Role: role, Path: path,
			MediaType: mediaType, ByteLength: 1, Digest: sha256Digest(payload),
		}, Open: func(_ context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil }, Cleanup: func() error { return nil }}
	}
	execution.Files = files
	receipt := receiptFromExecution(t, request, policy, execution)
	encoded, err := generationstop.CanonicalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	start, err := generationstop.CanonicalJSON(providerResponseStart{
		Schema: ProviderFrameSchema, Kind: "provider_response_start",
		ChunkBytes: RequestChunkBytes, Receipt: receipt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaximumReceiptBytes || len(start)+1 > MaximumFrameBytes {
		t.Fatalf("admitted worst-case receipt cannot be framed: receipt=%d frame=%d", len(encoded), len(start)+1)
	}
	t.Logf("worst admitted receipt=%d bytes provider_response_start=%d bytes", len(encoded), len(start)+1)
}

func testPolicy(t *testing.T) Policy {
	t.Helper()
	policy := Policy{
		Authority:               Pin{Ref: "ambit.runtime-provider/specialist-render-data-research@1"},
		Composition:             Pin{Ref: "ambit.runtime-composition/test@2", Digest: "sha256:" + strings.Repeat("b", 64)},
		Image:                   ImagePin{Ref: "registry.test/ambit/data-research@sha256:" + strings.Repeat("1", 64), ConfigDigest: "sha256:" + strings.Repeat("1", 64), PackID: "data-research", PackRef: "ambit.runtime-pack/data-research@1"},
		Interface:               Pin{Ref: InterfaceRef, Digest: "sha256:" + strings.Repeat("2", 64)},
		Executor:                Pin{Ref: "ambit://specialist-render-executors/data-research@1", Digest: "sha256:" + strings.Repeat("3", 64)},
		Executable:              "/opt/ambit/runtime-pack/data-research/bin/ambit-specialist-render",
		ProcessExecutablePath:   "/usr/local/bin/python3.14",
		ProcessExecutableDigest: "sha256:" + strings.Repeat("4", 64),
		EnvironmentDigest:       "sha256:" + strings.Repeat("5", 64),
		Seccomp:                 testSeccomp(t),
		PIDsLimit:               512, MemoryBytes: 4 * 1024 * 1024 * 1024, NanoCPUs: 4_000_000_000,
		WorkspaceSize: 1024 * 1024 * 1024, ScratchSize: 2 * 1024 * 1024 * 1024,
		ShmSize:                  64 * 1024 * 1024,
		Runtime:                  "runc",
		RuntimeStatusDigest:      "sha256:" + strings.Repeat("c", 64),
		CustodyBytesPerSecond:    4 * 1024 * 1024,
		SettlementBaseSeconds:    30,
		SettlementMaximumSeconds: 180,
	}
	digest, err := ComputePolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.Authority.Digest = digest
	return policy
}

func testRequest(t *testing.T, policy Policy) Request {
	t.Helper()
	request := Request{
		Schema: RequestSchema, OperationID: "11111111-1111-4111-8111-111111111111",
		ArtifactRenderJobRef: "ambit://artifact-render-jobs/11111111-1111-4111-8111-111111111111",
		Composition:          policy.Composition,
		Source:               generationstop.Source{ProviderResourceID: "sandbox", ExpectedProfile: "profile", ExpectedRuntimeKind: "full_image_runtime_pack"},
		Owner: generationstop.ProviderOwner{
			TenantID: "11111111-1111-4111-8111-111111111111", UserID: "22222222-2222-4222-8222-222222222222",
			WorkspaceID: "33333333-3333-4333-8333-333333333333", RunID: "44444444-4444-4444-8444-444444444444",
			GrantID: "55555555-5555-4555-8555-555555555555",
		},
		Fence: generationstop.Fence{WorkspaceExecutionManifestRef: "workspace-execution-manifest:sha256:" + strings.Repeat("6", 64)},
		ExpectedParentGeneration: generationstop.ExpectedGeneration{
			ContainerID: strings.Repeat("7", 64), ContainerCreatedAt: "2026-08-24T00:00:00.000Z",
			ExecutionStartedAt: "2026-08-24T00:00:00.000Z", RestartCount: 0,
		},
		Image: policy.Image, Interface: policy.Interface, Executor: policy.Executor,
		Executable: policy.Executable, ProviderPolicy: policy.Authority,
		RequestBytes: 1, RequestChunkCount: 1, RequestDigest: sha256Digest([]byte("r")),
		SourceBytes: 1, SourceChunkCount: 1, SourceDigest: sha256Digest([]byte("s")),
	}
	request.RequestFingerprint, _ = ComputeRequestFingerprint(request)
	return request
}

func testGenerationObservation(request Request) generationstop.ProviderGenerationObservation {
	return generationstop.ProviderGenerationObservation{
		Source: request.Source, Owner: request.Owner, Fence: request.Fence,
		Generation: request.ExpectedParentGeneration, State: "running", ObservedAt: "2026-08-24T00:00:00Z",
	}
}

func testExecution(request Request, policy Policy) ProviderExecution {
	payload := []byte("result")
	return ProviderExecution{
		Launch: LaunchObservation{
			ObservedAt: "2026-08-24T00:00:00.000Z", ContainerID: strings.Repeat("8", 64),
			ContainerName: "ambit-specialist-render-" + strings.ReplaceAll(request.OperationID, "-", ""),
			ImageID:       request.Image.ConfigDigest, Command: helperCommandLine(policy.Executable, strings.Repeat("a", 32)),
			ProcessIdentity: ProcessIdentity{PID: 1, StartTicks: "100"}, HostPID: 123,
			ExecutablePath: policy.ProcessExecutablePath, ExecutableDigest: policy.ProcessExecutableDigest,
			RoleRef: RoleRef, User: "1000:1000", EnvironmentDigest: policy.EnvironmentDigest,
			MountNamespace: "mnt:[2]", ProcessNamespace: "pid:[2]",
			ParentMountNamespace: "mnt:[1]", ParentProcessNamespace: "pid:[1]", ProcessCount: 1,
			NetworkMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, NoNewPrivileges: true,
			SeccompKernelMode: 2, EffectiveCapabilities: "0000000000000000",
			SeccompMode: "custom", SeccompDigest: sha256Digest(policy.Seccomp),
			Tmpfs: expectedTmpfs(policy), MountCount: 0,
			PIDsLimit: policy.PIDsLimit, MemoryBytes: policy.MemoryBytes, NanoCPUs: policy.NanoCPUs,
			ShmSize: policy.ShmSize, Runtime: policy.Runtime,
			RuntimeStatusDigest: policy.RuntimeStatusDigest,
			ParentGeneration:    request.ExpectedParentGeneration,
		},
		ReadyDigest: "sha256:" + strings.Repeat("9", 64), TerminalDigest: "sha256:" + strings.Repeat("a", 64),
		TerminalKind: "response_end", TerminalOutcome: "succeeded", HelperExitCode: 0,
		Files: []Payload{{
			File: OutputFile{Ordinal: 0, Role: "result", Path: "outputs/render/result.json", MediaType: "application/vnd.ambit.c18-specialist-render-command-result+json", ByteLength: int64(len(payload)), Digest: sha256Digest(payload)},
			Open: func(_ context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil }, Cleanup: func() error { return nil },
		}},
		Quiescence: QuiescenceReceipt{Schema: QuiescenceSchema, ContainerID: strings.Repeat("8", 64), ContainerAbsent: true, ObservedAt: "2026-08-24T00:00:01.000Z"},
	}
}

func receiptFromExecution(t *testing.T, request Request, policy Policy, execution ProviderExecution) Receipt {
	t.Helper()
	files := make([]OutputFile, len(execution.Files))
	var total int64
	for index, payload := range execution.Files {
		files[index] = payload.File
		total += payload.File.ByteLength
	}
	receipt := Receipt{
		Schema: ReceiptSchema, Outcome: execution.TerminalOutcome, Request: request,
		Nonce: strings.Repeat("a", 32), Launch: execution.Launch,
		ReadyDigest: execution.ReadyDigest, TerminalDigest: execution.TerminalDigest,
		TerminalKind: execution.TerminalKind, TerminalOutcome: execution.TerminalOutcome,
		HelperExitCode: execution.HelperExitCode, Files: files, TotalOutputBytes: total,
		StartedAt: "2026-08-24T00:00:00.000Z", Quiescence: execution.Quiescence,
		CompletedAt: "2026-08-24T00:00:01.000Z",
	}
	receipt.ReceiptDigest, _ = ComputeReceiptDigest(receipt)
	return receipt
}

func bytesInput(value []byte) Input {
	return Input{ByteLength: int64(len(value)), Digest: sha256Digest(value), Open: func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(value)), nil
	}}
}

func testSeccomp(t *testing.T) []byte {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller path unavailable")
	}
	path := filepath.Clean(filepath.Join(
		filepath.Dir(current),
		"../../../../images/ambit-agent-workspace/capabilities/c18-specialist-packs/policy/specialist-seccomp-v1.json",
	))
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type fakeProvider struct {
	mu           sync.Mutex
	calls        int
	execution    ProviderExecution
	beforeReturn func()
}

func (provider *fakeProvider) Execute(_ context.Context, _ ProviderExecutionRequest) (ProviderExecution, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.calls++
	if provider.beforeReturn != nil {
		provider.beforeReturn()
	}
	return provider.execution, nil
}

type fakeGenerations struct {
	observation           generationstop.ProviderGenerationObservation
	cancelledObservations int
}

func (fake *fakeGenerations) ObserveProviderCurrent(ctx context.Context, _ generationstop.ProviderGenerationObservationRequest) (generationstop.ProviderGenerationObservation, error) {
	if ctx.Err() != nil {
		fake.cancelledObservations++
		return generationstop.ProviderGenerationObservation{}, ctx.Err()
	}
	return fake.observation, nil
}

type storedObject struct {
	data     []byte
	metadata map[string]string
}

type fakeOperationStore struct {
	mu                 sync.Mutex
	objects            map[string]storedObject
	failReceiptCreates int
}

func newFakeOperationStore() *fakeOperationStore {
	return &fakeOperationStore{objects: make(map[string]storedObject)}
}

func (store *fakeOperationStore) CreatePrivateObject(_ context.Context, key string, data []byte, _ string, metadata map[string]string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if strings.HasSuffix(key, "/receipt.json") && store.failReceiptCreates > 0 {
		store.failReceiptCreates--
		return errors.New("injected receipt publication failure")
	}
	if _, exists := store.objects[key]; exists {
		return storage.ErrPrivateObjectAlreadyExists
	}
	store.objects[key] = storedObject{data: append([]byte(nil), data...), metadata: cloneStringMap(metadata)}
	return nil
}

func (store *fakeOperationStore) CreatePrivateObjectStream(ctx context.Context, key string, reader io.Reader, size int64, contentType string, metadata map[string]string) error {
	value, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil || int64(len(value)) != size {
		return errors.New("stream size differs")
	}
	return store.CreatePrivateObject(ctx, key, value, contentType, metadata)
}

func (store *fakeOperationStore) GetPrivateObject(_ context.Context, key string, maximum int64) ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.objects[key]
	if !exists {
		return nil, storage.ErrPrivateObjectNotFound
	}
	if int64(len(value.data)) > maximum {
		return nil, storage.ErrPrivateObjectTooLarge
	}
	return append([]byte(nil), value.data...), nil
}

func (store *fakeOperationStore) OpenPrivateObject(_ context.Context, key string) (io.ReadCloser, storage.PrivateObjectInfo, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.objects[key]
	if !exists {
		return nil, storage.PrivateObjectInfo{}, storage.ErrPrivateObjectNotFound
	}
	info := storage.PrivateObjectInfo{Size: int64(len(value.data)), ContentSHA256: sha256Digest(value.data), UserMetadata: cloneStringMap(value.metadata)}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), value.data...))), info, nil
}

func (store *fakeOperationStore) StatPrivateObject(_ context.Context, key string) (storage.PrivateObjectInfo, error) {
	reader, info, err := store.OpenPrivateObject(context.Background(), key)
	if reader != nil {
		_ = reader.Close()
	}
	return info, err
}

func (store *fakeOperationStore) ListPrivateObjects(_ context.Context, prefix string, maximum int) ([]string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	keys := make([]string, 0)
	for key := range store.objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > maximum {
		return nil, storage.ErrPrivateObjectListTooLarge
	}
	return keys, nil
}

func (store *fakeOperationStore) DeletePrivateObject(_ context.Context, key string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.objects, key)
	return nil
}

func mustProviderTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
