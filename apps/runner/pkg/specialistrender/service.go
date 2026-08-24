// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/google/uuid"
)

var providerTimePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)

var (
	ErrInvalidRequest = errors.New("invalid specialist-render request")
	ErrConflict       = errors.New("specialist-render authority conflict")
	ErrUnavailable    = errors.New("specialist-render provider unavailable")
	ErrNotFound       = errors.New("specialist-render parent generation not found")
	ErrOutcomeUnknown = errors.New("specialist-render outcome is unknown")
	ErrRenderFailed   = errors.New("specialist render failed")
)

type GenerationObserver interface {
	ObserveProviderCurrent(
		ctx context.Context,
		request generationstop.ProviderGenerationObservationRequest,
	) (generationstop.ProviderGenerationObservation, error)
}

type PolicyRegistry interface {
	Resolve(request Request) (Policy, error)
}

type Service struct {
	provider    Provider
	generations GenerationObserver
	policies    PolicyRegistry
	store       OperationStore
	concurrency chan struct{}
	locks       keyedLocks
	now         func() time.Time
	nonce       func() (string, error)
}

type ExecutionResult struct {
	Receipt Receipt
	Files   []Payload
}

type Admission struct {
	service *Service
	once    sync.Once
}

func (service *Service) Acquire(ctx context.Context) (*Admission, error) {
	select {
	case service.concurrency <- struct{}{}:
		return &Admission{service: service}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (admission *Admission) Release() {
	if admission == nil || admission.service == nil {
		return
	}
	admission.once.Do(func() { <-admission.service.concurrency })
}

func NewService(
	provider Provider,
	generations GenerationObserver,
	policies PolicyRegistry,
	store OperationStore,
) (*Service, error) {
	return NewServiceWithConcurrency(provider, generations, policies, store, 1)
}

func NewServiceWithConcurrency(
	provider Provider,
	generations GenerationObserver,
	policies PolicyRegistry,
	store OperationStore,
	maximumConcurrent int,
) (*Service, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: isolated execution provider is not configured", ErrUnavailable)
	}
	if generations == nil {
		return nil, fmt.Errorf("%w: parent-generation observer is not configured", ErrUnavailable)
	}
	if policies == nil {
		return nil, fmt.Errorf("%w: runner-owned policy registry is not configured", ErrUnavailable)
	}
	if store == nil {
		return nil, fmt.Errorf("%w: durable operation custody is not configured", ErrUnavailable)
	}
	if maximumConcurrent <= 0 || maximumConcurrent > 64 {
		return nil, fmt.Errorf("%w: maximum concurrency is outside the provider bound", ErrUnavailable)
	}
	return &Service{
		provider:    provider,
		generations: generations,
		policies:    policies,
		store:       store,
		concurrency: make(chan struct{}, maximumConcurrent),
		locks:       keyedLocks{items: make(map[string]*keyedLock)},
		now:         time.Now,
		nonce:       randomNonce,
	}, nil
}

func (service *Service) Execute(
	ctx context.Context,
	request Request,
	requestInput Input,
	sourceInput Input,
) (ExecutionResult, error) {
	admission, err := service.Acquire(ctx)
	if err != nil {
		return ExecutionResult{}, err
	}
	defer admission.Release()
	return service.ExecuteAdmitted(ctx, admission, request, requestInput, sourceInput)
}

func (service *Service) ExecuteAdmitted(
	ctx context.Context,
	admission *Admission,
	request Request,
	requestInput Input,
	sourceInput Input,
) (ExecutionResult, error) {
	if admission == nil || admission.service != service {
		return ExecutionResult{}, invalidf("specialist-render admission lease is invalid")
	}
	startedAt := service.now().UTC()
	request = cloneRequest(request)
	if err := ValidateRequest(request); err != nil {
		return ExecutionResult{}, err
	}
	if err := requireInput(requestInput, request.RequestBytes, request.RequestDigest, MaximumRequestBytes, "request"); err != nil {
		return ExecutionResult{}, err
	}
	if err := requireInput(sourceInput, request.SourceBytes, request.SourceDigest, MaximumSourceBytes, "source"); err != nil {
		return ExecutionResult{}, err
	}

	policy, err := service.policies.Resolve(request)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: resolve runner-owned policy: %v", ErrUnavailable, err)
	}
	if err := requireExactPolicy(request, policy); err != nil {
		return ExecutionResult{}, err
	}
	keys := keysForRequest(request)
	release := service.locks.acquire(keys.claim)
	defer release()
	if err := service.ensureClaim(ctx, keys, request); err != nil {
		return ExecutionResult{}, err
	}
	if existing, complete, err := service.readReceipt(ctx, keys, request, policy); err != nil {
		return ExecutionResult{}, err
	} else if complete {
		if existing.Receipt.Outcome != "succeeded" {
			return existing, ErrRenderFailed
		}
		return existing, nil
	}
	before, err := service.observeExactParent(ctx, request)
	if err != nil {
		return ExecutionResult{}, err
	}

	nonce, err := service.nonce()
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: generate transport nonce: %v", ErrUnavailable, err)
	}
	execution, err := service.provider.Execute(ctx, ProviderExecutionRequest{
		OperationID: request.OperationID,
		Nonce:       nonce,
		Authority:   request,
		Policy:      clonePolicy(policy),
		Request:     requestInput,
		Source:      sourceInput,
	})
	if err != nil {
		return ExecutionResult{}, err
	}
	accepted := false
	defer func() {
		if !accepted {
			cleanupPayloads(execution.Files)
		}
	}()

	if err := validateProviderExecution(execution, request, policy, nonce, before.Generation, startedAt); err != nil {
		return ExecutionResult{}, err
	}
	files := make([]OutputFile, len(execution.Files))
	var total int64
	for index, payload := range execution.Files {
		files[index] = payload.File
		total += payload.File.ByteLength
	}
	settlementSeconds := policy.SettlementBaseSeconds +
		(total+policy.CustodyBytesPerSecond-1)/policy.CustodyBytesPerSecond
	if settlementSeconds > policy.SettlementMaximumSeconds {
		return ExecutionResult{}, fmt.Errorf("%w: output exceeds provider settlement budget", ErrOutcomeUnknown)
	}
	settlementCtx, cancelSettlement := context.WithTimeout(
		context.Background(), time.Duration(settlementSeconds)*time.Second,
	)
	defer cancelSettlement()
	if _, err := service.observeExactParent(settlementCtx, request); err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: parent currentness after helper quiescence: %v", ErrOutcomeUnknown, err)
	}
	receipt := Receipt{
		Schema:           ReceiptSchema,
		Outcome:          execution.TerminalOutcome,
		Request:          request,
		Nonce:            nonce,
		Launch:           execution.Launch,
		ReadyDigest:      execution.ReadyDigest,
		TerminalDigest:   execution.TerminalDigest,
		TerminalKind:     execution.TerminalKind,
		TerminalOutcome:  execution.TerminalOutcome,
		HelperExitCode:   execution.HelperExitCode,
		Files:            files,
		TotalOutputBytes: total,
		StartedAt:        formatProviderTime(startedAt),
		Quiescence:       execution.Quiescence,
		CompletedAt:      formatProviderTime(service.now().UTC()),
	}
	receiptDigest, err := ComputeReceiptDigest(receipt)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: compute receipt digest: %v", ErrUnavailable, err)
	}
	receipt.ReceiptDigest = receiptDigest
	if err := ValidateReceiptWithPolicy(receipt, policy); err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: constructed receipt is invalid: %v", ErrOutcomeUnknown, err)
	}
	result, err := service.publishResult(
		settlementCtx,
		keys,
		ExecutionResult{Receipt: receipt, Files: execution.Files},
	)
	if err != nil {
		return ExecutionResult{}, err
	}
	accepted = true
	if result.Receipt.Outcome != "succeeded" {
		return result, ErrRenderFailed
	}
	return result, nil
}

func (service *Service) observeExactParent(
	ctx context.Context,
	request Request,
) (generationstop.ProviderGenerationObservation, error) {
	observation, err := service.generations.ObserveProviderCurrent(
		ctx,
		generationstop.ProviderGenerationObservationRequest{
			Source: request.Source,
			Owner:  request.Owner,
			Fence:  request.Fence,
		},
	)
	if err != nil {
		if errors.Is(err, generationstop.ErrNotFound) {
			return generationstop.ProviderGenerationObservation{}, fmt.Errorf("%w: parent sandbox generation is absent", ErrNotFound)
		}
		if errors.Is(err, generationstop.ErrConflict) {
			return generationstop.ProviderGenerationObservation{}, fmt.Errorf("%w: observe parent generation: %v", ErrConflict, err)
		}
		return generationstop.ProviderGenerationObservation{}, fmt.Errorf("%w: observe parent generation: %v", ErrUnavailable, err)
	}
	if observation.Generation != request.ExpectedParentGeneration || observation.State != "running" {
		return generationstop.ProviderGenerationObservation{}, fmt.Errorf(
			"%w: current parent generation or state differs from admitted running generation",
			ErrConflict,
		)
	}
	return observation, nil
}

func ValidateRequest(request Request) error {
	if request.Schema != RequestSchema {
		return invalidf("request schema is invalid")
	}
	if parsed, err := uuid.Parse(request.OperationID); err != nil || parsed.String() != request.OperationID || parsed == uuid.Nil {
		return invalidf("operationId must be a non-nil canonical UUID")
	}
	if !strings.HasPrefix(request.ArtifactRenderJobRef, "ambit://artifact-render-jobs/") ||
		len(request.ArtifactRenderJobRef) > 512 {
		return invalidf("artifactRenderJobRef is invalid")
	}
	jobID := strings.TrimPrefix(request.ArtifactRenderJobRef, "ambit://artifact-render-jobs/")
	if parsed, err := uuid.Parse(jobID); err != nil || parsed.String() != jobID || parsed == uuid.Nil {
		return invalidf("artifactRenderJobRef must end in a canonical UUID")
	}
	if !boundedOperationalRef(request.Composition.Ref, 512) || !exactDigest(request.Composition.Digest) {
		return invalidf("composition pin is invalid")
	}
	if err := generationstop.ValidateSource(request.Source); err != nil {
		return invalidf("source is invalid: %v", err)
	}
	if err := generationstop.ValidateProviderOwner(request.Owner); err != nil {
		return invalidf("owner is invalid: %v", err)
	}
	if request.Fence.WorkspaceExecutionManifestRef == "" || len(request.Fence.WorkspaceExecutionManifestRef) > 2048 {
		return invalidf("workspace execution manifest fence is invalid")
	}
	if err := validateParentGeneration(request.ExpectedParentGeneration); err != nil {
		return err
	}
	if request.Interface.Ref != InterfaceRef || !exactDigest(request.Interface.Digest) {
		return invalidf("interface pin is invalid")
	}
	if !exactDigest(request.Executor.Digest) || !boundedOperationalRef(request.Executor.Ref, 512) {
		return invalidf("executor pin is invalid")
	}
	if !exactDigest(request.Image.ConfigDigest) || !immutableOCIReference(request.Image.Ref) ||
		request.Image.PackID == "" || len(request.Image.PackID) > 64 ||
		!boundedOperationalRef(request.Image.PackRef, 512) {
		return invalidf("image pin is invalid")
	}
	if !strings.HasPrefix(request.Executable, "/opt/ambit/runtime-pack/") || len(request.Executable) > 512 {
		return invalidf("executable is invalid")
	}
	if !boundedOperationalRef(request.ProviderPolicy.Ref, 512) ||
		!exactDigest(request.ProviderPolicy.Digest) {
		return invalidf("provider policy pin is invalid")
	}
	if err := requirePayloadSummary(
		request.RequestBytes,
		request.RequestChunkCount,
		request.RequestDigest,
		MaximumRequestBytes,
		"request",
	); err != nil {
		return err
	}
	if err := requirePayloadSummary(
		request.SourceBytes,
		request.SourceChunkCount,
		request.SourceDigest,
		MaximumSourceBytes,
		"source",
	); err != nil {
		return err
	}
	expected, err := ComputeRequestFingerprint(request)
	if err != nil {
		return err
	}
	if request.RequestFingerprint != expected {
		return invalidf("requestFingerprint does not bind the exact request")
	}
	return nil
}

func ComputeRequestFingerprint(request Request) (string, error) {
	request = cloneRequest(request)
	if request.Schema != RequestSchema {
		return "", invalidf("request schema is invalid")
	}
	fields := []string{
		RequestSchema,
		request.OperationID,
		request.ArtifactRenderJobRef,
		request.Composition.Ref,
		request.Composition.Digest,
		request.Source.ProviderResourceID,
		request.Source.ExpectedProfile,
		request.Source.ExpectedRuntimeKind,
		request.Owner.TenantID,
		request.Owner.UserID,
		request.Owner.WorkspaceID,
		request.Owner.RunID,
		request.Owner.GrantID,
		request.Fence.WorkspaceExecutionManifestRef,
		request.ExpectedParentGeneration.ContainerID,
		request.ExpectedParentGeneration.ContainerCreatedAt,
		request.ExpectedParentGeneration.ExecutionStartedAt,
		strconv.Itoa(request.ExpectedParentGeneration.RestartCount),
		request.Image.Ref,
		request.Image.ConfigDigest,
		request.Image.PackID,
		request.Image.PackRef,
		request.Interface.Ref,
		request.Interface.Digest,
		request.Executor.Ref,
		request.Executor.Digest,
		request.Executable,
		request.ProviderPolicy.Ref,
		request.ProviderPolicy.Digest,
		strconv.FormatInt(request.RequestBytes, 10),
		strconv.Itoa(request.RequestChunkCount),
		request.RequestDigest,
		strconv.FormatInt(request.SourceBytes, 10),
		strconv.Itoa(request.SourceChunkCount),
		request.SourceDigest,
	}
	digest := sha256.Sum256([]byte(strings.Join(fields, "\n")))
	return hex.EncodeToString(digest[:]), nil
}

func ComputeReceiptDigest(receipt Receipt) (string, error) {
	receipt = cloneReceipt(receipt)
	receipt.ReceiptDigest = ""
	data, err := generationstop.CanonicalJSON(receipt)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ValidateReceipt(receipt Receipt) error {
	if receipt.Schema != ReceiptSchema || !exactDigest(receipt.ReceiptDigest) {
		return invalidf("receipt schema or digest is invalid")
	}
	if err := ValidateRequest(receipt.Request); err != nil {
		return invalidf("receipt request is invalid: %v", err)
	}
	if len(receipt.Nonce) != 32 || strings.ToLower(receipt.Nonce) != receipt.Nonce {
		return invalidf("receipt nonce is invalid")
	}
	if _, err := hex.DecodeString(receipt.Nonce); err != nil {
		return invalidf("receipt nonce is invalid")
	}
	if !exactDigest(receipt.ReadyDigest) || !exactDigest(receipt.TerminalDigest) {
		return invalidf("receipt helper frame digests are invalid")
	}
	expectedTerminal := map[string]struct {
		kind string
		exit int
	}{
		"succeeded": {kind: "response_end", exit: 0},
		"failed":    {kind: "response_end", exit: 1},
		"timed_out": {kind: "response_end", exit: 124},
		"cancelled": {kind: "cancelled", exit: 130},
	}
	expected, ok := expectedTerminal[receipt.TerminalOutcome]
	if !ok || receipt.Outcome != receipt.TerminalOutcome ||
		receipt.TerminalKind != expected.kind || receipt.HelperExitCode != expected.exit {
		return invalidf("receipt terminal tuple is invalid")
	}
	if receipt.Quiescence.Schema != QuiescenceSchema ||
		receipt.Quiescence.ContainerID != receipt.Launch.ContainerID ||
		!receipt.Quiescence.ContainerAbsent {
		return invalidf("receipt quiescence is invalid")
	}
	if err := validateReceiptLaunch(receipt); err != nil {
		return err
	}
	started, err := parseProviderTime(receipt.StartedAt)
	if err != nil {
		return err
	}
	launched, err := parseProviderTime(receipt.Launch.ObservedAt)
	if err != nil {
		return err
	}
	quiesced, err := parseProviderTime(receipt.Quiescence.ObservedAt)
	if err != nil {
		return err
	}
	completed, err := parseProviderTime(receipt.CompletedAt)
	if err != nil {
		return err
	}
	if launched.Before(started) || quiesced.Before(launched) || completed.Before(quiesced) ||
		completed.Sub(quiesced) > 5*time.Second {
		return invalidf("receipt provider times are out of order or exceed the commit bound")
	}
	if len(receipt.Files) > MaximumOutputFiles {
		return invalidf("receipt file count exceeds the bound")
	}
	var total int64
	paths := make(map[string]struct{}, len(receipt.Files))
	previousRole := ""
	previousArtifactPath := ""
	for index, file := range receipt.Files {
		if file.Ordinal != index || file.ByteLength <= 0 || !exactDigest(file.Digest) ||
			!safeOutputPath(file.Path) || !helperMediaTypePattern.MatchString(file.MediaType) ||
			len(file.MediaType) > 128 || !helperRoleOrder(index+1, file.Role, previousRole) {
			return invalidf("receipt file roster is invalid")
		}
		if _, exists := paths[file.Path]; exists {
			return invalidf("receipt file paths are not unique")
		}
		paths[file.Path] = struct{}{}
		previousRole = file.Role
		if file.Role == "artifact" {
			if previousArtifactPath != "" && previousArtifactPath >= file.Path {
				return invalidf("receipt artifact paths are not sorted and unique")
			}
			previousArtifactPath = file.Path
		}
		total += file.ByteLength
		if total > MaximumOutputBytes {
			return invalidf("receipt total output bytes exceed the bound")
		}
	}
	if total != receipt.TotalOutputBytes {
		return invalidf("receipt total output bytes differ from its roster")
	}
	if receipt.TerminalOutcome == "cancelled" {
		if len(receipt.Files) != 0 || receipt.TotalOutputBytes != 0 {
			return invalidf("cancelled receipt cannot contain output files")
		}
	} else if len(receipt.Files) == 0 || receipt.TotalOutputBytes <= 0 || receipt.Files[0].Role != "result" ||
		receipt.Files[0].MediaType != "application/vnd.ambit.c18-specialist-render-command-result+json" {
		return invalidf("render terminal receipt requires a positive result-first roster")
	}
	expectedDigest, err := ComputeReceiptDigest(receipt)
	if err != nil || expectedDigest != receipt.ReceiptDigest {
		return invalidf("receipt digest does not bind the exact receipt")
	}
	encodedReceipt, err := generationstop.CanonicalJSON(receipt)
	if err != nil || len(encodedReceipt) > MaximumReceiptBytes {
		return invalidf("receipt exceeds its canonical metadata bound")
	}
	return nil
}

func ValidateReceiptWithPolicy(receipt Receipt, policy Policy) error {
	if err := ValidateReceipt(receipt); err != nil {
		return err
	}
	if err := validatePolicy(policy); err != nil {
		return invalidf("receipt policy is invalid: %v", err)
	}
	if err := requireExactPolicy(receipt.Request, policy); err != nil {
		return err
	}
	launch := receipt.Launch
	if launch.ExecutablePath != policy.ProcessExecutablePath ||
		launch.ExecutableDigest != policy.ProcessExecutableDigest ||
		launch.EnvironmentDigest != policy.EnvironmentDigest ||
		launch.PIDsLimit != policy.PIDsLimit || launch.MemoryBytes != policy.MemoryBytes ||
		launch.NanoCPUs != policy.NanoCPUs || launch.ShmSize != policy.ShmSize || launch.Runtime != policy.Runtime ||
		launch.RuntimeStatusDigest != policy.RuntimeStatusDigest ||
		!stringMapsEqual(launch.Tmpfs, expectedTmpfs(policy)) {
		return invalidf("receipt launch differs from its provider policy")
	}
	if launch.SeccompMode != "custom" || launch.SeccompDigest != sha256Digest(policy.Seccomp) {
		return invalidf("receipt custom seccomp differs from its provider policy")
	}
	return nil
}

func validateReceiptLaunch(receipt Receipt) error {
	launch := receipt.Launch
	request := receipt.Request
	if !exactDigest(launch.ImageID) || launch.ImageID != request.Image.ConfigDigest ||
		launch.ContainerName != "ambit-specialist-render-"+strings.ReplaceAll(request.OperationID, "-", "") ||
		len(launch.ContainerID) != 64 || strings.ToLower(launch.ContainerID) != launch.ContainerID ||
		launch.ParentGeneration != request.ExpectedParentGeneration ||
		!stringSlicesEqual(launch.Command, helperCommandLine(request.Executable, receipt.Nonce)) ||
		launch.ProcessIdentity.PID != 1 || launch.ProcessIdentity.StartTicks == "" ||
		launch.HostPID <= 0 || launch.RoleRef != RoleRef || launch.User != "1000:1000" ||
		!exactDigest(launch.ExecutableDigest) || launch.ExecutablePath == "" ||
		!strings.HasPrefix(launch.ExecutablePath, "/") || !exactDigest(launch.EnvironmentDigest) ||
		launch.ProcessCount != 1 || launch.MountNamespace == "" || launch.ProcessNamespace == "" ||
		launch.ParentMountNamespace == "" || launch.ParentProcessNamespace == "" ||
		launch.MountNamespace == launch.ParentMountNamespace ||
		launch.ProcessNamespace == launch.ParentProcessNamespace ||
		launch.NetworkMode != "none" || !launch.ReadonlyRootfs ||
		len(launch.CapDrop) != 1 || launch.CapDrop[0] != "ALL" || !launch.NoNewPrivileges ||
		launch.SeccompKernelMode != 2 || launch.EffectiveCapabilities != "0000000000000000" ||
		launch.MountCount != 0 || launch.PIDsLimit <= 0 || launch.MemoryBytes <= 0 ||
		launch.NanoCPUs <= 0 || launch.ShmSize < 0 || len(launch.Tmpfs) != 2 ||
		launch.Tmpfs["/workspace"] == "" || launch.Tmpfs["/tmp/ambit-task"] == "" || launch.Runtime != "runc" ||
		!exactDigest(launch.RuntimeStatusDigest) {
		return invalidf("receipt launch does not satisfy intrinsic provider isolation")
	}
	if _, err := hex.DecodeString(launch.ContainerID); err != nil {
		return invalidf("receipt launch container identity is invalid")
	}
	if _, err := strconv.ParseUint(launch.ProcessIdentity.StartTicks, 10, 64); err != nil ||
		launch.ProcessIdentity.StartTicks == "0" {
		return invalidf("receipt launch process identity is invalid")
	}
	if launch.SeccompMode != "custom" || !exactDigest(launch.SeccompDigest) {
		return invalidf("receipt requires exact provider-policy seccomp")
	}
	return nil
}

func validateParentGeneration(value generationstop.ExpectedGeneration) error {
	if len(value.ContainerID) != 64 || strings.ToLower(value.ContainerID) != value.ContainerID || value.RestartCount < 0 {
		return invalidf("expected parent container generation is invalid")
	}
	if _, err := hex.DecodeString(value.ContainerID); err != nil {
		return invalidf("expected parent container identity is invalid")
	}
	created, createdErr := parseProviderTime(value.ContainerCreatedAt)
	started, startedErr := parseProviderTime(value.ExecutionStartedAt)
	if createdErr != nil || startedErr != nil || started.Before(created) ||
		len(value.ContainerCreatedAt) > 64 || len(value.ExecutionStartedAt) > 64 {
		return invalidf("expected parent generation timestamps are invalid")
	}
	return nil
}

func requirePayloadSummary(bytes int64, chunks int, digest string, maximum int64, label string) error {
	if bytes <= 0 || bytes > maximum {
		return invalidf("%s bytes exceed the bound", label)
	}
	expectedChunks := int((bytes + RequestChunkBytes - 1) / RequestChunkBytes)
	if chunks != expectedChunks {
		return invalidf("%s chunk count is invalid", label)
	}
	if !exactDigest(digest) {
		return invalidf("%s digest is invalid", label)
	}
	return nil
}

func requireInput(input Input, bytes int64, digest string, maximum int64, label string) error {
	if input.ByteLength != bytes || input.Digest != digest || input.Open == nil || bytes > maximum {
		return invalidf("%s provider-private input differs from the request", label)
	}
	return nil
}

func requireExactPolicy(request Request, policy Policy) error {
	if request.ProviderPolicy != policy.Authority || request.Composition != policy.Composition ||
		request.Image != policy.Image || request.Interface != policy.Interface ||
		request.Executor != policy.Executor || request.Executable != policy.Executable {
		return fmt.Errorf("%w: caller pins differ from runner-owned policy", ErrConflict)
	}
	if policy.PIDsLimit <= 0 || policy.MemoryBytes <= 0 || policy.NanoCPUs <= 0 ||
		policy.WorkspaceSize <= 0 || policy.ScratchSize <= 0 || policy.ShmSize < 0 {
		return fmt.Errorf("%w: runner-owned resource policy is incomplete", ErrUnavailable)
	}
	return nil
}

func validateProviderExecution(
	execution ProviderExecution,
	request Request,
	policy Policy,
	nonce string,
	parent generationstop.ExpectedGeneration,
	startedAt time.Time,
) error {
	if execution.Launch.ParentGeneration != parent || execution.Launch.ObservedAt == "" ||
		execution.Launch.ImageID != request.Image.ConfigDigest ||
		!stringSlicesEqual(execution.Launch.Command, helperCommandLine(policy.Executable, nonce)) ||
		execution.Launch.ContainerID == "" || execution.Launch.ContainerName == "" ||
		execution.Launch.ProcessIdentity.PID != 1 || execution.Launch.HostPID <= 0 ||
		execution.Launch.ProcessIdentity.StartTicks == "" ||
		execution.Launch.RoleRef != RoleRef || execution.Launch.User != "1000:1000" ||
		execution.Launch.EnvironmentDigest != policy.EnvironmentDigest || execution.Launch.ProcessCount != 1 ||
		execution.Launch.MountNamespace == "" || execution.Launch.ProcessNamespace == "" ||
		execution.Launch.ParentMountNamespace == "" || execution.Launch.ParentProcessNamespace == "" ||
		execution.Launch.MountNamespace == execution.Launch.ParentMountNamespace ||
		execution.Launch.ProcessNamespace == execution.Launch.ParentProcessNamespace ||
		execution.Launch.NetworkMode != "none" || !execution.Launch.ReadonlyRootfs ||
		len(execution.Launch.CapDrop) != 1 || execution.Launch.CapDrop[0] != "ALL" ||
		!execution.Launch.NoNewPrivileges || execution.Launch.SeccompKernelMode != 2 ||
		execution.Launch.EffectiveCapabilities != "0000000000000000" || execution.Launch.MountCount != 0 ||
		!stringMapsEqual(execution.Launch.Tmpfs, expectedTmpfs(policy)) ||
		execution.Launch.ExecutablePath != policy.ProcessExecutablePath ||
		execution.Launch.ExecutableDigest != policy.ProcessExecutableDigest ||
		execution.Launch.PIDsLimit != policy.PIDsLimit || execution.Launch.MemoryBytes != policy.MemoryBytes ||
		execution.Launch.NanoCPUs != policy.NanoCPUs || execution.Launch.ShmSize != policy.ShmSize ||
		execution.Launch.Runtime != policy.Runtime ||
		execution.Launch.RuntimeStatusDigest != policy.RuntimeStatusDigest {
		return fmt.Errorf("%w: provider launch observation is incomplete or differs", ErrOutcomeUnknown)
	}
	if execution.Launch.SeccompMode != "custom" ||
		execution.Launch.SeccompDigest != sha256Digest(policy.Seccomp) {
		return fmt.Errorf("%w: provider custom seccomp observation differs", ErrOutcomeUnknown)
	}
	if !exactDigest(execution.ReadyDigest) || !exactDigest(execution.TerminalDigest) {
		return fmt.Errorf("%w: helper frame digests are invalid", ErrOutcomeUnknown)
	}
	expectedTerminal := map[string]struct {
		kind string
		exit int
	}{
		"succeeded": {kind: "response_end", exit: 0},
		"failed":    {kind: "response_end", exit: 1},
		"timed_out": {kind: "response_end", exit: 124},
		"cancelled": {kind: "cancelled", exit: 130},
	}
	expected, ok := expectedTerminal[execution.TerminalOutcome]
	if !ok || execution.TerminalKind != expected.kind || execution.HelperExitCode != expected.exit {
		return fmt.Errorf("%w: helper outcome and exit code differ", ErrOutcomeUnknown)
	}
	if execution.Quiescence.Schema != QuiescenceSchema ||
		execution.Quiescence.ContainerID != execution.Launch.ContainerID ||
		!execution.Quiescence.ContainerAbsent || execution.Quiescence.ObservedAt == "" {
		return fmt.Errorf("%w: provider quiescence receipt is invalid", ErrOutcomeUnknown)
	}
	launchTime, launchErr := parseProviderTime(execution.Launch.ObservedAt)
	quiescenceTime, quiescenceErr := parseProviderTime(execution.Quiescence.ObservedAt)
	if launchErr != nil || quiescenceErr != nil ||
		launchTime.Before(startedAt.UTC().Truncate(time.Millisecond)) || quiescenceTime.Before(launchTime) {
		return fmt.Errorf("%w: provider launch/quiescence times are invalid", ErrOutcomeUnknown)
	}
	if len(execution.Files) > MaximumOutputFiles {
		return fmt.Errorf("%w: output file count exceeds the bound", ErrOutcomeUnknown)
	}
	var total int64
	previousRole := ""
	for index, payload := range execution.Files {
		if payload.Open == nil || payload.Cleanup == nil || payload.File.Ordinal != index ||
			payload.File.ByteLength <= 0 || !exactDigest(payload.File.Digest) ||
			!safeOutputPath(payload.File.Path) ||
			!helperMediaTypePattern.MatchString(payload.File.MediaType) ||
			!helperRoleOrder(index+1, payload.File.Role, previousRole) {
			return fmt.Errorf("%w: provider output custody is invalid", ErrOutcomeUnknown)
		}
		previousRole = payload.File.Role
		total += payload.File.ByteLength
		if total > MaximumOutputBytes {
			return fmt.Errorf("%w: provider output bytes exceed the bound", ErrOutcomeUnknown)
		}
	}
	if execution.TerminalOutcome == "cancelled" {
		if len(execution.Files) != 0 {
			return fmt.Errorf("%w: cancelled provider execution retained output", ErrOutcomeUnknown)
		}
	} else if len(execution.Files) == 0 || execution.Files[0].File.Role != "result" {
		return fmt.Errorf("%w: provider execution has no committed result", ErrOutcomeUnknown)
	}
	return nil
}

func stringSlicesEqual(left []string, right []string) bool {
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

func helperCommandLine(executable string, nonce string) []string {
	return []string{
		"/bin/sh", "-c",
		`stty raw -echo -onlcr && exec "$1" --framed-jsonl --nonce "$2"`,
		RoleRef, executable, nonce,
	}
}

func expectedTmpfs(policy Policy) map[string]string {
	return map[string]string{
		"/workspace":      fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,uid=1000,gid=1000,mode=0700", policy.WorkspaceSize),
		"/tmp/ambit-task": fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,uid=1000,gid=1000,mode=0700", policy.ScratchSize),
	}
}

func stringMapsEqual(left map[string]string, right map[string]string) bool {
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

func formatProviderTime(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

func parseProviderTime(value string) (time.Time, error) {
	if !providerTimePattern.MatchString(value) {
		return time.Time{}, invalidf("provider time is not an exact UTC millisecond instant")
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil || formatProviderTime(parsed) != value {
		return time.Time{}, invalidf("provider time is invalid")
	}
	return parsed, nil
}

func randomNonce() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func exactDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && strings.ToLower(value) == value
}

func boundedOperationalRef(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value ||
		(!strings.Contains(value, ":") && !strings.Contains(value, "@")) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func immutableOCIReference(value string) bool {
	if !boundedOperationalRef(value, 512) {
		return false
	}
	separator := strings.LastIndex(value, "@sha256:")
	if separator <= 0 || separator+len("@sha256:")+64 != len(value) {
		return false
	}
	_, err := hex.DecodeString(value[separator+len("@sha256:"):])
	return err == nil && strings.ToLower(value) == value
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func cleanupPayloads(payloads []Payload) {
	for _, payload := range payloads {
		if payload.Cleanup != nil {
			_ = payload.Cleanup()
		}
	}
}

func cloneRequest(value Request) Request {
	return value
}

func clonePolicy(value Policy) Policy {
	value.Seccomp = append([]byte(nil), value.Seccomp...)
	return value
}

func cloneReceipt(value Receipt) Receipt {
	value.Launch.Command = append([]string(nil), value.Launch.Command...)
	value.Launch.CapDrop = append([]string(nil), value.Launch.CapDrop...)
	value.Launch.Tmpfs = cloneStringMap(value.Launch.Tmpfs)
	value.Files = append([]OutputFile(nil), value.Files...)
	return value
}

func cloneStringMap(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func invalidf(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, fmt.Sprintf(format, values...))
}
