// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package generationstop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daytonaio/runner/pkg/storage"
	"github.com/google/uuid"
)

const (
	privateRoot         = "private/sandbox-generation-stops/v1"
	maximumClaimBytes   = 64 * 1024
	maximumReceiptBytes = 64 * 1024
	maximumSafeJSONInt  = int64(9_007_199_254_740_991)
)

var (
	ErrInvalidRequest = errors.New("invalid stopped-generation request")
	ErrConflict       = errors.New("stopped-generation conflict")
	ErrUnavailable    = errors.New("stopped-generation provider unavailable")
	ErrOutcomeUnknown = errors.New("stopped-generation outcome is unknown")

	documentRendererSessionPattern = regexp.MustCompile(`^ambit-document-render-[0-9a-f]{40}$`)
	startTicksPattern              = regexp.MustCompile(`^[1-9][0-9]{0,31}$`)
)

// ObjectStore is intentionally a subset of storage.PrivateObjectStorageClient.
// The production private object client satisfies it directly; this service
// needs only immutable conditional create and bounded read.
type ObjectStore interface {
	CreatePrivateObject(
		ctx context.Context,
		key string,
		data []byte,
		contentType string,
		metadata map[string]string,
	) error
	GetPrivateObject(ctx context.Context, key string, maximumBytes int64) ([]byte, error)
}

// ContainerClient is the complete provider mutation surface.  StopGeneration
// must address target.ExpectedGeneration.ContainerID directly and verify the
// supplied identity/fence at the adapter boundary.  There is intentionally no
// container-list or kill primitive in this contract. InspectGeneration must
// derive its observation from provider-owned container metadata (currently
// ambitWorkspaceId, ambitTenantId, ambitPrincipalId, ambitTaskId,
// ambitGrantId, ambitProfile, and ambitWorkspaceExecutionManifestRef), never
// by echoing request values.
type ContainerClient interface {
	InspectGeneration(
		ctx context.Context,
		providerResourceID string,
	) (CurrentGenerationObservation, error)
	StopGeneration(ctx context.Context, target ExactStopTarget) error
}

type Service struct {
	containers ContainerClient
	objects    ObjectStore
	now        func() time.Time
	locks      keyedLocks
}

type durableClaim struct {
	Version  int         `json:"version"`
	ClaimRef string      `json:"claimRef"`
	Request  StopRequest `json:"request"`
}

type operationKeys struct {
	claim   string
	receipt string
}

type keyedLocks struct {
	mu    sync.Mutex
	items map[string]*keyedLock
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

func NewService(containers ContainerClient, objects ObjectStore) (*Service, error) {
	if containers == nil {
		return nil, fmt.Errorf("%w: exact container-generation client is not configured", ErrUnavailable)
	}
	if objects == nil {
		return nil, fmt.Errorf("%w: private immutable object storage is not configured", ErrUnavailable)
	}
	return &Service{
		containers: containers,
		objects:    objects,
		now:        time.Now,
		locks:      keyedLocks{items: make(map[string]*keyedLock)},
	}, nil
}

// ObserveCurrent performs a read-only provider inspection.  It is the
// discovery half of the protocol: callers that do not yet know the Docker
// execution epoch can obtain it, then submit that exact generation in a
// separately authorized StopRequest.
func (s *Service) ObserveCurrent(
	ctx context.Context,
	request GenerationObservationRequest,
) (GenerationObservation, error) {
	if err := validateGenerationObservationRequest(request); err != nil {
		return GenerationObservation{}, err
	}
	observed, err := s.containers.InspectGeneration(ctx, request.Source.ProviderResourceID)
	if err != nil {
		return GenerationObservation{}, fmt.Errorf("%w: inspect current sandbox generation: %v", ErrUnavailable, err)
	}
	if err := requireObservedAuthority(observed, request.Source, request.Owner, request.Fence); err != nil {
		return GenerationObservation{}, err
	}
	if err := validateObservedGeneration(observed.Generation); err != nil {
		return GenerationObservation{}, err
	}
	if err := validateRuntimeState(observed.State); err != nil {
		return GenerationObservation{}, err
	}
	state := ""
	switch {
	case isExactRunning(observed.State) && observed.Generation.ExecutionFinishedAt == "":
		state = "running"
	case isExactExited(observed.State) && observed.Generation.ExecutionFinishedAt != "":
		state = "stopped"
	default:
		return GenerationObservation{}, fmt.Errorf(
			"%w: current generation is paused, restarting, dead, or incomplete (status=%q)",
			ErrConflict,
			observed.State.Status,
		)
	}
	return GenerationObservation{
		Source:     request.Source,
		Owner:      request.Owner,
		Fence:      request.Fence,
		Generation: observed.Generation.ExpectedGeneration,
		State:      state,
		ObservedAt: s.now().UTC().Format(time.RFC3339Nano),
	}, nil
}

// StopOnce durably claims one logical operation before any container read or
// mutation, then ensures that the exact claimed generation reaches the exited
// state.  A crash after the stop but before receipt publication is recovered by
// observing the exact exited generation and publishing the same logical
// receipt.  If the provider response is ambiguous, a replay may reissue the
// exact idempotent stop; it can never widen the effect to another generation.
// Two runner processes can therefore emit duplicate stop transport calls after
// both prove the same running epoch: preventing that with a permanent claim
// owner would make an owner crash before the effect unrecoverable. They still
// represent one logical state transition because every call carries and
// re-proves the same immutable container generation/fence, and all callers
// converge on one conditional immutable receipt.
func (s *Service) StopOnce(ctx context.Context, request StopRequest) (Receipt, error) {
	request = cloneStopRequest(request)
	if err := validateStopRequest(request); err != nil {
		return Receipt{}, err
	}

	keys := keysForRequest(request)
	release := s.locks.acquire(keys.claim)
	defer release()

	claim, err := s.ensureClaim(ctx, keys.claim, request)
	if err != nil {
		return Receipt{}, err
	}
	if receipt, complete, err := s.readReceipt(ctx, keys.receipt, claim); err != nil {
		return Receipt{}, err
	} else if complete {
		return receipt, nil
	}

	// This is the final provider read immediately before the effect.  It closes
	// logical-name ABA by requiring the full expected container generation and
	// provider-observed owner/fence before addressing the immutable container ID.
	before, err := s.containers.InspectGeneration(ctx, request.Source.ProviderResourceID)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: inspect claimed sandbox generation: %v", ErrUnavailable, err)
	}
	if err := requireExactGeneration(before, request); err != nil {
		return Receipt{}, err
	}

	if isExactExited(before.State) {
		return s.publishReceipt(ctx, keys.receipt, claim, before)
	}
	if !isExactRunning(before.State) {
		return Receipt{}, fmt.Errorf(
			"%w: claimed generation is neither exactly running nor exactly exited (status=%q)",
			ErrConflict,
			before.State.Status,
		)
	}

	target := ExactStopTarget{
		Source:             request.Source,
		Owner:              request.Owner,
		Fence:              request.Fence,
		ExpectedGeneration: request.ExpectedGeneration,
	}
	stopErr := s.containers.StopGeneration(ctx, target)

	// Always reconcile from provider state, including a lost/failed stop
	// response.  A response error cannot erase a successfully completed effect.
	after, inspectErr := s.containers.InspectGeneration(ctx, request.Source.ProviderResourceID)
	if inspectErr != nil {
		if stopErr != nil {
			return Receipt{}, errors.Join(
				fmt.Errorf("%w: exact stop returned: %v", ErrOutcomeUnknown, stopErr),
				fmt.Errorf("%w: inspect after exact stop: %v", ErrUnavailable, inspectErr),
			)
		}
		return Receipt{}, fmt.Errorf("%w: cannot prove terminal generation after stop: %v", ErrOutcomeUnknown, inspectErr)
	}
	if err := requireExactGeneration(after, request); err != nil {
		if stopErr != nil {
			return Receipt{}, errors.Join(err, fmt.Errorf("exact stop returned: %w", stopErr))
		}
		return Receipt{}, err
	}
	if isExactExited(after.State) {
		return s.publishReceipt(ctx, keys.receipt, claim, after)
	}
	if stopErr != nil {
		return Receipt{}, fmt.Errorf(
			"%w: exact stop returned %v and generation remains %q",
			ErrOutcomeUnknown,
			stopErr,
			after.State.Status,
		)
	}
	return Receipt{}, fmt.Errorf(
		"%w: provider returned from stop without an exact terminal generation (status=%q)",
		ErrOutcomeUnknown,
		after.State.Status,
	)
}

// Observe reports the immutable operation state without inspecting or
// mutating a container.  Supplying the full request makes observation itself
// collision-safe: operation ID reuse with any authority drift is rejected.
func (s *Service) Observe(ctx context.Context, request StopRequest) (Observation, error) {
	request = cloneStopRequest(request)
	if err := validateStopRequest(request); err != nil {
		return Observation{}, err
	}
	keys := keysForRequest(request)
	release := s.locks.acquire(keys.claim)
	defer release()

	claim, exists, err := s.readClaim(ctx, keys.claim)
	if err != nil {
		return Observation{}, err
	}
	if !exists {
		copy := cloneStopRequest(request)
		return Observation{Status: ObservationAbsent, Request: &copy}, nil
	}
	if err := requireExactRequest(claim.Request, request); err != nil {
		return Observation{}, err
	}
	receipt, complete, err := s.readReceipt(ctx, keys.receipt, claim)
	if err != nil {
		return Observation{}, err
	}
	if !complete {
		copy := cloneStopRequest(claim.Request)
		return Observation{Status: ObservationPartial, Request: &copy}, nil
	}
	return Observation{Status: ObservationComplete, Receipt: &receipt}, nil
}

// RequireCurrentReceipt resolves a compact downstream StopAuthority back to
// its full immutable claim and receipt, then freshly re-proves the exact
// provider-owned source/owner/fence/generation and exited PID-zero state.  It
// is the single stopped-generation authority boundary used by capture and
// renderer consumers; they do not need to duplicate Docker state semantics.
func (s *Service) RequireCurrentReceipt(
	ctx context.Context,
	expectedSource Source,
	expectedOwner Owner,
	expectedPurpose Purpose,
	authority StopAuthority,
) (Receipt, error) {
	expectedPurpose = clonePurpose(expectedPurpose)
	if err := ValidateSource(expectedSource); err != nil {
		return Receipt{}, err
	}
	if err := ValidateOwner(expectedOwner); err != nil {
		return Receipt{}, err
	}
	if err := validatePurpose(expectedPurpose); err != nil {
		return Receipt{}, err
	}
	if err := ValidateStopAuthority(authority); err != nil {
		return Receipt{}, err
	}

	keys := keysForIdentity(expectedOwner.TenantID, authority.OperationID)
	release := s.locks.acquire(keys.claim)
	defer release()
	claim, exists, err := s.readClaim(ctx, keys.claim)
	if err != nil {
		return Receipt{}, err
	}
	if !exists {
		return Receipt{}, fmt.Errorf("%w: stopped-generation claim is absent", ErrConflict)
	}
	if claim.Request.OperationID != authority.OperationID ||
		claim.Request.Source != expectedSource ||
		claim.Request.Owner != expectedOwner ||
		claim.Request.Fence != authority.Fence {
		return Receipt{}, fmt.Errorf("%w: stopped-generation authority differs from its immutable claim", ErrConflict)
	}
	if err := requireExactPurpose(claim.Request.Purpose, expectedPurpose); err != nil {
		return Receipt{}, err
	}
	receipt, complete, err := s.readReceipt(ctx, keys.receipt, claim)
	if err != nil {
		return Receipt{}, err
	}
	if !complete {
		return Receipt{}, fmt.Errorf("%w: stopped-generation terminal receipt is absent", ErrConflict)
	}
	if receipt.ReceiptRef != authority.ReceiptRef ||
		receipt.ReceiptDigest != authority.ReceiptDigest ||
		receipt.TerminalGeneration != authority.TerminalGeneration ||
		receipt.Request.Fence != authority.Fence {
		return Receipt{}, fmt.Errorf("%w: compact stop authority differs from immutable receipt", ErrConflict)
	}

	observed, err := s.containers.InspectGeneration(ctx, expectedSource.ProviderResourceID)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: re-prove stopped sandbox generation: %v", ErrUnavailable, err)
	}
	if err := requireExactGeneration(observed, claim.Request); err != nil {
		return Receipt{}, err
	}
	if !isExactExited(observed.State) {
		return Receipt{}, fmt.Errorf("%w: stopped-generation receipt is no longer currently exited", ErrConflict)
	}
	currentTerminal := TerminalGeneration{
		ExpectedGeneration:  observed.Generation.ExpectedGeneration,
		ExecutionFinishedAt: observed.Generation.ExecutionFinishedAt,
		ExitCode:            observed.Generation.ExitCode,
		OOMKilled:           observed.Generation.OOMKilled,
	}
	if currentTerminal != authority.TerminalGeneration {
		return Receipt{}, fmt.Errorf("%w: current terminal generation differs from immutable receipt", ErrConflict)
	}
	return receipt, nil
}

func (s *Service) ensureClaim(
	ctx context.Context,
	key string,
	request StopRequest,
) (durableClaim, error) {
	claim := durableClaim{Version: 1, ClaimRef: claimRef(request), Request: request}
	data, err := json.Marshal(claim)
	if err != nil {
		return durableClaim{}, fmt.Errorf("marshal stopped-generation claim: %w", err)
	}
	createErr := s.objects.CreatePrivateObject(
		ctx,
		key,
		data,
		"application/json",
		map[string]string{
			"contract":     "ambit-sandbox-generation-stop-claim-v1",
			"operation-id": request.OperationID,
			"claim-ref":    claim.ClaimRef,
		},
	)
	if createErr == nil {
		return claim, nil
	}

	winner, exists, readErr := s.readClaim(ctx, key)
	if readErr != nil {
		return durableClaim{}, errors.Join(
			fmt.Errorf("%w: persist immutable operation claim: %v", ErrOutcomeUnknown, createErr),
			readErr,
		)
	}
	if !exists {
		return durableClaim{}, fmt.Errorf(
			"%w: claim create returned %v but no immutable winner is observable",
			ErrOutcomeUnknown,
			createErr,
		)
	}
	if err := requireExactRequest(winner.Request, request); err != nil {
		return durableClaim{}, err
	}
	return winner, nil
}

func (s *Service) publishReceipt(
	ctx context.Context,
	key string,
	claim durableClaim,
	observed CurrentGenerationObservation,
) (Receipt, error) {
	if !isExactExited(observed.State) {
		return Receipt{}, fmt.Errorf("%w: terminal receipt requires exact exited state", ErrConflict)
	}
	terminal := TerminalGeneration{
		ExpectedGeneration:  observed.Generation.ExpectedGeneration,
		ExecutionFinishedAt: observed.Generation.ExecutionFinishedAt,
		ExitCode:            observed.Generation.ExitCode,
		OOMKilled:           observed.Generation.OOMKilled,
	}
	stoppedAt := s.now().UTC().Format(time.RFC3339Nano)
	receiptDigest, receiptRef, err := deriveReceiptIdentity(claim.Request, terminal, stoppedAt)
	if err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{
		Version:            1,
		Kind:               receiptKind,
		Request:            cloneStopRequest(claim.Request),
		ReceiptRef:         receiptRef,
		ReceiptDigest:      receiptDigest,
		TerminalGeneration: terminal,
		StoppedAt:          stoppedAt,
	}
	if err := validateReceipt(receipt, claim.Request); err != nil {
		return Receipt{}, err
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return Receipt{}, fmt.Errorf("marshal stopped-generation receipt: %w", err)
	}
	createErr := s.objects.CreatePrivateObject(
		ctx,
		key,
		data,
		"application/json",
		map[string]string{
			"contract":       "ambit-sandbox-generation-stop-receipt-v1",
			"operation-id":   claim.Request.OperationID,
			"receipt-ref":    receipt.ReceiptRef,
			"receipt-digest": receipt.ReceiptDigest,
		},
	)
	if createErr == nil {
		return receipt, nil
	}

	winner, exists, readErr := s.readReceipt(ctx, key, claim)
	if readErr != nil {
		return Receipt{}, errors.Join(
			fmt.Errorf("%w: persist immutable terminal receipt: %v", ErrOutcomeUnknown, createErr),
			readErr,
		)
	}
	if !exists {
		return Receipt{}, fmt.Errorf(
			"%w: receipt create returned %v but no immutable winner is observable",
			ErrOutcomeUnknown,
			createErr,
		)
	}
	if winner.TerminalGeneration != receipt.TerminalGeneration {
		return Receipt{}, fmt.Errorf(
			"%w: concurrent terminal observations disagree for the same claimed generation",
			ErrConflict,
		)
	}
	return winner, nil
}

func (s *Service) readClaim(ctx context.Context, key string) (durableClaim, bool, error) {
	data, err := s.objects.GetPrivateObject(ctx, key, maximumClaimBytes)
	if errors.Is(err, storage.ErrPrivateObjectNotFound) {
		return durableClaim{}, false, nil
	}
	if err != nil {
		return durableClaim{}, false, objectReadError("read immutable operation claim", err)
	}
	var claim durableClaim
	if err := strictJSON(data, &claim); err != nil {
		return durableClaim{}, false, fmt.Errorf("%w: operation claim is not canonical: %v", ErrConflict, err)
	}
	if claim.Version != 1 || claim.ClaimRef != claimRef(claim.Request) {
		return durableClaim{}, false, fmt.Errorf("%w: operation claim identity is invalid", ErrConflict)
	}
	if err := validateStopRequest(claim.Request); err != nil {
		return durableClaim{}, false, fmt.Errorf("%w: persisted operation claim is invalid: %v", ErrConflict, err)
	}
	return claim, true, nil
}

func (s *Service) readReceipt(
	ctx context.Context,
	key string,
	claim durableClaim,
) (Receipt, bool, error) {
	data, err := s.objects.GetPrivateObject(ctx, key, maximumReceiptBytes)
	if errors.Is(err, storage.ErrPrivateObjectNotFound) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, objectReadError("read immutable terminal receipt", err)
	}
	var receipt Receipt
	if err := strictJSON(data, &receipt); err != nil {
		return Receipt{}, false, fmt.Errorf("%w: terminal receipt is not canonical: %v", ErrConflict, err)
	}
	if err := validateReceipt(receipt, claim.Request); err != nil {
		return Receipt{}, false, err
	}
	return receipt, true, nil
}

func validateStopRequest(request StopRequest) error {
	if err := validateStopRequestFields(request); err != nil {
		return err
	}
	if len(request.RequestFingerprint) != 64 || !isLowerHex(request.RequestFingerprint) {
		return invalidf("requestFingerprint must be 64 lowercase hexadecimal characters")
	}
	expected, err := ComputeRequestFingerprint(request)
	if err != nil {
		return err
	}
	if request.RequestFingerprint != expected {
		return invalidf("requestFingerprint does not bind the exact stopped-generation request")
	}
	return nil
}

func validateStopRequestFields(request StopRequest) error {
	if !canonicalUUID(request.OperationID) {
		return invalidf("operationId must be a non-nil canonical UUID")
	}
	if err := ValidateSource(request.Source); err != nil {
		return err
	}
	if err := ValidateOwner(request.Owner); err != nil {
		return err
	}
	if !boundedRef(request.Fence.WorkspaceExecutionManifestRef, 2048) {
		return invalidf("workspace execution manifest fence is invalid")
	}
	if err := validateExpectedGeneration(request.ExpectedGeneration); err != nil {
		return err
	}
	return validatePurpose(request.Purpose)
}

// ComputeRequestFingerprint returns the frozen upstream/provider idempotency
// fingerprint. It validates every bound field first, joins the exact ordered
// UTF-8 field sequence with one newline and no trailing newline, and returns
// the lowercase hexadecimal SHA-256 digest. RequestFingerprint itself is not
// part of the preimage.
func ComputeRequestFingerprint(request StopRequest) (string, error) {
	request = cloneStopRequest(request)
	if err := validateStopRequestFields(request); err != nil {
		return "", err
	}
	fields := []string{
		"ambit.workspace-stop-generation-request/v1",
		request.OperationID,
		request.Source.ProviderResourceID,
		request.Source.ExpectedProfile,
		request.Source.ExpectedRuntimeKind,
		request.Owner.TenantID,
		request.Owner.UserID,
		request.Owner.WorkspaceID,
		request.Owner.RunID,
		request.Owner.GrantID,
		request.Owner.WorkingCopyID,
		request.Fence.WorkspaceExecutionManifestRef,
		request.ExpectedGeneration.ContainerID,
		request.ExpectedGeneration.ContainerCreatedAt,
		request.ExpectedGeneration.ExecutionStartedAt,
		strconv.Itoa(request.ExpectedGeneration.RestartCount),
		request.Purpose.Kind,
	}
	if request.Purpose.Kind == PurposeDocumentRendererQuiescence {
		fields = append(
			fields,
			request.Purpose.SessionID,
			request.Purpose.Nonce,
			strconv.FormatInt(request.Purpose.RendererProcessIdentity.PID, 10),
			request.Purpose.RendererProcessIdentity.StartTicks,
		)
	}
	return hashHex(strings.Join(fields, "\n")), nil
}

func validateGenerationObservationRequest(request GenerationObservationRequest) error {
	if err := ValidateSource(request.Source); err != nil {
		return err
	}
	if err := ValidateOwner(request.Owner); err != nil {
		return err
	}
	if !boundedRef(request.Fence.WorkspaceExecutionManifestRef, 2048) {
		return invalidf("workspace execution manifest fence is invalid")
	}
	return nil
}

// ValidateStopAuthority validates the complete compact durable authority
// without reading storage or requiring the sandbox to remain stopped.
func ValidateStopAuthority(authority StopAuthority) error {
	if !canonicalUUID(authority.OperationID) {
		return invalidf("stop authority operationId must be a non-nil canonical UUID")
	}
	if !boundedRef(authority.Fence.WorkspaceExecutionManifestRef, 2048) {
		return invalidf("stop authority workspace execution manifest fence is invalid")
	}
	if len(authority.ReceiptDigest) != len("sha256:")+64 ||
		!strings.HasPrefix(authority.ReceiptDigest, "sha256:") ||
		!isLowerHex(strings.TrimPrefix(authority.ReceiptDigest, "sha256:")) ||
		authority.ReceiptRef != "ambit.stopped-generation-receipt:v1:"+authority.ReceiptDigest {
		return invalidf("stop authority receipt identity is invalid")
	}
	if err := validateExpectedGeneration(authority.TerminalGeneration.ExpectedGeneration); err != nil {
		return err
	}
	finishedAt, err := parseUTCTime(authority.TerminalGeneration.ExecutionFinishedAt)
	startedAt, _ := parseUTCTime(authority.TerminalGeneration.ExecutionStartedAt)
	if err != nil || finishedAt.Before(startedAt) {
		return invalidf("stop authority terminal generation is invalid")
	}
	return nil
}

// ValidateSource validates the exact provider address without provider I/O.
func ValidateSource(source Source) error {
	if !boundedRef(source.ProviderResourceID, 512) ||
		!boundedRef(source.ExpectedProfile, 128) ||
		!boundedRef(source.ExpectedRuntimeKind, 128) {
		return invalidf("source address is incomplete or non-canonical")
	}
	return nil
}

// ValidateOwner validates the complete product owner without provider I/O.
func ValidateOwner(owner Owner) error {
	if !canonicalUUID(owner.TenantID) ||
		!canonicalUUID(owner.UserID) ||
		!canonicalUUID(owner.WorkspaceID) ||
		!canonicalUUID(owner.RunID) ||
		!canonicalUUID(owner.GrantID) ||
		!canonicalUUID(owner.WorkingCopyID) {
		return invalidf("owner must contain six non-nil canonical UUIDs")
	}
	return nil
}

// ValidateBinding is the pure syntax boundary for downstream identities that
// carry a source, owner, and compact stopped-generation authority. Capture can
// call RequireCurrentReceipt afterward when it needs live stopped-state proof;
// observe/read/delete paths can validate durable identity without pretending
// the sandbox must still be stopped.
func ValidateBinding(source Source, owner Owner, authority StopAuthority) error {
	if err := ValidateSource(source); err != nil {
		return err
	}
	if err := ValidateOwner(owner); err != nil {
		return err
	}
	return ValidateStopAuthority(authority)
}

func validatePurpose(purpose Purpose) error {
	switch purpose.Kind {
	case PurposeWorkingCopyCapture:
		if purpose.SessionID != "" || purpose.Nonce != "" || purpose.RendererProcessIdentity != nil {
			return invalidf("working_copy_capture purpose contains renderer-only fields")
		}
		return nil
	case PurposeDocumentRendererQuiescence:
		if !documentRendererSessionPattern.MatchString(purpose.SessionID) ||
			len(purpose.Nonce) != 32 || !isLowerHex(purpose.Nonce) ||
			purpose.RendererProcessIdentity == nil ||
			purpose.RendererProcessIdentity.PID <= 0 ||
			purpose.RendererProcessIdentity.PID > maximumSafeJSONInt ||
			!startTicksPattern.MatchString(purpose.RendererProcessIdentity.StartTicks) {
			return invalidf("document_renderer_quiescence purpose is invalid")
		}
		return nil
	default:
		return invalidf("purpose kind is not admitted by this contract version")
	}
}

func validateExpectedGeneration(generation ExpectedGeneration) error {
	if len(generation.ContainerID) != 64 || !isLowerHex(generation.ContainerID) {
		return invalidf("containerId must be the full 64-character lowercase container identity")
	}
	createdAt, err := parseUTCTime(generation.ContainerCreatedAt)
	if err != nil {
		return invalidf("containerCreatedAt is invalid")
	}
	startedAt, err := parseUTCTime(generation.ExecutionStartedAt)
	if err != nil || startedAt.Before(createdAt) {
		return invalidf("executionStartedAt is invalid or precedes container creation")
	}
	if generation.RestartCount < 0 {
		return invalidf("restartCount must be non-negative")
	}
	return nil
}

func validateObservedGeneration(generation ContainerGeneration) error {
	if err := validateExpectedGeneration(generation.ExpectedGeneration); err != nil {
		return fmt.Errorf("%w: provider returned an invalid generation: %v", ErrConflict, err)
	}
	if generation.ExecutionFinishedAt != "" {
		finishedAt, err := parseUTCTime(generation.ExecutionFinishedAt)
		startedAt, _ := parseUTCTime(generation.ExecutionStartedAt)
		if err != nil || finishedAt.Before(startedAt) {
			return fmt.Errorf("%w: provider returned an invalid execution finish time", ErrConflict)
		}
	}
	return nil
}

func validateRuntimeState(state RuntimeState) error {
	if !boundedRef(state.Status, 64) || state.PID < 0 {
		return fmt.Errorf("%w: provider returned an invalid runtime state", ErrConflict)
	}
	if state.Dead && (state.Running || state.Paused || state.Restarting) {
		return fmt.Errorf("%w: provider returned contradictory dead runtime state", ErrConflict)
	}
	if state.Paused && !state.Running {
		return fmt.Errorf("%w: provider returned a paused state that is not running", ErrConflict)
	}
	if state.Restarting && state.Paused {
		return fmt.Errorf("%w: provider returned contradictory restarting runtime state", ErrConflict)
	}
	return nil
}

func requireObservedAuthority(
	observed CurrentGenerationObservation,
	source Source,
	owner Owner,
	fence Fence,
) error {
	if observed.Source != source {
		return fmt.Errorf("%w: provider source identity differs from admitted source", ErrConflict)
	}
	if observed.Owner != providerOwner(owner) {
		return fmt.Errorf("%w: provider owner identity differs from admitted owner", ErrConflict)
	}
	if observed.Fence != fence {
		return fmt.Errorf("%w: workspace execution manifest fence differs", ErrConflict)
	}
	return nil
}

func providerOwner(owner Owner) ProviderOwner {
	return ProviderOwner{
		TenantID:    owner.TenantID,
		UserID:      owner.UserID,
		WorkspaceID: owner.WorkspaceID,
		RunID:       owner.RunID,
		GrantID:     owner.GrantID,
	}
}

func requireExactGeneration(observed CurrentGenerationObservation, request StopRequest) error {
	if err := requireObservedAuthority(observed, request.Source, request.Owner, request.Fence); err != nil {
		return err
	}
	if err := validateObservedGeneration(observed.Generation); err != nil {
		return err
	}
	if err := validateRuntimeState(observed.State); err != nil {
		return err
	}
	if observed.Generation.ExpectedGeneration != request.ExpectedGeneration {
		return fmt.Errorf("%w: provider container generation differs from the immutable claim", ErrConflict)
	}
	if isExactExited(observed.State) {
		if observed.Generation.ExecutionFinishedAt == "" {
			return fmt.Errorf("%w: exited generation has no execution finish time", ErrConflict)
		}
		return nil
	}
	if observed.Generation.ExecutionFinishedAt != "" {
		return fmt.Errorf("%w: non-exited generation has an execution finish time", ErrConflict)
	}
	return nil
}

func validateReceipt(receipt Receipt, expectedRequest StopRequest) error {
	if receipt.Version != 1 || receipt.Kind != receiptKind {
		return fmt.Errorf("%w: terminal receipt version or kind is invalid", ErrConflict)
	}
	if err := validateStopRequest(receipt.Request); err != nil {
		return fmt.Errorf("%w: terminal receipt request is invalid: %v", ErrConflict, err)
	}
	if err := requireExactRequest(receipt.Request, expectedRequest); err != nil {
		return err
	}
	if receipt.TerminalGeneration.ExpectedGeneration != expectedRequest.ExpectedGeneration {
		return fmt.Errorf("%w: receipt terminal generation differs from its request", ErrConflict)
	}
	finishedAt, err := parseUTCTime(receipt.TerminalGeneration.ExecutionFinishedAt)
	if err != nil {
		return fmt.Errorf("%w: receipt execution finish time is invalid", ErrConflict)
	}
	startedAt, _ := parseUTCTime(expectedRequest.ExpectedGeneration.ExecutionStartedAt)
	if finishedAt.Before(startedAt) {
		return fmt.Errorf("%w: receipt execution finish precedes its generation", ErrConflict)
	}
	stoppedAt, err := parseUTCTime(receipt.StoppedAt)
	if err != nil || stoppedAt.Before(finishedAt) {
		return fmt.Errorf("%w: receipt stoppedAt is invalid", ErrConflict)
	}
	digest, ref, err := deriveReceiptIdentity(
		receipt.Request,
		receipt.TerminalGeneration,
		receipt.StoppedAt,
	)
	if err != nil || receipt.ReceiptDigest != digest || receipt.ReceiptRef != ref {
		return fmt.Errorf("%w: receipt digest or reference is invalid", ErrConflict)
	}
	return nil
}

func requireExactRequest(actual, expected StopRequest) error {
	actualBytes, actualErr := canonicalJSON(actual)
	expectedBytes, expectedErr := canonicalJSON(expected)
	if actualErr != nil || expectedErr != nil || !bytes.Equal(actualBytes, expectedBytes) {
		return fmt.Errorf("%w: operationId is already claimed by different exact authority", ErrConflict)
	}
	return nil
}

func requireExactPurpose(actual, expected Purpose) error {
	actualBytes, actualErr := canonicalJSON(actual)
	expectedBytes, expectedErr := canonicalJSON(expected)
	if actualErr != nil || expectedErr != nil || !bytes.Equal(actualBytes, expectedBytes) {
		return fmt.Errorf("%w: stopped-generation purpose differs from the required purpose", ErrConflict)
	}
	return nil
}

func isExactRunning(state RuntimeState) bool {
	return state.Status == "running" && state.Running && !state.Paused &&
		!state.Restarting && !state.Dead && state.PID > 0
}

func isExactExited(state RuntimeState) bool {
	return state.Status == "exited" && !state.Running && !state.Paused &&
		!state.Restarting && !state.Dead && state.PID == 0
}

func keysForRequest(request StopRequest) operationKeys {
	return keysForIdentity(request.Owner.TenantID, request.OperationID)
}

func keysForIdentity(tenantID, operationID string) operationKeys {
	tenantDigest := hashHex("ambit-sandbox-generation-stop-tenant/v1\n" + tenantID)
	operationDigest := hashHex(strings.Join([]string{
		"ambit-sandbox-generation-stop-operation/v1",
		tenantID,
		operationID,
	}, "\n"))
	root := privateRoot + "/" + tenantDigest + "/" + operationDigest
	return operationKeys{claim: root + "/claim.json", receipt: root + "/receipt.json"}
}

func claimRef(request StopRequest) string {
	canonical, err := canonicalJSON(request)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(append([]byte("ambit-sandbox-generation-stop-claim/v1\n"), canonical...))
	return "ambit.stopped-generation-claim:v1:sha256:" + hex.EncodeToString(digest[:])
}

func hashHex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func strictJSON(data []byte, target any) error {
	if err := DecodeExactJSON(data, target); err != nil {
		return err
	}
	exact, err := json.Marshal(target)
	if err != nil {
		return fmt.Errorf("re-encode exact durable JSON: %w", err)
	}
	if !bytes.Equal(data, exact) {
		return errors.New("durable JSON is not the exact canonical contract encoding")
	}
	return nil
}

// rejectDuplicateJSONKeys walks the original token stream before decoding to
// a struct. encoding/json otherwise keeps the final value for a repeated key,
// which would allow an immutable authority record to have two textual
// meanings even though only one reaches validation.
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateUniqueJSONValue(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("JSON object did not close")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("JSON array did not close")
		}
		return nil
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func objectReadError(operation string, err error) error {
	if errors.Is(err, storage.ErrPrivateObjectTooLarge) {
		return fmt.Errorf("%w: %s exceeded its immutable record bound", ErrConflict, operation)
	}
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, operation, err)
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func parseUTCTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, errors.New("timestamp is not RFC3339Nano UTC")
	}
	return parsed, nil
}

func boundedRef(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character == 0 || unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func invalidf(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, fmt.Sprintf(format, arguments...))
}

func cloneStopRequest(request StopRequest) StopRequest {
	request.Purpose = clonePurpose(request.Purpose)
	return request
}

func clonePurpose(purpose Purpose) Purpose {
	if purpose.RendererProcessIdentity != nil {
		identity := *purpose.RendererProcessIdentity
		purpose.RendererProcessIdentity = &identity
	}
	return purpose
}

func (locks *keyedLocks) acquire(key string) func() {
	locks.mu.Lock()
	item := locks.items[key]
	if item == nil {
		item = &keyedLock{}
		locks.items[key] = item
	}
	item.refs++
	locks.mu.Unlock()

	item.mu.Lock()
	return func() {
		item.mu.Unlock()
		locks.mu.Lock()
		item.refs--
		if item.refs == 0 {
			delete(locks.items, key)
		}
		locks.mu.Unlock()
	}
}
