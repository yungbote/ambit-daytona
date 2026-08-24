// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/storage"
	"github.com/google/uuid"
)

const (
	operationRoot        = "private/specialist-renders/v1"
	operationClaimSchema = "ambit.runtime-provider-specialist-render-claim/v1"
	maximumClaimBytes    = 32 * 1024
)

type OperationStore interface {
	CreatePrivateObject(
		ctx context.Context,
		key string,
		data []byte,
		contentType string,
		metadata map[string]string,
	) error
	CreatePrivateObjectStream(
		ctx context.Context,
		key string,
		reader io.Reader,
		size int64,
		contentType string,
		metadata map[string]string,
	) error
	GetPrivateObject(ctx context.Context, key string, maximumBytes int64) ([]byte, error)
	OpenPrivateObject(ctx context.Context, key string) (io.ReadCloser, storage.PrivateObjectInfo, error)
	StatPrivateObject(ctx context.Context, key string) (storage.PrivateObjectInfo, error)
}

type operationClaim struct {
	Schema  string  `json:"schema"`
	Request Request `json:"request"`
}

type operationKeys struct {
	root    string
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

func keysForRequest(request Request) operationKeys {
	fields := []string{
		request.OperationID, request.Source.ProviderResourceID,
		request.Owner.TenantID, request.Owner.UserID, request.Owner.WorkspaceID,
		request.Owner.RunID, request.Owner.GrantID,
	}
	digest := sha256.Sum256([]byte(strings.Join(fields, "\n")))
	root := operationRoot + "/" + hex.EncodeToString(digest[:])
	return operationKeys{root: root, claim: root + "/claim.json", receipt: root + "/receipt.json"}
}

func keysForObserve(request ObserveRequest) operationKeys {
	return keysForRequest(Request{
		OperationID: request.OperationID, Source: request.Source, Owner: request.Owner,
	})
}

func fileKey(keys operationKeys, ordinal int) string {
	return fmt.Sprintf("%s/files/%03d.bin", keys.root, ordinal)
}

func (service *Service) ensureClaim(ctx context.Context, keys operationKeys, request Request) error {
	claim := operationClaim{Schema: operationClaimSchema, Request: request}
	data, err := generationstop.CanonicalJSON(claim)
	if err != nil || len(data) > maximumClaimBytes {
		return fmt.Errorf("%w: canonical operation claim is invalid", ErrInvalidRequest)
	}
	createErr := service.store.CreatePrivateObject(
		ctx, keys.claim, data, "application/json",
		map[string]string{"request-fingerprint": request.RequestFingerprint},
	)
	if createErr == nil {
		return nil
	}
	if !errors.Is(createErr, storage.ErrPrivateObjectAlreadyExists) {
		return fmt.Errorf("%w: create immutable operation claim: %v", ErrUnavailable, createErr)
	}
	existing, err := service.store.GetPrivateObject(ctx, keys.claim, maximumClaimBytes)
	if err != nil {
		return fmt.Errorf("%w: read immutable operation claim: %v", ErrUnavailable, err)
	}
	var observed operationClaim
	if err := generationstop.DecodeCanonicalJSON(existing, &observed); err != nil || observed != claim {
		return fmt.Errorf("%w: operationId is already claimed by a different request", ErrConflict)
	}
	return nil
}

func (service *Service) readReceipt(
	ctx context.Context,
	keys operationKeys,
	request Request,
	policy Policy,
) (ExecutionResult, bool, error) {
	data, err := service.store.GetPrivateObject(ctx, keys.receipt, MaximumReceiptBytes)
	if errors.Is(err, storage.ErrPrivateObjectNotFound) {
		return ExecutionResult{}, false, nil
	}
	if err != nil {
		return ExecutionResult{}, false, fmt.Errorf("%w: read immutable render receipt: %v", ErrUnavailable, err)
	}
	var receipt Receipt
	if err := generationstop.DecodeCanonicalJSON(data, &receipt); err != nil || receipt.Request != request {
		return ExecutionResult{}, false, fmt.Errorf("%w: stored render receipt is invalid or detached", ErrConflict)
	}
	if err := ValidateReceiptWithPolicy(receipt, policy); err != nil {
		return ExecutionResult{}, false, fmt.Errorf("%w: stored render receipt is invalid: %v", ErrConflict, err)
	}
	files := make([]Payload, len(receipt.Files))
	for index, descriptor := range receipt.Files {
		key := fileKey(keys, index)
		info, err := service.store.StatPrivateObject(ctx, key)
		if err != nil || info.Size != descriptor.ByteLength ||
			(info.ContentSHA256 != "" && info.ContentSHA256 != descriptor.Digest) ||
			info.UserMetadata["sha256"] != descriptor.Digest {
			return ExecutionResult{}, false, fmt.Errorf("%w: stored render output differs from receipt", ErrConflict)
		}
		fileKeyCopy := key
		descriptorCopy := descriptor
		files[index] = Payload{
			File: descriptorCopy,
			Open: func() (io.ReadCloser, error) {
				reader, info, err := service.store.OpenPrivateObject(ctx, fileKeyCopy)
				if err != nil {
					return nil, err
				}
				if info.Size != descriptorCopy.ByteLength ||
					(info.ContentSHA256 != "" && info.ContentSHA256 != descriptorCopy.Digest) ||
					info.UserMetadata["sha256"] != descriptorCopy.Digest {
					_ = reader.Close()
					return nil, fmt.Errorf("stored output identity changed")
				}
				return reader, nil
			},
			Cleanup: func() error { return nil },
		}
	}
	return ExecutionResult{Receipt: receipt, Files: files}, true, nil
}

func (service *Service) publishResult(
	ctx context.Context,
	keys operationKeys,
	result ExecutionResult,
) (ExecutionResult, error) {
	for index, payload := range result.Files {
		reader, err := payload.Open()
		if err != nil {
			return ExecutionResult{}, fmt.Errorf("%w: open provider output for durable custody: %v", ErrOutcomeUnknown, err)
		}
		key := fileKey(keys, index)
		createErr := service.store.CreatePrivateObjectStream(
			ctx, key, reader, payload.File.ByteLength, payload.File.MediaType,
			map[string]string{"sha256": payload.File.Digest},
		)
		closeErr := reader.Close()
		if createErr != nil && !errors.Is(createErr, storage.ErrPrivateObjectAlreadyExists) {
			return ExecutionResult{}, fmt.Errorf("%w: publish immutable render output: %v", ErrOutcomeUnknown, createErr)
		}
		if closeErr != nil {
			return ExecutionResult{}, fmt.Errorf("%w: close durable render output source: %v", ErrOutcomeUnknown, closeErr)
		}
		info, err := service.store.StatPrivateObject(ctx, key)
		if err != nil || info.Size != payload.File.ByteLength ||
			(info.ContentSHA256 != "" && info.ContentSHA256 != payload.File.Digest) ||
			info.UserMetadata["sha256"] != payload.File.Digest {
			return ExecutionResult{}, fmt.Errorf("%w: durable render output differs after publication", ErrOutcomeUnknown)
		}
	}
	receiptBytes, err := generationstop.CanonicalJSON(result.Receipt)
	if err != nil || len(receiptBytes) > MaximumReceiptBytes {
		return ExecutionResult{}, fmt.Errorf("%w: canonical render receipt exceeds its bound", ErrOutcomeUnknown)
	}
	createErr := service.store.CreatePrivateObject(
		ctx, keys.receipt, receiptBytes, "application/json",
		map[string]string{"receipt-digest": result.Receipt.ReceiptDigest},
	)
	if createErr != nil && !errors.Is(createErr, storage.ErrPrivateObjectAlreadyExists) {
		return ExecutionResult{}, fmt.Errorf("%w: publish immutable render receipt: %v", ErrOutcomeUnknown, createErr)
	}
	policy, err := service.policies.Resolve(result.Receipt.Request)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: resolve receipt policy after publication: %v", ErrOutcomeUnknown, err)
	}
	stored, complete, err := service.readReceipt(ctx, keys, result.Receipt.Request, policy)
	if err != nil || !complete {
		return ExecutionResult{}, fmt.Errorf("%w: reconcile immutable render receipt: %v", ErrOutcomeUnknown, err)
	}
	if stored.Receipt.ReceiptDigest != result.Receipt.ReceiptDigest {
		cleanupPayloads(result.Files)
		return stored, nil
	}
	return result, nil
}

func (service *Service) Observe(ctx context.Context, request ObserveRequest) (Observation, error) {
	if err := validateObserveRequest(request); err != nil {
		return Observation{}, err
	}
	keys := keysForObserve(request)
	release := service.locks.acquire(keys.claim)
	defer release()
	claimBytes, err := service.store.GetPrivateObject(ctx, keys.claim, maximumClaimBytes)
	if errors.Is(err, storage.ErrPrivateObjectNotFound) {
		return Observation{Schema: ObservationSchema, Status: "absent"}, nil
	}
	if err != nil {
		return Observation{}, fmt.Errorf("%w: read immutable operation claim: %v", ErrUnavailable, err)
	}
	var claim operationClaim
	if err := generationstop.DecodeCanonicalJSON(claimBytes, &claim); err != nil ||
		claim.Schema != operationClaimSchema || claim.Request.OperationID != request.OperationID ||
		claim.Request.RequestFingerprint != request.RequestFingerprint || claim.Request.Source != request.Source ||
		claim.Request.Owner != request.Owner || claim.Request.Fence != request.Fence {
		return Observation{}, fmt.Errorf("%w: observed operation claim differs from authority", ErrConflict)
	}
	policy, err := service.policies.Resolve(claim.Request)
	if err != nil {
		return Observation{}, fmt.Errorf("%w: resolve observed operation policy: %v", ErrUnavailable, err)
	}
	result, complete, err := service.readReceipt(ctx, keys, claim.Request, policy)
	if err != nil {
		return Observation{}, err
	}
	if !complete {
		return Observation{Schema: ObservationSchema, Status: "partial"}, nil
	}
	return Observation{Schema: ObservationSchema, Status: "complete", Receipt: &result.Receipt}, nil
}

func validateObserveRequest(request ObserveRequest) error {
	if request.Schema != ObserveRequestSchema {
		return invalidf("observe request schema is invalid")
	}
	if parsed, err := uuid.Parse(request.OperationID); err != nil || parsed == uuid.Nil || parsed.String() != request.OperationID {
		return invalidf("observe operationId must be a non-nil canonical UUID")
	}
	if len(request.RequestFingerprint) != 64 || strings.ToLower(request.RequestFingerprint) != request.RequestFingerprint {
		return invalidf("observe requestFingerprint is invalid")
	}
	if _, err := hex.DecodeString(request.RequestFingerprint); err != nil {
		return invalidf("observe requestFingerprint is invalid")
	}
	if err := generationstop.ValidateSource(request.Source); err != nil {
		return invalidf("observe source is invalid")
	}
	if err := generationstop.ValidateProviderOwner(request.Owner); err != nil {
		return invalidf("observe owner is invalid")
	}
	if request.Fence.WorkspaceExecutionManifestRef == "" || len(request.Fence.WorkspaceExecutionManifestRef) > 2048 {
		return invalidf("observe fence is invalid")
	}
	return nil
}
