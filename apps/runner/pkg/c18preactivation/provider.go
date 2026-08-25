// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

// Package c18preactivation implements the provider-neutral physical execution
// boundary for the C18 pre-activation evaluator. It deliberately delegates
// isolated rendering to the existing specialist-render authority instead of
// acquiring Docker, workspace paths, or task-container authority of its own.
package c18preactivation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

// ProviderExecutionInput contains the complete product authority and exact
// in-memory payload bytes for one specialist-render operation. Implementations
// may transport these values differently, but may not reinterpret them.
type ProviderExecutionInput struct {
	Workspace                generationstop.Source
	OperationID              string
	ArtifactRenderJobRef     string
	Composition              specialistrender.Pin
	Owner                    generationstop.ProviderOwner
	Fence                    generationstop.Fence
	ExpectedParentGeneration generationstop.ExpectedGeneration
	Image                    specialistrender.ImagePin
	Interface                specialistrender.Pin
	Executor                 specialistrender.Pin
	Executable               string
	ProviderPolicy           specialistrender.Pin
	RequestBytes             []byte
	SourceBytes              []byte
}

// ProviderExecutionResult retains both the exact provider receipt and the
// byte-custodied output files in receipt order.
type ProviderExecutionResult struct {
	Receipt specialistrender.Receipt
	Files   []ProviderOutput
}

type ProviderOutput struct {
	Descriptor specialistrender.OutputFile
	Bytes      []byte
}

// SpecialistRenderProvider is the only effectful port used by the evaluator.
// It is intentionally narrower than a Runner or Docker client.
type SpecialistRenderProvider interface {
	Execute(context.Context, ProviderExecutionInput) (ProviderExecutionResult, error)
}

// ProviderRequest materializes and validates the exact existing Runner wire
// header. Copies prevent a caller from mutating payload bytes after admission.
func ProviderRequest(input ProviderExecutionInput) (specialistrender.Request, []byte, []byte, error) {
	requestBytes := append([]byte(nil), input.RequestBytes...)
	sourceBytes := append([]byte(nil), input.SourceBytes...)
	if len(requestBytes) == 0 || len(requestBytes) > specialistrender.MaximumRequestBytes {
		return specialistrender.Request{}, nil, nil, fmt.Errorf("C18 provider request bytes are outside their bound")
	}
	if len(sourceBytes) == 0 || len(sourceBytes) > specialistrender.MaximumSourceBytes {
		return specialistrender.Request{}, nil, nil, fmt.Errorf("C18 provider source bytes are outside their bound")
	}
	request := specialistrender.Request{
		Schema:                   specialistrender.RequestSchema,
		OperationID:              input.OperationID,
		ArtifactRenderJobRef:     input.ArtifactRenderJobRef,
		Composition:              input.Composition,
		Source:                   input.Workspace,
		Owner:                    input.Owner,
		Fence:                    input.Fence,
		ExpectedParentGeneration: input.ExpectedParentGeneration,
		Image:                    input.Image,
		Interface:                input.Interface,
		Executor:                 input.Executor,
		Executable:               input.Executable,
		ProviderPolicy:           input.ProviderPolicy,
		RequestBytes:             int64(len(requestBytes)),
		RequestChunkCount:        chunkCount(len(requestBytes)),
		RequestDigest:            sha256Digest(requestBytes),
		SourceBytes:              int64(len(sourceBytes)),
		SourceChunkCount:         chunkCount(len(sourceBytes)),
		SourceDigest:             sha256Digest(sourceBytes),
	}
	fingerprint, err := specialistrender.ComputeRequestFingerprint(request)
	if err != nil {
		return specialistrender.Request{}, nil, nil, fmt.Errorf("compute C18 provider request fingerprint: %w", err)
	}
	request.RequestFingerprint = fingerprint
	if err := specialistrender.ValidateRequest(request); err != nil {
		return specialistrender.Request{}, nil, nil, fmt.Errorf("validate C18 provider request: %w", err)
	}
	return request, requestBytes, sourceBytes, nil
}

func chunkCount(length int) int {
	return (length + specialistrender.RequestChunkBytes - 1) / specialistrender.RequestChunkBytes
}

func sha256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
