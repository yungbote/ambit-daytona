// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18imagepublication

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type Publisher struct {
	client           *http.Client
	clock            func() time.Time
	executableSHA256 string
	transferPolicy   transferPolicy
}

func NewPublisher(client *http.Client, clock func() time.Time, executableSHA256 string) (*Publisher, error) {
	if !exactSHA256(executableSHA256) {
		return nil, errors.New("publisher executable SHA-256 is invalid")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Publisher{
		client: client, clock: clock, executableSHA256: executableSHA256,
		transferPolicy: defaultProductionTransferPolicy(),
	}, nil
}

func (value *Publisher) Publish(ctx context.Context, request Request, requestSHA256 string) (Receipt, error) {
	if ctx == nil {
		return Receipt{}, errors.New("publication context is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	if err := ValidateRequest(request); err != nil {
		return Receipt{}, err
	}
	requestBytes, err := CanonicalJSON(request)
	if err != nil || !exactSHA256(requestSHA256) || digestBytes(requestBytes) != requestSHA256 {
		return Receipt{}, errors.New("publication request SHA-256 is invalid")
	}
	registry, err := newRegistryClient(request.Registry.PublicationOrigin, value.client, value.transferPolicy)
	if err != nil {
		return Receipt{}, err
	}
	startedAt := formatInstant(value.clock())
	archives := make([]*inspectedArchive, 0, len(request.Archives))
	closeAll := func() error {
		var result error
		for _, archive := range archives {
			result = errors.Join(result, archive.Close())
		}
		return result
	}
	fail := func(cause error) (Receipt, error) {
		return Receipt{}, errors.Join(cause, closeAll())
	}
	for _, archiveRequest := range request.Archives {
		archive, inspectErr := inspectArchive(ctx, archiveRequest, request.ImageTag, request.Source)
		if inspectErr != nil {
			return fail(fmt.Errorf("inspect %s OCI archive: %w", archiveRequest.PackID, inspectErr))
		}
		archives = append(archives, archive)
	}
	if err := registry.ping(ctx); err != nil {
		return fail(err)
	}
	for _, archive := range archives {
		if err := archive.verifyPathBinding(); err != nil {
			return fail(err)
		}
	}
	// Prove the complete mutable-name frontier before uploading anything. A
	// conflict in the fourth repository must not leave the first three changed.
	for _, archive := range archives {
		if _, err := registry.requireCompatibleTag(ctx, archive, request.ImageTag); err != nil {
			return fail(err)
		}
		if err := registry.preflightImmutableState(ctx, archive); err != nil {
			return fail(err)
		}
	}
	published := make([]PublishedArchive, 0, len(archives))
	for _, archive := range archives {
		row, publishErr := registry.publishArchive(ctx, archive, request)
		if publishErr != nil {
			return fail(fmt.Errorf("publish %s OCI archive: %w", archive.request.PackID, publishErr))
		}
		published = append(published, row)
	}
	// The exact held inode is rehashed after all network reads and writes. A
	// pathname substitution cannot affect the descriptor, and an in-place
	// mutation cannot authorize a receipt.
	for _, archive := range archives {
		if err := archive.verifyArchiveDigest(ctx); err != nil {
			return fail(err)
		}
	}
	if err := context.Cause(ctx); err != nil {
		return fail(err)
	}
	if err := closeAll(); err != nil {
		return Receipt{}, fmt.Errorf("close OCI archive custody: %w", err)
	}
	if err := context.Cause(ctx); err != nil {
		return Receipt{}, err
	}
	completedAt := formatInstant(value.clock())
	return SealReceipt(Receipt{
		RequestSHA256:     requestSHA256,
		Request:           request,
		Executable:        ExecutableAuthority{SHA256: value.executableSHA256},
		StartedAt:         startedAt,
		CompletedAt:       completedAt,
		PublishedArchives: published,
		Outcome:           "succeeded",
	})
}
