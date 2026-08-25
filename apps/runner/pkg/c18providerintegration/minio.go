// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/storage"
)

const minIOConcurrentContenders = 16

func RunMinIOIntegration(
	ctx context.Context,
	run MinIOIntegrationRun,
	objects storage.PrivateObjectStreamStorageClient,
	now func() time.Time,
) (MinIOIntegrationReceipt, error) {
	if err := ValidateMinIOIntegrationRun(run); err != nil {
		return MinIOIntegrationReceipt{}, err
	}
	if objects == nil {
		return MinIOIntegrationReceipt{}, fmt.Errorf("streaming private object storage is not configured")
	}
	if now == nil {
		now = time.Now
	}
	observedFrom := formatObservationTime(now())
	root := "private/integration/c18-provider-live/" + run.RunID
	mainKey := root + "/conditional-checksum-range.bin"
	streamKey := root + "/stream/only.bin"
	concurrentKey := root + "/concurrent-conditional-create.bin"
	keys := []string{mainKey, streamKey, concurrentKey}
	for _, key := range keys {
		if err := objects.DeletePrivateObject(ctx, key); err != nil {
			return MinIOIntegrationReceipt{}, fmt.Errorf("clear exact integration key before run: %w", err)
		}
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, key := range keys {
			_ = objects.DeletePrivateObject(cleanupCtx, key)
		}
	}()

	payload := []byte("ambit-c18-minio-integration\n" + run.RunID + "\n" + run.SourceRevision + "\n")
	payloadDigest := digestBytes(payload)
	mainMetadata := map[string]string{
		"contract":      "ambit-private-object-integration-v1",
		"run-id-sha256": digestBytes([]byte(run.RunID)),
	}
	if err := objects.CreatePrivateObject(ctx, mainKey, payload, "application/octet-stream", mainMetadata); err != nil {
		return MinIOIntegrationReceipt{}, fmt.Errorf("conditional create private object: %w", err)
	}
	if err := objects.CreatePrivateObject(ctx, mainKey, []byte("replacement"), "application/octet-stream", nil); !errors.Is(err, storage.ErrPrivateObjectAlreadyExists) {
		return MinIOIntegrationReceipt{}, fmt.Errorf("immutable write conflict was not rejected")
	}
	mainInfo, err := objects.StatPrivateObject(ctx, mainKey)
	if err != nil || mainInfo.Size != int64(len(payload)) || mainInfo.ContentSHA256 != payloadDigest {
		return MinIOIntegrationReceipt{}, fmt.Errorf("checksum stat differs from the exact payload")
	}
	mainMetadataDigest, err := canonicalMapDigest(mainInfo.UserMetadata)
	if err != nil {
		return MinIOIntegrationReceipt{}, err
	}

	rangeOffset := int64(7)
	rangeLength := int64(13)
	ranged, err := objects.GetPrivateObjectRange(ctx, mainKey, rangeOffset, rangeLength)
	if err != nil || !bytes.Equal(ranged, payload[rangeOffset:rangeOffset+rangeLength]) {
		return MinIOIntegrationReceipt{}, fmt.Errorf("ranged private object read differs")
	}

	streamMetadata := map[string]string{"sha256": payloadDigest}
	if err := objects.CreatePrivateObjectStream(
		ctx, streamKey, bytes.NewReader(payload), int64(len(payload)),
		"application/octet-stream", streamMetadata,
	); err != nil {
		return MinIOIntegrationReceipt{}, fmt.Errorf("streaming conditional create: %w", err)
	}
	stream, streamInfo, err := objects.OpenPrivateObject(ctx, streamKey)
	if err != nil {
		return MinIOIntegrationReceipt{}, fmt.Errorf("open streamed private object: %w", err)
	}
	streamed, readErr := io.ReadAll(io.LimitReader(stream, int64(len(payload))+1))
	closeErr := stream.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(streamed, payload) ||
		streamInfo.Size != int64(len(payload)) || streamInfo.UserMetadata["sha256"] != payloadDigest {
		return MinIOIntegrationReceipt{}, fmt.Errorf("streaming open differs from the exact payload")
	}
	streamMetadataDigest, err := canonicalMapDigest(streamInfo.UserMetadata)
	if err != nil {
		return MinIOIntegrationReceipt{}, err
	}
	listed, err := objects.ListPrivateObjects(ctx, root+"/stream/", 8)
	if err != nil || len(listed) != 1 || listed[0] != streamKey {
		return MinIOIntegrationReceipt{}, fmt.Errorf("bounded private object list differs")
	}
	listedDigest, err := canonicalStringRosterDigest(listed)
	if err != nil {
		return MinIOIntegrationReceipt{}, err
	}

	type contenderResult struct{ err error }
	results := make(chan contenderResult, minIOConcurrentContenders)
	var group sync.WaitGroup
	for index := 0; index < minIOConcurrentContenders; index++ {
		index := index
		group.Add(1)
		go func() {
			defer group.Done()
			candidate := []byte(fmt.Sprintf("candidate-%02d", index))
			results <- contenderResult{err: objects.CreatePrivateObject(
				ctx, concurrentKey, candidate, "application/octet-stream", nil,
			)}
		}()
	}
	group.Wait()
	close(results)
	winners := 0
	for result := range results {
		switch {
		case result.err == nil:
			winners++
		case errors.Is(result.err, storage.ErrPrivateObjectAlreadyExists):
		default:
			return MinIOIntegrationReceipt{}, fmt.Errorf("concurrent conditional create failed outside the exact conflict class")
		}
	}
	if winners != 1 {
		return MinIOIntegrationReceipt{}, fmt.Errorf("concurrent conditional create admitted %d winners", winners)
	}
	winner, err := objects.GetPrivateObject(ctx, concurrentKey, 64)
	winnerAdmitted := false
	for index := 0; index < minIOConcurrentContenders; index++ {
		if bytes.Equal(winner, []byte(fmt.Sprintf("candidate-%02d", index))) {
			winnerAdmitted = true
			break
		}
	}
	if err != nil || !winnerAdmitted {
		return MinIOIntegrationReceipt{}, fmt.Errorf("concurrent immutable winner is unreadable")
	}

	for _, key := range keys {
		if err := objects.DeletePrivateObject(ctx, key); err != nil {
			return MinIOIntegrationReceipt{}, fmt.Errorf("delete exact integration object: %w", err)
		}
		if _, err := objects.StatPrivateObject(ctx, key); !errors.Is(err, storage.ErrPrivateObjectNotFound) {
			return MinIOIntegrationReceipt{}, fmt.Errorf("deleted integration object is not absent")
		}
	}
	observedUntil := formatObservationTime(now())
	return SealMinIOIntegrationReceipt(MinIOIntegrationReceipt{
		SourceRevision: run.SourceRevision, SourceTree: run.SourceTree, SourceSetDigest: run.SourceSetDigest,
		ObservedFrom: observedFrom, ObservedUntil: observedUntil,
		Observations: MinIOOperationObservations{
			ConditionalCreate: MinIOConditionalCreateObservation{
				PayloadBytes: int64(len(payload)), PayloadSHA256: payloadDigest,
				Contenders: minIOConcurrentContenders, ConcurrentWinners: winners,
				ConflictDisposition: "precondition_failed",
			},
			ChecksumStat: MinIOChecksumStatObservation{
				ByteLength: mainInfo.Size, ContentSHA256: mainInfo.ContentSHA256,
				UserMetadataSHA256: mainMetadataDigest,
			},
			RangedRead: MinIORangedReadObservation{
				Offset: rangeOffset, ByteLength: int64(len(ranged)), SHA256: digestBytes(ranged),
			},
			StreamingOpen: MinIOStreamingOpenObservation{
				ByteLength: int64(len(streamed)), SHA256: digestBytes(streamed),
				UserMetadataSHA256: streamMetadataDigest,
			},
			BoundedList: MinIOBoundedListObservation{Maximum: 8, Count: len(listed), RosterSHA256: listedDigest},
			Delete:      MinIODeleteObservation{ObjectCount: len(keys), AllAbsent: true},
		},
	})
}

func canonicalMapDigest(value map[string]string) (string, error) {
	normalized := make(map[string]string, len(value))
	for key, item := range value {
		normalized[key] = item
	}
	encoded, err := generationstop.CanonicalJSON(normalized)
	if err != nil {
		return "", fmt.Errorf("canonicalize object metadata: %w", err)
	}
	return digestBytes(encoded), nil
}

func canonicalStringRosterDigest(value []string) (string, error) {
	copy := append([]string(nil), value...)
	sort.Strings(copy)
	encoded, err := generationstop.CanonicalJSON(copy)
	if err != nil {
		return "", fmt.Errorf("canonicalize object roster: %w", err)
	}
	return digestBytes(encoded), nil
}
