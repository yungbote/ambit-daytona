// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"

	"github.com/daytonaio/runner/pkg/storage"
)

// Each part uses the established immutable single-PUT stream authority. A
// logical pack may reach 8 GiB while every object remains below S3's 5 GiB PUT
// limit. No multipart publication or replacement writes are introduced.
const maximumInventoryBytePartBytes int64 = MaximumCaptureBytes
const inventoryBytePartContract = "ambit-working-tree-inventory-byte-part-v1"

type inventoryBytePackWriter struct {
	file               *os.File
	digest             hash.Hash
	partDigest         hash.Hash
	parts              []WorkingTreeInventoryBytePart
	length, partLength int64
	sealed             bool
}

func newInventoryBytePackWriter() (*inventoryBytePackWriter, error) {
	file, err := newPrivateScratchFile("ambit-working-tree-bytes-*")
	if err != nil {
		return nil, err
	}
	return &inventoryBytePackWriter{file: file, digest: sha256.New(), partDigest: sha256.New(), parts: []WorkingTreeInventoryBytePart{}}, nil
}

func (w *inventoryBytePackWriter) Close() error { return w.file.Close() }

func (w *inventoryBytePackWriter) Write(data []byte) (int, error) {
	if w.sealed {
		return 0, errors.New("inventory byte pack is sealed")
	}
	if int64(len(data)) > MaximumWorkingTreeAggregateBytes-w.length {
		return 0, fmt.Errorf("%w: inventory byte pack exceeds its byte bound", ErrConflict)
	}
	written := 0
	for len(data) > 0 {
		length := min(int64(len(data)), maximumInventoryBytePartBytes-w.partLength)
		count, err := w.file.Write(data[:length])
		if count > 0 {
			_, _ = w.digest.Write(data[:count])
			_, _ = w.partDigest.Write(data[:count])
			w.length += int64(count)
			w.partLength += int64(count)
			written += count
			data = data[count:]
		}
		if err != nil {
			return written, err
		}
		if int64(count) != length {
			return written, io.ErrShortWrite
		}
		if w.partLength == maximumInventoryBytePartBytes {
			w.finishPart()
		}
	}
	return written, nil
}

func (w *inventoryBytePackWriter) finishPart() {
	if w.partLength == 0 {
		return
	}
	w.parts = append(w.parts, WorkingTreeInventoryBytePart{ByteOffset: w.length - w.partLength, ByteLength: w.partLength, SHA256: "sha256:" + hex.EncodeToString(w.partDigest.Sum(nil))})
	w.partLength = 0
	w.partDigest.Reset()
}

func (w *inventoryBytePackWriter) Seal() WorkingTreeInventoryBytePack {
	w.finishPart()
	w.sealed = true
	return WorkingTreeInventoryBytePack{ByteLength: w.length, SHA256: "sha256:" + hex.EncodeToString(w.digest.Sum(nil)), Parts: append([]WorkingTreeInventoryBytePart{}, w.parts...)}
}

func inventoryBytePartKey(root string, index int) string {
	return fmt.Sprintf("%s/bytes/%012d.bin", root, index)
}

func validateInventoryBytePack(pack WorkingTreeInventoryBytePack, maximum int64) error {
	if pack.ByteLength < 0 || pack.ByteLength > maximum || !isSHA256Digest(pack.SHA256) || pack.Parts == nil {
		return fmt.Errorf("%w: inventory byte pack is invalid", ErrConflict)
	}
	var offset int64
	for _, part := range pack.Parts {
		if part.ByteOffset != offset || part.ByteLength < 1 || part.ByteLength > maximumInventoryBytePartBytes || part.ByteLength > pack.ByteLength-offset || !isSHA256Digest(part.SHA256) {
			return fmt.Errorf("%w: inventory byte parts do not cover the exact pack", ErrConflict)
		}
		offset += part.ByteLength
	}
	if offset != pack.ByteLength || (pack.ByteLength == 0 && pack.SHA256 != sha256Digest(nil)) {
		return fmt.Errorf("%w: inventory byte pack coverage changed", ErrConflict)
	}
	return nil
}

func (s *Service) verifyInventoryBytePart(ctx context.Context, request WorkingTreeInventoryRequest, index int, part WorkingTreeInventoryBytePart) error {
	info, err := s.objects.StatPrivateObject(ctx, inventoryBytePartKey(inventoryRoot(request), index))
	if err != nil {
		return err
	}
	metadata := lowerMetadata(info.UserMetadata)
	if info.Size != part.ByteLength || info.ContentSHA256 != part.SHA256 || metadata["sha256"] != part.SHA256 || metadata["byte-offset"] != strconv.FormatInt(part.ByteOffset, 10) || metadata["byte-length"] != strconv.FormatInt(part.ByteLength, 10) || metadata["provider-resource-id"] != inventoryResourceID(request) || metadata["contract"] != inventoryBytePartContract {
		return fmt.Errorf("%w: inventory byte part differs from its pinned custody", ErrConflict)
	}
	return nil
}

func (s *Service) publishInventoryBytes(ctx context.Context, request WorkingTreeInventoryRequest, pack WorkingTreeInventoryBytePack, file *os.File) error {
	for index, part := range pack.Parts {
		if err := s.requireInventoryNotDeleting(ctx, request); err != nil {
			return err
		}
		if err := s.verifyInventoryBytePart(ctx, request, index, part); err == nil {
			continue
		} else if !errors.Is(err, storage.ErrPrivateObjectNotFound) {
			return objectReadError("inspect inventory byte part", err)
		}
		err := s.objects.CreatePrivateObjectStream(ctx, inventoryBytePartKey(inventoryRoot(request), index), captureContextReader{ctx: ctx, reader: io.NewSectionReader(file, part.ByteOffset, part.ByteLength)}, part.ByteLength, "application/octet-stream", map[string]string{
			"sha256": part.SHA256, "byte-offset": strconv.FormatInt(part.ByteOffset, 10), "byte-length": strconv.FormatInt(part.ByteLength, 10), "provider-resource-id": inventoryResourceID(request), "contract": inventoryBytePartContract,
		})
		if verifyErr := s.verifyInventoryBytePart(ctx, request, index, part); verifyErr != nil {
			return errors.Join(fmt.Errorf("%w: inventory byte publication is unresolved", ErrOutcomeUnknown), err, verifyErr)
		}
	}
	return nil
}

func (s *Service) ReadWorkingTreeInventoryRange(ctx context.Context, sandboxID string, request WorkingTreeInventoryRangeRequest) (WorkingTreeInventoryRange, error) {
	if err := s.validateInventoryRequest(sandboxID, request.Request); err != nil {
		return WorkingTreeInventoryRange{}, err
	}
	if request.ProviderResourceID != inventoryResourceID(request.Request) || !isSHA256Digest(request.InventoryDigest) || request.Offset < 0 || request.MaximumBytes < 1 || request.MaximumBytes > MaximumReadBytes {
		return WorkingTreeInventoryRange{}, invalidf("inventory range request is invalid")
	}
	root := inventoryRoot(request.Request)
	release := s.locks.acquire(root)
	defer release()
	if err := s.requireInventoryNotDeleting(ctx, request.Request); err != nil {
		return WorkingTreeInventoryRange{}, err
	}
	index, exists, err := s.readInventoryIndex(ctx, request.Request)
	if err != nil {
		return WorkingTreeInventoryRange{}, err
	}
	if !exists {
		return WorkingTreeInventoryRange{}, fmt.Errorf("%w: inventory is not complete", ErrUnavailable)
	}
	if index.InventoryDigest != request.InventoryDigest || request.Offset > index.BytePack.ByteLength {
		return WorkingTreeInventoryRange{}, fmt.Errorf("%w: inventory range differs from its pinned index", ErrConflict)
	}
	length := min(request.MaximumBytes, index.BytePack.ByteLength-request.Offset)
	data := make([]byte, 0, length)
	position := request.Offset
	for partIndex, part := range index.BytePack.Parts {
		if position >= request.Offset+length {
			break
		}
		if position >= part.ByteOffset+part.ByteLength {
			continue
		}
		if position < part.ByteOffset {
			return WorkingTreeInventoryRange{}, fmt.Errorf("%w: inventory byte parts contain a gap", ErrConflict)
		}
		if err := s.verifyInventoryBytePart(ctx, request.Request, partIndex, part); err != nil {
			return WorkingTreeInventoryRange{}, objectReadError("verify inventory byte part", err)
		}
		count := min(request.Offset+length-position, part.ByteOffset+part.ByteLength-position)
		chunk, err := s.objects.GetPrivateObjectRange(ctx, inventoryBytePartKey(root, partIndex), position-part.ByteOffset, count)
		if err != nil {
			return WorkingTreeInventoryRange{}, objectReadError("read inventory byte range", err)
		}
		if int64(len(chunk)) != count {
			return WorkingTreeInventoryRange{}, fmt.Errorf("%w: inventory byte range was truncated", ErrConflict)
		}
		data = append(data, chunk...)
		position += count
	}
	if int64(len(data)) != length {
		return WorkingTreeInventoryRange{}, fmt.Errorf("%w: inventory byte range is incomplete", ErrConflict)
	}
	return WorkingTreeInventoryRange{ProviderResourceID: index.ProviderResourceID, InventoryDigest: index.InventoryDigest, Offset: request.Offset, ByteLength: length, TotalByteLength: index.BytePack.ByteLength, EOF: request.Offset+length == index.BytePack.ByteLength, BytesBase64: base64.StdEncoding.EncodeToString(data)}, nil
}
