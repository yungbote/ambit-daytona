// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

type providerRequestStart struct {
	Schema     string                   `json:"schema"`
	Kind       string                   `json:"kind"`
	ChunkBytes int                      `json:"chunkBytes"`
	Request    specialistrender.Request `json:"request"`
}

type providerChunk struct {
	Schema      string `json:"schema"`
	Kind        string `json:"kind"`
	OperationID string `json:"operationId"`
	Index       int    `json:"index"`
	Bytes       int    `json:"bytes"`
	Digest      string `json:"sha256"`
	Base64      string `json:"base64"`
}

type providerRequestEnd struct {
	Schema            string `json:"schema"`
	Kind              string `json:"kind"`
	OperationID       string `json:"operationId"`
	RequestBytes      int64  `json:"requestBytes"`
	RequestChunkCount int    `json:"requestChunkCount"`
	RequestDigest     string `json:"requestSha256"`
	SourceBytes       int64  `json:"sourceBytes"`
	SourceChunkCount  int    `json:"sourceChunkCount"`
	SourceDigest      string `json:"sourceSha256"`
	FrameCount        int    `json:"frameCount"`
	StreamDigest      string `json:"streamSha256"`
}

type providerResponseStart struct {
	Schema     string                   `json:"schema"`
	Kind       string                   `json:"kind"`
	ChunkBytes int                      `json:"chunkBytes"`
	Receipt    specialistrender.Receipt `json:"receipt"`
}

type providerFileChunk struct {
	Schema      string `json:"schema"`
	Kind        string `json:"kind"`
	OperationID string `json:"operationId"`
	Ordinal     int    `json:"ordinal"`
	Index       int    `json:"index"`
	Bytes       int    `json:"bytes"`
	Digest      string `json:"sha256"`
	Base64      string `json:"base64"`
}

type providerResponseEnd struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	OperationID   string `json:"operationId"`
	ReceiptDigest string `json:"receiptDigest"`
	FileCount     int    `json:"fileCount"`
	TotalBytes    int64  `json:"totalBytes"`
	FrameCount    int    `json:"frameCount"`
	StreamDigest  string `json:"streamSha256"`
}

type frameKind struct {
	Kind string `json:"kind"`
}

// EncodeProviderRequestStream is the client-side inverse of
// specialistrender.DecodeRequestStream. Both are exercised against each other
// in tests so the driver does not maintain an unproved parallel transport.
func EncodeProviderRequestStream(
	writer io.Writer,
	request specialistrender.Request,
	requestBytes []byte,
	sourceBytes []byte,
) error {
	if err := specialistrender.ValidateRequest(request); err != nil {
		return fmt.Errorf("encode invalid specialist-render request: %w", err)
	}
	if int64(len(requestBytes)) != request.RequestBytes || sha256Digest(requestBytes) != request.RequestDigest ||
		chunkCount(len(requestBytes)) != request.RequestChunkCount ||
		int64(len(sourceBytes)) != request.SourceBytes || sha256Digest(sourceBytes) != request.SourceDigest ||
		chunkCount(len(sourceBytes)) != request.SourceChunkCount {
		return errors.New("specialist-render payload bytes differ from their request authority")
	}
	streamHash := sha256.New()
	frameCount := 0
	write := func(value any) error {
		line, err := generationstop.CanonicalJSON(value)
		if err != nil {
			return fmt.Errorf("canonicalize specialist-render request frame: %w", err)
		}
		if len(line)+1 > specialistrender.MaximumFrameBytes {
			return errors.New("specialist-render request frame exceeds its bound")
		}
		if _, err := writer.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("write specialist-render request frame: %w", err)
		}
		writeHashedLine(streamHash, line)
		frameCount++
		return nil
	}
	if err := write(providerRequestStart{
		Schema: specialistrender.ProviderFrameSchema, Kind: "provider_request_start",
		ChunkBytes: specialistrender.RequestChunkBytes, Request: request,
	}); err != nil {
		return err
	}
	if err := writePayloadFrames(write, request.OperationID, "request_chunk", requestBytes); err != nil {
		return err
	}
	if err := writePayloadFrames(write, request.OperationID, "source_chunk", sourceBytes); err != nil {
		return err
	}
	end := providerRequestEnd{
		Schema: specialistrender.ProviderFrameSchema, Kind: "provider_request_end",
		OperationID:  request.OperationID,
		RequestBytes: request.RequestBytes, RequestChunkCount: request.RequestChunkCount,
		RequestDigest: request.RequestDigest, SourceBytes: request.SourceBytes,
		SourceChunkCount: request.SourceChunkCount, SourceDigest: request.SourceDigest,
		FrameCount: frameCount, StreamDigest: hashDigest(streamHash),
	}
	line, err := generationstop.CanonicalJSON(end)
	if err != nil {
		return fmt.Errorf("canonicalize specialist-render request end: %w", err)
	}
	if len(line)+1 > specialistrender.MaximumFrameBytes {
		return errors.New("specialist-render request end exceeds its bound")
	}
	if _, err := writer.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write specialist-render request end: %w", err)
	}
	return nil
}

func writePayloadFrames(
	write func(any) error,
	operationID string,
	kind string,
	payload []byte,
) error {
	for index, offset := 0, 0; offset < len(payload); index++ {
		end := offset + specialistrender.RequestChunkBytes
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[offset:end]
		if err := write(providerChunk{
			Schema: specialistrender.ProviderFrameSchema, Kind: kind,
			OperationID: operationID, Index: index, Bytes: len(chunk),
			Digest: sha256Digest(chunk), Base64: base64.StdEncoding.EncodeToString(chunk),
		}); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

// DecodeProviderResponseStream is the client-side inverse of
// specialistrender.EncodeResponseStream. It admits no partial output: every
// descriptor, chunk, aggregate, receipt, and stream digest must agree before
// any bytes are returned.
func DecodeProviderResponseStream(
	ctx context.Context,
	reader io.Reader,
	expected specialistrender.Request,
) (ProviderExecutionResult, error) {
	if err := specialistrender.ValidateRequest(expected); err != nil {
		return ProviderExecutionResult{}, fmt.Errorf("expected specialist-render request is invalid: %w", err)
	}
	lines := bufio.NewReaderSize(reader, specialistrender.MaximumFrameBytes+1)
	first, err := readFrameLine(lines)
	if err != nil {
		return ProviderExecutionResult{}, err
	}
	var start providerResponseStart
	if err := generationstop.DecodeCanonicalJSON(first, &start); err != nil {
		return ProviderExecutionResult{}, fmt.Errorf("specialist-render response start is invalid: %w", err)
	}
	if start.Schema != specialistrender.ProviderFrameSchema || start.Kind != "provider_response_start" ||
		start.ChunkBytes != specialistrender.RequestChunkBytes {
		return ProviderExecutionResult{}, errors.New("specialist-render response start contract differs")
	}
	if err := specialistrender.ValidateReceipt(start.Receipt); err != nil {
		return ProviderExecutionResult{}, fmt.Errorf("specialist-render receipt is invalid: %w", err)
	}
	if !canonicalEqual(start.Receipt.Request, expected) {
		return ProviderExecutionResult{}, errors.New("specialist-render receipt changed the exact request")
	}
	streamHash := sha256.New()
	writeHashedLine(streamHash, first)
	frameCount := 1
	files := make([]ProviderOutput, len(start.Receipt.Files))
	fileHashes := make([]hash.Hash, len(start.Receipt.Files))
	fileIndexes := make([]int, len(start.Receipt.Files))
	fileBytes := make([]int64, len(start.Receipt.Files))
	for index, descriptor := range start.Receipt.Files {
		files[index].Descriptor = descriptor
		files[index].Bytes = make([]byte, 0, descriptor.ByteLength)
		fileHashes[index] = sha256.New()
	}
	currentOrdinal := 0
	for {
		if err := ctx.Err(); err != nil {
			return ProviderExecutionResult{}, err
		}
		line, err := readFrameLine(lines)
		if err != nil {
			return ProviderExecutionResult{}, err
		}
		var kind frameKind
		if err := json.Unmarshal(line, &kind); err != nil {
			return ProviderExecutionResult{}, fmt.Errorf("specialist-render response frame kind is invalid: %w", err)
		}
		switch kind.Kind {
		case "file_chunk":
			var chunk providerFileChunk
			if err := generationstop.DecodeCanonicalJSON(line, &chunk); err != nil {
				return ProviderExecutionResult{}, fmt.Errorf("specialist-render file chunk is invalid: %w", err)
			}
			if chunk.Schema != specialistrender.ProviderFrameSchema || chunk.OperationID != expected.OperationID ||
				chunk.Ordinal < 0 || chunk.Ordinal >= len(files) || chunk.Ordinal < currentOrdinal ||
				chunk.Index != fileIndexes[chunk.Ordinal] {
				return ProviderExecutionResult{}, errors.New("specialist-render file chunk authority or order differs")
			}
			currentOrdinal = chunk.Ordinal
			decoded, err := decodeCanonicalBase64(chunk.Base64, chunk.Bytes)
			if err != nil || chunk.Bytes > specialistrender.RequestChunkBytes || chunk.Digest != sha256Digest(decoded) {
				return ProviderExecutionResult{}, errors.New("specialist-render file chunk bytes or digest are invalid")
			}
			fileBytes[chunk.Ordinal] += int64(len(decoded))
			if fileBytes[chunk.Ordinal] > files[chunk.Ordinal].Descriptor.ByteLength {
				return ProviderExecutionResult{}, errors.New("specialist-render file bytes exceed their descriptor")
			}
			_, _ = fileHashes[chunk.Ordinal].Write(decoded)
			files[chunk.Ordinal].Bytes = append(files[chunk.Ordinal].Bytes, decoded...)
			fileIndexes[chunk.Ordinal]++
			writeHashedLine(streamHash, line)
			frameCount++
		case "provider_response_end":
			var end providerResponseEnd
			if err := generationstop.DecodeCanonicalJSON(line, &end); err != nil {
				return ProviderExecutionResult{}, fmt.Errorf("specialist-render response end is invalid: %w", err)
			}
			if end.Schema != specialistrender.ProviderFrameSchema || end.OperationID != expected.OperationID ||
				end.ReceiptDigest != start.Receipt.ReceiptDigest || end.FileCount != len(files) ||
				end.TotalBytes != start.Receipt.TotalOutputBytes || end.FrameCount != frameCount ||
				end.StreamDigest != hashDigest(streamHash) {
				return ProviderExecutionResult{}, errors.New("specialist-render response end authority differs")
			}
			var aggregate int64
			for index := range files {
				descriptor := files[index].Descriptor
				aggregate += fileBytes[index]
				if fileBytes[index] != descriptor.ByteLength || hashDigest(fileHashes[index]) != descriptor.Digest {
					return ProviderExecutionResult{}, errors.New("specialist-render output differs from its receipt")
				}
			}
			if aggregate != end.TotalBytes {
				return ProviderExecutionResult{}, errors.New("specialist-render aggregate output bytes differ")
			}
			if err := requireStreamEOF(lines); err != nil {
				return ProviderExecutionResult{}, err
			}
			return ProviderExecutionResult{Receipt: start.Receipt, Files: files}, nil
		default:
			return ProviderExecutionResult{}, errors.New("specialist-render response frame kind or order is invalid")
		}
	}
}

func readFrameLine(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > specialistrender.MaximumFrameBytes {
		return nil, errors.New("specialist-render frame exceeds its bound")
	}
	if err != nil {
		return nil, fmt.Errorf("read specialist-render frame: %w", err)
	}
	if len(line) < 3 || line[len(line)-1] != '\n' || bytes.IndexByte(line[:len(line)-1], '\n') >= 0 {
		return nil, errors.New("specialist-render frame delimiter is invalid")
	}
	return append([]byte(nil), line[:len(line)-1]...), nil
}

func requireStreamEOF(reader *bufio.Reader) error {
	value, err := reader.ReadByte()
	if err == nil {
		return fmt.Errorf("specialist-render response contains trailing byte %#x", value)
	}
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("read specialist-render response tail: %w", err)
	}
	return nil
}

func decodeCanonicalBase64(value string, expected int) ([]byte, error) {
	if value == "" || expected <= 0 || expected > specialistrender.RequestChunkBytes {
		return nil, errors.New("base64 payload bound is invalid")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != expected || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("payload is not canonical base64")
	}
	return decoded, nil
}

func canonicalEqual(left, right any) bool {
	leftBytes, leftErr := generationstop.CanonicalJSON(left)
	rightBytes, rightErr := generationstop.CanonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func writeHashedLine(target hash.Hash, line []byte) {
	_, _ = target.Write(line)
	_, _ = target.Write([]byte{'\n'})
}

func hashDigest(target hash.Hash) string {
	return "sha256:" + hex.EncodeToString(target.Sum(nil))
}
