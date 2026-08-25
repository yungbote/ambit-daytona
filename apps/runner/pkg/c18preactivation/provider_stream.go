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

// ProviderResponseObservation is the complete, payload-free provider response
// authority. WireSHA256 covers every exact response byte, including newlines
// and provider_response_end; the receipt's stream digest intentionally covers
// only the preceding frames according to the existing Runner protocol.
type ProviderResponseObservation struct {
	Receipt    specialistrender.Receipt
	WireSHA256 string
}

// ProviderResponseCustody owns transactional staging for streamed provider
// files. OpenFile must return a fresh writer for the exact descriptor. Commit
// is invoked only after every byte, digest, frame, terminal field, and EOF has
// been validated. Abort is invoked on every non-committed path.
type ProviderResponseCustody interface {
	OpenFile(context.Context, specialistrender.OutputFile) (io.Writer, error)
	Commit(context.Context, ProviderResponseObservation) error
	Abort()
}

type discardProviderResponseCustody struct{}

func (discardProviderResponseCustody) OpenFile(context.Context, specialistrender.OutputFile) (io.Writer, error) {
	return io.Discard, nil
}

func (discardProviderResponseCustody) Commit(context.Context, ProviderResponseObservation) error {
	return nil
}

func (discardProviderResponseCustody) Abort() {}

// DiscardProviderResponseCustody returns the explicit zero-retention sink.
func DiscardProviderResponseCustody() ProviderResponseCustody {
	return discardProviderResponseCustody{}
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
	custody := newMemoryProviderResponseCustody()
	observation, err := ObserveProviderResponseStream(ctx, reader, expected, custody)
	if err != nil {
		return ProviderExecutionResult{}, err
	}
	files := make([]ProviderOutput, len(observation.Receipt.Files))
	for index, descriptor := range observation.Receipt.Files {
		files[index] = ProviderOutput{
			Descriptor: descriptor,
			Bytes:      append([]byte(nil), custody.files[index].Bytes()...),
		}
	}
	return ProviderExecutionResult{Receipt: observation.Receipt, Files: files}, nil
}

// ObserveProviderResponseStream validates and streams one exact Runner
// response without accumulating payload bytes in this package.
func ObserveProviderResponseStream(
	ctx context.Context,
	reader io.Reader,
	expected specialistrender.Request,
	custody ProviderResponseCustody,
) (_ ProviderResponseObservation, err error) {
	if err := specialistrender.ValidateRequest(expected); err != nil {
		return ProviderResponseObservation{}, fmt.Errorf("expected specialist-render request is invalid: %w", err)
	}
	if custody == nil {
		custody = DiscardProviderResponseCustody()
	}
	committed := false
	defer func() {
		if !committed {
			custody.Abort()
		}
	}()
	lines := bufio.NewReaderSize(reader, specialistrender.MaximumFrameBytes+1)
	first, err := readFrameLine(lines)
	if err != nil {
		return ProviderResponseObservation{}, err
	}
	var start providerResponseStart
	if err := generationstop.DecodeCanonicalJSON(first, &start); err != nil {
		return ProviderResponseObservation{}, fmt.Errorf("specialist-render response start is invalid: %w", err)
	}
	if start.Schema != specialistrender.ProviderFrameSchema || start.Kind != "provider_response_start" ||
		start.ChunkBytes != specialistrender.RequestChunkBytes {
		return ProviderResponseObservation{}, errors.New("specialist-render response start contract differs")
	}
	if err := specialistrender.ValidateReceipt(start.Receipt); err != nil {
		return ProviderResponseObservation{}, fmt.Errorf("specialist-render receipt is invalid: %w", err)
	}
	if !canonicalEqual(start.Receipt.Request, expected) {
		return ProviderResponseObservation{}, errors.New("specialist-render receipt changed the exact request")
	}
	streamHash := sha256.New()
	writeHashedLine(streamHash, first)
	wireHash := sha256.New()
	writeHashedLine(wireHash, first)
	frameCount := 1
	fileHashes := make([]hash.Hash, len(start.Receipt.Files))
	fileIndexes := make([]int, len(start.Receipt.Files))
	fileBytes := make([]int64, len(start.Receipt.Files))
	fileWriters := make([]io.Writer, len(start.Receipt.Files))
	for index, descriptor := range start.Receipt.Files {
		fileHashes[index] = sha256.New()
		writer, err := custody.OpenFile(ctx, descriptor)
		if err != nil {
			return ProviderResponseObservation{}, fmt.Errorf("open specialist-render response custody: %w", err)
		}
		if writer == nil {
			return ProviderResponseObservation{}, errors.New("specialist-render response custody returned no writer")
		}
		fileWriters[index] = writer
	}
	currentOrdinal := 0
	for {
		if err := ctx.Err(); err != nil {
			return ProviderResponseObservation{}, err
		}
		line, err := readFrameLine(lines)
		if err != nil {
			return ProviderResponseObservation{}, err
		}
		var kind frameKind
		if err := json.Unmarshal(line, &kind); err != nil {
			return ProviderResponseObservation{}, fmt.Errorf("specialist-render response frame kind is invalid: %w", err)
		}
		switch kind.Kind {
		case "file_chunk":
			var chunk providerFileChunk
			if err := generationstop.DecodeCanonicalJSON(line, &chunk); err != nil {
				return ProviderResponseObservation{}, fmt.Errorf("specialist-render file chunk is invalid: %w", err)
			}
			if chunk.Schema != specialistrender.ProviderFrameSchema || chunk.OperationID != expected.OperationID ||
				chunk.Ordinal < 0 || chunk.Ordinal >= len(start.Receipt.Files) || chunk.Ordinal < currentOrdinal ||
				chunk.Index != fileIndexes[chunk.Ordinal] {
				return ProviderResponseObservation{}, errors.New("specialist-render file chunk authority or order differs")
			}
			currentOrdinal = chunk.Ordinal
			decoded, err := decodeCanonicalBase64(chunk.Base64, chunk.Bytes)
			if err != nil || chunk.Bytes > specialistrender.RequestChunkBytes || chunk.Digest != sha256Digest(decoded) {
				return ProviderResponseObservation{}, errors.New("specialist-render file chunk bytes or digest are invalid")
			}
			fileBytes[chunk.Ordinal] += int64(len(decoded))
			if fileBytes[chunk.Ordinal] > start.Receipt.Files[chunk.Ordinal].ByteLength {
				return ProviderResponseObservation{}, errors.New("specialist-render file bytes exceed their descriptor")
			}
			_, _ = fileHashes[chunk.Ordinal].Write(decoded)
			written, writeErr := fileWriters[chunk.Ordinal].Write(decoded)
			if writeErr != nil {
				return ProviderResponseObservation{}, fmt.Errorf("write specialist-render response custody: %w", writeErr)
			}
			if written != len(decoded) {
				return ProviderResponseObservation{}, io.ErrShortWrite
			}
			fileIndexes[chunk.Ordinal]++
			writeHashedLine(streamHash, line)
			writeHashedLine(wireHash, line)
			frameCount++
		case "provider_response_end":
			var end providerResponseEnd
			if err := generationstop.DecodeCanonicalJSON(line, &end); err != nil {
				return ProviderResponseObservation{}, fmt.Errorf("specialist-render response end is invalid: %w", err)
			}
			if end.Schema != specialistrender.ProviderFrameSchema || end.OperationID != expected.OperationID ||
				end.ReceiptDigest != start.Receipt.ReceiptDigest || end.FileCount != len(start.Receipt.Files) ||
				end.TotalBytes != start.Receipt.TotalOutputBytes || end.FrameCount != frameCount ||
				end.StreamDigest != hashDigest(streamHash) {
				return ProviderResponseObservation{}, errors.New("specialist-render response end authority differs")
			}
			var aggregate int64
			for index, descriptor := range start.Receipt.Files {
				aggregate += fileBytes[index]
				if fileBytes[index] != descriptor.ByteLength || hashDigest(fileHashes[index]) != descriptor.Digest {
					return ProviderResponseObservation{}, errors.New("specialist-render output differs from its receipt")
				}
			}
			if aggregate != end.TotalBytes {
				return ProviderResponseObservation{}, errors.New("specialist-render aggregate output bytes differ")
			}
			writeHashedLine(wireHash, line)
			if err := requireStreamEOF(lines); err != nil {
				return ProviderResponseObservation{}, err
			}
			observation := ProviderResponseObservation{
				Receipt: start.Receipt, WireSHA256: hashDigest(wireHash),
			}
			if err := custody.Commit(ctx, observation); err != nil {
				return ProviderResponseObservation{}, fmt.Errorf("commit specialist-render response custody: %w", err)
			}
			committed = true
			return observation, nil
		default:
			return ProviderResponseObservation{}, errors.New("specialist-render response frame kind or order is invalid")
		}
	}
}

type memoryProviderResponseCustody struct {
	files     []*bytes.Buffer
	committed bool
}

func newMemoryProviderResponseCustody() *memoryProviderResponseCustody {
	return &memoryProviderResponseCustody{}
}

func (custody *memoryProviderResponseCustody) OpenFile(
	_ context.Context,
	descriptor specialistrender.OutputFile,
) (io.Writer, error) {
	if custody.committed || descriptor.Ordinal != len(custody.files) {
		return nil, errors.New("memory provider custody descriptor order is invalid")
	}
	file := bytes.NewBuffer(make([]byte, 0, descriptor.ByteLength))
	custody.files = append(custody.files, file)
	return file, nil
}

func (custody *memoryProviderResponseCustody) Commit(context.Context, ProviderResponseObservation) error {
	if custody.committed {
		return errors.New("memory provider custody was already committed")
	}
	custody.committed = true
	return nil
}

func (custody *memoryProviderResponseCustody) Abort() {
	if !custody.committed {
		custody.files = nil
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
	if len(line) < 3 || line[len(line)-1] != '\n' ||
		bytes.IndexByte(line[:len(line)-1], '\n') >= 0 || bytes.IndexByte(line[:len(line)-1], '\r') >= 0 {
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
