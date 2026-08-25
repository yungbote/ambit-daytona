// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

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
	"os"
	"path/filepath"
	"sync"

	"github.com/daytonaio/runner/pkg/generationstop"
)

type providerRequestStart struct {
	Schema     string  `json:"schema"`
	Kind       string  `json:"kind"`
	ChunkBytes int     `json:"chunkBytes"`
	Request    Request `json:"request"`
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
	Schema     string  `json:"schema"`
	Kind       string  `json:"kind"`
	ChunkBytes int     `json:"chunkBytes"`
	Receipt    Receipt `json:"receipt"`
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

// RequestStream owns bounded request/source bytes in a private host directory.
// Close is idempotent and removes only that directory.
type RequestStream struct {
	Request   Request
	Input     Input
	Source    Input
	mu        sync.Mutex
	root      string
	removeAll func(string) error
}

func (stream *RequestStream) Close() error {
	if stream == nil {
		return nil
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.root == "" {
		return nil
	}
	removeAll := stream.removeAll
	if removeAll == nil {
		removeAll = os.RemoveAll
	}
	if err := removeAll(stream.root); err != nil {
		return fmt.Errorf("%w: remove private input custody: %w", ErrOutcomeUnknown, err)
	}
	stream.root = ""
	stream.Input = Input{}
	stream.Source = Input{}
	return nil
}

type requestDecodeCustody struct {
	root        string
	requestFile io.Closer
	sourceFile  io.Closer
	removeAll   func(string) error
}

func (custody *requestDecodeCustody) closeFiles() error {
	var cleanupErr error
	if custody.requestFile != nil {
		if err := custody.requestFile.Close(); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		} else {
			custody.requestFile = nil
		}
	}
	if custody.sourceFile != nil {
		if err := custody.sourceFile.Close(); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		} else {
			custody.sourceFile = nil
		}
	}
	return cleanupErr
}

func (custody *requestDecodeCustody) cleanup() error {
	closeErr := custody.closeFiles()
	var removeErr error
	if custody.root != "" {
		removeAll := custody.removeAll
		if removeAll == nil {
			removeAll = os.RemoveAll
		}
		if err := removeAll(custody.root); err != nil {
			removeErr = fmt.Errorf("remove private input custody: %w", err)
		} else {
			custody.root = ""
		}
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close private input custody: %w", closeErr)
	}
	return errors.Join(closeErr, removeErr)
}

// DecodeRequestStream admits one complete canonical provider JSONL request,
// writes payload bytes only to provider-private host custody, and rejects any
// byte after provider_request_end.
func DecodeRequestStream(reader io.Reader) (_ *RequestStream, err error) {
	return decodeRequestStream(reader, os.RemoveAll)
}

func decodeRequestStream(
	reader io.Reader,
	removeAll func(string) error,
) (_ *RequestStream, err error) {
	root, err := os.MkdirTemp("", "ambit-specialist-render-input-")
	if err != nil {
		return nil, fmt.Errorf("%w: create private input root: %v", ErrUnavailable, err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		protectErr := fmt.Errorf("%w: protect private input root: %v", ErrUnavailable, err)
		if cleanupErr := removeAll(root); cleanupErr != nil {
			return nil, errors.Join(protectErr, fmt.Errorf("remove unprotected private input root: %w", cleanupErr))
		}
		return nil, protectErr
	}
	custody := &requestDecodeCustody{root: root, removeAll: removeAll}
	defer func() {
		if err != nil {
			if cleanupErr := custody.cleanup(); cleanupErr != nil {
				err = errors.Join(
					err,
					fmt.Errorf("%w: clean rejected provider input: %w", ErrOutcomeUnknown, cleanupErr),
				)
			}
		}
	}()

	requestPath := filepath.Join(root, "request.bin")
	sourcePath := filepath.Join(root, "source.bin")
	requestFile, err := os.OpenFile(requestPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: create private request object: %v", ErrUnavailable, err)
	}
	custody.requestFile = requestFile
	sourceFile, err := os.OpenFile(sourcePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: create private source object: %v", ErrUnavailable, err)
	}
	custody.sourceFile = sourceFile

	lines := bufio.NewReaderSize(reader, MaximumFrameBytes+1)
	first, err := readFrameLine(lines)
	if err != nil {
		return nil, err
	}
	var start providerRequestStart
	if err := generationstop.DecodeCanonicalJSON(first, &start); err != nil {
		return nil, invalidf("provider_request_start is invalid: %v", err)
	}
	if start.Schema != ProviderFrameSchema || start.Kind != "provider_request_start" || start.ChunkBytes != RequestChunkBytes {
		return nil, invalidf("provider_request_start contract differs")
	}
	if err := ValidateRequest(start.Request); err != nil {
		return nil, err
	}

	streamHash := sha256.New()
	writeHashedLine(streamHash, first)
	frameCount := 1
	requestHash := sha256.New()
	sourceHash := sha256.New()
	requestBytes := int64(0)
	sourceBytes := int64(0)
	requestIndex := 0
	sourceIndex := 0
	inSource := false

	for {
		line, lineErr := readFrameLine(lines)
		if lineErr != nil {
			return nil, lineErr
		}
		var kind frameKind
		if err := json.Unmarshal(line, &kind); err != nil {
			return nil, invalidf("provider frame kind is invalid: %v", err)
		}
		switch kind.Kind {
		case "request_chunk", "source_chunk":
			var chunk providerChunk
			if err := generationstop.DecodeCanonicalJSON(line, &chunk); err != nil {
				return nil, invalidf("provider payload chunk is invalid: %v", err)
			}
			if chunk.Schema != ProviderFrameSchema || chunk.OperationID != start.Request.OperationID {
				return nil, invalidf("provider payload chunk authority differs")
			}
			if chunk.Kind == "request_chunk" && inSource {
				return nil, invalidf("request chunk appears after source data")
			}
			decoded, decodeErr := decodeCanonicalBase64(chunk.Base64, chunk.Bytes)
			if decodeErr != nil || chunk.Bytes <= 0 || chunk.Bytes > RequestChunkBytes ||
				chunk.Digest != sha256Digest(decoded) {
				return nil, invalidf("provider payload chunk bytes or digest are invalid")
			}
			if chunk.Kind == "request_chunk" {
				if chunk.Index != requestIndex || requestIndex >= start.Request.RequestChunkCount {
					return nil, invalidf("request chunk index exceeds its declared sequence")
				}
				requestIndex++
				requestBytes += int64(len(decoded))
				if requestBytes > start.Request.RequestBytes || requestBytes > MaximumRequestBytes {
					return nil, invalidf("request bytes exceed the declared bound")
				}
				if written, err := requestFile.Write(decoded); err != nil {
					return nil, fmt.Errorf("%w: write private request object: %v", ErrUnavailable, err)
				} else if written != len(decoded) {
					return nil, fmt.Errorf("%w: write private request object: %v", ErrUnavailable, io.ErrShortWrite)
				}
				_, _ = requestHash.Write(decoded)
			} else {
				inSource = true
				if chunk.Index != sourceIndex || sourceIndex >= start.Request.SourceChunkCount {
					return nil, invalidf("source chunk index exceeds its declared sequence")
				}
				sourceIndex++
				sourceBytes += int64(len(decoded))
				if sourceBytes > start.Request.SourceBytes || sourceBytes > MaximumSourceBytes {
					return nil, invalidf("source bytes exceed the declared bound")
				}
				if written, err := sourceFile.Write(decoded); err != nil {
					return nil, fmt.Errorf("%w: write private source object: %v", ErrUnavailable, err)
				} else if written != len(decoded) {
					return nil, fmt.Errorf("%w: write private source object: %v", ErrUnavailable, io.ErrShortWrite)
				}
				_, _ = sourceHash.Write(decoded)
			}
			writeHashedLine(streamHash, line)
			frameCount++
		case "provider_request_end":
			var end providerRequestEnd
			if err := generationstop.DecodeCanonicalJSON(line, &end); err != nil {
				return nil, invalidf("provider_request_end is invalid: %v", err)
			}
			if end.Schema != ProviderFrameSchema || end.OperationID != start.Request.OperationID ||
				end.RequestBytes != start.Request.RequestBytes ||
				end.RequestChunkCount != start.Request.RequestChunkCount ||
				end.RequestDigest != start.Request.RequestDigest ||
				end.SourceBytes != start.Request.SourceBytes ||
				end.SourceChunkCount != start.Request.SourceChunkCount ||
				end.SourceDigest != start.Request.SourceDigest ||
				end.FrameCount != frameCount ||
				end.StreamDigest != hashDigest(streamHash) ||
				requestBytes != start.Request.RequestBytes || requestIndex != start.Request.RequestChunkCount ||
				sourceBytes != start.Request.SourceBytes || sourceIndex != start.Request.SourceChunkCount ||
				start.Request.RequestDigest != hashDigest(requestHash) ||
				start.Request.SourceDigest != hashDigest(sourceHash) {
				return nil, invalidf("provider_request_end does not close the exact stream")
			}
			if err := requireStreamEOF(lines); err != nil {
				return nil, err
			}
			if err := requestFile.Sync(); err != nil {
				return nil, fmt.Errorf("%w: sync private request object: %v", ErrUnavailable, err)
			}
			if err := sourceFile.Sync(); err != nil {
				return nil, fmt.Errorf("%w: sync private source object: %v", ErrUnavailable, err)
			}
			if closeErr := custody.closeFiles(); closeErr != nil {
				return nil, fmt.Errorf("%w: close admitted private input custody: %w", ErrOutcomeUnknown, closeErr)
			}
			return &RequestStream{
				Request:   start.Request,
				Input:     fileInput(requestPath, requestBytes, start.Request.RequestDigest),
				Source:    fileInput(sourcePath, sourceBytes, start.Request.SourceDigest),
				root:      root,
				removeAll: removeAll,
			}, nil
		default:
			return nil, invalidf("provider request frame kind or order is invalid")
		}
	}
}

// EncodeResponseStream emits an already-committed receipt and its provider-
// private bytes. The returned stream digest excludes provider_response_end.
func EncodeResponseStream(ctx context.Context, writer io.Writer, result ExecutionResult) (err error) {
	cleaned := false
	defer func() {
		if !cleaned {
			if cleanupErr := CleanupPayloads(result.Files); cleanupErr != nil {
				err = errors.Join(
					err,
					fmt.Errorf("%w: clean provider response custody: %w", ErrOutcomeUnknown, cleanupErr),
				)
			}
		}
	}()
	if result.Receipt.Schema != ReceiptSchema || len(result.Files) != len(result.Receipt.Files) {
		return fmt.Errorf("%w: response receipt and payload custody differ", ErrOutcomeUnknown)
	}
	expectedReceiptDigest, err := ComputeReceiptDigest(result.Receipt)
	if err != nil || expectedReceiptDigest != result.Receipt.ReceiptDigest {
		return fmt.Errorf("%w: response receipt digest is invalid", ErrOutcomeUnknown)
	}
	streamHash := sha256.New()
	frameCount := 0
	write := func(value any) error {
		line, err := generationstop.CanonicalJSON(value)
		if err != nil {
			return err
		}
		if len(line)+1 > MaximumFrameBytes {
			return errors.New("provider response frame exceeds its bound")
		}
		framed := append(line, '\n')
		written, err := writer.Write(framed)
		if err != nil {
			return err
		}
		if written != len(framed) {
			return io.ErrShortWrite
		}
		writeHashedLine(streamHash, line)
		frameCount++
		return nil
	}
	if err := write(providerResponseStart{
		Schema: ProviderFrameSchema, Kind: "provider_response_start",
		ChunkBytes: RequestChunkBytes, Receipt: result.Receipt,
	}); err != nil {
		return err
	}
	for ordinal, payload := range result.Files {
		if payload.File != result.Receipt.Files[ordinal] {
			return fmt.Errorf("%w: response file roster differs from receipt", ErrOutcomeUnknown)
		}
		reader, err := payload.Open(ctx)
		if err != nil {
			return fmt.Errorf("%w: open provider-private output: %w", ErrOutcomeUnknown, err)
		}
		fileHash := sha256.New()
		remaining := payload.File.ByteLength
		index := 0
		for remaining > 0 {
			size := int64(RequestChunkBytes)
			if remaining < size {
				size = remaining
			}
			chunk := make([]byte, int(size))
			if _, err := io.ReadFull(reader, chunk); err != nil {
				return errors.Join(
					fmt.Errorf("%w: read provider-private output: %w", ErrOutcomeUnknown, err),
					closeProviderOutputReader(reader),
				)
			}
			_, _ = fileHash.Write(chunk)
			if err := write(providerFileChunk{
				Schema: ProviderFrameSchema, Kind: "file_chunk",
				OperationID: result.Receipt.Request.OperationID,
				Ordinal:     ordinal, Index: index, Bytes: len(chunk),
				Digest: sha256Digest(chunk), Base64: base64.StdEncoding.EncodeToString(chunk),
			}); err != nil {
				return errors.Join(err, closeProviderOutputReader(reader))
			}
			remaining -= int64(len(chunk))
			index++
		}
		extra := make([]byte, 1)
		count, readErr := reader.Read(extra)
		closeErr := reader.Close()
		if count != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil ||
			hashDigest(fileHash) != payload.File.Digest {
			identityErr := fmt.Errorf("%w: provider-private output differs from receipt", ErrOutcomeUnknown)
			if closeErr != nil {
				identityErr = errors.Join(
					identityErr,
					fmt.Errorf("%w: close provider-private output: %w", ErrOutcomeUnknown, closeErr),
				)
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				identityErr = errors.Join(
					identityErr,
					fmt.Errorf("%w: read provider-private output tail: %w", ErrOutcomeUnknown, readErr),
				)
			}
			return identityErr
		}
	}
	cleanupErr := CleanupPayloads(result.Files)
	cleaned = true
	if cleanupErr != nil {
		return fmt.Errorf("%w: clean provider response custody before terminal: %w", ErrOutcomeUnknown, cleanupErr)
	}
	end := providerResponseEnd{
		Schema: ProviderFrameSchema, Kind: "provider_response_end",
		OperationID:   result.Receipt.Request.OperationID,
		ReceiptDigest: result.Receipt.ReceiptDigest,
		FileCount:     len(result.Receipt.Files), TotalBytes: result.Receipt.TotalOutputBytes,
		FrameCount: frameCount, StreamDigest: hashDigest(streamHash),
	}
	line, err := generationstop.CanonicalJSON(end)
	if err != nil {
		return err
	}
	if len(line)+1 > MaximumFrameBytes {
		return errors.New("provider response end exceeds its bound")
	}
	framed := append(line, '\n')
	written, err := writer.Write(framed)
	if err != nil {
		return err
	}
	if written != len(framed) {
		return io.ErrShortWrite
	}
	return nil
}

func closeProviderOutputReader(reader io.Closer) error {
	if err := reader.Close(); err != nil {
		return fmt.Errorf("%w: close provider-private output: %w", ErrOutcomeUnknown, err)
	}
	return nil
}

func readFrameLine(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, invalidf("provider frame exceeds its bound")
		}
		if errors.Is(err, io.EOF) {
			return nil, invalidf("provider stream closed before its terminal frame")
		}
		return nil, invalidf("read provider stream: %v", err)
	}
	if len(line) == 1 || len(line) > MaximumFrameBytes || bytes.IndexByte(line, '\r') >= 0 {
		return nil, invalidf("provider frame delimiter or size is invalid")
	}
	return line[:len(line)-1], nil
}

func requireStreamEOF(reader *bufio.Reader) error {
	value, err := reader.ReadByte()
	if err == nil {
		_ = value
		return invalidf("provider request contains bytes after its terminal frame")
	}
	if !errors.Is(err, io.EOF) {
		return invalidf("read provider stream tail: %v", err)
	}
	return nil
}

func fileInput(path string, byteLength int64, digest string) Input {
	return Input{
		ByteLength: byteLength,
		Digest:     digest,
		Open: func() (io.ReadCloser, error) {
			return os.Open(path)
		},
	}
}

func decodeCanonicalBase64(value string, expected int) ([]byte, error) {
	if value == "" || expected <= 0 || expected > RequestChunkBytes {
		return nil, errors.New("base64 payload bound is invalid")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != expected || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("payload is not canonical base64")
	}
	return decoded, nil
}

func writeHashedLine(target hash.Hash, line []byte) {
	_, _ = target.Write(line)
	_, _ = target.Write([]byte{'\n'})
}

func hashDigest(target hash.Hash) string {
	return "sha256:" + hex.EncodeToString(target.Sum(nil))
}

func sha256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
