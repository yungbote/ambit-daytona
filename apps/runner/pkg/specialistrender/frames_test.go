// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
)

func TestDecodeRequestStreamAcceptsExactCanonicalFrames(t *testing.T) {
	policy := testPolicy(t)
	request := testRequest(t, policy)
	command := []byte("command")
	source := []byte("source")
	stream := providerRequestBytes(t, request, command, source)
	decoded, err := DecodeRequestStream(bytes.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	if decoded.Request.RequestFingerprint == "" {
		t.Fatal("decoded request lost its fingerprint")
	}
	for label, item := range map[string]struct {
		input Input
		want  []byte
	}{"request": {decoded.Input, command}, "source": {decoded.Source, source}} {
		reader, err := item.input.Open()
		if err != nil {
			t.Fatal(err)
		}
		value, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil || !bytes.Equal(value, item.want) {
			t.Fatalf("%s input read failed: %v", label, err)
		}
	}
}

func TestDecodeRequestStreamRejectsOversizedUnterminatedLine(t *testing.T) {
	_, err := DecodeRequestStream(bytes.NewReader(bytes.Repeat([]byte{'x'}, MaximumFrameBytes+1)))
	if err == nil {
		t.Fatal("oversized unterminated frame was accepted")
	}
}

func TestDecodeRequestStreamRejectsNoncanonicalBase64AndTail(t *testing.T) {
	policy := testPolicy(t)
	request := testRequest(t, policy)
	command := []byte("f")
	source := []byte("s")
	request.RequestBytes, request.SourceBytes = 1, 1
	request.RequestChunkCount, request.SourceChunkCount = 1, 1
	request.RequestDigest, request.SourceDigest = sha256Digest(command), sha256Digest(source)
	request.RequestFingerprint, _ = ComputeRequestFingerprint(request)
	start := providerRequestStart{Schema: ProviderFrameSchema, Kind: "provider_request_start", ChunkBytes: RequestChunkBytes, Request: request}
	bad := []any{
		start,
		providerChunk{Schema: ProviderFrameSchema, Kind: "request_chunk", OperationID: request.OperationID, Index: 0, Bytes: 1, Digest: sha256Digest(command), Base64: "Zh=="},
	}
	var wire bytes.Buffer
	for _, frame := range bad {
		line, _ := generationstop.CanonicalJSON(frame)
		wire.Write(line)
		wire.WriteByte('\n')
	}
	if _, err := DecodeRequestStream(bytes.NewReader(wire.Bytes())); err == nil {
		t.Fatal("noncanonical base64 was accepted")
	}

	valid := providerRequestBytes(t, request, command, source)
	valid = append(valid, []byte(`{"kind":"tail"}`+"\n")...)
	if _, err := DecodeRequestStream(bytes.NewReader(valid)); err == nil {
		t.Fatal("bytes after provider_request_end were accepted")
	}
}

func TestValidateRequestRejectsZeroByteInputs(t *testing.T) {
	request := testRequest(t, testPolicy(t))
	request.RequestBytes = 0
	request.RequestChunkCount = 0
	request.RequestDigest = sha256Digest(nil)
	request.RequestFingerprint, _ = ComputeRequestFingerprint(request)
	if err := ValidateRequest(request); err == nil {
		t.Fatal("zero-byte provider request was accepted")
	}
}

func TestRequestStreamCloseRetriesExactRemoveTarget(t *testing.T) {
	root, err := os.MkdirTemp("", "ambit-request-stream-close-test-")
	if err != nil {
		t.Fatal(err)
	}
	removeFailure := errors.New("injected request stream remove failure")
	calls := 0
	stream := &RequestStream{
		Input: Input{ByteLength: 1}, Source: Input{ByteLength: 1}, root: root,
		removeAll: func(path string) error {
			calls++
			if path != root {
				t.Fatalf("request stream changed cleanup target: %q", path)
			}
			if calls == 1 {
				return removeFailure
			}
			return os.RemoveAll(path)
		},
	}
	if err := stream.Close(); !errors.Is(err, removeFailure) || stream.root != root || stream.Input.ByteLength != 1 {
		t.Fatalf("request stream discarded failed cleanup target: root=%q err=%v", stream.root, err)
	}
	if err := stream.Close(); err != nil || stream.root != "" || stream.Input.ByteLength != 0 {
		t.Fatalf("request stream cleanup retry failed: root=%q err=%v", stream.root, err)
	}
	if err := stream.Close(); err != nil || calls != 2 {
		t.Fatalf("request stream close is not idempotent: calls=%d err=%v", calls, err)
	}
}

func TestRequestDecodeCustodyRetriesCloseThenRemoveFailures(t *testing.T) {
	root, err := os.MkdirTemp("", "ambit-request-decode-cleanup-test-")
	if err != nil {
		t.Fatal(err)
	}
	closeFailure := errors.New("injected request descriptor close failure")
	removeFailure := errors.New("injected request root remove failure")
	closer := &retryCloser{failure: closeFailure}
	removeCalls := 0
	custody := &requestDecodeCustody{
		root: root, requestFile: closer, sourceFile: &retryCloser{},
		removeAll: func(path string) error {
			removeCalls++
			if removeCalls == 1 {
				return removeFailure
			}
			return os.RemoveAll(path)
		},
	}
	if err := custody.cleanup(); !errors.Is(err, closeFailure) || !errors.Is(err, removeFailure) ||
		removeCalls != 1 || custody.root != root {
		t.Fatalf("decode custody did not attempt and retain cleanup authority: calls=%d root=%q err=%v", removeCalls, custody.root, err)
	}
	if err := custody.cleanup(); err != nil || removeCalls != 2 || custody.root != "" {
		t.Fatalf("decode custody cleanup retry failed: calls=%d root=%q err=%v", removeCalls, custody.root, err)
	}
}

func TestDecodeRequestStreamJoinsParseAndCleanupFailure(t *testing.T) {
	cleanupFailure := errors.New("injected rejected-input cleanup failure")
	var root string
	_, err := decodeRequestStream(bytes.NewReader([]byte("invalid\n")), func(path string) error {
		root = path
		return cleanupFailure
	})
	defer func() {
		if root != "" {
			_ = os.RemoveAll(root)
		}
	}()
	if err == nil || !errors.Is(err, cleanupFailure) || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("request decoder discarded parse or cleanup failure: %v", err)
	}
}

type retryCloser struct {
	failure error
	calls   int
}

func (closer *retryCloser) Close() error {
	closer.calls++
	if closer.calls == 1 && closer.failure != nil {
		return closer.failure
	}
	return nil
}

func providerRequestBytes(t *testing.T, request Request, command []byte, source []byte) []byte {
	t.Helper()
	request.RequestBytes, request.SourceBytes = int64(len(command)), int64(len(source))
	request.RequestChunkCount = int((len(command) + RequestChunkBytes - 1) / RequestChunkBytes)
	request.SourceChunkCount = int((len(source) + RequestChunkBytes - 1) / RequestChunkBytes)
	request.RequestDigest, request.SourceDigest = sha256Digest(command), sha256Digest(source)
	request.RequestFingerprint, _ = ComputeRequestFingerprint(request)
	frames := make([]any, 0)
	frames = append(frames, providerRequestStart{
		Schema: ProviderFrameSchema, Kind: "provider_request_start",
		ChunkBytes: RequestChunkBytes, Request: request,
	})
	appendChunks := func(kind string, payload []byte) {
		for index := 0; index*RequestChunkBytes < len(payload); index++ {
			end := (index + 1) * RequestChunkBytes
			if end > len(payload) {
				end = len(payload)
			}
			chunk := payload[index*RequestChunkBytes : end]
			frames = append(frames, providerChunk{
				Schema: ProviderFrameSchema, Kind: kind, OperationID: request.OperationID,
				Index: index, Bytes: len(chunk), Digest: sha256Digest(chunk),
				Base64: base64.StdEncoding.EncodeToString(chunk),
			})
		}
	}
	appendChunks("request_chunk", command)
	appendChunks("source_chunk", source)
	streamDigest := sha256.New()
	var wire bytes.Buffer
	for _, frame := range frames {
		line, err := generationstop.CanonicalJSON(frame)
		if err != nil {
			t.Fatal(err)
		}
		wire.Write(line)
		wire.WriteByte('\n')
		writeHashedLine(streamDigest, line)
	}
	end := providerRequestEnd{
		Schema: ProviderFrameSchema, Kind: "provider_request_end", OperationID: request.OperationID,
		RequestBytes: request.RequestBytes, RequestChunkCount: request.RequestChunkCount,
		RequestDigest: request.RequestDigest, SourceBytes: request.SourceBytes,
		SourceChunkCount: request.SourceChunkCount, SourceDigest: request.SourceDigest,
		FrameCount: len(frames), StreamDigest: hashDigest(streamDigest),
	}
	line, err := generationstop.CanonicalJSON(end)
	if err != nil {
		t.Fatal(err)
	}
	wire.Write(line)
	wire.WriteByte('\n')
	return wire.Bytes()
}
