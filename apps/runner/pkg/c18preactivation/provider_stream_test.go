// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

func TestProviderRequestStreamRoundTripsThroughRunnerDecoder(t *testing.T) {
	request, requestBytes, sourceBytes := testProviderRequest(t)
	var encoded bytes.Buffer
	if err := EncodeProviderRequestStream(&encoded, request, requestBytes, sourceBytes); err != nil {
		t.Fatal(err)
	}

	stream, err := specialistrender.DecodeRequestStream(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if !canonicalEqual(stream.Request, request) {
		t.Fatal("Runner decoded a different request authority")
	}
	assertInputBytes(t, stream.Input, requestBytes)
	assertInputBytes(t, stream.Source, sourceBytes)
}

func TestProviderRequestStreamRejectsPayloadSubstitution(t *testing.T) {
	request, requestBytes, sourceBytes := testProviderRequest(t)
	sourceBytes[0] ^= 0xff
	if err := EncodeProviderRequestStream(io.Discard, request, requestBytes, sourceBytes); err == nil {
		t.Fatal("substituted source bytes were admitted")
	}
}

func TestProviderRequestStreamRejectsShortWriter(t *testing.T) {
	request, requestBytes, sourceBytes := testProviderRequest(t)
	if err := EncodeProviderRequestStream(shortProviderWriter{}, request, requestBytes, sourceBytes); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short provider write was not surfaced: %v", err)
	}
}

type shortProviderWriter struct{}

func (shortProviderWriter) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	return len(value) - 1, nil
}

func TestProviderResponseStreamRoundTripsThroughRunnerEncoder(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := bytes.Repeat([]byte("result-byte-"), 9_000)
	receipt := testProviderReceipt(t, request, payload)
	result := specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0],
			Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			Cleanup: func() error { return nil },
		}},
	}
	var encoded bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &encoded, result); err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeProviderResponseStream(context.Background(), &encoded, request)
	if err != nil {
		t.Fatal(err)
	}
	if !canonicalEqual(decoded.Receipt, receipt) || len(decoded.Files) != 1 ||
		decoded.Files[0].Descriptor != receipt.Files[0] || !bytes.Equal(decoded.Files[0].Bytes, payload) {
		t.Fatal("driver decoded a different provider response")
	}
}

func TestProviderResponseEncoderWithholdsTerminalUntilPayloadCleanup(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := []byte("provider result")
	receipt := testProviderReceipt(t, request, payload)
	cleanupFailure := errors.New("injected response cleanup failure")
	result := specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0],
			Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			Cleanup: func() error { return cleanupFailure },
		}},
	}
	var encoded bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &encoded, result); !errors.Is(err, cleanupFailure) {
		t.Fatalf("response encoder discarded cleanup failure: %v", err)
	}
	if bytes.Contains(encoded.Bytes(), []byte(`"kind":"provider_response_end"`)) {
		t.Fatal("response encoder emitted a committable terminal before cleanup succeeded")
	}
	custody := &hashingResponseCustody{}
	if _, err := ObserveProviderResponseStream(
		context.Background(), io.NopCloser(bytes.NewReader(encoded.Bytes())), request, custody,
	); err == nil || custody.committed || !custody.aborted {
		t.Fatalf("unterminated cleanup failure was admitted: committed=%t aborted=%t err=%v", custody.committed, custody.aborted, err)
	}
}

func TestProviderResponseEncoderJoinsReadAndCleanupFailures(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := []byte("provider result")
	receipt := testProviderReceipt(t, request, payload)
	readFailure := errors.New("injected response read failure")
	cleanupFailure := errors.New("injected response cleanup failure")
	var encoded bytes.Buffer
	err := specialistrender.EncodeResponseStream(context.Background(), &encoded, specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0],
			Open: func(context.Context) (io.ReadCloser, error) {
				return nil, readFailure
			},
			Cleanup: func() error { return cleanupFailure },
		}},
	})
	if !errors.Is(err, readFailure) || !errors.Is(err, cleanupFailure) {
		t.Fatalf("response encoder did not join read and cleanup failures: %v", err)
	}
	if bytes.Contains(encoded.Bytes(), []byte(`"kind":"provider_response_end"`)) {
		t.Fatal("failed response encoder emitted a terminal frame")
	}
}

func TestProviderResponseObserverStreamsTransactionalCustodyAndHashesExactWire(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := bytes.Repeat([]byte("stream-without-retention-"), 8_000)
	receipt := testProviderReceipt(t, request, payload)
	result := specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0],
			Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			Cleanup: func() error { return nil },
		}},
	}
	var encoded bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &encoded, result); err != nil {
		t.Fatal(err)
	}
	custody := &hashingResponseCustody{}
	observation, err := ObserveProviderResponseStream(
		context.Background(), io.NopCloser(bytes.NewReader(encoded.Bytes())), request, custody,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !custody.committed || custody.aborted || len(custody.files) != 1 ||
		observation.WireSHA256 != sha256Digest(encoded.Bytes()) ||
		!canonicalEqual(observation.Receipt, receipt) {
		t.Fatal("streaming response custody did not commit the exact wire")
	}
}

func TestProviderResponseObserverAbortsCustodyBeforeCommitOnInvalidTail(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := []byte("result")
	receipt := testProviderReceipt(t, request, payload)
	result := specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0],
			Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			Cleanup: func() error { return nil },
		}},
	}
	var encoded bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &encoded, result); err != nil {
		t.Fatal(err)
	}
	corrupt := append(append([]byte(nil), encoded.Bytes()...), 'x')
	custody := &hashingResponseCustody{}
	if _, err := ObserveProviderResponseStream(context.Background(), io.NopCloser(bytes.NewReader(corrupt)), request, custody); err == nil {
		t.Fatal("response with an invalid tail was admitted")
	}
	if custody.committed || !custody.aborted {
		t.Fatal("invalid response custody was not aborted")
	}
}

func TestProviderResponseObserverRejectsCRLFFraming(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := []byte("result")
	receipt := testProviderReceipt(t, request, payload)
	result := specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0],
			Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			Cleanup: func() error { return nil },
		}},
	}
	var encoded bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &encoded, result); err != nil {
		t.Fatal(err)
	}
	crlf := bytes.Replace(encoded.Bytes(), []byte{'\n'}, []byte{'\r', '\n'}, 1)
	custody := &hashingResponseCustody{}
	if _, err := ObserveProviderResponseStream(context.Background(), io.NopCloser(bytes.NewReader(crlf)), request, custody); err == nil {
		t.Fatal("CRLF provider framing was admitted")
	}
	if custody.committed || !custody.aborted {
		t.Fatal("CRLF response custody was not aborted")
	}
}

func TestProviderResponseObserverRejectsNoncanonicalChunkPartition(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := []byte("result")
	receipt := testProviderReceipt(t, request, payload)
	var encoded bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &encoded, specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0], Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			}, Cleanup: func() error { return nil },
		}},
	}); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(encoded.Bytes(), []byte{'\n'})
	mutated := false
	for index, line := range lines {
		var kind frameKind
		if json.Unmarshal(line, &kind) != nil || kind.Kind != "file_chunk" {
			continue
		}
		var chunk providerFileChunk
		if err := generationstop.DecodeCanonicalJSON(line, &chunk); err != nil {
			t.Fatal(err)
		}
		chunk.Bytes = 1
		chunk.Base64 = base64Of(payload[:1])
		chunk.Digest = sha256Digest(payload[:1])
		lines[index], _ = generationstop.CanonicalJSON(chunk)
		mutated = true
		break
	}
	if !mutated {
		t.Fatal("test response had no file chunk")
	}
	custody := &hashingResponseCustody{}
	if _, err := ObserveProviderResponseStream(
		context.Background(), io.NopCloser(bytes.NewReader(bytes.Join(lines, []byte{'\n'}))), request, custody,
	); err == nil {
		t.Fatal("one-byte frame amplification was admitted")
	}
	if custody.committed || !custody.aborted {
		t.Fatal("noncanonical chunk partition did not abort custody")
	}
}

func TestProviderResponseStreamRejectsRequestAndByteSubstitution(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := []byte("result")
	receipt := testProviderReceipt(t, request, payload)
	result := specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0],
			Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			Cleanup: func() error { return nil },
		}},
	}
	var encoded bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &encoded, result); err != nil {
		t.Fatal(err)
	}

	other := request
	other.ArtifactRenderJobRef = "ambit://artifact-render-jobs/22222222-2222-4222-8222-222222222222"
	other.RequestFingerprint, _ = specialistrender.ComputeRequestFingerprint(other)
	if _, err := DecodeProviderResponseStream(context.Background(), bytes.NewReader(encoded.Bytes()), other); err == nil {
		t.Fatal("response detached from its expected request was admitted")
	}

	corrupt := bytes.Replace(encoded.Bytes(), []byte(base64Of(payload)), []byte(base64Of([]byte("RESULT"))), 1)
	if bytes.Equal(corrupt, encoded.Bytes()) {
		t.Fatal("test did not locate encoded payload")
	}
	if _, err := DecodeProviderResponseStream(context.Background(), bytes.NewReader(corrupt), request); err == nil {
		t.Fatal("substituted response bytes were admitted")
	}
}

func TestProviderResponseStreamHonorsCancellation(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := []byte("result")
	receipt := testProviderReceipt(t, request, payload)
	result := specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0],
			Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			Cleanup: func() error { return nil },
		}},
	}
	var encoded bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &encoded, result); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DecodeProviderResponseStream(ctx, &encoded, request); err == nil {
		t.Fatal("cancelled response decode completed")
	}
}

func TestProviderResponseObserverAdmitsExactReceiptOnlySettlements(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	for _, outcome := range []string{"cancelled", "timed_out"} {
		t.Run(outcome, func(t *testing.T) {
			receipt := receiptOnlyProviderReceipt(t, request, outcome)
			var encoded bytes.Buffer
			if err := specialistrender.EncodeResponseStream(
				context.Background(), &encoded, specialistrender.ExecutionResult{
					Receipt: receipt, Files: []specialistrender.Payload{},
				},
			); err != nil {
				t.Fatal(err)
			}
			observation, err := ObserveProviderResponseStream(
				context.Background(), io.NopCloser(bytes.NewReader(encoded.Bytes())),
				request, DiscardProviderResponseCustody(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if observation.Receipt.Outcome != outcome || len(observation.Receipt.Files) != 0 ||
				observation.WireSHA256 != sha256Digest(encoded.Bytes()) {
				t.Fatal("receipt-only transport changed settlement authority")
			}
		})
	}
}

func TestProviderResponseObserverCancelsBlockedFirstRead(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	reader := newBlockingReadCloser(nil)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := ObserveProviderResponseStream(ctx, reader, request, DiscardProviderResponseCustody())
		result <- err
	}()
	awaitSignal(t, reader.started)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked first read returned the wrong error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked first read did not cancel")
	}
}

func TestProviderResponseObserverUsesActiveBoundedCleanupAfterCancellation(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	reader := newBlockingReadCloser(nil)
	ctx, cancel := context.WithCancel(context.Background())
	custody := &activeCleanupCustody{}
	completed := make(chan error, 1)
	go func() {
		_, err := ObserveProviderResponseStream(ctx, reader, request, custody)
		completed <- err
	}()
	awaitSignal(t, reader.started)
	cancel()
	select {
	case err := <-completed:
		if !errors.Is(err, context.Canceled) || !custody.aborted || custody.cancelledContext {
			t.Fatalf("response cleanup inherited cancelled operation context: aborted=%t cancelled=%t err=%v", custody.aborted, custody.cancelledContext, err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled response cleanup leaked")
	}
}

func TestProviderResponseObserverCancelsBlockedTailRead(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := []byte("result")
	receipt := testProviderReceipt(t, request, payload)
	var encoded bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &encoded, specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0], Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			}, Cleanup: func() error { return nil },
		}},
	}); err != nil {
		t.Fatal(err)
	}
	reader := newBlockingReadCloser(encoded.Bytes())
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := ObserveProviderResponseStream(ctx, reader, request, DiscardProviderResponseCustody())
		result <- err
	}()
	awaitSignal(t, reader.started)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked tail read returned the wrong error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked tail read did not cancel")
	}
}

func TestProviderResponseObserverCancelsCustodyWriter(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := []byte("result")
	receipt := testProviderReceipt(t, request, payload)
	var encoded bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &encoded, specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0], Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			}, Cleanup: func() error { return nil },
		}},
	}); err != nil {
		t.Fatal(err)
	}
	custody := &blockingWriterCustody{started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := ObserveProviderResponseStream(
			ctx, io.NopCloser(bytes.NewReader(encoded.Bytes())), request, custody,
		)
		result <- err
	}()
	awaitSignal(t, custody.started)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || !custody.aborted {
			t.Fatalf("blocked custody writer was not cancelled and aborted: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked custody writer did not cancel")
	}
}

func testProviderRequest(t *testing.T) (specialistrender.Request, []byte, []byte) {
	t.Helper()
	requestBytes := bytes.Repeat([]byte("request-byte-"), 5_000)
	sourceBytes := bytes.Repeat([]byte("source-byte-"), 6_000)
	request, admittedRequest, admittedSource, err := ProviderRequest(ProviderExecutionInput{
		Workspace: generationstop.Source{
			ProviderResourceID: "sandbox-c18", ExpectedProfile: "c18-full-image",
			ExpectedRuntimeKind: "full_image_runtime_pack",
		},
		OperationID:          "11111111-1111-4111-8111-111111111111",
		ArtifactRenderJobRef: "ambit://artifact-render-jobs/11111111-1111-4111-8111-111111111111",
		Composition:          testPin("ambit://runtime-compositions/c18@2", "1"),
		Owner: generationstop.ProviderOwner{
			TenantID: "11111111-1111-4111-8111-111111111111", UserID: "22222222-2222-4222-8222-222222222222",
			WorkspaceID: "33333333-3333-4333-8333-333333333333", RunID: "44444444-4444-4444-8444-444444444444",
			GrantID: "55555555-5555-4555-8555-555555555555",
		},
		Fence: generationstop.Fence{WorkspaceExecutionManifestRef: "workspace-execution-manifest:sha256:" + strings.Repeat("6", 64)},
		ExpectedParentGeneration: generationstop.ExpectedGeneration{
			ContainerID: strings.Repeat("7", 64), ContainerCreatedAt: "2026-08-24T00:00:00.000Z",
			ExecutionStartedAt: "2026-08-24T00:00:00.000Z", RestartCount: 0,
		},
		Image: specialistrender.ImagePin{
			Ref:          "registry.test/ambit/data-research@sha256:" + strings.Repeat("8", 64),
			ConfigDigest: "sha256:" + strings.Repeat("9", 64), PackID: "data-research",
			PackRef: "ambit.runtime-pack/data-research@1",
		},
		Interface:      testPin(specialistrender.InterfaceRef, "a"),
		Executor:       testPin("ambit://specialist-render-executors/data-research@1", "b"),
		Executable:     "/opt/ambit/runtime-pack/data-research/bin/ambit-specialist-render",
		ProviderPolicy: testPin("ambit.runtime-provider/specialist-render-data-research@1", "c"),
		RequestBytes:   requestBytes,
		SourceBytes:    sourceBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return request, admittedRequest, admittedSource
}

func testProviderReceipt(t *testing.T, request specialistrender.Request, payload []byte) specialistrender.Receipt {
	t.Helper()
	nonce := strings.Repeat("d", 32)
	receipt := specialistrender.Receipt{
		Schema: specialistrender.ReceiptSchema, Outcome: "succeeded", Request: request,
		Nonce: nonce,
		Launch: specialistrender.LaunchObservation{
			ObservedAt: "2026-08-24T00:00:00.000Z", ContainerID: strings.Repeat("e", 64),
			ContainerName: "ambit-specialist-render-" + strings.ReplaceAll(request.OperationID, "-", ""),
			ImageID:       request.Image.ConfigDigest,
			Command: []string{
				"/bin/sh", "-c",
				`stty raw -echo -onlcr && exec "$1" --framed-jsonl --nonce "$2"`,
				specialistrender.RoleRef, request.Executable, nonce,
			},
			ProcessIdentity: specialistrender.ProcessIdentity{PID: 1, StartTicks: "100"}, HostPID: 123,
			ExecutablePath: "/usr/local/bin/python3.14", ExecutableDigest: "sha256:" + strings.Repeat("f", 64),
			RoleRef: specialistrender.RoleRef, User: "1000:1000", EnvironmentDigest: "sha256:" + strings.Repeat("0", 64),
			MountNamespace: "mnt:[2]", ProcessNamespace: "pid:[2]", ParentMountNamespace: "mnt:[1]",
			ParentProcessNamespace: "pid:[1]", ProcessCount: 1, NetworkMode: "none", ReadonlyRootfs: true,
			CapDrop: []string{"ALL"}, NoNewPrivileges: true, SeccompKernelMode: 2,
			EffectiveCapabilities: "0000000000000000", SeccompMode: "custom", SeccompDigest: "sha256:" + strings.Repeat("1", 64),
			Tmpfs: map[string]string{
				"/tmp":       "rw,noexec,nosuid,nodev,size=1073741824,mode=1777",
				"/workspace": "rw,noexec,nosuid,nodev,size=1073741824,mode=0700,uid=1000,gid=1000",
			},
			MountCount: 0, PIDsLimit: 512, MemoryBytes: 4 * 1024 * 1024 * 1024,
			NanoCPUs: 4_000_000_000, ShmSize: 64 * 1024 * 1024, Runtime: "runc",
			RuntimeStatusDigest: "sha256:" + strings.Repeat("2", 64), ParentGeneration: request.ExpectedParentGeneration,
		},
		ReadyDigest: "sha256:" + strings.Repeat("3", 64), TerminalDigest: "sha256:" + strings.Repeat("4", 64),
		TerminalKind: "response_end", TerminalOutcome: "succeeded", HelperExitCode: 0,
		Files: []specialistrender.OutputFile{{
			Ordinal: 0, Role: "result", Path: "outputs/render/result.json",
			MediaType:  "application/vnd.ambit.c18-specialist-render-command-result+json",
			ByteLength: int64(len(payload)), Digest: sha256Digest(payload),
		}},
		TotalOutputBytes: int64(len(payload)), StartedAt: "2026-08-24T00:00:00.000Z",
		Quiescence: specialistrender.QuiescenceReceipt{
			Schema: specialistrender.QuiescenceSchema, ContainerID: strings.Repeat("e", 64),
			ContainerAbsent: true, ObservedAt: "2026-08-24T00:00:01.000Z",
		},
		CompletedAt: "2026-08-24T00:00:01.000Z",
	}
	var err error
	receipt.ReceiptDigest, err = specialistrender.ComputeReceiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := specialistrender.ValidateReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func assertInputBytes(t *testing.T, input specialistrender.Input, expected []byte) {
	t.Helper()
	reader, err := input.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	value, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, expected) {
		t.Fatal("decoded provider input bytes differ")
	}
}

func testPin(ref, digit string) specialistrender.Pin {
	return specialistrender.Pin{Ref: ref, Digest: "sha256:" + strings.Repeat(digit, 64)}
}

func base64Of(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

type hashingResponseCustody struct {
	files       []*hashingResponseFile
	admitted    bool
	committed   bool
	aborted     bool
	observation ProviderResponseObservation
}

func (custody *hashingResponseCustody) AdmitReceipt(
	ctx context.Context,
	_ specialistrender.Receipt,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if custody.admitted || custody.committed || custody.aborted {
		return errors.New("hashing custody receipt state is invalid")
	}
	custody.admitted = true
	return nil
}

type hashingResponseFile struct {
	descriptor specialistrender.OutputFile
	hash       hash.Hash
	bytes      int64
}

func (custody *hashingResponseCustody) OpenFile(
	_ context.Context,
	descriptor specialistrender.OutputFile,
) (ProviderResponseFileWriter, error) {
	if !custody.admitted || custody.committed || custody.aborted || descriptor.Ordinal != len(custody.files) {
		return nil, errors.New("hashing custody descriptor order is invalid")
	}
	file := &hashingResponseFile{descriptor: descriptor, hash: sha256.New()}
	custody.files = append(custody.files, file)
	return file, nil
}

func (custody *hashingResponseCustody) Commit(
	_ context.Context,
	observation ProviderResponseObservation,
) error {
	if !custody.admitted || custody.committed || custody.aborted {
		return errors.New("hashing custody terminal state is invalid")
	}
	for _, file := range custody.files {
		if file.bytes != file.descriptor.ByteLength ||
			"sha256:"+hex.EncodeToString(file.hash.Sum(nil)) != file.descriptor.Digest {
			return errors.New("hashing custody bytes differ from descriptor")
		}
	}
	custody.committed = true
	custody.observation = observation
	return nil
}

func (custody *hashingResponseCustody) Abort(context.Context) error {
	custody.aborted = true
	return nil
}

func (file *hashingResponseFile) WriteContext(ctx context.Context, value []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	written, err := file.hash.Write(value)
	file.bytes += int64(written)
	return written, err
}

type blockingReadCloser struct {
	reader  *bytes.Reader
	started chan struct{}
	closed  chan struct{}
	start   sync.Once
	close   sync.Once
}

func newBlockingReadCloser(value []byte) *blockingReadCloser {
	return &blockingReadCloser{
		reader: bytes.NewReader(value), started: make(chan struct{}), closed: make(chan struct{}),
	}
}

func (reader *blockingReadCloser) Read(target []byte) (int, error) {
	if reader.reader.Len() > 0 {
		return reader.reader.Read(target)
	}
	reader.start.Do(func() { close(reader.started) })
	<-reader.closed
	return 0, errors.New("blocked reader closed")
}

func (reader *blockingReadCloser) Close() error {
	reader.close.Do(func() { close(reader.closed) })
	return nil
}

type blockingWriterCustody struct {
	started chan struct{}
	start   sync.Once
	aborted bool
}

type activeCleanupCustody struct {
	aborted          bool
	cancelledContext bool
}

func (*activeCleanupCustody) AdmitReceipt(context.Context, specialistrender.Receipt) error {
	return errors.New("active cleanup custody unexpectedly admitted a receipt")
}

func (*activeCleanupCustody) OpenFile(
	context.Context,
	specialistrender.OutputFile,
) (ProviderResponseFileWriter, error) {
	return nil, errors.New("active cleanup custody unexpectedly opened a file")
}

func (*activeCleanupCustody) Commit(context.Context, ProviderResponseObservation) error {
	return errors.New("active cleanup custody unexpectedly committed")
}

func (custody *activeCleanupCustody) Abort(ctx context.Context) error {
	custody.aborted = true
	custody.cancelledContext = ctx.Err() != nil
	if custody.cancelledContext {
		return errors.New("cleanup context is cancelled")
	}
	return nil
}

func (custody *blockingWriterCustody) AdmitReceipt(
	ctx context.Context,
	_ specialistrender.Receipt,
) error {
	return ctx.Err()
}

func (custody *blockingWriterCustody) OpenFile(
	context.Context,
	specialistrender.OutputFile,
) (ProviderResponseFileWriter, error) {
	return custody, nil
}

func (custody *blockingWriterCustody) WriteContext(ctx context.Context, _ []byte) (int, error) {
	custody.start.Do(func() { close(custody.started) })
	<-ctx.Done()
	return 0, ctx.Err()
}

func (*blockingWriterCustody) Commit(context.Context, ProviderResponseObservation) error {
	return errors.New("blocking writer custody unexpectedly committed")
}

func (custody *blockingWriterCustody) Abort(context.Context) error {
	custody.aborted = true
	return nil
}

func awaitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("test operation did not reach its blocking boundary")
	}
}
