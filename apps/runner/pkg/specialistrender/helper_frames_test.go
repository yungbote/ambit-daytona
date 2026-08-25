// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
)

func TestHelperCollectorAcceptsFailureGoldenWithDistinctSemanticAndByteDigests(t *testing.T) {
	golden := loadRenderGolden(t)
	policy := testPolicy(t)
	policy.Image.PackID = "office-authoring"
	policy.Image.PackRef = "ambit.runtime-pack/office-authoring@1"
	policy.Executor = Pin{
		Ref:    "ambit://specialist-render-executors/office-authoring@1",
		Digest: "sha256:" + strings.Repeat("0", 63) + "5",
	}
	policy.Executable = "/opt/ambit/runtime-pack/office-authoring/bin/ambit-specialist-render"
	policy.Authority.Ref = "ambit.runtime-provider/specialist-render-office-authoring@1"
	policy.Authority.Digest, _ = ComputePolicyDigest(policy)
	request := testRequest(t, policy)
	request.ArtifactRenderJobRef = "ambit://artifact-render-jobs/018f6f56-7b2c-7d20-8a1f-abcdef123456"
	request.RequestBytes = int64(len(golden.Request))
	request.RequestChunkCount = 1
	request.RequestDigest = golden.RequestDigest
	request.SourceBytes = 25
	request.SourceChunkCount = 1
	request.SourceDigest = "sha256:df68d1d60e0bb3549243031d40bd261c14c7cfc6a894e4330bc06cd83b8175f8"
	request.RequestFingerprint, _ = ComputeRequestFingerprint(request)
	nonce := strings.Repeat("b", 32)
	process := ProcessIdentity{PID: 1, StartTicks: "123"}
	executionRequest := ProviderExecutionRequest{
		OperationID: request.OperationID, Nonce: nonce, Authority: request, Policy: policy,
		Request: Input{ByteLength: int64(len(golden.Request)), Digest: golden.RequestDigest, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(golden.Request)), nil
		}},
		Source: Input{ByteLength: 25, Digest: request.SourceDigest, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(make([]byte, 25))), nil
		}},
	}
	collector, err := newHelperCollector(nonce, policy, executionRequest, process)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.cleanup()

	var semanticResult helperSemanticResult
	if err := json.Unmarshal([]byte(golden.Failure), &semanticResult); err != nil {
		t.Fatal(err)
	}
	files := []struct {
		role      string
		path      string
		mediaType string
		body      []byte
		digest    string
	}{
		{role: "result", path: "outputs/render/result.json", mediaType: "application/vnd.ambit.c18-specialist-render-command-result+json", body: []byte(golden.Failure), digest: golden.FailureDigest},
		{role: "evidence", path: golden.FailureEvidence.Descriptor.Path, mediaType: golden.FailureEvidence.Descriptor.MediaType, body: []byte(golden.FailureEvidence.Body), digest: golden.FailureEvidence.Descriptor.Digest},
	}
	total := int64(len(files[0].body) + len(files[1].body))
	start := helperResponseStart{
		ExecutorRevision: pinToHelper(policy.Executor), ExitCode: 1, FileCount: 2,
		Kind: "response_start", Nonce: nonce, Outcome: "failed",
		Request:      helperRequestIdentity{Digest: semanticResult.Request.Digest, JobRef: semanticResult.Request.JobRef, JobRoot: semanticResult.Request.JobRoot},
		ResultDigest: semanticResult.Digest, Schema: FrameSchema, TotalBytes: total,
	}
	ready := helperReady{
		CancellationExitCode: 130, ChunkBytes: RequestChunkBytes, Executable: policy.Executable,
		ExecutorRevision: pinToHelper(policy.Executor), Interface: pinToHelper(policy.Interface),
		Kind: "ready", Nonce: nonce, ProcessIdentity: helperProcessIdentity(process), Schema: FrameSchema,
	}
	frames := []any{start}
	for index, file := range files {
		ordinal := index + 1
		frames = append(frames,
			helperFileStart{
				ByteLength: int64(len(file.body)), ChunkBytes: RequestChunkBytes, ChunkCount: 1,
				Kind: "file_start", MediaType: file.mediaType, Nonce: nonce, Ordinal: ordinal,
				Path: file.path, Role: file.role, Schema: FrameSchema, Digest: file.digest,
			},
			helperFileChunk{
				Base64: base64.StdEncoding.EncodeToString(file.body), Bytes: len(file.body),
				ChunkIndex: 0, Kind: "file_chunk", Nonce: nonce, Ordinal: ordinal,
				Schema: FrameSchema, Digest: sha256Digest(file.body),
			},
		)
	}
	streamHash := sha256.New()
	var wire bytes.Buffer
	writeCanonicalLine(t, &wire, ready)
	for _, frame := range frames {
		line, err := generationstop.CanonicalJSON(frame)
		if err != nil {
			t.Fatal(err)
		}
		wire.Write(line)
		wire.WriteByte('\n')
		writeHashedLine(streamHash, line)
	}
	end := helperResponseEnd{
		ExecutorRevision: start.ExecutorRevision, ExitCode: 1, FileCount: 2,
		FrameCount: len(frames), Kind: "response_end", Nonce: nonce, Outcome: "failed",
		PrivateRootCleanup: "completed", ProcessIdentity: helperProcessIdentity(process),
		Request: start.Request, ResultDigest: start.ResultDigest, Schema: FrameSchema,
		StreamDigest: hashDigest(streamHash), TerminalSelection: "helper-selected", TotalBytes: total,
	}
	writeCanonicalLine(t, &wire, end)

	reader := bufio.NewReaderSize(bytes.NewReader(wire.Bytes()), MaximumFrameBytes+1)
	if err := collector.readReady(reader); err != nil {
		t.Fatal(err)
	}
	result, err := collector.collect(reader)
	if err != nil {
		t.Fatal(err)
	}
	if result.TerminalOutcome != "failed" || len(result.Files) != 2 ||
		result.Files[0].File.Digest != golden.FailureDigest ||
		result.Files[1].File.Digest != golden.FailureEvidence.Descriptor.Digest {
		t.Fatalf("golden helper result differs: %#v", result)
	}
}

func TestHelperCancellationDiscardsCompletedAndPartialResponseFiles(t *testing.T) {
	root := t.TempDir()
	privateRoot := filepath.Join(root, "output")
	if err := os.Mkdir(privateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(t)
	nonce := strings.Repeat("c", 32)
	process := helperProcessIdentity{PID: 1, StartTicks: "123"}
	collector := &helperCollector{
		nonce: nonce, policy: policy,
		request: helperRequestIdentity{Digest: "sha256:" + strings.Repeat("1", 64), JobRef: "ambit://artifact-render-jobs/11111111-1111-4111-8111-111111111111", JobRoot: "/workspace/.ambit/render-jobs/11111111-1111-4111-8111-111111111111"},
		process: process, readyDigest: "sha256:" + strings.Repeat("2", 64),
		root: privateRoot, paths: make(map[string]struct{}), streamHash: sha256.New(),
	}
	start := helperResponseStart{
		ExecutorRevision: pinToHelper(policy.Executor), ExitCode: 0, FileCount: 2,
		Kind: "response_start", Nonce: nonce, Outcome: "succeeded", Request: collector.request,
		ResultDigest: "sha256:" + strings.Repeat("3", 64), Schema: FrameSchema, TotalBytes: 7,
	}
	startLine, _ := generationstop.CanonicalJSON(start)
	if err := collector.acceptStart(startLine); err != nil {
		t.Fatal(err)
	}
	payload := []byte("result")
	fileStart := helperFileStart{
		ByteLength: int64(len(payload)), ChunkBytes: RequestChunkBytes, ChunkCount: 1,
		Kind: "file_start", MediaType: "application/json", Nonce: nonce, Ordinal: 1,
		Path: "outputs/result.json", Role: "result", Schema: FrameSchema, Digest: sha256Digest(payload),
	}
	line, _ := generationstop.CanonicalJSON(fileStart)
	if err := collector.acceptFileStart(line); err != nil {
		t.Fatal(err)
	}
	chunk := helperFileChunk{
		Base64: base64.StdEncoding.EncodeToString(payload), Bytes: len(payload), ChunkIndex: 0,
		Kind: "file_chunk", Nonce: nonce, Ordinal: 1, Schema: FrameSchema, Digest: sha256Digest(payload),
	}
	line, _ = generationstop.CanonicalJSON(chunk)
	if err := collector.acceptFileChunk(line); err != nil {
		t.Fatal(err)
	}
	cancelled := helperCancelled{
		ExecutorRevision: pinToHelper(policy.Executor), ExitCode: 130, Kind: "cancelled",
		Nonce: nonce, Outcome: "cancelled", PrivateRootCleanup: "completed",
		ProcessIdentity: process, Schema: FrameSchema, TerminalSelection: "helper-selected",
	}
	line, _ = generationstop.CanonicalJSON(cancelled)
	result, err := collector.acceptCancelled(line)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 0 || collector.root != "" {
		t.Fatalf("cancelled response retained files or root: %#v root=%q", result.Files, collector.root)
	}
	if _, err := os.Stat(privateRoot); !os.IsNotExist(err) {
		t.Fatalf("cancelled provider-private root remains: %v", err)
	}
}

func TestHelperTimeoutDiscardsCompletedResultCustody(t *testing.T) {
	result, privateRoot, err := collectGoldenFailureAtExit(t, 124, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.TerminalOutcome != "timed_out" || len(result.Files) != 0 {
		t.Fatalf("timed-out helper retained result custody: %#v", result)
	}
	if _, err := os.Stat(privateRoot); !os.IsNotExist(err) {
		t.Fatalf("timed-out helper root remains: %v", err)
	}
}

func TestHelperTimeoutSurfacesCustodyCleanupFailure(t *testing.T) {
	cleanupFailure := errors.New("injected helper cleanup failure")
	_, privateRoot, err := collectGoldenFailureAtExit(
		t,
		124,
		func(string) error { return cleanupFailure },
		nil,
	)
	defer os.RemoveAll(privateRoot)
	if !errors.Is(err, cleanupFailure) {
		t.Fatalf("helper cleanup failure was not surfaced: %v", err)
	}
}

func TestHelperTimeoutDiscardsSemanticallyInvalidStagedResult(t *testing.T) {
	result, privateRoot, err := collectGoldenFailureAtExit(t, 124, nil, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if result.TerminalOutcome != "timed_out" || len(result.Files) != 0 {
		t.Fatalf("timed-out invalid result was not reduced to receipt-only settlement: %#v", result)
	}
	if _, err := os.Stat(privateRoot); !os.IsNotExist(err) {
		t.Fatalf("timed-out invalid result root remains: %v", err)
	}
}

func collectGoldenFailureAtExit(
	t *testing.T,
	exitCode int,
	removeAll func(string) error,
	resultBody []byte,
) (helperResult, string, error) {
	t.Helper()
	golden := loadRenderGolden(t)
	policy := testPolicy(t)
	policy.Image.PackID = "office-authoring"
	policy.Image.PackRef = "ambit.runtime-pack/office-authoring@1"
	policy.Executor = Pin{
		Ref:    "ambit://specialist-render-executors/office-authoring@1",
		Digest: "sha256:" + strings.Repeat("0", 63) + "5",
	}
	policy.Executable = "/opt/ambit/runtime-pack/office-authoring/bin/ambit-specialist-render"
	policy.Authority.Ref = "ambit.runtime-provider/specialist-render-office-authoring@1"
	policy.Authority.Digest, _ = ComputePolicyDigest(policy)
	request := testRequest(t, policy)
	request.ArtifactRenderJobRef = "ambit://artifact-render-jobs/018f6f56-7b2c-7d20-8a1f-abcdef123456"
	request.RequestBytes = int64(len(golden.Request))
	request.RequestChunkCount = 1
	request.RequestDigest = golden.RequestDigest
	request.SourceBytes = 25
	request.SourceChunkCount = 1
	request.SourceDigest = "sha256:df68d1d60e0bb3549243031d40bd261c14c7cfc6a894e4330bc06cd83b8175f8"
	request.RequestFingerprint, _ = ComputeRequestFingerprint(request)
	nonce := strings.Repeat("d", 32)
	process := ProcessIdentity{PID: 1, StartTicks: "123"}
	executionRequest := ProviderExecutionRequest{
		OperationID: request.OperationID, Nonce: nonce, Authority: request, Policy: policy,
		Request: Input{ByteLength: int64(len(golden.Request)), Digest: golden.RequestDigest, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(golden.Request)), nil
		}},
		Source: Input{ByteLength: 25, Digest: request.SourceDigest, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(make([]byte, 25))), nil
		}},
	}
	collector, err := newHelperCollector(nonce, policy, executionRequest, process)
	if err != nil {
		t.Fatal(err)
	}
	privateRoot := collector.root
	if removeAll != nil {
		collector.removeAll = removeAll
	}
	var semanticResult helperSemanticResult
	if err := json.Unmarshal([]byte(golden.Failure), &semanticResult); err != nil {
		t.Fatal(err)
	}
	resultDigest := semanticResult.Digest
	if resultBody == nil {
		resultBody = []byte(golden.Failure)
	} else {
		resultDigest = sha256Digest(resultBody)
	}
	files := []struct {
		role, path, mediaType string
		body                  []byte
		digest                string
	}{
		{role: "result", path: "outputs/render/result.json", mediaType: "application/vnd.ambit.c18-specialist-render-command-result+json", body: resultBody, digest: sha256Digest(resultBody)},
		{role: "evidence", path: golden.FailureEvidence.Descriptor.Path, mediaType: golden.FailureEvidence.Descriptor.MediaType, body: []byte(golden.FailureEvidence.Body), digest: golden.FailureEvidence.Descriptor.Digest},
	}
	total := int64(len(files[0].body) + len(files[1].body))
	start := helperResponseStart{
		ExecutorRevision: pinToHelper(policy.Executor), ExitCode: exitCode, FileCount: len(files),
		Kind: "response_start", Nonce: nonce, Outcome: "failed",
		Request:      helperRequestIdentity{Digest: semanticResult.Request.Digest, JobRef: semanticResult.Request.JobRef, JobRoot: semanticResult.Request.JobRoot},
		ResultDigest: resultDigest, Schema: FrameSchema, TotalBytes: total,
	}
	ready := helperReady{
		CancellationExitCode: 130, ChunkBytes: RequestChunkBytes, Executable: policy.Executable,
		ExecutorRevision: pinToHelper(policy.Executor), Interface: pinToHelper(policy.Interface),
		Kind: "ready", Nonce: nonce, ProcessIdentity: helperProcessIdentity(process), Schema: FrameSchema,
	}
	frames := []any{start}
	for index, file := range files {
		ordinal := index + 1
		frames = append(frames,
			helperFileStart{
				ByteLength: int64(len(file.body)), ChunkBytes: RequestChunkBytes, ChunkCount: 1,
				Kind: "file_start", MediaType: file.mediaType, Nonce: nonce, Ordinal: ordinal,
				Path: file.path, Role: file.role, Schema: FrameSchema, Digest: file.digest,
			},
			helperFileChunk{
				Base64: base64.StdEncoding.EncodeToString(file.body), Bytes: len(file.body),
				ChunkIndex: 0, Kind: "file_chunk", Nonce: nonce, Ordinal: ordinal,
				Schema: FrameSchema, Digest: sha256Digest(file.body),
			},
		)
	}
	streamHash := sha256.New()
	var wire bytes.Buffer
	writeCanonicalLine(t, &wire, ready)
	for _, frame := range frames {
		line, err := generationstop.CanonicalJSON(frame)
		if err != nil {
			t.Fatal(err)
		}
		wire.Write(line)
		wire.WriteByte('\n')
		writeHashedLine(streamHash, line)
	}
	end := helperResponseEnd{
		ExecutorRevision: start.ExecutorRevision, ExitCode: exitCode, FileCount: len(files),
		FrameCount: len(frames), Kind: "response_end", Nonce: nonce, Outcome: "failed",
		PrivateRootCleanup: "completed", ProcessIdentity: helperProcessIdentity(process),
		Request: start.Request, ResultDigest: start.ResultDigest, Schema: FrameSchema,
		StreamDigest: hashDigest(streamHash), TerminalSelection: "helper-selected", TotalBytes: total,
	}
	writeCanonicalLine(t, &wire, end)
	reader := bufio.NewReaderSize(bytes.NewReader(wire.Bytes()), MaximumFrameBytes+1)
	if err := collector.readReady(reader); err != nil {
		t.Fatal(err)
	}
	result, err := collector.collect(reader)
	return result, privateRoot, err
}

type renderGolden struct {
	Request         string `json:"request"`
	RequestDigest   string `json:"requestDigest"`
	Failure         string `json:"failure"`
	FailureDigest   string `json:"failureDigest"`
	FailureEvidence struct {
		Descriptor helperArtifactDescriptor `json:"descriptor"`
		Body       string                   `json:"body"`
	} `json:"failureEvidence"`
}

func loadRenderGolden(t *testing.T) renderGolden {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller path unavailable")
	}
	path := filepath.Clean(filepath.Join(
		filepath.Dir(current), "../../../../images/ambit-agent-workspace/capabilities/c18-specialist-packs/protocol/render-command-goldens.v2.json",
	))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value renderGolden
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func writeCanonicalLine(t *testing.T, target *bytes.Buffer, value any) {
	t.Helper()
	line, err := generationstop.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	target.Write(line)
	target.WriteByte('\n')
}
