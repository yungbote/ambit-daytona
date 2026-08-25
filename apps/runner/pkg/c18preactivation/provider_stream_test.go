// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"strings"
	"testing"

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
