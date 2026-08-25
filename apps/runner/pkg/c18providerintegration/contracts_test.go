// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

func TestProviderLiveCollectionGoldenIsCanonicalAndRejectsFacetSubstitution(t *testing.T) {
	collection := providerCollectionFixture(t)
	encoded, err := generationstop.CanonicalJSON(collection)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "c18-provider-live-collection.golden.json", encoded)
	parsed, err := ParseProviderLiveCollection(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Digest != collection.Digest || len(parsed.ProviderReceipts) != 12 || len(parsed.AuthenticatedStreaming.Cases) != 6 {
		t.Fatalf("provider collection differs after parse: %#v", parsed)
	}

	forged := cloneCollection(t, collection)
	forged.ProviderReceipts[0].Facet = "pdf"
	forged.Digest = digestSeed(900)
	forgedBytes, _ := generationstop.CanonicalJSON(forged)
	if _, err := ParseProviderLiveCollection(forgedBytes); err == nil {
		t.Fatal("facet-to-pack substitution was accepted")
	}
}

func TestMinIOIntegrationReceiptGoldenIsCanonicalAndSelfDigested(t *testing.T) {
	receipt, err := SealMinIOIntegrationReceipt(MinIOIntegrationReceipt{
		SourceRevision:  "1" + strings.Repeat("0", 39),
		SourceTree:      "2" + strings.Repeat("0", 39),
		SourceSetDigest: digestSeed(3),
		ObservedFrom:    "2026-08-25T04:00:00Z",
		ObservedUntil:   "2026-08-25T04:00:01Z",
		Observations: MinIOOperationObservations{
			ConditionalCreate: MinIOConditionalCreateObservation{
				PayloadBytes: 128, PayloadSHA256: digestSeed(4), Contenders: 16,
				ConcurrentWinners: 1, ConflictDisposition: "precondition_failed",
			},
			ChecksumStat: MinIOChecksumStatObservation{
				ByteLength: 128, ContentSHA256: digestSeed(4), UserMetadataSHA256: digestSeed(5),
			},
			RangedRead: MinIORangedReadObservation{Offset: 7, ByteLength: 13, SHA256: digestSeed(6)},
			StreamingOpen: MinIOStreamingOpenObservation{
				ByteLength: 128, SHA256: digestSeed(4), UserMetadataSHA256: digestSeed(7),
			},
			BoundedList: MinIOBoundedListObservation{Maximum: 8, Count: 1, RosterSHA256: digestSeed(8)},
			Delete:      MinIODeleteObservation{ObjectCount: 3, AllAbsent: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := generationstop.CanonicalJSON(receipt)
	assertGolden(t, "c18-minio-integration-receipt.golden.json", encoded)
	if _, err := ParseMinIOIntegrationReceipt(encoded); err != nil {
		t.Fatal(err)
	}
	forged := receipt
	forged.Operations = append([]string(nil), receipt.Operations...)
	forged.Operations[0] = "unbounded_list"
	forgedBytes, _ := generationstop.CanonicalJSON(forged)
	if _, err := ParseMinIOIntegrationReceipt(forgedBytes); err == nil {
		t.Fatal("forged MinIO operation roster was accepted")
	}
}

func TestProviderRequestAndResponseStreamsRoundTripExactBytes(t *testing.T) {
	collection := providerCollectionFixture(t)
	row := collection.ProviderReceipts[1]
	requestBytes := []byte(`{"contract":"fixture","value":1}`)
	sourceBytes := []byte("source bytes")
	request := row.Receipt.Request
	request.RequestBytes = int64(len(requestBytes))
	request.RequestChunkCount = chunkCount(len(requestBytes))
	request.RequestDigest = digestBytes(requestBytes)
	request.SourceBytes = int64(len(sourceBytes))
	request.SourceChunkCount = chunkCount(len(sourceBytes))
	request.SourceDigest = digestBytes(sourceBytes)
	fingerprint, err := specialistrender.ComputeRequestFingerprint(request)
	if err != nil {
		t.Fatal(err)
	}
	request.RequestFingerprint = fingerprint
	var wire bytes.Buffer
	if err := encodeRequestStream(context.Background(), &wire, request, requestBytes, sourceBytes); err != nil {
		t.Fatal(err)
	}
	decoded, err := specialistrender.DecodeRequestStream(bytes.NewReader(wire.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	if decoded.Request != request {
		t.Fatal("decoded provider request differs")
	}

	policy := policyForReceipt(t, collection.RunnerPolicy, row.Receipt)
	receipt := row.Receipt
	receipt.Request = request
	receipt.Launch.ParentGeneration = request.ExpectedParentGeneration
	receipt.ReceiptDigest, err = specialistrender.ComputeReceiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	resultBytes := []byte("result")
	var response bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &response, specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0],
			Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(resultBytes)), nil
			},
			Cleanup: func() error { return nil },
		}},
	}); err != nil {
		t.Fatal(err)
	}
	observed, streamDigest, err := decodeResponseStream(bytes.NewReader(response.Bytes()), request, policy)
	if err != nil {
		t.Fatal(err)
	}
	if observed.ReceiptDigest != receipt.ReceiptDigest || streamDigest != digestBytes(response.Bytes()) {
		t.Fatal("response stream identity differs")
	}
}

func providerCollectionFixture(t *testing.T) ProviderLiveCollection {
	t.Helper()
	policySet, policies := policyFixture(t)
	policyJSON, err := generationstop.CanonicalJSON(policySet)
	if err != nil {
		t.Fatal(err)
	}
	baseBytes, err := os.ReadFile(filepath.Join(repoRoot(t), "apps/runner/pkg/specialistrender/testdata/provider-contract-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var base specialistrender.Receipt
	if err := generationstop.DecodeCanonicalJSON(bytes.TrimSuffix(baseBytes, []byte{'\n'}), &base); err != nil {
		t.Fatal(err)
	}
	facets := []string{"data_analysis", "pdf", "presentation", "research", "spreadsheet", "web_application"}
	rows := make([]ProviderReceiptRow, 0, 12)
	streams := make([]AuthenticatedStreamingCase, 0, 6)
	sequence := 1
	for _, facet := range facets {
		for _, mode := range []string{"cancel", "success"} {
			policy := policies[facetPacks[facet]]
			receipt := receiptFixture(t, base, policy, sequence, mode)
			rows = append(rows, ProviderReceiptRow{Facet: facet, Mode: mode, Receipt: receipt})
			if mode == "success" {
				streams = append(streams, AuthenticatedStreamingCase{
					Facet: facet, OperationID: receipt.Request.OperationID, HTTPStatus: 200,
					Authenticated: true, RequestStreamSHA256: digestSeed(300 + sequence),
					ResponseStreamSHA256: digestSeed(400 + sequence), ReceiptDigest: receipt.ReceiptDigest,
				})
			}
			sequence++
		}
	}
	collection, err := SealProviderLiveCollection(ProviderLiveCollection{
		SourceRevision: "1" + strings.Repeat("0", 39), SourceTree: "2" + strings.Repeat("0", 39),
		SourceSetDigest:  digestSeed(3),
		RunnerPolicy:     RunnerPolicyPin{CanonicalJSON: string(policyJSON), ContentSHA256: digestBytes(policyJSON)},
		ProviderReceipts: rows,
		AuthenticatedStreaming: AuthenticatedStreamingObservation{
			Outcome: "passed", ObservedFrom: "2026-08-25T04:00:00Z",
			ObservedUntil: "2026-08-25T04:01:00Z", Cases: streams,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return collection
}

func policyFixture(t *testing.T) (specialistrender.PolicySet, map[string]specialistrender.Policy) {
	t.Helper()
	return policyFixtureAt(
		t,
		filepath.Join(repoRoot(t), "images/ambit-agent-workspace/capabilities/c18-specialist-packs/policy/specialist-seccomp-v1.json"),
		"/opt/ambit/c18/specialist-seccomp-v1.json",
	)
}

func policyFixtureAt(t *testing.T, seccompSourcePath, documentSeccompPath string) (specialistrender.PolicySet, map[string]specialistrender.Policy) {
	t.Helper()
	seccomp, err := os.ReadFile(seccompSourcePath)
	if err != nil {
		t.Fatal(err)
	}
	packs := []string{"data-research", "office-authoring", "pdf-ocr", "web-browser"}
	documents := make([]specialistrender.PolicyDocument, 0, 4)
	policies := make(map[string]specialistrender.Policy, 4)
	for index, pack := range packs {
		policy := specialistrender.Policy{
			Authority:   specialistrender.Pin{Ref: "ambit.runtime-provider/specialist-render-" + pack + "@1"},
			Composition: specialistrender.Pin{Ref: "runtime-full-image-composition:" + digestSeed(10), Digest: digestSeed(10)},
			Image: specialistrender.ImagePin{
				Ref:          "registry.test/ambit-c18-" + pack + "@" + digestSeed(20+index),
				ConfigDigest: digestSeed(30 + index), PackID: pack, PackRef: "ambit.runtime-pack/" + pack + "@1",
			},
			Interface:             specialistrender.Pin{Ref: specialistrender.InterfaceRef, Digest: digestSeed(40)},
			Executor:              specialistrender.Pin{Ref: "ambit://specialist-render-executors/" + pack + "@1", Digest: digestSeed(50 + index)},
			Executable:            "/opt/ambit/runtime-pack/" + pack + "/bin/ambit-specialist-render",
			ProcessExecutablePath: "/usr/local/bin/python3.14", ProcessExecutableDigest: digestSeed(60 + index),
			EnvironmentDigest: digestSeed(70 + index), Seccomp: seccomp,
			PIDsLimit: 512, MemoryBytes: 4 * 1024 * 1024 * 1024, NanoCPUs: 4_000_000_000,
			WorkspaceSize: 1024 * 1024 * 1024, ScratchSize: 2 * 1024 * 1024 * 1024,
			ShmSize: 64 * 1024 * 1024, Runtime: "runc", RuntimeStatusDigest: digestSeed(80),
			CustodyBytesPerSecond: 4 * 1024 * 1024, SettlementBaseSeconds: 30, SettlementMaximumSeconds: 180,
		}
		if pack == "web-browser" {
			policy.ProcessExecutablePath = "/usr/bin/python3.12"
			policy.PIDsLimit = 1024
			policy.MemoryBytes = 6 * 1024 * 1024 * 1024
			policy.ShmSize = 1024 * 1024 * 1024
		}
		policy.Authority.Digest, err = specialistrender.ComputePolicyDigest(policy)
		if err != nil {
			t.Fatal(err)
		}
		policies[pack] = policy
		documents = append(documents, specialistrender.PolicyDocument{
			Authority: policy.Authority, Composition: policy.Composition, Image: policy.Image,
			Interface: policy.Interface, Executor: policy.Executor, Executable: policy.Executable,
			ProcessExecutablePath: policy.ProcessExecutablePath, ProcessExecutableDigest: policy.ProcessExecutableDigest,
			EnvironmentDigest: policy.EnvironmentDigest, SeccompPath: documentSeccompPath,
			SeccompDigest: specialistrender.SpecialistSeccompDigest, PIDsLimit: policy.PIDsLimit,
			MemoryBytes: policy.MemoryBytes, NanoCPUs: policy.NanoCPUs, WorkspaceSize: policy.WorkspaceSize,
			ScratchSize: policy.ScratchSize, ShmSize: policy.ShmSize, Runtime: policy.Runtime,
			RuntimeStatusDigest: policy.RuntimeStatusDigest, CustodyBytesPerSecond: policy.CustodyBytesPerSecond,
			SettlementBaseSeconds: policy.SettlementBaseSeconds, SettlementMaximumSeconds: policy.SettlementMaximumSeconds,
		})
	}
	return specialistrender.PolicySet{Schema: specialistrender.PolicySetSchema, Policies: documents}, policies
}

func receiptFixture(t *testing.T, base specialistrender.Receipt, policy specialistrender.Policy, sequence int, mode string) specialistrender.Receipt {
	t.Helper()
	encoded, _ := generationstop.CanonicalJSON(base)
	var receipt specialistrender.Receipt
	if err := generationstop.DecodeCanonicalJSON(encoded, &receipt); err != nil {
		t.Fatal(err)
	}
	operationID := fmt.Sprintf("11111111-1111-4111-8111-%012d", sequence)
	jobID := fmt.Sprintf("22222222-2222-4222-8222-%012d", sequence)
	receipt.Request.OperationID = operationID
	receipt.Request.ArtifactRenderJobRef = "ambit://artifact-render-jobs/" + jobID
	receipt.Request.Composition = policy.Composition
	receipt.Request.Image = policy.Image
	receipt.Request.Interface = policy.Interface
	receipt.Request.Executor = policy.Executor
	receipt.Request.Executable = policy.Executable
	receipt.Request.ProviderPolicy = policy.Authority
	fingerprint, err := specialistrender.ComputeRequestFingerprint(receipt.Request)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Request.RequestFingerprint = fingerprint
	receipt.Nonce = fmt.Sprintf("%032x", sequence)
	receipt.Launch.ContainerID = fmt.Sprintf("%064x", 1000+sequence)
	receipt.Launch.ContainerName = "ambit-specialist-render-" + strings.ReplaceAll(operationID, "-", "")
	receipt.Launch.ImageID = policy.Image.ConfigDigest
	receipt.Launch.Command = []string{
		"/bin/sh", "-c", `stty raw -echo -onlcr && exec "$1" --framed-jsonl --nonce "$2"`,
		specialistrender.RoleRef, policy.Executable, receipt.Nonce,
	}
	receipt.Launch.ExecutablePath = policy.ProcessExecutablePath
	receipt.Launch.ExecutableDigest = policy.ProcessExecutableDigest
	receipt.Launch.EnvironmentDigest = policy.EnvironmentDigest
	receipt.Launch.PIDsLimit = policy.PIDsLimit
	receipt.Launch.MemoryBytes = policy.MemoryBytes
	receipt.Launch.NanoCPUs = policy.NanoCPUs
	receipt.Launch.ShmSize = policy.ShmSize
	receipt.Launch.RuntimeStatusDigest = policy.RuntimeStatusDigest
	receipt.Launch.SeccompDigest = specialistrender.SpecialistSeccompDigest
	receipt.Launch.Tmpfs = map[string]string{
		"/workspace": fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,uid=1000,gid=1000,mode=0700", policy.WorkspaceSize),
		"/tmp":       fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,uid=0,gid=0,mode=1777", policy.ScratchSize),
	}
	receipt.Quiescence.ContainerID = receipt.Launch.ContainerID
	receipt.ReadyDigest = digestSeed(500 + sequence)
	receipt.TerminalDigest = digestSeed(600 + sequence)
	if mode == "cancel" {
		receipt.Outcome = "cancelled"
		receipt.TerminalKind = "cancelled"
		receipt.TerminalOutcome = "cancelled"
		receipt.HelperExitCode = 130
		receipt.Files = []specialistrender.OutputFile{}
		receipt.TotalOutputBytes = 0
	} else {
		receipt.Outcome = "succeeded"
		receipt.TerminalKind = "response_end"
		receipt.TerminalOutcome = "succeeded"
		receipt.HelperExitCode = 0
	}
	receipt.ReceiptDigest, err = specialistrender.ComputeReceiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := specialistrender.ValidateReceiptWithPolicy(receipt, policy); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func policyForReceipt(t *testing.T, pin RunnerPolicyPin, receipt specialistrender.Receipt) specialistrender.Policy {
	t.Helper()
	_, policies := policyFixture(t)
	policy := policies[receipt.Request.Image.PackID]
	if policy.Image != receipt.Request.Image {
		t.Fatal("fixture policy differs")
	}
	_ = pin
	return policy
}

func cloneCollection(t *testing.T, source ProviderLiveCollection) ProviderLiveCollection {
	t.Helper()
	encoded, _ := generationstop.CanonicalJSON(source)
	var clone ProviderLiveCollection
	if err := generationstop.DecodeCanonicalJSON(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source path is unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))
}

func assertGolden(t *testing.T, name string, actual []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_C18_GOLDENS") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, actual, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, actual) {
		t.Fatalf("golden %s differs; run with UPDATE_C18_GOLDENS=1", name)
	}
}

func digestSeed(seed int) string {
	return fmt.Sprintf("sha256:%064x", seed)
}
