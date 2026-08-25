// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

type renderGoldenBundle struct {
	Contract        string                 `json:"contract"`
	Request         string                 `json:"request"`
	Success         string                 `json:"success"`
	Failure         string                 `json:"failure"`
	Evidence        []renderGoldenEvidence `json:"evidence"`
	FailureEvidence renderGoldenEvidence   `json:"failureEvidence"`
}

type renderGoldenEvidence struct {
	Descriptor RenderEvidenceDescriptor `json:"descriptor"`
	Body       string                   `json:"body"`
}

func TestRenderProtocolAdmitsExactPythonGoldens(t *testing.T) {
	golden := loadRenderGolden(t)
	if golden.Contract != "ambit.c18-specialist-render-command-goldens/v2" {
		t.Fatal("unexpected render golden contract")
	}
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	if err := verifySealedDigest(command, command.Digest); err != nil {
		t.Fatal(err)
	}
	success, err := ParseRenderResultV2(command, []byte(golden.Success))
	if err != nil {
		t.Fatal(err)
	}
	if success.Outcome != "succeeded" || len(success.Checks) != len(golden.Evidence) {
		t.Fatal("success golden did not retain its result roster")
	}
	for index, value := range golden.Evidence {
		parsed, err := ParseRenderCheckEvidenceV1(
			command, success.Execution.ExecutorRevision, value.Descriptor, []byte(value.Body),
		)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Check != success.Checks[index].Check || parsed.Outcome != success.Checks[index].Outcome {
			t.Fatal("evidence golden differs from result golden")
		}
	}
	failure, err := ParseRenderResultV2(command, []byte(golden.Failure))
	if err != nil {
		t.Fatal(err)
	}
	if failure.Outcome != "failed" || failure.Failure == nil {
		t.Fatal("failure golden lost its explicit failure")
	}
	if _, err := ParseRenderCheckEvidenceV1(
		command, failure.Execution.ExecutorRevision, golden.FailureEvidence.Descriptor,
		[]byte(golden.FailureEvidence.Body),
	); err != nil {
		t.Fatal(err)
	}
}

func TestRenderCommandBindsSourceBytesAndFacetExecutable(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	source := []byte("exact preactivation source")
	command.Source.ByteLength = int64(len(source))
	command.Source.Digest = sha256Digest(source)
	bindCommandToRuntimePolicyForTest(t, &command)
	command.Digest = resealForTest(t, command)
	encoded, err := generationstop.CanonicalJSON(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRenderCommandV2(encoded, source); err != nil {
		t.Fatal(err)
	}

	if _, err := ParseRenderCommandV2(encoded, append([]byte(nil), source[:len(source)-1]...)); err == nil {
		t.Fatal("truncated inline source was admitted")
	}
	command.Renderer.ExecutablePath = facetExecutable("pdf")
	command.Digest = resealForTest(t, command)
	encoded, err = generationstop.CanonicalJSON(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRenderCommandV2(encoded, source); err == nil {
		t.Fatal("cross-pack executable substitution was admitted")
	}
}

func TestRenderResultRejectsReboundRequestEvenWhenResealed(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	var result RenderResultV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Success), &result); err != nil {
		t.Fatal(err)
	}
	result.Request.Digest = "sha256:" + repeatHex("f")
	result.Digest = resealForTest(t, result)
	encoded, err := generationstop.CanonicalJSON(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRenderResultV2(command, encoded); err == nil {
		t.Fatal("result rebound to another request was admitted")
	}
}

func TestRenderResultRejectsReceiptOnlyOutcome(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	var result RenderResultV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Failure), &result); err != nil {
		t.Fatal(err)
	}
	result.Outcome = "cancelled"
	result.Digest = resealForTest(t, result)
	encoded, err := generationstop.CanonicalJSON(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRenderResultV2(command, encoded); err == nil {
		t.Fatal("receipt-only cancellation was admitted as a result-bearing helper document")
	}
}

func TestRenderResultRejectsNullCheckRoster(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	var result RenderResultV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Failure), &result); err != nil {
		t.Fatal(err)
	}
	result.Checks = nil
	result.Digest = resealForTest(t, result)
	encoded, err := generationstop.CanonicalJSON(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRenderResultV2(command, encoded); err == nil {
		t.Fatal("render result checks:null was admitted in place of an empty roster")
	}
}

func TestAdmitRenderExecutionParsesOwnedFailureEvidenceAndRejectsOrphans(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	source := []byte("exact preactivation source")
	command.Source.ByteLength = int64(len(source))
	command.Source.Digest = sha256Digest(source)
	bindCommandToRuntimePolicyForTest(t, &command)
	command.Digest = resealForTest(t, command)
	commandBytes, err := generationstop.CanonicalJSON(command)
	if err != nil {
		t.Fatal(err)
	}
	providerInput := testProviderInput(t, commandBytes, source)
	providerInput.OperationID = command.JobRef[len("ambit://artifact-render-jobs/"):]
	providerInput.ArtifactRenderJobRef = command.JobRef
	providerInput.Fence.WorkspaceExecutionManifestRef = command.Runtime.WorkspaceExecutionManifest.Ref
	providerInput.Executable = command.Renderer.ExecutablePath
	providerInput.Image = specialistrender.ImagePin{
		Ref:          "registry.test/ambit/office-authoring@sha256:" + repeatHex("8"),
		ConfigDigest: "sha256:" + repeatHex("9"), PackID: "office-authoring",
		PackRef: "ambit.runtime-pack/office-authoring@1",
	}
	providerInput.Executor = specialistrender.Pin{
		Ref:    "ambit://specialist-render-executors/office-authoring@1",
		Digest: "sha256:" + repeatHex("5"),
	}
	providerInput.ProviderPolicy = testPin("ambit.runtime-provider/specialist-render-office-authoring@1", "c")
	providerRequest, _, _, err := ProviderRequest(providerInput)
	if err != nil {
		t.Fatal(err)
	}
	evidenceValues := make([]RenderCheckEvidenceV1, len(command.PackRequiredChecks))
	evidenceBytes := make([][]byte, len(command.PackRequiredChecks))
	evidenceDescriptors := make([]RenderEvidenceDescriptor, len(command.PackRequiredChecks))
	resultChecks := make([]RenderResultCheckV2, len(command.PackRequiredChecks))
	for index, required := range command.PackRequiredChecks {
		evidenceValues[index] = RenderCheckEvidenceV1{
			Artifacts: []RenderEvidenceDescriptor{}, Check: required.Check,
			Contract:         RenderEvidenceContractV1,
			ExecutorRevision: providerRequest.Executor,
			Facts:            []RenderEvidenceFactV1{{Key: "fixture", Value: "failed exactly"}},
			Outcome:          "failed",
			Request: RenderEvidenceRequestV1{
				Digest: command.Digest, JobRef: command.JobRef, SourceDigest: command.Source.Digest,
			},
		}
		evidenceValues[index].Digest = resealForTest(t, evidenceValues[index])
		evidenceBytes[index], err = generationstop.CanonicalJSON(evidenceValues[index])
		if err != nil {
			t.Fatal(err)
		}
		evidenceDescriptors[index] = RenderEvidenceDescriptor{
			Path:      fmt.Sprintf("%s/evidence/%03d-%s.json", command.Output.JobOutputRoot, index+1, required.Check),
			MediaType: RenderEvidenceMediaType, ByteLength: int64(len(evidenceBytes[index])),
			Digest: sha256Digest(evidenceBytes[index]),
		}
		resultChecks[index] = RenderResultCheckV2{
			Check: required.Check, Evidence: &evidenceDescriptors[index], Outcome: "failed",
		}
	}
	result := RenderResultV2{
		Checks:   resultChecks,
		Contract: RenderResultContractV2,
		Execution: RenderExecutionV2{
			CompletedAt: "2026-08-24T00:00:02.000Z", ExecutorRevision: providerRequest.Executor,
			StartedAt: "2026-08-24T00:00:01.000Z",
		},
		Failure: &RenderFailureV2{Code: "check_failed", Message: "The exact check failed."},
		Outcome: "failed", Preview: nil,
		Request: RenderResultRequestV2{Digest: command.Digest, JobRef: command.JobRef, JobRoot: command.JobRoot},
	}
	result.Digest = resealForTest(t, result)
	resultBytes, err := generationstop.CanonicalJSON(result)
	if err != nil {
		t.Fatal(err)
	}
	provider := failedProviderResult(t, providerRequest, command, resultBytes, evidenceDescriptors, evidenceBytes)

	parsed, parsedEvidence, err := AdmitRenderExecution(commandBytes, source, providerRequest, provider)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Digest != result.Digest || len(parsedEvidence) != len(evidenceValues) ||
		parsedEvidence[0].Digest != evidenceValues[0].Digest {
		t.Fatal("admitted render execution lost exact helper evidence")
	}

	orphan := []byte("orphan")
	provider.Receipt.Files = append(provider.Receipt.Files, specialistrender.OutputFile{
		Ordinal: 2, Role: "artifact", Path: command.Output.JobOutputRoot + "/artifacts/orphan.bin",
		MediaType: "application/octet-stream", ByteLength: int64(len(orphan)), Digest: sha256Digest(orphan),
	})
	provider.Receipt.TotalOutputBytes += int64(len(orphan))
	provider.Receipt.ReceiptDigest, err = specialistrender.ComputeReceiptDigest(provider.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	provider.Files = append(provider.Files, ProviderOutput{Descriptor: provider.Receipt.Files[2], Bytes: orphan})
	if _, _, err := AdmitRenderExecution(commandBytes, source, providerRequest, provider); err == nil {
		t.Fatal("unowned provider artifact was admitted")
	}

	provider = failedProviderResult(t, providerRequest, command, resultBytes, evidenceDescriptors, evidenceBytes)
	provider.Receipt.Request.Composition.Digest = "sha256:" + repeatHex("f")
	provider.Receipt.Request.RequestFingerprint, err = specialistrender.ComputeRequestFingerprint(provider.Receipt.Request)
	if err != nil {
		t.Fatal(err)
	}
	provider.Receipt.ReceiptDigest, err = specialistrender.ComputeReceiptDigest(provider.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := specialistrender.ValidateReceipt(provider.Receipt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AdmitRenderExecution(commandBytes, source, providerRequest, provider); err == nil {
		t.Fatal("self-consistent foreign provider authority was admitted")
	}

	provider = failedProviderResult(t, providerRequest, command, resultBytes, evidenceDescriptors, evidenceBytes)
	provider.Files[len(provider.Files)-1].Bytes[0] ^= 0xff
	if _, _, err := AdmitRenderExecution(commandBytes, source, providerRequest, provider); err == nil {
		t.Fatal("memory-custodied provider byte substitution was admitted")
	}
}

func TestReceiptOnlyStageAdmissionCoversCancelledAndTimedOut(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	source := []byte("exact preactivation source")
	command.Source.ByteLength = int64(len(source))
	command.Source.Digest = sha256Digest(source)
	bindCommandToRuntimePolicyForTest(t, &command)
	command.Digest = resealForTest(t, command)
	commandBytes, err := generationstop.CanonicalJSON(command)
	if err != nil {
		t.Fatal(err)
	}
	providerInput := testProviderInput(t, commandBytes, source)
	providerInput.OperationID = command.JobRef[len("ambit://artifact-render-jobs/"):]
	providerInput.ArtifactRenderJobRef = command.JobRef
	providerInput.Fence.WorkspaceExecutionManifestRef = command.Runtime.WorkspaceExecutionManifest.Ref
	providerInput.Executable = command.Renderer.ExecutablePath
	providerInput.Image = specialistrender.ImagePin{
		Ref:          "registry.test/ambit/office-authoring@sha256:" + repeatHex("8"),
		ConfigDigest: "sha256:" + repeatHex("9"), PackID: "office-authoring",
		PackRef: "ambit.runtime-pack/office-authoring@1",
	}
	providerInput.Executor = specialistrender.Pin{
		Ref:    "ambit://specialist-render-executors/office-authoring@1",
		Digest: "sha256:" + repeatHex("5"),
	}
	providerInput.ProviderPolicy = testPin("ambit.runtime-provider/specialist-render-office-authoring@1", "c")
	providerRequest, _, _, err := ProviderRequest(providerInput)
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []string{"cancelled", "timed_out"} {
		t.Run(outcome, func(t *testing.T) {
			receipt := receiptOnlyProviderReceipt(t, providerRequest, outcome)
			evaluation, err := AdmitReceiptOnlyRenderStage(
				commandBytes, source, providerRequest, receipt,
			)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := generationstop.CanonicalJSON(evaluation)
			if err != nil {
				t.Fatal(err)
			}
			var reparsed StageEvaluationV2
			if err := generationstop.DecodeCanonicalJSON(encoded, &reparsed); err != nil {
				t.Fatal(err)
			}
			if reparsed.Outcome != outcome || len(reparsed.Checks) != 0 || reparsed.ResultFileSHA256 != "" {
				t.Fatal("receipt-only stage grew result-bearing fields")
			}
		})
	}
}

func TestReceiptOnlyStageMarshalRejectsHiddenResultEvidence(t *testing.T) {
	evaluation := StageEvaluationV2{
		StageRef:      "ambit://skill-evaluations/c18-preactivation/stages/018f6f56-7b2c-7d20-8a1f-abcdef123456",
		CommandDigest: "sha256:" + repeatHex("a"), Outcome: "cancelled",
		Checks: []StageCheckEvaluationV2{},
	}
	if _, err := generationstop.CanonicalJSON(evaluation); err == nil {
		t.Fatal("receipt-only stage silently discarded hidden result evidence")
	}
}

func loadRenderGolden(t *testing.T) renderGoldenBundle {
	t.Helper()
	path := filepath.Clean(filepath.Join(
		"..", "..", "..", "..", "images", "ambit-agent-workspace", "capabilities",
		"c18-specialist-packs", "protocol", "render-command-goldens.v2.json",
	))
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var golden renderGoldenBundle
	if err := json.Unmarshal(encoded, &golden); err != nil {
		t.Fatal(err)
	}
	return golden
}

func bindCommandToRuntimePolicyForTest(t *testing.T, command *RenderCommandV2) {
	t.Helper()
	policy, found := runtimePolicyForCommand(*command)
	if !found {
		t.Fatal("render golden has no exact runtime policy")
	}
	command.Renderer = RenderRendererV2{
		ExecutablePath: policy.ExecutablePath, RenderMode: policy.RenderMode,
		RendererRef: policy.RendererRef, Representation: policy.Representation,
		ValidationPolicyRef: policy.ValidationPolicyRef,
	}
	command.PackRequiredChecks = append([]RenderLabeledCheckV2(nil), policy.CheckLabels...)
	if !containsPinRef(command.Runtime.PackRevisions, policy.ExecutorPackRevisionRef) {
		command.Runtime.PackRevisions = append(command.Runtime.PackRevisions, specialistrender.Pin{
			Ref: policy.ExecutorPackRevisionRef, Digest: "sha256:" + repeatHex("e"),
		})
		sort.Slice(command.Runtime.PackRevisions, func(left, right int) bool {
			return command.Runtime.PackRevisions[left].Ref < command.Runtime.PackRevisions[right].Ref
		})
	}
}

func resealForTest(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	delete(body, "digest")
	digest, err := semanticDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func repeatHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result[:64]
}

func failedProviderResult(
	t *testing.T,
	request specialistrender.Request,
	command RenderCommandV2,
	resultBytes []byte,
	evidenceDescriptors []RenderEvidenceDescriptor,
	evidenceBytes [][]byte,
) ProviderExecutionResult {
	t.Helper()
	receipt := testProviderReceipt(t, request, resultBytes)
	receipt.Outcome = "failed"
	receipt.TerminalOutcome = "failed"
	receipt.HelperExitCode = 1
	receipt.Files = []specialistrender.OutputFile{{
		Ordinal: 0, Role: "result", Path: command.Output.ResultPath,
		MediaType: RenderResultMediaType, ByteLength: int64(len(resultBytes)),
		Digest: sha256Digest(resultBytes),
	}}
	files := []ProviderOutput{{Descriptor: receipt.Files[0], Bytes: resultBytes}}
	receipt.TotalOutputBytes = int64(len(resultBytes))
	for index, descriptor := range evidenceDescriptors {
		file := specialistrender.OutputFile{
			Ordinal: index + 1, Role: "evidence", Path: descriptor.Path,
			MediaType: descriptor.MediaType, ByteLength: descriptor.ByteLength,
			Digest: descriptor.Digest,
		}
		receipt.Files = append(receipt.Files, file)
		files = append(files, ProviderOutput{Descriptor: file, Bytes: evidenceBytes[index]})
		receipt.TotalOutputBytes += int64(len(evidenceBytes[index]))
	}
	var err error
	receipt.ReceiptDigest, err = specialistrender.ComputeReceiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := specialistrender.ValidateReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	return ProviderExecutionResult{Receipt: receipt, Files: files}
}

func receiptOnlyProviderReceipt(
	t *testing.T,
	request specialistrender.Request,
	outcome string,
) specialistrender.Receipt {
	t.Helper()
	receipt := testProviderReceipt(t, request, []byte("discarded"))
	receipt.Outcome = outcome
	receipt.TerminalOutcome = outcome
	receipt.Files = []specialistrender.OutputFile{}
	receipt.TotalOutputBytes = 0
	switch outcome {
	case "cancelled":
		receipt.TerminalKind = "cancelled"
		receipt.HelperExitCode = 130
	case "timed_out":
		receipt.TerminalKind = "response_end"
		receipt.HelperExitCode = 124
	default:
		t.Fatalf("unsupported receipt-only outcome %q", outcome)
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
