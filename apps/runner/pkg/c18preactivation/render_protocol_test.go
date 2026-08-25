// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestAdmitRenderExecutionParsesOwnedFailureEvidenceAndRejectsOrphans(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	source := []byte("exact preactivation source")
	command.Source.ByteLength = int64(len(source))
	command.Source.Digest = sha256Digest(source)
	command.Digest = resealForTest(t, command)
	commandBytes, err := generationstop.CanonicalJSON(command)
	if err != nil {
		t.Fatal(err)
	}
	providerInput := testProviderInput(t, commandBytes, source)
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
	check := command.PackRequiredChecks[0].Check
	evidence := RenderCheckEvidenceV1{
		Artifacts: []RenderEvidenceDescriptor{}, Check: check,
		Contract:         RenderEvidenceContractV1,
		ExecutorRevision: providerRequest.Executor,
		Facts:            []RenderEvidenceFactV1{{Key: "fixture", Value: "failed exactly"}},
		Outcome:          "failed",
		Request: RenderEvidenceRequestV1{
			Digest: command.Digest, JobRef: command.JobRef, SourceDigest: command.Source.Digest,
		},
	}
	evidence.Digest = resealForTest(t, evidence)
	evidenceBytes, err := generationstop.CanonicalJSON(evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidenceDescriptor := RenderEvidenceDescriptor{
		Path:      command.Output.JobOutputRoot + "/evidence/001-" + check + ".json",
		MediaType: RenderEvidenceMediaType, ByteLength: int64(len(evidenceBytes)),
		Digest: sha256Digest(evidenceBytes),
	}
	result := RenderResultV2{
		Checks:   []RenderResultCheckV2{{Check: check, Evidence: &evidenceDescriptor, Outcome: "failed"}},
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
	provider := failedProviderResult(t, providerRequest, command, resultBytes, evidenceDescriptor, evidenceBytes)

	parsed, parsedEvidence, err := AdmitRenderExecution(commandBytes, source, provider)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Digest != result.Digest || len(parsedEvidence) != 1 || parsedEvidence[0].Digest != evidence.Digest {
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
	if _, _, err := AdmitRenderExecution(commandBytes, source, provider); err == nil {
		t.Fatal("unowned provider artifact was admitted")
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
	evidenceDescriptor RenderEvidenceDescriptor,
	evidenceBytes []byte,
) ProviderExecutionResult {
	t.Helper()
	receipt := testProviderReceipt(t, request, resultBytes)
	receipt.Outcome = "failed"
	receipt.TerminalOutcome = "failed"
	receipt.HelperExitCode = 1
	receipt.Files = []specialistrender.OutputFile{
		{
			Ordinal: 0, Role: "result", Path: command.Output.ResultPath,
			MediaType: RenderResultMediaType, ByteLength: int64(len(resultBytes)),
			Digest: sha256Digest(resultBytes),
		},
		{
			Ordinal: 1, Role: "evidence", Path: evidenceDescriptor.Path,
			MediaType: evidenceDescriptor.MediaType, ByteLength: evidenceDescriptor.ByteLength,
			Digest: evidenceDescriptor.Digest,
		},
	}
	receipt.TotalOutputBytes = int64(len(resultBytes) + len(evidenceBytes))
	var err error
	receipt.ReceiptDigest, err = specialistrender.ComputeReceiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := specialistrender.ValidateReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	return ProviderExecutionResult{
		Receipt: receipt,
		Files: []ProviderOutput{
			{Descriptor: receipt.Files[0], Bytes: resultBytes},
			{Descriptor: receipt.Files[1], Bytes: evidenceBytes},
		},
	}
}
