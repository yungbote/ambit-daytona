// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

func TestRenderResultRejectsOversizedEvidenceDocument(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	var result RenderResultV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Success), &result); err != nil {
		t.Fatal(err)
	}
	result.Checks[0].Evidence.ByteLength = maximumRenderEvidenceBytes + 1
	result.Digest = mustSealedDigest(t, result)
	encoded, err := generationstop.CanonicalJSON(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRenderResultV2(command, encoded); err == nil {
		t.Fatal("oversized check-evidence document was admitted")
	}
}

func TestRenderCommandRejectsExactAuthorityPredicateSubstitutions(t *testing.T) {
	golden := loadRenderGolden(t)
	var original RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &original); err != nil {
		t.Fatal(err)
	}
	source := []byte("exact preactivation source")
	for _, test := range []struct {
		name   string
		mutate func(*RenderCommandV2)
	}{
		{name: "source schema", mutate: func(command *RenderCommandV2) {
			value := "file:///tmp/schema"
			command.Source.SchemaURI = &value
		}},
		{name: "aggregate image relation", mutate: func(command *RenderCommandV2) {
			command.Output.MaximumAggregateImagePixels = command.Output.MaximumImagePixels - 1
		}},
		{name: "runtime pack ref", mutate: func(command *RenderCommandV2) {
			command.Runtime.PackRevisions[0].Ref = "ambit://runtime-pack/noncanonical"
		}},
		{name: "renderer ref", mutate: func(command *RenderCommandV2) {
			command.Renderer.RendererRef = "ambit://renderer/noncanonical"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := original
			command.Runtime.PackRevisions = append([]specialistrender.Pin(nil), original.Runtime.PackRevisions...)
			command.Source.ByteLength = int64(len(source))
			command.Source.Digest = sha256Digest(source)
			bindCommandToRuntimePolicyForTest(t, &command)
			test.mutate(&command)
			command.Digest = mustSealedDigest(t, command)
			encoded, err := generationstop.CanonicalJSON(command)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRenderCommandV2(encoded, source); err == nil {
				t.Fatal("substituted render command authority was admitted")
			}
		})
	}
}

func TestRenderResultRejectsDeadlineAndEvidencePathSubstitution(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*RenderResultV2)
	}{
		{name: "completion after deadline", mutate: func(result *RenderResultV2) {
			result.Execution.CompletedAt = "2026-08-24T00:05:01.000Z"
		}},
		{name: "evidence outside job root", mutate: func(result *RenderResultV2) {
			result.Checks[0].Evidence.Path = "outputs/other/evidence.json"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var result RenderResultV2
			if err := generationstop.DecodeCanonicalJSON([]byte(golden.Success), &result); err != nil {
				t.Fatal(err)
			}
			test.mutate(&result)
			result.Digest = mustSealedDigest(t, result)
			encoded, err := generationstop.CanonicalJSON(result)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRenderResultV2(command, encoded); err == nil {
				t.Fatal("substituted render result authority was admitted")
			}
		})
	}
}

func TestRenderAdmissionRejectsAggregateEvidenceOverflowWithoutReadingOpaqueArtifact(t *testing.T) {
	command, commandBytes, source, expectedRequest := singleCheckRenderAuthority(t)
	artifact := RenderEvidenceDescriptor{
		Path: "outputs/render/artifacts/large.bin", MediaType: "application/octet-stream",
		ByteLength: maximumAggregateEvidenceBytes + 1, Digest: "sha256:" + repeatHex("a"),
	}
	evidence := RenderCheckEvidenceV1{
		Artifacts: []RenderEvidenceDescriptor{artifact}, Check: command.PackRequiredChecks[0].Check,
		Contract: RenderEvidenceContractV1, ExecutorRevision: expectedRequest.Executor,
		Facts: []RenderEvidenceFactV1{{Key: "verified", Value: "true"}}, Outcome: "failed",
		Request: RenderEvidenceRequestV1{
			Digest: command.Digest, JobRef: command.JobRef, SourceDigest: command.Source.Digest,
		},
	}
	evidence.Digest = mustSealedDigest(t, evidence)
	evidenceBytes, err := generationstop.CanonicalJSON(evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidenceDescriptor := RenderEvidenceDescriptor{
		Path: "outputs/render/evidence/001-check.json", MediaType: RenderEvidenceMediaType,
		ByteLength: int64(len(evidenceBytes)), Digest: sha256Digest(evidenceBytes),
	}
	result := RenderResultV2{
		Checks: []RenderResultCheckV2{{
			Check: command.PackRequiredChecks[0].Check, Evidence: &evidenceDescriptor, Outcome: "failed",
		}},
		Contract: RenderResultContractV2,
		Execution: RenderExecutionV2{
			CompletedAt: "2026-08-24T00:00:02.000Z", ExecutorRevision: expectedRequest.Executor,
			StartedAt: "2026-08-24T00:00:01.000Z",
		},
		Failure: &RenderFailureV2{Code: "check_failed", Message: "The check failed."},
		Outcome: "failed", Request: RenderResultRequestV2{
			Digest: command.Digest, JobRef: command.JobRef, JobRoot: command.JobRoot,
		},
	}
	result.Digest = mustSealedDigest(t, result)
	resultBytes, err := generationstop.CanonicalJSON(result)
	if err != nil {
		t.Fatal(err)
	}
	files := []specialistrender.OutputFile{
		{Ordinal: 0, Role: "result", Path: command.Output.ResultPath, MediaType: RenderResultMediaType, ByteLength: int64(len(resultBytes)), Digest: sha256Digest(resultBytes)},
		{Ordinal: 1, Role: "evidence", Path: evidenceDescriptor.Path, MediaType: evidenceDescriptor.MediaType, ByteLength: evidenceDescriptor.ByteLength, Digest: evidenceDescriptor.Digest},
		{Ordinal: 2, Role: "artifact", Path: artifact.Path, MediaType: artifact.MediaType, ByteLength: artifact.ByteLength, Digest: artifact.Digest},
	}
	receipt := testProviderReceipt(t, expectedRequest, resultBytes)
	receipt.Outcome = "failed"
	receipt.TerminalOutcome = "failed"
	receipt.TerminalKind = "response_end"
	receipt.HelperExitCode = 1
	receipt.Files = files
	receipt.TotalOutputBytes = files[0].ByteLength + files[1].ByteLength + files[2].ByteLength
	receipt.ReceiptDigest, err = specialistrender.ComputeReceiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	reader := &selectiveOutputReader{values: map[string][]byte{
		files[0].Path: resultBytes, files[1].Path: evidenceBytes,
	}}
	if _, err := AdmitRenderCustody(commandBytes, source, expectedRequest, receipt, reader); err == nil {
		t.Fatal("aggregate evidence overflow was admitted")
	}
	if reader.artifactOpened {
		t.Fatal("opaque evidence artifact was unnecessarily buffered")
	}
}

func TestRenderBoundedCustodyRejectsSemanticOverflowBeforeDelegateAdmission(t *testing.T) {
	command, _, _, expectedRequest := singleCheckRenderAuthority(t)
	base := testProviderReceipt(t, expectedRequest, []byte("result"))
	tests := []struct {
		name   string
		mutate func(*specialistrender.Receipt)
	}{
		{name: "result", mutate: func(receipt *specialistrender.Receipt) {
			receipt.Files[0].ByteLength = maximumRenderCommandBytes + 1
			receipt.Files[0].Digest = "sha256:" + repeatHex("1")
		}},
		{name: "preview", mutate: func(receipt *specialistrender.Receipt) {
			receipt.Files = append(receipt.Files, specialistrender.OutputFile{
				Ordinal: 1, Role: "preview", Path: command.Output.PreviewPath,
				MediaType: RenderPreviewMediaType, ByteLength: command.Output.MaximumPreviewBytes + 1,
				Digest: "sha256:" + repeatHex("2"),
			})
		}},
		{name: "evidence document", mutate: func(receipt *specialistrender.Receipt) {
			receipt.Files = append(receipt.Files, specialistrender.OutputFile{
				Ordinal: 1, Role: "evidence", Path: command.Output.JobOutputRoot + "/evidence/check.json",
				MediaType: RenderEvidenceMediaType, ByteLength: maximumRenderEvidenceBytes + 1,
				Digest: "sha256:" + repeatHex("3"),
			})
		}},
		{name: "evidence aggregate", mutate: func(receipt *specialistrender.Receipt) {
			receipt.Files = append(receipt.Files, specialistrender.OutputFile{
				Ordinal: 1, Role: "artifact", Path: command.Output.JobOutputRoot + "/artifacts/large.bin",
				MediaType: "application/octet-stream", ByteLength: maximumAggregateEvidenceBytes + 1,
				Digest: "sha256:" + repeatHex("4"),
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receipt := base
			receipt.Files = append([]specialistrender.OutputFile(nil), base.Files...)
			test.mutate(&receipt)
			receipt.TotalOutputBytes = 0
			for _, file := range receipt.Files {
				receipt.TotalOutputBytes += file.ByteLength
			}
			var err error
			receipt.ReceiptDigest, err = specialistrender.ComputeReceiptDigest(receipt)
			if err != nil || specialistrender.ValidateReceipt(receipt) != nil {
				t.Fatalf("test receipt is not structurally valid: %v", err)
			}
			delegate := &hashingResponseCustody{}
			custody, err := newRenderBoundedResponseCustody(delegate, command)
			if err != nil {
				t.Fatal(err)
			}
			if err := custody.AdmitReceipt(context.Background(), receipt); err == nil {
				t.Fatal("semantic overflow reached generic provider staging")
			}
			if delegate.admitted || len(delegate.files) != 0 {
				t.Fatal("semantic overflow admitted or opened generic custody")
			}
		})
	}
}

func singleCheckRenderAuthority(
	t *testing.T,
) (RenderCommandV2, []byte, []byte, specialistrender.Request) {
	t.Helper()
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	source := []byte("exact preactivation source")
	command.Source.ByteLength = int64(len(source))
	command.Source.Digest = sha256Digest(source)
	bindCommandToRuntimePolicyForTest(t, &command)
	command.Digest = mustSealedDigest(t, command)
	commandBytes, err := generationstop.CanonicalJSON(command)
	if err != nil {
		t.Fatal(err)
	}
	input := testProviderInput(t, commandBytes, source)
	input.OperationID = command.JobRef[len("ambit://artifact-render-jobs/"):]
	input.ArtifactRenderJobRef = command.JobRef
	input.Fence.WorkspaceExecutionManifestRef = command.Runtime.WorkspaceExecutionManifest.Ref
	input.Executable = command.Renderer.ExecutablePath
	input.Image = specialistrender.ImagePin{
		Ref:          "registry.test/ambit/office-authoring@sha256:" + repeatHex("8"),
		ConfigDigest: "sha256:" + repeatHex("9"), PackID: "office-authoring",
		PackRef: "ambit.runtime-pack/office-authoring@1",
	}
	input.Executor = specialistrender.Pin{
		Ref: "ambit://specialist-render-executors/office-authoring@1", Digest: "sha256:" + repeatHex("5"),
	}
	input.ProviderPolicy = testPin("ambit.runtime-provider/specialist-render-office-authoring@1", "c")
	request, _, _, err := ProviderRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	return command, commandBytes, source, request
}

type selectiveOutputReader struct {
	values         map[string][]byte
	artifactOpened bool
}

func (reader *selectiveOutputReader) Open(descriptor specialistrender.OutputFile) (io.ReadCloser, error) {
	if descriptor.Role == "artifact" {
		reader.artifactOpened = true
		return nil, errors.New("opaque artifact should not be opened")
	}
	value, exists := reader.values[descriptor.Path]
	if !exists {
		return nil, errors.New("output is absent")
	}
	return io.NopCloser(bytes.NewReader(value)), nil
}
