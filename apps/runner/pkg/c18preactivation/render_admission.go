// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/daytonaio/runner/pkg/specialistrender"
)

type ProviderOutputReader interface {
	Open(specialistrender.OutputFile) (io.ReadCloser, error)
}

type AdmittedRenderStageV2 struct {
	Command    RenderCommandV2
	Result     RenderResultV2
	Evidence   []RenderCheckEvidenceV1
	Evaluation StageEvaluationV2
}

type renderBoundedResponseCustody struct {
	delegate ProviderResponseCustody
	command  RenderCommandV2
}

func newRenderBoundedResponseCustody(
	delegate ProviderResponseCustody,
	command RenderCommandV2,
) (*renderBoundedResponseCustody, error) {
	if delegate == nil {
		return nil, errors.New("C18 bounded response custody is unavailable")
	}
	return &renderBoundedResponseCustody{delegate: delegate, command: command}, nil
}

func (custody *renderBoundedResponseCustody) AdmitReceipt(
	ctx context.Context,
	receipt specialistrender.Receipt,
) error {
	if err := specialistrender.ValidateReceipt(receipt); err != nil {
		return err
	}
	if receipt.Outcome == "cancelled" || receipt.Outcome == "timed_out" {
		return custody.delegate.AdmitReceipt(ctx, receipt)
	}
	var evidenceBytes int64
	for _, descriptor := range receipt.Files {
		switch descriptor.Role {
		case "result":
			if descriptor.Path != custody.command.Output.ResultPath ||
				descriptor.MediaType != RenderResultMediaType ||
				descriptor.ByteLength > maximumRenderCommandBytes {
				return errors.New("C18 provider result exceeds its semantic custody bound")
			}
		case "preview":
			if descriptor.Path != custody.command.Output.PreviewPath ||
				descriptor.MediaType != RenderPreviewMediaType ||
				descriptor.ByteLength > custody.command.Output.MaximumPreviewBytes {
				return errors.New("C18 provider preview exceeds its semantic custody bound")
			}
		case "evidence":
			if descriptor.MediaType != RenderEvidenceMediaType ||
				descriptor.ByteLength > maximumRenderEvidenceBytes ||
				!strings.HasPrefix(descriptor.Path, custody.command.Output.JobOutputRoot+"/") {
				return errors.New("C18 provider check evidence exceeds its semantic custody bound")
			}
			evidenceBytes += descriptor.ByteLength
		case "artifact":
			if !strings.HasPrefix(descriptor.Path, custody.command.Output.JobOutputRoot+"/") {
				return errors.New("C18 provider evidence artifact is outside its semantic custody root")
			}
			evidenceBytes += descriptor.ByteLength
		default:
			return errors.New("C18 provider output role is invalid")
		}
		if evidenceBytes > maximumAggregateEvidenceBytes {
			return errors.New("C18 provider evidence exceeds its aggregate semantic custody bound")
		}
	}
	return custody.delegate.AdmitReceipt(ctx, receipt)
}

func (custody *renderBoundedResponseCustody) OpenFile(
	ctx context.Context,
	descriptor specialistrender.OutputFile,
) (ProviderResponseFileWriter, error) {
	return custody.delegate.OpenFile(ctx, descriptor)
}

func (custody *renderBoundedResponseCustody) Commit(
	ctx context.Context,
	observation ProviderResponseObservation,
) error {
	return custody.delegate.Commit(ctx, observation)
}

func (custody *renderBoundedResponseCustody) Abort(ctx context.Context) error {
	return custody.delegate.Abort(ctx)
}

func AdmitRenderCustody(
	commandBytes []byte,
	sourceBytes []byte,
	expectedRequest specialistrender.Request,
	receipt specialistrender.Receipt,
	reader ProviderOutputReader,
) (AdmittedRenderStageV2, error) {
	command, err := ParseRenderCommandV2(commandBytes, sourceBytes)
	if err != nil {
		return AdmittedRenderStageV2{}, err
	}
	if reader == nil || specialistrender.ValidateRequest(expectedRequest) != nil ||
		specialistrender.ValidateReceipt(receipt) != nil || !canonicalEqual(receipt.Request, expectedRequest) ||
		expectedRequest.RequestDigest != sha256Digest(commandBytes) ||
		expectedRequest.SourceDigest != command.Source.Digest ||
		expectedRequest.Executable != command.Renderer.ExecutablePath ||
		expectedRequest.ArtifactRenderJobRef != command.JobRef ||
		expectedRequest.OperationID != command.JobRef[len("ambit://artifact-render-jobs/"):] ||
		expectedRequest.Fence.WorkspaceExecutionManifestRef != command.Runtime.WorkspaceExecutionManifest.Ref {
		return AdmittedRenderStageV2{}, errors.New("provider receipt changed C18 render command authority")
	}
	if receipt.Outcome != "succeeded" && receipt.Outcome != "failed" {
		return AdmittedRenderStageV2{}, errors.New("receipt-only settlement cannot enter result-bearing admission")
	}
	byPath := make(map[string]specialistrender.OutputFile, len(receipt.Files))
	for _, descriptor := range receipt.Files {
		if _, exists := byPath[descriptor.Path]; exists {
			return AdmittedRenderStageV2{}, errors.New("provider output paths are not unique")
		}
		byPath[descriptor.Path] = descriptor
	}
	resultDescriptor, exists := byPath[command.Output.ResultPath]
	if !exists || resultDescriptor.Role != "result" || resultDescriptor.MediaType != RenderResultMediaType {
		return AdmittedRenderStageV2{}, errors.New("provider result file is absent")
	}
	resultBytes, err := readProviderOutput(reader, resultDescriptor, maximumRenderCommandBytes)
	if err != nil {
		return AdmittedRenderStageV2{}, err
	}
	result, err := ParseRenderResultV2(command, resultBytes)
	if err != nil {
		return AdmittedRenderStageV2{}, err
	}
	if receipt.Outcome != result.Outcome || result.Execution.ExecutorRevision != receipt.Request.Executor ||
		len(result.Checks) != len(command.PackRequiredChecks) {
		return AdmittedRenderStageV2{}, errors.New("provider receipt and helper result outcomes disagree")
	}
	owned := map[string]struct{}{resultDescriptor.Path: {}}
	var preview *StagePreviewEvaluationV2
	if result.Preview != nil {
		descriptor, exists := byPath[result.Preview.Path]
		if !exists || descriptor.Role != "preview" || descriptor.MediaType != result.Preview.MediaType ||
			descriptor.ByteLength != result.Preview.ByteLength || descriptor.Digest != result.Preview.BytesDigest {
			return AdmittedRenderStageV2{}, errors.New("provider preview differs from helper result")
		}
		owned[descriptor.Path] = struct{}{}
		previewBytes, err := readProviderOutput(reader, descriptor, command.Output.MaximumPreviewBytes)
		if err != nil {
			return AdmittedRenderStageV2{}, err
		}
		parsedPreview, err := ParseArtifactPreviewV1(previewBytes, command)
		if err != nil || parsedPreview.Digest != result.Preview.EnvelopeDigest {
			if err != nil {
				return AdmittedRenderStageV2{}, err
			}
			return AdmittedRenderStageV2{}, errors.New("provider preview envelope digest differs from helper result")
		}
		preview = &StagePreviewEvaluationV2{
			FileSHA256: descriptor.Digest, EnvelopeDigest: result.Preview.EnvelopeDigest,
		}
	}
	evidence := make([]RenderCheckEvidenceV1, len(result.Checks))
	checks := make([]StageCheckEvaluationV2, len(result.Checks))
	var evidenceAggregate int64
	evidencePaths := make(map[string]struct{}, len(result.Checks))
	addEvidenceBytes := func(descriptor RenderEvidenceDescriptor) error {
		if _, exists := evidencePaths[descriptor.Path]; exists {
			return nil
		}
		evidencePaths[descriptor.Path] = struct{}{}
		evidenceAggregate += descriptor.ByteLength
		if evidenceAggregate > maximumAggregateEvidenceBytes {
			return errors.New("provider evidence exceeds its aggregate semantic bound")
		}
		return nil
	}
	for index, check := range result.Checks {
		if check.Check != command.PackRequiredChecks[index].Check || check.Evidence == nil {
			return AdmittedRenderStageV2{}, errors.New("helper result did not retain every pack check evidence")
		}
		evidenceDescriptor, exists := byPath[check.Evidence.Path]
		if !exists || evidenceDescriptor.Role != "evidence" || evidenceDescriptor.MediaType != check.Evidence.MediaType ||
			evidenceDescriptor.ByteLength != check.Evidence.ByteLength || evidenceDescriptor.Digest != check.Evidence.Digest {
			return AdmittedRenderStageV2{}, errors.New("provider check evidence differs from helper result")
		}
		if err := addEvidenceBytes(*check.Evidence); err != nil {
			return AdmittedRenderStageV2{}, err
		}
		evidenceBytes, err := readProviderOutput(reader, evidenceDescriptor, maximumRenderEvidenceBytes)
		if err != nil {
			return AdmittedRenderStageV2{}, err
		}
		parsed, err := ParseRenderCheckEvidenceV1(
			command, receipt.Request.Executor, *check.Evidence, evidenceBytes,
		)
		if err != nil || parsed.Check != check.Check || parsed.Outcome != check.Outcome {
			if err != nil {
				return AdmittedRenderStageV2{}, err
			}
			return AdmittedRenderStageV2{}, errors.New("nested check evidence differs from helper result")
		}
		owned[evidenceDescriptor.Path] = struct{}{}
		artifacts := make([]StageArtifactEvaluationV2, len(parsed.Artifacts))
		for artifactIndex, artifact := range parsed.Artifacts {
			descriptor, exists := byPath[artifact.Path]
			if !exists || descriptor.Role != "artifact" || descriptor.MediaType != artifact.MediaType ||
				descriptor.ByteLength != artifact.ByteLength || descriptor.Digest != artifact.Digest {
				return AdmittedRenderStageV2{}, errors.New("provider evidence artifact differs from nested evidence")
			}
			owned[descriptor.Path] = struct{}{}
			if err := addEvidenceBytes(artifact); err != nil {
				return AdmittedRenderStageV2{}, err
			}
			artifacts[artifactIndex] = StageArtifactEvaluationV2{Path: descriptor.Path, SHA256: descriptor.Digest}
		}
		evidence[index] = parsed
		checks[index] = StageCheckEvaluationV2{
			Artifacts: artifacts, Check: parsed.Check, Outcome: parsed.Outcome,
			EvidenceDocumentDigest: parsed.Digest, EvidencePath: evidenceDescriptor.Path,
			EvidenceFileSHA256: evidenceDescriptor.Digest,
		}
	}
	if len(owned) != len(receipt.Files) {
		return AdmittedRenderStageV2{}, errors.New("provider returned an unowned output file")
	}
	evaluation := StageEvaluationV2{
		StageRef:      "ambit://skill-evaluations/c18-preactivation/stages/" + receipt.Request.OperationID,
		CommandDigest: command.Digest, Outcome: result.Outcome,
		ResultDocumentDigest: result.Digest, ResultFileSHA256: resultDescriptor.Digest,
		Preview: preview, Checks: checks,
	}
	return AdmittedRenderStageV2{
		Command: command, Result: result, Evidence: evidence, Evaluation: evaluation,
	}, nil
}

func AdmitReceiptOnlyRenderStage(
	commandBytes []byte,
	sourceBytes []byte,
	expectedRequest specialistrender.Request,
	receipt specialistrender.Receipt,
) (StageEvaluationV2, error) {
	command, err := ParseRenderCommandV2(commandBytes, sourceBytes)
	if err != nil {
		return StageEvaluationV2{}, err
	}
	if specialistrender.ValidateRequest(expectedRequest) != nil || specialistrender.ValidateReceipt(receipt) != nil ||
		!canonicalEqual(receipt.Request, expectedRequest) ||
		(receipt.Outcome != "cancelled" && receipt.Outcome != "timed_out") ||
		len(receipt.Files) != 0 || receipt.TotalOutputBytes != 0 ||
		expectedRequest.RequestDigest != sha256Digest(commandBytes) ||
		expectedRequest.SourceDigest != command.Source.Digest ||
		expectedRequest.Executable != command.Renderer.ExecutablePath ||
		expectedRequest.ArtifactRenderJobRef != command.JobRef ||
		expectedRequest.OperationID != command.JobRef[len("ambit://artifact-render-jobs/"):] ||
		expectedRequest.Fence.WorkspaceExecutionManifestRef != command.Runtime.WorkspaceExecutionManifest.Ref {
		return StageEvaluationV2{}, errors.New("receipt-only C18 render settlement authority is invalid")
	}
	return StageEvaluationV2{
		StageRef:      "ambit://skill-evaluations/c18-preactivation/stages/" + receipt.Request.OperationID,
		CommandDigest: command.Digest, Outcome: receipt.Outcome,
	}, nil
}

func readProviderOutput(
	reader ProviderOutputReader,
	descriptor specialistrender.OutputFile,
	maximum int64,
) ([]byte, error) {
	if descriptor.ByteLength < 1 || descriptor.ByteLength > maximum {
		return nil, errors.New("provider output exceeds its parser bound")
	}
	stream, err := reader.Open(descriptor)
	if err != nil {
		return nil, fmt.Errorf("open provider output: %w", err)
	}
	value, readErr := io.ReadAll(io.LimitReader(stream, maximum+1))
	closeErr := stream.Close()
	if readErr != nil || closeErr != nil || int64(len(value)) != descriptor.ByteLength ||
		sha256Digest(value) != descriptor.Digest {
		return nil, errors.New("provider output bytes differ from their receipt")
	}
	return value, nil
}

type memoryProviderOutputReader struct {
	files []ProviderOutput
}

func (reader memoryProviderOutputReader) Open(
	descriptor specialistrender.OutputFile,
) (io.ReadCloser, error) {
	if descriptor.Ordinal < 0 || descriptor.Ordinal >= len(reader.files) ||
		reader.files[descriptor.Ordinal].Descriptor != descriptor {
		return nil, errors.New("provider output is absent from memory custody")
	}
	return io.NopCloser(bytes.NewReader(reader.files[descriptor.Ordinal].Bytes)), nil
}

func MaterializationEvidencePinV2(
	request PhysicalCaseRequestV2,
	sampleRef string,
	stage string,
	artifact SourceIdentityV1,
	providerRequestSHA256 string,
) (specialistrender.Pin, error) {
	if !validOperationalRef(sampleRef) || !validJourneyStage(stage) || !validOperationalRef(artifact.Ref) ||
		!exactSHA256.MatchString(artifact.Digest) || !canonicalMediaTypeValue(artifact.MediaType) ||
		!exactSHA256.MatchString(providerRequestSHA256) {
		return specialistrender.Pin{}, errors.New("C18 materialization evidence input is invalid")
	}
	type projectedAsset struct {
		Digest    string `json:"digest"`
		MediaType string `json:"mediaType"`
		Ref       string `json:"ref"`
		Role      string `json:"role"`
	}
	assets := make([]projectedAsset, len(request.CorpusAssets))
	for index, value := range request.CorpusAssets {
		assets[index] = projectedAsset{
			Ref: value.Ref, Digest: value.Digest, MediaType: value.MediaType, Role: value.Role,
		}
	}
	body := struct {
		Artifact              SourceIdentityV1     `json:"artifact"`
		Contract              string               `json:"contract"`
		CorpusAssets          []projectedAsset     `json:"corpusAssets"`
		ProviderRequestSHA256 string               `json:"providerRequestSha256"`
		RequestDigest         string               `json:"requestDigest"`
		SampleRef             string               `json:"sampleRef"`
		Stage                 string               `json:"stage"`
		SubjectArtifact       specialistrender.Pin `json:"subjectArtifact"`
	}{
		Artifact: artifact, Contract: "C18PreactivationPhysicalMaterializationEvidence@2",
		CorpusAssets: assets, ProviderRequestSHA256: providerRequestSHA256,
		RequestDigest: request.Digest, SampleRef: sampleRef, Stage: stage,
		SubjectArtifact: request.Binding.SubjectArtifact,
	}
	digest, err := semanticDigest(body)
	if err != nil {
		return specialistrender.Pin{}, err
	}
	return specialistrender.Pin{
		Ref:    "ambit://skill-evaluations/c18-preactivation/materializations/" + digest[len("sha256:"):],
		Digest: digest,
	}, nil
}
