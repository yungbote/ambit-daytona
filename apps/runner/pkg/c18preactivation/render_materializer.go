// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"errors"
	"fmt"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

type MaterializedRenderStageV2 struct {
	OperationID   string
	Command       RenderCommandV2
	CommandBytes  []byte
	Artifact      InlineArtifactV2
	ArtifactBytes []byte
}

func MaterializeRenderStageV2(
	request PhysicalCaseRequestV2,
	sampleRef string,
	stageName string,
	deadlineAt string,
) (MaterializedRenderStageV2, error) {
	if !exactMillisecondInstant(deadlineAt) || deadlineAt > request.Binding.ExpiresAt {
		return MaterializedRenderStageV2{}, errors.New("C18 render stage deadline is outside its binding")
	}
	var journey *SampleJourneyV2
	for index := range request.SampleJourneys {
		if request.SampleJourneys[index].SampleRef == sampleRef {
			journey = &request.SampleJourneys[index]
		}
	}
	if journey == nil {
		return MaterializedRenderStageV2{}, errors.New("C18 render stage sample is absent")
	}
	var stage *JourneyStageV2
	for index := range journey.Stages {
		if journey.Stages[index].Stage == stageName {
			stage = &journey.Stages[index]
		}
	}
	if stage == nil {
		return MaterializedRenderStageV2{}, errors.New("C18 render journey stage is absent")
	}
	artifactBytes, err := decodeInlineArtifact(stage.Artifact)
	if err != nil {
		return MaterializedRenderStageV2{}, err
	}
	operationID, err := DeriveProviderOperationIDV2(request.Digest, sampleRef, stageName)
	if err != nil {
		return MaterializedRenderStageV2{}, err
	}
	extension := sourceExtension(stage.Artifact.MediaType)
	if extension == "" {
		return MaterializedRenderStageV2{}, errors.New("C18 render stage media type has no exact file suffix")
	}
	authority := request.RenderCommandAuthority
	command := RenderCommandV2{
		Contract:   RenderCommandContractV2,
		DeadlineAt: deadlineAt,
		Facet:      authority.Facet,
		JobRef:     "ambit://artifact-render-jobs/" + operationID,
		JobRoot:    "/workspace/.ambit/render-jobs/" + operationID,
		Operation:  "render_validate",
		Output: RenderOutputAuthorityV2{
			JobOutputRoot: "outputs/render", MaximumAggregateImagePixels: authority.Output.MaximumAggregateImagePixels,
			MaximumImagePixels:  authority.Output.MaximumImagePixels,
			MaximumPreviewBytes: authority.Output.MaximumPreviewBytes,
			PreviewMediaType:    authority.Output.PreviewMediaType,
			PreviewPath:         "outputs/render/preview.json", ResultPath: "outputs/render/result.json",
		},
		PackRequiredChecks: append([]RenderLabeledCheckV2(nil), authority.PackRequiredChecks...),
		Renderer: RenderRendererV2{
			ExecutablePath: authority.ExecutablePath, RenderMode: authority.Renderer.RenderMode,
			RendererRef: authority.Renderer.RendererRef, Representation: authority.Renderer.Representation,
			ValidationPolicyRef: authority.Renderer.ValidationPolicyRef,
		},
		RequestPath: "inputs/request.json",
		Runtime: RenderRuntimeV2{
			PackRevisions:              append([]specialistrender.Pin(nil), authority.Runtime.PackRevisions...),
			ProfileRevision:            authority.Runtime.ProfileRevision,
			WorkspaceExecutionManifest: authority.Runtime.WorkspaceExecutionManifest,
		},
		Source: RenderSourceV2{
			ByteLength: stage.Artifact.ByteLength, Digest: stage.Artifact.Digest,
			MediaType: stage.Artifact.MediaType, Path: "inputs/source-" + stageName + extension,
			Ref: stage.Artifact.Ref, SchemaURI: authority.Renderer.SourceSchemaURI,
		},
	}
	command.Digest, err = sealedDigest(command)
	if err != nil {
		return MaterializedRenderStageV2{}, fmt.Errorf("seal C18 render command: %w", err)
	}
	commandBytes, err := generationstop.CanonicalJSON(command)
	if err != nil {
		return MaterializedRenderStageV2{}, fmt.Errorf("encode C18 render command: %w", err)
	}
	parsed, err := ParseRenderCommandV2(commandBytes, artifactBytes)
	if err != nil {
		return MaterializedRenderStageV2{}, err
	}
	return MaterializedRenderStageV2{
		OperationID: operationID, Command: parsed, CommandBytes: commandBytes,
		Artifact: stage.Artifact, ArtifactBytes: artifactBytes,
	}, nil
}

func ProviderInputForRenderStage(
	request PhysicalCaseRequestV2,
	stage MaterializedRenderStageV2,
) ProviderExecutionInput {
	binding := request.Binding
	return ProviderExecutionInput{
		Workspace:                binding.ProviderTarget.Workspace.providerSource(),
		OperationID:              stage.OperationID,
		ArtifactRenderJobRef:     "ambit://artifact-render-jobs/" + stage.OperationID,
		Composition:              binding.Authority.Composition,
		Owner:                    binding.ProviderTarget.Owner,
		Fence:                    binding.ProviderTarget.Fence,
		ExpectedParentGeneration: binding.ProviderTarget.ExpectedParentGeneration,
		Image:                    binding.Authority.Image,
		Interface:                binding.Authority.Component.Interface,
		Executor:                 binding.Authority.Executor,
		Executable:               request.RenderCommandAuthority.ExecutablePath,
		ProviderPolicy:           binding.Authority.ProviderPolicy,
		RequestBytes:             append([]byte(nil), stage.CommandBytes...),
		SourceBytes:              append([]byte(nil), stage.ArtifactBytes...),
	}
}

func sourceExtension(mediaType string) string {
	return map[string]string{
		"application/json":                                                          ".json",
		"application/pdf":                                                           ".pdf",
		"application/vnd.ambit.data-analysis+json":                                  ".json",
		"application/vnd.ambit.research+json":                                       ".json",
		"application/vnd.ambit.web-application+json":                                ".json",
		"application/vnd.ambit.web-application+zip":                                 ".zip",
		"application/vnd.apache.parquet":                                            ".parquet",
		"application/vnd.oasis.opendocument.presentation":                           ".odp",
		"application/vnd.oasis.opendocument.spreadsheet":                            ".ods",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         ".xlsx",
		"application/zip":                                                           ".zip",
		"image/jpeg":                                                                ".jpg",
		"image/png":                                                                 ".png",
		"image/tiff":                                                                ".tiff",
		"image/x-portable-graymap":                                                  ".pgm",
		"text/csv":                                                                  ".csv",
		"text/html":                                                                 ".html",
		"text/markdown":                                                             ".md",
		"text/tab-separated-values":                                                 ".tsv",
	}[mediaType]
}
