// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"encoding/json"
	"fmt"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

const (
	PhysicalCaseRequestContractV2      = "C18ArtifactSkillPreactivationPhysicalCaseRequest@2"
	PhysicalCaseObservationContractV2  = "C18ArtifactSkillPreactivationPhysicalCaseObservation@2"
	StageLineageContractV1             = "C18PreactivationStageLineage@1"
	PhysicalEvaluationReportContractV1 = "C18PreactivationPhysicalEvaluationReport@1"
)

const (
	maximumPhysicalRequestBytes  = 16 * 1024 * 1024
	maximumPhysicalResponseBytes = 64 * 1024 * 1024
	maximumInlineArtifactBytes   = 512 * 1024
	maximumInlineAggregateBytes  = 12 * 1024 * 1024
	maximumJourneyStages         = 8
)

type PhysicalCaseRequestV2 struct {
	Binding                EvaluationBindingV1       `json:"binding"`
	Contract               string                    `json:"contract"`
	Corpus                 EvaluationCorpusV1        `json:"corpus"`
	CorpusAssets           []EvaluationCorpusAssetV1 `json:"corpusAssets"`
	DeterministicChecks    []string                  `json:"deterministicChecks"`
	Digest                 string                    `json:"digest"`
	EvaluationCase         EvaluationCaseV1          `json:"evaluationCase"`
	JourneyPlan            JourneyPlanV2             `json:"journeyPlan"`
	MeasuredMetrics        []string                  `json:"measuredMetrics"`
	RenderCommandAuthority RenderCommandAuthorityV2  `json:"renderCommandAuthority"`
	SampleJourneys         []SampleJourneyV2         `json:"sampleJourneys"`
	SamplePolicy           *SamplePolicyV2           `json:"samplePolicy"`
	SampleRoster           []SampleSourceV1          `json:"sampleRoster"`
}

type EvaluationBindingV1 struct {
	Authority       PhysicalAuthorityV1  `json:"authority"`
	CaseSampleSets  []CaseSampleSetV1    `json:"caseSampleSets"`
	Contract        string               `json:"contract"`
	Corpus          specialistrender.Pin `json:"corpus"`
	Digest          string               `json:"digest"`
	ExpiresAt       string               `json:"expiresAt"`
	ProviderTarget  ProviderTargetV1     `json:"providerTarget"`
	RuntimeClosure  specialistrender.Pin `json:"runtimeClosure"`
	Skill           specialistrender.Pin `json:"skill"`
	SubjectArtifact specialistrender.Pin `json:"subjectArtifact"`
}

type PhysicalAuthorityV1 struct {
	Candidate         specialistrender.Pin      `json:"candidate"`
	Component         SpecialistComponentV1     `json:"component"`
	Composition       specialistrender.Pin      `json:"composition"`
	Executor          specialistrender.Pin      `json:"executor"`
	Image             specialistrender.ImagePin `json:"image"`
	ProviderPolicy    specialistrender.Pin      `json:"providerPolicy"`
	Routing           specialistrender.Pin      `json:"routing"`
	SourceAuthorities []specialistrender.Pin    `json:"sourceAuthorities"`
}

type SpecialistComponentV1 struct {
	Artifact  specialistrender.Pin `json:"artifact"`
	Interface specialistrender.Pin `json:"interface"`
	RoleRef   string               `json:"roleRef"`
}

type ProviderTargetV1 struct {
	ExpectedParentGeneration generationstop.ExpectedGeneration `json:"expectedParentGeneration"`
	Fence                    generationstop.Fence              `json:"fence"`
	Owner                    generationstop.ProviderOwner      `json:"owner"`
	Workspace                ProviderWorkspaceV1               `json:"workspace"`
}

type ProviderWorkspaceV1 struct {
	ExpectedProfile     string `json:"expectedProfile"`
	ExpectedRuntimeKind string `json:"expectedRuntimeKind"`
	ProviderResourceID  string `json:"providerResourceId"`
	TenantID            string `json:"tenantId"`
	UserID              string `json:"userId"`
	WorkspaceID         string `json:"workspaceId"`
}

func (workspace ProviderWorkspaceV1) providerSource() generationstop.Source {
	return generationstop.Source{
		ProviderResourceID:  workspace.ProviderResourceID,
		ExpectedProfile:     workspace.ExpectedProfile,
		ExpectedRuntimeKind: workspace.ExpectedRuntimeKind,
	}
}

type CaseSampleSetV1 struct {
	CaseRef string           `json:"caseRef"`
	Samples []SampleSourceV1 `json:"samples"`
}

type SampleSourceV1 struct {
	SampleRef string           `json:"sampleRef"`
	Source    SourceIdentityV1 `json:"source"`
}

type SourceIdentityV1 struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Ref       string `json:"ref"`
}

type EvaluationCorpusV1 struct {
	Cases                       []EvaluationCaseV1  `json:"cases"`
	Contract                    string              `json:"contract"`
	CorpusRef                   string              `json:"corpusRef"`
	Digest                      string              `json:"digest"`
	Inputs                      []EvaluationInputV1 `json:"inputs"`
	ManifestDigest              string              `json:"manifestDigest"`
	ManifestRef                 string              `json:"manifestRef"`
	RequiredRuntimeCapabilities []string            `json:"requiredRuntimeCapabilities"`
	Revision                    int                 `json:"revision"`
	SkillDigest                 string              `json:"skillDigest"`
	SkillRef                    string              `json:"skillRef"`
}

type EvaluationInputV1 struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Ref       string `json:"ref"`
	Role      string `json:"role"`
}

type EvaluationCorpusAssetV1 struct {
	Body      string `json:"body"`
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Ref       string `json:"ref"`
	Role      string `json:"role"`
}

type EvaluationCaseV1 struct {
	CaseRef              string   `json:"caseRef"`
	ExpectedProperties   []string `json:"expectedProperties"`
	InputRefs            []string `json:"inputRefs"`
	MeasurementClass     string   `json:"measurementClass"`
	Metric               string   `json:"metric"`
	Scenario             string   `json:"scenario"`
	ThresholdBasisPoints int      `json:"thresholdBasisPoints"`
}

type InlineArtifactV2 struct {
	Base64     string `json:"base64"`
	ByteLength int64  `json:"byteLength"`
	Digest     string `json:"digest"`
	MediaType  string `json:"mediaType"`
	Ref        string `json:"ref"`
}

type SampleJourneyV2 struct {
	SampleRef string           `json:"sampleRef"`
	Stages    []JourneyStageV2 `json:"stages"`
}

type JourneyStageV2 struct {
	Artifact InlineArtifactV2 `json:"artifact"`
	Lineage  *StageLineageV1  `json:"lineage"`
	Stage    string           `json:"stage"`
}

type StageLineageV1 struct {
	Action         string                 `json:"action"`
	Contract       string                 `json:"contract"`
	Digest         string                 `json:"digest"`
	Input          StageLineageEndpointV1 `json:"input"`
	ObservedAt     string                 `json:"observedAt"`
	Output         StageLineageEndpointV1 `json:"output"`
	RawEvidence    []InlineArtifactV2     `json:"rawEvidence"`
	VerifiedClaims []string               `json:"verifiedClaims"`
}

type StageLineageEndpointV1 struct {
	Artifact specialistrender.Pin `json:"artifact"`
	Stage    string               `json:"stage"`
}

type RenderCommandAuthorityV2 struct {
	Candidate          specialistrender.Pin     `json:"candidate"`
	ExecutablePath     string                   `json:"executablePath"`
	Facet              string                   `json:"facet"`
	Operation          string                   `json:"operation"`
	Output             RenderTemplateOutputV2   `json:"output"`
	PackRequiredChecks []RenderLabeledCheckV2   `json:"packRequiredChecks"`
	Renderer           RenderTemplateRendererV2 `json:"renderer"`
	Runtime            RenderTemplateRuntimeV2  `json:"runtime"`
}

type RenderTemplateOutputV2 struct {
	JobRoot                     string `json:"jobRoot"`
	MaximumAggregateImagePixels int64  `json:"maximumAggregateImagePixels"`
	MaximumImagePixels          int64  `json:"maximumImagePixels"`
	MaximumPreviewBytes         int64  `json:"maximumPreviewBytes"`
	PreviewMediaType            string `json:"previewMediaType"`
}

type RenderTemplateRendererV2 struct {
	RenderMode          string  `json:"renderMode"`
	RendererRef         string  `json:"rendererRef"`
	Representation      string  `json:"representation"`
	SourceSchemaURI     *string `json:"sourceSchemaUri"`
	ValidationPolicyRef string  `json:"validationPolicyRef"`
}

type RenderTemplateRuntimeV2 struct {
	PackRevisions              []specialistrender.Pin `json:"packRevisions"`
	ProfileRevision            specialistrender.Pin   `json:"profileRevision"`
	RuntimeClosure             specialistrender.Pin   `json:"runtimeClosure"`
	WorkspaceExecutionManifest specialistrender.Pin   `json:"workspaceExecutionManifest"`
}

type JourneyPlanV2 struct {
	CheckDerivations      []CheckDerivationV2  `json:"checkDerivations"`
	MetricDerivations     []MetricDerivationV2 `json:"metricDerivations"`
	Relations             []JourneyRelationV2  `json:"relations"`
	RequireEveryPackCheck bool                 `json:"requireEveryPackCheck"`
	RequiredStages        []string             `json:"requiredStages"`
}

type CheckDerivationV2 struct {
	Check  string `json:"check"`
	Source string `json:"source"`
}

type MetricDerivationV2 struct {
	Metric  string   `json:"metric"`
	Sources []string `json:"sources"`
}

type JourneyRelationV2 struct {
	LeftStage  string `json:"leftStage"`
	Relation   string `json:"relation"`
	RightStage string `json:"rightStage"`
}

type SamplePolicyV2 struct {
	MaximumSamples int `json:"maximumSamples"`
	MinimumSamples int `json:"minimumSamples"`
}

type PhysicalCaseObservationV2 struct {
	CaseRef             string                         `json:"caseRef"`
	Contract            string                         `json:"contract"`
	DeterministicChecks []DeterministicObservationV1   `json:"deterministicChecks"`
	Digest              string                         `json:"digest"`
	EvaluationArtifacts []PhysicalEvaluationArtifactV1 `json:"evaluationArtifacts"`
	FailureModes        []EvaluationFailureModeV1      `json:"failureModes"`
	ObservedAt          string                         `json:"observedAt"`
	Outcome             string                         `json:"outcome"`
	Properties          []PropertyObservationV1        `json:"properties"`
	Rates               []RateObservationV1            `json:"rates"`
	RequestDigest       string                         `json:"requestDigest"`
	Samples             []PhysicalSampleV2             `json:"samples"`
}

type PhysicalSampleV2 struct {
	SampleRef string                   `json:"sampleRef"`
	Stages    []PhysicalJourneyStageV2 `json:"stages"`
}

type PhysicalJourneyStageV2 struct {
	Artifact                SourceIdentityV1         `json:"artifact"`
	Evaluation              StageEvaluationV2        `json:"evaluation"`
	MaterializationEvidence specialistrender.Pin     `json:"materializationEvidence"`
	ProviderReceipt         specialistrender.Receipt `json:"providerReceipt"`
	RenderRequest           RenderCommandV2          `json:"renderRequest"`
	Stage                   string                   `json:"stage"`
}

type StageEvaluationV2 struct {
	Checks               []StageCheckEvaluationV2
	CommandDigest        string
	Outcome              string
	Preview              *StagePreviewEvaluationV2
	ResultDocumentDigest string
	ResultFileSHA256     string
	StageRef             string
}

type resultBearingStageEvaluationWireV2 struct {
	Checks               []StageCheckEvaluationV2  `json:"checks"`
	CommandDigest        string                    `json:"commandDigest"`
	Outcome              string                    `json:"outcome"`
	Preview              *StagePreviewEvaluationV2 `json:"preview"`
	ResultDocumentDigest string                    `json:"resultDocumentDigest"`
	ResultFileSHA256     string                    `json:"resultFileSha256"`
	StageRef             string                    `json:"stageRef"`
}

type receiptOnlyStageEvaluationWireV2 struct {
	CommandDigest string `json:"commandDigest"`
	Outcome       string `json:"outcome"`
	StageRef      string `json:"stageRef"`
}

func (evaluation *StageEvaluationV2) UnmarshalJSON(encoded []byte) error {
	var discriminator struct {
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(encoded, &discriminator); err != nil {
		return err
	}
	switch discriminator.Outcome {
	case "succeeded", "failed":
		var wire resultBearingStageEvaluationWireV2
		if err := generationstop.DecodeExactJSON(encoded, &wire); err != nil {
			return fmt.Errorf("decode result-bearing C18 stage evaluation: %w", err)
		}
		*evaluation = StageEvaluationV2{
			Checks: wire.Checks, CommandDigest: wire.CommandDigest, Outcome: wire.Outcome,
			Preview: wire.Preview, ResultDocumentDigest: wire.ResultDocumentDigest,
			ResultFileSHA256: wire.ResultFileSHA256, StageRef: wire.StageRef,
		}
		return nil
	case "cancelled", "timed_out":
		var wire receiptOnlyStageEvaluationWireV2
		if err := generationstop.DecodeExactJSON(encoded, &wire); err != nil {
			return fmt.Errorf("decode receipt-only C18 stage evaluation: %w", err)
		}
		*evaluation = StageEvaluationV2{
			CommandDigest: wire.CommandDigest, Outcome: wire.Outcome, StageRef: wire.StageRef,
		}
		return nil
	default:
		return fmt.Errorf("C18 stage evaluation outcome is invalid")
	}
}

func (evaluation StageEvaluationV2) MarshalJSON() ([]byte, error) {
	switch evaluation.Outcome {
	case "succeeded", "failed":
		if evaluation.Checks == nil {
			return nil, fmt.Errorf("result-bearing C18 stage evaluation check roster is null")
		}
		return json.Marshal(resultBearingStageEvaluationWireV2{
			Checks: evaluation.Checks, CommandDigest: evaluation.CommandDigest,
			Outcome: evaluation.Outcome, Preview: evaluation.Preview,
			ResultDocumentDigest: evaluation.ResultDocumentDigest,
			ResultFileSHA256:     evaluation.ResultFileSHA256, StageRef: evaluation.StageRef,
		})
	case "cancelled", "timed_out":
		if evaluation.Checks != nil || evaluation.Preview != nil ||
			evaluation.ResultDocumentDigest != "" || evaluation.ResultFileSHA256 != "" {
			return nil, fmt.Errorf("receipt-only C18 stage evaluation contains hidden result evidence")
		}
		return json.Marshal(receiptOnlyStageEvaluationWireV2{
			CommandDigest: evaluation.CommandDigest, Outcome: evaluation.Outcome,
			StageRef: evaluation.StageRef,
		})
	default:
		return nil, fmt.Errorf("C18 stage evaluation outcome is invalid")
	}
}

type StagePreviewEvaluationV2 struct {
	EnvelopeDigest string `json:"envelopeDigest"`
	FileSHA256     string `json:"fileSha256"`
}

type StageCheckEvaluationV2 struct {
	Artifacts              []StageArtifactEvaluationV2 `json:"artifacts"`
	Check                  string                      `json:"check"`
	EvidenceDocumentDigest string                      `json:"evidenceDocumentDigest"`
	EvidenceFileSHA256     string                      `json:"evidenceFileSha256"`
	EvidencePath           string                      `json:"evidencePath"`
	Outcome                string                      `json:"outcome"`
}

type StageArtifactEvaluationV2 struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type PropertyObservationV1 struct {
	Outcome  string `json:"outcome"`
	Property string `json:"property"`
}

type DeterministicObservationV1 struct {
	Check   string `json:"check"`
	Outcome string `json:"outcome"`
}

type RateObservationV1 struct {
	MeasurementClass     string `json:"measurementClass"`
	Metric               string `json:"metric"`
	PassedSamples        int    `json:"passedSamples"`
	ThresholdBasisPoints int    `json:"thresholdBasisPoints"`
	TotalSamples         int    `json:"totalSamples"`
}

type EvaluationFailureModeV1 struct {
	Code     string                `json:"code"`
	Evidence *specialistrender.Pin `json:"evidence"`
}

type PhysicalEvaluationArtifactV1 struct {
	Base64     string   `json:"base64"`
	ByteLength int64    `json:"byteLength"`
	MediaType  string   `json:"mediaType"`
	Ref        string   `json:"ref"`
	Role       string   `json:"role"`
	SampleRefs []string `json:"sampleRefs"`
	SHA256     string   `json:"sha256"`
}

type PhysicalEvaluationReportV1 struct {
	CaseRef             string                       `json:"caseRef"`
	Contract            string                       `json:"contract"`
	DeterministicChecks []DeterministicObservationV1 `json:"deterministicChecks"`
	FailureModes        []EvaluationFailureModeV1    `json:"failureModes"`
	Outcome             string                       `json:"outcome"`
	Properties          []PropertyObservationV1      `json:"properties"`
	Rates               []RateObservationV1          `json:"rates"`
	RequestDigest       string                       `json:"requestDigest"`
	SampleRefs          []string                     `json:"sampleRefs"`
	StageEvaluations    []PhysicalReportStageV1      `json:"stageEvaluations"`
	SubjectArtifact     specialistrender.Pin         `json:"subjectArtifact"`
}

type PhysicalReportStageV1 struct {
	Evaluation StageEvaluationV2 `json:"evaluation"`
	SampleRef  string            `json:"sampleRef"`
	Stage      string            `json:"stage"`
}
