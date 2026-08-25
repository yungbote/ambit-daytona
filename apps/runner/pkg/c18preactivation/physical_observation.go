// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

type projectedStageFile struct {
	Path   string `json:"path"`
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
}

func ParsePhysicalCaseObservationV2(
	encoded []byte,
	request PhysicalCaseRequestV2,
) (PhysicalCaseObservationV2, error) {
	if len(encoded) < 2 || len(encoded) > maximumPhysicalResponseBytes {
		return PhysicalCaseObservationV2{}, errors.New("C18 physical observation bytes exceed their bound")
	}
	if err := validatePhysicalCaseRequestV2(request); err != nil {
		return PhysicalCaseObservationV2{}, err
	}
	var observation PhysicalCaseObservationV2
	if err := generationstop.DecodeCanonicalJSON(encoded, &observation); err != nil {
		return PhysicalCaseObservationV2{}, fmt.Errorf("decode C18 physical observation: %w", err)
	}
	if observation.Contract != PhysicalCaseObservationContractV2 ||
		observation.RequestDigest != request.Digest || observation.CaseRef != request.EvaluationCase.CaseRef ||
		observation.DeterministicChecks == nil || observation.EvaluationArtifacts == nil ||
		observation.FailureModes == nil || observation.Properties == nil ||
		observation.Rates == nil || observation.Samples == nil ||
		!exactMillisecondInstant(observation.ObservedAt) || observation.ObservedAt >= request.Binding.ExpiresAt {
		return PhysicalCaseObservationV2{}, errors.New("C18 physical observation authority is invalid")
	}
	if err := verifySealedDigest(observation, observation.Digest); err != nil {
		return PhysicalCaseObservationV2{}, err
	}
	if err := validatePhysicalSamples(observation, request); err != nil {
		return PhysicalCaseObservationV2{}, err
	}
	if err := validatePhysicalResults(observation, request); err != nil {
		return PhysicalCaseObservationV2{}, err
	}
	if err := validatePhysicalReport(observation, request); err != nil {
		return PhysicalCaseObservationV2{}, err
	}
	return observation, nil
}

func validatePhysicalSamples(
	observation PhysicalCaseObservationV2,
	request PhysicalCaseRequestV2,
) error {
	if len(observation.Samples) != len(request.SampleJourneys) {
		return errors.New("C18 physical observation sample roster is incomplete")
	}
	observedAt, _ := time.Parse("2006-01-02T15:04:05.000Z", observation.ObservedAt)
	operationIDs := make(map[string]struct{})
	for sampleIndex, sample := range observation.Samples {
		journey := request.SampleJourneys[sampleIndex]
		if sample.Stages == nil || sample.SampleRef != journey.SampleRef || len(sample.Stages) != len(journey.Stages) {
			return errors.New("C18 physical observation changed a sample journey")
		}
		for stageIndex, stage := range sample.Stages {
			expectedStage := journey.Stages[stageIndex]
			artifact := SourceIdentityV1{
				Ref: expectedStage.Artifact.Ref, Digest: expectedStage.Artifact.Digest,
				MediaType: expectedStage.Artifact.MediaType,
			}
			if stage.Stage != expectedStage.Stage || stage.Artifact != artifact {
				return errors.New("C18 physical observation changed a stage artifact")
			}
			materialized, err := MaterializeRenderStageV2(
				request, sample.SampleRef, stage.Stage, stage.RenderRequest.DeadlineAt,
			)
			if err != nil || !canonicalEqual(materialized.Command, stage.RenderRequest) {
				return errors.New("C18 physical observation changed a render command")
			}
			expectedRequest, _, _, err := ProviderRequest(ProviderInputForRenderStage(request, materialized))
			if err != nil || specialistrender.ValidateReceipt(stage.ProviderReceipt) != nil ||
				!canonicalEqual(stage.ProviderReceipt.Request, expectedRequest) {
				return errors.New("C18 physical observation changed provider authority")
			}
			completed, err := time.Parse("2006-01-02T15:04:05.000Z", stage.ProviderReceipt.CompletedAt)
			if err != nil || completed.After(observedAt) || stage.RenderRequest.DeadlineAt < stage.ProviderReceipt.CompletedAt {
				return errors.New("C18 physical stage chronology is invalid")
			}
			if _, duplicate := operationIDs[expectedRequest.OperationID]; duplicate {
				return errors.New("C18 physical provider operation IDs are not unique")
			}
			operationIDs[expectedRequest.OperationID] = struct{}{}
			expectedMaterialization, err := MaterializationEvidencePinV2(
				request, sample.SampleRef, stage.Stage, artifact, expectedRequest.RequestDigest,
			)
			if err != nil || stage.MaterializationEvidence != expectedMaterialization {
				return errors.New("C18 physical stage materialization evidence is invalid")
			}
			if err := validateStageEvaluationSummary(stage, materialized.Command); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateStageEvaluationSummary(
	stage PhysicalJourneyStageV2,
	command RenderCommandV2,
) error {
	evaluation := stage.Evaluation
	receipt := stage.ProviderReceipt
	if evaluation.StageRef != "ambit://skill-evaluations/c18-preactivation/stages/"+receipt.Request.OperationID ||
		evaluation.CommandDigest != command.Digest || evaluation.Outcome != receipt.Outcome {
		return errors.New("C18 physical stage evaluation identity is invalid")
	}
	if evaluation.Outcome == "cancelled" || evaluation.Outcome == "timed_out" {
		if len(receipt.Files) != 0 || receipt.TotalOutputBytes != 0 || len(evaluation.Checks) != 0 ||
			evaluation.ResultDocumentDigest != "" || evaluation.ResultFileSHA256 != "" || evaluation.Preview != nil {
			return errors.New("C18 receipt-only stage grew result-bearing evidence")
		}
		return nil
	}
	if evaluation.Outcome != "succeeded" && evaluation.Outcome != "failed" {
		return errors.New("C18 physical stage evaluation outcome is invalid")
	}
	if evaluation.Checks == nil || !exactSHA256.MatchString(evaluation.ResultDocumentDigest) ||
		!exactSHA256.MatchString(evaluation.ResultFileSHA256) ||
		len(evaluation.Checks) != len(command.PackRequiredChecks) {
		return errors.New("C18 result-bearing stage evaluation is incomplete")
	}
	expected := make(map[string]projectedStageFile)
	add := func(file projectedStageFile) error {
		if prior, exists := expected[file.Path]; exists && prior != file {
			return errors.New("C18 stage output path has conflicting evidence")
		}
		expected[file.Path] = file
		return nil
	}
	_ = add(projectedStageFile{Path: command.Output.ResultPath, Role: "result", SHA256: evaluation.ResultFileSHA256})
	if evaluation.Preview != nil {
		if !exactSHA256.MatchString(evaluation.Preview.FileSHA256) ||
			!exactSHA256.MatchString(evaluation.Preview.EnvelopeDigest) {
			return errors.New("C18 stage preview summary is invalid")
		}
		_ = add(projectedStageFile{Path: command.Output.PreviewPath, Role: "preview", SHA256: evaluation.Preview.FileSHA256})
	}
	for index, check := range evaluation.Checks {
		if check.Artifacts == nil || check.Check != command.PackRequiredChecks[index].Check ||
			(check.Outcome != "passed" && check.Outcome != "failed" && check.Outcome != "blocked") ||
			!exactSHA256.MatchString(check.EvidenceDocumentDigest) ||
			!exactSHA256.MatchString(check.EvidenceFileSHA256) || !safeZonePath(check.EvidencePath, "outputs") {
			return errors.New("C18 stage check summary is invalid")
		}
		if err := add(projectedStageFile{Path: check.EvidencePath, Role: "evidence", SHA256: check.EvidenceFileSHA256}); err != nil {
			return err
		}
		artifactPaths := make([]string, len(check.Artifacts))
		for artifactIndex, artifact := range check.Artifacts {
			if !safeZonePath(artifact.Path, "outputs") || !exactSHA256.MatchString(artifact.SHA256) {
				return errors.New("C18 stage evidence artifact summary is invalid")
			}
			artifactPaths[artifactIndex] = artifact.Path
			if err := add(projectedStageFile{Path: artifact.Path, Role: "artifact", SHA256: artifact.SHA256}); err != nil {
				return err
			}
		}
		if !sortedUnique(artifactPaths) {
			return errors.New("C18 stage evidence artifacts are not sorted and unique")
		}
	}
	actual := make(map[string]projectedStageFile, len(receipt.Files))
	for _, file := range receipt.Files {
		actual[file.Path] = projectedStageFile{Path: file.Path, Role: file.Role, SHA256: file.Digest}
	}
	if !canonicalEqual(sortedProjectedFiles(expected), sortedProjectedFiles(actual)) ||
		(evaluation.Outcome == "succeeded" &&
			(evaluation.Preview == nil || anyStageCheckFailed(evaluation.Checks))) {
		return errors.New("C18 stage summary differs from provider output custody")
	}
	return nil
}

func sortedProjectedFiles(values map[string]projectedStageFile) []projectedStageFile {
	result := make([]projectedStageFile, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Path < result[right].Path })
	return result
}

func anyStageCheckFailed(checks []StageCheckEvaluationV2) bool {
	for _, check := range checks {
		if check.Outcome != "passed" {
			return true
		}
	}
	return false
}

func validatePhysicalResults(
	observation PhysicalCaseObservationV2,
	request PhysicalCaseRequestV2,
) error {
	if len(observation.Properties) != len(request.EvaluationCase.ExpectedProperties) ||
		len(observation.DeterministicChecks) != len(request.DeterministicChecks) ||
		len(observation.Rates) != len(request.MeasuredMetrics) {
		return errors.New("C18 physical observation result rosters are incomplete")
	}
	for index, property := range observation.Properties {
		if property.Property != request.EvaluationCase.ExpectedProperties[index] || !passFailOutcome(property.Outcome) {
			return errors.New("C18 physical property observation is invalid")
		}
	}
	for index, check := range observation.DeterministicChecks {
		if check.Check != request.DeterministicChecks[index] || !passFailOutcome(check.Outcome) {
			return errors.New("C18 physical deterministic observation is invalid")
		}
	}
	for index, rate := range observation.Rates {
		if rate.Metric != request.MeasuredMetrics[index] || rate.MeasurementClass != "measured" ||
			rate.TotalSamples != len(observation.Samples) || rate.PassedSamples < 0 ||
			rate.PassedSamples > rate.TotalSamples || rate.ThresholdBasisPoints != request.EvaluationCase.ThresholdBasisPoints {
			return errors.New("C18 physical rate observation is invalid")
		}
	}
	providerFailed := false
	stageCheckFailed := false
	for _, sample := range observation.Samples {
		for _, stage := range sample.Stages {
			providerFailed = providerFailed || stage.ProviderReceipt.Outcome != "succeeded"
			stageCheckFailed = stageCheckFailed || anyStageCheckFailed(stage.Evaluation.Checks)
		}
	}
	passed := !providerFailed && !stageCheckFailed
	for _, property := range observation.Properties {
		passed = passed && property.Outcome == "passed"
	}
	for _, check := range observation.DeterministicChecks {
		passed = passed && check.Outcome == "passed"
	}
	for _, rate := range observation.Rates {
		passed = passed && rate.PassedSamples*10_000 >= rate.ThresholdBasisPoints*rate.TotalSamples
	}
	expectedOutcome := "failed"
	if passed {
		expectedOutcome = "passed"
	}
	failureCodes := make([]string, len(observation.FailureModes))
	for index, failure := range observation.FailureModes {
		if !canonicalTokenValue(failure.Code) || failure.Evidence != nil {
			return errors.New("C18 physical failure mode is invalid")
		}
		failureCodes[index] = failure.Code
	}
	if !sortedUnique(failureCodes) || observation.Outcome != expectedOutcome ||
		(observation.Outcome == "passed") != (len(observation.FailureModes) == 0) {
		return errors.New("C18 physical observation outcome or failures are invalid")
	}
	return nil
}

func validatePhysicalReport(
	observation PhysicalCaseObservationV2,
	request PhysicalCaseRequestV2,
) error {
	if len(observation.EvaluationArtifacts) != 1 {
		return errors.New("C18 physical evaluation report roster is invalid")
	}
	artifact := observation.EvaluationArtifacts[0]
	bytes, err := base64.StdEncoding.Strict().DecodeString(artifact.Base64)
	if err != nil || base64.StdEncoding.EncodeToString(bytes) != artifact.Base64 ||
		artifact.Role != "case_evaluation_report" || artifact.MediaType != "application/json" ||
		artifact.ByteLength < 1 || artifact.ByteLength > 512*1024 || int64(len(bytes)) != artifact.ByteLength ||
		sha256Digest(bytes) != artifact.SHA256 ||
		artifact.Ref != "ambit://skill-evaluation-evidence/"+request.Digest[len("sha256:"):] {
		return errors.New("C18 physical evaluation report bytes are invalid")
	}
	expected := PhysicalEvaluationReportV1{
		Contract: PhysicalEvaluationReportContractV1, RequestDigest: request.Digest,
		CaseRef: request.EvaluationCase.CaseRef, SubjectArtifact: request.Binding.SubjectArtifact,
		SampleRefs: make([]string, len(observation.Samples)), StageEvaluations: make([]PhysicalReportStageV1, 0),
		Properties: observation.Properties, DeterministicChecks: observation.DeterministicChecks,
		Rates: observation.Rates, FailureModes: observation.FailureModes, Outcome: observation.Outcome,
	}
	for index, sample := range observation.Samples {
		expected.SampleRefs[index] = sample.SampleRef
		for _, stage := range sample.Stages {
			expected.StageEvaluations = append(expected.StageEvaluations, PhysicalReportStageV1{
				SampleRef: sample.SampleRef, Stage: stage.Stage, Evaluation: stage.Evaluation,
			})
		}
	}
	if !equalStrings(artifact.SampleRefs, expected.SampleRefs) {
		return errors.New("C18 physical evaluation report sample roster is invalid")
	}
	var report PhysicalEvaluationReportV1
	if err := generationstop.DecodeCanonicalJSON(bytes, &report); err != nil || !canonicalEqual(report, expected) {
		return errors.New("C18 physical evaluation report differs from observation")
	}
	return nil
}

func passFailOutcome(value string) bool { return value == "passed" || value == "failed" }
