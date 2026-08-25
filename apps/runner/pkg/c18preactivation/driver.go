// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

type DriverClock interface {
	Now() time.Time
}

type systemDriverClock struct{}

func (systemDriverClock) Now() time.Time { return time.Now() }

type PhysicalDriver struct {
	provider StreamingSpecialistRenderProvider
	clock    DriverClock
}

func NewPhysicalDriver(
	provider StreamingSpecialistRenderProvider,
	clock DriverClock,
) (*PhysicalDriver, error) {
	if provider == nil {
		return nil, errors.New("C18 physical driver provider is unavailable")
	}
	if clock == nil {
		clock = systemDriverClock{}
	}
	return &PhysicalDriver{provider: provider, clock: clock}, nil
}

func (driver *PhysicalDriver) Evaluate(
	ctx context.Context,
	request PhysicalCaseRequestV2,
) (PhysicalCaseObservationV2, error) {
	if driver == nil || driver.provider == nil || driver.clock == nil {
		return PhysicalCaseObservationV2{}, errors.New("C18 physical driver is unavailable")
	}
	if err := validatePhysicalCaseRequestV2(request); err != nil {
		return PhysicalCaseObservationV2{}, err
	}
	if err := ctx.Err(); err != nil {
		return PhysicalCaseObservationV2{}, err
	}
	now := exactDriverNow(driver.clock)
	if now.IsZero() || !now.Before(request.ExpiresAt()) {
		return PhysicalCaseObservationV2{}, errors.New("C18 physical request binding is expired")
	}
	evaluationCtx, cancel := context.WithTimeout(ctx, request.ExpiresAt().Sub(now))
	defer cancel()
	samples := make([]PhysicalSampleV2, len(request.SampleJourneys))
	for sampleIndex, journey := range request.SampleJourneys {
		stages := make([]PhysicalJourneyStageV2, len(journey.Stages))
		for stageIndex, stage := range journey.Stages {
			if err := evaluationCtx.Err(); err != nil {
				return PhysicalCaseObservationV2{}, err
			}
			materialized, err := MaterializeRenderStageV2(
				request, journey.SampleRef, stage.Stage, request.Binding.ExpiresAt,
			)
			if err != nil {
				return PhysicalCaseObservationV2{}, err
			}
			providerInput := ProviderInputForRenderStage(request, materialized)
			expectedRequest, exactCommandBytes, exactSourceBytes, err := ProviderRequest(providerInput)
			if err != nil {
				return PhysicalCaseObservationV2{}, err
			}
			providerInput.RequestBytes = exactCommandBytes
			providerInput.SourceBytes = exactSourceBytes
			custody, err := NewTemporaryProviderResponseCustody()
			if err != nil {
				return PhysicalCaseObservationV2{}, err
			}
			boundedCustody, err := newRenderBoundedResponseCustody(custody, materialized.Command)
			if err != nil {
				return PhysicalCaseObservationV2{}, abortAndCleanupCustody(evaluationCtx, custody, err)
			}
			response, executeErr := driver.provider.ExecuteToCustody(evaluationCtx, providerInput, boundedCustody)
			receipt, settlementErr := settledReceipt(response, executeErr)
			if settlementErr != nil {
				return PhysicalCaseObservationV2{}, abortAndCleanupCustody(evaluationCtx, custody, settlementErr)
			}
			var evaluation StageEvaluationV2
			switch receipt.Outcome {
			case "succeeded", "failed":
				admitted, err := AdmitRenderCustody(
					exactCommandBytes, exactSourceBytes,
					expectedRequest, receipt, custody,
				)
				if err != nil {
					return PhysicalCaseObservationV2{}, abortAndCleanupCustody(evaluationCtx, custody, err)
				}
				evaluation = admitted.Evaluation
			case "cancelled", "timed_out":
				evaluation, err = AdmitReceiptOnlyRenderStage(
					exactCommandBytes, exactSourceBytes, expectedRequest, receipt,
				)
				if err != nil {
					return PhysicalCaseObservationV2{}, abortAndCleanupCustody(evaluationCtx, custody, err)
				}
			default:
				return PhysicalCaseObservationV2{}, abortAndCleanupCustody(
					evaluationCtx, custody, errors.New("C18 provider returned an unknown settlement"),
				)
			}
			if err := custody.Cleanup(); err != nil {
				return PhysicalCaseObservationV2{}, err
			}
			artifact := SourceIdentityV1{
				Ref: stage.Artifact.Ref, Digest: stage.Artifact.Digest, MediaType: stage.Artifact.MediaType,
			}
			materializationEvidence, err := MaterializationEvidencePinV2(
				request, journey.SampleRef, stage.Stage, artifact, expectedRequest.RequestDigest,
			)
			if err != nil {
				return PhysicalCaseObservationV2{}, err
			}
			stages[stageIndex] = PhysicalJourneyStageV2{
				Artifact: artifact, Evaluation: evaluation,
				MaterializationEvidence: materializationEvidence,
				ProviderReceipt:         receipt, RenderRequest: materialized.Command, Stage: stage.Stage,
			}
		}
		samples[sampleIndex] = PhysicalSampleV2{SampleRef: journey.SampleRef, Stages: stages}
	}
	return createPhysicalObservation(request, samples, exactDriverNow(driver.clock))
}

func abortAndCleanupCustody(
	ctx context.Context,
	custody *TemporaryProviderResponseCustody,
	cause error,
) error {
	return errors.Join(cause, custody.Abort(ctx), custody.Cleanup())
}

func settledReceipt(
	response ProviderResponseObservation,
	executeErr error,
) (specialistrender.Receipt, error) {
	if executeErr == nil {
		return response.Receipt, nil
	}
	var settlement *ProviderSettlementError
	if errors.As(executeErr, &settlement) && settlement.Kind == "complete_output_unadmitted" &&
		settlement.Observation != nil && settlement.Observation.Receipt != nil {
		receipt := *settlement.Observation.Receipt
		if receipt.Outcome == "cancelled" || receipt.Outcome == "timed_out" {
			return receipt, nil
		}
	}
	return specialistrender.Receipt{}, executeErr
}

func createPhysicalObservation(
	request PhysicalCaseRequestV2,
	samples []PhysicalSampleV2,
	observedAt time.Time,
) (PhysicalCaseObservationV2, error) {
	if !observedAt.Before(request.ExpiresAt()) {
		return PhysicalCaseObservationV2{}, errors.New("C18 physical observation is outside its binding")
	}
	providerFailed := false
	stageCheckFailed := false
	for _, sample := range samples {
		for _, stage := range sample.Stages {
			completed, err := time.Parse("2006-01-02T15:04:05.000Z", stage.ProviderReceipt.CompletedAt)
			if err != nil || completed.After(observedAt) {
				return PhysicalCaseObservationV2{}, errors.New("C18 provider completion is future-dated")
			}
			if stage.ProviderReceipt.Outcome != "succeeded" {
				providerFailed = true
			}
			for _, check := range stage.Evaluation.Checks {
				if check.Outcome != "passed" {
					stageCheckFailed = true
				}
			}
		}
	}
	properties := make([]PropertyObservationV1, len(request.EvaluationCase.ExpectedProperties))
	deterministic := make([]DeterministicObservationV1, len(request.DeterministicChecks))
	rates := make([]RateObservationV1, len(request.MeasuredMetrics))
	derivationFailed := false
	if request.EvaluationCase.MeasurementClass == "deterministic" {
		for index, derivation := range request.JourneyPlan.CheckDerivations {
			passed := everySampleDerives(request, samples, derivation.Check, []string{derivation.Source})
			deterministic[index] = DeterministicObservationV1{
				Check: derivation.Check, Outcome: passFail(passed),
			}
			derivationFailed = derivationFailed || !passed
		}
	} else {
		for index, derivation := range request.JourneyPlan.MetricDerivations {
			passed := 0
			for sampleIndex := range samples {
				if sampleDerives(request, samples[sampleIndex], derivation.Metric, derivation.Sources) {
					passed++
				}
			}
			rates[index] = RateObservationV1{
				Metric: derivation.Metric, MeasurementClass: "measured", PassedSamples: passed,
				TotalSamples: len(samples), ThresholdBasisPoints: request.EvaluationCase.ThresholdBasisPoints,
			}
			if passed*10_000 < request.EvaluationCase.ThresholdBasisPoints*len(samples) {
				derivationFailed = true
			}
		}
	}
	propertiesPass := !providerFailed && !stageCheckFailed && !derivationFailed
	for index, property := range request.EvaluationCase.ExpectedProperties {
		properties[index] = PropertyObservationV1{Property: property, Outcome: passFail(propertiesPass)}
	}
	failureCodes := make([]string, 0, 3)
	if derivationFailed {
		failureCodes = append(failureCodes, "journey_derivation_failed")
	}
	if providerFailed {
		failureCodes = append(failureCodes, "provider_execution_not_succeeded")
	}
	if stageCheckFailed {
		failureCodes = append(failureCodes, "provider_stage_check_not_passed")
	}
	sort.Strings(failureCodes)
	failureModes := make([]EvaluationFailureModeV1, len(failureCodes))
	for index, code := range failureCodes {
		failureModes[index] = EvaluationFailureModeV1{Code: code, Evidence: nil}
	}
	outcome := "passed"
	if len(failureModes) != 0 {
		outcome = "failed"
	}
	report := PhysicalEvaluationReportV1{
		Contract: PhysicalEvaluationReportContractV1, RequestDigest: request.Digest,
		CaseRef: request.EvaluationCase.CaseRef, SubjectArtifact: request.Binding.SubjectArtifact,
		SampleRefs: make([]string, len(samples)), StageEvaluations: make([]PhysicalReportStageV1, 0),
		Properties: properties, DeterministicChecks: deterministic, Rates: rates,
		FailureModes: failureModes, Outcome: outcome,
	}
	for index, sample := range samples {
		report.SampleRefs[index] = sample.SampleRef
		for _, stage := range sample.Stages {
			report.StageEvaluations = append(report.StageEvaluations, PhysicalReportStageV1{
				SampleRef: sample.SampleRef, Stage: stage.Stage, Evaluation: stage.Evaluation,
			})
		}
	}
	reportBytes, err := generationstop.CanonicalJSON(report)
	if err != nil || len(reportBytes) == 0 || len(reportBytes) > 512*1024 {
		return PhysicalCaseObservationV2{}, errors.New("C18 physical evaluation report exceeds its bound")
	}
	evaluationArtifact := PhysicalEvaluationArtifactV1{
		Base64: base64.StdEncoding.EncodeToString(reportBytes), ByteLength: int64(len(reportBytes)),
		MediaType: "application/json",
		Ref:       "ambit://skill-evaluation-evidence/" + request.Digest[len("sha256:"):],
		Role:      "case_evaluation_report", SampleRefs: report.SampleRefs, SHA256: sha256Digest(reportBytes),
	}
	observation := PhysicalCaseObservationV2{
		CaseRef: request.EvaluationCase.CaseRef, Contract: PhysicalCaseObservationContractV2,
		DeterministicChecks: deterministic, EvaluationArtifacts: []PhysicalEvaluationArtifactV1{evaluationArtifact},
		FailureModes: failureModes, ObservedAt: formatDriverTime(observedAt), Outcome: outcome,
		Properties: properties, Rates: rates, RequestDigest: request.Digest, Samples: samples,
	}
	observation.Digest, err = sealedDigest(observation)
	if err != nil {
		return PhysicalCaseObservationV2{}, err
	}
	return observation, nil
}

func everySampleDerives(
	request PhysicalCaseRequestV2,
	samples []PhysicalSampleV2,
	claim string,
	sources []string,
) bool {
	for _, sample := range samples {
		if !sampleDerives(request, sample, claim, sources) {
			return false
		}
	}
	return true
}

func sampleDerives(
	request PhysicalCaseRequestV2,
	sample PhysicalSampleV2,
	claim string,
	sources []string,
) bool {
	for _, source := range sources {
		switch source {
		case "pack_check":
			for _, stage := range sample.Stages {
				if stage.ProviderReceipt.Outcome != "succeeded" || len(stage.Evaluation.Checks) != len(request.RenderCommandAuthority.PackRequiredChecks) {
					return false
				}
				for _, check := range stage.Evaluation.Checks {
					if check.Outcome != "passed" {
						return false
					}
				}
			}
		case "byte_relation":
			journey := requestJourney(request, sample.SampleRef)
			if journey == nil {
				return false
			}
			for _, relation := range request.JourneyPlan.Relations {
				left := journeyStage(journey.Stages, relation.LeftStage)
				right := journeyStage(journey.Stages, relation.RightStage)
				if left == nil || right == nil ||
					((left.Artifact.Digest == right.Artifact.Digest) != (relation.Relation == "equal_digest")) {
					return false
				}
			}
		case "action_lineage_claim":
			journey := requestJourney(request, sample.SampleRef)
			count := 0
			if journey != nil {
				for _, stage := range journey.Stages {
					if stage.Lineage != nil && containsStringInOrder(stage.Lineage.VerifiedClaims, claim) {
						count++
					}
				}
			}
			if count != 1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func requestJourney(request PhysicalCaseRequestV2, sampleRef string) *SampleJourneyV2 {
	for index := range request.SampleJourneys {
		if request.SampleJourneys[index].SampleRef == sampleRef {
			return &request.SampleJourneys[index]
		}
	}
	return nil
}

func passFail(passed bool) string {
	if passed {
		return "passed"
	}
	return "failed"
}

func exactDriverNow(clock DriverClock) time.Time {
	value := clock.Now()
	if value.Location() == nil || value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Truncate(time.Millisecond)
}

func formatDriverTime(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}
