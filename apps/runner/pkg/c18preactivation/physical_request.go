// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

func ParsePhysicalCaseRequestV2(encoded []byte) (PhysicalCaseRequestV2, error) {
	if len(encoded) < 2 || len(encoded) > maximumPhysicalRequestBytes {
		return PhysicalCaseRequestV2{}, errors.New("C18 physical request bytes exceed their bound")
	}
	var request PhysicalCaseRequestV2
	if err := generationstop.DecodeCanonicalJSON(encoded, &request); err != nil {
		return PhysicalCaseRequestV2{}, fmt.Errorf("decode C18 physical request: %w", err)
	}
	if err := validatePhysicalCaseRequestV2(request); err != nil {
		return PhysicalCaseRequestV2{}, err
	}
	return request, nil
}

func validatePhysicalCaseRequestV2(request PhysicalCaseRequestV2) error {
	if request.Contract != PhysicalCaseRequestContractV2 {
		return errors.New("C18 physical request contract is invalid")
	}
	if err := verifySealedDigest(request, request.Digest); err != nil {
		return err
	}
	if err := validateEvaluationBinding(request.Binding); err != nil {
		return err
	}
	if err := validateEvaluationCorpus(request); err != nil {
		return err
	}
	if err := validateRenderCommandAuthority(request); err != nil {
		return err
	}
	if err := validateSampleRoster(request); err != nil {
		return err
	}
	if err := validateJourneyPlan(request); err != nil {
		return err
	}
	if err := validateSampleJourneys(request); err != nil {
		return err
	}
	return nil
}

func validateEvaluationBinding(binding EvaluationBindingV1) error {
	if binding.Contract != "C18ArtifactSkillPreactivationEvaluationBinding@1" ||
		!exactMillisecondInstant(binding.ExpiresAt) {
		return errors.New("C18 evaluation binding contract or expiry is invalid")
	}
	if err := verifySealedDigest(binding, binding.Digest); err != nil {
		return err
	}
	for _, pin := range []specialistrender.Pin{binding.Corpus, binding.Skill} {
		if !validIdentityPin(pin.Ref, pin.Digest) {
			return errors.New("C18 evaluation binding contains an invalid identity pin")
		}
	}
	for _, pin := range []specialistrender.Pin{binding.RuntimeClosure, binding.SubjectArtifact} {
		if !validOperationalPin(pin.Ref, pin.Digest) {
			return errors.New("C18 evaluation binding contains an invalid operational pin")
		}
	}
	for _, pin := range []specialistrender.Pin{
		binding.Authority.Candidate, binding.Authority.ProviderPolicy, binding.Authority.Composition,
		binding.Authority.Routing, binding.Authority.Component.Artifact,
		binding.Authority.Component.Interface, binding.Authority.Executor,
	} {
		if !validPin(pin.Ref, pin.Digest) {
			return errors.New("C18 evaluation binding contains an invalid authority pin")
		}
	}
	packID := binding.Authority.Image.PackID
	if !currentCandidatePin(binding.Authority.Candidate) ||
		!canonicalTokenValue(packID) || len(packID) > 64 ||
		binding.Authority.Image.PackRef != "ambit.runtime-pack/"+packID+"@1" ||
		binding.Authority.ProviderPolicy.Ref != "ambit.runtime-provider/specialist-render-"+packID+"@1" ||
		binding.Authority.Executor.Ref != "ambit://specialist-render-executors/"+packID+"@1" ||
		binding.Authority.Component.Artifact.Ref != "ambit.runtime-component-artifact/"+packID+"@1" ||
		binding.Authority.Component.RoleRef != specialistrender.RoleRef ||
		binding.Authority.Component.Interface.Ref != specialistrender.InterfaceRef ||
		!exactSHA256.MatchString(binding.Authority.Image.ConfigDigest) ||
		!printable(binding.Authority.Image.Ref, 1_024) || len(binding.Authority.Image.Ref) > 1_024 ||
		!validImmutableOCIReference(binding.Authority.Image.Ref) {
		return errors.New("C18 evaluation binding physical authority is invalid")
	}
	if len(binding.Authority.SourceAuthorities) == 0 || len(binding.Authority.SourceAuthorities) > 128 ||
		!sortedUniquePins(binding.Authority.SourceAuthorities) {
		return errors.New("C18 evaluation binding source authority roster is invalid")
	}
	target := binding.ProviderTarget
	if target.Workspace.ExpectedRuntimeKind != "full_image_runtime_pack" ||
		!printable(target.Workspace.ProviderResourceID, 512) ||
		len([]byte(target.Workspace.ProviderResourceID)) > 1_024 ||
		!printable(target.Workspace.ExpectedProfile, 512) ||
		len([]byte(target.Workspace.ExpectedProfile)) > 1_024 ||
		!canonicalUUID.MatchString(target.Workspace.TenantID) ||
		!canonicalUUID.MatchString(target.Workspace.UserID) ||
		!canonicalUUID.MatchString(target.Workspace.WorkspaceID) ||
		target.Owner.TenantID != target.Workspace.TenantID ||
		target.Owner.UserID != target.Workspace.UserID ||
		target.Owner.WorkspaceID != target.Workspace.WorkspaceID ||
		!canonicalUUID.MatchString(target.Owner.RunID) || !canonicalUUID.MatchString(target.Owner.GrantID) ||
		!workspaceManifestAuthorityRef.MatchString(target.Fence.WorkspaceExecutionManifestRef) ||
		!exactHex64.MatchString(target.ExpectedParentGeneration.ContainerID) ||
		!exactMillisecondInstant(target.ExpectedParentGeneration.ContainerCreatedAt) ||
		!exactMillisecondInstant(target.ExpectedParentGeneration.ExecutionStartedAt) ||
		target.ExpectedParentGeneration.RestartCount < 0 ||
		target.ExpectedParentGeneration.RestartCount > 2_147_483_647 {
		return errors.New("C18 evaluation binding provider target is invalid")
	}
	if target.ExpectedParentGeneration.ExecutionStartedAt < target.ExpectedParentGeneration.ContainerCreatedAt ||
		binding.ExpiresAt <= target.ExpectedParentGeneration.ExecutionStartedAt {
		return errors.New("C18 evaluation binding chronology is invalid")
	}
	return nil
}

func validateEvaluationCorpus(request PhysicalCaseRequestV2) error {
	corpus := request.Corpus
	if request.DeterministicChecks == nil || request.MeasuredMetrics == nil ||
		corpus.Contract != "ArtifactSkillEvaluationCorpus@1" || corpus.Revision != 1 ||
		!corpusAuthorityRef.MatchString(corpus.CorpusRef) || !strings.HasSuffix(corpus.CorpusRef, "@1") ||
		!skillAuthorityRef.MatchString(corpus.SkillRef) ||
		!skillManifestAuthorityRef.MatchString(corpus.ManifestRef) ||
		corpus.CorpusRef != request.Binding.Corpus.Ref || corpus.Digest != request.Binding.Corpus.Digest ||
		corpus.SkillRef != request.Binding.Skill.Ref || corpus.SkillDigest != request.Binding.Skill.Digest ||
		!exactSHA256.MatchString(corpus.ManifestDigest) ||
		len(corpus.Cases) == 0 || len(corpus.Cases) > 512 ||
		len(corpus.Inputs) == 0 || len(corpus.Inputs) > 256 ||
		len(corpus.RequiredRuntimeCapabilities) == 0 || len(corpus.RequiredRuntimeCapabilities) > 512 ||
		!sortedUnique(extractInputRefs(corpus.Inputs)) ||
		!sortedUnique(extractCaseRefs(corpus.Cases)) ||
		!sortedUnique(corpus.RequiredRuntimeCapabilities) {
		return errors.New("C18 physical request corpus authority is invalid")
	}
	corpusBytes, err := generationstop.CanonicalJSON(corpus)
	if err != nil || len(corpusBytes) > 2*1024*1024 {
		return errors.New("C18 physical request corpus exceeds its canonical bound")
	}
	if err := verifySealedDigest(corpus, corpus.Digest); err != nil {
		return err
	}
	for _, capability := range corpus.RequiredRuntimeCapabilities {
		if !runtimeCapabilityAuthorityRef.MatchString(capability) {
			return errors.New("C18 physical request runtime capability ref is invalid")
		}
	}
	inputs := make(map[string]EvaluationInputV1, len(corpus.Inputs))
	for _, input := range corpus.Inputs {
		if !validOperationalRef(input.Ref) || !exactSHA256.MatchString(input.Digest) ||
			!canonicalMediaTypeValue(input.MediaType) || !canonicalTokenValue(input.Role) {
			return errors.New("C18 physical request corpus input is invalid")
		}
		inputs[input.Ref] = input
	}
	for _, evaluationCase := range corpus.Cases {
		if !caseAuthorityRef.MatchString(evaluationCase.CaseRef) ||
			!canonicalTokenValue(evaluationCase.Scenario) || !canonicalTokenValue(evaluationCase.Metric) ||
			(evaluationCase.MeasurementClass != "deterministic" &&
				evaluationCase.MeasurementClass != "measured" && evaluationCase.MeasurementClass != "judgment") ||
			evaluationCase.ThresholdBasisPoints < 1 || evaluationCase.ThresholdBasisPoints > 10_000 ||
			(evaluationCase.MeasurementClass == "deterministic" && evaluationCase.ThresholdBasisPoints != 10_000) ||
			len(evaluationCase.InputRefs) == 0 || len(evaluationCase.InputRefs) > 64 ||
			len(evaluationCase.ExpectedProperties) == 0 || len(evaluationCase.ExpectedProperties) > 128 ||
			!sortedUnique(evaluationCase.InputRefs) || !sortedUnique(evaluationCase.ExpectedProperties) {
			return errors.New("C18 physical request corpus case is invalid")
		}
		for _, ref := range evaluationCase.InputRefs {
			if !validOperationalRef(ref) || inputs[ref].Ref == "" {
				return errors.New("C18 physical request corpus case input ref is invalid")
			}
		}
		for _, property := range evaluationCase.ExpectedProperties {
			if !canonicalTokenValue(property) {
				return errors.New("C18 physical request corpus case property is invalid")
			}
		}
	}
	var current *EvaluationCaseV1
	for index := range corpus.Cases {
		candidate := &corpus.Cases[index]
		if candidate.CaseRef == request.EvaluationCase.CaseRef {
			current = candidate
		}
	}
	if current == nil || !canonicalEqual(*current, request.EvaluationCase) ||
		(request.EvaluationCase.MeasurementClass != "deterministic" && request.EvaluationCase.MeasurementClass != "measured") ||
		request.EvaluationCase.ThresholdBasisPoints < 1 || request.EvaluationCase.ThresholdBasisPoints > 10_000 ||
		!sortedUnique(request.EvaluationCase.ExpectedProperties) || !sortedUnique(request.EvaluationCase.InputRefs) {
		return errors.New("C18 physical request evaluation case is invalid")
	}
	if len(request.CorpusAssets) != len(request.EvaluationCase.InputRefs) {
		return errors.New("C18 physical request corpus asset roster is incomplete")
	}
	assetRefs := make([]string, len(request.CorpusAssets))
	for index, asset := range request.CorpusAssets {
		expected, exists := inputs[asset.Ref]
		if !exists || expected != (EvaluationInputV1{
			Ref: asset.Ref, Digest: asset.Digest, MediaType: asset.MediaType, Role: asset.Role,
		}) || sha256Digest([]byte(asset.Body)) != asset.Digest {
			return errors.New("C18 physical request corpus asset bytes are invalid")
		}
		assetRefs[index] = asset.Ref
	}
	if !equalStrings(assetRefs, request.EvaluationCase.InputRefs) {
		return errors.New("C18 physical request corpus assets differ from the case")
	}
	if request.EvaluationCase.MeasurementClass == "deterministic" {
		if len(request.DeterministicChecks) == 0 || len(request.MeasuredMetrics) != 0 {
			return errors.New("C18 deterministic request changed its check partition")
		}
	} else if len(request.DeterministicChecks) != 0 || len(request.MeasuredMetrics) == 0 {
		return errors.New("C18 measured request changed its metric partition")
	}
	if len(request.DeterministicChecks) > 256 || len(request.MeasuredMetrics) > 256 ||
		!sortedUnique(request.DeterministicChecks) || !sortedUnique(request.MeasuredMetrics) {
		return errors.New("C18 physical request check or metric roster is invalid")
	}
	for _, roster := range [][]string{request.DeterministicChecks, request.MeasuredMetrics} {
		for _, value := range roster {
			if !canonicalTokenValue(value) {
				return errors.New("C18 physical request check or metric is invalid")
			}
		}
	}
	return nil
}

func validateRenderCommandAuthority(request PhysicalCaseRequestV2) error {
	authority := request.RenderCommandAuthority
	policy, foundPolicy := runtimePolicyForCandidate(authority.Candidate.Ref)
	if authority.Candidate != request.Binding.Authority.Candidate || authority.Operation != "render_validate" ||
		!foundPolicy || authority.Facet != policy.Facet ||
		request.Corpus.CorpusRef != physicalCorpusRefForFacet(policy.Facet) ||
		authority.ExecutablePath != policy.ExecutablePath ||
		request.Binding.Authority.Image.PackRef != policy.ExecutorPackRevisionRef ||
		!templateRendererMatchesRuntimePolicy(authority.Renderer, policy) ||
		!canonicalEqual(authority.PackRequiredChecks, policy.CheckLabels) ||
		authority.Runtime.RuntimeClosure != request.Binding.RuntimeClosure ||
		authority.Runtime.WorkspaceExecutionManifest.Ref != request.Binding.ProviderTarget.Fence.WorkspaceExecutionManifestRef ||
		authority.Output.JobRoot != "/ambit" || authority.Output.MaximumAggregateImagePixels != 33_554_432 ||
		authority.Output.MaximumImagePixels != 8_388_608 || authority.Output.MaximumPreviewBytes != 8_388_608 ||
		authority.Output.PreviewMediaType != RenderPreviewMediaType || len(authority.PackRequiredChecks) == 0 {
		return errors.New("C18 render command template authority is invalid")
	}
	if len(authority.Runtime.PackRevisions) == 0 || len(authority.Runtime.PackRevisions) > 32 ||
		!validPinWithPattern(authority.Runtime.ProfileRevision, runtimeProfileAuthorityRef) ||
		!validPinWithPattern(authority.Runtime.WorkspaceExecutionManifest, workspaceManifestAuthorityRef) ||
		!sortedUniquePinsWithPattern(authority.Runtime.PackRevisions, runtimePackAuthorityRef) {
		return errors.New("C18 render command runtime authority is invalid")
	}
	foundPack := containsPinRef(authority.Runtime.PackRevisions, policy.ExecutorPackRevisionRef)
	checks := make([]string, len(authority.PackRequiredChecks))
	for index, check := range authority.PackRequiredChecks {
		if !canonicalToken.MatchString(check.Check) || !printable(check.Label, 512) {
			return errors.New("C18 render command pack check is invalid")
		}
		checks[index] = check.Check
	}
	if !foundPack || !sortedUnique(checks) || !printable(authority.Renderer.RendererRef, 512) ||
		!printable(authority.Renderer.ValidationPolicyRef, 512) ||
		!canonicalToken.MatchString(authority.Renderer.Representation) ||
		!canonicalToken.MatchString(authority.Renderer.RenderMode) {
		return errors.New("C18 render command candidate policy is invalid")
	}
	return nil
}

func validateSampleRoster(request PhysicalCaseRequestV2) error {
	if err := validateBindingSampleSets(request); err != nil {
		return err
	}
	var expected []SampleSourceV1
	for _, set := range request.Binding.CaseSampleSets {
		if set.CaseRef == request.EvaluationCase.CaseRef {
			expected = set.Samples
		}
	}
	if expected == nil || !canonicalEqual(expected, request.SampleRoster) || len(request.SampleRoster) == 0 ||
		len(request.SampleRoster) > 128 {
		return errors.New("C18 physical request sample roster differs from its binding")
	}
	sampleRefs := make([]string, len(request.SampleRoster))
	sourceRefs := make([]string, len(request.SampleRoster))
	sourceDigests := make(map[string]struct{}, len(request.SampleRoster))
	containsSubject := false
	for index, sample := range request.SampleRoster {
		_, admittedMedia := runtimePolicyForCandidateMedia(
			request.RenderCommandAuthority.Candidate.Ref,
			sample.Source.MediaType,
		)
		if !validOperationalRef(sample.SampleRef) || !validOperationalRef(sample.Source.Ref) ||
			!exactSHA256.MatchString(sample.Source.Digest) || !canonicalMediaTypeValue(sample.Source.MediaType) ||
			!admittedMedia {
			return errors.New("C18 physical request sample identity is invalid")
		}
		sampleRefs[index] = sample.SampleRef
		sourceRefs[index] = sample.Source.Ref
		sourceDigests[sample.Source.Digest] = struct{}{}
		if sample.Source.Ref == request.Binding.SubjectArtifact.Ref && sample.Source.Digest == request.Binding.SubjectArtifact.Digest {
			containsSubject = true
		}
	}
	if !sortedUnique(sampleRefs) || !uniqueAfterSort(sourceRefs) || !containsSubject {
		return errors.New("C18 physical request sample roster is not unique or lacks its subject")
	}
	if request.EvaluationCase.MeasurementClass == "deterministic" {
		if len(request.SampleRoster) != 1 || request.SamplePolicy != nil ||
			request.SampleRoster[0].Source.Ref != request.Binding.SubjectArtifact.Ref ||
			request.SampleRoster[0].Source.Digest != request.Binding.SubjectArtifact.Digest {
			return errors.New("C18 deterministic request does not use exactly its subject")
		}
	} else {
		minimum := measuredMinimum(request.EvaluationCase.ThresholdBasisPoints)
		if request.SamplePolicy == nil || request.SamplePolicy.MinimumSamples != minimum ||
			request.SamplePolicy.MaximumSamples != 128 || len(request.SampleRoster) < minimum ||
			len(sourceDigests) != len(request.SampleRoster) {
			return errors.New("C18 measured request sample policy or diversity is invalid")
		}
	}
	return nil
}

func validateBindingSampleSets(request PhysicalCaseRequestV2) error {
	automatedCases := make([]EvaluationCaseV1, 0, len(request.Corpus.Cases))
	for _, evaluationCase := range request.Corpus.Cases {
		if evaluationCase.MeasurementClass != "judgment" {
			automatedCases = append(automatedCases, evaluationCase)
		}
	}
	if len(automatedCases) == 0 || len(request.Binding.CaseSampleSets) != len(automatedCases) {
		return errors.New("C18 evaluation binding automated sample-set roster is incomplete")
	}
	for index, set := range request.Binding.CaseSampleSets {
		evaluationCase := automatedCases[index]
		minimum, maximum := 1, 1
		if evaluationCase.MeasurementClass == "measured" {
			minimum, maximum = measuredMinimum(evaluationCase.ThresholdBasisPoints), 128
		}
		if set.CaseRef != evaluationCase.CaseRef || len(set.Samples) < minimum || len(set.Samples) > maximum {
			return errors.New("C18 evaluation binding sample set differs from its case")
		}
		sampleRefs := make([]string, len(set.Samples))
		sourceRefs := make([]string, len(set.Samples))
		sourceDigests := make(map[string]struct{}, len(set.Samples))
		containsSubject := false
		for sampleIndex, sample := range set.Samples {
			_, admittedMedia := runtimePolicyForCandidateMedia(
				request.Binding.Authority.Candidate.Ref,
				sample.Source.MediaType,
			)
			if !validOperationalRef(sample.SampleRef) || !validOperationalRef(sample.Source.Ref) ||
				!exactSHA256.MatchString(sample.Source.Digest) ||
				!canonicalMediaTypeValue(sample.Source.MediaType) || !admittedMedia {
				return errors.New("C18 evaluation binding sample source is invalid")
			}
			sampleRefs[sampleIndex] = sample.SampleRef
			sourceRefs[sampleIndex] = sample.Source.Ref
			sourceDigests[sample.Source.Digest] = struct{}{}
			containsSubject = containsSubject ||
				(sample.Source.Ref == request.Binding.SubjectArtifact.Ref &&
					sample.Source.Digest == request.Binding.SubjectArtifact.Digest)
		}
		if !sortedUnique(sampleRefs) || !uniqueAfterSort(sourceRefs) || !containsSubject ||
			(evaluationCase.MeasurementClass == "measured" && len(sourceDigests) != len(set.Samples)) {
			return errors.New("C18 evaluation binding sample set is noncanonical or lacks its subject")
		}
	}
	return nil
}

func validateJourneyPlan(request PhysicalCaseRequestV2) error {
	plan := request.JourneyPlan
	expectedStages := physicalJourneyStages(
		request.RenderCommandAuthority.Facet,
		request.EvaluationCase.MeasurementClass,
	)
	if plan.RequiredStages == nil || plan.Relations == nil || plan.CheckDerivations == nil ||
		plan.MetricDerivations == nil || !plan.RequireEveryPackCheck ||
		len(expectedStages) == 0 || len(plan.RequiredStages) > maximumJourneyStages ||
		!canonicalEqual(plan.RequiredStages, expectedStages) || !uniqueStringsInOrder(plan.RequiredStages) ||
		!canonicalEqual(plan.Relations, physicalJourneyRelations(expectedStages)) {
		return errors.New("C18 physical journey stage plan is invalid")
	}
	for _, stage := range plan.RequiredStages {
		if !validJourneyStage(stage) {
			return errors.New("C18 physical journey plan contains an unknown stage")
		}
	}
	if len(plan.CheckDerivations) != len(request.DeterministicChecks) ||
		len(plan.MetricDerivations) != len(request.MeasuredMetrics) {
		return errors.New("C18 physical journey derivation roster is incomplete")
	}
	for index, derivation := range plan.CheckDerivations {
		if derivation.Check != request.DeterministicChecks[index] ||
			derivation.Source != physicalCheckDerivationSource(derivation.Check) {
			return errors.New("C18 physical check derivation is invalid")
		}
	}
	expectedMetricSources := []string{"action_lineage_claim", "byte_relation", "pack_check"}
	for index, derivation := range plan.MetricDerivations {
		if derivation.Metric != request.MeasuredMetrics[index] ||
			!canonicalEqual(derivation.Sources, expectedMetricSources) {
			return errors.New("C18 physical metric derivation is invalid")
		}
	}
	for _, relation := range plan.Relations {
		if !containsStringInOrder(plan.RequiredStages, relation.LeftStage) ||
			!containsStringInOrder(plan.RequiredStages, relation.RightStage) ||
			(relation.Relation != "equal_digest" && relation.Relation != "different_digest") {
			return errors.New("C18 physical journey relation is invalid")
		}
	}
	return nil
}

func validateSampleJourneys(request PhysicalCaseRequestV2) error {
	if len(request.SampleJourneys) != len(request.SampleRoster) {
		return errors.New("C18 physical sample journey roster is incomplete")
	}
	requiredClaims := request.DeterministicChecks
	if request.EvaluationCase.MeasurementClass == "measured" {
		requiredClaims = request.MeasuredMetrics
	}
	var aggregate int64
	for index, journey := range request.SampleJourneys {
		expected := request.SampleRoster[index]
		if journey.SampleRef != expected.SampleRef || len(journey.Stages) != len(request.JourneyPlan.RequiredStages) {
			return errors.New("C18 physical sample journey identity is invalid")
		}
		claims := make(map[string]int, len(requiredClaims))
		artifactRefs := make([]string, len(journey.Stages))
		for stageIndex := range journey.Stages {
			stage := journey.Stages[stageIndex]
			if stage.Stage != request.JourneyPlan.RequiredStages[stageIndex] || !validJourneyStage(stage.Stage) {
				return errors.New("C18 physical sample journey stage order is invalid")
			}
			bytes, err := decodeInlineArtifact(stage.Artifact)
			if err != nil {
				return err
			}
			aggregate += int64(len(bytes))
			artifactRefs[stageIndex] = stage.Artifact.Ref
			if stageIndex == 0 {
				if stage.Stage != "source" || stage.Lineage != nil ||
					stage.Artifact.Ref != expected.Source.Ref || stage.Artifact.Digest != expected.Source.Digest ||
					stage.Artifact.MediaType != expected.Source.MediaType {
					return errors.New("C18 physical sample source stage is invalid")
				}
				continue
			}
			prior := journey.Stages[stageIndex-1]
			if err := validateStageLineage(stage, prior, request.Binding.ExpiresAt, &aggregate, claims); err != nil {
				return err
			}
			if stage.Artifact.MediaType != journey.Stages[0].Artifact.MediaType {
				return errors.New("C18 physical sample journey changed media type")
			}
		}
		if !uniqueAfterSort(artifactRefs) {
			return errors.New("C18 physical sample journey artifact refs are not unique")
		}
		for _, relation := range request.JourneyPlan.Relations {
			left := journeyStage(journey.Stages, relation.LeftStage)
			right := journeyStage(journey.Stages, relation.RightStage)
			if left == nil || right == nil ||
				((left.Artifact.Digest == right.Artifact.Digest) != (relation.Relation == "equal_digest")) {
				return errors.New("C18 physical sample journey violates a byte relation")
			}
		}
		for _, claim := range requiredClaims {
			if claims[claim] != 1 {
				return errors.New("C18 physical sample lineage does not exactly prove every claim")
			}
		}
		for claim, count := range claims {
			if count != 1 || !containsStringInOrder(requiredClaims, claim) {
				return errors.New("C18 physical sample lineage contains an extra or duplicate claim")
			}
		}
	}
	if aggregate > maximumInlineAggregateBytes {
		return errors.New("C18 physical request inline bytes exceed their aggregate bound")
	}
	return nil
}

func validateStageLineage(
	stage JourneyStageV2,
	prior JourneyStageV2,
	expiresAt string,
	aggregate *int64,
	claims map[string]int,
) error {
	lineage := stage.Lineage
	if lineage == nil || lineage.Contract != StageLineageContractV1 || lineage.Action != stage.Stage ||
		lineage.Input.Stage != prior.Stage || lineage.Input.Artifact != (specialistrender.Pin{
		Ref: prior.Artifact.Ref, Digest: prior.Artifact.Digest,
	}) || lineage.Output.Stage != stage.Stage || lineage.Output.Artifact != (specialistrender.Pin{
		Ref: stage.Artifact.Ref, Digest: stage.Artifact.Digest,
	}) || !exactMillisecondInstant(lineage.ObservedAt) || lineage.ObservedAt >= expiresAt ||
		lineage.RawEvidence == nil || lineage.VerifiedClaims == nil ||
		len(lineage.RawEvidence) == 0 || len(lineage.RawEvidence) > 64 ||
		!sortedUnique(lineage.VerifiedClaims) {
		return errors.New("C18 physical stage lineage authority is invalid")
	}
	if err := verifySealedDigest(*lineage, lineage.Digest); err != nil {
		return err
	}
	evidenceRefs := make([]string, len(lineage.RawEvidence))
	for index, evidence := range lineage.RawEvidence {
		bytes, err := decodeInlineArtifact(evidence)
		if err != nil {
			return err
		}
		*aggregate += int64(len(bytes))
		evidenceRefs[index] = evidence.Ref
	}
	if !sortedUnique(evidenceRefs) {
		return errors.New("C18 physical stage lineage evidence refs are invalid")
	}
	for _, claim := range lineage.VerifiedClaims {
		if !canonicalTokenValue(claim) {
			return errors.New("C18 physical stage lineage claim is invalid")
		}
		claims[claim]++
	}
	return nil
}

func decodeInlineArtifact(artifact InlineArtifactV2) ([]byte, error) {
	if !validOperationalRef(artifact.Ref) || !exactSHA256.MatchString(artifact.Digest) ||
		!canonicalMediaTypeValue(artifact.MediaType) || artifact.ByteLength < 1 ||
		artifact.ByteLength > maximumInlineArtifactBytes || artifact.Base64 == "" {
		return nil, errors.New("C18 inline artifact authority is invalid")
	}
	bytes, err := base64.StdEncoding.Strict().DecodeString(artifact.Base64)
	if err != nil || base64.StdEncoding.EncodeToString(bytes) != artifact.Base64 ||
		int64(len(bytes)) != artifact.ByteLength || sha256Digest(bytes) != artifact.Digest {
		return nil, errors.New("C18 inline artifact bytes or digest are forged")
	}
	return bytes, nil
}

func extractInputRefs(values []EvaluationInputV1) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.Ref
	}
	return result
}

func extractCaseRefs(values []EvaluationCaseV1) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.CaseRef
	}
	return result
}

func uniqueAfterSort(values []string) bool {
	copy := append([]string(nil), values...)
	return sortedUnique(sortStrings(copy))
}

func sortStrings(values []string) []string {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && values[cursor] < values[cursor-1]; cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
	}
	return values
}

func uniqueStringsInOrder(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func containsStringInOrder(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func journeyStage(stages []JourneyStageV2, expected string) *JourneyStageV2 {
	for index := range stages {
		if stages[index].Stage == expected {
			return &stages[index]
		}
	}
	return nil
}

func physicalJourneyStages(facet, measurementClass string) []string {
	if measurementClass != "deterministic" && measurementClass != "measured" {
		return nil
	}
	if facet == "web_application" {
		if measurementClass == "measured" {
			return []string{"source", "edited", "rebuilt", "browser_validated", "reopened"}
		}
		return []string{"source", "browser_validated", "reopened"}
	}
	if measurementClass == "measured" {
		return []string{"source", "edited", "reopened"}
	}
	return []string{"source", "reopened"}
}

func physicalCorpusRefForFacet(facet string) string {
	return "ambit.skill-eval-corpus/" + strings.ReplaceAll(facet, "_", "-") + "/core@1"
}

func physicalJourneyRelations(stages []string) []JourneyRelationV2 {
	relations := make([]JourneyRelationV2, 0, 3)
	if containsStringInOrder(stages, "edited") {
		terminal := "edited"
		if containsStringInOrder(stages, "rebuilt") {
			terminal = "rebuilt"
		}
		relations = append(relations,
			JourneyRelationV2{LeftStage: "source", Relation: "different_digest", RightStage: "edited"},
			JourneyRelationV2{LeftStage: terminal, Relation: "equal_digest", RightStage: "reopened"},
		)
		if containsStringInOrder(stages, "browser_validated") {
			relations = append(relations, JourneyRelationV2{
				LeftStage: terminal, Relation: "equal_digest", RightStage: "browser_validated",
			})
		}
		return relations
	}
	for _, stage := range stages[1:] {
		relations = append(relations, JourneyRelationV2{
			LeftStage: "source", Relation: "equal_digest", RightStage: stage,
		})
	}
	return relations
}

func physicalCheckDerivationSource(check string) string {
	if check == "artifact_render_validate" {
		return "pack_check"
	}
	if strings.Contains(check, "download_reopen") || strings.Contains(check, "reopen_preservation") {
		return "byte_relation"
	}
	return "action_lineage_claim"
}

func measuredMinimum(threshold int) int {
	divisor := greatestCommonDivisor(threshold, 10_000)
	minimum := 10_000 / divisor
	if minimum < 10 {
		minimum = 10
	}
	return minimum
}

func greatestCommonDivisor(left, right int) int {
	for right != 0 {
		left, right = right, left%right
	}
	return left
}

func (request PhysicalCaseRequestV2) ExpiresAt() time.Time {
	parsed, _ := time.Parse("2006-01-02T15:04:05.000Z", request.Binding.ExpiresAt)
	return parsed
}
