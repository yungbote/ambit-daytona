// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

func TestPhysicalRequestRejectsInlineAndAuthoritySubstitutions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PhysicalCaseRequestV2)
	}{
		{
			name: "inline digest",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.SampleJourneys[0].Stages[0].Artifact.Digest = "sha256:" + repeatHex("f")
			},
		},
		{
			name: "inline per-sample overflow",
			mutate: func(request *PhysicalCaseRequestV2) {
				value := bytes.Repeat([]byte{'x'}, maximumInlineArtifactBytes+1)
				artifact := &request.SampleJourneys[0].Stages[0].Artifact
				artifact.Base64 = base64.StdEncoding.EncodeToString(value)
				artifact.ByteLength = int64(len(value))
				artifact.Digest = sha256Digest(value)
			},
		},
		{
			name: "candidate media",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.SampleRoster[0].Source.MediaType = "application/pdf"
				for index := range request.SampleJourneys[0].Stages {
					request.SampleJourneys[0].Stages[index].Artifact.MediaType = "application/pdf"
				}
				for setIndex := range request.Binding.CaseSampleSets {
					if request.Binding.CaseSampleSets[setIndex].CaseRef == request.EvaluationCase.CaseRef {
						request.Binding.CaseSampleSets[setIndex].Samples[0].Source.MediaType = "application/pdf"
					}
				}
				request.Binding.Digest = mustSealedDigest(t, request.Binding)
			},
		},
		{
			name: "candidate digest",
			mutate: func(request *PhysicalCaseRequestV2) {
				forged := "sha256:" + repeatHex("f")
				request.Binding.Authority.Candidate.Digest = forged
				request.RenderCommandAuthority.Candidate.Digest = forged
				request.Binding.Digest = mustSealedDigest(t, request.Binding)
			},
		},
		{
			name: "wrong current candidate",
			mutate: func(request *PhysicalCaseRequestV2) {
				candidate := currentCandidatePins.Candidates[2]
				request.Binding.Authority.Candidate = specialistrender.Pin{
					Ref: candidate.CandidateRef, Digest: candidate.CandidateDigest,
				}
				request.RenderCommandAuthority.Candidate = request.Binding.Authority.Candidate
				request.Binding.Digest = mustSealedDigest(t, request.Binding)
			},
		},
		{
			name: "image ref control",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.Binding.Authority.Image.Ref = "registry.test/ambit/data\x00research@sha256:" + repeatHex("a")
				request.Binding.Digest = mustSealedDigest(t, request.Binding)
			},
		},
		{
			name: "provider resource control",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.Binding.ProviderTarget.Workspace.ProviderResourceID += "\n"
				request.Binding.Digest = mustSealedDigest(t, request.Binding)
			},
		},
		{
			name: "composition pin overflow",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.Binding.Authority.Composition.Ref = strings.Repeat("c", 1_025)
				request.Binding.Digest = mustSealedDigest(t, request.Binding)
			},
		},
		{
			name: "routing pin overflow",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.Binding.Authority.Routing.Ref = strings.Repeat("r", 1_025)
				request.Binding.Digest = mustSealedDigest(t, request.Binding)
			},
		},
		{
			name: "component pin overflow",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.Binding.Authority.Component.Artifact.Ref = strings.Repeat("a", 1_025)
				request.Binding.Digest = mustSealedDigest(t, request.Binding)
			},
		},
		{
			name: "source authority pin overflow",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.Binding.Authority.SourceAuthorities[0].Ref = strings.Repeat("s", 1_025)
				request.Binding.Digest = mustSealedDigest(t, request.Binding)
			},
		},
		{
			name: "parent restart overflow",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.Binding.ProviderTarget.ExpectedParentGeneration.RestartCount = 2_147_483_648
				request.Binding.Digest = mustSealedDigest(t, request.Binding)
			},
		},
		{
			name: "non-current measured sample diversity",
			mutate: func(request *PhysicalCaseRequestV2) {
				measured := &request.Binding.CaseSampleSets[1]
				measured.Samples[1].Source.Digest = measured.Samples[0].Source.Digest
				request.Binding.Digest = mustSealedDigest(t, request.Binding)
			},
		},
		{
			name: "render command authority",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.RenderCommandAuthority.Renderer.RendererRef = "ambit.renderer/pdf-document-v1@1"
			},
		},
		{
			name: "runtime executable",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.RenderCommandAuthority.ExecutablePath = facetExecutable("pdf")
			},
		},
		{
			name: "validation policy",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.RenderCommandAuthority.Renderer.ValidationPolicyRef = "ambit.validation-policy/research-artifact-v1@1"
			},
		},
		{
			name: "representation",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.RenderCommandAuthority.Renderer.Representation = "research_claim_citation_document"
			},
		},
		{
			name: "render mode",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.RenderCommandAuthority.Renderer.RenderMode = "claim_ledger_document_and_citation_graph"
			},
		},
		{
			name: "source schema",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.RenderCommandAuthority.Renderer.SourceSchemaURI = nil
			},
		},
		{
			name: "pack check label",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.RenderCommandAuthority.PackRequiredChecks[0].Label = "Substituted"
			},
		},
		{
			name: "executor pack revision",
			mutate: func(request *PhysicalCaseRequestV2) {
				packRef := request.Binding.Authority.Image.PackRef
				for index, pin := range request.RenderCommandAuthority.Runtime.PackRevisions {
					if pin.Ref == packRef {
						request.RenderCommandAuthority.Runtime.PackRevisions = append(
							request.RenderCommandAuthority.Runtime.PackRevisions[:index],
							request.RenderCommandAuthority.Runtime.PackRevisions[index+1:]...,
						)
						return
					}
				}
			},
		},
		{
			name: "derivation source",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.JourneyPlan.CheckDerivations[0].Source = "unproved"
			},
		},
		{
			name: "null empty metric roster",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.MeasuredMetrics = nil
			},
		},
		{
			name: "valid but wrong derivation source",
			mutate: func(request *PhysicalCaseRequestV2) {
				for index := range request.JourneyPlan.CheckDerivations {
					if request.JourneyPlan.CheckDerivations[index].Check == "artifact_render_validate" {
						request.JourneyPlan.CheckDerivations[index].Source = "action_lineage_claim"
						return
					}
				}
			},
		},
		{
			name: "journey relation",
			mutate: func(request *PhysicalCaseRequestV2) {
				request.JourneyPlan.Relations[0].Relation = "different_digest"
			},
		},
		{
			name: "lineage claim",
			mutate: func(request *PhysicalCaseRequestV2) {
				lineage := request.SampleJourneys[0].Stages[1].Lineage
				lineage.VerifiedClaims[0] = "bogus_claim"
				lineage.Digest = mustSealedDigest(t, *lineage)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			golden, _ := loadPhysicalGolden(t)
			request := clonePhysicalRequest(t, golden.Request)
			test.mutate(&request)
			request.Digest = mustSealedDigest(t, request)
			encoded, err := generationstop.CanonicalJSON(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParsePhysicalCaseRequestV2(encoded); err == nil {
				t.Fatal("substituted physical request was admitted")
			}
		})
	}
}

func TestPhysicalRequestRejectsAggregateInlineOverflow(t *testing.T) {
	golden, _ := loadPhysicalGolden(t)
	request := clonePhysicalRequest(t, golden.Request)
	lineage := request.SampleJourneys[0].Stages[1].Lineage
	lineage.RawEvidence = make([]InlineArtifactV2, 25)
	value := bytes.Repeat([]byte{'e'}, maximumInlineArtifactBytes)
	for index := range lineage.RawEvidence {
		lineage.RawEvidence[index] = InlineArtifactV2{
			Base64: base64.StdEncoding.EncodeToString(value), ByteLength: int64(len(value)),
			Digest: sha256Digest(value), MediaType: "application/json",
			Ref: fmt.Sprintf("ambit://raw-evidence/c18/aggregate/%03d", index),
		}
	}
	lineage.Digest = mustSealedDigest(t, *lineage)
	if err := validateSampleJourneys(request); err == nil {
		t.Fatal("aggregate inline byte overflow was admitted")
	}
}

func clonePhysicalRequest(t *testing.T, source PhysicalCaseRequestV2) PhysicalCaseRequestV2 {
	t.Helper()
	encoded, err := generationstop.CanonicalJSON(source)
	if err != nil {
		t.Fatal(err)
	}
	var result PhysicalCaseRequestV2
	if err := generationstop.DecodeCanonicalJSON(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func mustSealedDigest(t *testing.T, value any) string {
	t.Helper()
	digest, err := sealedDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
