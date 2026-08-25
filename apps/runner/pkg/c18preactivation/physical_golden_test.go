// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"os"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

type physicalDriverGoldenV2 struct {
	Contract    string                    `json:"contract"`
	Observation PhysicalCaseObservationV2 `json:"observation"`
	Request     PhysicalCaseRequestV2     `json:"request"`
}

func TestPhysicalContractsDecodeExactBackendGeneratedGolden(t *testing.T) {
	golden, _ := loadPhysicalGolden(t)
	requestBytes, err := generationstop.CanonicalJSON(golden.Request)
	if err != nil {
		t.Fatal(err)
	}
	if golden.Contract != "C18PreactivationPhysicalDriverGolden@2" {
		t.Fatal("physical driver golden contract is invalid")
	}
	if err := verifySealedDigest(golden.Request, golden.Request.Digest); err != nil {
		t.Fatal(err)
	}
	if err := verifySealedDigest(golden.Observation, golden.Observation.Digest); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePhysicalCaseRequestV2(requestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !canonicalEqual(parsed, golden.Request) {
		t.Fatal("Go physical request projection drifted from backend golden")
	}
	for _, sample := range golden.Observation.Samples {
		for _, observedStage := range sample.Stages {
			materialized, err := MaterializeRenderStageV2(
				parsed, sample.SampleRef, observedStage.Stage, observedStage.RenderRequest.DeadlineAt,
			)
			if err != nil {
				t.Fatal(err)
			}
			if !canonicalEqual(materialized.Command, observedStage.RenderRequest) ||
				materialized.OperationID != observedStage.ProviderReceipt.Request.OperationID {
				t.Fatal("Go render command materialization drifted from backend golden")
			}
			providerRequest, requestPayload, sourcePayload, err := ProviderRequest(
				ProviderInputForRenderStage(parsed, materialized),
			)
			if err != nil {
				t.Fatal(err)
			}
			if !canonicalEqual(providerRequest, observedStage.ProviderReceipt.Request) ||
				string(requestPayload) != string(materialized.CommandBytes) ||
				string(sourcePayload) != string(materialized.ArtifactBytes) {
				t.Fatal("Go provider request materialization drifted from backend golden")
			}
			if err := specialistrender.ValidateReceipt(observedStage.ProviderReceipt); err != nil {
				t.Fatal(err)
			}
		}
	}
	observationBytes, err := generationstop.CanonicalJSON(golden.Observation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePhysicalCaseObservationV2(observationBytes, parsed); err != nil {
		t.Fatal(err)
	}
}

func loadPhysicalGolden(t *testing.T) (physicalDriverGoldenV2, []byte) {
	t.Helper()
	encoded, err := os.ReadFile("testdata/c18-preactivation-physical-driver-golden.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	if sha256Digest(encoded) != "sha256:7bea1a4b53a71a7b4569649bc55c951a9b6cae88f68f209991a7f8fb2a9b576d" {
		t.Fatal("backend-generated physical driver golden bytes drifted")
	}
	var golden physicalDriverGoldenV2
	if err := generationstop.DecodeCanonicalJSON(encoded, &golden); err != nil {
		t.Fatal(err)
	}
	return golden, encoded
}
