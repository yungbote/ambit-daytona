// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

func TestPhysicalDriverExecutesExactJourneyAndDerivesPassingObservation(t *testing.T) {
	golden, _ := loadPhysicalGolden(t)
	provider := &fakeStreamingProvider{execute: func(
		ctx context.Context,
		input ProviderExecutionInput,
		custody ProviderResponseCustody,
	) (ProviderResponseObservation, error) {
		if _, bounded := ctx.Deadline(); !bounded {
			return ProviderResponseObservation{}, errors.New("driver provider context has no binding deadline")
		}
		return successfulStageExecution(t, ctx, input, custody)
	}}
	driver, err := NewPhysicalDriver(provider, fixedDriverClock("2026-08-24T00:10:00.000Z"))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := driver.Evaluate(context.Background(), golden.Request)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Outcome != "passed" || provider.calls != len(golden.Request.SampleJourneys[0].Stages) {
		t.Fatalf("physical driver did not complete the exact journey: %#v", observation)
	}
	for _, check := range observation.DeterministicChecks {
		if check.Outcome != "passed" {
			t.Fatalf("deterministic derivation did not pass: %#v", check)
		}
	}
	encoded, err := generationstop.CanonicalJSON(observation)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip PhysicalCaseObservationV2
	if err := generationstop.DecodeCanonicalJSON(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if !canonicalEqual(roundTrip, observation) {
		t.Fatal("physical observation did not round trip canonically")
	}
	if _, err := ParsePhysicalCaseObservationV2(encoded, golden.Request); err != nil {
		t.Fatal(err)
	}
}

func TestPhysicalDriverRetainsReceiptOnlySettlementsWithoutInventingResults(t *testing.T) {
	for _, outcome := range []string{"cancelled", "timed_out"} {
		t.Run(outcome, func(t *testing.T) {
			golden, _ := loadPhysicalGolden(t)
			provider := &fakeStreamingProvider{execute: func(
				ctx context.Context,
				input ProviderExecutionInput,
				custody ProviderResponseCustody,
			) (ProviderResponseObservation, error) {
				request, _, _, err := ProviderRequest(input)
				if err != nil {
					return ProviderResponseObservation{}, err
				}
				receipt := receiptOnlyProviderReceipt(t, request, outcome)
				observation := ProviderResponseObservation{
					Receipt: receipt, WireSHA256: "sha256:" + repeatHex("d"),
				}
				if err := custody.AdmitReceipt(ctx, receipt); err != nil {
					return ProviderResponseObservation{}, err
				}
				if err := custody.Commit(ctx, observation); err != nil {
					return ProviderResponseObservation{}, err
				}
				return observation, nil
			}}
			driver, err := NewPhysicalDriver(provider, fixedDriverClock("2026-08-24T00:10:00.000Z"))
			if err != nil {
				t.Fatal(err)
			}
			observation, err := driver.Evaluate(context.Background(), golden.Request)
			if err != nil {
				t.Fatal(err)
			}
			if observation.Outcome != "failed" {
				t.Fatal("receipt-only provider settlement was represented as passing")
			}
			encoded, err := generationstop.CanonicalJSON(observation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParsePhysicalCaseObservationV2(encoded, golden.Request); err != nil {
				t.Fatal(err)
			}
			for _, sample := range observation.Samples {
				for _, stage := range sample.Stages {
					if stage.Evaluation.Outcome != outcome || stage.Evaluation.ResultFileSHA256 != "" || len(stage.Evaluation.Checks) != 0 {
						t.Fatal("receipt-only stage invented result-bearing fields")
					}
				}
			}
		})
	}
}

func TestPhysicalDriverNeverTurnsAmbiguousSettlementIntoObservation(t *testing.T) {
	golden, _ := loadPhysicalGolden(t)
	provider := &fakeStreamingProvider{execute: func(
		context.Context,
		ProviderExecutionInput,
		ProviderResponseCustody,
	) (ProviderResponseObservation, error) {
		return ProviderResponseObservation{}, &ProviderSettlementError{Kind: "partial"}
	}}
	driver, err := NewPhysicalDriver(provider, fixedDriverClock("2026-08-24T00:10:00.000Z"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Evaluate(context.Background(), golden.Request); err == nil {
		t.Fatal("ambiguous provider settlement became an observation")
	}
}

func TestSettledReceiptAdmitsOnlyReconciledReceiptOnlyTerminal(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	for _, outcome := range []string{"cancelled", "timed_out"} {
		receipt := receiptOnlyProviderReceipt(t, request, outcome)
		observed, err := settledReceipt(ProviderResponseObservation{}, &ProviderSettlementError{
			Kind: "complete_output_unadmitted",
			Observation: &specialistrender.Observation{
				Schema: specialistrender.ObservationSchema, Status: generationstop.ObservationComplete,
				Receipt: &receipt,
			},
		})
		if err != nil || observed.ReceiptDigest != receipt.ReceiptDigest {
			t.Fatalf("reconciled %s receipt-only terminal was lost: %#v %v", outcome, observed, err)
		}
	}
	succeeded := testProviderReceipt(t, request, []byte("result"))
	if _, err := settledReceipt(ProviderResponseObservation{}, &ProviderSettlementError{
		Kind: "complete_output_unadmitted",
		Observation: &specialistrender.Observation{
			Schema: specialistrender.ObservationSchema, Status: generationstop.ObservationComplete,
			Receipt: &succeeded,
		},
	}); err == nil {
		t.Fatal("reconciled result-bearing receipt became an observation without output custody")
	}
}

type fakeStreamingProvider struct {
	calls   int
	execute func(context.Context, ProviderExecutionInput, ProviderResponseCustody) (ProviderResponseObservation, error)
}

func (provider *fakeStreamingProvider) ExecuteToCustody(
	ctx context.Context,
	input ProviderExecutionInput,
	custody ProviderResponseCustody,
) (ProviderResponseObservation, error) {
	provider.calls++
	return provider.execute(ctx, input, custody)
}

type fixedDriverClock string

func (clock fixedDriverClock) Now() time.Time {
	parsed, _ := time.Parse("2006-01-02T15:04:05.000Z", string(clock))
	return parsed
}

func successfulStageExecution(
	t *testing.T,
	ctx context.Context,
	input ProviderExecutionInput,
	custody ProviderResponseCustody,
) (ProviderResponseObservation, error) {
	request, requestBytes, sourceBytes, err := ProviderRequest(input)
	if err != nil {
		return ProviderResponseObservation{}, err
	}
	command, err := ParseRenderCommandV2(requestBytes, sourceBytes)
	if err != nil {
		return ProviderResponseObservation{}, err
	}
	evidenceBytes := make([][]byte, len(command.PackRequiredChecks))
	resultChecks := make([]RenderResultCheckV2, len(command.PackRequiredChecks))
	for index, required := range command.PackRequiredChecks {
		evidence := RenderCheckEvidenceV1{
			Artifacts: []RenderEvidenceDescriptor{}, Check: required.Check,
			Contract: RenderEvidenceContractV1, ExecutorRevision: request.Executor,
			Facts: []RenderEvidenceFactV1{{Key: "verified", Value: "true"}}, Outcome: "passed",
			Request: RenderEvidenceRequestV1{
				Digest: command.Digest, JobRef: command.JobRef, SourceDigest: command.Source.Digest,
			},
		}
		evidence.Digest, err = sealedDigest(evidence)
		if err != nil {
			return ProviderResponseObservation{}, err
		}
		encoded, err := generationstop.CanonicalJSON(evidence)
		if err != nil {
			return ProviderResponseObservation{}, err
		}
		path := "outputs/render/evidence/" + formatOrdinal(index+1) + "-" + strings.ReplaceAll(required.Check, ".", "_") + ".json"
		descriptor := RenderEvidenceDescriptor{
			Path: path, MediaType: RenderEvidenceMediaType,
			ByteLength: int64(len(encoded)), Digest: sha256Digest(encoded),
		}
		evidenceBytes[index] = encoded
		resultChecks[index] = RenderResultCheckV2{Check: required.Check, Evidence: &descriptor, Outcome: "passed"}
	}
	previewBytes, previewDigest, err := successfulPreviewBytes(command)
	if err != nil {
		return ProviderResponseObservation{}, err
	}
	result := RenderResultV2{
		Checks: resultChecks, Contract: RenderResultContractV2,
		Execution: RenderExecutionV2{
			CompletedAt: "2026-08-24T00:00:02.000Z", ExecutorRevision: request.Executor,
			StartedAt: "2026-08-24T00:00:01.000Z",
		},
		Outcome: "succeeded",
		Preview: &RenderPreviewV2{
			Path: command.Output.PreviewPath, MediaType: RenderPreviewMediaType,
			ByteLength: int64(len(previewBytes)), BytesDigest: sha256Digest(previewBytes),
			EnvelopeDigest: previewDigest,
		},
		Request: RenderResultRequestV2{Digest: command.Digest, JobRef: command.JobRef, JobRoot: command.JobRoot},
	}
	result.Digest, err = sealedDigest(result)
	if err != nil {
		return ProviderResponseObservation{}, err
	}
	resultBytes, err := generationstop.CanonicalJSON(result)
	if err != nil {
		return ProviderResponseObservation{}, err
	}
	files := []ProviderOutput{
		{Descriptor: specialistrender.OutputFile{
			Ordinal: 0, Role: "result", Path: command.Output.ResultPath, MediaType: RenderResultMediaType,
			ByteLength: int64(len(resultBytes)), Digest: sha256Digest(resultBytes),
		}, Bytes: resultBytes},
		{Descriptor: specialistrender.OutputFile{
			Ordinal: 1, Role: "preview", Path: command.Output.PreviewPath, MediaType: RenderPreviewMediaType,
			ByteLength: int64(len(previewBytes)), Digest: sha256Digest(previewBytes),
		}, Bytes: previewBytes},
	}
	for index := range evidenceBytes {
		descriptor := resultChecks[index].Evidence
		files = append(files, ProviderOutput{Descriptor: specialistrender.OutputFile{
			Ordinal: len(files), Role: "evidence", Path: descriptor.Path,
			MediaType: descriptor.MediaType, ByteLength: descriptor.ByteLength, Digest: descriptor.Digest,
		}, Bytes: evidenceBytes[index]})
	}
	receipt := testProviderReceipt(t, request, resultBytes)
	receipt.Files = make([]specialistrender.OutputFile, len(files))
	receipt.TotalOutputBytes = 0
	for index, file := range files {
		receipt.Files[index] = file.Descriptor
		receipt.TotalOutputBytes += file.Descriptor.ByteLength
	}
	receipt.ReceiptDigest, err = specialistrender.ComputeReceiptDigest(receipt)
	if err != nil || specialistrender.ValidateReceipt(receipt) != nil {
		return ProviderResponseObservation{}, errors.New("test provider receipt is invalid")
	}
	if err := custody.AdmitReceipt(ctx, receipt); err != nil {
		return ProviderResponseObservation{}, err
	}
	for _, file := range files {
		writer, err := custody.OpenFile(ctx, file.Descriptor)
		if err != nil {
			return ProviderResponseObservation{}, err
		}
		if written, err := writer.WriteContext(ctx, file.Bytes); err != nil || written != len(file.Bytes) {
			return ProviderResponseObservation{}, errors.New("test provider custody write failed")
		}
	}
	observation := ProviderResponseObservation{
		Receipt: receipt, WireSHA256: "sha256:" + repeatHex("e"),
	}
	if err := custody.Commit(ctx, observation); err != nil {
		return ProviderResponseObservation{}, err
	}
	return observation, nil
}

func successfulPreviewBytes(command RenderCommandV2) ([]byte, string, error) {
	body := "Verified preview."
	view, err := generationstop.CanonicalJSON(PreviewTextViewV1{
		Body: body, ByteLength: int64(len(body)), Digest: sha256Digest([]byte(body)),
		Kind: "text", Label: "Preview", MediaType: "text/plain", Ordinal: 1,
	})
	if err != nil {
		return nil, "", err
	}
	validation := make([]PreviewValidationV1, len(command.PackRequiredChecks))
	for index, check := range command.PackRequiredChecks {
		validation[index] = PreviewValidationV1{Check: check.Check, Label: check.Label, Status: "passed"}
	}
	preview := ArtifactPreviewV1{
		Contract: previewContractV1, Facet: command.Facet, Facts: []PreviewFactV1{},
		Limitations: []PreviewLimitationV1{}, SchemaVersion: 1, Summary: "Verified summary.",
		Title: "Verified title", Validation: validation, Views: []json.RawMessage{view},
	}
	preview.Digest, err = sealedDigest(preview)
	if err != nil {
		return nil, "", err
	}
	encoded, err := generationstop.CanonicalJSON(preview)
	return encoded, preview.Digest, err
}

func formatOrdinal(value int) string {
	return fmt.Sprintf("%03d", value)
}
