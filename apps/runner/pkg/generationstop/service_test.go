// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package generationstop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/storage"
)

func TestStopOnceClaimsBeforeExactStopAndPublishesCanonicalReceipt(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	objects := newFakeObjectStore()
	containers := newFakeContainer(request)
	containers.beforeInspect = func(call int) error {
		if call != 1 {
			return nil
		}
		if _, ok := objects.findSuffix("/claim.json"); !ok {
			return errors.New("container inspected before immutable claim")
		}
		if _, ok := objects.findSuffix("/receipt.json"); ok {
			return errors.New("receipt existed before terminal proof")
		}
		return nil
	}
	service := mustService(t, containers, objects)
	service.now = func() time.Time { return mustTime("2026-08-24T00:02:00Z") }

	receipt, err := service.StopOnce(context.Background(), request)
	if err != nil {
		t.Fatalf("stop once failed: %v", err)
	}
	if containers.stopCalls != 1 || containers.inspectCalls != 2 {
		t.Fatalf("unexpected provider effects: inspect=%d stop=%d", containers.inspectCalls, containers.stopCalls)
	}
	if got := containers.stopTargets[0]; got != exactTarget(request) {
		t.Fatalf("stop did not carry exact generation authority: %#v", got)
	}
	if receipt.Request.RequestFingerprint != request.RequestFingerprint ||
		receipt.TerminalGeneration.ExpectedGeneration != request.ExpectedGeneration ||
		receipt.TerminalGeneration.ExecutionFinishedAt != "2026-08-24T00:01:00Z" ||
		receipt.StoppedAt != "2026-08-24T00:02:00Z" {
		t.Fatalf("receipt did not echo exact terminal authority: %#v", receipt)
	}
	digest, ref, err := deriveReceiptIdentity(request, receipt.TerminalGeneration, receipt.StoppedAt)
	if err != nil || receipt.ReceiptDigest != digest || receipt.ReceiptRef != ref {
		t.Fatalf("canonical receipt identity mismatch: %#v, %v", receipt, err)
	}
	if !strings.HasPrefix(receipt.ReceiptRef, "ambit.stopped-generation-receipt:v1:sha256:") {
		t.Fatalf("unexpected receipt ref %q", receipt.ReceiptRef)
	}
}

func TestCurrentGenerationIsReadOnlyAndRejectsProviderAuthorityDrift(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	objects := newFakeObjectStore()
	containers := newFakeContainer(request)
	service := mustService(t, containers, objects)
	query := queryFromRequest(request)

	observed, err := service.ObserveCurrent(context.Background(), query)
	if err != nil {
		t.Fatalf("current generation failed: %v", err)
	}
	if observed.Generation != request.ExpectedGeneration ||
		observed.State != "running" || observed.ObservedAt != "2026-08-24T00:02:00Z" ||
		containers.inspectCalls != 1 || containers.stopCalls != 0 || len(objects.objects) != 0 {
		t.Fatalf("current generation was not a pure exact read: %#v", observed)
	}

	containers.observation.Fence.WorkspaceExecutionManifestRef = "ambit.workspace-execution-manifest:v1:sha256:" + strings.Repeat("f", 64)
	_, err = service.ObserveCurrent(context.Background(), query)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected provider fence conflict, got %v", err)
	}

	containers.observation.Fence = request.Fence
	containers.makeExited()
	observed, err = service.ObserveCurrent(context.Background(), query)
	if err != nil || observed.State != "stopped" || observed.Generation != request.ExpectedGeneration {
		t.Fatalf("exact stopped discovery failed: %#v, %v", observed, err)
	}
	containers.observation.State = RuntimeState{Status: "paused", Running: true, Paused: true, PID: 42}
	containers.observation.Generation.ExecutionFinishedAt = ""
	if _, err := service.ObserveCurrent(context.Background(), query); !errors.Is(err, ErrConflict) {
		t.Fatalf("paused discovery was not rejected: %v", err)
	}
}

func TestProviderCurrentGenerationNormalizesExactMillisecondAuthority(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	containers := newFakeContainer(request)
	containers.observation.Generation.ContainerCreatedAt = "2026-08-23T23:59:00.123456789Z"
	containers.observation.Generation.ExecutionStartedAt = "2026-08-24T00:00:00Z"
	observer, err := NewObserver(containers)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := observer.ObserveProviderCurrent(
		context.Background(),
		ProviderGenerationObservationRequest{
			Source: request.Source, Owner: providerOwner(request.Owner), Fence: request.Fence,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Generation.ContainerCreatedAt != "2026-08-23T23:59:00.123Z" ||
		observed.Generation.ExecutionStartedAt != "2026-08-24T00:00:00.000Z" {
		t.Fatalf("provider generation was not normalized to exact milliseconds: %#v", observed.Generation)
	}
}

func TestRequireCurrentReceiptReprovesFullAuthorityAndFreshProviderState(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	objects := newFakeObjectStore()
	containers := newFakeContainer(request)
	service := mustService(t, containers, objects)
	receipt, err := service.StopOnce(context.Background(), request)
	if err != nil {
		t.Fatalf("seed stop failed: %v", err)
	}
	authority := authorityFromReceipt(receipt)

	restarted := mustService(t, containers, objects)
	inspectBefore := containers.inspectCalls
	got, err := restarted.RequireCurrentReceipt(
		context.Background(),
		request.Source,
		request.Owner,
		request.Purpose,
		authority,
	)
	if err != nil || !receiptsEqual(got, receipt) {
		t.Fatalf("current receipt reproof failed: %#v, %v", got, err)
	}
	if containers.inspectCalls != inspectBefore+1 || containers.stopCalls != 1 {
		t.Fatalf("reproof did not perform exactly one fresh read: inspect=%d stop=%d", containers.inspectCalls, containers.stopCalls)
	}

	claimsOnlyMutations := map[string]func(*Source, *Owner, *Purpose, *StopAuthority){
		"working-copy-owner": func(_ *Source, owner *Owner, _ *Purpose, _ *StopAuthority) {
			owner.WorkingCopyID = "00000000-0000-4000-8000-000000000099"
		},
		"purpose": func(_ *Source, _ *Owner, purpose *Purpose, _ *StopAuthority) {
			*purpose = validRendererPurpose()
		},
		"receipt-digest": func(_ *Source, _ *Owner, _ *Purpose, authority *StopAuthority) {
			authority.ReceiptDigest = "sha256:" + strings.Repeat("f", 64)
			authority.ReceiptRef = "ambit.stopped-generation-receipt:v1:" + authority.ReceiptDigest
		},
		"terminal": func(_ *Source, _ *Owner, _ *Purpose, authority *StopAuthority) {
			authority.TerminalGeneration.ExitCode++
		},
		"fence": func(_ *Source, _ *Owner, _ *Purpose, authority *StopAuthority) {
			authority.Fence.WorkspaceExecutionManifestRef = "ambit.workspace-execution-manifest:v1:sha256:" + strings.Repeat("f", 64)
		},
	}
	for name, mutate := range claimsOnlyMutations {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			source := request.Source
			owner := request.Owner
			purpose := clonePurpose(request.Purpose)
			candidate := authority
			mutate(&source, &owner, &purpose, &candidate)
			before := containers.inspectCalls
			if _, err := restarted.RequireCurrentReceipt(context.Background(), source, owner, purpose, candidate); !errors.Is(err, ErrConflict) {
				t.Fatalf("expected immutable authority conflict, got %v", err)
			}
			if containers.inspectCalls != before {
				t.Fatal("immutable authority mismatch reached provider reproof")
			}
		})
	}

	t.Run("provider-fence-drift", func(t *testing.T) {
		containers.observation.Fence.WorkspaceExecutionManifestRef = "ambit.workspace-execution-manifest:v1:sha256:" + strings.Repeat("f", 64)
		if _, err := restarted.RequireCurrentReceipt(
			context.Background(), request.Source, request.Owner, request.Purpose, authority,
		); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected fresh provider fence conflict, got %v", err)
		}
		containers.observation.Fence = request.Fence
	})

	t.Run("generation-restarted", func(t *testing.T) {
		containers.observation.State = RuntimeState{Status: "running", Running: true, PID: 77}
		containers.observation.Generation.ExecutionFinishedAt = ""
		containers.observation.Generation.RestartCount++
		if _, err := restarted.RequireCurrentReceipt(
			context.Background(), request.Source, request.Owner, request.Purpose, authority,
		); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected restarted-generation conflict, got %v", err)
		}
	})
}

func TestValidateBindingIsPureAndDoesNotRequireCurrentProviderState(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	containers := newFakeContainer(request)
	objects := newFakeObjectStore()
	service := mustService(t, containers, objects)
	receipt, err := service.StopOnce(context.Background(), request)
	if err != nil {
		t.Fatalf("seed receipt failed: %v", err)
	}
	authority := authorityFromReceipt(receipt)
	inspectCalls := containers.inspectCalls
	if err := ValidateBinding(request.Source, request.Owner, authority); err != nil {
		t.Fatalf("valid pure binding failed: %v", err)
	}
	if err := ValidateSource(request.Source); err != nil {
		t.Fatalf("valid source failed: %v", err)
	}
	if err := ValidateOwner(request.Owner); err != nil {
		t.Fatalf("valid owner failed: %v", err)
	}
	if err := ValidateStopAuthority(authority); err != nil {
		t.Fatalf("valid stop authority failed: %v", err)
	}
	if containers.inspectCalls != inspectCalls || containers.stopCalls != 1 {
		t.Fatal("pure binding validation performed provider I/O")
	}

	invalidSource := request.Source
	invalidSource.ProviderResourceID = " contains-space"
	if err := ValidateBinding(invalidSource, request.Owner, authority); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid source was accepted: %v", err)
	}
	invalidOwner := request.Owner
	invalidOwner.WorkingCopyID = "not-a-uuid"
	if err := ValidateBinding(request.Source, invalidOwner, authority); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid owner was accepted: %v", err)
	}
	invalidAuthority := authority
	invalidAuthority.ReceiptDigest = "sha256:" + strings.Repeat("f", 64)
	if err := ValidateBinding(request.Source, request.Owner, invalidAuthority); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid authority was accepted: %v", err)
	}
}

func TestReceiptWireHasOnlyFrozenNestedKeys(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	service := mustService(t, newFakeContainer(request), newFakeObjectStore())
	receipt, err := service.StopOnce(context.Background(), request)
	if err != nil {
		t.Fatalf("seed stop failed: %v", err)
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatalf("decode receipt wire: %v", err)
	}
	wantKeys := []string{
		"kind", "receiptDigest", "receiptRef", "request", "stoppedAt", "terminalGeneration", "version",
	}
	for _, key := range wantKeys {
		if _, ok := wire[key]; !ok {
			t.Fatalf("receipt wire missing %q: %s", key, data)
		}
	}
	if len(wire) != len(wantKeys) {
		t.Fatalf("receipt wire gained an unreviewed field: %s", data)
	}
	if _, flattened := wire["operationId"]; flattened {
		t.Fatalf("receipt request was flattened: %s", data)
	}
}

func TestDecodeExactJSONAcceptsWireOrderAndWhitespaceButRejectsSchemaAmbiguity(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	original, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var unordered map[string]any
	if err := json.Unmarshal(original, &unordered); err != nil {
		t.Fatalf("decode request fixture: %v", err)
	}
	reordered, err := json.MarshalIndent(unordered, "", "  ")
	if err != nil {
		t.Fatalf("indent reordered request: %v", err)
	}
	var decoded StopRequest
	if err := DecodeExactJSON(reordered, &decoded); err != nil || !stopRequestsEqual(decoded, request) {
		t.Fatalf("wire-irrelevant order/whitespace was rejected: %#v, %v", decoded, err)
	}

	tests := map[string][]byte{
		"nested-duplicate": []byte(strings.Replace(
			string(original),
			`"providerResourceId":"sandbox-1"`,
			`"providerResourceId":"sandbox-1","providerResourceId":"replacement"`,
			1,
		)),
		"missing-required-zero": []byte(strings.Replace(string(original), `,"restartCount":0`, "", 1)),
		"case-alias":            []byte(strings.Replace(string(original), `"restartCount":0`, `"RestartCount":0`, 1)),
		"explicit-null-variant": []byte(strings.Replace(
			string(original),
			`"purpose":{"kind":"working_copy_capture"}`,
			`"purpose":{"kind":"working_copy_capture","rendererProcessIdentity":null}`,
			1,
		)),
		"unknown":  []byte(strings.Replace(string(original), `"purpose":`, `"unknown":1,"purpose":`, 1)),
		"trailing": append(append([]byte(nil), original...), []byte(` {}`)...),
		"unpaired-high-surrogate": []byte(strings.Replace(
			string(original), "sandbox-1", `sandbox-\ud800`, 1,
		)),
		"unpaired-low-surrogate": []byte(strings.Replace(
			string(original), "sandbox-1", `sandbox-\udc00`, 1,
		)),
		"high-followed-by-non-low": []byte(strings.Replace(
			string(original), "sandbox-1", `sandbox-\ud800\u0041`, 1,
		)),
	}
	invalidUTF8 := append([]byte(nil), original...)
	markerIndex := strings.Index(string(invalidUTF8), "sandbox-1")
	invalidUTF8[markerIndex] = 0xff
	tests["invalid-utf8"] = invalidUTF8
	for name, data := range tests {
		name, data := name, data
		t.Run(name, func(t *testing.T) {
			var target StopRequest
			if err := DecodeExactJSON(data, &target); err == nil {
				t.Fatalf("ambiguous exact JSON was accepted: %s", data)
			}
		})
	}

	validPair := []byte(strings.Replace(string(original), "sandbox-1", `sandbox-\ud83d\ude80`, 1))
	var pairDecoded StopRequest
	if err := DecodeExactJSON(validPair, &pairDecoded); err != nil {
		t.Fatalf("valid surrogate pair was rejected: %v", err)
	}
	if pairDecoded.Source.ProviderResourceID != "sandbox-🚀" {
		t.Fatalf("valid surrogate pair decoded incorrectly: %q", pairDecoded.Source.ProviderResourceID)
	}
}

func TestCompleteReplaySurvivesServiceReconstructionWithoutProviderEffect(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	objects := newFakeObjectStore()
	firstContainers := newFakeContainer(request)
	first := mustService(t, firstContainers, objects)
	first.now = func() time.Time { return mustTime("2026-08-24T00:02:00Z") }
	want, err := first.StopOnce(context.Background(), request)
	if err != nil {
		t.Fatalf("first stop failed: %v", err)
	}

	restartedContainers := newFakeContainer(request)
	restartedContainers.inspectErrors = []error{errors.New("must not inspect on complete replay")}
	restarted := mustService(t, restartedContainers, objects)
	got, err := restarted.StopOnce(context.Background(), request)
	if err != nil || got != want {
		t.Fatalf("restart replay did not return immutable receipt: %#v, %v", got, err)
	}
	if restartedContainers.inspectCalls != 0 || restartedContainers.stopCalls != 0 {
		t.Fatalf("complete replay touched provider: inspect=%d stop=%d", restartedContainers.inspectCalls, restartedContainers.stopCalls)
	}
	observation, err := restarted.Observe(context.Background(), request)
	if err != nil || observation.Status != ObservationComplete || observation.Receipt == nil || *observation.Receipt != want {
		t.Fatalf("durable complete observation failed: %#v, %v", observation, err)
	}
}

func TestClaimAndReceiptResponseLossReconcileExactWinner(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	objects := newFakeObjectStore()
	objects.failAfterStoreSuffix = "/claim.json"
	containers := newFakeContainer(request)
	service := mustService(t, containers, objects)
	service.now = func() time.Time { return mustTime("2026-08-24T00:02:00Z") }

	if _, err := service.StopOnce(context.Background(), request); err != nil {
		t.Fatalf("lost claim response was not reconciled: %v", err)
	}
	if containers.stopCalls != 1 {
		t.Fatalf("claim reconciliation duplicated or skipped stop: %d", containers.stopCalls)
	}

	secondRequest := validStopRequest()
	secondRequest.OperationID = "20000000-0000-4000-8000-000000000009"
	refreshRequestFingerprint(&secondRequest)
	secondContainers := newFakeContainer(secondRequest)
	objects.failAfterStoreSuffix = "/receipt.json"
	second := mustService(t, secondContainers, objects)
	second.now = func() time.Time { return mustTime("2026-08-24T00:02:00Z") }
	receipt, err := second.StopOnce(context.Background(), secondRequest)
	if err != nil || receipt.ReceiptDigest == "" {
		t.Fatalf("lost receipt response was not reconciled: %#v, %v", receipt, err)
	}
	if secondContainers.stopCalls != 1 {
		t.Fatalf("receipt reconciliation duplicated stop: %d", secondContainers.stopCalls)
	}
}

func TestCrashWindowsResumeClaimAndTerminalGeneration(t *testing.T) {
	t.Parallel()
	t.Run("after-claim-before-stop", func(t *testing.T) {
		request := validStopRequest()
		objects := newFakeObjectStore()
		firstContainers := newFakeContainer(request)
		firstContainers.inspectErrors = []error{errors.New("runner crashed before inspect")}
		first := mustService(t, firstContainers, objects)
		if _, err := first.StopOnce(context.Background(), request); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected unavailable first attempt, got %v", err)
		}
		observation, err := first.Observe(context.Background(), request)
		if err != nil || observation.Status != ObservationPartial {
			t.Fatalf("claim was not durably partial: %#v, %v", observation, err)
		}

		secondContainers := newFakeContainer(request)
		second := mustService(t, secondContainers, objects)
		if _, err := second.StopOnce(context.Background(), request); err != nil {
			t.Fatalf("restart did not resume claim: %v", err)
		}
		if secondContainers.stopCalls != 1 {
			t.Fatalf("restart did not perform exact pending stop: %d", secondContainers.stopCalls)
		}
	})

	t.Run("stop-response-lost-after-effect", func(t *testing.T) {
		request := validStopRequest()
		containers := newFakeContainer(request)
		containers.stopErr = errors.New("transport response lost")
		service := mustService(t, containers, newFakeObjectStore())
		receipt, err := service.StopOnce(context.Background(), request)
		if err != nil || receipt.TerminalGeneration.ExecutionFinishedAt == "" {
			t.Fatalf("terminal provider state did not reconcile stop response loss: %#v, %v", receipt, err)
		}
	})

	t.Run("after-stop-before-receipt", func(t *testing.T) {
		request := validStopRequest()
		objects := newFakeObjectStore()
		objects.failBeforeStoreSuffix = "/receipt.json"
		containers := newFakeContainer(request)
		first := mustService(t, containers, objects)
		if _, err := first.StopOnce(context.Background(), request); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("expected unknown receipt publication outcome, got %v", err)
		}
		if containers.stopCalls != 1 || containers.observation.State.Status != "exited" {
			t.Fatalf("stop did not survive receipt failure: %#v", containers)
		}

		second := mustService(t, containers, objects)
		if _, err := second.StopOnce(context.Background(), request); err != nil {
			t.Fatalf("restart did not publish receipt from terminal state: %v", err)
		}
		if containers.stopCalls != 1 {
			t.Fatalf("terminal restart reissued stop: %d", containers.stopCalls)
		}
	})
}

func TestConflictingOperationReuseCannotInspectOrStop(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	objects := newFakeObjectStore()
	containers := newFakeContainer(request)
	service := mustService(t, containers, objects)
	containers.inspectErrors = []error{errors.New("first attempt cut after claim")}
	if _, err := service.StopOnce(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed to create partial claim: %v", err)
	}
	inspectCalls := containers.inspectCalls

	mutations := map[string]func(*StopRequest){
		"owner":  func(value *StopRequest) { value.Owner.UserID = "00000000-0000-4000-8000-000000000099" },
		"source": func(value *StopRequest) { value.Source.ProviderResourceID = "sandbox-replacement" },
		"fence": func(value *StopRequest) {
			value.Fence.WorkspaceExecutionManifestRef = "ambit.workspace-execution-manifest:v1:sha256:" + strings.Repeat("f", 64)
		},
		"generation": func(value *StopRequest) { value.ExpectedGeneration.ContainerID = strings.Repeat("b", 64) },
		"purpose":    func(value *StopRequest) { value.Purpose = validRendererPurpose() },
	}
	for name, mutate := range mutations {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			conflict := cloneStopRequest(request)
			mutate(&conflict)
			refreshRequestFingerprint(&conflict)
			if _, err := service.StopOnce(context.Background(), conflict); !errors.Is(err, ErrConflict) {
				t.Fatalf("expected immutable claim conflict, got %v", err)
			}
			if _, err := service.Observe(context.Background(), conflict); !errors.Is(err, ErrConflict) {
				t.Fatalf("expected immutable observation conflict, got %v", err)
			}
		})
	}
	if containers.inspectCalls != inspectCalls || containers.stopCalls != 0 {
		t.Fatalf("conflicting reuse reached provider: inspect=%d stop=%d", containers.inspectCalls, containers.stopCalls)
	}
}

func TestABAGenerationOwnerAndFenceDriftFailClosed(t *testing.T) {
	t.Parallel()
	mutations := map[string]func(*CurrentGenerationObservation){
		"container-id": func(value *CurrentGenerationObservation) {
			value.Generation.ContainerID = strings.Repeat("b", 64)
		},
		"container-created": func(value *CurrentGenerationObservation) {
			value.Generation.ContainerCreatedAt = "2026-08-23T23:59:01Z"
		},
		"execution-start": func(value *CurrentGenerationObservation) {
			value.Generation.ExecutionStartedAt = "2026-08-24T00:00:01Z"
		},
		"restart-count": func(value *CurrentGenerationObservation) { value.Generation.RestartCount++ },
		"owner": func(value *CurrentGenerationObservation) {
			value.Owner.RunID = "00000000-0000-4000-8000-000000000099"
		},
		"fence": func(value *CurrentGenerationObservation) {
			value.Fence.WorkspaceExecutionManifestRef = "ambit.workspace-execution-manifest:v1:sha256:" + strings.Repeat("f", 64)
		},
	}
	for name, mutate := range mutations {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			request := validStopRequest()
			containers := newFakeContainer(request)
			mutate(&containers.observation)
			objects := newFakeObjectStore()
			service := mustService(t, containers, objects)
			if _, err := service.StopOnce(context.Background(), request); !errors.Is(err, ErrConflict) {
				t.Fatalf("expected ABA conflict, got %v", err)
			}
			if containers.stopCalls != 0 {
				t.Fatalf("ABA conflict reached stop: %d", containers.stopCalls)
			}
			if _, ok := objects.findSuffix("/receipt.json"); ok {
				t.Fatal("ABA conflict published a receipt")
			}
		})
	}

	t.Run("replacement-after-stop", func(t *testing.T) {
		request := validStopRequest()
		containers := newFakeContainer(request)
		containers.afterStop = func(value *CurrentGenerationObservation) {
			value.Generation.ContainerID = strings.Repeat("b", 64)
		}
		objects := newFakeObjectStore()
		service := mustService(t, containers, objects)
		if _, err := service.StopOnce(context.Background(), request); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected post-stop replacement conflict, got %v", err)
		}
		if _, ok := objects.findSuffix("/receipt.json"); ok {
			t.Fatal("replacement generation received terminal receipt")
		}
	})
}

func TestOnlyExactExitedPIDZeroStateCanPublishReceipt(t *testing.T) {
	t.Parallel()
	nonTerminal := map[string]RuntimeState{
		"paused":      {Status: "paused", Running: true, Paused: true, PID: 42},
		"restarting":  {Status: "restarting", Restarting: true, PID: 0},
		"dead":        {Status: "dead", Dead: true, PID: 0},
		"created":     {Status: "created", PID: 0},
		"exited-pid":  {Status: "exited", PID: 42},
		"exited-dead": {Status: "exited", Dead: true, PID: 0},
	}
	for name, state := range nonTerminal {
		name, state := name, state
		t.Run(name, func(t *testing.T) {
			request := validStopRequest()
			containers := newFakeContainer(request)
			containers.observation.State = state
			if state.Status == "exited" {
				containers.observation.Generation.ExecutionFinishedAt = "2026-08-24T00:01:00Z"
			}
			objects := newFakeObjectStore()
			service := mustService(t, containers, objects)
			if _, err := service.StopOnce(context.Background(), request); !errors.Is(err, ErrConflict) {
				t.Fatalf("expected exact-state conflict, got %v", err)
			}
			if containers.stopCalls != 0 {
				t.Fatalf("invalid state reached stop: %d", containers.stopCalls)
			}
			if _, ok := objects.findSuffix("/receipt.json"); ok {
				t.Fatal("invalid terminal state published receipt")
			}
		})
	}

	t.Run("already-exited-recovery", func(t *testing.T) {
		request := validStopRequest()
		containers := newFakeContainer(request)
		containers.makeExited()
		service := mustService(t, containers, newFakeObjectStore())
		receipt, err := service.StopOnce(context.Background(), request)
		if err != nil || receipt.TerminalGeneration.ExecutionFinishedAt == "" {
			t.Fatalf("exact exited recovery failed: %#v, %v", receipt, err)
		}
		if containers.stopCalls != 0 {
			t.Fatalf("already exited generation was stopped again: %d", containers.stopCalls)
		}
	})
}

func TestReceiptTamperingAndNonCanonicalDurableRecordsFailClosed(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	objects := newFakeObjectStore()
	service := mustService(t, newFakeContainer(request), objects)
	receipt, err := service.StopOnce(context.Background(), request)
	if err != nil {
		t.Fatalf("seed receipt failed: %v", err)
	}
	receiptKey, ok := objects.keyWithSuffix("/receipt.json")
	if !ok {
		t.Fatal("receipt missing")
	}

	tampered := receipt
	tampered.TerminalGeneration.ExitCode++
	objects.setJSON(receiptKey, tampered)
	restarted := mustService(t, newFakeContainer(request), objects)
	if _, err := restarted.StopOnce(context.Background(), request); !errors.Is(err, ErrConflict) {
		t.Fatalf("tampered receipt was accepted: %v", err)
	}

	claimKey, _ := objects.keyWithSuffix("/claim.json")
	objects.setRaw(claimKey, append(objects.getRaw(claimKey), []byte(` {}`)...))
	if _, err := restarted.Observe(context.Background(), request); !errors.Is(err, ErrConflict) {
		t.Fatalf("trailing durable JSON was accepted: %v", err)
	}
}

func TestDurableRecordsRejectNestedDuplicateKeysAndInvalidUTF8(t *testing.T) {
	t.Parallel()
	request := validStopRequest()

	t.Run("nested-claim-duplicate", func(t *testing.T) {
		objects := newFakeObjectStore()
		containers := newFakeContainer(request)
		service := mustService(t, containers, objects)
		containers.inspectErrors = []error{errors.New("leave claim partial")}
		if _, err := service.StopOnce(context.Background(), request); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("seed partial claim failed: %v", err)
		}
		claimKey, _ := objects.keyWithSuffix("/claim.json")
		data := strings.Replace(
			string(objects.getRaw(claimKey)),
			`"providerResourceId":"sandbox-1"`,
			`"providerResourceId":"sandbox-1","providerResourceId":"sandbox-replacement"`,
			1,
		)
		objects.setRaw(claimKey, []byte(data))
		if _, err := service.Observe(context.Background(), request); !errors.Is(err, ErrConflict) {
			t.Fatalf("nested duplicate claim key was accepted: %v", err)
		}
	})

	t.Run("nested-receipt-duplicate", func(t *testing.T) {
		objects := newFakeObjectStore()
		service := mustService(t, newFakeContainer(request), objects)
		if _, err := service.StopOnce(context.Background(), request); err != nil {
			t.Fatalf("seed receipt failed: %v", err)
		}
		receiptKey, _ := objects.keyWithSuffix("/receipt.json")
		data := strings.Replace(
			string(objects.getRaw(receiptKey)),
			`"exitCode":0`,
			`"exitCode":0,"exitCode":1`,
			1,
		)
		objects.setRaw(receiptKey, []byte(data))
		if _, err := service.Observe(context.Background(), request); !errors.Is(err, ErrConflict) {
			t.Fatalf("nested duplicate receipt key was accepted: %v", err)
		}
	})

	t.Run("invalid-utf8", func(t *testing.T) {
		objects := newFakeObjectStore()
		containers := newFakeContainer(request)
		containers.inspectErrors = []error{errors.New("leave claim partial")}
		service := mustService(t, containers, objects)
		if _, err := service.StopOnce(context.Background(), request); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("seed partial claim failed: %v", err)
		}
		claimKey, _ := objects.keyWithSuffix("/claim.json")
		data := objects.getRaw(claimKey)
		marker := []byte("sandbox-1")
		index := strings.Index(string(data), string(marker))
		if index < 0 {
			t.Fatal("claim did not contain source marker")
		}
		data[index] = 0xff
		objects.setRaw(claimKey, data)
		if _, err := service.Observe(context.Background(), request); !errors.Is(err, ErrConflict) {
			t.Fatalf("invalid UTF-8 claim was accepted: %v", err)
		}
	})

	t.Run("missing-zero-valued-required-receipt-field", func(t *testing.T) {
		objects := newFakeObjectStore()
		service := mustService(t, newFakeContainer(request), objects)
		if _, err := service.StopOnce(context.Background(), request); err != nil {
			t.Fatalf("seed receipt failed: %v", err)
		}
		receiptKey, _ := objects.keyWithSuffix("/receipt.json")
		data := strings.Replace(string(objects.getRaw(receiptKey)), `,"exitCode":0`, "", 1)
		objects.setRaw(receiptKey, []byte(data))
		if _, err := service.Observe(context.Background(), request); !errors.Is(err, ErrConflict) {
			t.Fatalf("missing required zero receipt field was accepted: %v", err)
		}
	})

	t.Run("case-insensitive-receipt-alias", func(t *testing.T) {
		objects := newFakeObjectStore()
		service := mustService(t, newFakeContainer(request), objects)
		if _, err := service.StopOnce(context.Background(), request); err != nil {
			t.Fatalf("seed receipt failed: %v", err)
		}
		receiptKey, _ := objects.keyWithSuffix("/receipt.json")
		data := strings.Replace(string(objects.getRaw(receiptKey)), `"exitCode":0`, `"ExitCode":0`, 1)
		objects.setRaw(receiptKey, []byte(data))
		if _, err := service.Observe(context.Background(), request); !errors.Is(err, ErrConflict) {
			t.Fatalf("case-insensitive receipt alias was accepted: %v", err)
		}
	})

	t.Run("explicit-null-omitted-purpose-field", func(t *testing.T) {
		objects := newFakeObjectStore()
		containers := newFakeContainer(request)
		containers.inspectErrors = []error{errors.New("leave claim partial")}
		service := mustService(t, containers, objects)
		if _, err := service.StopOnce(context.Background(), request); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("seed partial claim failed: %v", err)
		}
		claimKey, _ := objects.keyWithSuffix("/claim.json")
		data := strings.Replace(
			string(objects.getRaw(claimKey)),
			`"purpose":{"kind":"working_copy_capture"}`,
			`"purpose":{"kind":"working_copy_capture","rendererProcessIdentity":null}`,
			1,
		)
		objects.setRaw(claimKey, []byte(data))
		if _, err := service.Observe(context.Background(), request); !errors.Is(err, ErrConflict) {
			t.Fatalf("explicit null optional purpose field was accepted: %v", err)
		}
	})

	t.Run("missing-required-claim-number", func(t *testing.T) {
		objects := newFakeObjectStore()
		containers := newFakeContainer(request)
		containers.inspectErrors = []error{errors.New("leave claim partial")}
		service := mustService(t, containers, objects)
		if _, err := service.StopOnce(context.Background(), request); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("seed partial claim failed: %v", err)
		}
		claimKey, _ := objects.keyWithSuffix("/claim.json")
		data := strings.Replace(string(objects.getRaw(claimKey)), `,"restartCount":0`, "", 1)
		objects.setRaw(claimKey, []byte(data))
		if _, err := service.Observe(context.Background(), request); !errors.Is(err, ErrConflict) {
			t.Fatalf("missing required claim number was accepted: %v", err)
		}
	})
}

func TestCrossServiceConcurrentReceiptPublicationConvergesToWinner(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	objects := newFakeObjectStore()
	containers := newFakeContainer(request)
	containers.makeExited()
	first := mustService(t, containers, objects)
	second := mustService(t, containers, objects)
	first.now = func() time.Time { return mustTime("2026-08-24T00:02:00Z") }
	second.now = func() time.Time { return mustTime("2026-08-24T00:03:00Z") }

	var arrived sync.WaitGroup
	arrived.Add(2)
	release := make(chan struct{})
	objects.beforeCreate = func(key string) {
		if !strings.HasSuffix(key, "/receipt.json") {
			return
		}
		arrived.Done()
		<-release
	}
	type result struct {
		receipt Receipt
		err     error
	}
	results := make(chan result, 2)
	go func() {
		receipt, err := first.StopOnce(context.Background(), request)
		results <- result{receipt: receipt, err: err}
	}()
	go func() {
		receipt, err := second.StopOnce(context.Background(), request)
		results <- result{receipt: receipt, err: err}
	}()
	arrived.Wait()
	close(release)
	firstResult := <-results
	secondResult := <-results
	if firstResult.err != nil || secondResult.err != nil {
		t.Fatalf("cross-service convergence failed: %v / %v", firstResult.err, secondResult.err)
	}
	if !receiptsEqual(firstResult.receipt, secondResult.receipt) {
		t.Fatalf("cross-service callers did not converge to conditional-create winner:\n%#v\n%#v", firstResult.receipt, secondResult.receipt)
	}
	if firstResult.receipt.StoppedAt != "2026-08-24T00:02:00Z" &&
		firstResult.receipt.StoppedAt != "2026-08-24T00:03:00Z" {
		t.Fatalf("winner has an unexpected stoppedAt: %q", firstResult.receipt.StoppedAt)
	}
	if containers.stopCalls != 0 {
		t.Fatalf("already-terminal cross-service publication issued stop: %d", containers.stopCalls)
	}
}

func TestCrossServiceRunningCallsMayDuplicateTransportButConvergeOneLogicalTransition(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	objects := newFakeObjectStore()
	containers := newFakeContainer(request)
	first := mustService(t, containers, objects)
	second := mustService(t, containers, objects)
	first.now = func() time.Time { return mustTime("2026-08-24T00:02:00Z") }
	second.now = func() time.Time { return mustTime("2026-08-24T00:03:00Z") }

	var stopsArrived sync.WaitGroup
	stopsArrived.Add(2)
	releaseStops := make(chan struct{})
	containers.beforeStop = func(target ExactStopTarget) {
		if target != exactTarget(request) {
			panic(fmt.Sprintf("replacement stop target: %#v", target))
		}
		stopsArrived.Done()
		<-releaseStops
	}
	var receiptsArrived sync.WaitGroup
	receiptsArrived.Add(2)
	releaseReceipts := make(chan struct{})
	objects.beforeCreate = func(key string) {
		if !strings.HasSuffix(key, "/receipt.json") {
			return
		}
		receiptsArrived.Done()
		<-releaseReceipts
	}

	type result struct {
		receipt Receipt
		err     error
	}
	results := make(chan result, 2)
	for _, service := range []*Service{first, second} {
		service := service
		go func() {
			receipt, err := service.StopOnce(context.Background(), request)
			results <- result{receipt: receipt, err: err}
		}()
	}
	stopsArrived.Wait()
	close(releaseStops)
	receiptsArrived.Wait()
	close(releaseReceipts)
	firstResult := <-results
	secondResult := <-results
	if firstResult.err != nil || secondResult.err != nil {
		t.Fatalf("concurrent running stops failed: %v / %v", firstResult.err, secondResult.err)
	}
	if !receiptsEqual(firstResult.receipt, secondResult.receipt) {
		t.Fatalf("concurrent running stops did not converge:\n%#v\n%#v", firstResult.receipt, secondResult.receipt)
	}
	if containers.stopCalls < 1 || containers.stopCalls > 2 {
		t.Fatalf("exact transport calls were not bounded to 1-2: %d", containers.stopCalls)
	}
	for _, target := range containers.stopTargets {
		if target != exactTarget(request) {
			t.Fatalf("concurrent call adopted a replacement target: %#v", target)
		}
	}
	if objects.countSuffix("/claim.json") != 1 || objects.countSuffix("/receipt.json") != 1 {
		t.Fatalf("logical operation did not retain one claim/receipt: %#v", objects.objects)
	}

	inspectBefore := containers.inspectCalls
	replay, err := mustService(t, containers, objects).StopOnce(context.Background(), request)
	if err != nil || !receiptsEqual(replay, firstResult.receipt) {
		t.Fatalf("durable exact replay diverged: %#v, %v", replay, err)
	}
	if containers.inspectCalls != inspectBefore {
		t.Fatal("complete replay re-entered provider transport")
	}
}

func TestConditionalReceiptRejectsDivergentTerminalFacts(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	objects := newFakeObjectStore()
	firstContainer := newFakeContainer(request)
	firstContainer.makeExited()
	secondContainer := newFakeContainer(request)
	secondContainer.makeExited()
	secondContainer.observation.Generation.ExitCode = 137
	secondContainer.observation.Generation.OOMKilled = true
	first := mustService(t, firstContainer, objects)
	second := mustService(t, secondContainer, objects)
	first.now = func() time.Time { return mustTime("2026-08-24T00:02:00Z") }
	second.now = func() time.Time { return mustTime("2026-08-24T00:03:00Z") }

	var arrived sync.WaitGroup
	arrived.Add(2)
	release := make(chan struct{})
	objects.beforeCreate = func(key string) {
		if !strings.HasSuffix(key, "/receipt.json") {
			return
		}
		arrived.Done()
		<-release
	}
	type result struct {
		receipt Receipt
		err     error
	}
	results := make(chan result, 2)
	go func() {
		receipt, err := first.StopOnce(context.Background(), request)
		results <- result{receipt: receipt, err: err}
	}()
	go func() {
		receipt, err := second.StopOnce(context.Background(), request)
		results <- result{receipt: receipt, err: err}
	}()
	arrived.Wait()
	close(release)
	left := <-results
	right := <-results
	successes := 0
	conflicts := 0
	for _, result := range []result{left, right} {
		switch {
		case result.err == nil:
			successes++
		case errors.Is(result.err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected divergent-terminal result: %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("divergent terminal facts did not select one winner and reject one loser: %#v / %#v", left, right)
	}
	if objects.countSuffix("/receipt.json") != 1 {
		t.Fatalf("divergent facts published more than one receipt: %#v", objects.objects)
	}
}

func TestPurposeUnionValidationIsExactAndExtensible(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	service := mustService(t, newFakeContainer(request), newFakeObjectStore())

	validRenderer := cloneStopRequest(request)
	validRenderer.Purpose = validRendererPurpose()
	refreshRequestFingerprint(&validRenderer)
	containers := newFakeContainer(validRenderer)
	service = mustService(t, containers, newFakeObjectStore())
	if _, err := service.StopOnce(context.Background(), validRenderer); err != nil {
		t.Fatalf("valid renderer purpose failed: %v", err)
	}

	invalid := map[string]Purpose{
		"capture-with-renderer-field": {
			Kind:      PurposeWorkingCopyCapture,
			SessionID: "ambit-document-render-" + strings.Repeat("a", 40),
		},
		"unknown": {Kind: "future_unadmitted_kind"},
		"renderer-session": {
			Kind:                    PurposeDocumentRendererQuiescence,
			SessionID:               "bad",
			Nonce:                   strings.Repeat("b", 32),
			RendererProcessIdentity: &RendererProcessIdentity{PID: 42, StartTicks: "123"},
		},
		"renderer-nonce": {
			Kind:                    PurposeDocumentRendererQuiescence,
			SessionID:               "ambit-document-render-" + strings.Repeat("a", 40),
			Nonce:                   strings.Repeat("B", 32),
			RendererProcessIdentity: &RendererProcessIdentity{PID: 42, StartTicks: "123"},
		},
		"renderer-pid": {
			Kind:                    PurposeDocumentRendererQuiescence,
			SessionID:               "ambit-document-render-" + strings.Repeat("a", 40),
			Nonce:                   strings.Repeat("b", 32),
			RendererProcessIdentity: &RendererProcessIdentity{PID: maximumSafeJSONInt + 1, StartTicks: "123"},
		},
		"renderer-start-ticks": {
			Kind:                    PurposeDocumentRendererQuiescence,
			SessionID:               "ambit-document-render-" + strings.Repeat("a", 40),
			Nonce:                   strings.Repeat("b", 32),
			RendererProcessIdentity: &RendererProcessIdentity{PID: 42, StartTicks: "0123"},
		},
	}
	for name, purpose := range invalid {
		name, purpose := name, purpose
		t.Run(name, func(t *testing.T) {
			candidate := cloneStopRequest(request)
			candidate.OperationID = "30000000-0000-4000-8000-000000000009"
			candidate.Purpose = purpose
			objects := newFakeObjectStore()
			containers := newFakeContainer(candidate)
			candidateService := mustService(t, containers, objects)
			if _, err := candidateService.StopOnce(context.Background(), candidate); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected invalid purpose, got %v", err)
			}
			if containers.inspectCalls != 0 || containers.stopCalls != 0 || len(objects.objects) != 0 {
				t.Fatal("invalid purpose reached a provider or durable effect")
			}
		})
	}
}

func TestComputeRequestFingerprintFrozenVectorsAndEnforcement(t *testing.T) {
	t.Parallel()
	capture := validStopRequest()
	if capture.RequestFingerprint != "7dd5161b4b26b60ad12c5ca45331e1438f682a6d6a97725be8db497d10b76d3c" {
		t.Fatalf("working-copy fingerprint vector drifted: %q", capture.RequestFingerprint)
	}
	computed, err := ComputeRequestFingerprint(capture)
	if err != nil || computed != capture.RequestFingerprint {
		t.Fatalf("public capture fingerprint helper failed: %q, %v", computed, err)
	}

	renderer := cloneStopRequest(capture)
	renderer.Purpose = validRendererPurpose()
	computed, err = ComputeRequestFingerprint(renderer)
	if err != nil {
		t.Fatalf("public renderer fingerprint helper failed: %v", err)
	}
	const rendererVector = "49c2dc4a258914ed71dba7709cf35d89497108555a1ab9b8c9d6a61506a9c7bc"
	if computed != rendererVector {
		t.Fatalf("renderer fingerprint vector drifted: %q", computed)
	}
	renderer.RequestFingerprint = computed
	if err := validateStopRequest(renderer); err != nil {
		t.Fatalf("renderer vector did not validate: %v", err)
	}

	stale := cloneStopRequest(capture)
	stale.ExpectedGeneration.RestartCount++
	objects := newFakeObjectStore()
	containers := newFakeContainer(stale)
	service := mustService(t, containers, objects)
	if _, err := service.StopOnce(context.Background(), stale); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("stale request fingerprint was accepted: %v", err)
	}
	if containers.inspectCalls != 0 || containers.stopCalls != 0 || len(objects.objects) != 0 {
		t.Fatal("stale fingerprint reached a durable or provider effect")
	}

	invalid := capture
	invalid.Purpose = Purpose{Kind: PurposeDocumentRendererQuiescence}
	if _, err := ComputeRequestFingerprint(invalid); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("helper fingerprinted invalid fields: %v", err)
	}
}

func TestCanonicalReceiptPayloadIsRecursivelySortedAndStable(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	terminal := TerminalGeneration{
		ExpectedGeneration:  request.ExpectedGeneration,
		ExecutionFinishedAt: "2026-08-24T00:01:00Z",
		ExitCode:            0,
		OOMKilled:           false,
	}
	payload := canonicalReceiptPayload{
		Version:            1,
		Kind:               receiptKind,
		Request:            request,
		TerminalGeneration: terminal,
		StoppedAt:          "2026-08-24T00:02:00Z",
	}
	got, err := canonicalJSON(payload)
	if err != nil {
		t.Fatalf("canonical JSON failed: %v", err)
	}
	want := `{"kind":"agent_workspace_stopped_generation_receipt","request":{"expectedGeneration":{"containerCreatedAt":"2026-08-23T23:59:00Z","containerId":"` + strings.Repeat("a", 64) + `","executionStartedAt":"2026-08-24T00:00:00Z","restartCount":0},"fence":{"workspaceExecutionManifestRef":"ambit.workspace-execution-manifest:v1:sha256:` + strings.Repeat("c", 64) + `"},"operationId":"10000000-0000-4000-8000-000000000009","owner":{"grantId":"00000000-0000-4000-8000-000000000005","runId":"00000000-0000-4000-8000-000000000004","tenantId":"00000000-0000-4000-8000-000000000001","userId":"00000000-0000-4000-8000-000000000002","workingCopyId":"00000000-0000-4000-8000-000000000006","workspaceId":"00000000-0000-4000-8000-000000000003"},"purpose":{"kind":"working_copy_capture"},"requestFingerprint":"` + request.RequestFingerprint + `","source":{"expectedProfile":"managed-container","expectedRuntimeKind":"full_image_runtime_pack","providerResourceId":"sandbox-1"}},"stoppedAt":"2026-08-24T00:02:00Z","terminalGeneration":{"containerCreatedAt":"2026-08-23T23:59:00Z","containerId":"` + strings.Repeat("a", 64) + `","executionFinishedAt":"2026-08-24T00:01:00Z","executionStartedAt":"2026-08-24T00:00:00Z","exitCode":0,"oomKilled":false,"restartCount":0},"version":1}`
	if string(got) != want {
		t.Fatalf("canonical payload drifted\nwant: %s\n got: %s", want, got)
	}
	expectedHash := sha256.Sum256([]byte(want))
	digest, ref, err := deriveReceiptIdentity(request, terminal, "2026-08-24T00:02:00Z")
	if err != nil {
		t.Fatalf("derive receipt identity failed: %v", err)
	}
	wantDigest := "sha256:" + hex.EncodeToString(expectedHash[:])
	if digest != wantDigest || ref != "ambit.stopped-generation-receipt:v1:"+wantDigest {
		t.Fatalf("receipt identity drifted: digest=%q ref=%q", digest, ref)
	}
}

func TestCanonicalJSONUsesMinimalUTF8StringEscaping(t *testing.T) {
	t.Parallel()
	got, err := canonicalJSON(map[string]any{
		"z": map[string]any{"b": 2, "a": 1},
		"a": "<&>é\n\t\b\f\r\"\\\x01",
	})
	if err != nil {
		t.Fatalf("canonical JSON failed: %v", err)
	}
	want := "{\"a\":\"<&>é\\n\\t\\b\\f\\r\\\"\\\\\\u0001\",\"z\":{\"a\":1,\"b\":2}}"
	if string(got) != want {
		t.Fatalf("canonical UTF-8 escaping drifted\nwant: %s\n got: %s", want, got)
	}
}

func TestConcurrentExactReplaysShareOneLogicalStop(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	objects := newFakeObjectStore()
	containers := newFakeContainer(request)
	service := mustService(t, containers, objects)

	const callers = 16
	receipts := make(chan Receipt, callers)
	errorsChannel := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			receipt, err := service.StopOnce(context.Background(), request)
			receipts <- receipt
			errorsChannel <- err
		}()
	}
	wait.Wait()
	close(receipts)
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent exact replay failed: %v", err)
		}
	}
	var first *Receipt
	for receipt := range receipts {
		if first == nil {
			copy := receipt
			first = &copy
		} else if receipt != *first {
			t.Fatalf("concurrent replay returned different receipts: %#v != %#v", receipt, *first)
		}
	}
	if containers.stopCalls != 1 {
		t.Fatalf("in-process exact replays performed %d stops", containers.stopCalls)
	}
}

func TestOperationKeysContainOnlyTenantAndOperationDigests(t *testing.T) {
	t.Parallel()
	request := validStopRequest()
	keys := keysForRequest(request)
	for _, key := range []string{keys.claim, keys.receipt} {
		if strings.Contains(key, request.Owner.TenantID) || strings.Contains(key, request.OperationID) ||
			strings.Contains(key, request.Source.ProviderResourceID) {
			t.Fatalf("private object key leaked raw authority: %q", key)
		}
		parts := strings.Split(key, "/")
		if len(parts) != 6 || len(parts[3]) != 64 || len(parts[4]) != 64 {
			t.Fatalf("operation root is not tenant/operation hashed: %q", key)
		}
	}
}

func validStopRequest() StopRequest {
	request := StopRequest{
		OperationID: "10000000-0000-4000-8000-000000000009",
		Source: Source{
			ProviderResourceID:  "sandbox-1",
			ExpectedProfile:     "managed-container",
			ExpectedRuntimeKind: "full_image_runtime_pack",
		},
		Owner: Owner{
			TenantID:      "00000000-0000-4000-8000-000000000001",
			UserID:        "00000000-0000-4000-8000-000000000002",
			WorkspaceID:   "00000000-0000-4000-8000-000000000003",
			RunID:         "00000000-0000-4000-8000-000000000004",
			GrantID:       "00000000-0000-4000-8000-000000000005",
			WorkingCopyID: "00000000-0000-4000-8000-000000000006",
		},
		Fence: Fence{
			WorkspaceExecutionManifestRef: "ambit.workspace-execution-manifest:v1:sha256:" + strings.Repeat("c", 64),
		},
		ExpectedGeneration: ExpectedGeneration{
			ContainerID:        strings.Repeat("a", 64),
			ContainerCreatedAt: "2026-08-23T23:59:00Z",
			ExecutionStartedAt: "2026-08-24T00:00:00Z",
			RestartCount:       0,
		},
		Purpose: Purpose{Kind: PurposeWorkingCopyCapture},
	}
	refreshRequestFingerprint(&request)
	return request
}

func refreshRequestFingerprint(request *StopRequest) {
	fingerprint, err := ComputeRequestFingerprint(*request)
	if err != nil {
		panic(err)
	}
	request.RequestFingerprint = fingerprint
}

func validRendererPurpose() Purpose {
	return Purpose{
		Kind:      PurposeDocumentRendererQuiescence,
		SessionID: "ambit-document-render-" + strings.Repeat("a", 40),
		Nonce:     strings.Repeat("b", 32),
		RendererProcessIdentity: &RendererProcessIdentity{
			PID:        42,
			StartTicks: "123456789",
		},
	}
}

func queryFromRequest(request StopRequest) GenerationObservationRequest {
	return GenerationObservationRequest{
		Source: request.Source,
		Owner:  request.Owner,
		Fence:  request.Fence,
	}
}

func exactTarget(request StopRequest) ExactStopTarget {
	return ExactStopTarget{
		Source:             request.Source,
		Owner:              request.Owner,
		Fence:              request.Fence,
		ExpectedGeneration: request.ExpectedGeneration,
	}
}

func authorityFromReceipt(receipt Receipt) StopAuthority {
	return StopAuthority{
		OperationID:        receipt.Request.OperationID,
		ReceiptRef:         receipt.ReceiptRef,
		ReceiptDigest:      receipt.ReceiptDigest,
		TerminalGeneration: receipt.TerminalGeneration,
		Fence:              receipt.Request.Fence,
	}
}

func receiptsEqual(left, right Receipt) bool {
	leftBytes, leftErr := canonicalJSON(left)
	rightBytes, rightErr := canonicalJSON(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

func stopRequestsEqual(left, right StopRequest) bool {
	leftBytes, leftErr := canonicalJSON(left)
	rightBytes, rightErr := canonicalJSON(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

func mustService(t *testing.T, containers ContainerClient, objects ObjectStore) *Service {
	t.Helper()
	service, err := NewService(containers, objects)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	service.now = func() time.Time { return mustTime("2026-08-24T00:02:00Z") }
	return service
}

func mustTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		panic(err)
	}
	return parsed
}

type fakeContainer struct {
	mu            sync.Mutex
	observation   CurrentGenerationObservation
	inspectCalls  int
	stopCalls     int
	stopTargets   []ExactStopTarget
	inspectErrors []error
	stopErr       error
	beforeInspect func(call int) error
	afterStop     func(*CurrentGenerationObservation)
	beforeStop    func(ExactStopTarget)
}

func newFakeContainer(request StopRequest) *fakeContainer {
	return &fakeContainer{
		observation: CurrentGenerationObservation{
			Source: request.Source,
			Owner:  providerOwner(request.Owner),
			Fence:  request.Fence,
			Generation: ContainerGeneration{
				ExpectedGeneration: request.ExpectedGeneration,
			},
			State: RuntimeState{Status: "running", Running: true, PID: 42},
		},
	}
}

func (fake *fakeContainer) InspectGeneration(
	_ context.Context,
	providerResourceID string,
) (CurrentGenerationObservation, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.inspectCalls++
	if fake.beforeInspect != nil {
		if err := fake.beforeInspect(fake.inspectCalls); err != nil {
			return CurrentGenerationObservation{}, err
		}
	}
	if providerResourceID != fake.observation.Source.ProviderResourceID {
		return CurrentGenerationObservation{}, fmt.Errorf("unexpected provider resource %q", providerResourceID)
	}
	if len(fake.inspectErrors) != 0 {
		err := fake.inspectErrors[0]
		fake.inspectErrors = fake.inspectErrors[1:]
		return CurrentGenerationObservation{}, err
	}
	return fake.observation, nil
}

func (fake *fakeContainer) StopGeneration(_ context.Context, target ExactStopTarget) error {
	if fake.beforeStop != nil {
		fake.beforeStop(target)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.stopCalls++
	fake.stopTargets = append(fake.stopTargets, target)
	fake.makeExitedLocked()
	if fake.afterStop != nil {
		fake.afterStop(&fake.observation)
	}
	return fake.stopErr
}

func (fake *fakeContainer) makeExited() {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.makeExitedLocked()
}

func (fake *fakeContainer) makeExitedLocked() {
	fake.observation.State = RuntimeState{Status: "exited", PID: 0}
	fake.observation.Generation.ExecutionFinishedAt = "2026-08-24T00:01:00Z"
	fake.observation.Generation.ExitCode = 0
	fake.observation.Generation.OOMKilled = false
}

type fakeObjectStore struct {
	mu                    sync.Mutex
	objects               map[string][]byte
	createCalls           []string
	failBeforeStoreSuffix string
	failAfterStoreSuffix  string
	beforeCreate          func(key string)
}

func newFakeObjectStore() *fakeObjectStore {
	return &fakeObjectStore{objects: make(map[string][]byte)}
}

func (fake *fakeObjectStore) CreatePrivateObject(
	_ context.Context,
	key string,
	data []byte,
	_ string,
	_ map[string]string,
) error {
	if fake.beforeCreate != nil {
		fake.beforeCreate(key)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.createCalls = append(fake.createCalls, key)
	if strings.HasSuffix(key, fake.failBeforeStoreSuffix) && fake.failBeforeStoreSuffix != "" {
		fake.failBeforeStoreSuffix = ""
		return errors.New("simulated failure before immutable create")
	}
	if _, exists := fake.objects[key]; exists {
		return storage.ErrPrivateObjectAlreadyExists
	}
	fake.objects[key] = append([]byte(nil), data...)
	if strings.HasSuffix(key, fake.failAfterStoreSuffix) && fake.failAfterStoreSuffix != "" {
		fake.failAfterStoreSuffix = ""
		return errors.New("simulated lost immutable create response")
	}
	return nil
}

func (fake *fakeObjectStore) GetPrivateObject(
	_ context.Context,
	key string,
	maximumBytes int64,
) ([]byte, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	data, exists := fake.objects[key]
	if !exists {
		return nil, storage.ErrPrivateObjectNotFound
	}
	if int64(len(data)) > maximumBytes {
		return nil, storage.ErrPrivateObjectTooLarge
	}
	return append([]byte(nil), data...), nil
}

func (fake *fakeObjectStore) findSuffix(suffix string) ([]byte, bool) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for key, data := range fake.objects {
		if strings.HasSuffix(key, suffix) {
			return append([]byte(nil), data...), true
		}
	}
	return nil, false
}

func (fake *fakeObjectStore) keyWithSuffix(suffix string) (string, bool) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for key := range fake.objects {
		if strings.HasSuffix(key, suffix) {
			return key, true
		}
	}
	return "", false
}

func (fake *fakeObjectStore) setJSON(key string, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	fake.setRaw(key, data)
}

func (fake *fakeObjectStore) setRaw(key string, data []byte) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.objects[key] = append([]byte(nil), data...)
}

func (fake *fakeObjectStore) getRaw(key string) []byte {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]byte(nil), fake.objects[key]...)
}

func (fake *fakeObjectStore) countSuffix(suffix string) int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	count := 0
	for key := range fake.objects {
		if strings.HasSuffix(key, suffix) {
			count++
		}
	}
	return count
}
