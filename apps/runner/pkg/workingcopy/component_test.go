// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
	containertypes "github.com/docker/docker/api/types/container"
)

func testCaptureComponent(authority CaptureAuthority) CaptureComponent {
	return CaptureComponent{RoleRef: authority.RoleRef, Protocol: authority.Protocol, Helper: authority.Helper}
}

func nextCaptureComponent(component CaptureComponent) CaptureComponent {
	component.Helper.Digest = "sha256:" + strings.Repeat("a", 64)
	component.Helper.Ref = "runtime-component-artifact:" + component.Helper.Digest
	return component
}

func TestCaptureComponentMeasuresExecutableAndInterfaceBytes(t *testing.T) {
	protocol := []byte(`{"interface":"fixture"}`)
	component, err := measureCaptureComponent(strings.NewReader("native executable bytes"), protocol)
	if err != nil {
		t.Fatal(err)
	}
	if component.Helper.Digest != sha256Digest([]byte("native executable bytes")) || component.Protocol.Digest != sha256Digest(protocol) {
		t.Fatal("component does not name actual bytes")
	}
	if _, err := measureCaptureComponent(failedCaptureReader{}, protocol); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed executable read was accepted: %v", err)
	}
	if _, err := measureCaptureComponent(strings.NewReader("binary"), []byte("invalid")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("invalid interface was accepted")
	}
	self, err := MeasureCaptureComponent(protocol)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	expected, err := measureCaptureComponent(file, protocol)
	if err != nil || self != expected {
		t.Fatal("self measurement is not the current executable")
	}
}

func TestCaptureComponentServesDistinctQualifiedImageLineages(t *testing.T) {
	binding := validBinding()
	containers, objects := newFakeContainer([]byte("independent lineages")), newFakeObjectStore()
	service := mustService(t, containers, objects, binding.Authority)
	first, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatal(err)
	}
	other := binding
	other.Authority.LineageRef = "runtime-current-component-lineage:v1:sha256:" + strings.Repeat("9", 64)
	other.Authority.AuthorityRef = captureAuthorityRef(other.Authority)
	if _, err := service.Capture(context.Background(), other.Source.ProviderResourceID, other); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed lineage replaced the original capture binding: %v", err)
	}
	other.ProviderName += "-second"
	second, err := service.Capture(context.Background(), other.Source.ProviderResourceID, other)
	if err != nil || second.CaptureBinding != other || first.ProviderResourceID == second.ProviderResourceID {
		t.Fatalf("independent image lineages were conflated: %v", err)
	}
	if containers.copyCalls != 2 {
		t.Fatal("expected two independently admitted captures")
	}
}

func TestCaptureComponentRolloutPreservesCompleteCustody(t *testing.T) {
	binding := validBinding()
	containers, objects := newFakeContainer([]byte("preserved across rollout")), newFakeObjectStore()
	original := mustService(t, containers, objects, binding.Authority)
	receipt, err := original.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatal(err)
	}
	current := mustService(t, containers, objects, binding.Authority)
	current.component = nextCaptureComponent(current.component)
	containers.state = &containertypes.State{Status: containertypes.StateRunning, Running: true, Pid: 42}
	copies, inspections := containers.copyCalls, containers.inspectCalls
	replayed, err := current.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || replayed != receipt {
		t.Fatalf("complete replay lost immutable custody: %v", err)
	}
	observed, err := current.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || observed.Status != "complete" || *observed.Receipt != receipt {
		t.Fatalf("historical observation failed: %v", err)
	}
	read, err := current.Read(context.Background(), binding.Source.ProviderResourceID, CaptureReadRequest{CaptureIdentity: receipt.CaptureIdentity, ExpectedTotalByteLength: receipt.TotalByteLength, ExpectedProviderSHA256Digest: receipt.ProviderSHA256Digest, MaximumBytes: MaximumReadBytes})
	content, _ := base64.StdEncoding.DecodeString(read.BytesBase64)
	if err != nil || !bytes.Equal(content, containers.content) {
		t.Fatalf("historical content read failed: %v", err)
	}
	exists, err := current.Exists(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity)
	if err != nil || !exists.Exists {
		t.Fatalf("historical existence failed: %v", err)
	}
	for range 2 {
		if _, err := current.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity); err != nil {
			t.Fatalf("historical deletion failed: %v", err)
		}
	}
	if containers.copyCalls != copies || containers.inspectCalls != inspections {
		t.Fatal("historical custody touched the mutable source")
	}
	if _, err := current.Capture(context.Background(), binding.Source.ProviderResourceID, binding); !errors.Is(err, ErrConflict) {
		t.Fatal("historical tombstone permitted recapture")
	}
}

func TestCaptureComponentRolloutFinishesOnlyAlreadyCapturedBytes(t *testing.T) {
	for _, staged := range []bool{true, false} {
		t.Run(map[bool]string{true: "staged", false: "intent_only"}[staged], func(t *testing.T) {
			binding := validBinding()
			containers, objects := newFakeContainer([]byte("private staged bytes")), newFakeObjectStore()
			original := mustService(t, containers, objects, binding.Authority)
			objects.failBeforeStoreSuffix = "/receipt.json"
			if _, err := original.Capture(context.Background(), binding.Source.ProviderResourceID, binding); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("expected retained stage: %v", err)
			}
			objects.failBeforeStoreSuffix = ""
			if !staged {
				key, _ := objects.findSuffix("/content.bin")
				delete(objects.objects, key)
			}
			current := mustService(t, containers, objects, binding.Authority)
			current.component = nextCaptureComponent(current.component)
			copies, inspections := containers.copyCalls, containers.inspectCalls
			receipt, err := current.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
			if staged {
				if err != nil || receipt.CaptureBinding != binding {
					t.Fatalf("exact staged bytes were lost: %v", err)
				}
			} else if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("old incomplete authority reached fresh source: %v", err)
			}
			if containers.copyCalls != copies || containers.inspectCalls != inspections {
				t.Fatal("rollout re-read the source")
			}
			if _, found := objects.findSuffix("/intent.json"); !found {
				t.Fatal("retained intent disappeared")
			}
		})
	}
}

func TestCaptureComponentRolloutPreservesInventoryCustody(t *testing.T) {
	original, containers, objects, request := inventoryFixture(t, tarEntry{name: "workspace/receipt.txt", typeflag: tar.TypeReg, body: []byte("stored tree bytes")})
	receipt, err := original.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request)
	if err != nil {
		t.Fatal(err)
	}
	current := mustService(t, containers, objects, request.Generation.Authority)
	current.component = nextCaptureComponent(current.component)
	copies, inspections := containers.copyCalls, containers.inspectCalls
	replayed, err := current.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request)
	if err != nil || replayed.InventoryDigest != receipt.InventoryDigest {
		t.Fatalf("historical inventory replay failed: %v", err)
	}
	for _, page := range receipt.Pages {
		if _, err := current.ReadWorkingTreeInventoryPage(context.Background(), request.Generation.Source.ProviderResourceID, WorkingTreeInventoryPageRequest{Request: request, ProviderResourceID: receipt.ProviderResourceID, PageIndex: page.PageIndex}); err != nil {
			t.Fatal(err)
		}
	}
	read, err := current.ReadWorkingTreeInventoryRange(context.Background(), request.Generation.Source.ProviderResourceID, WorkingTreeInventoryRangeRequest{Request: request, ProviderResourceID: receipt.ProviderResourceID, InventoryDigest: receipt.InventoryDigest, MaximumBytes: MaximumReadBytes})
	content, _ := base64.StdEncoding.DecodeString(read.BytesBase64)
	if err != nil || string(content) != "stored tree bytes" {
		t.Fatalf("historical inventory bytes failed: %v", err)
	}
	for range 2 {
		if _, err := current.DeleteWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); err != nil {
			t.Fatal(err)
		}
	}
	if containers.copyCalls != copies || containers.inspectCalls != inspections {
		t.Fatal("historical inventory touched the mutable source")
	}
}

type captureTestGenerationObserver struct {
	request generationstop.ProviderGenerationObservationRequest
	err     error
	calls   int
}

func (observer *captureTestGenerationObserver) ObserveProviderCurrent(_ context.Context, request generationstop.ProviderGenerationObservationRequest) (generationstop.ProviderGenerationObservation, error) {
	observer.calls++
	if observer.err != nil {
		return generationstop.ProviderGenerationObservation{}, observer.err
	}
	if request != observer.request {
		return generationstop.ProviderGenerationObservation{}, generationstop.ErrConflict
	}
	return generationstop.ProviderGenerationObservation{Source: request.Source, Owner: request.Owner, Fence: request.Fence}, nil
}

func captureTestObserver(request CaptureCapabilitiesRequest) *captureTestGenerationObserver {
	return &captureTestGenerationObserver{request: generationstop.ProviderGenerationObservationRequest{Source: request.Source, Owner: generationstop.ProviderOwner{TenantID: request.Owner.TenantID, UserID: request.Owner.UserID, WorkspaceID: request.Owner.WorkspaceID, RunID: request.Owner.RunID, GrantID: request.Owner.GrantID}, Fence: request.Fence}}
}

type capturePhysicalInspector struct {
	observation generationstop.CurrentGenerationObservation
	calls       int
}

func (inspector *capturePhysicalInspector) InspectGeneration(_ context.Context, resourceID string) (generationstop.CurrentGenerationObservation, error) {
	inspector.calls++
	if resourceID != inspector.observation.Source.ProviderResourceID {
		return generationstop.CurrentGenerationObservation{}, generationstop.ErrConflict
	}
	return inspector.observation, nil
}

func TestCaptureComponentDiscoveryUsesExistingPhysicalGenerationOwner(t *testing.T) {
	binding := validBinding()
	request := CaptureCapabilitiesRequest{Authority: binding.Authority, Source: binding.Source, Owner: binding.Owner, Fence: binding.StopAuthority.Fence}
	expected := captureTestObserver(request).request
	physical := generationstop.CurrentGenerationObservation{Source: expected.Source, Owner: expected.Owner, Fence: expected.Fence,
		Generation: generationstop.ContainerGeneration{ExpectedGeneration: binding.StopAuthority.TerminalGeneration.ExpectedGeneration},
		State:      generationstop.RuntimeState{Status: "running", Running: true, PID: 42}}
	inspector := &capturePhysicalInspector{observation: physical}
	observer, err := generationstop.NewObserver(inspector)
	if err != nil {
		t.Fatal(err)
	}
	service, containers, objects, _ := workingTreeFixture(t)
	service.generations = observer
	if _, err := service.Capabilities(context.Background(), binding.Source.ProviderResourceID, request); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*generationstop.CurrentGenerationObservation){
		"tenant": func(o *generationstop.CurrentGenerationObservation) {
			o.Owner.TenantID = "99999999-9999-4999-8999-999999999999"
		},
		"workspace": func(o *generationstop.CurrentGenerationObservation) {
			o.Owner.WorkspaceID = "99999999-9999-4999-8999-999999999999"
		},
		"run": func(o *generationstop.CurrentGenerationObservation) {
			o.Owner.RunID = "99999999-9999-4999-8999-999999999999"
		},
		"grant": func(o *generationstop.CurrentGenerationObservation) {
			o.Owner.GrantID = "99999999-9999-4999-8999-999999999999"
		},
		"manifest": func(o *generationstop.CurrentGenerationObservation) {
			o.Fence.WorkspaceExecutionManifestRef = "different-manifest"
		},
		"profile": func(o *generationstop.CurrentGenerationObservation) { o.Source.ExpectedProfile = "managed-linux-vm" },
		"paused":  func(o *generationstop.CurrentGenerationObservation) { o.State.Paused = true },
	} {
		t.Run(name, func(t *testing.T) {
			inspector.observation = physical
			mutate(&inspector.observation)
			if _, err := service.Capabilities(context.Background(), binding.Source.ProviderResourceID, request); !errors.Is(err, ErrConflict) {
				t.Fatalf("physical authority drift was admitted or mistyped: %v", err)
			}
		})
	}
	if inspector.calls != 8 || containers.copyCalls != 0 || len(objects.objects) != 0 {
		t.Fatal("discovery did not stay read-only through the existing observer")
	}
}

func TestCaptureComponentRolloutPreservesIncompleteInventoryWithoutSourceRead(t *testing.T) {
	service, containers, objects, request := inventoryFixture(t, tarEntry{name: "workspace/file.txt", typeflag: tar.TypeReg, body: []byte("bytes")})
	objects.failBeforeStoreSuffix = "/index.json"
	if _, err := service.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("expected partial inventory: %v", err)
	}
	objects.failBeforeStoreSuffix = ""
	current := mustService(t, containers, objects, request.Generation.Authority)
	current.component = nextCaptureComponent(current.component)
	copies, inspections := containers.copyCalls, containers.inspectCalls
	if _, err := current.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unqualified partial inventory read the source: %v", err)
	}
	objects.failDeleteSuffix = "/pages/000000000000.json"
	if _, err := current.DeleteWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("lost cleanup must remain unknown: %v", err)
	}
	objects.failDeleteSuffix = ""
	if _, err := current.DeleteWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); err != nil {
		t.Fatal(err)
	}
	if containers.copyCalls != copies || containers.inspectCalls != inspections {
		t.Fatal("partial custody reconciliation reread source")
	}
}
