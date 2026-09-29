// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
)

func capabilityRequest(binding CaptureGenerationBinding) CaptureCapabilitiesRequest {
	return CaptureCapabilitiesRequest{
		Authority: binding.Authority, Source: binding.Source, Owner: binding.Owner,
		Fence: binding.StopAuthority.Fence,
	}
}

func TestCaptureCapabilitiesStateTheComponentAndEchoOnlyItsOwnAuthority(t *testing.T) {
	service, containers, objects, tree := workingTreeFixture(t)
	binding := tree.Generation
	request := capabilityRequest(binding)
	service.generations = captureTestObserver(request)
	another := request
	another.Authority.Helper.Digest = "sha256:" + strings.Repeat("a", 64)
	another.Authority.Helper.Ref = "runtime-component-artifact:" + another.Authority.Helper.Digest
	unnamed := request
	unnamed.Authority = CaptureAuthority{}
	for _, test := range []struct {
		name    string
		request CaptureCapabilitiesRequest
		echo    CaptureAuthority
		fields  []string
	}{
		{"its own component", request, binding.Authority, []string{"authority", "component", "stoppedWorkingTreeInventory"}},
		{"another component", another, CaptureAuthority{}, []string{"component", "stoppedWorkingTreeInventory"}},
		{"no expectation", unnamed, CaptureAuthority{}, []string{"component", "stoppedWorkingTreeInventory"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, err := service.Capabilities(context.Background(), binding.Source.ProviderResourceID, test.request)
			if err != nil || response.Authority != test.echo || response.Component != binding.Authority.component() ||
				response.StoppedWorkingTreeInventory.Contract != workingTreeInventoryContract ||
				response.StoppedWorkingTreeInventory.SemanticZoneRef != userFilesSemanticZoneRef ||
				response.StoppedWorkingTreeInventory.MaximumFileBytes != MaximumWorkingTreeAggregateBytes ||
				response.StoppedWorkingTreeInventory.MaximumReadBytes != MaximumReadBytes ||
				response.StoppedWorkingTreeInventory.MaximumPageEntries != MaximumWorkingTreeInventoryPageEntries ||
				response.StoppedWorkingTreeInventory.MaximumDepth != MaximumWorkingTreeDepth ||
				response.StoppedWorkingTreeInventory.MaximumAggregateBytes != MaximumWorkingTreeAggregateBytes ||
				response.StoppedWorkingTreeInventory.MaximumIndexBytes != MaximumWorkingTreeInventoryIndexBytes {
				t.Fatalf("stated capture capability differs: %#v %v", response, err)
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			if actual := slices.Sorted(maps.Keys(fields)); !slices.Equal(actual, test.fields) {
				t.Fatalf("answer fields are %v, want %v", actual, test.fields)
			}
		})
	}
	if containers.inspectCalls != 0 || containers.copyCalls != 0 || len(objects.objects) != 0 {
		t.Fatal("capability discovery reached Docker or durable storage")
	}
}

func TestCaptureCapabilitiesRequestSurvivesTheExactWireWithOrWithoutAuthority(t *testing.T) {
	_, _, _, tree := workingTreeFixture(t)
	named := capabilityRequest(tree.Generation)
	unnamed := named
	unnamed.Authority = CaptureAuthority{}
	for _, request := range []CaptureCapabilitiesRequest{named, unnamed} {
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var decoded CaptureCapabilitiesRequest
		if err := DecodeExactJSON(encoded, &decoded); err != nil || decoded != request {
			t.Fatalf("capability request did not survive the exact wire: %v", err)
		}
		if bytes.Contains(encoded, []byte(`"authority"`)) != (request.Authority != CaptureAuthority{}) {
			t.Fatalf("absent authority was encoded: %s", encoded)
		}
	}
	encoded, err := json.Marshal(unnamed)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := json.Marshal(struct {
		CaptureCapabilitiesRequest
		Authority map[string]string `json:"authority"`
	}{unnamed, map[string]string{"roleRef": captureRoleRef}})
	if err != nil {
		t.Fatal(err)
	}
	for name, wire := range map[string][]byte{
		"empty":   bytes.Replace(encoded, []byte(`{`), []byte(`{"authority":{},`), 1),
		"partial": partial,
	} {
		var decoded CaptureCapabilitiesRequest
		if err := DecodeExactJSON(wire, &decoded); err == nil {
			t.Fatalf("%s authority was admitted as absent: %s", name, wire)
		}
	}
}

func TestCaptureCapabilitiesRefuseMalformedRequestsAndUnprovenSources(t *testing.T) {
	service, containers, objects, tree := workingTreeFixture(t)
	binding := tree.Generation
	request := capabilityRequest(binding)
	observer := captureTestObserver(request)
	service.generations = observer
	for name, mutate := range map[string]func(*CaptureCapabilitiesRequest){
		"sandbox":             func(r *CaptureCapabilitiesRequest) { r.Source.ProviderResourceID = "other-sandbox" },
		"runtime":             func(r *CaptureCapabilitiesRequest) { r.Source.ExpectedRuntimeKind = "base_profile" },
		"owner":               func(r *CaptureCapabilitiesRequest) { r.Owner.TenantID = "" },
		"fence":               func(r *CaptureCapabilitiesRequest) { r.Fence.WorkspaceExecutionManifestRef = "" },
		"foreign-valid-owner": func(r *CaptureCapabilitiesRequest) { r.Owner.TenantID = "00000000-0000-4000-8000-000000000099" },
		"different-manifest": func(r *CaptureCapabilitiesRequest) {
			r.Fence.WorkspaceExecutionManifestRef = "workspace-execution-manifest:other"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			if _, err := service.Capabilities(context.Background(), binding.Source.ProviderResourceID, changed); err == nil {
				t.Fatal("unproven capture source was admitted")
			}
		})
	}
	for name, mutate := range map[string]func(*CaptureAuthority){
		"authority reference": func(a *CaptureAuthority) {
			a.AuthorityRef = "ambit.working-copy-capture-authority:v2:sha256:" + strings.Repeat("0", 64)
		},
		"role": func(a *CaptureAuthority) { a.RoleRef = "ambit.runtime-component/other@1" },
		"helper": func(a *CaptureAuthority) {
			a.Helper.Ref = "runtime-component-artifact:sha256:" + strings.Repeat("b", 64)
		},
	} {
		t.Run("malformed "+name, func(t *testing.T) {
			changed := request
			mutate(&changed.Authority)
			if _, err := service.Capabilities(context.Background(), binding.Source.ProviderResourceID, changed); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("malformed expected authority was not refused as invalid: %v", err)
			}
		})
	}
	observer.err = errors.New("provider temporarily unavailable")
	if _, err := service.Capabilities(context.Background(), binding.Source.ProviderResourceID, request); !errors.Is(err, observer.err) {
		t.Fatal("failed physical observation was replaced with availability")
	}
	observer.err = nil
	service.generations = nil
	if _, err := service.Capabilities(context.Background(), binding.Source.ProviderResourceID, request); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing physical observer advertised capability")
	}
	service.generations = observer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Capabilities(ctx, binding.Source.ProviderResourceID, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled discovery was admitted: %v", err)
	}
	if containers.inspectCalls != 0 || containers.copyCalls != 0 || len(objects.objects) != 0 {
		t.Fatal("capability discovery reached Docker or durable storage")
	}
}
