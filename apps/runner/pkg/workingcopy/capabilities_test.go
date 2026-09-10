// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestCaptureCapabilitiesRequireCurrentLineageWithoutProviderEffects(t *testing.T) {
	service, containers, objects, tree := workingTreeFixture(t)
	binding := tree.Generation
	request := CaptureCapabilitiesRequest{
		Authority: binding.Authority, Source: binding.Source, Owner: binding.Owner,
		Fence: binding.StopAuthority.Fence,
	}
	response, err := service.Capabilities(context.Background(), binding.Source.ProviderResourceID, request)
	if err != nil || response.Authority != binding.Authority ||
		response.StoppedWorkingTreeInventory.Contract != workingTreeInventoryContract ||
		response.StoppedWorkingTreeInventory.SemanticZoneRef != userFilesSemanticZoneRef ||
		response.StoppedWorkingTreeInventory.MaximumFileBytes != MaximumWorkingTreeAggregateBytes ||
		response.StoppedWorkingTreeInventory.MaximumReadBytes != MaximumReadBytes ||
		response.StoppedWorkingTreeInventory.MaximumPageEntries != MaximumWorkingTreeInventoryPageEntries ||
		response.StoppedWorkingTreeInventory.MaximumDepth != MaximumWorkingTreeDepth ||
		response.StoppedWorkingTreeInventory.MaximumAggregateBytes != MaximumWorkingTreeAggregateBytes ||
		response.StoppedWorkingTreeInventory.MaximumIndexBytes != MaximumWorkingTreeInventoryIndexBytes {
		t.Fatalf("deployed capture capability differs: %#v %v", response, err)
	}
	for name, mutate := range map[string]func(*CaptureCapabilitiesRequest){
		"sandbox": func(r *CaptureCapabilitiesRequest) { r.Source.ProviderResourceID = "other-sandbox" },
		"runtime": func(r *CaptureCapabilitiesRequest) { r.Source.ExpectedRuntimeKind = "base_profile" },
		"owner":   func(r *CaptureCapabilitiesRequest) { r.Owner.TenantID = "" },
		"fence":   func(r *CaptureCapabilitiesRequest) { r.Fence.WorkspaceExecutionManifestRef = "" },
		"helper": func(r *CaptureCapabilitiesRequest) {
			r.Authority.Helper.Digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			r.Authority.Helper.Ref = "runtime-component-artifact:" + r.Authority.Helper.Digest
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			if _, err := service.Capabilities(context.Background(), binding.Source.ProviderResourceID, changed); err == nil {
				t.Fatal("invalid capability authority was admitted")
			}
		})
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CaptureCapabilitiesRequest
	if err := DecodeExactJSON(encoded, &decoded); err != nil || decoded != request {
		t.Fatalf("capability request did not survive the exact wire: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Capabilities(ctx, binding.Source.ProviderResourceID, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled discovery was admitted: %v", err)
	}
	if containers.inspectCalls != 0 || containers.copyCalls != 0 || len(objects.objects) != 0 {
		t.Fatal("capability discovery reached Docker or durable storage")
	}
}
