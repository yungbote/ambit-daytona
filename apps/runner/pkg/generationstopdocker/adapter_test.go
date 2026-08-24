// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package generationstopdocker

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
	containertypes "github.com/docker/docker/api/types/container"
)

func TestAdapterDerivesAuthorityFromDockerLabelsAndStopsFullContainerID(t *testing.T) {
	t.Parallel()
	api := newFakeDockerAPI()
	adapter, err := New(api)
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	observed, err := adapter.InspectGeneration(context.Background(), "sandbox-1")
	if err != nil {
		t.Fatalf("inspect generation: %v", err)
	}
	target := generationstop.ExactStopTarget{
		Source:             observed.Source,
		Owner:              exactOwner(observed.Owner),
		Fence:              observed.Fence,
		ExpectedGeneration: observed.Generation.ExpectedGeneration,
	}
	if err := adapter.StopGeneration(context.Background(), target); err != nil {
		t.Fatalf("stop generation: %v", err)
	}
	if api.stopCalls != 1 || api.stopIDs[0] != strings.Repeat("a", 64) {
		t.Fatalf("stop did not address the full immutable ID: %#v", api.stopIDs)
	}
}

func TestAdapterRejectsAuthorityDriftBeforeDockerStop(t *testing.T) {
	t.Parallel()
	api := newFakeDockerAPI()
	adapter, _ := New(api)
	observed, err := adapter.InspectGeneration(context.Background(), "sandbox-1")
	if err != nil {
		t.Fatalf("inspect generation: %v", err)
	}
	target := generationstop.ExactStopTarget{
		Source:             observed.Source,
		Owner:              exactOwner(observed.Owner),
		Fence:              observed.Fence,
		ExpectedGeneration: observed.Generation.ExpectedGeneration,
	}
	api.inspect.Config.Labels["ambitGrantId"] = "00000000-0000-4000-8000-000000000099"
	if err := adapter.StopGeneration(context.Background(), target); err == nil {
		t.Fatal("provider label drift was accepted")
	}
	if api.stopCalls != 0 {
		t.Fatal("authority drift reached Docker stop")
	}
}

func TestAdapterTreatsExactExitedGenerationAsIdempotentlyStopped(t *testing.T) {
	t.Parallel()
	api := newFakeDockerAPI()
	api.makeExited()
	adapter, _ := New(api)
	observed, err := adapter.InspectGeneration(context.Background(), "sandbox-1")
	if err != nil {
		t.Fatalf("inspect generation: %v", err)
	}
	target := generationstop.ExactStopTarget{
		Source:             observed.Source,
		Owner:              exactOwner(observed.Owner),
		Fence:              observed.Fence,
		ExpectedGeneration: observed.Generation.ExpectedGeneration,
	}
	if err := adapter.StopGeneration(context.Background(), target); err != nil {
		t.Fatalf("idempotent terminal stop: %v", err)
	}
	if api.stopCalls != 0 {
		t.Fatal("already-terminal generation issued another Docker stop")
	}
}

type fakeDockerAPI struct {
	inspect   containertypes.InspectResponse
	stopCalls int
	stopIDs   []string
	stopErr   error
}

func newFakeDockerAPI() *fakeDockerAPI {
	labels := map[string]string{
		"ambitWorkspaceId":                   "00000000-0000-4000-8000-000000000003",
		"ambitTenantId":                      "00000000-0000-4000-8000-000000000001",
		"ambitPrincipalId":                   "00000000-0000-4000-8000-000000000002",
		"ambitTaskId":                        "00000000-0000-4000-8000-000000000004",
		"ambitGrantId":                       "00000000-0000-4000-8000-000000000005",
		"ambitProfile":                       "managed-container",
		"ambitWorkspaceExecutionManifestRef": "ambit.workspace-execution-manifest:v1:sha256:" + strings.Repeat("c", 64),
		"ambitRuntimeKind":                   fullImageRuntimeObservationKind,
		"ambitRuntimeWorkspaceId":            "00000000-0000-4000-8000-000000000003",
		"ambitRuntimeManifestRef":            "ambit.workspace-execution-manifest:v1:sha256:" + strings.Repeat("c", 64),
		"ambitRuntimeProductRunId":           "00000000-0000-4000-8000-000000000004",
		"ambitRuntimeGrantId":                "00000000-0000-4000-8000-000000000005",
	}
	return &fakeDockerAPI{inspect: containertypes.InspectResponse{ContainerJSONBase: &containertypes.ContainerJSONBase{
		ID:           strings.Repeat("a", 64),
		Created:      "2026-08-23T23:59:00Z",
		Name:         "/sandbox-1",
		RestartCount: 0,
		State: &containertypes.State{
			Status:    containertypes.StateRunning,
			Running:   true,
			Pid:       42,
			StartedAt: "2026-08-24T00:00:00Z",
		},
	}, Config: &containertypes.Config{Labels: labels}}}
}

func (fake *fakeDockerAPI) ContainerInspect(
	_ context.Context,
	_ string,
) (containertypes.InspectResponse, error) {
	return fake.inspect, nil
}

func (fake *fakeDockerAPI) ContainerStop(
	_ context.Context,
	containerID string,
	_ containertypes.StopOptions,
) error {
	fake.stopCalls++
	fake.stopIDs = append(fake.stopIDs, containerID)
	if fake.stopErr == nil {
		fake.makeExited()
	}
	return fake.stopErr
}

func (fake *fakeDockerAPI) ContainerWait(
	_ context.Context,
	_ string,
	_ containertypes.WaitCondition,
) (<-chan containertypes.WaitResponse, <-chan error) {
	status := make(chan containertypes.WaitResponse, 1)
	failures := make(chan error, 1)
	if fake.stopErr != nil {
		failures <- errors.New("stop failed")
	} else {
		status <- containertypes.WaitResponse{StatusCode: 0}
	}
	return status, failures
}

func (fake *fakeDockerAPI) makeExited() {
	fake.inspect.State = &containertypes.State{
		Status:     containertypes.StateExited,
		Pid:        0,
		StartedAt:  "2026-08-24T00:00:00Z",
		FinishedAt: "2026-08-24T00:01:00Z",
		ExitCode:   0,
	}
}

func exactOwner(provider generationstop.ProviderOwner) generationstop.Owner {
	return generationstop.Owner{
		TenantID:      provider.TenantID,
		UserID:        provider.UserID,
		WorkspaceID:   provider.WorkspaceID,
		RunID:         provider.RunID,
		GrantID:       provider.GrantID,
		WorkingCopyID: "00000000-0000-4000-8000-000000000006",
	}
}
