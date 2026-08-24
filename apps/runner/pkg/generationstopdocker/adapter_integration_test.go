// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package generationstopdocker

import (
	"context"
	"os"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/docker/docker/client"
)

func TestDockerAdapterStopsOneRealLabeledGenerationAndReprovesTerminal(t *testing.T) {
	containerName := os.Getenv("AMBIT_TEST_DOCKER_GENERATION_CONTAINER")
	if containerName == "" {
		t.Skip("AMBIT_TEST_DOCKER_GENERATION_CONTAINER is not configured")
	}
	api, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("create Docker client: %v", err)
	}
	defer api.Close()
	adapter, err := New(api)
	if err != nil {
		t.Fatalf("create stopped-generation adapter: %v", err)
	}
	ctx := context.Background()
	before, err := adapter.InspectGeneration(ctx, containerName)
	if err != nil {
		t.Fatalf("inspect running generation: %v", err)
	}
	if !exactRunning(before.State) {
		t.Fatalf("integration generation is not exactly running: %#v", before.State)
	}
	target := generationstop.ExactStopTarget{
		Source: before.Source,
		Owner: generationstop.Owner{
			TenantID:      before.Owner.TenantID,
			UserID:        before.Owner.UserID,
			WorkspaceID:   before.Owner.WorkspaceID,
			RunID:         before.Owner.RunID,
			GrantID:       before.Owner.GrantID,
			WorkingCopyID: "00000000-0000-4000-8000-000000000006",
		},
		Fence:              before.Fence,
		ExpectedGeneration: before.Generation.ExpectedGeneration,
	}
	if err := adapter.StopGeneration(ctx, target); err != nil {
		t.Fatalf("stop exact generation: %v", err)
	}
	after, err := adapter.InspectGeneration(ctx, containerName)
	if err != nil {
		t.Fatalf("inspect terminal generation: %v", err)
	}
	if !exactExited(after.State) || after.Generation.ExpectedGeneration != before.Generation.ExpectedGeneration ||
		after.Generation.ExecutionFinishedAt == "" {
		t.Fatalf("terminal proof differs: before=%#v after=%#v", before, after)
	}
	if err := adapter.StopGeneration(ctx, target); err != nil {
		t.Fatalf("idempotent exact terminal reproof: %v", err)
	}
}
