// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

// Package generationstopdocker adapts Docker's container-generation API to
// the provider-neutral durable stopped-generation authority.
package generationstopdocker

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/daytonaio/runner/pkg/generationstop"
	containertypes "github.com/docker/docker/api/types/container"
)

const (
	fullImageRuntimeObservationKind = "full_image_runtime_pack_provider_observation"
	fullImageRuntimeKind            = "full_image_runtime_pack"
	baseProfileRuntimeKind          = "base_profile"
)

type DockerAPI interface {
	ContainerInspect(ctx context.Context, containerID string) (containertypes.InspectResponse, error)
	ContainerStop(ctx context.Context, containerID string, options containertypes.StopOptions) error
	ContainerWait(
		ctx context.Context,
		containerID string,
		condition containertypes.WaitCondition,
	) (<-chan containertypes.WaitResponse, <-chan error)
}

type Adapter struct {
	api DockerAPI
}

func New(api DockerAPI) (*Adapter, error) {
	if api == nil {
		return nil, errors.New("Docker generation API is not configured")
	}
	return &Adapter{api: api}, nil
}

func (adapter *Adapter) InspectGeneration(
	ctx context.Context,
	providerResourceID string,
) (generationstop.CurrentGenerationObservation, error) {
	inspect, err := adapter.api.ContainerInspect(ctx, providerResourceID)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return generationstop.CurrentGenerationObservation{}, generationstop.ErrNotFound
		}
		return generationstop.CurrentGenerationObservation{}, err
	}
	return observation(providerResourceID, inspect)
}

func (adapter *Adapter) StopGeneration(
	ctx context.Context,
	target generationstop.ExactStopTarget,
) error {
	// Re-prove immediately at the mutable adapter boundary. The service's prior
	// inspection cannot authorize a later call if a name, label, fence, or
	// execution epoch changed between those two operations.
	before, err := adapter.InspectGeneration(ctx, target.Source.ProviderResourceID)
	if err != nil {
		return fmt.Errorf("inspect exact stop target: %w", err)
	}
	if err := requireExactTarget(before, target); err != nil {
		return err
	}
	if exactExited(before.State) {
		return nil
	}
	if !exactRunning(before.State) {
		return fmt.Errorf("exact stop target is not running or exited (status=%q)", before.State.Status)
	}

	timeoutSeconds := 10
	if err := adapter.api.ContainerStop(
		ctx,
		target.ExpectedGeneration.ContainerID,
		containertypes.StopOptions{Signal: "SIGTERM", Timeout: &timeoutSeconds},
	); err != nil {
		return fmt.Errorf("stop exact container generation: %w", err)
	}
	statusChannel, errorChannel := adapter.api.ContainerWait(
		ctx,
		target.ExpectedGeneration.ContainerID,
		containertypes.WaitConditionNotRunning,
	)
	select {
	case err := <-errorChannel:
		if err != nil {
			return fmt.Errorf("wait for exact container generation: %w", err)
		}
	case <-statusChannel:
	case <-ctx.Done():
		return ctx.Err()
	}

	after, err := adapter.InspectGeneration(ctx, target.Source.ProviderResourceID)
	if err != nil {
		return fmt.Errorf("inspect exact stopped generation: %w", err)
	}
	if err := requireExactTarget(after, target); err != nil {
		return err
	}
	if !exactExited(after.State) || after.Generation.ExecutionFinishedAt == "" {
		return fmt.Errorf("Docker returned without exact exited PID-zero state")
	}
	return nil
}

func observation(
	providerResourceID string,
	inspect containertypes.InspectResponse,
) (generationstop.CurrentGenerationObservation, error) {
	if inspect.ContainerJSONBase == nil || inspect.Config == nil || inspect.State == nil {
		return generationstop.CurrentGenerationObservation{}, errors.New("Docker inspection is incomplete")
	}
	if strings.TrimPrefix(inspect.Name, "/") != providerResourceID {
		return generationstop.CurrentGenerationObservation{}, fmt.Errorf(
			"Docker container name %q does not match provider resource %q",
			inspect.Name,
			providerResourceID,
		)
	}
	labels := inspect.Config.Labels
	if labels == nil {
		return generationstop.CurrentGenerationObservation{}, errors.New("Docker generation has no provider labels")
	}
	runtimeKind := ""
	switch labels["ambitRuntimeKind"] {
	case fullImageRuntimeObservationKind:
		if labels["ambitRuntimeWorkspaceId"] != labels["ambitWorkspaceId"] ||
			labels["ambitRuntimeManifestRef"] != labels["ambitWorkspaceExecutionManifestRef"] ||
			labels["ambitRuntimeProductRunId"] != labels["ambitTaskId"] ||
			labels["ambitRuntimeGrantId"] != labels["ambitGrantId"] {
			return generationstop.CurrentGenerationObservation{}, errors.New(
				"Docker full-image runtime labels are absent, partial, or substituted",
			)
		}
		runtimeKind = fullImageRuntimeKind
	case "":
		for label := range labels {
			if strings.HasPrefix(label, "ambitRuntime") {
				return generationstop.CurrentGenerationObservation{}, errors.New(
					"Docker base-profile runtime labels are partial or substituted",
				)
			}
		}
		runtimeKind = baseProfileRuntimeKind
	default:
		return generationstop.CurrentGenerationObservation{}, fmt.Errorf(
			"Docker runtime observation kind %q is retired or unrecognized",
			labels["ambitRuntimeKind"],
		)
	}
	state := inspect.State
	finishedAt := state.FinishedAt
	if finishedAt == "0001-01-01T00:00:00Z" || strings.HasPrefix(finishedAt, "0001-01-01T00:00:00.") {
		finishedAt = ""
	}
	return generationstop.CurrentGenerationObservation{
		Source: generationstop.Source{
			ProviderResourceID:  strings.TrimPrefix(inspect.Name, "/"),
			ExpectedProfile:     labels["ambitProfile"],
			ExpectedRuntimeKind: runtimeKind,
		},
		Owner: generationstop.ProviderOwner{
			TenantID:    labels["ambitTenantId"],
			UserID:      labels["ambitPrincipalId"],
			WorkspaceID: labels["ambitWorkspaceId"],
			RunID:       labels["ambitTaskId"],
			GrantID:     labels["ambitGrantId"],
		},
		Fence: generationstop.Fence{
			WorkspaceExecutionManifestRef: labels["ambitWorkspaceExecutionManifestRef"],
		},
		Generation: generationstop.ContainerGeneration{
			ExpectedGeneration: generationstop.ExpectedGeneration{
				ContainerID:        inspect.ID,
				ContainerCreatedAt: inspect.Created,
				ExecutionStartedAt: state.StartedAt,
				RestartCount:       inspect.RestartCount,
			},
			ExecutionFinishedAt: finishedAt,
			ExitCode:            state.ExitCode,
			OOMKilled:           state.OOMKilled,
		},
		State: generationstop.RuntimeState{
			Status:     state.Status,
			Running:    state.Running,
			Paused:     state.Paused,
			Restarting: state.Restarting,
			Dead:       state.Dead,
			PID:        state.Pid,
		},
	}, nil
}

func requireExactTarget(
	observed generationstop.CurrentGenerationObservation,
	target generationstop.ExactStopTarget,
) error {
	if observed.Source != target.Source ||
		observed.Owner.TenantID != target.Owner.TenantID ||
		observed.Owner.UserID != target.Owner.UserID ||
		observed.Owner.WorkspaceID != target.Owner.WorkspaceID ||
		observed.Owner.RunID != target.Owner.RunID ||
		observed.Owner.GrantID != target.Owner.GrantID ||
		observed.Fence != target.Fence ||
		observed.Generation.ExpectedGeneration != target.ExpectedGeneration {
		return errors.New("Docker exact stop target authority changed before effect")
	}
	return nil
}

func exactRunning(state generationstop.RuntimeState) bool {
	return state.Status == "running" && state.Running && !state.Paused &&
		!state.Restarting && !state.Dead && state.PID > 0
}

func exactExited(state generationstop.RuntimeState) bool {
	return state.Status == "exited" && !state.Running && !state.Paused &&
		!state.Restarting && !state.Dead && state.PID == 0
}
