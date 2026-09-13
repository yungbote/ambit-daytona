// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"context"
	"fmt"

	"github.com/daytonaio/runner/pkg/generationstop"
)

// Capabilities reports the surface actually implemented by this Runner under
// its admitted capture lineage. The API authorizes the sandbox source, owner,
// and fence before dispatch. Discovery takes no Docker, stop, or storage effect.
func (s *Service) Capabilities(ctx context.Context, sandboxID string, request CaptureCapabilitiesRequest) (CaptureCapabilities, error) {
	if err := ctx.Err(); err != nil {
		return CaptureCapabilities{}, err
	}
	if err := validateAuthority(request.Authority); err != nil {
		return CaptureCapabilities{}, err
	}
	if request.Authority != s.admittedAuthority {
		return CaptureCapabilities{}, fmt.Errorf("%w: capture capability authority is not the admitted current lineage", ErrConflict)
	}
	if err := generationstop.ValidateSource(request.Source); err != nil {
		return CaptureCapabilities{}, invalidf("capture capability source is invalid: " + err.Error())
	}
	if err := generationstop.ValidateOwner(request.Owner); err != nil {
		return CaptureCapabilities{}, invalidf("capture capability owner is invalid: " + err.Error())
	}
	if !boundedRef(sandboxID, 512) || request.Source.ProviderResourceID != sandboxID ||
		request.Source.ExpectedProfile != "managed-container" ||
		request.Source.ExpectedRuntimeKind != "full_image_runtime_pack" ||
		!boundedRef(request.Fence.WorkspaceExecutionManifestRef, 2048) {
		return CaptureCapabilities{}, invalidf("capture capability source or fence is not admitted")
	}
	capabilities := CaptureCapabilities{
		Authority: s.admittedAuthority,
		StoppedWorkingTreeInventory: WorkingTreeInventoryCapability{
			Contract: workingTreeInventoryContract, SemanticZoneRef: userFilesSemanticZoneRef,
			MaximumDepth: MaximumWorkingTreeDepth, MaximumFileBytes: MaximumWorkingTreeAggregateBytes, MaximumAggregateBytes: MaximumWorkingTreeAggregateBytes,
			MaximumPageEntries: MaximumWorkingTreeInventoryPageEntries, MaximumPageBytes: MaximumWorkingTreeInventoryPageBytes,
			MaximumIndexBytes: MaximumWorkingTreeInventoryIndexBytes, MaximumReadBytes: MaximumReadBytes,
		},
	}
	if s.fileSnapshots != nil {
		capabilities.FileSnapshot = &FileSnapshotCapability{Contract: FileSnapshotContract, MaximumBytes: MaximumCaptureBytes}
	}
	return capabilities, nil
}
