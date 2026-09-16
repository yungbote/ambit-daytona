// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package generationstop

import "context"

// SandboxGenerationObservation describes native provider ownership and physical
// execution only. Product labels and certification are separate authority.
type SandboxGenerationObservation struct {
	SandboxID      string
	OrganizationID string
	Generation     ContainerGeneration
	State          RuntimeState
}

type SandboxGenerationInspector interface {
	InspectSandboxGeneration(context.Context, string) (SandboxGenerationObservation, error)
}
