// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

const (
	RunnerContainerKindLabel            = "daytona.runner.container-kind"
	RunnerContainerKindSandbox          = "sandbox"
	RunnerContainerKindSpecialistRender = "specialist-render"
)

// IsSandboxContainer preserves unlabeled legacy sandboxes during migration
// while excluding every explicitly provider-owned non-sandbox kind from
// sandbox network/source-guard lifecycle handling.
func IsSandboxContainer(labels map[string]string) bool {
	kind := labels[RunnerContainerKindLabel]
	return kind == "" || kind == RunnerContainerKindSandbox
}
