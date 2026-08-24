// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import "testing"

func TestIsSandboxContainerPreservesLegacyAndExcludesProviderTasks(t *testing.T) {
	for name, test := range map[string]struct {
		labels map[string]string
		want   bool
	}{
		"legacy":     {labels: nil, want: true},
		"sandbox":    {labels: map[string]string{RunnerContainerKindLabel: RunnerContainerKindSandbox}, want: true},
		"specialist": {labels: map[string]string{RunnerContainerKindLabel: RunnerContainerKindSpecialistRender}, want: false},
		"future":     {labels: map[string]string{RunnerContainerKindLabel: "another-provider-task"}, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := IsSandboxContainer(test.labels); got != test.want {
				t.Fatalf("IsSandboxContainer=%v want %v", got, test.want)
			}
		})
	}
}
