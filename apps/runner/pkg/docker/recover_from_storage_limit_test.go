// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"strings"
	"testing"
)

func TestRecoverFromStorageLimitRejectsExpansionWhenLimitsAreEnforced(t *testing.T) {
	client := &DockerClient{resourceLimitsDisabled: false}

	err := client.RecoverFromStorageLimit(context.Background(), "sandbox-1", 20, nil)

	if err == nil || !strings.Contains(err.Error(), "disabled while resource limits are enforced") {
		t.Fatalf("expected enforced resource limits to reject storage expansion, got %v", err)
	}
}
