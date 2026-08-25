// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"fmt"
	"testing"

	"github.com/daytonaio/runner/pkg/c18providerintegration"
)

func TestAbandonedProviderCollectionUsesStableRetryOrchestrationExit(t *testing.T) {
	if status := fail(fmt.Errorf("wrapped: %w", c18providerintegration.ErrProviderCollectionAbandoned)); status != 75 {
		t.Fatalf("abandoned provider collection exit changed: %d", status)
	}
	if status := fail(fmt.Errorf("ordinary failure")); status != 1 {
		t.Fatalf("ordinary provider collection exit changed: %d", status)
	}
}
