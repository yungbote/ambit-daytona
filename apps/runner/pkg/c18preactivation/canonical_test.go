// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"strings"
	"testing"
)

func TestAuthorityAndIdentityPinsMatchBackendCharacterAndByteBounds(t *testing.T) {
	digest := "sha256:" + repeatHex("a")
	if !validIdentityPin(strings.Repeat("a", 512), digest) ||
		!validIdentityPin(strings.Repeat("😀", 256), digest) {
		t.Fatal("backend-boundary identity pin was rejected")
	}
	if validIdentityPin(strings.Repeat("a", 513), digest) ||
		validIdentityPin(strings.Repeat("😀", 257), digest) {
		t.Fatal("oversized identity pin was admitted")
	}
	if !validPin(strings.Repeat("a", 1_024), digest) ||
		!validPin(strings.Repeat("😀", 512), digest) {
		t.Fatal("backend-boundary authority pin was rejected")
	}
	if validPin(strings.Repeat("a", 1_025), digest) ||
		validPin(strings.Repeat("😀", 513), digest) {
		t.Fatal("oversized authority pin was admitted")
	}
}
