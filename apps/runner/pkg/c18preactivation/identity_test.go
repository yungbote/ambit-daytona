// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"strings"
	"testing"
)

func TestProviderOperationIDMatchesBackendSemanticUUIDVector(t *testing.T) {
	requestDigest := "sha256:" + strings.Repeat("a", 64)
	sampleRef := "ambit://skill-evaluation-samples/test/001"
	operationID, err := DeriveProviderOperationIDV2(requestDigest, sampleRef, "source")
	if err != nil {
		t.Fatal(err)
	}
	if operationID != "5aef17a2-a332-87f8-bf55-e14170aa2052" {
		t.Fatalf("cross-language operation identity drifted: %s", operationID)
	}
	other, err := DeriveProviderOperationIDV2(requestDigest, sampleRef, "reopened")
	if err != nil {
		t.Fatal(err)
	}
	if other == operationID {
		t.Fatal("journey-stage substitution did not change operation identity")
	}
}

func TestProviderOperationIDRejectsInvalidAuthority(t *testing.T) {
	if _, err := DeriveProviderOperationIDV2("sha256:invalid", "ambit://samples/one", "source"); err == nil {
		t.Fatal("invalid request digest was admitted")
	}
	if _, err := DeriveProviderOperationIDV2("sha256:"+strings.Repeat("a", 64), "file:///tmp/source", "source"); err == nil {
		t.Fatal("non-Ambit sample reference was admitted")
	}
	if _, err := DeriveProviderOperationIDV2("sha256:"+strings.Repeat("a", 64), "ambit://samples/one", "unknown"); err == nil {
		t.Fatal("unknown journey stage was admitted")
	}
}
