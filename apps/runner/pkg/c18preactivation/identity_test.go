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
	for _, ref := range []string{
		"ambit:///missing-authority", "ambit://Bad/one", "ambit://samples//one",
		"ambit://user@samples/one", "ambit://samples:80/one", "ambit://samples/one?",
		"ambit://samples/a/../b", "ambit://samples/a/.", "ambit://samples/a/%2e%2e/b",
		"ambit://samples/a b", "ambit://samples/%broken", "ambit://samples/a\\b",
		"ambit://samples/a%5cb", "ambit://samples/one?x=`", "ambit://samples/one#x=`",
	} {
		if _, err := DeriveProviderOperationIDV2("sha256:"+strings.Repeat("a", 64), ref, "source"); err == nil {
			t.Fatalf("noncanonical operational ref was admitted: %q", ref)
		}
	}
}

func TestOperationalRefsMatchBackendURLCanonicalizationVectors(t *testing.T) {
	for _, ref := range []string{
		"ambit://samples/one",
		"ambit://samples/a%2fb",
		"ambit://samples/a%2Fb",
		"ambit://samples/%41",
		"ambit://samples/one?a=b",
		"ambit://samples/one?x=\\",
		"ambit://samples/one#evidence",
		"ambit://samples/one#x\\",
	} {
		if !validOperationalRef(ref) {
			t.Fatalf("backend-canonical operational ref was rejected: %q", ref)
		}
	}
}
