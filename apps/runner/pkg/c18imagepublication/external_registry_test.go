// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18imagepublication

import (
	"net/http"
	"os"
	"testing"
)

// This opt-in gate is run against a disposable, loopback-bound registry:2
// container. Normal unit/race suites stay hermetic and skip it.
func TestExternalRegistryDigestOnlyPublication(t *testing.T) {
	origin := os.Getenv("AMBIT_C18_TEST_REGISTRY_ORIGIN")
	if origin == "" {
		t.Skip("AMBIT_C18_TEST_REGISTRY_ORIGIN is not set")
	}
	request, requestDigest := testRequest(t, origin, archiveVariation{})
	client := &http.Client{}
	first := runTestPublication(t, request, requestDigest, client)
	second := runTestPublication(t, request, requestDigest, client)
	for index := range first.PublishedArchives {
		if first.PublishedArchives[index].ImageTagState != "absent" ||
			first.PublishedArchives[index].Manifest.Disposition != "uploaded" ||
			second.PublishedArchives[index].ImageTagState != "absent" ||
			second.PublishedArchives[index].Manifest.Disposition != "already_present" {
			t.Fatalf("registry:2 digest-only/idempotent contract failed at row %d", index)
		}
	}
}
