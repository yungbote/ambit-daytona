// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18oci

import (
	"strings"
	"testing"
)

func TestImmutableReferenceMatchesBackendCrossLanguageVectors(t *testing.T) {
	suffix := "@sha256:" + strings.Repeat("d", 64)
	prefix := "registry/"
	boundary := prefix + strings.Repeat("a", 512-len(prefix)-len(suffix)) + suffix
	if len(boundary) != 512 || !ValidImmutableReference(boundary) ||
		ValidImmutableReference(prefix+strings.Repeat("a", 513-len(prefix)-len(suffix))+suffix) {
		t.Fatal("immutable OCI reference byte bound drifted from backend")
	}
	for _, value := range []string{
		"registry:6000/ambit-c18-data-research@sha256:" + strings.Repeat("a", 64),
		"127.0.0.1:5001/team/image_name@sha256:" + strings.Repeat("b", 64),
		"[::1]:5001/team/image@sha256:" + strings.Repeat("c", 64),
	} {
		if !ValidImmutableReference(value) {
			t.Fatalf("backend-valid immutable OCI reference was rejected: %q", value)
		}
	}
	for _, value := range []string{
		"registry:6000/team/image:tag@sha256:" + strings.Repeat("a", 64),
		"registry:6000/team/bad name@sha256:" + strings.Repeat("a", 64),
		"registry:6000/team/image@@sha256:" + strings.Repeat("a", 64),
		"registry:6000/team/image@sha256:" + strings.Repeat("a", 63),
		"registry:06000/team/image@sha256:" + strings.Repeat("a", 64),
		"registry:70000/team/image@sha256:" + strings.Repeat("a", 64),
		"REGISTRY:6000/team/image@sha256:" + strings.Repeat("a", 64),
		"registry..local:6000/team/image@sha256:" + strings.Repeat("a", 64),
		"registry:6000/team//image@sha256:" + strings.Repeat("a", 64),
		"registry:6000/team/image@sha256:" + strings.Repeat("a", 64) + "?query",
		"registry:6000/team/image@sha256:" + strings.Repeat("a", 64) + "#fragment",
		"registry:6000/team/image\\name@sha256:" + strings.Repeat("a", 64),
		"[0:0:0:0:0:0:0:1]:5001/team/image@sha256:" + strings.Repeat("a", 64),
		"[2001:0db8::1]:5001/team/image@sha256:" + strings.Repeat("a", 64),
		"[2001:DB8::1]:5001/team/image@sha256:" + strings.Repeat("a", 64),
		"[::ffff:c000:280]:5001/team/image@sha256:" + strings.Repeat("a", 64),
	} {
		if ValidImmutableReference(value) {
			t.Fatalf("backend-invalid immutable OCI reference was admitted: %q", value)
		}
	}
}
