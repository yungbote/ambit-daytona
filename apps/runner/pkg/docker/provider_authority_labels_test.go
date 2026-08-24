// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"strings"
	"testing"
)

func TestProviderAuthorityLabelsProjectOnlyCanonicalReservedMetadata(t *testing.T) {
	t.Parallel()
	projected, err := providerAuthorityLabels(map[string]string{
		"organizationName": "ordinary metadata",
		providerAuthorityMetadataPrefix + "ambitWorkspaceId": "00000000-0000-4000-8000-000000000003",
		providerAuthorityMetadataPrefix + "ambitRuntimeKind": "full_image_runtime_pack_provider_observation",
	})
	if err != nil {
		t.Fatalf("project provider labels: %v", err)
	}
	if len(projected) != 2 ||
		projected["ambitWorkspaceId"] != "00000000-0000-4000-8000-000000000003" ||
		projected["ambitRuntimeKind"] != "full_image_runtime_pack_provider_observation" {
		t.Fatalf("unexpected authority projection: %#v", projected)
	}
	if _, leaked := projected["organizationName"]; leaked {
		t.Fatal("ordinary metadata became a Docker authority label")
	}
}

func TestProviderAuthorityLabelsRejectInvalidNamesAndValues(t *testing.T) {
	t.Parallel()
	tests := map[string]map[string]string{
		"empty-name": {
			providerAuthorityMetadataPrefix: "value",
		},
		"wrong-namespace": {
			providerAuthorityMetadataPrefix + "daytonaWorkspaceId": "value",
		},
		"punctuation": {
			providerAuthorityMetadataPrefix + "ambitWorkspace.Id": "value",
		},
		"control-value": {
			providerAuthorityMetadataPrefix + "ambitWorkspaceId": "value\nsubstituted",
		},
		"oversize-value": {
			providerAuthorityMetadataPrefix + "ambitWorkspaceId": strings.Repeat("a", 2049),
		},
	}
	for name, metadata := range tests {
		metadata := metadata
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := providerAuthorityLabels(metadata); err == nil {
				t.Fatal("invalid authority metadata was accepted")
			}
		})
	}
}
