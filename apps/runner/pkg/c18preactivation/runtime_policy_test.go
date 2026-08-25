// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

func TestEmbeddedRuntimeRenderPolicyMatchesCertifiedImageInput(t *testing.T) {
	path := filepath.Clean(filepath.Join(
		"..", "..", "..", "..", "images", "ambit-agent-workspace", "capabilities",
		"c18-specialist-packs", "protocol", "render-policy-matrix.v1.json",
	))
	imagePolicy, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(imagePolicy, embeddedRuntimeRenderPolicyBytes) {
		t.Fatal("embedded runtime policy differs byte-for-byte from the specialist-pack image input")
	}
	if sha256Digest(imagePolicy) != runtimeRenderPolicyDigest {
		t.Fatal("embedded runtime policy digest changed")
	}
	if len(runtimeRenderPolicy.Entries) != 24 {
		t.Fatalf("runtime policy row count = %d, want 24", len(runtimeRenderPolicy.Entries))
	}
	for _, policy := range runtimeRenderPolicy.Entries {
		candidateRef := candidateRefForRenderer(policy.RendererRef)
		resolved, found := runtimePolicyForCandidateMedia(candidateRef, policy.SourceMediaType)
		if !found || !canonicalEqual(resolved, policy) {
			t.Fatalf("runtime policy row %s/%s cannot be resolved exactly", policy.Facet, policy.SourceMediaType)
		}
		if facetExecutable(policy.Facet) != policy.ExecutablePath {
			t.Fatalf("facet %s has ambiguous executable authority", policy.Facet)
		}
		if sourceExtension(policy.SourceMediaType) == "" {
			t.Fatalf("runtime policy media %s has no exact backend source suffix", policy.SourceMediaType)
		}
	}
}

func TestRenderCommandAdmitsEveryCertifiedRuntimePolicyRow(t *testing.T) {
	golden := loadRenderGolden(t)
	var base RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &base); err != nil {
		t.Fatal(err)
	}
	source := []byte("exact preactivation source")
	for _, policy := range runtimeRenderPolicy.Entries {
		t.Run(policy.Facet+"/"+policy.SourceMediaType, func(t *testing.T) {
			command := cloneRenderCommandForTest(t, base)
			command.Facet = policy.Facet
			command.Source.ByteLength = int64(len(source))
			command.Source.Digest = sha256Digest(source)
			command.Source.MediaType = policy.SourceMediaType
			command.Source.Path = "inputs/source" + sourceExtension(policy.SourceMediaType)
			command.Source.SchemaURI = policy.RequiredSchemaURI
			command.Renderer = RenderRendererV2{
				ExecutablePath: policy.ExecutablePath, RenderMode: policy.RenderMode,
				RendererRef: policy.RendererRef, Representation: policy.Representation,
				ValidationPolicyRef: policy.ValidationPolicyRef,
			}
			command.PackRequiredChecks = append([]RenderLabeledCheckV2(nil), policy.CheckLabels...)
			command.Runtime.PackRevisions = []specialistrender.Pin{{
				Ref: policy.ExecutorPackRevisionRef, Digest: "sha256:" + repeatHex("e"),
			}}
			command.Digest = resealForTest(t, command)
			encoded, err := generationstop.CanonicalJSON(command)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRenderCommandV2(encoded, source); err != nil {
				t.Fatalf("certified runtime policy row was rejected: %v", err)
			}
		})
	}
}

func TestRenderCommandRejectsEveryRuntimePolicySubstitution(t *testing.T) {
	golden := loadRenderGolden(t)
	var base RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &base); err != nil {
		t.Fatal(err)
	}
	source := []byte("exact preactivation source")
	base.Source.ByteLength = int64(len(source))
	base.Source.Digest = sha256Digest(source)
	bindCommandToRuntimePolicyForTest(t, &base)
	base.Digest = resealForTest(t, base)

	schema := "ambit://schemas/c18/substituted@1"
	tests := []struct {
		name   string
		mutate func(*RenderCommandV2)
	}{
		{name: "facet", mutate: func(command *RenderCommandV2) { command.Facet = "pdf" }},
		{name: "media", mutate: func(command *RenderCommandV2) { command.Source.MediaType = "text/csv" }},
		{name: "executable", mutate: func(command *RenderCommandV2) { command.Renderer.ExecutablePath = facetExecutable("pdf") }},
		{name: "renderer", mutate: func(command *RenderCommandV2) {
			command.Renderer.RendererRef = "ambit.renderer/spreadsheet-flat-table-v1@1"
		}},
		{name: "validation policy", mutate: func(command *RenderCommandV2) {
			command.Renderer.ValidationPolicyRef = "ambit.validation-policy/spreadsheet-flat-table-v1@1"
		}},
		{name: "representation", mutate: func(command *RenderCommandV2) { command.Renderer.Representation = "spreadsheet_flat_table" }},
		{name: "render mode", mutate: func(command *RenderCommandV2) { command.Renderer.RenderMode = "flat_table_preview_and_structure" }},
		{name: "schema", mutate: func(command *RenderCommandV2) { command.Source.SchemaURI = &schema }},
		{name: "check label", mutate: func(command *RenderCommandV2) { command.PackRequiredChecks[0].Label = "Substituted" }},
		{name: "executor pack", mutate: func(command *RenderCommandV2) {
			policy, _ := runtimePolicyForCommand(*command)
			for index, pin := range command.Runtime.PackRevisions {
				if pin.Ref == policy.ExecutorPackRevisionRef {
					command.Runtime.PackRevisions = append(command.Runtime.PackRevisions[:index], command.Runtime.PackRevisions[index+1:]...)
					return
				}
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := cloneRenderCommandForTest(t, base)
			test.mutate(&command)
			command.Digest = resealForTest(t, command)
			encoded, err := generationstop.CanonicalJSON(command)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRenderCommandV2(encoded, source); err == nil {
				t.Fatal("runtime policy substitution was admitted")
			}
		})
	}
}

func cloneRenderCommandForTest(t *testing.T, source RenderCommandV2) RenderCommandV2 {
	t.Helper()
	encoded, err := generationstop.CanonicalJSON(source)
	if err != nil {
		t.Fatal(err)
	}
	var result RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
