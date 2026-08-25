// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/daytonaio/runner/pkg/generationstop"
)

const (
	runtimeRenderPolicySchema = "ambit.c18-specialist-render-runtime-policy-matrix/v1"
	runtimeRenderPolicyDigest = "sha256:ea339d65f0d6f04dc0ed25407a5b7a31f2c23de84a4054c763b0fae0f5936918"
)

// embeddedRuntimeRenderPolicyBytes is copied byte-for-byte from the certified
// specialist-pack image input. The digest freezes the executable policy used
// by this statically linked driver; changing the image policy therefore
// requires an explicit driver authority update rather than a silent fallback.
//
//go:embed render-policy-matrix.v1.json
var embeddedRuntimeRenderPolicyBytes []byte

type runtimeRenderPolicyMatrixV1 struct {
	Entries []runtimeRenderPolicyEntryV1 `json:"entries"`
	Schema  string                       `json:"schema"`
}

type runtimeRenderPolicyEntryV1 struct {
	CheckLabels             []RenderLabeledCheckV2 `json:"checkLabels"`
	ExecutablePath          string                 `json:"executablePath"`
	ExecutorPackRevisionRef string                 `json:"executorPackRevisionRef"`
	Facet                   string                 `json:"facet"`
	PackChecks              []string               `json:"packChecks"`
	RenderMode              string                 `json:"renderMode"`
	RendererRef             string                 `json:"rendererRef"`
	Representation          string                 `json:"representation"`
	RequiredSchemaURI       *string                `json:"requiredSchemaUri"`
	SourceMediaType         string                 `json:"sourceMediaType"`
	ValidationPolicyRef     string                 `json:"validationPolicyRef"`
}

var runtimeRenderPolicy = mustLoadRuntimeRenderPolicy()

func mustLoadRuntimeRenderPolicy() runtimeRenderPolicyMatrixV1 {
	matrix, err := loadRuntimeRenderPolicy(embeddedRuntimeRenderPolicyBytes)
	if err != nil {
		panic(fmt.Sprintf("load embedded C18 runtime render policy: %v", err))
	}
	return matrix
}

func loadRuntimeRenderPolicy(encoded []byte) (runtimeRenderPolicyMatrixV1, error) {
	if sha256Digest(encoded) != runtimeRenderPolicyDigest {
		return runtimeRenderPolicyMatrixV1{}, errors.New("runtime render policy digest differs from the certified image input")
	}
	if len(encoded) < 2 || encoded[len(encoded)-1] != '\n' || encoded[len(encoded)-2] == '\r' {
		return runtimeRenderPolicyMatrixV1{}, errors.New("runtime render policy must have exactly canonical JSON followed by LF")
	}
	canonical := encoded[:len(encoded)-1]
	if bytes.IndexByte(canonical, '\n') >= 0 || bytes.IndexByte(canonical, '\r') >= 0 {
		return runtimeRenderPolicyMatrixV1{}, errors.New("runtime render policy contains noncanonical line framing")
	}
	var matrix runtimeRenderPolicyMatrixV1
	if err := generationstop.DecodeCanonicalJSON(canonical, &matrix); err != nil {
		return runtimeRenderPolicyMatrixV1{}, fmt.Errorf("decode runtime render policy: %w", err)
	}
	if matrix.Schema != runtimeRenderPolicySchema || len(matrix.Entries) == 0 {
		return runtimeRenderPolicyMatrixV1{}, errors.New("runtime render policy identity is invalid")
	}

	previousIdentity := ""
	byRenderer := make(map[string]runtimeRenderPolicyEntryV1)
	for _, entry := range matrix.Entries {
		identity := entry.Facet + "\x00" + entry.SourceMediaType
		if identity <= previousIdentity || !validRuntimeRenderPolicyEntry(entry) {
			return runtimeRenderPolicyMatrixV1{}, errors.New("runtime render policy entries are invalid or noncanonical")
		}
		previousIdentity = identity
		if previous, exists := byRenderer[entry.RendererRef]; exists {
			if !sameCandidateRuntimePolicy(previous, entry) {
				return runtimeRenderPolicyMatrixV1{}, errors.New("runtime render policy changes authority within one candidate")
			}
		} else {
			byRenderer[entry.RendererRef] = entry
		}
	}
	return matrix, nil
}

func validRuntimeRenderPolicyEntry(entry runtimeRenderPolicyEntryV1) bool {
	if !canonicalTokenValue(entry.Facet) || !canonicalMediaTypeValue(entry.SourceMediaType) ||
		!rendererAuthorityRef.MatchString(entry.RendererRef) ||
		!validationAuthorityRef.MatchString(entry.ValidationPolicyRef) ||
		!runtimePackAuthorityRef.MatchString(entry.ExecutorPackRevisionRef) ||
		!canonicalTokenValue(entry.Representation) || !canonicalTokenValue(entry.RenderMode) ||
		!strings.HasPrefix(entry.ExecutablePath, "/opt/ambit/runtime-pack/") ||
		!strings.HasSuffix(entry.ExecutablePath, "/bin/ambit-specialist-render") ||
		len(entry.PackChecks) == 0 || len(entry.PackChecks) > 256 ||
		len(entry.CheckLabels) != len(entry.PackChecks) {
		return false
	}
	if entry.RequiredSchemaURI != nil && !validOperationalRef(*entry.RequiredSchemaURI) {
		return false
	}
	for index, check := range entry.PackChecks {
		label := entry.CheckLabels[index]
		if !canonicalTokenValue(check) || label.Check != check || !printableBounded(label.Label, 512, 2_048) {
			return false
		}
	}
	return sortedUnique(entry.PackChecks)
}

func sameCandidateRuntimePolicy(left, right runtimeRenderPolicyEntryV1) bool {
	return left.Facet == right.Facet && left.ExecutablePath == right.ExecutablePath &&
		left.ExecutorPackRevisionRef == right.ExecutorPackRevisionRef &&
		left.RenderMode == right.RenderMode && left.RendererRef == right.RendererRef &&
		left.Representation == right.Representation &&
		canonicalEqual(left.RequiredSchemaURI, right.RequiredSchemaURI) &&
		left.ValidationPolicyRef == right.ValidationPolicyRef &&
		canonicalEqual(left.PackChecks, right.PackChecks) &&
		canonicalEqual(left.CheckLabels, right.CheckLabels)
}

func runtimePolicyForCommand(command RenderCommandV2) (runtimeRenderPolicyEntryV1, bool) {
	for _, entry := range runtimeRenderPolicy.Entries {
		if entry.Facet == command.Facet && entry.SourceMediaType == command.Source.MediaType {
			return entry, true
		}
	}
	return runtimeRenderPolicyEntryV1{}, false
}

func runtimePolicyForCandidateMedia(candidateRef, mediaType string) (runtimeRenderPolicyEntryV1, bool) {
	for _, entry := range runtimeRenderPolicy.Entries {
		if candidateRefForRenderer(entry.RendererRef) == candidateRef && entry.SourceMediaType == mediaType {
			return entry, true
		}
	}
	return runtimeRenderPolicyEntryV1{}, false
}

func runtimePolicyForCandidate(candidateRef string) (runtimeRenderPolicyEntryV1, bool) {
	for _, entry := range runtimeRenderPolicy.Entries {
		if candidateRefForRenderer(entry.RendererRef) == candidateRef {
			return entry, true
		}
	}
	return runtimeRenderPolicyEntryV1{}, false
}

func candidateRefForRenderer(rendererRef string) string {
	const prefix = "ambit.renderer/"
	if !strings.HasPrefix(rendererRef, prefix) {
		return ""
	}
	return "ambit.renderer-candidate/" + strings.TrimPrefix(rendererRef, prefix)
}

func rendererMatchesRuntimePolicy(renderer RenderRendererV2, policy runtimeRenderPolicyEntryV1) bool {
	return renderer == (RenderRendererV2{
		ExecutablePath:      policy.ExecutablePath,
		RenderMode:          policy.RenderMode,
		RendererRef:         policy.RendererRef,
		Representation:      policy.Representation,
		ValidationPolicyRef: policy.ValidationPolicyRef,
	})
}

func templateRendererMatchesRuntimePolicy(renderer RenderTemplateRendererV2, policy runtimeRenderPolicyEntryV1) bool {
	return renderer.RenderMode == policy.RenderMode && renderer.RendererRef == policy.RendererRef &&
		renderer.Representation == policy.Representation &&
		canonicalEqual(renderer.SourceSchemaURI, policy.RequiredSchemaURI) &&
		renderer.ValidationPolicyRef == policy.ValidationPolicyRef
}

func facetExecutable(facet string) string {
	result := ""
	for _, entry := range runtimeRenderPolicy.Entries {
		if entry.Facet != facet {
			continue
		}
		if result != "" && result != entry.ExecutablePath {
			return ""
		}
		result = entry.ExecutablePath
	}
	return result
}
