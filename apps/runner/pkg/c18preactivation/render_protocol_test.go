// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
)

type renderGoldenBundle struct {
	Contract        string                 `json:"contract"`
	Request         string                 `json:"request"`
	Success         string                 `json:"success"`
	Failure         string                 `json:"failure"`
	Evidence        []renderGoldenEvidence `json:"evidence"`
	FailureEvidence renderGoldenEvidence   `json:"failureEvidence"`
}

type renderGoldenEvidence struct {
	Descriptor RenderEvidenceDescriptor `json:"descriptor"`
	Body       string                   `json:"body"`
}

func TestRenderProtocolAdmitsExactPythonGoldens(t *testing.T) {
	golden := loadRenderGolden(t)
	if golden.Contract != "ambit.c18-specialist-render-command-goldens/v2" {
		t.Fatal("unexpected render golden contract")
	}
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	if err := verifySealedDigest(command, command.Digest); err != nil {
		t.Fatal(err)
	}
	success, err := ParseRenderResultV2(command, []byte(golden.Success))
	if err != nil {
		t.Fatal(err)
	}
	if success.Outcome != "succeeded" || len(success.Checks) != len(golden.Evidence) {
		t.Fatal("success golden did not retain its result roster")
	}
	for index, value := range golden.Evidence {
		parsed, err := ParseRenderCheckEvidenceV1(
			command, success.Execution.ExecutorRevision, value.Descriptor, []byte(value.Body),
		)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Check != success.Checks[index].Check || parsed.Outcome != success.Checks[index].Outcome {
			t.Fatal("evidence golden differs from result golden")
		}
	}
	failure, err := ParseRenderResultV2(command, []byte(golden.Failure))
	if err != nil {
		t.Fatal(err)
	}
	if failure.Outcome != "failed" || failure.Failure == nil {
		t.Fatal("failure golden lost its explicit failure")
	}
	if _, err := ParseRenderCheckEvidenceV1(
		command, failure.Execution.ExecutorRevision, golden.FailureEvidence.Descriptor,
		[]byte(golden.FailureEvidence.Body),
	); err != nil {
		t.Fatal(err)
	}
}

func TestRenderCommandBindsSourceBytesAndFacetExecutable(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	source := []byte("exact preactivation source")
	command.Source.ByteLength = int64(len(source))
	command.Source.Digest = sha256Digest(source)
	command.Digest = resealForTest(t, command)
	encoded, err := generationstop.CanonicalJSON(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRenderCommandV2(encoded, source); err != nil {
		t.Fatal(err)
	}

	if _, err := ParseRenderCommandV2(encoded, append([]byte(nil), source[:len(source)-1]...)); err == nil {
		t.Fatal("truncated inline source was admitted")
	}
	command.Renderer.ExecutablePath = facetExecutables["pdf"]
	command.Digest = resealForTest(t, command)
	encoded, err = generationstop.CanonicalJSON(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRenderCommandV2(encoded, source); err == nil {
		t.Fatal("cross-pack executable substitution was admitted")
	}
}

func TestRenderResultRejectsReboundRequestEvenWhenResealed(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	var result RenderResultV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Success), &result); err != nil {
		t.Fatal(err)
	}
	result.Request.Digest = "sha256:" + repeatHex("f")
	result.Digest = resealForTest(t, result)
	encoded, err := generationstop.CanonicalJSON(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRenderResultV2(command, encoded); err == nil {
		t.Fatal("result rebound to another request was admitted")
	}
}

func loadRenderGolden(t *testing.T) renderGoldenBundle {
	t.Helper()
	path := filepath.Clean(filepath.Join(
		"..", "..", "..", "..", "images", "ambit-agent-workspace", "capabilities",
		"c18-specialist-packs", "protocol", "render-command-goldens.v2.json",
	))
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var golden renderGoldenBundle
	if err := json.Unmarshal(encoded, &golden); err != nil {
		t.Fatal(err)
	}
	return golden
}

func resealForTest(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	delete(body, "digest")
	digest, err := semanticDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func repeatHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result[:64]
}
