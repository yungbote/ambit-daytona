// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
	"github.com/gin-gonic/gin"
)

func TestCanonicalControlResponsesMatchCrossLanguageGoldens(t *testing.T) {
	gin.SetMode(gin.TestMode)
	current := generationstop.ProviderGenerationObservation{
		Source: generationstop.Source{
			ProviderResourceID: "11111111-1111-4111-8111-111111111111",
			ExpectedProfile:    "managed-container", ExpectedRuntimeKind: "full_image_runtime_pack",
		},
		Owner: generationstop.ProviderOwner{
			TenantID:    "22222222-2222-4222-8222-222222222222",
			UserID:      "33333333-3333-4333-8333-333333333333",
			WorkspaceID: "44444444-4444-4444-8444-444444444444",
			RunID:       "55555555-5555-4555-8555-555555555555",
			GrantID:     "66666666-6666-4666-8666-666666666666",
		},
		Fence: generationstop.Fence{
			WorkspaceExecutionManifestRef: "workspace-execution-manifest:sha256:" + strings.Repeat("7", 64),
		},
		Generation: generationstop.ExpectedGeneration{
			ContainerID:        strings.Repeat("8", 64),
			ContainerCreatedAt: "2026-08-25T05:00:00.000Z",
			ExecutionStartedAt: "2026-08-25T05:00:01.000Z", RestartCount: 0,
		},
		State: "running", ObservedAt: "2026-08-25T05:00:02.123456789Z",
	}
	receipt := readSpecialistReceiptGolden(t)
	specialist := specialistrender.Observation{
		Schema: specialistrender.ObservationSchema, Status: "complete", Receipt: &receipt,
	}

	for _, test := range []struct {
		name       string
		golden     string
		value      any
		firstField string
	}{
		{
			name: "current-generation", golden: "provider-current-generation.canonical.json",
			value: current, firstField: `{"fence":`,
		},
		{
			name: "specialist-render-observe", golden: "specialist-render-observation.canonical.json",
			value: specialist, firstField: `{"receipt":`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			writeCanonicalJSONResponse(ctx, http.StatusOK, test.value)

			actual := recorder.Body.Bytes()
			assertControlGolden(t, test.golden, actual)
			if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("canonical response metadata differs: status=%d content-type=%q", recorder.Code, recorder.Header().Get("Content-Type"))
			}
			if !bytes.HasPrefix(actual, []byte(test.firstField)) || bytes.HasSuffix(actual, []byte{'\n'}) {
				t.Fatalf("canonical response field order or delimiter differs: %q", actual[:min(len(actual), 96)])
			}
			if !backendStrictCanonicalJSONAccepts(actual) {
				t.Fatal("backend strict canonical JSON consumer rejected the response")
			}
			ordinary, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(ordinary, actual) {
				t.Fatal("test fixture did not distinguish Go struct order from canonical key order")
			}
		})
	}
}

func TestCanonicalControlResponseFailsBeforeCommittingUnsupportedJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	writeCanonicalJSONResponse(ctx, http.StatusOK, map[string]any{"nonIntegral": 1.5})
	if recorder.Body.Len() != 0 || len(ctx.Errors) != 1 {
		t.Fatalf("unsupported canonical response was partially committed: body=%q errors=%#v", recorder.Body.Bytes(), ctx.Errors)
	}
}

func backendStrictCanonicalJSONAccepts(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false
	}
	canonical, err := generationstop.CanonicalJSON(value)
	return err == nil && bytes.Equal(canonical, data)
}

func readSpecialistReceiptGolden(t *testing.T) specialistrender.Receipt {
	t.Helper()
	path := filepath.Join(
		controllerRepoRoot(t),
		"apps/runner/pkg/specialistrender/testdata/provider-contract-golden.json",
	)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt specialistrender.Receipt
	if err := generationstop.DecodeCanonicalJSON(bytes.TrimSuffix(data, []byte{'\n'}), &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func controllerRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("controller test source path is unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../.."))
}

func assertControlGolden(t *testing.T, name string, actual []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_CANONICAL_CONTROL_GOLDENS") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, actual, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, actual) {
		t.Fatalf("canonical control golden %s differs; run with UPDATE_CANONICAL_CONTROL_GOLDENS=1", name)
	}
}
