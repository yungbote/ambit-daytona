// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/c18preactivation"
	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

func TestCollectorUsesAuthenticatedAPIWithConcurrentSuccessesAndDurableCancellations(t *testing.T) {
	fixture := newProviderCollectorFixture(t)
	defer fixture.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	collection, err := fixture.collector.Collect(ctx, fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	if len(collection.ProviderReceipts) != 12 ||
		len(collection.AuthenticatedStreaming.Cases) != providerSuccessConcurrency ||
		collection.ConcurrentLoad.PredeclaredConcurrency != providerSuccessConcurrency ||
		collection.ConcurrentLoad.MaximumDurationMilliseconds != int64(fixture.run.Timeouts.ExecuteSeconds)*1000 ||
		!collection.ConcurrentLoad.AllSucceeded || collection.ConcurrentLoad.Outcome != "passed" ||
		len(collection.ConcurrentLoad.Cases) != providerSuccessConcurrency {
		t.Fatalf("live collection coverage differs: %#v", collection)
	}
	cancelled := 0
	for _, row := range collection.ProviderReceipts {
		if row.Mode == "cancel" {
			cancelled++
			if row.Receipt.Outcome != "cancelled" || len(row.Receipt.Files) != 0 || !row.Receipt.Quiescence.ContainerAbsent {
				t.Fatalf("cancellation receipt differs: %#v", row)
			}
		}
	}
	fixture.harness.mu.Lock()
	unauthenticated := fixture.harness.unauthenticated
	successStreams := fixture.harness.successStreams
	cancelledOperations := fixture.harness.cancelledOperations
	peakSuccessRequests := fixture.harness.peakSuccessRequests
	settledSuccessRequests := fixture.harness.settledSuccessRequests
	fixture.harness.mu.Unlock()
	if cancelled != 6 || unauthenticated != 0 || successStreams != 6 || cancelledOperations != 6 ||
		peakSuccessRequests != providerSuccessConcurrency || settledSuccessRequests != providerSuccessConcurrency {
		t.Fatalf("authenticated provider census differs: %#v", fixture.harness)
	}
	encoded, _ := generationstop.CanonicalJSON(collection)
	if _, err := ParseProviderLiveCollection(encoded); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorConcurrentSuccessFailureSettlesEveryReleasedRequest(t *testing.T) {
	fixture := newProviderCollectorFixture(t)
	defer fixture.close()
	for _, execution := range fixture.run.Executions {
		if execution.Facet == "presentation" && execution.Mode == "success" {
			fixture.harness.failedSuccessOperation = execution.OperationID
		}
	}
	if fixture.harness.failedSuccessOperation == "" {
		t.Fatal("failure operation fixture is absent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	collection, err := fixture.collector.Collect(ctx, fixture.run)
	if err == nil || !strings.Contains(err.Error(), "presentation success") {
		t.Fatalf("concurrent provider failure was not attributed: collection=%#v err=%v", collection, err)
	}
	if collection.Contract != "" || collection.Digest != "" || len(collection.ProviderReceipts) != 0 {
		t.Fatal("failed concurrent load returned a partial collection")
	}
	fixture.harness.mu.Lock()
	arrived := fixture.harness.arrivedSuccessRequests
	settled := fixture.harness.settledSuccessRequests
	peak := fixture.harness.peakSuccessRequests
	cancelledOperations := fixture.harness.cancelledOperations
	fixture.harness.mu.Unlock()
	if arrived != providerSuccessConcurrency || settled != providerSuccessConcurrency ||
		peak != providerSuccessConcurrency || cancelledOperations != providerSuccessConcurrency {
		t.Fatalf("concurrent failure did not settle the full released batch: %#v", fixture.harness)
	}
}

func TestCollectorRejectsParentGenerationRotationAfterIssuance(t *testing.T) {
	fixture := newProviderCollectorFixture(t)
	defer fixture.close()
	fixture.run.Target.ExpectedGeneration.RestartCount++
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	collection, err := fixture.collector.Collect(ctx, fixture.run)
	if err == nil || !strings.Contains(err.Error(), "current generation observation differs") {
		t.Fatalf("rotated parent generation was not rejected: collection=%#v err=%v", collection, err)
	}
	fixture.harness.mu.Lock()
	executed := fixture.harness.successStreams + fixture.harness.cancelledOperations
	fixture.harness.mu.Unlock()
	if executed != 0 {
		t.Fatalf("provider executed after parent generation rotation: %d", executed)
	}
}

type providerCollectorFixture struct {
	collector *Collector
	run       ProviderLiveRun
	harness   *providerHarness
	server    *httptest.Server
}

func (fixture providerCollectorFixture) close() {
	fixture.server.Close()
}

func newProviderCollectorFixture(t *testing.T) providerCollectorFixture {
	t.Helper()
	root := t.TempDir()
	seccompSource := filepath.Join(repoRoot(t), "images/ambit-agent-workspace/capabilities/c18-specialist-packs/policy/specialist-seccomp-v1.json")
	seccompBytes, err := os.ReadFile(seccompSource)
	if err != nil {
		t.Fatal(err)
	}
	seccompPath := filepath.Join(root, "specialist-seccomp-v1.json")
	if err := os.WriteFile(seccompPath, seccompBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	policySet, policies := policyFixtureAt(t, seccompPath, seccompPath)
	policyBytes, _ := generationstop.CanonicalJSON(policySet)
	policyPath := filepath.Join(root, "runner-policy.json")
	if err := os.WriteFile(policyPath, policyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	base := readBaseReceipt(t)
	renderPolicies := providerRenderPolicies(t)
	executions := make([]ProviderLiveExecution, 0, 12)
	modes := make(map[string]string, 12)
	sequences := make(map[string]int, 12)
	sequence := 1
	for _, facet := range []string{"data_analysis", "pdf", "presentation", "research", "spreadsheet", "web_application"} {
		sourceBytes := []byte("provider integration source for " + facet)
		sourcePath := filepath.Join(root, "source-"+facet+".bin")
		if err := os.WriteFile(sourcePath, sourceBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"cancel", "success"} {
			operationID := fmt.Sprintf("33333333-3333-4333-8333-%012d", sequence)
			commandBytes := providerCommandFixture(t, renderPolicies[facet], operationID, sourceBytes)
			commandPath := filepath.Join(root, "request-"+facet+"-"+mode+".json")
			if err := os.WriteFile(commandPath, commandBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			executions = append(executions, ProviderLiveExecution{
				Facet: facet, Mode: mode, OperationID: operationID,
				ArtifactRenderJobRef: "ambit://artifact-render-jobs/" + operationID,
				Request:              PinnedInputFile{Path: commandPath, ByteLength: int64(len(commandBytes)), SHA256: digestBytes(commandBytes)},
				Source:               PinnedInputFile{Path: sourcePath, ByteLength: int64(len(sourceBytes)), SHA256: digestBytes(sourceBytes)},
			})
			modes[operationID] = mode
			sequences[operationID] = sequence
			sequence++
		}
	}
	run := ProviderLiveRun{
		Contract:       ProviderLiveRunContract,
		SourceRevision: "1" + strings.Repeat("0", 39), SourceTree: "2" + strings.Repeat("0", 39),
		SourceSetDigest: digestSeed(3),
		RunnerPolicy:    PinnedInputFile{Path: policyPath, ByteLength: int64(len(policyBytes)), SHA256: digestBytes(policyBytes)},
		Target: ProviderLiveTarget{
			Source: base.Request.Source, Owner: base.Request.Owner,
			Fence: generationstop.Fence{
				WorkspaceExecutionManifestRef: "workspace-execution-manifest:" + digestSeed(3),
			},
			ExpectedGeneration: base.Request.ExpectedParentGeneration,
			ObservedAt:         "2026-08-24T00:00:00.000Z",
			WorkspaceExecutionManifest: specialistrender.Pin{
				Ref: "workspace-execution-manifest:" + digestSeed(3), Digest: digestSeed(90),
			},
		},
		Executions: executions,
		Timeouts: ProviderLiveTimeouts{
			ExecuteSeconds: providerExecuteSeconds, ObservationSeconds: providerObservationSeconds,
			PollMilliseconds:               providerPollMilliseconds,
			CancelAfterPartialMilliseconds: providerCancelAfterPartialMilli,
		},
	}

	harness := &providerHarness{
		t: t, credential: "live-test-key", base: base, policies: policies,
		modes: modes, sequences: sequences, states: make(map[string]specialistrender.Observation),
		observationCalls: make(map[string]int),
		releaseSuccess:   make(chan struct{}),
	}
	server := httptest.NewServer(http.HandlerFunc(harness.serveHTTP))
	baseURL, _ := url.Parse(server.URL + "/api/")
	collector, err := NewCollector(
		DaytonaAPIConfig{BaseURL: baseURL, Credential: harness.credential, OrganizationID: base.Request.Owner.TenantID},
		server.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)
	collector.now = func() time.Time {
		value := observedAt
		observedAt = observedAt.Add(time.Second)
		return value
	}
	collector.after = func(time.Duration) <-chan time.Time {
		ready := make(chan time.Time, 1)
		ready <- time.Now()
		return ready
	}
	return providerCollectorFixture{collector: collector, run: run, harness: harness, server: server}
}

type providerHarness struct {
	t          *testing.T
	credential string
	base       specialistrender.Receipt
	policies   map[string]specialistrender.Policy
	modes      map[string]string
	sequences  map[string]int

	mu                     sync.Mutex
	states                 map[string]specialistrender.Observation
	unauthenticated        int
	successStreams         int
	cancelledOperations    int
	arrivedSuccessRequests int
	activeSuccessRequests  int
	peakSuccessRequests    int
	settledSuccessRequests int
	renderObservations     int
	releaseSuccess         chan struct{}
	failedSuccessOperation string
	hideFirstObservation   bool
	observationCalls       map[string]int
	observationDelay       time.Duration
}

func (harness *providerHarness) serveHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Authorization") != "Bearer "+harness.credential ||
		request.Header.Get("X-Daytona-Source") != "ambit-c18-provider-integration" {
		harness.mu.Lock()
		harness.unauthenticated++
		harness.mu.Unlock()
		response.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case strings.HasSuffix(request.URL.Path, "/generation/observe-current"):
		harness.observeCurrent(response, request)
	case strings.HasSuffix(request.URL.Path, "/specialist-renders/observe"):
		harness.observeRender(response, request)
	case strings.HasSuffix(request.URL.Path, "/specialist-renders"):
		harness.execute(response, request)
	default:
		response.WriteHeader(http.StatusNotFound)
	}
}

func (harness *providerHarness) observeCurrent(response http.ResponseWriter, request *http.Request) {
	data, err := io.ReadAll(request.Body)
	if err != nil {
		harness.t.Error(err)
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	var authority generationstop.ProviderGenerationObservationRequest
	if err := generationstop.DecodeCanonicalJSON(data, &authority); err != nil {
		harness.t.Error(err)
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(generationstop.ProviderGenerationObservation{
		Source: authority.Source, Owner: authority.Owner, Fence: authority.Fence,
		Generation: harness.base.Request.ExpectedParentGeneration, State: "running",
		ObservedAt: "2026-08-25T04:00:00Z",
	})
}

func (harness *providerHarness) observeRender(response http.ResponseWriter, request *http.Request) {
	data, err := io.ReadAll(request.Body)
	if err != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	var observe specialistrender.ObserveRequest
	if err := generationstop.DecodeCanonicalJSON(data, &observe); err != nil {
		harness.t.Error(err)
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	harness.mu.Lock()
	harness.renderObservations++
	delay := harness.observationDelay
	harness.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	harness.mu.Lock()
	if harness.hideFirstObservation && harness.observationCalls[observe.OperationID] == 0 {
		harness.observationCalls[observe.OperationID]++
		harness.mu.Unlock()
		response.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(response).Encode(specialistrender.Observation{
			Schema: specialistrender.ObservationSchema, Status: "absent",
		})
		return
	}
	observation, exists := harness.states[observe.OperationID]
	harness.mu.Unlock()
	if !exists {
		observation = specialistrender.Observation{Schema: specialistrender.ObservationSchema, Status: "absent"}
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(response).Encode(observation)
}

func (harness *providerHarness) execute(response http.ResponseWriter, request *http.Request) {
	stream, err := specialistrender.DecodeRequestStream(request.Body)
	if err != nil {
		harness.t.Error(err)
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	defer stream.Close()
	mode := harness.modes[stream.Request.OperationID]
	policy := harness.policies[stream.Request.Image.PackID]
	if mode == "" || policy.Image.PackID == "" {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	if mode == "cancel" {
		harness.mu.Lock()
		harness.states[stream.Request.OperationID] = specialistrender.Observation{
			Schema: specialistrender.ObservationSchema, Status: "partial",
		}
		harness.mu.Unlock()
		<-request.Context().Done()
		receipt := receiptForRequest(harness.t, harness.base, policy, stream.Request, harness.sequences[stream.Request.OperationID], "cancel")
		harness.mu.Lock()
		harness.states[stream.Request.OperationID] = specialistrender.Observation{
			Schema: specialistrender.ObservationSchema, Status: "complete", Receipt: &receipt,
		}
		harness.cancelledOperations++
		harness.mu.Unlock()
		return
	}
	harness.mu.Lock()
	harness.arrivedSuccessRequests++
	harness.activeSuccessRequests++
	if harness.activeSuccessRequests > harness.peakSuccessRequests {
		harness.peakSuccessRequests = harness.activeSuccessRequests
	}
	if harness.arrivedSuccessRequests == providerSuccessConcurrency {
		close(harness.releaseSuccess)
	}
	releaseSuccess := harness.releaseSuccess
	failed := stream.Request.OperationID == harness.failedSuccessOperation
	harness.mu.Unlock()
	select {
	case <-releaseSuccess:
	case <-request.Context().Done():
		return
	}
	defer func() {
		harness.mu.Lock()
		harness.activeSuccessRequests--
		harness.settledSuccessRequests++
		harness.mu.Unlock()
	}()
	if failed {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	receipt := receiptForRequest(harness.t, harness.base, policy, stream.Request, harness.sequences[stream.Request.OperationID], "success")
	response.Header().Set("Content-Type", specialistRenderContentType)
	response.WriteHeader(http.StatusOK)
	if err := specialistrender.EncodeResponseStream(request.Context(), response, specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0],
			Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("result"))), nil
			},
			Cleanup: func() error { return nil },
		}},
	}); err != nil {
		harness.t.Error(err)
	}
	harness.mu.Lock()
	harness.successStreams++
	harness.states[stream.Request.OperationID] = specialistrender.Observation{
		Schema: specialistrender.ObservationSchema, Status: "complete", Receipt: &receipt,
	}
	harness.mu.Unlock()
}

func receiptForRequest(
	t *testing.T,
	base specialistrender.Receipt,
	policy specialistrender.Policy,
	request specialistrender.Request,
	sequence int,
	mode string,
) specialistrender.Receipt {
	t.Helper()
	receipt := receiptFixture(t, base, policy, sequence, mode)
	receipt.Request = request
	receipt.Launch.ContainerName = "ambit-specialist-render-" + strings.ReplaceAll(request.OperationID, "-", "")
	receipt.Launch.Command = []string{
		"/bin/sh", "-c", `stty raw -echo -onlcr && exec "$1" --framed-jsonl --nonce "$2"`,
		specialistrender.RoleRef, request.Executable, receipt.Nonce,
	}
	receipt.Launch.ParentGeneration = request.ExpectedParentGeneration
	receipt.ReceiptDigest, _ = specialistrender.ComputeReceiptDigest(receipt)
	if err := specialistrender.ValidateReceiptWithPolicy(receipt, policy); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func readBaseReceipt(t *testing.T) specialistrender.Receipt {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "apps/runner/pkg/specialistrender/testdata/provider-contract-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt specialistrender.Receipt
	if err := generationstop.DecodeCanonicalJSON(bytes.TrimSuffix(data, []byte{'\n'}), &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

type providerRenderPolicyFixture struct {
	CheckLabels             []c18preactivation.RenderLabeledCheckV2 `json:"checkLabels"`
	ExecutablePath          string                                  `json:"executablePath"`
	ExecutorPackRevisionRef string                                  `json:"executorPackRevisionRef"`
	Facet                   string                                  `json:"facet"`
	RenderMode              string                                  `json:"renderMode"`
	RendererRef             string                                  `json:"rendererRef"`
	Representation          string                                  `json:"representation"`
	RequiredSchemaURI       *string                                 `json:"requiredSchemaUri"`
	SourceMediaType         string                                  `json:"sourceMediaType"`
	ValidationPolicyRef     string                                  `json:"validationPolicyRef"`
}

func providerRenderPolicies(t *testing.T) map[string]providerRenderPolicyFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(
		repoRoot(t),
		"images/ambit-agent-workspace/capabilities/c18-specialist-packs/protocol/render-policy-matrix.v1.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var matrix struct {
		Entries []providerRenderPolicyFixture `json:"entries"`
		Schema  string                        `json:"schema"`
	}
	if err := json.Unmarshal(bytes.TrimSuffix(data, []byte{'\n'}), &matrix); err != nil {
		t.Fatal(err)
	}
	mediaByFacet := map[string]string{
		"data_analysis":   "text/csv",
		"pdf":             "application/pdf",
		"presentation":    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"research":        "text/markdown",
		"spreadsheet":     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"web_application": "text/html",
	}
	result := make(map[string]providerRenderPolicyFixture, len(mediaByFacet))
	for _, entry := range matrix.Entries {
		if mediaByFacet[entry.Facet] == entry.SourceMediaType {
			result[entry.Facet] = entry
		}
	}
	if len(result) != providerSuccessConcurrency {
		t.Fatalf("provider command policy coverage differs: %#v", result)
	}
	return result
}

func providerCommandFixture(
	t *testing.T,
	policy providerRenderPolicyFixture,
	operationID string,
	sourceBytes []byte,
) []byte {
	t.Helper()
	jobRef := "ambit://artifact-render-jobs/" + operationID
	command := c18preactivation.RenderCommandV2{
		Contract:   c18preactivation.RenderCommandContractV2,
		DeadlineAt: "2026-08-24T04:00:00.000Z",
		Facet:      policy.Facet, JobRef: jobRef,
		JobRoot:   "/workspace/.ambit/render-jobs/" + operationID,
		Operation: "render_validate",
		Output: c18preactivation.RenderOutputAuthorityV2{
			JobOutputRoot: "outputs/render", MaximumAggregateImagePixels: 32 * 1024 * 1024,
			MaximumImagePixels: 8 * 1024 * 1024, MaximumPreviewBytes: 8 * 1024 * 1024,
			PreviewMediaType: c18preactivation.RenderPreviewMediaType,
			PreviewPath:      "outputs/render/preview.json", ResultPath: "outputs/render/result.json",
		},
		PackRequiredChecks: append([]c18preactivation.RenderLabeledCheckV2(nil), policy.CheckLabels...),
		Renderer: c18preactivation.RenderRendererV2{
			ExecutablePath: policy.ExecutablePath, RenderMode: policy.RenderMode,
			RendererRef: policy.RendererRef, Representation: policy.Representation,
			ValidationPolicyRef: policy.ValidationPolicyRef,
		},
		RequestPath: "inputs/request.json",
		Runtime: c18preactivation.RenderRuntimeV2{
			PackRevisions: []specialistrender.Pin{{Ref: policy.ExecutorPackRevisionRef, Digest: digestSeed(91)}},
			ProfileRevision: specialistrender.Pin{
				Ref: "ambit.workspace-runtime/provider-live-test@1", Digest: digestSeed(92),
			},
			WorkspaceExecutionManifest: specialistrender.Pin{
				Ref: "workspace-execution-manifest:" + digestSeed(3), Digest: digestSeed(90),
			},
		},
		Source: c18preactivation.RenderSourceV2{
			ByteLength: int64(len(sourceBytes)), Digest: digestBytes(sourceBytes),
			MediaType: policy.SourceMediaType, Path: "inputs/source.bin",
			Ref:       "ambit://artifact-revisions/provider-live/" + policy.Facet,
			SchemaURI: policy.RequiredSchemaURI,
		},
	}
	raw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	delete(body, "digest")
	bodyBytes, err := generationstop.CanonicalJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	command.Digest = digestBytes(bodyBytes)
	encoded, err := generationstop.CanonicalJSON(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c18preactivation.ParseRenderCommandV2(encoded, sourceBytes); err != nil {
		t.Fatal(err)
	}
	return encoded
}
