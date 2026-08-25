// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

func TestHTTPProviderUsesExactRunnerTransport(t *testing.T) {
	request, requestBytes, sourceBytes := testProviderRequest(t)
	payload := []byte("provider result")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, observed *http.Request) {
		if observed.URL.Path != "/api/sandbox/sandbox-c18/specialist-renders" ||
			observed.Header.Get("Accept") != specialistRenderMediaType ||
			observed.Header.Get("Content-Type") != specialistRenderMediaType ||
			observed.Header.Get("Authorization") != "Bearer secret" ||
			observed.Header.Get("X-Daytona-Organization-ID") != "organization" ||
			observed.Header.Get("X-Daytona-Source") != "ambit-backend" {
			t.Errorf("HTTP provider authority differs: path=%q headers=%v", observed.URL.Path, observed.Header)
		}
		stream, err := specialistrender.DecodeRequestStream(observed.Body)
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		defer stream.Close()
		if !canonicalEqual(stream.Request, request) {
			t.Error("HTTP provider request authority differs")
		}
		assertInputBytes(t, stream.Input, requestBytes)
		assertInputBytes(t, stream.Source, sourceBytes)
		receipt := testProviderReceipt(t, request, payload)
		writer.Header().Set("Content-Type", specialistRenderMediaType)
		writer.WriteHeader(http.StatusOK)
		if err := specialistrender.EncodeResponseStream(observed.Context(), writer, specialistrender.ExecutionResult{
			Receipt: receipt,
			Files: []specialistrender.Payload{{
				File: receipt.Files[0],
				Open: func(context.Context) (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(payload)), nil
				},
				Cleanup: func() error { return nil },
			}},
		}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	baseURL, err := url.Parse(server.URL + "/api/")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewHTTPProvider(HTTPProviderConfig{
		BaseURL: baseURL, Credential: "secret", OrganizationID: "organization",
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	input := testProviderInput(t, requestBytes, sourceBytes)
	result, err := provider.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt.Outcome != "succeeded" || len(result.Files) != 1 ||
		!bytes.Equal(result.Files[0].Bytes, payload) {
		t.Fatal("HTTP provider result differs")
	}
	custody := &hashingResponseCustody{}
	observation, err := provider.ExecuteToCustody(context.Background(), input, custody)
	if err != nil {
		t.Fatal(err)
	}
	if !custody.committed || custody.aborted || observation.WireSHA256 == "" ||
		observation.Receipt.ReceiptDigest != result.Receipt.ReceiptDigest {
		t.Fatal("streaming HTTP provider did not commit exact response custody")
	}
}

func TestHTTPProviderConfigurationMatchesBackendCredentialRules(t *testing.T) {
	environment := map[string]string{
		"DAYTONA_API_URL":         "https://daytona.test/api",
		"DAYTONA_API_KEY":         "api-key",
		"DAYTONA_JWT_TOKEN":       "jwt",
		"DAYTONA_ORGANIZATION_ID": "organization",
	}
	config, err := HTTPProviderConfigFromEnvironment(func(name string) string { return environment[name] })
	if err != nil {
		t.Fatal(err)
	}
	if config.Credential != "api-key" || config.BaseURL.String() != "https://daytona.test/api/" {
		t.Fatalf("unexpected transport: %#v", config)
	}
	delete(environment, "DAYTONA_API_KEY")
	if config, err = HTTPProviderConfigFromEnvironment(func(name string) string { return environment[name] }); err != nil || config.Credential != "jwt" {
		t.Fatalf("JWT transport was not admitted: %#v %v", config, err)
	}
	delete(environment, "DAYTONA_ORGANIZATION_ID")
	if _, err := HTTPProviderConfigFromEnvironment(func(name string) string { return environment[name] }); err == nil {
		t.Fatal("organization-free JWT transport was admitted")
	}
	for _, rawURL := range []string{
		"https://daytona.test/api?",
		"https://daytona.test/api/%2f",
		"https://daytona.test/api\\authority",
	} {
		baseURL, parseErr := url.Parse(rawURL)
		if parseErr != nil {
			continue
		}
		if _, err := NewHTTPProvider(HTTPProviderConfig{BaseURL: baseURL, Credential: "secret"}, nil); err == nil {
			t.Fatalf("noncanonical Daytona base URL was admitted: %q", rawURL)
		}
	}
}

func TestHTTPProviderRejectsRedirectAndStatusOutcomeDisagreement(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
	}{
		{name: "redirect", status: http.StatusTemporaryRedirect},
		{name: "unprocessable without failed receipt", status: http.StatusUnprocessableEntity},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, requestBytes, sourceBytes := testProviderRequest(t)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, observed *http.Request) {
				if strings.HasSuffix(observed.URL.Path, "/specialist-renders/observe") {
					writeAbsentProviderObservation(t, writer)
					return
				}
				stream, err := specialistrender.DecodeRequestStream(observed.Body)
				if err == nil {
					_ = stream.Close()
				}
				if test.status == http.StatusTemporaryRedirect {
					writer.Header().Set("Location", "https://example.invalid/")
					writer.WriteHeader(test.status)
					return
				}
				payload := []byte("provider result")
				receipt := testProviderReceipt(t, request, payload)
				writer.Header().Set("Content-Type", specialistRenderMediaType)
				writer.WriteHeader(test.status)
				_ = specialistrender.EncodeResponseStream(observed.Context(), writer, specialistrender.ExecutionResult{
					Receipt: receipt,
					Files: []specialistrender.Payload{{
						File: receipt.Files[0], Open: func(context.Context) (io.ReadCloser, error) {
							return io.NopCloser(bytes.NewReader(payload)), nil
						}, Cleanup: func() error { return nil },
					}},
				})
			}))
			defer server.Close()
			baseURL, _ := url.Parse(server.URL + "/")
			provider, err := NewHTTPProvider(HTTPProviderConfig{BaseURL: baseURL, Credential: "secret"}, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			custody := &hashingResponseCustody{}
			if _, err := provider.ExecuteToCustody(
				context.Background(), testProviderInput(t, requestBytes, sourceBytes), custody,
			); err == nil {
				t.Fatal("invalid HTTP settlement was admitted")
			}
			if custody.committed || !custody.aborted {
				t.Fatal("invalid HTTP settlement did not abort custody")
			}
		})
	}
}

func TestHTTPProviderRejectsStatusOutcomeBeforeOpeningCustody(t *testing.T) {
	for _, test := range []struct {
		name           string
		status         int
		receiptOutcome string
	}{
		{name: "422 succeeded", status: http.StatusUnprocessableEntity, receiptOutcome: "succeeded"},
		{name: "200 failed", status: http.StatusOK, receiptOutcome: "failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, requestBytes, sourceBytes := testProviderRequest(t)
			payload := []byte("provider result")
			receipt := testProviderReceipt(t, request, payload)
			if test.receiptOutcome == "failed" {
				receipt.Outcome = "failed"
				receipt.TerminalOutcome = "failed"
				receipt.HelperExitCode = 1
				var err error
				receipt.ReceiptDigest, err = specialistrender.ComputeReceiptDigest(receipt)
				if err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, observed *http.Request) {
				if strings.HasSuffix(observed.URL.Path, "/specialist-renders/observe") {
					writeAbsentProviderObservation(t, writer)
					return
				}
				stream, err := specialistrender.DecodeRequestStream(observed.Body)
				if err != nil {
					t.Error(err)
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				_ = stream.Close()
				writer.Header().Set("Content-Type", specialistRenderMediaType)
				writer.WriteHeader(test.status)
				_ = specialistrender.EncodeResponseStream(observed.Context(), writer, specialistrender.ExecutionResult{
					Receipt: receipt,
					Files: []specialistrender.Payload{{
						File: receipt.Files[0], Open: func(context.Context) (io.ReadCloser, error) {
							return io.NopCloser(bytes.NewReader(payload)), nil
						}, Cleanup: func() error { return nil },
					}},
				})
			}))
			defer server.Close()
			baseURL, _ := url.Parse(server.URL + "/")
			provider, err := NewHTTPProvider(
				HTTPProviderConfig{BaseURL: baseURL, Credential: "secret"},
				server.Client(),
			)
			if err != nil {
				t.Fatal(err)
			}
			custody := &hashingResponseCustody{}
			_, executeErr := provider.ExecuteToCustody(
				context.Background(), testProviderInput(t, requestBytes, sourceBytes), custody,
			)
			if executeErr == nil || len(custody.files) != 0 || custody.committed || !custody.aborted {
				t.Fatalf("status/outcome mismatch reached output custody: files=%d committed=%t aborted=%t err=%v", len(custody.files), custody.committed, custody.aborted, executeErr)
			}
		})
	}
}

func TestHTTPProviderEscapesResourceIDExactlyOnce(t *testing.T) {
	requestBytes := []byte("request")
	sourceBytes := []byte("source")
	observedURI := ""
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/specialist-renders/observe") {
			writeAbsentProviderObservation(t, writer)
			return
		}
		observedURI = request.RequestURI
		_, _ = io.Copy(io.Discard, request.Body)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	baseURL, _ := url.Parse(server.URL + "/api/")
	provider, err := NewHTTPProvider(HTTPProviderConfig{BaseURL: baseURL, Credential: "secret"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		resourceID string
		expected   string
	}{
		{resourceID: "sandbox/a%b", expected: "/api/sandbox/sandbox%2Fa%25b/specialist-renders"},
		{resourceID: "sandbox/雪", expected: "/api/sandbox/sandbox%2F%E9%9B%AA/specialist-renders"},
	} {
		input := testProviderInput(t, requestBytes, sourceBytes)
		input.Workspace.ProviderResourceID = test.resourceID
		if _, err := provider.Execute(context.Background(), input); err == nil {
			t.Fatal("injected server failure was not returned")
		}
		if observedURI != test.expected {
			t.Fatalf("resource ID %q was not escaped exactly once: %q", test.resourceID, observedURI)
		}
	}
}

func TestHTTPProviderReconcilesEveryPostSendAmbiguity(t *testing.T) {
	for _, test := range []struct {
		status string
		kind   string
	}{
		{status: generationstop.ObservationAbsent, kind: "not_admitted"},
		{status: generationstop.ObservationPartial, kind: "partial"},
		{status: generationstop.ObservationComplete, kind: "complete_output_unadmitted"},
	} {
		t.Run(test.status, func(t *testing.T) {
			requestBytes := []byte("request")
			sourceBytes := []byte("source")
			input := testProviderInput(t, requestBytes, sourceBytes)
			expected, _, _, err := ProviderRequest(input)
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("result")
			receipt := testProviderReceipt(t, expected, payload)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if strings.HasSuffix(request.URL.Path, "/specialist-renders/observe") {
					body, err := io.ReadAll(io.LimitReader(request.Body, 32*1024+1))
					if err != nil {
						t.Error(err)
					}
					var observed specialistrender.ObserveRequest
					if err := generationstop.DecodeCanonicalJSON(body, &observed); err != nil ||
						observed.OperationID != expected.OperationID || observed.RequestFingerprint != expected.RequestFingerprint {
						t.Errorf("reconciliation authority differs: %#v %v", observed, err)
					}
					observation := specialistrender.Observation{
						Schema: specialistrender.ObservationSchema, Status: test.status,
					}
					if test.status == generationstop.ObservationComplete {
						observation.Receipt = &receipt
					}
					encoded, _ := generationstop.CanonicalJSON(observation)
					writer.Header().Set("Content-Type", "application/json")
					writer.WriteHeader(http.StatusOK)
					_, _ = writer.Write(encoded)
					return
				}
				stream, err := specialistrender.DecodeRequestStream(request.Body)
				if err != nil {
					t.Error(err)
				} else {
					_ = stream.Close()
				}
				writer.WriteHeader(http.StatusBadGateway)
			}))
			defer server.Close()
			baseURL, _ := url.Parse(server.URL + "/")
			provider, err := NewHTTPProvider(HTTPProviderConfig{BaseURL: baseURL, Credential: "secret"}, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			custody := &hashingResponseCustody{}
			_, executeErr := provider.ExecuteToCustody(context.Background(), input, custody)
			var settlement *ProviderSettlementError
			if !errors.As(executeErr, &settlement) || settlement.Kind != test.kind ||
				settlement.Observation == nil || custody.committed || !custody.aborted {
				t.Fatalf("unexpected reconciled settlement: %#v error=%v", settlement, executeErr)
			}
		})
	}
}

func TestHTTPProviderReconcilesEveryUnexpectedPostSendStatusClass(t *testing.T) {
	for _, status := range []int{
		http.StatusTemporaryRedirect,
		http.StatusRequestTimeout,
		http.StatusConflict,
		http.StatusTooEarly,
		http.StatusTooManyRequests,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if strings.HasSuffix(request.URL.Path, "/specialist-renders/observe") {
					writeAbsentProviderObservation(t, writer)
					return
				}
				_, _ = io.Copy(io.Discard, request.Body)
				writer.WriteHeader(status)
			}))
			defer server.Close()
			baseURL, _ := url.Parse(server.URL + "/")
			provider, err := NewHTTPProvider(
				HTTPProviderConfig{BaseURL: baseURL, Credential: "secret"},
				server.Client(),
			)
			if err != nil {
				t.Fatal(err)
			}
			custody := &hashingResponseCustody{}
			_, executeErr := provider.ExecuteToCustody(
				context.Background(),
				testProviderInput(t, []byte("request"), []byte("source")),
				custody,
			)
			var settlement *ProviderSettlementError
			if !errors.As(executeErr, &settlement) || settlement.Kind != "not_admitted" ||
				settlement.Observation == nil || settlement.Observation.Status != generationstop.ObservationAbsent ||
				custody.committed || !custody.aborted {
				t.Fatalf("status %d bypassed exact reconciliation: settlement=%#v err=%v", status, settlement, executeErr)
			}
		})
	}
}

func TestHTTPProviderNeverForwardsAuthorizationAcrossRedirect(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetCalls.Add(1)
		if request.Header.Get("Authorization") != "" {
			t.Error("redirect target received provider authorization")
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		writer.Header().Set("Location", target.URL)
		writer.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	baseURL, _ := url.Parse(source.URL + "/")
	provider, err := NewHTTPProvider(HTTPProviderConfig{BaseURL: baseURL, Credential: "secret"}, source.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Execute(context.Background(), testProviderInput(t, []byte("request"), []byte("source"))); err == nil {
		t.Fatal("redirect was admitted")
	}
	if targetCalls.Load() != 0 {
		t.Fatalf("redirect target was called %d times", targetCalls.Load())
	}
}

func TestHTTPProviderUnblocksEncoderWhenTransportReturnsBeforeReadingBody(t *testing.T) {
	baseURL, _ := url.Parse("https://daytona.test/")
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/specialist-renders/observe") {
			encoded, _ := generationstop.CanonicalJSON(specialistrender.Observation{
				Schema: specialistrender.ObservationSchema, Status: generationstop.ObservationAbsent,
			})
			return testHTTPResponse(request, http.StatusOK, "application/json", encoded), nil
		}
		// Deliberately return without consuming or closing the streaming body.
		return testHTTPResponse(request, http.StatusServiceUnavailable, "", nil), nil
	})
	provider, err := NewHTTPProvider(
		HTTPProviderConfig{BaseURL: baseURL, Credential: "secret"},
		&http.Client{Transport: transport},
	)
	if err != nil {
		t.Fatal(err)
	}
	input := testProviderInput(
		t,
		bytes.Repeat([]byte{'r'}, specialistrender.MaximumRequestBytes),
		[]byte("source"),
	)
	completed := make(chan error, 1)
	go func() {
		_, err := provider.ExecuteToCustody(context.Background(), input, DiscardProviderResponseCustody())
		completed <- err
	}()
	select {
	case executeErr := <-completed:
		var settlement *ProviderSettlementError
		if !errors.As(executeErr, &settlement) || settlement.Kind != "not_admitted" {
			t.Fatalf("early transport response was not reconciled: %v", executeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("early transport response stranded the provider request encoder")
	}
}

func TestHTTPProviderReconciliationRecoversReceiptOnlyAfterCallerCancellation(t *testing.T) {
	for _, outcome := range []string{"cancelled", "timed_out"} {
		t.Run(outcome, func(t *testing.T) {
			baseURL, _ := url.Parse("https://daytona.test/")
			input := testProviderInput(t, []byte("request"), []byte("source"))
			expected, _, _, err := ProviderRequest(input)
			if err != nil {
				t.Fatal(err)
			}
			receipt := receiptOnlyProviderReceipt(t, expected, outcome)
			ctx, cancel := context.WithCancel(context.Background())
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if strings.HasSuffix(request.URL.Path, "/specialist-renders/observe") {
					encoded, _ := generationstop.CanonicalJSON(specialistrender.Observation{
						Schema: specialistrender.ObservationSchema, Status: generationstop.ObservationComplete,
						Receipt: &receipt,
					})
					return testHTTPResponse(request, http.StatusOK, "application/json", encoded), nil
				}
				cancel()
				return nil, errors.New("injected post-send transport failure")
			})
			provider, err := NewHTTPProvider(
				HTTPProviderConfig{BaseURL: baseURL, Credential: "secret"},
				&http.Client{Transport: transport},
			)
			if err != nil {
				t.Fatal(err)
			}
			_, executeErr := provider.ExecuteToCustody(ctx, input, DiscardProviderResponseCustody())
			var settlement *ProviderSettlementError
			if !errors.As(executeErr, &settlement) || settlement.Kind != "complete_output_unadmitted" ||
				settlement.Observation == nil || settlement.Observation.Receipt == nil ||
				settlement.Observation.Receipt.Outcome != outcome {
				t.Fatalf("caller cancellation lost durable %s settlement: %#v err=%v", outcome, settlement, executeErr)
			}
		})
	}
}

func TestHTTPProviderReconciliationHasIndependentBoundedTimeout(t *testing.T) {
	baseURL, _ := url.Parse("https://daytona.test/")
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/specialist-renders/observe") {
			<-request.Context().Done()
			return nil, request.Context().Err()
		}
		return nil, errors.New("injected post-send transport failure")
	})
	provider, err := NewHTTPProvider(
		HTTPProviderConfig{BaseURL: baseURL, Credential: "secret"},
		&http.Client{Transport: transport},
	)
	if err != nil {
		t.Fatal(err)
	}
	provider.settlementTimeout = 20 * time.Millisecond
	started := time.Now()
	_, executeErr := provider.ExecuteToCustody(
		context.Background(),
		testProviderInput(t, []byte("request"), []byte("source")),
		DiscardProviderResponseCustody(),
	)
	var settlement *ProviderSettlementError
	if elapsed := time.Since(started); elapsed > time.Second ||
		!errors.As(executeErr, &settlement) || settlement.Kind != "ambiguous" {
		t.Fatalf("settlement reconciliation exceeded its independent bound: elapsed=%s err=%v", elapsed, executeErr)
	}
}

func TestHTTPProviderCancelledBeforeSendStillCleansConcreteCustody(t *testing.T) {
	baseURL, _ := url.Parse("https://daytona.test/")
	provider, err := NewHTTPProvider(
		HTTPProviderConfig{BaseURL: baseURL, Credential: "secret"},
		&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("transport must not be called")
		})},
	)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := NewTemporaryProviderResponseCustody()
	if err != nil {
		t.Fatal(err)
	}
	root := custody.root
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.ExecuteToCustody(
		ctx, testProviderInput(t, []byte("request"), []byte("source")), custody,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled provider call returned the wrong error: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("cancelled direct provider custody root remains: %v", err)
	}
	if err := custody.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testHTTPResponse(
	request *http.Request,
	status int,
	contentType string,
	body []byte,
) *http.Response {
	header := make(http.Header)
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body)), Request: request,
	}
}

func writeAbsentProviderObservation(t *testing.T, writer http.ResponseWriter) {
	t.Helper()
	encoded, err := generationstop.CanonicalJSON(specialistrender.Observation{
		Schema: specialistrender.ObservationSchema, Status: generationstop.ObservationAbsent,
	})
	if err != nil {
		t.Fatal(err)
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(encoded); err != nil {
		t.Error(err)
	}
}

func testProviderInput(t *testing.T, requestBytes, sourceBytes []byte) ProviderExecutionInput {
	t.Helper()
	request, _, _, err := ProviderRequest(ProviderExecutionInput{
		RequestBytes: requestBytes, SourceBytes: sourceBytes,
	})
	if err == nil || request.Schema != "" {
		t.Fatal("incomplete provider input unexpectedly admitted")
	}
	complete, _, _ := testProviderRequest(t)
	return ProviderExecutionInput{
		Workspace: complete.Source, OperationID: complete.OperationID,
		ArtifactRenderJobRef: complete.ArtifactRenderJobRef, Composition: complete.Composition,
		Owner: complete.Owner, Fence: complete.Fence, ExpectedParentGeneration: complete.ExpectedParentGeneration,
		Image: complete.Image, Interface: complete.Interface, Executor: complete.Executor,
		Executable: complete.Executable, ProviderPolicy: complete.ProviderPolicy,
		RequestBytes: requestBytes, SourceBytes: sourceBytes,
	}
}
