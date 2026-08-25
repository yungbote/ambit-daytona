// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

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
