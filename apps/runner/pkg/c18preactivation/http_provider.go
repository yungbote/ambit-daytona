// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

const specialistRenderMediaType = "application/vnd.ambit.runtime-provider-specialist-render+jsonl;version=1"

type HTTPProviderConfig struct {
	BaseURL        *url.URL
	Credential     string
	OrganizationID string
}

type HTTPProvider struct {
	config HTTPProviderConfig
	client *http.Client
}

// HTTPStatusError is deliberately value-blind. Provider response bodies are
// untrusted and are never reflected into driver stderr or the evaluation wire.
type HTTPStatusError struct {
	StatusCode int
}

func (err *HTTPStatusError) Error() string {
	return fmt.Sprintf("Daytona specialist-render request failed with status %d", err.StatusCode)
}

// NewHTTPProvider returns the concrete adapter for the existing Runner host
// API. Redirects are rejected so an authenticated request cannot silently move
// outside the configured authority.
func NewHTTPProvider(config HTTPProviderConfig, client *http.Client) (*HTTPProvider, error) {
	parsed, err := validateHTTPProviderConfig(config)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{}
	} else {
		copy := *client
		client = &copy
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &HTTPProvider{config: parsed, client: client}, nil
}

// HTTPProviderConfigFromEnvironment applies the same value-blind credential
// precedence and organization rule as the backend Daytona host adapter.
func HTTPProviderConfigFromEnvironment(getenv func(string) string) (HTTPProviderConfig, error) {
	if getenv == nil {
		return HTTPProviderConfig{}, errors.New("C18 Daytona environment reader is unavailable")
	}
	rawURL := exactEnvironmentValue(getenv("DAYTONA_API_URL"))
	apiKey := exactEnvironmentValue(getenv("DAYTONA_API_KEY"))
	jwt := exactEnvironmentValue(getenv("DAYTONA_JWT_TOKEN"))
	organizationID := exactEnvironmentValue(getenv("DAYTONA_ORGANIZATION_ID"))
	credential := apiKey
	if credential == "" {
		credential = jwt
	}
	if rawURL == "" || credential == "" || (apiKey == "" && organizationID == "") {
		return HTTPProviderConfig{}, errors.New("C18 Daytona host API transport is not configured")
	}
	if !strings.HasSuffix(rawURL, "/") {
		rawURL += "/"
	}
	baseURL, err := url.Parse(rawURL)
	if err != nil {
		return HTTPProviderConfig{}, errors.New("C18 Daytona host API URL is invalid")
	}
	return validateHTTPProviderConfig(HTTPProviderConfig{
		BaseURL: baseURL, Credential: credential, OrganizationID: organizationID,
	})
}

func (provider *HTTPProvider) Execute(
	ctx context.Context,
	input ProviderExecutionInput,
) (ProviderExecutionResult, error) {
	if provider == nil || provider.client == nil {
		return ProviderExecutionResult{}, errors.New("C18 Daytona provider is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return ProviderExecutionResult{}, err
	}
	requestAuthority, requestBytes, sourceBytes, err := ProviderRequest(input)
	if err != nil {
		return ProviderExecutionResult{}, err
	}
	reader, writer := io.Pipe()
	encoded := make(chan error, 1)
	go func() {
		err := EncodeProviderRequestStream(writer, requestAuthority, requestBytes, sourceBytes)
		_ = writer.CloseWithError(err)
		encoded <- err
	}()

	endpoint := provider.config.BaseURL.ResolveReference(&url.URL{
		Path: "sandbox/" + url.PathEscape(requestAuthority.Source.ProviderResourceID) + "/specialist-renders",
	})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), reader)
	if err != nil {
		_ = reader.CloseWithError(err)
		<-encoded
		return ProviderExecutionResult{}, fmt.Errorf("create C18 Daytona request: %w", err)
	}
	request.Header.Set("Accept", specialistRenderMediaType)
	request.Header.Set("Authorization", "Bearer "+provider.config.Credential)
	request.Header.Set("Content-Type", specialistRenderMediaType)
	request.Header.Set("X-Daytona-Source", "ambit-backend")
	if provider.config.OrganizationID != "" {
		request.Header.Set("X-Daytona-Organization-ID", provider.config.OrganizationID)
	}
	response, requestErr := provider.client.Do(request)
	encodeErr := <-encoded
	if requestErr != nil {
		return ProviderExecutionResult{}, fmt.Errorf("execute C18 Daytona request: %w", requestErr)
	}
	defer response.Body.Close()
	if encodeErr != nil {
		return ProviderExecutionResult{}, fmt.Errorf("encode C18 Daytona request: %w", encodeErr)
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusUnprocessableEntity {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024+1))
		return ProviderExecutionResult{}, &HTTPStatusError{StatusCode: response.StatusCode}
	}
	if response.Header.Get("Content-Type") != specialistRenderMediaType {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024+1))
		return ProviderExecutionResult{}, errors.New("C18 Daytona response media type is invalid")
	}
	result, err := DecodeProviderResponseStream(ctx, response.Body, requestAuthority)
	if err != nil {
		return ProviderExecutionResult{}, fmt.Errorf("decode C18 Daytona response: %w", err)
	}
	if (response.StatusCode == http.StatusOK) != (result.Receipt.Outcome == "succeeded") {
		return ProviderExecutionResult{}, errors.New("C18 Daytona status and receipt outcome disagree")
	}
	return result, nil
}

func validateHTTPProviderConfig(config HTTPProviderConfig) (HTTPProviderConfig, error) {
	if config.BaseURL == nil || exactEnvironmentValue(config.Credential) == "" ||
		(config.OrganizationID != "" && exactEnvironmentValue(config.OrganizationID) == "") {
		return HTTPProviderConfig{}, errors.New("C18 Daytona host API configuration is invalid")
	}
	baseURL := *config.BaseURL
	if (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.Host == "" ||
		baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return HTTPProviderConfig{}, errors.New("C18 Daytona host API URL is invalid")
	}
	if !strings.HasSuffix(baseURL.Path, "/") {
		baseURL.Path += "/"
	}
	return HTTPProviderConfig{
		BaseURL: &baseURL, Credential: config.Credential, OrganizationID: config.OrganizationID,
	}, nil
}

func exactEnvironmentValue(value string) string {
	if value == "" || len(value) > 4_096 || value != strings.TrimSpace(value) {
		return ""
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return ""
		}
	}
	return value
}
