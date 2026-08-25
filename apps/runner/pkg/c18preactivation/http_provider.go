// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

const specialistRenderMediaType = "application/vnd.ambit.runtime-provider-specialist-render+jsonl;version=1"
const defaultProviderSettlementTimeout = 30 * time.Second

type HTTPProviderConfig struct {
	BaseURL        *url.URL
	Credential     string
	OrganizationID string
}

type HTTPProvider struct {
	config            HTTPProviderConfig
	client            *http.Client
	settlementTimeout time.Duration
}

// HTTPStatusError is deliberately value-blind. Provider response bodies are
// untrusted and are never reflected into driver stderr or the evaluation wire.
type HTTPStatusError struct {
	StatusCode int
}

type ProviderSettlementError struct {
	Kind        string
	Observation *specialistrender.Observation
	Cause       error
}

func (err *ProviderSettlementError) Error() string {
	return "Daytona specialist-render settlement is " + err.Kind
}

func (err *ProviderSettlementError) Unwrap() error { return err.Cause }

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
	return &HTTPProvider{config: parsed, client: client, settlementTimeout: defaultProviderSettlementTimeout}, nil
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
	custody := newMemoryProviderResponseCustody()
	observation, err := provider.ExecuteToCustody(ctx, input, custody)
	if err != nil {
		return ProviderExecutionResult{}, err
	}
	files := make([]ProviderOutput, len(observation.Receipt.Files))
	for index, descriptor := range observation.Receipt.Files {
		files[index] = ProviderOutput{
			Descriptor: descriptor,
			Bytes:      custody.files[index].Bytes(),
		}
	}
	return ProviderExecutionResult{Receipt: observation.Receipt, Files: files}, nil
}

func (provider *HTTPProvider) ExecuteToCustody(
	ctx context.Context,
	input ProviderExecutionInput,
	custody ProviderResponseCustody,
) (_ ProviderResponseObservation, err error) {
	if custody == nil {
		custody = DiscardProviderResponseCustody()
	}
	guardedCustody := &guardedResponseCustody{delegate: custody}
	defer func() {
		cleanupCtx, cancel := providerResponseCleanupContext(ctx)
		defer cancel()
		if abortErr := guardedCustody.Abort(cleanupCtx); abortErr != nil {
			err = errors.Join(err, abortErr)
		}
	}()
	if provider == nil || provider.client == nil {
		return ProviderResponseObservation{}, errors.New("C18 Daytona provider is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return ProviderResponseObservation{}, err
	}
	requestAuthority, requestBytes, sourceBytes, err := ProviderRequest(input)
	if err != nil {
		return ProviderResponseObservation{}, err
	}
	reader, writer := io.Pipe()
	encoded := make(chan error, 1)
	go func() {
		err := EncodeProviderRequestStream(writer, requestAuthority, requestBytes, sourceBytes)
		_ = writer.CloseWithError(err)
		encoded <- err
	}()

	endpoint := provider.endpoint(requestAuthority.Source.ProviderResourceID, "specialist-renders")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), reader)
	if err != nil {
		_ = reader.CloseWithError(err)
		<-encoded
		return ProviderResponseObservation{}, fmt.Errorf("create C18 Daytona request: %w", err)
	}
	request.Header.Set("Accept", specialistRenderMediaType)
	request.Header.Set("Authorization", "Bearer "+provider.config.Credential)
	request.Header.Set("Content-Type", specialistRenderMediaType)
	request.Header.Set("X-Daytona-Source", "ambit-backend")
	if provider.config.OrganizationID != "" {
		request.Header.Set("X-Daytona-Organization-ID", provider.config.OrganizationID)
	}
	response, requestErr := provider.client.Do(request)
	if requestErr != nil {
		_ = reader.CloseWithError(requestErr)
	} else {
		_ = reader.Close()
	}
	encodeErr := <-encoded
	if requestErr != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return ProviderResponseObservation{}, provider.reconcile(ctx, requestAuthority, requestErr)
	}
	defer response.Body.Close()
	if encodeErr != nil {
		_ = response.Body.Close()
		return ProviderResponseObservation{}, provider.reconcile(ctx, requestAuthority, encodeErr)
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusUnprocessableEntity {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024+1))
		_ = response.Body.Close()
		return ProviderResponseObservation{}, provider.reconcile(
			ctx,
			requestAuthority,
			&HTTPStatusError{StatusCode: response.StatusCode},
		)
	}
	if response.Header.Get("Content-Type") != specialistRenderMediaType {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024+1))
		_ = response.Body.Close()
		return ProviderResponseObservation{}, provider.reconcile(
			ctx,
			requestAuthority,
			errors.New("C18 Daytona response media type is invalid"),
		)
	}
	statusCustody := &httpStatusResponseCustody{delegate: guardedCustody, statusCode: response.StatusCode}
	observation, err := ObserveProviderResponseStream(ctx, response.Body, requestAuthority, statusCustody)
	if err != nil {
		_ = response.Body.Close()
		return ProviderResponseObservation{}, provider.reconcile(ctx, requestAuthority, err)
	}
	return observation, nil
}

func (provider *HTTPProvider) reconcile(
	ctx context.Context,
	request specialistrender.Request,
	cause error,
) error {
	timeout := provider.settlementTimeout
	if timeout <= 0 {
		timeout = defaultProviderSettlementTimeout
	}
	settlementCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	observation, err := provider.observe(settlementCtx, request)
	if err != nil {
		return &ProviderSettlementError{Kind: "ambiguous", Cause: errors.Join(cause, err)}
	}
	switch observation.Status {
	case generationstop.ObservationAbsent:
		return &ProviderSettlementError{Kind: "not_admitted", Observation: &observation, Cause: cause}
	case generationstop.ObservationPartial:
		return &ProviderSettlementError{Kind: "partial", Observation: &observation, Cause: cause}
	case generationstop.ObservationComplete:
		return &ProviderSettlementError{Kind: "complete_output_unadmitted", Observation: &observation, Cause: cause}
	default:
		return &ProviderSettlementError{Kind: "ambiguous", Cause: cause}
	}
}

func (provider *HTTPProvider) observe(
	ctx context.Context,
	request specialistrender.Request,
) (specialistrender.Observation, error) {
	observeRequest := specialistrender.ObserveRequest{
		Schema: specialistrender.ObserveRequestSchema, OperationID: request.OperationID,
		RequestFingerprint: request.RequestFingerprint, Source: request.Source,
		Owner: request.Owner, Fence: request.Fence,
	}
	body, err := generationstop.CanonicalJSON(observeRequest)
	if err != nil {
		return specialistrender.Observation{}, err
	}
	httpRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		provider.endpoint(request.Source.ProviderResourceID, "specialist-renders/observe").String(),
		bytes.NewReader(body),
	)
	if err != nil {
		return specialistrender.Observation{}, err
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+provider.config.Credential)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("X-Daytona-Source", "ambit-backend")
	if provider.config.OrganizationID != "" {
		httpRequest.Header.Set("X-Daytona-Organization-ID", provider.config.OrganizationID)
	}
	response, err := provider.client.Do(httpRequest)
	if err != nil {
		return specialistrender.Observation{}, err
	}
	defer response.Body.Close()
	contentType := response.Header.Get("Content-Type")
	if response.StatusCode != http.StatusOK ||
		(contentType != "application/json; charset=utf-8" && contentType != "application/json") {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024+1))
		return specialistrender.Observation{}, errors.New("Daytona specialist-render observation failed")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
	if err != nil || len(encoded) == 0 || len(encoded) > 256*1024 {
		return specialistrender.Observation{}, errors.New("Daytona specialist-render observation exceeds its bound")
	}
	var observation specialistrender.Observation
	if err := generationstop.DecodeCanonicalJSON(encoded, &observation); err != nil {
		return specialistrender.Observation{}, fmt.Errorf("decode Daytona specialist-render observation: %w", err)
	}
	if observation.Schema != specialistrender.ObservationSchema ||
		(observation.Status != generationstop.ObservationAbsent &&
			observation.Status != generationstop.ObservationPartial &&
			observation.Status != generationstop.ObservationComplete) {
		return specialistrender.Observation{}, errors.New("Daytona specialist-render observation is invalid")
	}
	if observation.Status == generationstop.ObservationComplete {
		if observation.Receipt == nil || specialistrender.ValidateReceipt(*observation.Receipt) != nil ||
			!canonicalEqual(observation.Receipt.Request, request) {
			return specialistrender.Observation{}, errors.New("Daytona complete specialist-render observation is invalid")
		}
	} else if observation.Receipt != nil {
		return specialistrender.Observation{}, errors.New("Daytona incomplete specialist-render observation carried a receipt")
	}
	return observation, nil
}

func (provider *HTTPProvider) endpoint(providerResourceID, suffix string) *url.URL {
	return provider.config.BaseURL.ResolveReference(&url.URL{
		Path:    "sandbox/" + providerResourceID + "/" + suffix,
		RawPath: "sandbox/" + url.PathEscape(providerResourceID) + "/" + suffix,
	})
}

type guardedResponseCustody struct {
	delegate ProviderResponseCustody
	admitted bool
	settled  bool
}

func (custody *guardedResponseCustody) AdmitReceipt(
	ctx context.Context,
	receipt specialistrender.Receipt,
) error {
	if custody.admitted || custody.settled {
		return errors.New("C18 response custody receipt state is invalid")
	}
	if err := custody.delegate.AdmitReceipt(ctx, receipt); err != nil {
		return err
	}
	custody.admitted = true
	return nil
}

func (custody *guardedResponseCustody) OpenFile(
	ctx context.Context,
	descriptor specialistrender.OutputFile,
) (ProviderResponseFileWriter, error) {
	if !custody.admitted || custody.settled {
		return nil, errors.New("C18 response custody is already settled")
	}
	return custody.delegate.OpenFile(ctx, descriptor)
}

func (custody *guardedResponseCustody) Commit(
	ctx context.Context,
	observation ProviderResponseObservation,
) error {
	if !custody.admitted || custody.settled {
		return errors.New("C18 response custody is already settled")
	}
	if err := custody.delegate.Commit(ctx, observation); err != nil {
		return err
	}
	custody.settled = true
	return nil
}

type httpStatusResponseCustody struct {
	delegate   ProviderResponseCustody
	statusCode int
}

func (custody *httpStatusResponseCustody) AdmitReceipt(
	ctx context.Context,
	receipt specialistrender.Receipt,
) error {
	if (custody.statusCode == http.StatusOK) != (receipt.Outcome == "succeeded") {
		return errors.New("C18 Daytona status and receipt outcome disagree")
	}
	return custody.delegate.AdmitReceipt(ctx, receipt)
}

func (custody *httpStatusResponseCustody) OpenFile(
	ctx context.Context,
	descriptor specialistrender.OutputFile,
) (ProviderResponseFileWriter, error) {
	return custody.delegate.OpenFile(ctx, descriptor)
}

func (custody *httpStatusResponseCustody) Commit(
	ctx context.Context,
	observation ProviderResponseObservation,
) error {
	return custody.delegate.Commit(ctx, observation)
}

func (custody *httpStatusResponseCustody) Abort(ctx context.Context) error {
	return custody.delegate.Abort(ctx)
}

func (custody *guardedResponseCustody) Abort(ctx context.Context) error {
	if custody.settled {
		return nil
	}
	custody.settled = true
	return custody.delegate.Abort(ctx)
}

func validateHTTPProviderConfig(config HTTPProviderConfig) (HTTPProviderConfig, error) {
	if config.BaseURL == nil || exactEnvironmentValue(config.Credential) == "" ||
		(config.OrganizationID != "" && exactEnvironmentValue(config.OrganizationID) == "") {
		return HTTPProviderConfig{}, errors.New("C18 Daytona host API configuration is invalid")
	}
	baseURL := *config.BaseURL
	if (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.Host == "" ||
		baseURL.User != nil || baseURL.Opaque != "" || baseURL.RawPath != "" ||
		baseURL.RawQuery != "" || baseURL.ForceQuery || baseURL.Fragment != "" ||
		strings.Contains(baseURL.Path, `\`) {
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
