// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daytonaio/runner/pkg/c18preactivation"
	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
	"golang.org/x/sys/unix"
)

const specialistRenderContentType = "application/vnd.ambit.runtime-provider-specialist-render+jsonl;version=1"

type Collector struct {
	api     DaytonaAPIConfig
	client  *http.Client
	now     func() time.Time
	clockMu sync.Mutex
}

func NewCollector(api DaytonaAPIConfig, client *http.Client) (*Collector, error) {
	if api.BaseURL == nil || api.Credential == "" {
		return nil, fmt.Errorf("Daytona API configuration is incomplete")
	}
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DisableCompression = true
		client = &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Collector{api: api, client: client, now: time.Now}, nil
}

func (collector *Collector) Collect(ctx context.Context, run ProviderLiveRun) (ProviderLiveCollection, error) {
	if err := ValidateProviderLiveRun(run); err != nil {
		return ProviderLiveCollection{}, err
	}
	policyBytes, err := readPinnedFile(run.RunnerPolicy, 32*1024*1024)
	if err != nil {
		return ProviderLiveCollection{}, err
	}
	var policySet specialistrender.PolicySet
	if err := generationstop.DecodeCanonicalJSON(policyBytes, &policySet); err != nil ||
		policySet.Schema != specialistrender.PolicySetSchema || len(policySet.Policies) != 4 {
		return ProviderLiveCollection{}, fmt.Errorf("runner policy is not one exact canonical four-pack set")
	}
	registry, err := specialistrender.LoadPolicyRegistry(run.RunnerPolicy.Path)
	if err != nil {
		return ProviderLiveCollection{}, fmt.Errorf("load runner policy registry: %w", err)
	}
	policyBytesAfter, err := readPinnedFile(run.RunnerPolicy, 32*1024*1024)
	if err != nil || !bytes.Equal(policyBytes, policyBytesAfter) {
		return ProviderLiveCollection{}, fmt.Errorf("runner policy changed while loaded")
	}
	documents := make(map[string]specialistrender.PolicyDocument, 4)
	for _, policy := range policySet.Policies {
		if !knownPack(policy.Image.PackID) {
			return ProviderLiveCollection{}, fmt.Errorf("runner policy contains an unknown pack")
		}
		if _, duplicate := documents[policy.Image.PackID]; duplicate {
			return ProviderLiveCollection{}, fmt.Errorf("runner policy pack is duplicated")
		}
		documents[policy.Image.PackID] = policy
	}

	observedFrom := formatObservationTime(collector.observedNow())
	receipts := make([]ProviderReceiptRow, 0, len(run.Executions))
	for _, execution := range run.Executions {
		if execution.Mode != "cancel" {
			continue
		}
		prepared, err := collector.prepareExecution(ctx, run, execution, documents, registry)
		if err != nil {
			return ProviderLiveCollection{}, fmt.Errorf("prepare %s %s: %w", execution.Facet, execution.Mode, err)
		}
		result, err := collector.executeCancellation(
			ctx,
			run,
			prepared.request,
			prepared.policy,
			prepared.requestBytes,
			prepared.sourceBytes,
		)
		if err != nil {
			return ProviderLiveCollection{}, fmt.Errorf("collect %s %s: %w", execution.Facet, execution.Mode, err)
		}
		receipts = append(receipts, ProviderReceiptRow{
			Facet:   execution.Facet,
			Mode:    execution.Mode,
			Receipt: result.receipt,
		})
	}

	successes := make([]preparedProviderExecution, 0, providerSuccessConcurrency)
	for _, execution := range run.Executions {
		if execution.Mode != "success" {
			continue
		}
		prepared, err := collector.prepareExecution(ctx, run, execution, documents, registry)
		if err != nil {
			return ProviderLiveCollection{}, fmt.Errorf("prepare %s %s: %w", execution.Facet, execution.Mode, err)
		}
		successes = append(successes, prepared)
	}
	successReceipts, streamCases, concurrentLoad, err := collector.collectConcurrentSuccesses(ctx, run, successes)
	if err != nil {
		return ProviderLiveCollection{}, err
	}
	receipts = append(receipts, successReceipts...)
	sort.Slice(receipts, func(left, right int) bool {
		return receipts[left].Facet+"\x00"+receipts[left].Mode < receipts[right].Facet+"\x00"+receipts[right].Mode
	})
	observedUntil := formatObservationTime(collector.observedNow())
	return SealProviderLiveCollection(ProviderLiveCollection{
		SourceRevision: run.SourceRevision, SourceTree: run.SourceTree, SourceSetDigest: run.SourceSetDigest,
		RunnerPolicy:     RunnerPolicyPin{CanonicalJSON: string(policyBytes), ContentSHA256: digestBytes(policyBytes)},
		ProviderReceipts: receipts,
		AuthenticatedStreaming: AuthenticatedStreamingObservation{
			Outcome: "passed", ObservedFrom: observedFrom, ObservedUntil: observedUntil, Cases: streamCases,
		},
		ConcurrentLoad: concurrentLoad,
	})
}

type preparedProviderExecution struct {
	execution    ProviderLiveExecution
	request      specialistrender.Request
	policy       specialistrender.Policy
	requestBytes []byte
	sourceBytes  []byte
}

func (collector *Collector) prepareExecution(
	ctx context.Context,
	run ProviderLiveRun,
	execution ProviderLiveExecution,
	documents map[string]specialistrender.PolicyDocument,
	registry specialistrender.PolicyRegistry,
) (preparedProviderExecution, error) {
	if err := ctx.Err(); err != nil {
		return preparedProviderExecution{}, err
	}
	requestBytes, err := readPinnedFile(execution.Request, specialistrender.MaximumRequestBytes)
	if err != nil {
		return preparedProviderExecution{}, err
	}
	var canonicalRequest json.RawMessage
	if err := generationstop.DecodeCanonicalJSON(requestBytes, &canonicalRequest); err != nil {
		return preparedProviderExecution{}, fmt.Errorf("command is not canonical JSON: %w", err)
	}
	sourceBytes, err := readPinnedFile(execution.Source, specialistrender.MaximumSourceBytes)
	if err != nil {
		return preparedProviderExecution{}, err
	}
	command, err := c18preactivation.ParseRenderCommandV2(requestBytes, sourceBytes)
	if err != nil {
		return preparedProviderExecution{}, fmt.Errorf("command and source authority are invalid: %w", err)
	}
	deadline, deadlineErr := time.Parse(observationTimeLayout, command.DeadlineAt)
	observedAt, observedErr := time.Parse(observationTimeLayout, run.Target.ObservedAt)
	if deadlineErr != nil || observedErr != nil ||
		!deadline.Equal(observedAt.Add(4*time.Hour)) ||
		!collector.observedNow().Before(deadline) ||
		command.Facet != execution.Facet ||
		command.JobRef != execution.ArtifactRenderJobRef ||
		command.Runtime.WorkspaceExecutionManifest != run.Target.WorkspaceExecutionManifest {
		return preparedProviderExecution{}, fmt.Errorf("command differs from the issued live-run authority")
	}
	generation, err := collector.observeCurrent(ctx, run, run.Timeouts.ObservationSeconds)
	if err != nil {
		return preparedProviderExecution{}, fmt.Errorf("observe current parent: %w", err)
	}
	policyDocument, exists := documents[facetPacks[execution.Facet]]
	if !exists {
		return preparedProviderExecution{}, fmt.Errorf("runner policy does not cover facet %s", execution.Facet)
	}
	request, err := specialistRequest(run, execution, policyDocument, generation, requestBytes, sourceBytes)
	if err != nil {
		return preparedProviderExecution{}, fmt.Errorf("construct provider request: %w", err)
	}
	if err := specialistrender.ValidateRequest(request); err != nil {
		return preparedProviderExecution{}, fmt.Errorf("constructed provider request is invalid: %w", err)
	}
	policy, err := registry.Resolve(request)
	if err != nil {
		return preparedProviderExecution{}, fmt.Errorf("provider request is not admitted by the runner policy: %w", err)
	}
	return preparedProviderExecution{
		execution: execution, request: request, policy: policy,
		requestBytes: requestBytes, sourceBytes: sourceBytes,
	}, nil
}

type concurrentSuccessResult struct {
	facet   string
	receipt ProviderReceiptRow
	stream  AuthenticatedStreamingCase
	load    ConcurrentLoadCase
	err     error
}

func (collector *Collector) collectConcurrentSuccesses(
	ctx context.Context,
	run ProviderLiveRun,
	executions []preparedProviderExecution,
) ([]ProviderReceiptRow, []AuthenticatedStreamingCase, ConcurrentLoadObservation, error) {
	if len(executions) != providerSuccessConcurrency {
		return nil, nil, ConcurrentLoadObservation{}, fmt.Errorf("concurrent provider load requires exactly six prepared successes")
	}

	results := make(chan concurrentSuccessResult, providerSuccessConcurrency)
	startMeasurement := make(chan struct{})
	startExecution := make(chan struct{})
	var measured sync.WaitGroup
	measured.Add(providerSuccessConcurrency)
	var loadCtx context.Context

	for _, prepared := range executions {
		prepared := prepared
		go func() {
			<-startMeasurement
			measured.Done()
			<-startExecution
			observation, err := collector.executeSuccess(
				loadCtx,
				run,
				prepared.request,
				prepared.policy,
				prepared.requestBytes,
				prepared.sourceBytes,
			)
			result := concurrentSuccessResult{facet: prepared.execution.Facet, err: err}
			if err == nil {
				startedAt, startErr := parseObservationTime(observation.receipt.StartedAt)
				completedAt, completionErr := parseObservationTime(observation.receipt.CompletedAt)
				if startErr != nil || completionErr != nil || !startedAt.Before(completedAt) {
					result.err = fmt.Errorf("provider success receipt interval is invalid")
					results <- result
					return
				}
				result.receipt = ProviderReceiptRow{
					Facet:   prepared.execution.Facet,
					Mode:    prepared.execution.Mode,
					Receipt: observation.receipt,
				}
				result.stream = AuthenticatedStreamingCase{
					Facet: prepared.execution.Facet, OperationID: prepared.execution.OperationID,
					HTTPStatus: 200, Authenticated: true,
					RequestStreamSHA256:  observation.requestStreamSHA256,
					ResponseStreamSHA256: observation.responseStreamSHA256,
					ReceiptDigest:        observation.receipt.ReceiptDigest,
				}
				result.load = ConcurrentLoadCase{
					Facet:     prepared.execution.Facet,
					StartedAt: formatObservationTime(startedAt), CompletedAt: formatObservationTime(completedAt),
					DurationMilliseconds: completedAt.Sub(startedAt).Milliseconds(),
					ReceiptDigest:        observation.receipt.ReceiptDigest,
				}
			}
			results <- result
		}()
	}

	close(startMeasurement)
	measured.Wait()
	var cancel context.CancelFunc
	loadCtx, cancel = context.WithTimeout(ctx, time.Duration(run.Timeouts.ExecuteSeconds)*time.Second)
	defer cancel()
	close(startExecution)

	completed := make([]concurrentSuccessResult, 0, providerSuccessConcurrency)
	for range executions {
		completed = append(completed, <-results)
	}
	sort.Slice(completed, func(left, right int) bool { return completed[left].facet < completed[right].facet })
	errorsByFacet := make([]error, 0)
	for _, result := range completed {
		if result.err != nil {
			errorsByFacet = append(errorsByFacet, fmt.Errorf("collect %s success: %w", result.facet, result.err))
		}
	}
	if len(errorsByFacet) > 0 {
		return nil, nil, ConcurrentLoadObservation{}, errors.Join(errorsByFacet...)
	}

	receipts := make([]ProviderReceiptRow, 0, providerSuccessConcurrency)
	streams := make([]AuthenticatedStreamingCase, 0, providerSuccessConcurrency)
	loadCases := make([]ConcurrentLoadCase, 0, providerSuccessConcurrency)
	for _, result := range completed {
		receipts = append(receipts, result.receipt)
		streams = append(streams, result.stream)
		loadCases = append(loadCases, result.load)
	}
	return receipts, streams, ConcurrentLoadObservation{
		PredeclaredConcurrency:      providerSuccessConcurrency,
		MaximumDurationMilliseconds: int64(providerExecuteSeconds) * 1000,
		AllSucceeded:                true,
		Outcome:                     "passed",
		Cases:                       loadCases,
	}, nil
}

func (collector *Collector) observedNow() time.Time {
	collector.clockMu.Lock()
	defer collector.clockMu.Unlock()
	return collector.now().UTC().Truncate(time.Millisecond)
}

type executionObservation struct {
	receipt              specialistrender.Receipt
	requestStreamSHA256  string
	responseStreamSHA256 string
}

func (collector *Collector) executeSuccess(
	ctx context.Context,
	run ProviderLiveRun,
	request specialistrender.Request,
	policy specialistrender.Policy,
	requestBytes []byte,
	sourceBytes []byte,
) (executionObservation, error) {
	executeCtx, cancel := context.WithTimeout(ctx, time.Duration(run.Timeouts.ExecuteSeconds)*time.Second)
	defer cancel()
	response, requestDigest, err := collector.execute(executeCtx, request, requestBytes, sourceBytes)
	if err != nil {
		return executionObservation{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != specialistRenderContentType {
		discard(response.Body, 64*1024)
		return executionObservation{}, fmt.Errorf("authenticated provider success returned an invalid status or content type")
	}
	receipt, responseDigest, err := decodeResponseStream(executeCtx, response.Body, request, policy)
	if err != nil {
		return executionObservation{}, err
	}
	if receipt.Outcome != "succeeded" {
		return executionObservation{}, fmt.Errorf("provider success did not produce a succeeded receipt")
	}
	return executionObservation{receipt: receipt, requestStreamSHA256: requestDigest, responseStreamSHA256: responseDigest}, nil
}

func (collector *Collector) executeCancellation(
	ctx context.Context,
	run ProviderLiveRun,
	request specialistrender.Request,
	policy specialistrender.Policy,
	requestBytes []byte,
	sourceBytes []byte,
) (executionObservation, error) {
	executeCtx, cancelExecute := context.WithTimeout(ctx, time.Duration(run.Timeouts.ExecuteSeconds)*time.Second)
	defer cancelExecute()
	type executeResult struct {
		response *http.Response
		digest   string
		err      error
	}
	result := make(chan executeResult, 1)
	go func() {
		response, digest, err := collector.execute(executeCtx, request, requestBytes, sourceBytes)
		result <- executeResult{response: response, digest: digest, err: err}
	}()

	observationCtx, cancelObservation := context.WithTimeout(ctx, time.Duration(run.Timeouts.ObservationSeconds)*time.Second)
	defer cancelObservation()
	var early *executeResult
	for {
		select {
		case completed := <-result:
			early = &completed
		case <-time.After(time.Duration(run.Timeouts.PollMilliseconds) * time.Millisecond):
			observation, err := collector.observeRender(observationCtx, request)
			if err != nil {
				return executionObservation{}, err
			}
			switch observation.Status {
			case "absent":
				continue
			case "partial":
				if delay := run.Timeouts.CancelAfterPartialMilliseconds; delay > 0 {
					select {
					case <-time.After(time.Duration(delay) * time.Millisecond):
					case <-observationCtx.Done():
						return executionObservation{}, observationCtx.Err()
					}
				}
				cancelExecute()
				goto cancelled
			case "complete":
				if observation.Receipt == nil {
					return executionObservation{}, fmt.Errorf("complete cancellation observation has no receipt")
				}
				if err := specialistrender.ValidateReceiptWithPolicy(*observation.Receipt, policy); err != nil {
					return executionObservation{}, err
				}
				if observation.Receipt.Outcome != "cancelled" {
					return executionObservation{}, fmt.Errorf("cancellation operation completed before cancellation")
				}
				cancelExecute()
				return executionObservation{receipt: *observation.Receipt}, nil
			default:
				return executionObservation{}, fmt.Errorf("provider cancellation observation status is invalid")
			}
		case <-observationCtx.Done():
			return executionObservation{}, observationCtx.Err()
		}
		if early != nil {
			break
		}
	}
	if early.response != nil {
		defer early.response.Body.Close()
		if early.response.StatusCode == http.StatusUnprocessableEntity &&
			early.response.Header.Get("Content-Type") == specialistRenderContentType {
			receipt, _, decodeErr := decodeResponseStream(observationCtx, early.response.Body, request, policy)
			if decodeErr == nil && receipt.Outcome == "cancelled" {
				return executionObservation{receipt: receipt}, nil
			}
		}
	}
	return executionObservation{}, fmt.Errorf("cancellation execution settled before an admitted partial operation")

cancelled:
	select {
	case completed := <-result:
		if completed.response != nil {
			_ = completed.response.Body.Close()
		}
	case <-time.After(15 * time.Second):
		return executionObservation{}, fmt.Errorf("cancelled authenticated request transport did not settle")
	}
	for {
		observation, err := collector.observeRender(observationCtx, request)
		if err != nil {
			return executionObservation{}, err
		}
		if observation.Status == "complete" {
			if observation.Receipt == nil {
				return executionObservation{}, fmt.Errorf("complete cancellation observation has no receipt")
			}
			if err := specialistrender.ValidateReceiptWithPolicy(*observation.Receipt, policy); err != nil {
				return executionObservation{}, err
			}
			if observation.Receipt.Outcome != "cancelled" || len(observation.Receipt.Files) != 0 ||
				observation.Receipt.TotalOutputBytes != 0 || !observation.Receipt.Quiescence.ContainerAbsent {
				return executionObservation{}, fmt.Errorf("provider cancellation receipt is not exactly quiescent and empty")
			}
			return executionObservation{receipt: *observation.Receipt}, nil
		}
		select {
		case <-time.After(time.Duration(run.Timeouts.PollMilliseconds) * time.Millisecond):
		case <-observationCtx.Done():
			return executionObservation{}, observationCtx.Err()
		}
	}
}

func (collector *Collector) execute(
	ctx context.Context,
	request specialistrender.Request,
	requestBytes []byte,
	sourceBytes []byte,
) (*http.Response, string, error) {
	body, digestResult := requestStream(ctx, request, requestBytes, sourceBytes)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, collector.endpoint(request.Source.ProviderResourceID, "specialist-renders"), body)
	if err != nil {
		return nil, "", fmt.Errorf("construct provider request: %w", err)
	}
	collector.headers(httpRequest, specialistRenderContentType, specialistRenderContentType)
	response, requestErr := collector.client.Do(httpRequest)
	digest := <-digestResult
	if requestErr != nil {
		return nil, digest.digest, requestErr
	}
	if digest.err != nil {
		_ = response.Body.Close()
		return nil, "", digest.err
	}
	return response, digest.digest, nil
}

func (collector *Collector) observeCurrent(ctx context.Context, run ProviderLiveRun, timeoutSeconds int) (generationstop.ExpectedGeneration, error) {
	request := generationstop.ProviderGenerationObservationRequest{
		Source: run.Target.Source, Owner: run.Target.Owner, Fence: run.Target.Fence,
	}
	var observation generationstop.ProviderGenerationObservation
	if err := collector.postJSON(ctx, timeoutSeconds, run.Target.Source.ProviderResourceID, "generation/observe-current", request, &observation); err != nil {
		return generationstop.ExpectedGeneration{}, err
	}
	if observation.Source != request.Source || observation.Owner != request.Owner || observation.Fence != request.Fence ||
		observation.State != "running" || observation.Generation != run.Target.ExpectedGeneration {
		return generationstop.ExpectedGeneration{}, fmt.Errorf("current generation observation differs from the target authority")
	}
	return observation.Generation, nil
}

func (collector *Collector) observeRender(ctx context.Context, request specialistrender.Request) (specialistrender.Observation, error) {
	observe := specialistrender.ObserveRequest{
		Schema: specialistrender.ObserveRequestSchema, OperationID: request.OperationID,
		RequestFingerprint: request.RequestFingerprint, Source: request.Source,
		Owner: request.Owner, Fence: request.Fence,
	}
	var observation specialistrender.Observation
	if err := collector.postJSON(ctx, 30, request.Source.ProviderResourceID, "specialist-renders/observe", observe, &observation); err != nil {
		return specialistrender.Observation{}, err
	}
	if observation.Schema != specialistrender.ObservationSchema ||
		(observation.Status != "absent" && observation.Status != "partial" && observation.Status != "complete") {
		return specialistrender.Observation{}, fmt.Errorf("provider observation schema or status is invalid")
	}
	if observation.Status == "complete" {
		if observation.Receipt == nil || observation.Receipt.Request != request {
			return specialistrender.Observation{}, fmt.Errorf("provider observation receipt differs from the exact request")
		}
	} else if observation.Receipt != nil {
		return specialistrender.Observation{}, fmt.Errorf("incomplete provider observation contains a receipt")
	}
	return observation, nil
}

func (collector *Collector) postJSON(ctx context.Context, timeoutSeconds int, providerResourceID, path string, value, target any) error {
	encoded, err := generationstop.CanonicalJSON(value)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, collector.endpoint(providerResourceID, path), bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	collector.headers(request, "application/json", "application/json")
	response, err := collector.client.Do(request)
	if err != nil {
		return fmt.Errorf("authenticated Daytona control request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		discard(response.Body, 64*1024)
		return fmt.Errorf("authenticated Daytona control request returned status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
	if err != nil || len(data) == 0 || len(data) > 256*1024 {
		return fmt.Errorf("Daytona control response is absent or exceeds its bound")
	}
	if err := generationstop.DecodeExactJSON(data, target); err != nil {
		return fmt.Errorf("Daytona control response is not exact JSON: %w", err)
	}
	return nil
}

func (collector *Collector) endpoint(providerResourceID, suffix string) string {
	return collector.api.BaseURL.String() + "sandbox/" + url.PathEscape(providerResourceID) + "/" + suffix
}

func (collector *Collector) headers(request *http.Request, accept, contentType string) {
	request.Header.Set("Accept", accept)
	request.Header.Set("Authorization", "Bearer "+collector.api.Credential)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("X-Daytona-Source", "ambit-c18-provider-integration")
	if collector.api.OrganizationID != "" {
		request.Header.Set("X-Daytona-Organization-ID", collector.api.OrganizationID)
	}
}

func specialistRequest(
	run ProviderLiveRun,
	execution ProviderLiveExecution,
	policy specialistrender.PolicyDocument,
	generation generationstop.ExpectedGeneration,
	requestBytes, sourceBytes []byte,
) (specialistrender.Request, error) {
	request, _, _, err := c18preactivation.ProviderRequest(c18preactivation.ProviderExecutionInput{
		Workspace: run.Target.Source, OperationID: execution.OperationID,
		ArtifactRenderJobRef: execution.ArtifactRenderJobRef, Composition: policy.Composition,
		Owner: run.Target.Owner, Fence: run.Target.Fence, ExpectedParentGeneration: generation,
		Image: policy.Image, Interface: policy.Interface, Executor: policy.Executor,
		Executable: policy.Executable, ProviderPolicy: policy.Authority,
		RequestBytes: requestBytes, SourceBytes: sourceBytes,
	})
	return request, err
}

type requestDigestResult struct {
	digest string
	err    error
}

func requestStream(ctx context.Context, request specialistrender.Request, requestBytes, sourceBytes []byte) (io.ReadCloser, <-chan requestDigestResult) {
	reader, writer := io.Pipe()
	result := make(chan requestDigestResult, 1)
	go func() {
		digest := sha256.New()
		err := encodeRequestStream(ctx, io.MultiWriter(writer, digest), request, requestBytes, sourceBytes)
		_ = writer.CloseWithError(err)
		result <- requestDigestResult{digest: hashDigest(digest), err: err}
	}()
	return reader, result
}

func encodeRequestStream(ctx context.Context, writer io.Writer, request specialistrender.Request, requestBytes, sourceBytes []byte) error {
	return c18preactivation.EncodeProviderRequestStream(
		&contextWriter{ctx: ctx, writer: writer}, request, requestBytes, sourceBytes,
	)
}

type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (writer *contextWriter) Write(value []byte) (int, error) {
	if err := writer.ctx.Err(); err != nil {
		return 0, err
	}
	return writer.writer.Write(value)
}

func decodeResponseStream(
	ctx context.Context,
	reader io.ReadCloser,
	request specialistrender.Request,
	policy specialistrender.Policy,
) (specialistrender.Receipt, string, error) {
	observation, err := c18preactivation.ObserveProviderResponseStream(
		ctx, reader, request, c18preactivation.DiscardProviderResponseCustody(),
	)
	if err != nil {
		return specialistrender.Receipt{}, "", err
	}
	if err := specialistrender.ValidateReceiptWithPolicy(observation.Receipt, policy); err != nil {
		return specialistrender.Receipt{}, "", fmt.Errorf("provider receipt differs from runner policy: %w", err)
	}
	return observation.Receipt, observation.WireSHA256, nil
}

func readPinnedFile(pin PinnedInputFile, maximum int64) ([]byte, error) {
	if err := validatePinnedInput(pin, maximum, "input file"); err != nil {
		return nil, err
	}
	descriptor, err := unix.Open(pin.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open pinned input file: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), pin.Path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("open pinned input file descriptor")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != pin.ByteLength || before.Size() > maximum {
		return nil, fmt.Errorf("pinned input file metadata differs")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != pin.ByteLength || digestBytes(data) != pin.SHA256 {
		return nil, fmt.Errorf("pinned input file bytes differ")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("pinned input file changed while read")
	}
	return data, nil
}

func hashDigest(value hash.Hash) string {
	return "sha256:" + hex.EncodeToString(value.Sum(nil))
}

func formatObservationTime(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format(observationTimeLayout)
}

func discard(reader io.Reader, maximum int64) {
	_, _ = io.Copy(io.Discard, io.LimitReader(reader, maximum))
}
