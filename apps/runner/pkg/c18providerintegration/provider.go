// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
	"golang.org/x/sys/unix"
)

const specialistRenderContentType = "application/vnd.ambit.runtime-provider-specialist-render+jsonl;version=1"

type Collector struct {
	api    DaytonaAPIConfig
	client *http.Client
	now    func() time.Time
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

	observedFrom := formatObservationTime(collector.now())
	receipts := make([]ProviderReceiptRow, 0, len(run.Executions))
	streamCases := make([]AuthenticatedStreamingCase, 0, 6)
	for _, execution := range run.Executions {
		if err := ctx.Err(); err != nil {
			return ProviderLiveCollection{}, err
		}
		requestBytes, err := readPinnedFile(execution.Request, specialistrender.MaximumRequestBytes)
		if err != nil {
			return ProviderLiveCollection{}, err
		}
		var canonicalRequest json.RawMessage
		if err := generationstop.DecodeCanonicalJSON(requestBytes, &canonicalRequest); err != nil {
			return ProviderLiveCollection{}, fmt.Errorf("%s %s command is not canonical JSON: %w", execution.Facet, execution.Mode, err)
		}
		sourceBytes, err := readPinnedFile(execution.Source, specialistrender.MaximumSourceBytes)
		if err != nil {
			return ProviderLiveCollection{}, err
		}
		generation, err := collector.observeCurrent(ctx, run, run.Timeouts.ObservationSeconds)
		if err != nil {
			return ProviderLiveCollection{}, fmt.Errorf("observe current parent before %s %s: %w", execution.Facet, execution.Mode, err)
		}
		policyDocument, exists := documents[facetPacks[execution.Facet]]
		if !exists {
			return ProviderLiveCollection{}, fmt.Errorf("runner policy does not cover facet %s", execution.Facet)
		}
		request, err := specialistRequest(run, execution, policyDocument, generation, requestBytes, sourceBytes)
		if err != nil {
			return ProviderLiveCollection{}, fmt.Errorf("construct provider request: %w", err)
		}
		if err := specialistrender.ValidateRequest(request); err != nil {
			return ProviderLiveCollection{}, fmt.Errorf("constructed provider request is invalid: %w", err)
		}
		policy, err := registry.Resolve(request)
		if err != nil {
			return ProviderLiveCollection{}, fmt.Errorf("provider request is not admitted by the runner policy: %w", err)
		}

		var result executionObservation
		if execution.Mode == "success" {
			result, err = collector.executeSuccess(ctx, run, request, policy, requestBytes, sourceBytes)
		} else {
			result, err = collector.executeCancellation(ctx, run, request, policy, requestBytes, sourceBytes)
		}
		if err != nil {
			return ProviderLiveCollection{}, fmt.Errorf("collect %s %s: %w", execution.Facet, execution.Mode, err)
		}
		receipts = append(receipts, ProviderReceiptRow{Facet: execution.Facet, Mode: execution.Mode, Receipt: result.receipt})
		if execution.Mode == "success" {
			streamCases = append(streamCases, AuthenticatedStreamingCase{
				Facet: execution.Facet, OperationID: execution.OperationID,
				HTTPStatus: 200, Authenticated: true,
				RequestStreamSHA256:  result.requestStreamSHA256,
				ResponseStreamSHA256: result.responseStreamSHA256,
				ReceiptDigest:        result.receipt.ReceiptDigest,
			})
		}
	}
	sort.Slice(receipts, func(left, right int) bool {
		return receipts[left].Facet+"\x00"+receipts[left].Mode < receipts[right].Facet+"\x00"+receipts[right].Mode
	})
	sort.Slice(streamCases, func(left, right int) bool { return streamCases[left].Facet < streamCases[right].Facet })
	observedUntil := formatObservationTime(collector.now())
	return SealProviderLiveCollection(ProviderLiveCollection{
		SourceRevision: run.SourceRevision, SourceTree: run.SourceTree, SourceSetDigest: run.SourceSetDigest,
		RunnerPolicy:     RunnerPolicyPin{CanonicalJSON: string(policyBytes), ContentSHA256: digestBytes(policyBytes)},
		ProviderReceipts: receipts,
		AuthenticatedStreaming: AuthenticatedStreamingObservation{
			Outcome: "passed", ObservedFrom: observedFrom, ObservedUntil: observedUntil, Cases: streamCases,
		},
	})
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
	receipt, responseDigest, err := decodeResponseStream(response.Body, request, policy)
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
			receipt, _, decodeErr := decodeResponseStream(early.response.Body, request, policy)
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
		observation.State != "running" {
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
	request := specialistrender.Request{
		Schema: specialistrender.RequestSchema, OperationID: execution.OperationID,
		ArtifactRenderJobRef: execution.ArtifactRenderJobRef,
		Composition:          policy.Composition, Source: run.Target.Source, Owner: run.Target.Owner,
		Fence: run.Target.Fence, ExpectedParentGeneration: generation,
		Image: policy.Image, Interface: policy.Interface, Executor: policy.Executor,
		Executable: policy.Executable, ProviderPolicy: policy.Authority,
		RequestBytes: int64(len(requestBytes)), RequestChunkCount: chunkCount(len(requestBytes)),
		RequestDigest: digestBytes(requestBytes), SourceBytes: int64(len(sourceBytes)),
		SourceChunkCount: chunkCount(len(sourceBytes)), SourceDigest: digestBytes(sourceBytes),
	}
	fingerprint, err := specialistrender.ComputeRequestFingerprint(request)
	if err != nil {
		return specialistrender.Request{}, err
	}
	request.RequestFingerprint = fingerprint
	return request, nil
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

type providerRequestStart struct {
	Schema     string                   `json:"schema"`
	Kind       string                   `json:"kind"`
	ChunkBytes int                      `json:"chunkBytes"`
	Request    specialistrender.Request `json:"request"`
}

type providerChunk struct {
	Schema      string `json:"schema"`
	Kind        string `json:"kind"`
	OperationID string `json:"operationId"`
	Index       int    `json:"index"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
	Base64      string `json:"base64"`
}

type providerRequestEnd struct {
	Schema            string `json:"schema"`
	Kind              string `json:"kind"`
	OperationID       string `json:"operationId"`
	RequestBytes      int64  `json:"requestBytes"`
	RequestChunkCount int    `json:"requestChunkCount"`
	RequestSHA256     string `json:"requestSha256"`
	SourceBytes       int64  `json:"sourceBytes"`
	SourceChunkCount  int    `json:"sourceChunkCount"`
	SourceSHA256      string `json:"sourceSha256"`
	FrameCount        int    `json:"frameCount"`
	StreamSHA256      string `json:"streamSha256"`
}

func encodeRequestStream(ctx context.Context, writer io.Writer, request specialistrender.Request, requestBytes, sourceBytes []byte) error {
	protocolHash := sha256.New()
	frameCount := 0
	write := func(value any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := generationstop.CanonicalJSON(value)
		if err != nil || len(line)+1 > specialistrender.MaximumFrameBytes {
			return fmt.Errorf("provider request frame is invalid")
		}
		framed := append(line, '\n')
		if _, err := writer.Write(framed); err != nil {
			return err
		}
		_, _ = protocolHash.Write(framed)
		frameCount++
		return nil
	}
	if err := write(providerRequestStart{Schema: specialistrender.ProviderFrameSchema, Kind: "provider_request_start", ChunkBytes: specialistrender.RequestChunkBytes, Request: request}); err != nil {
		return err
	}
	for _, item := range []struct {
		kind  string
		bytes []byte
	}{{"request_chunk", requestBytes}, {"source_chunk", sourceBytes}} {
		for index, offset := 0, 0; offset < len(item.bytes); index, offset = index+1, offset+specialistrender.RequestChunkBytes {
			end := offset + specialistrender.RequestChunkBytes
			if end > len(item.bytes) {
				end = len(item.bytes)
			}
			chunk := item.bytes[offset:end]
			if err := write(providerChunk{
				Schema: specialistrender.ProviderFrameSchema, Kind: item.kind,
				OperationID: request.OperationID, Index: index, Bytes: len(chunk),
				SHA256: digestBytes(chunk), Base64: base64.StdEncoding.EncodeToString(chunk),
			}); err != nil {
				return err
			}
		}
	}
	end := providerRequestEnd{
		Schema: specialistrender.ProviderFrameSchema, Kind: "provider_request_end", OperationID: request.OperationID,
		RequestBytes: request.RequestBytes, RequestChunkCount: request.RequestChunkCount, RequestSHA256: request.RequestDigest,
		SourceBytes: request.SourceBytes, SourceChunkCount: request.SourceChunkCount, SourceSHA256: request.SourceDigest,
		FrameCount: frameCount, StreamSHA256: hashDigest(protocolHash),
	}
	line, err := generationstop.CanonicalJSON(end)
	if err != nil || len(line)+1 > specialistrender.MaximumFrameBytes {
		return fmt.Errorf("provider request end is invalid")
	}
	_, err = writer.Write(append(line, '\n'))
	return err
}

type providerResponseStart struct {
	Schema     string                   `json:"schema"`
	Kind       string                   `json:"kind"`
	ChunkBytes int                      `json:"chunkBytes"`
	Receipt    specialistrender.Receipt `json:"receipt"`
}

type providerFileChunk struct {
	Schema      string `json:"schema"`
	Kind        string `json:"kind"`
	OperationID string `json:"operationId"`
	Ordinal     int    `json:"ordinal"`
	Index       int    `json:"index"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
	Base64      string `json:"base64"`
}

type providerResponseEnd struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	OperationID   string `json:"operationId"`
	ReceiptDigest string `json:"receiptDigest"`
	FileCount     int    `json:"fileCount"`
	TotalBytes    int64  `json:"totalBytes"`
	FrameCount    int    `json:"frameCount"`
	StreamSHA256  string `json:"streamSha256"`
}

type frameKind struct {
	Kind string `json:"kind"`
}

func decodeResponseStream(reader io.Reader, request specialistrender.Request, policy specialistrender.Policy) (specialistrender.Receipt, string, error) {
	lines := bufio.NewReaderSize(reader, specialistrender.MaximumFrameBytes+1)
	protocolHash := sha256.New()
	wholeHash := sha256.New()
	frameCount := 0
	line, framed, err := readCanonicalLine(lines)
	if err != nil {
		return specialistrender.Receipt{}, "", err
	}
	var start providerResponseStart
	if err := generationstop.DecodeCanonicalJSON(line, &start); err != nil ||
		start.Schema != specialistrender.ProviderFrameSchema || start.Kind != "provider_response_start" ||
		start.ChunkBytes != specialistrender.RequestChunkBytes || start.Receipt.Request != request {
		return specialistrender.Receipt{}, "", fmt.Errorf("provider response start is invalid")
	}
	if err := specialistrender.ValidateReceiptWithPolicy(start.Receipt, policy); err != nil {
		return specialistrender.Receipt{}, "", fmt.Errorf("provider receipt is invalid: %w", err)
	}
	_, _ = protocolHash.Write(framed)
	_, _ = wholeHash.Write(framed)
	frameCount++
	fileHashes := make([]hash.Hash, len(start.Receipt.Files))
	fileBytes := make([]int64, len(start.Receipt.Files))
	fileIndexes := make([]int, len(start.Receipt.Files))
	currentOrdinal := 0
	for index := range fileHashes {
		fileHashes[index] = sha256.New()
	}
	terminal := providerResponseEnd{}
	for {
		line, framed, err = readCanonicalLine(lines)
		if err != nil {
			return specialistrender.Receipt{}, "", err
		}
		var kind frameKind
		if err := json.Unmarshal(line, &kind); err != nil {
			return specialistrender.Receipt{}, "", fmt.Errorf("provider response kind is invalid")
		}
		if kind.Kind == "provider_response_end" {
			if err := generationstop.DecodeCanonicalJSON(line, &terminal); err != nil {
				return specialistrender.Receipt{}, "", fmt.Errorf("provider response end is invalid")
			}
			_, _ = wholeHash.Write(framed)
			break
		}
		var chunk providerFileChunk
		if err := generationstop.DecodeCanonicalJSON(line, &chunk); err != nil ||
			chunk.Schema != specialistrender.ProviderFrameSchema || chunk.Kind != "file_chunk" ||
			chunk.OperationID != request.OperationID || chunk.Ordinal != currentOrdinal || chunk.Ordinal >= len(start.Receipt.Files) ||
			chunk.Index != fileIndexes[chunk.Ordinal] || chunk.Bytes <= 0 || chunk.Bytes > specialistrender.RequestChunkBytes {
			return specialistrender.Receipt{}, "", fmt.Errorf("provider output chunk is invalid")
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(chunk.Base64)
		if err != nil || len(decoded) != chunk.Bytes || base64.StdEncoding.EncodeToString(decoded) != chunk.Base64 ||
			chunk.SHA256 != digestBytes(decoded) {
			return specialistrender.Receipt{}, "", fmt.Errorf("provider output chunk bytes are invalid")
		}
		fileIndexes[chunk.Ordinal]++
		fileBytes[chunk.Ordinal] += int64(len(decoded))
		if fileBytes[chunk.Ordinal] > start.Receipt.Files[chunk.Ordinal].ByteLength {
			return specialistrender.Receipt{}, "", fmt.Errorf("provider output exceeds its declared file length")
		}
		_, _ = fileHashes[chunk.Ordinal].Write(decoded)
		if fileBytes[chunk.Ordinal] == start.Receipt.Files[chunk.Ordinal].ByteLength {
			if "sha256:"+hex.EncodeToString(fileHashes[chunk.Ordinal].Sum(nil)) != start.Receipt.Files[chunk.Ordinal].Digest {
				return specialistrender.Receipt{}, "", fmt.Errorf("provider output file digest differs")
			}
			currentOrdinal++
		}
		_, _ = protocolHash.Write(framed)
		_, _ = wholeHash.Write(framed)
		frameCount++
	}
	if terminal.Schema != specialistrender.ProviderFrameSchema || terminal.Kind != "provider_response_end" ||
		terminal.OperationID != request.OperationID || terminal.ReceiptDigest != start.Receipt.ReceiptDigest ||
		terminal.FileCount != len(start.Receipt.Files) || terminal.TotalBytes != start.Receipt.TotalOutputBytes ||
		terminal.FrameCount != frameCount || terminal.StreamSHA256 != hashDigest(protocolHash) ||
		currentOrdinal != len(start.Receipt.Files) {
		return specialistrender.Receipt{}, "", fmt.Errorf("provider response end does not close the exact stream")
	}
	for index, descriptor := range start.Receipt.Files {
		if fileBytes[index] != descriptor.ByteLength || "sha256:"+hex.EncodeToString(fileHashes[index].Sum(nil)) != descriptor.Digest {
			return specialistrender.Receipt{}, "", fmt.Errorf("provider output bytes differ from the receipt")
		}
	}
	if trailing, err := lines.ReadByte(); err == nil || !errors.Is(err, io.EOF) {
		_ = trailing
		return specialistrender.Receipt{}, "", fmt.Errorf("provider response contains trailing bytes")
	}
	return start.Receipt, hashDigest(wholeHash), nil
}

func readCanonicalLine(reader *bufio.Reader) ([]byte, []byte, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return nil, nil, fmt.Errorf("provider response closed before its terminal frame")
	}
	if len(line) <= 1 || len(line) > specialistrender.MaximumFrameBytes || bytes.ContainsRune(line, '\r') {
		return nil, nil, fmt.Errorf("provider response line is invalid")
	}
	framed := append([]byte(nil), line...)
	return line[:len(line)-1], framed, nil
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

func chunkCount(size int) int {
	return (size + specialistrender.RequestChunkBytes - 1) / specialistrender.RequestChunkBytes
}

func hashDigest(value hash.Hash) string {
	return "sha256:" + hex.EncodeToString(value.Sum(nil))
}

func formatObservationTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func discard(reader io.Reader, maximum int64) {
	_, _ = io.Copy(io.Discard, io.LimitReader(reader, maximum))
}
