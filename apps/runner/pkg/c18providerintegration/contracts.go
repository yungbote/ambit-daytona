// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package c18providerintegration owns the live, release-time evidence boundary
// for C18 specialist-provider and private-object-store integration. It emits
// canonical, self-digested observations only after the real authenticated
// transport and storage operations have completed.
package c18providerintegration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

const (
	ProviderLiveCollectionContract  = "C18ProviderLiveCollection@1"
	MinIOIntegrationReceiptContract = "C18MinioIntegrationReceipt@1"
	ProviderLiveRunContract         = "C18ProviderLiveRun@1"
	MinIOIntegrationRunContract     = "C18MinioIntegrationRun@1"
	MinIOIntegrationTestRef         = "TestPrivateObjectMinIOConditionalChecksumRangeAndDelete"
	observationTimeLayout           = "2006-01-02T15:04:05.000Z"
	providerSuccessConcurrency      = 6
	providerExecuteSeconds          = 600
	providerObservationSeconds      = 180
	providerPollMilliseconds        = 250
	providerCancelAfterPartialMilli = 100
)

type providerFacetBinding struct {
	Facet string
	Pack  string
}

var providerFacetRoster = [providerSuccessConcurrency]providerFacetBinding{
	{Facet: "data_analysis", Pack: "data-research"},
	{Facet: "pdf", Pack: "pdf-ocr"},
	{Facet: "presentation", Pack: "office-authoring"},
	{Facet: "research", Pack: "data-research"},
	{Facet: "spreadsheet", Pack: "office-authoring"},
	{Facet: "web_application", Pack: "web-browser"},
}

var facetPacks = func() map[string]string {
	result := make(map[string]string, len(providerFacetRoster))
	for _, binding := range providerFacetRoster {
		result[binding.Facet] = binding.Pack
	}
	return result
}()

var minIOOperations = []string{
	"bounded_list",
	"checksum_stat",
	"conditional_create",
	"delete",
	"ranged_read",
	"streaming_open",
	"write_conflict",
}

type RunnerPolicyPin struct {
	CanonicalJSON string `json:"canonicalJson"`
	ContentSHA256 string `json:"contentSha256"`
}

type ProviderReceiptRow struct {
	Facet   string                   `json:"facet"`
	Mode    string                   `json:"mode"`
	Receipt specialistrender.Receipt `json:"receipt"`
}

type AuthenticatedStreamingCase struct {
	Facet                string `json:"facet"`
	OperationID          string `json:"operationId"`
	HTTPStatus           int    `json:"httpStatus"`
	Authenticated        bool   `json:"authenticated"`
	RequestStreamSHA256  string `json:"requestStreamSha256"`
	ResponseStreamSHA256 string `json:"responseStreamSha256"`
	ReceiptDigest        string `json:"receiptDigest"`
}

type AuthenticatedStreamingObservation struct {
	Outcome       string                       `json:"outcome"`
	ObservedFrom  string                       `json:"observedFrom"`
	ObservedUntil string                       `json:"observedUntil"`
	Cases         []AuthenticatedStreamingCase `json:"cases"`
}

type ConcurrentLoadCase struct {
	Facet                string `json:"facet"`
	StartedAt            string `json:"startedAt"`
	CompletedAt          string `json:"completedAt"`
	DurationMilliseconds int64  `json:"durationMilliseconds"`
	ReceiptDigest        string `json:"receiptDigest"`
}

type ConcurrentLoadObservation struct {
	PredeclaredConcurrency      int                  `json:"predeclaredConcurrency"`
	MaximumDurationMilliseconds int64                `json:"maximumDurationMilliseconds"`
	AllSucceeded                bool                 `json:"allSucceeded"`
	Outcome                     string               `json:"outcome"`
	Cases                       []ConcurrentLoadCase `json:"cases"`
}

type ProviderLiveCollection struct {
	Contract               string                            `json:"contract"`
	SourceRevision         string                            `json:"sourceRevision"`
	SourceTree             string                            `json:"sourceTree"`
	SourceSetDigest        string                            `json:"sourceSetDigest"`
	RunnerPolicy           RunnerPolicyPin                   `json:"runnerPolicy"`
	ProviderReceipts       []ProviderReceiptRow              `json:"providerReceipts"`
	AuthenticatedStreaming AuthenticatedStreamingObservation `json:"authenticatedStreaming"`
	ConcurrentLoad         ConcurrentLoadObservation         `json:"concurrentLoad"`
	Digest                 string                            `json:"digest"`
}

type providerLiveCollectionBody struct {
	Contract               string                            `json:"contract"`
	SourceRevision         string                            `json:"sourceRevision"`
	SourceTree             string                            `json:"sourceTree"`
	SourceSetDigest        string                            `json:"sourceSetDigest"`
	RunnerPolicy           RunnerPolicyPin                   `json:"runnerPolicy"`
	ProviderReceipts       []ProviderReceiptRow              `json:"providerReceipts"`
	AuthenticatedStreaming AuthenticatedStreamingObservation `json:"authenticatedStreaming"`
	ConcurrentLoad         ConcurrentLoadObservation         `json:"concurrentLoad"`
}

type MinIOConditionalCreateObservation struct {
	PayloadBytes        int64  `json:"payloadBytes"`
	PayloadSHA256       string `json:"payloadSha256"`
	Contenders          int    `json:"contenders"`
	ConcurrentWinners   int    `json:"concurrentWinners"`
	ConflictDisposition string `json:"conflictDisposition"`
}

type MinIOChecksumStatObservation struct {
	ByteLength         int64  `json:"byteLength"`
	ContentSHA256      string `json:"contentSha256"`
	UserMetadataSHA256 string `json:"userMetadataSha256"`
}

type MinIORangedReadObservation struct {
	Offset     int64  `json:"offset"`
	ByteLength int64  `json:"byteLength"`
	SHA256     string `json:"sha256"`
}

type MinIOStreamingOpenObservation struct {
	ByteLength         int64  `json:"byteLength"`
	SHA256             string `json:"sha256"`
	UserMetadataSHA256 string `json:"userMetadataSha256"`
}

type MinIOBoundedListObservation struct {
	Maximum      int    `json:"maximum"`
	Count        int    `json:"count"`
	RosterSHA256 string `json:"rosterSha256"`
}

type MinIODeleteObservation struct {
	ObjectCount int  `json:"objectCount"`
	AllAbsent   bool `json:"allAbsent"`
}

type MinIOOperationObservations struct {
	ConditionalCreate MinIOConditionalCreateObservation `json:"conditionalCreate"`
	ChecksumStat      MinIOChecksumStatObservation      `json:"checksumStat"`
	RangedRead        MinIORangedReadObservation        `json:"rangedRead"`
	StreamingOpen     MinIOStreamingOpenObservation     `json:"streamingOpen"`
	BoundedList       MinIOBoundedListObservation       `json:"boundedList"`
	Delete            MinIODeleteObservation            `json:"delete"`
}

type MinIOIntegrationReceipt struct {
	Contract        string                     `json:"contract"`
	SourceRevision  string                     `json:"sourceRevision"`
	SourceTree      string                     `json:"sourceTree"`
	SourceSetDigest string                     `json:"sourceSetDigest"`
	TestRef         string                     `json:"testRef"`
	Operations      []string                   `json:"operations"`
	Outcome         string                     `json:"outcome"`
	ObservedFrom    string                     `json:"observedFrom"`
	ObservedUntil   string                     `json:"observedUntil"`
	Observations    MinIOOperationObservations `json:"observations"`
	Digest          string                     `json:"digest"`
}

type minIOIntegrationReceiptBody struct {
	Contract        string                     `json:"contract"`
	SourceRevision  string                     `json:"sourceRevision"`
	SourceTree      string                     `json:"sourceTree"`
	SourceSetDigest string                     `json:"sourceSetDigest"`
	TestRef         string                     `json:"testRef"`
	Operations      []string                   `json:"operations"`
	Outcome         string                     `json:"outcome"`
	ObservedFrom    string                     `json:"observedFrom"`
	ObservedUntil   string                     `json:"observedUntil"`
	Observations    MinIOOperationObservations `json:"observations"`
}

func SealProviderLiveCollection(value ProviderLiveCollection) (ProviderLiveCollection, error) {
	value.Contract = ProviderLiveCollectionContract
	value.Digest = ""
	if err := validateProviderCollectionBody(value); err != nil {
		return ProviderLiveCollection{}, err
	}
	body := providerCollectionBody(value)
	encoded, err := generationstop.CanonicalJSON(body)
	if err != nil {
		return ProviderLiveCollection{}, fmt.Errorf("canonicalize provider collection: %w", err)
	}
	value.Digest = digestBytes(encoded)
	full, err := generationstop.CanonicalJSON(value)
	if err != nil {
		return ProviderLiveCollection{}, fmt.Errorf("canonicalize sealed provider collection: %w", err)
	}
	return ParseProviderLiveCollection(full)
}

func ParseProviderLiveCollection(data []byte) (ProviderLiveCollection, error) {
	var value ProviderLiveCollection
	if err := generationstop.DecodeCanonicalJSON(data, &value); err != nil {
		return ProviderLiveCollection{}, fmt.Errorf("decode canonical provider collection: %w", err)
	}
	if value.Contract != ProviderLiveCollectionContract {
		return ProviderLiveCollection{}, fmt.Errorf("provider collection contract is invalid")
	}
	if err := validateProviderCollectionBody(value); err != nil {
		return ProviderLiveCollection{}, err
	}
	body, err := generationstop.CanonicalJSON(providerCollectionBody(value))
	if err != nil || value.Digest != digestBytes(body) {
		return ProviderLiveCollection{}, fmt.Errorf("provider collection digest is invalid")
	}
	return value, nil
}

func SealMinIOIntegrationReceipt(value MinIOIntegrationReceipt) (MinIOIntegrationReceipt, error) {
	value.Contract = MinIOIntegrationReceiptContract
	value.TestRef = MinIOIntegrationTestRef
	value.Operations = append([]string(nil), minIOOperations...)
	value.Outcome = "passed"
	value.Digest = ""
	if err := validateMinIOReceiptBody(value); err != nil {
		return MinIOIntegrationReceipt{}, err
	}
	body, err := generationstop.CanonicalJSON(minIOReceiptBody(value))
	if err != nil {
		return MinIOIntegrationReceipt{}, fmt.Errorf("canonicalize MinIO receipt: %w", err)
	}
	value.Digest = digestBytes(body)
	full, err := generationstop.CanonicalJSON(value)
	if err != nil {
		return MinIOIntegrationReceipt{}, fmt.Errorf("canonicalize sealed MinIO receipt: %w", err)
	}
	return ParseMinIOIntegrationReceipt(full)
}

func ParseMinIOIntegrationReceipt(data []byte) (MinIOIntegrationReceipt, error) {
	var value MinIOIntegrationReceipt
	if err := generationstop.DecodeCanonicalJSON(data, &value); err != nil {
		return MinIOIntegrationReceipt{}, fmt.Errorf("decode canonical MinIO receipt: %w", err)
	}
	if value.Contract != MinIOIntegrationReceiptContract {
		return MinIOIntegrationReceipt{}, fmt.Errorf("MinIO receipt contract is invalid")
	}
	if err := validateMinIOReceiptBody(value); err != nil {
		return MinIOIntegrationReceipt{}, err
	}
	body, err := generationstop.CanonicalJSON(minIOReceiptBody(value))
	if err != nil || value.Digest != digestBytes(body) {
		return MinIOIntegrationReceipt{}, fmt.Errorf("MinIO receipt digest is invalid")
	}
	return value, nil
}

func EncodeCanonical(value any) ([]byte, error) {
	return generationstop.CanonicalJSON(value)
}

func validateProviderCollectionBody(value ProviderLiveCollection) error {
	if err := validateSourceIdentity(value.SourceRevision, value.SourceTree, value.SourceSetDigest); err != nil {
		return err
	}
	streaming := value.AuthenticatedStreaming
	observedFrom, observedUntil, intervalErr := parseObservationInterval(
		streaming.ObservedFrom,
		streaming.ObservedUntil,
	)
	if streaming.Outcome != "passed" || intervalErr != nil ||
		len(streaming.Cases) != providerSuccessConcurrency {
		return fmt.Errorf("authenticated streaming observation is invalid")
	}
	if value.RunnerPolicy.CanonicalJSON == "" || !exactDigest(value.RunnerPolicy.ContentSHA256) ||
		value.RunnerPolicy.ContentSHA256 != digestBytes([]byte(value.RunnerPolicy.CanonicalJSON)) {
		return fmt.Errorf("runner policy pin is invalid")
	}
	var policySet specialistrender.PolicySet
	if err := generationstop.DecodeCanonicalJSON([]byte(value.RunnerPolicy.CanonicalJSON), &policySet); err != nil ||
		policySet.Schema != specialistrender.PolicySetSchema || len(policySet.Policies) != 4 {
		return fmt.Errorf("runner policy set is invalid")
	}
	policyPack := make(map[string]specialistrender.PolicyDocument, len(policySet.Policies))
	for _, policy := range policySet.Policies {
		if !knownPack(policy.Image.PackID) {
			return fmt.Errorf("runner policy pack is invalid")
		}
		if _, duplicate := policyPack[policy.Image.PackID]; duplicate {
			return fmt.Errorf("runner policy packs are not unique")
		}
		policyPack[policy.Image.PackID] = policy
	}
	if len(value.ProviderReceipts) != 12 {
		return fmt.Errorf("provider collection requires exactly twelve receipts")
	}
	seenRows := make(map[string]struct{}, 12)
	seenOperations := make(map[string]struct{}, 12)
	seenReceiptDigests := make(map[string]struct{}, 12)
	previous := ""
	for index, row := range value.ProviderReceipts {
		key := row.Facet + "\x00" + row.Mode
		if index > 0 && previous >= key {
			return fmt.Errorf("provider receipt rows are not sorted and unique")
		}
		previous = key
		pack, exists := facetPacks[row.Facet]
		if !exists || (row.Mode != "cancel" && row.Mode != "success") {
			return fmt.Errorf("provider receipt facet or mode is invalid")
		}
		policy, exists := policyPack[pack]
		if !exists || row.Receipt.Request.Image.PackID != pack ||
			row.Receipt.Request.ProviderPolicy != policy.Authority ||
			row.Receipt.Request.Composition != policy.Composition ||
			row.Receipt.Request.Image != policy.Image ||
			row.Receipt.Request.Interface != policy.Interface ||
			row.Receipt.Request.Executor != policy.Executor ||
			row.Receipt.Request.Executable != policy.Executable {
			return fmt.Errorf("provider receipt is detached from its exact facet policy")
		}
		launch := row.Receipt.Launch
		if launch.ExecutablePath != policy.ProcessExecutablePath ||
			launch.ExecutableDigest != policy.ProcessExecutableDigest ||
			launch.EnvironmentDigest != policy.EnvironmentDigest ||
			launch.SeccompDigest != policy.SeccompDigest || launch.PIDsLimit != policy.PIDsLimit ||
			launch.MemoryBytes != policy.MemoryBytes || launch.NanoCPUs != policy.NanoCPUs ||
			launch.ShmSize != policy.ShmSize || launch.Runtime != policy.Runtime ||
			launch.RuntimeStatusDigest != policy.RuntimeStatusDigest ||
			!equalStringMap(launch.Tmpfs, map[string]string{
				"/workspace": fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,uid=1000,gid=1000,mode=0700", policy.WorkspaceSize),
				"/tmp":       fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,uid=0,gid=0,mode=1777", policy.ScratchSize),
			}) {
			return fmt.Errorf("provider receipt launch differs from its exact runner policy")
		}
		if row.Receipt.Files == nil {
			return fmt.Errorf("provider receipt file roster is not an explicit array")
		}
		if err := specialistrender.ValidateReceipt(row.Receipt); err != nil {
			return fmt.Errorf("provider receipt is invalid: %w", err)
		}
		startedAt, startedErr := parseObservationTime(row.Receipt.StartedAt)
		completedAt, completedErr := parseObservationTime(row.Receipt.CompletedAt)
		if startedErr != nil || completedErr != nil || startedAt.Before(observedFrom) || completedAt.After(observedUntil) {
			return fmt.Errorf("provider receipt chronology falls outside the authenticated streaming interval")
		}
		wanted := "succeeded"
		if row.Mode == "cancel" {
			wanted = "cancelled"
		}
		if row.Receipt.Outcome != wanted || row.Receipt.TerminalOutcome != wanted || !row.Receipt.Quiescence.ContainerAbsent {
			return fmt.Errorf("provider receipt outcome is invalid")
		}
		if _, duplicate := seenRows[key]; duplicate {
			return fmt.Errorf("provider receipt rows are duplicated")
		}
		if _, duplicate := seenOperations[row.Receipt.Request.OperationID]; duplicate {
			return fmt.Errorf("provider operation ids are not unique")
		}
		if _, duplicate := seenReceiptDigests[row.Receipt.ReceiptDigest]; duplicate {
			return fmt.Errorf("provider receipt digests are not unique")
		}
		seenRows[key] = struct{}{}
		seenOperations[row.Receipt.Request.OperationID] = struct{}{}
		seenReceiptDigests[row.Receipt.ReceiptDigest] = struct{}{}
	}
	previous = ""
	for index, item := range streaming.Cases {
		if index > 0 && previous >= item.Facet {
			return fmt.Errorf("authenticated streaming cases are not sorted and unique")
		}
		previous = item.Facet
		if item.Facet != providerFacetRoster[index].Facet || item.HTTPStatus != 200 || !item.Authenticated ||
			!exactDigest(item.RequestStreamSHA256) || !exactDigest(item.ResponseStreamSHA256) ||
			!exactDigest(item.ReceiptDigest) {
			return fmt.Errorf("authenticated streaming case is invalid")
		}
		row, ok := successRow(value.ProviderReceipts, item.Facet)
		if !ok || row.Receipt.Request.OperationID != item.OperationID || row.Receipt.ReceiptDigest != item.ReceiptDigest {
			return fmt.Errorf("authenticated streaming case is detached from its success receipt")
		}
	}
	if err := validateConcurrentLoad(value.ConcurrentLoad, streaming, value.ProviderReceipts, observedFrom, observedUntil); err != nil {
		return err
	}
	return nil
}

func validateConcurrentLoad(
	load ConcurrentLoadObservation,
	streaming AuthenticatedStreamingObservation,
	receipts []ProviderReceiptRow,
	observedFrom time.Time,
	observedUntil time.Time,
) error {
	if load.PredeclaredConcurrency != providerSuccessConcurrency ||
		load.MaximumDurationMilliseconds != providerExecuteSeconds*1000 ||
		!load.AllSucceeded || load.Outcome != "passed" ||
		len(load.Cases) != providerSuccessConcurrency {
		return fmt.Errorf("concurrent provider load declaration is invalid")
	}

	var latestStart time.Time
	var earliestCompletion time.Time
	for index, item := range load.Cases {
		if item.Facet != providerFacetRoster[index].Facet || !exactDigest(item.ReceiptDigest) {
			return fmt.Errorf("concurrent provider load case roster is invalid")
		}
		startedAt, startErr := parseObservationTime(item.StartedAt)
		completedAt, completionErr := parseObservationTime(item.CompletedAt)
		duration := completedAt.Sub(startedAt).Milliseconds()
		if startErr != nil || completionErr != nil || duration <= 0 ||
			item.DurationMilliseconds != duration ||
			item.DurationMilliseconds > load.MaximumDurationMilliseconds ||
			startedAt.Before(observedFrom) || completedAt.After(observedUntil) {
			return fmt.Errorf("concurrent provider load case interval is invalid")
		}
		row, rowExists := successRow(receipts, item.Facet)
		stream, streamExists := authenticatedStreamCase(streaming.Cases, item.Facet)
		var receiptStartedAt, receiptCompletedAt time.Time
		var receiptStartErr, receiptCompletionErr error
		if rowExists {
			receiptStartedAt, receiptStartErr = parseObservationTime(row.Receipt.StartedAt)
			receiptCompletedAt, receiptCompletionErr = parseObservationTime(row.Receipt.CompletedAt)
		}
		if !rowExists || !streamExists ||
			receiptStartErr != nil || receiptCompletionErr != nil ||
			row.Receipt.Outcome != "succeeded" || row.Receipt.TerminalOutcome != "succeeded" ||
			item.ReceiptDigest != row.Receipt.ReceiptDigest ||
			item.ReceiptDigest != stream.ReceiptDigest ||
			row.Receipt.Request.OperationID != stream.OperationID ||
			startedAt.Before(receiptStartedAt) || completedAt.After(receiptCompletedAt) {
			return fmt.Errorf("concurrent provider load case is detached from its authenticated success stream")
		}
		if latestStart.IsZero() || startedAt.After(latestStart) {
			latestStart = startedAt
		}
		if earliestCompletion.IsZero() || completedAt.Before(earliestCompletion) {
			earliestCompletion = completedAt
		}
	}
	if !latestStart.Before(earliestCompletion) {
		return fmt.Errorf("concurrent provider load cases do not share a positive overlap")
	}
	return nil
}

func validateMinIOReceiptBody(value MinIOIntegrationReceipt) error {
	if err := validateSourceIdentity(value.SourceRevision, value.SourceTree, value.SourceSetDigest); err != nil {
		return err
	}
	if value.TestRef != MinIOIntegrationTestRef || value.Outcome != "passed" ||
		!equalStrings(value.Operations, minIOOperations) ||
		!validInterval(value.ObservedFrom, value.ObservedUntil) {
		return fmt.Errorf("MinIO receipt identity, operations, or interval is invalid")
	}
	o := value.Observations
	if o.ConditionalCreate.PayloadBytes <= 0 || !exactDigest(o.ConditionalCreate.PayloadSHA256) ||
		o.ConditionalCreate.Contenders < 2 || o.ConditionalCreate.Contenders > 128 ||
		o.ConditionalCreate.ConcurrentWinners != 1 ||
		o.ConditionalCreate.ConflictDisposition != "precondition_failed" ||
		o.ChecksumStat.ByteLength != o.ConditionalCreate.PayloadBytes ||
		o.ChecksumStat.ContentSHA256 != o.ConditionalCreate.PayloadSHA256 ||
		!exactDigest(o.ChecksumStat.UserMetadataSHA256) ||
		o.RangedRead.Offset < 0 || o.RangedRead.ByteLength <= 0 || !exactDigest(o.RangedRead.SHA256) ||
		o.StreamingOpen.ByteLength != o.ConditionalCreate.PayloadBytes ||
		o.StreamingOpen.SHA256 != o.ConditionalCreate.PayloadSHA256 ||
		!exactDigest(o.StreamingOpen.UserMetadataSHA256) ||
		o.BoundedList.Maximum < 1 || o.BoundedList.Count != 1 ||
		o.BoundedList.Count > o.BoundedList.Maximum || !exactDigest(o.BoundedList.RosterSHA256) ||
		o.Delete.ObjectCount != 3 || !o.Delete.AllAbsent {
		return fmt.Errorf("MinIO operation observations are invalid")
	}
	return nil
}

func providerCollectionBody(value ProviderLiveCollection) providerLiveCollectionBody {
	return providerLiveCollectionBody{
		Contract: value.Contract, SourceRevision: value.SourceRevision, SourceTree: value.SourceTree,
		SourceSetDigest: value.SourceSetDigest, RunnerPolicy: value.RunnerPolicy,
		ProviderReceipts: value.ProviderReceipts, AuthenticatedStreaming: value.AuthenticatedStreaming,
		ConcurrentLoad: value.ConcurrentLoad,
	}
}

func minIOReceiptBody(value MinIOIntegrationReceipt) minIOIntegrationReceiptBody {
	return minIOIntegrationReceiptBody{
		Contract: value.Contract, SourceRevision: value.SourceRevision, SourceTree: value.SourceTree,
		SourceSetDigest: value.SourceSetDigest, TestRef: value.TestRef,
		Operations: value.Operations, Outcome: value.Outcome, ObservedFrom: value.ObservedFrom,
		ObservedUntil: value.ObservedUntil, Observations: value.Observations,
	}
}

func validateSourceIdentity(revision, tree, sourceSet string) error {
	if !gitObject(revision) || !gitObject(tree) || !exactDigest(sourceSet) {
		return fmt.Errorf("source identity is invalid")
	}
	return nil
}

func validInterval(from, until string) bool {
	_, _, err := parseObservationInterval(from, until)
	return err == nil
}

func parseObservationInterval(from, until string) (time.Time, time.Time, error) {
	start, startErr := parseObservationTime(from)
	end, endErr := parseObservationTime(until)
	if startErr != nil || endErr != nil || end.Before(start) {
		return time.Time{}, time.Time{}, fmt.Errorf("observation interval is invalid")
	}
	return start, end, nil
}

func parseObservationTime(value string) (time.Time, error) {
	parsed, err := time.Parse(observationTimeLayout, value)
	if err != nil || formatObservationTime(parsed) != value {
		return time.Time{}, fmt.Errorf("observation time is not an exact UTC millisecond instant")
	}
	return parsed, nil
}

func successRow(rows []ProviderReceiptRow, facet string) (ProviderReceiptRow, bool) {
	for _, row := range rows {
		if row.Facet == facet && row.Mode == "success" {
			return row, true
		}
	}
	return ProviderReceiptRow{}, false
}

func authenticatedStreamCase(cases []AuthenticatedStreamingCase, facet string) (AuthenticatedStreamingCase, bool) {
	for _, item := range cases {
		if item.Facet == facet {
			return item, true
		}
	}
	return AuthenticatedStreamingCase{}, false
}

func exactDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func gitObject(value string) bool {
	if len(value) != 40 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func equalStrings(left, right []string) bool {
	return len(left) == len(right) && bytes.Equal([]byte(strings.Join(left, "\x00")), []byte(strings.Join(right, "\x00")))
}

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func knownPack(pack string) bool {
	for _, candidate := range facetPacks {
		if candidate == pack {
			return true
		}
	}
	return false
}
