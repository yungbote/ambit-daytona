// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/daytonaio/runner/pkg/generationstop"
)

var helperMediaTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`)
var helperTokenPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)

type helperPin struct {
	Digest string `json:"digest"`
	Ref    string `json:"ref"`
}

type helperProcessIdentity struct {
	PID        int    `json:"pid"`
	StartTicks string `json:"startTicks"`
}

type helperRequestIdentity struct {
	Digest  string `json:"digest"`
	JobRef  string `json:"jobRef"`
	JobRoot string `json:"jobRoot"`
}

type helperReady struct {
	CancellationExitCode int                   `json:"cancellationExitCode"`
	ChunkBytes           int                   `json:"chunkBytes"`
	Executable           string                `json:"executable"`
	ExecutorRevision     helperPin             `json:"executorRevision"`
	Interface            helperPin             `json:"interface"`
	Kind                 string                `json:"kind"`
	Nonce                string                `json:"nonce"`
	ProcessIdentity      helperProcessIdentity `json:"processIdentity"`
	Schema               string                `json:"schema"`
}

type helperResponseStart struct {
	ExecutorRevision helperPin             `json:"executorRevision"`
	ExitCode         int                   `json:"exitCode"`
	FileCount        int                   `json:"fileCount"`
	Kind             string                `json:"kind"`
	Nonce            string                `json:"nonce"`
	Outcome          string                `json:"outcome"`
	Request          helperRequestIdentity `json:"request"`
	ResultDigest     string                `json:"resultDigest"`
	Schema           string                `json:"schema"`
	TotalBytes       int64                 `json:"totalBytes"`
}

type helperFileStart struct {
	ByteLength int64  `json:"byteLength"`
	ChunkBytes int    `json:"chunkBytes"`
	ChunkCount int    `json:"chunkCount"`
	Kind       string `json:"kind"`
	MediaType  string `json:"mediaType"`
	Nonce      string `json:"nonce"`
	Ordinal    int    `json:"ordinal"`
	Path       string `json:"path"`
	Role       string `json:"role"`
	Schema     string `json:"schema"`
	Digest     string `json:"sha256"`
}

type helperFileChunk struct {
	Base64     string `json:"base64"`
	Bytes      int    `json:"bytes"`
	ChunkIndex int    `json:"chunkIndex"`
	Kind       string `json:"kind"`
	Nonce      string `json:"nonce"`
	Ordinal    int    `json:"ordinal"`
	Schema     string `json:"schema"`
	Digest     string `json:"sha256"`
}

type helperResponseEnd struct {
	ExecutorRevision   helperPin             `json:"executorRevision"`
	ExitCode           int                   `json:"exitCode"`
	FileCount          int                   `json:"fileCount"`
	FrameCount         int                   `json:"frameCount"`
	Kind               string                `json:"kind"`
	Nonce              string                `json:"nonce"`
	Outcome            string                `json:"outcome"`
	PrivateRootCleanup string                `json:"privateRootCleanup"`
	ProcessIdentity    helperProcessIdentity `json:"processIdentity"`
	Request            helperRequestIdentity `json:"request"`
	ResultDigest       string                `json:"resultDigest"`
	Schema             string                `json:"schema"`
	StreamDigest       string                `json:"streamSha256"`
	TerminalSelection  string                `json:"terminalSelection"`
	TotalBytes         int64                 `json:"totalBytes"`
}

type helperCancelled struct {
	ExecutorRevision   helperPin             `json:"executorRevision"`
	ExitCode           int                   `json:"exitCode"`
	Kind               string                `json:"kind"`
	Nonce              string                `json:"nonce"`
	Outcome            string                `json:"outcome"`
	PrivateRootCleanup string                `json:"privateRootCleanup"`
	ProcessIdentity    helperProcessIdentity `json:"processIdentity"`
	Schema             string                `json:"schema"`
	TerminalSelection  string                `json:"terminalSelection"`
}

type helperRequestStart struct {
	ChunkBytes        int    `json:"chunkBytes"`
	Kind              string `json:"kind"`
	Nonce             string `json:"nonce"`
	RequestBytes      int64  `json:"requestBytes"`
	RequestChunkCount int    `json:"requestChunkCount"`
	RequestDigest     string `json:"requestSha256"`
	Schema            string `json:"schema"`
	SourceBytes       int64  `json:"sourceBytes"`
	SourceChunkCount  int    `json:"sourceChunkCount"`
	SourceDigest      string `json:"sourceSha256"`
}

type helperChunk struct {
	Base64 string `json:"base64"`
	Bytes  int    `json:"bytes"`
	Index  int    `json:"index"`
	Kind   string `json:"kind"`
	Nonce  string `json:"nonce"`
	Schema string `json:"schema"`
	Digest string `json:"sha256"`
}

type helperRequestEnd struct {
	Kind              string `json:"kind"`
	Nonce             string `json:"nonce"`
	RequestBytes      int64  `json:"requestBytes"`
	RequestChunkCount int    `json:"requestChunkCount"`
	RequestDigest     string `json:"requestSha256"`
	Schema            string `json:"schema"`
	SourceBytes       int64  `json:"sourceBytes"`
	SourceChunkCount  int    `json:"sourceChunkCount"`
	SourceDigest      string `json:"sourceSha256"`
}

type helperCancel struct {
	Kind   string `json:"kind"`
	Nonce  string `json:"nonce"`
	Schema string `json:"schema"`
}

type helperCollector struct {
	nonce        string
	policy       Policy
	request      helperRequestIdentity
	sourceDigest string
	command      helperCommand
	process      helperProcessIdentity
	readyDigest  string
	root         string
	files        []Payload
	paths        map[string]struct{}
	current      *helperOpenFile
	start        *helperResponseStart
	streamHash   hash.Hash
	frameCount   int
	projected    int64
	lastRole     string
}

type helperOpenFile struct {
	start helperFileStart
	path  string
	file  *os.File
	hash  hash.Hash
	next  int
}

type helperResult struct {
	ReadyDigest     string
	TerminalDigest  string
	TerminalKind    string
	TerminalOutcome string
	ExitCode        int
	Files           []Payload
}

// HelperResult is the validated terminal surface returned to a provider
// adapter. Raw helper frames remain private to this package.
type HelperResult = helperResult

// HelperSession owns strict helper framing and provider-private output custody.
type HelperSession struct {
	collector *helperCollector
}

func NewHelperSession(request ProviderExecutionRequest, process ProcessIdentity) (*HelperSession, error) {
	collector, err := newHelperCollector(request.Nonce, request.Policy, request, process)
	if err != nil {
		return nil, err
	}
	return &HelperSession{collector: collector}, nil
}

func (session *HelperSession) ReadReady(reader *bufio.Reader) error {
	return session.collector.readReady(reader)
}

func (session *HelperSession) WriteRequest(writer io.Writer, request ProviderExecutionRequest) error {
	return writeHelperRequest(writer, request)
}

func (session *HelperSession) WriteCancel(writer io.Writer, nonce string) error {
	return writeHelperCancel(writer, nonce)
}

// WriteHelperCancel emits the exact nonce-bound cancellation frame before a
// HelperSession exists or ready has arrived.
func WriteHelperCancel(writer io.Writer, nonce string) error {
	return writeHelperCancel(writer, nonce)
}

func (session *HelperSession) Collect(reader *bufio.Reader) (HelperResult, error) {
	return session.collector.collect(reader)
}

func (session *HelperSession) Cleanup() {
	session.collector.cleanup()
}

func newHelperCollector(
	nonce string,
	policy Policy,
	request ProviderExecutionRequest,
	process ProcessIdentity,
) (*helperCollector, error) {
	command, err := parseHelperCommand(request.Request, request.Authority, policy)
	if err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp("", "ambit-specialist-render-output-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	return &helperCollector{
		nonce:  nonce,
		policy: clonePolicy(policy),
		request: helperRequestIdentity{
			Digest:  command.Digest,
			JobRef:  command.JobRef,
			JobRoot: command.JobRoot,
		},
		sourceDigest: command.Source.Digest,
		command:      command,
		process:      helperProcessIdentity{PID: process.PID, StartTicks: process.StartTicks},
		root:         root,
		paths:        make(map[string]struct{}),
		streamHash:   sha256.New(),
	}, nil
}

func (collector *helperCollector) cleanup() {
	if collector.current != nil && collector.current.file != nil {
		_ = collector.current.file.Close()
	}
	_ = os.RemoveAll(collector.root)
	collector.root = ""
	collector.files = nil
}

func (collector *helperCollector) readReady(reader *bufio.Reader) error {
	line, err := readFrameLine(reader)
	if err != nil {
		return err
	}
	var ready helperReady
	if err := generationstop.DecodeCanonicalJSON(line, &ready); err != nil {
		return fmt.Errorf("helper ready is invalid: %w", err)
	}
	if ready.Schema != FrameSchema || ready.Kind != "ready" || ready.Nonce != collector.nonce ||
		ready.ChunkBytes != RequestChunkBytes || ready.CancellationExitCode != 130 ||
		ready.Executable != collector.policy.Executable ||
		ready.Interface != pinToHelper(collector.policy.Interface) ||
		ready.ExecutorRevision != pinToHelper(collector.policy.Executor) ||
		ready.ProcessIdentity != collector.process {
		return errors.New("helper ready identity differs")
	}
	collector.readyDigest = sha256Digest(line)
	return nil
}

func (collector *helperCollector) collect(reader *bufio.Reader) (_ helperResult, err error) {
	defer func() {
		if err != nil {
			collector.cleanup()
		}
	}()
	for {
		line, readErr := readFrameLine(reader)
		if readErr != nil {
			return helperResult{}, readErr
		}
		var kind frameKind
		if err := jsonUnmarshalKind(line, &kind); err != nil {
			return helperResult{}, err
		}
		switch kind.Kind {
		case "response_start":
			if err := collector.acceptStart(line); err != nil {
				return helperResult{}, err
			}
		case "file_start":
			if err := collector.acceptFileStart(line); err != nil {
				return helperResult{}, err
			}
		case "file_chunk":
			if err := collector.acceptFileChunk(line); err != nil {
				return helperResult{}, err
			}
		case "response_end":
			result, err := collector.acceptEnd(line)
			if err != nil {
				return helperResult{}, err
			}
			return result, nil
		case "cancelled":
			result, err := collector.acceptCancelled(line)
			if err != nil {
				return helperResult{}, err
			}
			return result, nil
		default:
			return helperResult{}, errors.New("helper response kind or order is invalid")
		}
	}
}

func (collector *helperCollector) acceptStart(line []byte) error {
	var frame helperResponseStart
	if err := generationstop.DecodeCanonicalJSON(line, &frame); err != nil {
		return err
	}
	validOutcome := (frame.Outcome == "succeeded" && frame.ExitCode == 0) ||
		(frame.Outcome == "failed" && (frame.ExitCode == 1 || frame.ExitCode == 124))
	if collector.start != nil || collector.current != nil || len(collector.files) != 0 ||
		frame.Schema != FrameSchema || frame.Kind != "response_start" || frame.Nonce != collector.nonce ||
		frame.ExecutorRevision != pinToHelper(collector.policy.Executor) || frame.Request != collector.request ||
		!exactDigest(frame.ResultDigest) || !validOutcome || frame.FileCount <= 0 ||
		frame.FileCount > MaximumOutputFiles || frame.TotalBytes <= 0 || frame.TotalBytes > MaximumOutputBytes {
		return errors.New("helper response_start identity or bounds differ")
	}
	collector.start = &frame
	collector.record(line)
	return nil
}

func (collector *helperCollector) acceptFileStart(line []byte) error {
	var frame helperFileStart
	if err := generationstop.DecodeCanonicalJSON(line, &frame); err != nil {
		return err
	}
	expectedOrdinal := len(collector.files) + 1
	expectedChunks := int((frame.ByteLength + RequestChunkBytes - 1) / RequestChunkBytes)
	roleOrder := helperRoleOrder(frame.Ordinal, frame.Role, collector.lastRole)
	_, duplicate := collector.paths[frame.Path]
	if collector.start == nil || collector.current != nil || frame.Schema != FrameSchema ||
		frame.Kind != "file_start" || frame.Nonce != collector.nonce || frame.Ordinal != expectedOrdinal ||
		frame.Ordinal > collector.start.FileCount || frame.ByteLength <= 0 ||
		frame.ByteLength > MaximumOutputBytes || frame.ChunkBytes != RequestChunkBytes ||
		frame.ChunkCount != expectedChunks || frame.ChunkCount <= 0 || !exactDigest(frame.Digest) ||
		!safeOutputPath(frame.Path) || duplicate || !helperMediaTypePattern.MatchString(frame.MediaType) ||
		len(frame.MediaType) > 128 || !roleOrder || collector.projected+frame.ByteLength > collector.start.TotalBytes {
		return errors.New("helper file_start identity, order, or bounds differ")
	}
	path := filepath.Join(collector.root, fmt.Sprintf("%03d.bin", frame.Ordinal))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	collector.paths[frame.Path] = struct{}{}
	collector.lastRole = frame.Role
	collector.projected += frame.ByteLength
	collector.current = &helperOpenFile{start: frame, path: path, file: file, hash: sha256.New()}
	collector.record(line)
	return nil
}

func (collector *helperCollector) acceptFileChunk(line []byte) error {
	var frame helperFileChunk
	if err := generationstop.DecodeCanonicalJSON(line, &frame); err != nil {
		return err
	}
	current := collector.current
	if current == nil {
		return errors.New("helper file_chunk has no active file")
	}
	remaining := current.start.ByteLength - int64(current.next*RequestChunkBytes)
	expectedBytes := int64(RequestChunkBytes)
	if remaining < expectedBytes {
		expectedBytes = remaining
	}
	decoded, err := decodeCanonicalBase64(frame.Base64, frame.Bytes)
	if err != nil || frame.Schema != FrameSchema || frame.Kind != "file_chunk" ||
		frame.Nonce != collector.nonce || frame.Ordinal != current.start.Ordinal ||
		frame.ChunkIndex != current.next || frame.ChunkIndex >= current.start.ChunkCount ||
		frame.Bytes != int(expectedBytes) || frame.Digest != sha256Digest(decoded) {
		return errors.New("helper file_chunk identity, order, bytes, or digest differ")
	}
	if _, err := current.file.Write(decoded); err != nil {
		return err
	}
	_, _ = current.hash.Write(decoded)
	current.next++
	collector.record(line)
	if current.next == current.start.ChunkCount {
		if hashDigest(current.hash) != current.start.Digest {
			return errors.New("helper output file aggregate digest differs")
		}
		if err := current.file.Sync(); err != nil {
			return err
		}
		if err := current.file.Close(); err != nil {
			return err
		}
		path := current.path
		root := collector.root
		collector.files = append(collector.files, Payload{
			File: OutputFile{
				Ordinal: current.start.Ordinal - 1, Role: current.start.Role,
				Path: current.start.Path, MediaType: current.start.MediaType,
				ByteLength: current.start.ByteLength, Digest: current.start.Digest,
			},
			Open:    func(_ context.Context) (io.ReadCloser, error) { return os.Open(path) },
			Cleanup: func() error { return os.RemoveAll(root) },
		})
		collector.current = nil
	}
	return nil
}

func (collector *helperCollector) acceptEnd(line []byte) (helperResult, error) {
	var frame helperResponseEnd
	if err := generationstop.DecodeCanonicalJSON(line, &frame); err != nil {
		return helperResult{}, err
	}
	start := collector.start
	if start == nil || collector.current != nil || frame.Schema != FrameSchema ||
		frame.Kind != "response_end" || frame.Nonce != collector.nonce ||
		frame.ExecutorRevision != start.ExecutorRevision || frame.ExitCode != start.ExitCode ||
		frame.FileCount != start.FileCount || frame.Outcome != start.Outcome || frame.Request != start.Request ||
		frame.ResultDigest != start.ResultDigest || frame.TotalBytes != start.TotalBytes ||
		frame.FrameCount != collector.frameCount || frame.StreamDigest != hashDigest(collector.streamHash) ||
		frame.ProcessIdentity != collector.process || frame.PrivateRootCleanup != "completed" ||
		frame.TerminalSelection != "helper-selected" || len(collector.files) != start.FileCount ||
		collector.projected != start.TotalBytes || collector.files[0].File.Role != "result" {
		return helperResult{}, errors.New("helper response_end identity or aggregate differs")
	}
	if err := collector.validateSemantics(*start); err != nil {
		return helperResult{}, err
	}
	outcome := frame.Outcome
	if frame.ExitCode == 124 {
		outcome = "timed_out"
	}
	return helperResult{
		ReadyDigest: collector.readyDigest, TerminalDigest: sha256Digest(line),
		TerminalKind: frame.Kind, TerminalOutcome: outcome, ExitCode: frame.ExitCode,
		Files: append([]Payload(nil), collector.files...),
	}, nil
}

func (collector *helperCollector) acceptCancelled(line []byte) (helperResult, error) {
	var frame helperCancelled
	if err := generationstop.DecodeCanonicalJSON(line, &frame); err != nil {
		return helperResult{}, err
	}
	if frame.Schema != FrameSchema || frame.Kind != "cancelled" || frame.Nonce != collector.nonce ||
		frame.Outcome != "cancelled" || frame.ExitCode != 130 ||
		frame.ExecutorRevision != pinToHelper(collector.policy.Executor) ||
		frame.ProcessIdentity != collector.process || frame.PrivateRootCleanup != "completed" ||
		frame.TerminalSelection != "helper-selected" {
		return helperResult{}, errors.New("helper cancelled terminal identity differs")
	}
	// Cancellation never commits a partial response, even if file frames raced
	// before the helper selected its terminal.
	collector.cleanup()
	return helperResult{
		ReadyDigest: collector.readyDigest, TerminalDigest: sha256Digest(line),
		TerminalKind: frame.Kind, TerminalOutcome: frame.Outcome, ExitCode: frame.ExitCode,
		Files: []Payload{},
	}, nil
}

func (collector *helperCollector) record(line []byte) {
	writeHashedLine(collector.streamHash, line)
	collector.frameCount++
}

type helperArtifactDescriptor struct {
	ByteLength int64  `json:"byteLength"`
	Digest     string `json:"digest"`
	MediaType  string `json:"mediaType"`
	Path       string `json:"path"`
}

type helperCommandSource struct {
	ByteLength int64           `json:"byteLength"`
	Digest     string          `json:"digest"`
	MediaType  string          `json:"mediaType"`
	Path       string          `json:"path"`
	Ref        string          `json:"ref"`
	SchemaURI  json.RawMessage `json:"schemaUri"`
}

type helperCommandOutput struct {
	JobOutputRoot               string `json:"jobOutputRoot"`
	MaximumAggregateImagePixels int64  `json:"maximumAggregateImagePixels"`
	MaximumImagePixels          int64  `json:"maximumImagePixels"`
	MaximumPreviewBytes         int64  `json:"maximumPreviewBytes"`
	PreviewMediaType            string `json:"previewMediaType"`
	PreviewPath                 string `json:"previewPath"`
	ResultPath                  string `json:"resultPath"`
}

type helperCommandCheck struct {
	Check string `json:"check"`
	Label string `json:"label"`
}

type helperCommandRenderer struct {
	ExecutablePath      string `json:"executablePath"`
	RenderMode          string `json:"renderMode"`
	RendererRef         string `json:"rendererRef"`
	Representation      string `json:"representation"`
	ValidationPolicyRef string `json:"validationPolicyRef"`
}

type helperCommand struct {
	Contract           string                `json:"contract"`
	DeadlineAt         string                `json:"deadlineAt"`
	Digest             string                `json:"digest"`
	Facet              string                `json:"facet"`
	JobRef             string                `json:"jobRef"`
	JobRoot            string                `json:"jobRoot"`
	Operation          string                `json:"operation"`
	Output             helperCommandOutput   `json:"output"`
	PackRequiredChecks []helperCommandCheck  `json:"packRequiredChecks"`
	RequestPath        string                `json:"requestPath"`
	Renderer           helperCommandRenderer `json:"renderer"`
	Runtime            json.RawMessage       `json:"runtime"`
	Source             helperCommandSource   `json:"source"`
}

type helperCommandUnsealed struct {
	Contract           string                `json:"contract"`
	DeadlineAt         string                `json:"deadlineAt"`
	Facet              string                `json:"facet"`
	JobRef             string                `json:"jobRef"`
	JobRoot            string                `json:"jobRoot"`
	Operation          string                `json:"operation"`
	Output             helperCommandOutput   `json:"output"`
	PackRequiredChecks []helperCommandCheck  `json:"packRequiredChecks"`
	RequestPath        string                `json:"requestPath"`
	Renderer           helperCommandRenderer `json:"renderer"`
	Runtime            json.RawMessage       `json:"runtime"`
	Source             helperCommandSource   `json:"source"`
}

func parseHelperCommand(input Input, authority Request, policy Policy) (helperCommand, error) {
	payload := Payload{
		File: OutputFile{ByteLength: input.ByteLength},
		Open: func(_ context.Context) (io.ReadCloser, error) { return input.Open() },
	}
	value, err := readPayloadBounded(payload, MaximumRequestBytes)
	if err != nil {
		return helperCommand{}, fmt.Errorf("read canonical helper command: %w", err)
	}
	if sha256Digest(value) != authority.RequestDigest {
		return helperCommand{}, errors.New("canonical helper command differs from transport digest")
	}
	var command helperCommand
	if err := generationstop.DecodeCanonicalJSON(value, &command); err != nil {
		return helperCommand{}, fmt.Errorf("canonical helper command is invalid: %w", err)
	}
	unsealed := helperCommandUnsealed{
		Contract: command.Contract, DeadlineAt: command.DeadlineAt, Facet: command.Facet,
		JobRef: command.JobRef, JobRoot: command.JobRoot, Operation: command.Operation,
		Output: command.Output, PackRequiredChecks: command.PackRequiredChecks,
		RequestPath: command.RequestPath, Renderer: command.Renderer,
		Runtime: command.Runtime, Source: command.Source,
	}
	unsealedBytes, err := generationstop.CanonicalJSON(unsealed)
	jobID := strings.TrimPrefix(authority.ArtifactRenderJobRef, "ambit://artifact-render-jobs/")
	if err != nil || command.Contract != "ambit.c18-specialist-render-command-request/v2" ||
		command.Digest != sha256Digest(unsealedBytes) || command.Operation != "render_validate" ||
		command.JobRef != authority.ArtifactRenderJobRef ||
		command.JobRoot != "/workspace/.ambit/render-jobs/"+jobID ||
		command.Source.ByteLength != authority.SourceBytes ||
		command.Source.Digest != authority.SourceDigest ||
		command.Renderer.ExecutablePath != policy.Executable || command.RequestPath != "inputs/request.json" ||
		command.Output.ResultPath == "" || command.Output.PreviewPath == "" ||
		command.Output.PreviewMediaType != "application/vnd.ambit.c18-specialist-artifact-preview+json" ||
		command.Output.JobOutputRoot == "" || command.Output.MaximumPreviewBytes <= 0 ||
		len(command.Runtime) == 0 || !safeInputPath(command.Source.Path) ||
		!safeOutputPath(command.Output.ResultPath) || !safeOutputPath(command.Output.PreviewPath) ||
		!safeOutputPath(command.Output.JobOutputRoot+"/sentinel") {
		return helperCommand{}, errors.New("canonical helper command authority or seal differs")
	}
	if _, err := parseProviderTime(command.DeadlineAt); err != nil {
		return helperCommand{}, errors.New("canonical helper command deadline is invalid")
	}
	checks := make([]string, len(command.PackRequiredChecks))
	for index, check := range command.PackRequiredChecks {
		checks[index] = check.Check
		if check.Label == "" || len(check.Label) > 512 {
			return helperCommand{}, errors.New("canonical helper command check label is invalid")
		}
	}
	if !strictlySorted(checks) {
		return helperCommand{}, errors.New("canonical helper command checks are not sorted and unique")
	}
	return command, nil
}

type helperPreviewDescriptor struct {
	ByteLength     int64  `json:"byteLength"`
	BytesDigest    string `json:"bytesDigest"`
	EnvelopeDigest string `json:"envelopeDigest"`
	MediaType      string `json:"mediaType"`
	Path           string `json:"path"`
}

type helperResultCheck struct {
	Check    string                    `json:"check"`
	Evidence *helperArtifactDescriptor `json:"evidence"`
	Outcome  string                    `json:"outcome"`
}

type helperExpectedEvidence struct {
	descriptor helperArtifactDescriptor
	check      string
	outcome    string
}

type helperResultExecution struct {
	CompletedAt      string    `json:"completedAt"`
	ExecutorRevision helperPin `json:"executorRevision"`
	StartedAt        string    `json:"startedAt"`
}

type helperResultFailure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type helperSemanticResult struct {
	Checks    []helperResultCheck      `json:"checks"`
	Contract  string                   `json:"contract"`
	Digest    string                   `json:"digest"`
	Execution helperResultExecution    `json:"execution"`
	Failure   *helperResultFailure     `json:"failure"`
	Outcome   string                   `json:"outcome"`
	Preview   *helperPreviewDescriptor `json:"preview"`
	Request   helperRequestIdentity    `json:"request"`
}

type helperSemanticResultUnsealed struct {
	Checks    []helperResultCheck      `json:"checks"`
	Contract  string                   `json:"contract"`
	Execution helperResultExecution    `json:"execution"`
	Failure   *helperResultFailure     `json:"failure"`
	Outcome   string                   `json:"outcome"`
	Preview   *helperPreviewDescriptor `json:"preview"`
	Request   helperRequestIdentity    `json:"request"`
}

type helperEvidenceRequest struct {
	Digest       string `json:"digest"`
	JobRef       string `json:"jobRef"`
	SourceDigest string `json:"sourceDigest"`
}

type helperEvidenceFact struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type helperSemanticEvidence struct {
	Artifacts        []helperArtifactDescriptor `json:"artifacts"`
	Check            string                     `json:"check"`
	Contract         string                     `json:"contract"`
	Digest           string                     `json:"digest"`
	ExecutorRevision helperPin                  `json:"executorRevision"`
	Facts            []helperEvidenceFact       `json:"facts"`
	Outcome          string                     `json:"outcome"`
	Request          helperEvidenceRequest      `json:"request"`
}

type helperSemanticEvidenceUnsealed struct {
	Artifacts        []helperArtifactDescriptor `json:"artifacts"`
	Check            string                     `json:"check"`
	Contract         string                     `json:"contract"`
	ExecutorRevision helperPin                  `json:"executorRevision"`
	Facts            []helperEvidenceFact       `json:"facts"`
	Outcome          string                     `json:"outcome"`
	Request          helperEvidenceRequest      `json:"request"`
}

type helperSemanticPreview struct {
	Contract      string          `json:"contract"`
	Digest        string          `json:"digest"`
	Facet         string          `json:"facet"`
	Facts         json.RawMessage `json:"facts"`
	Limitations   json.RawMessage `json:"limitations"`
	SchemaVersion int             `json:"schemaVersion"`
	Summary       string          `json:"summary"`
	Title         string          `json:"title"`
	Validation    json.RawMessage `json:"validation"`
	Views         json.RawMessage `json:"views"`
}

type helperSemanticPreviewUnsealed struct {
	Contract      string          `json:"contract"`
	Facet         string          `json:"facet"`
	Facts         json.RawMessage `json:"facts"`
	Limitations   json.RawMessage `json:"limitations"`
	SchemaVersion int             `json:"schemaVersion"`
	Summary       string          `json:"summary"`
	Title         string          `json:"title"`
	Validation    json.RawMessage `json:"validation"`
	Views         json.RawMessage `json:"views"`
}

func (collector *helperCollector) validateSemantics(start helperResponseStart) error {
	resultBytes, err := readPayloadBounded(collector.files[0], MaximumRequestBytes)
	if err != nil {
		return fmt.Errorf("helper semantic result read failed: %w", err)
	}
	var result helperSemanticResult
	if err := generationstop.DecodeCanonicalJSON(resultBytes, &result); err != nil {
		return fmt.Errorf("helper semantic result is invalid: %w", err)
	}
	unsealed := helperSemanticResultUnsealed{
		Checks: result.Checks, Contract: result.Contract, Execution: result.Execution,
		Failure: result.Failure, Outcome: result.Outcome, Preview: result.Preview, Request: result.Request,
	}
	unsealedBytes, err := generationstop.CanonicalJSON(unsealed)
	if err != nil || result.Contract != "ambit.c18-specialist-render-command-result/v2" ||
		result.Digest != sha256Digest(unsealedBytes) || result.Digest != start.ResultDigest ||
		result.Request != collector.request || result.Outcome != start.Outcome ||
		result.Execution.ExecutorRevision != pinToHelper(collector.policy.Executor) ||
		result.Execution.StartedAt == "" || result.Execution.CompletedAt == "" {
		return errors.New("helper semantic result identity or seal differs")
	}
	if collector.files[0].File.Path != collector.command.Output.ResultPath {
		return errors.New("helper result file path differs from command")
	}
	if collector.files[0].File.MediaType != "application/vnd.ambit.c18-specialist-render-command-result+json" {
		return errors.New("helper result file media type differs")
	}
	started, startErr := parseProviderTime(result.Execution.StartedAt)
	completed, completeErr := parseProviderTime(result.Execution.CompletedAt)
	if startErr != nil || completeErr != nil || completed.Before(started) {
		return errors.New("helper semantic result execution time is invalid")
	}
	if (result.Outcome == "succeeded" && (result.Preview == nil || result.Failure != nil)) ||
		(result.Outcome != "succeeded" && (result.Preview != nil || result.Failure == nil)) {
		return errors.New("helper semantic result outcome relation differs")
	}
	if result.Failure != nil && (!helperTokenPattern.MatchString(result.Failure.Code) ||
		len(result.Failure.Code) > 128 || result.Failure.Message == "" ||
		len(result.Failure.Message) > 2048 || strings.TrimSpace(result.Failure.Message) != result.Failure.Message) {
		return errors.New("helper semantic result failure is invalid")
	}

	fileByPath := make(map[string]Payload, len(collector.files))
	for _, payload := range collector.files {
		fileByPath[payload.File.Path] = payload
	}
	evidenceFiles := make([]Payload, 0)
	artifactFiles := make([]Payload, 0)
	previewSeen := false
	for _, payload := range collector.files[1:] {
		switch payload.File.Role {
		case "preview":
			if previewSeen {
				return errors.New("helper emitted more than one preview file")
			}
			previewSeen = true
			if result.Preview == nil || !descriptorMatchesPreview(payload.File, *result.Preview) {
				return errors.New("helper preview file differs from semantic result")
			}
			if result.Preview.Path != collector.command.Output.PreviewPath ||
				result.Preview.MediaType != collector.command.Output.PreviewMediaType ||
				result.Preview.ByteLength > collector.command.Output.MaximumPreviewBytes {
				return errors.New("helper preview descriptor differs from command")
			}
			previewBytes, err := readPayloadBounded(payload, 16*1024*1024)
			if err != nil {
				return err
			}
			var preview helperSemanticPreview
			if err := generationstop.DecodeCanonicalJSON(previewBytes, &preview); err != nil {
				return fmt.Errorf("helper semantic preview is invalid: %w", err)
			}
			previewUnsealed := helperSemanticPreviewUnsealed{
				Contract: preview.Contract, Facet: preview.Facet, Facts: preview.Facts,
				Limitations: preview.Limitations, SchemaVersion: preview.SchemaVersion,
				Summary: preview.Summary, Title: preview.Title,
				Validation: preview.Validation, Views: preview.Views,
			}
			previewUnsealedBytes, err := generationstop.CanonicalJSON(previewUnsealed)
			if err != nil || preview.Contract != "ambit.c18-specialist-artifact-preview/v1" ||
				preview.SchemaVersion != 1 || preview.Digest != sha256Digest(previewUnsealedBytes) ||
				preview.Digest != result.Preview.EnvelopeDigest {
				return errors.New("helper semantic preview identity or seal differs")
			}
		case "evidence":
			evidenceFiles = append(evidenceFiles, payload)
		case "artifact":
			artifactFiles = append(artifactFiles, payload)
		}
	}
	if (result.Preview != nil) != previewSeen {
		return errors.New("helper preview transport presence differs from semantic result")
	}
	checkNames := make([]string, 0, len(result.Checks))
	expectedEvidence := make([]helperExpectedEvidence, 0)
	for _, check := range result.Checks {
		if check.Check == "" || (check.Outcome != "passed" && check.Outcome != "failed" && check.Outcome != "blocked") {
			return errors.New("helper semantic result check is invalid")
		}
		checkNames = append(checkNames, check.Check)
		if check.Evidence != nil {
			expectedEvidence = append(expectedEvidence, helperExpectedEvidence{
				descriptor: *check.Evidence, check: check.Check, outcome: check.Outcome,
			})
		}
	}
	if !strictlySorted(checkNames) || len(expectedEvidence) != len(evidenceFiles) {
		return errors.New("helper semantic result check/evidence order differs")
	}
	commandChecks := make([]string, len(collector.command.PackRequiredChecks))
	for index, check := range collector.command.PackRequiredChecks {
		commandChecks[index] = check.Check
	}
	if result.Outcome == "succeeded" {
		if len(checkNames) != len(commandChecks) {
			return errors.New("successful helper result checks differ from command")
		}
		for index := range checkNames {
			if checkNames[index] != commandChecks[index] || result.Checks[index].Outcome != "passed" ||
				result.Checks[index].Evidence == nil {
				return errors.New("successful helper result checks differ from command")
			}
		}
	} else {
		allowed := make(map[string]struct{}, len(commandChecks))
		for _, check := range commandChecks {
			allowed[check] = struct{}{}
		}
		for _, check := range checkNames {
			if _, exists := allowed[check]; !exists {
				return errors.New("failed helper result contains an unrequested check")
			}
		}
	}
	expectedArtifacts := make(map[string]helperArtifactDescriptor)
	for index, expectedEvidenceItem := range expectedEvidence {
		descriptor := expectedEvidenceItem.descriptor
		if !descriptorMatchesFile(evidenceFiles[index].File, descriptor) {
			return errors.New("helper evidence transport differs from result descriptor")
		}
		evidenceBytes, err := readPayloadBounded(evidenceFiles[index], 1*1024*1024)
		if err != nil {
			return err
		}
		var evidence helperSemanticEvidence
		if err := generationstop.DecodeCanonicalJSON(evidenceBytes, &evidence); err != nil {
			return fmt.Errorf("helper evidence is invalid: %w", err)
		}
		evidenceUnsealed := helperSemanticEvidenceUnsealed{
			Artifacts: evidence.Artifacts, Check: evidence.Check, Contract: evidence.Contract,
			ExecutorRevision: evidence.ExecutorRevision, Facts: evidence.Facts,
			Outcome: evidence.Outcome, Request: evidence.Request,
		}
		evidenceUnsealedBytes, err := generationstop.CanonicalJSON(evidenceUnsealed)
		if err != nil || evidence.Contract != "ambit.c18-specialist-render-check-evidence/v1" ||
			evidence.Digest != sha256Digest(evidenceUnsealedBytes) ||
			evidence.ExecutorRevision != pinToHelper(collector.policy.Executor) ||
			evidence.Request != (helperEvidenceRequest{
				Digest: collector.request.Digest, JobRef: collector.request.JobRef,
				SourceDigest: collector.sourceDigest,
			}) || evidence.Check != expectedEvidenceItem.check || evidence.Outcome != expectedEvidenceItem.outcome {
			return errors.New("helper semantic evidence identity or seal differs")
		}
		factKeys := make([]string, len(evidence.Facts))
		for factIndex, fact := range evidence.Facts {
			factKeys[factIndex] = fact.Key
		}
		if !strictlySorted(factKeys) {
			return errors.New("helper evidence facts are not sorted and unique")
		}
		artifactPaths := make([]string, len(evidence.Artifacts))
		for artifactIndex, artifact := range evidence.Artifacts {
			artifactPaths[artifactIndex] = artifact.Path
		}
		if !strictlySorted(artifactPaths) && len(artifactPaths) > 1 {
			return errors.New("helper evidence artifacts are not sorted and unique")
		}
		for _, artifact := range evidence.Artifacts {
			if existing, exists := expectedArtifacts[artifact.Path]; exists && existing != artifact {
				return errors.New("helper evidence artifact identity conflicts")
			}
			expectedArtifacts[artifact.Path] = artifact
		}
	}
	if len(expectedArtifacts) != len(artifactFiles) {
		return errors.New("helper artifact transport differs from evidence descriptors")
	}
	// Transport artifacts are globally path-sorted. Evidence documents are in
	// result order, so compare through the exact path map after proving the
	// transport order itself.
	artifactPaths := make([]string, len(artifactFiles))
	for index, payload := range artifactFiles {
		artifactPaths[index] = payload.File.Path
	}
	if !strictlySorted(artifactPaths) && len(artifactPaths) > 1 {
		return errors.New("helper transport artifacts are not path-sorted")
	}
	for _, descriptor := range expectedArtifacts {
		payload, exists := fileByPath[descriptor.Path]
		if !exists || payload.File.Role != "artifact" || !descriptorMatchesFile(payload.File, descriptor) {
			return errors.New("helper artifact differs from evidence descriptor")
		}
	}
	return nil
}

func readPayloadBounded(payload Payload, maximum int64) ([]byte, error) {
	if payload.File.ByteLength <= 0 || payload.File.ByteLength > maximum {
		return nil, errors.New("semantic payload exceeds its bound")
	}
	reader, err := payload.Open(context.Background())
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	value, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(value)) != payload.File.ByteLength {
		return nil, errors.New("semantic payload bytes differ")
	}
	return value, nil
}

func descriptorMatchesFile(file OutputFile, descriptor helperArtifactDescriptor) bool {
	return file.Path == descriptor.Path && file.MediaType == descriptor.MediaType &&
		file.ByteLength == descriptor.ByteLength && file.Digest == descriptor.Digest
}

func descriptorMatchesPreview(file OutputFile, descriptor helperPreviewDescriptor) bool {
	return file.Path == descriptor.Path && file.MediaType == descriptor.MediaType &&
		file.ByteLength == descriptor.ByteLength && file.Digest == descriptor.BytesDigest &&
		exactDigest(descriptor.EnvelopeDigest)
}

func strictlySorted(values []string) bool {
	for index, value := range values {
		if value == "" || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}

func writeHelperRequest(writer io.Writer, request ProviderExecutionRequest) error {
	write := func(value any) error {
		line, err := generationstop.CanonicalJSON(value)
		if err != nil {
			return err
		}
		if len(line)+1 > MaximumFrameBytes {
			return errors.New("helper request frame exceeds its bound")
		}
		_, err = writer.Write(append(line, '\n'))
		return err
	}
	if err := write(helperRequestStart{
		ChunkBytes: RequestChunkBytes, Kind: "request_start", Nonce: request.Nonce,
		RequestBytes:      request.Request.ByteLength,
		RequestChunkCount: int((request.Request.ByteLength + RequestChunkBytes - 1) / RequestChunkBytes),
		RequestDigest:     request.Request.Digest, Schema: FrameSchema,
		SourceBytes:      request.Source.ByteLength,
		SourceChunkCount: int((request.Source.ByteLength + RequestChunkBytes - 1) / RequestChunkBytes),
		SourceDigest:     request.Source.Digest,
	}); err != nil {
		return err
	}
	if err := writeHelperInput(writer, write, request.Nonce, "request_chunk", request.Request); err != nil {
		return err
	}
	if err := writeHelperInput(writer, write, request.Nonce, "source_chunk", request.Source); err != nil {
		return err
	}
	return write(helperRequestEnd{
		Kind: "request_end", Nonce: request.Nonce,
		RequestBytes:      request.Request.ByteLength,
		RequestChunkCount: int((request.Request.ByteLength + RequestChunkBytes - 1) / RequestChunkBytes),
		RequestDigest:     request.Request.Digest, Schema: FrameSchema,
		SourceBytes:      request.Source.ByteLength,
		SourceChunkCount: int((request.Source.ByteLength + RequestChunkBytes - 1) / RequestChunkBytes),
		SourceDigest:     request.Source.Digest,
	})
}

func writeHelperInput(
	writer io.Writer,
	write func(any) error,
	nonce string,
	kind string,
	input Input,
) error {
	reader, err := input.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	remaining := input.ByteLength
	index := 0
	observed := sha256.New()
	for remaining > 0 {
		size := int64(RequestChunkBytes)
		if remaining < size {
			size = remaining
		}
		chunk := make([]byte, int(size))
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return err
		}
		_, _ = observed.Write(chunk)
		if err := write(helperChunk{
			Base64: base64.StdEncoding.EncodeToString(chunk), Bytes: len(chunk), Index: index,
			Kind: kind, Nonce: nonce, Schema: FrameSchema, Digest: sha256Digest(chunk),
		}); err != nil {
			return err
		}
		remaining -= int64(len(chunk))
		index++
	}
	var extra [1]byte
	count, readErr := reader.Read(extra[:])
	if count != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) || hashDigest(observed) != input.Digest {
		return errors.New("provider-private input differs while framing")
	}
	return nil
}

func writeHelperCancel(writer io.Writer, nonce string) error {
	line, err := generationstop.CanonicalJSON(helperCancel{Kind: "cancel", Nonce: nonce, Schema: FrameSchema})
	if err != nil {
		return err
	}
	_, err = writer.Write(append(line, '\n'))
	return err
}

func pinToHelper(pin Pin) helperPin {
	return helperPin{Digest: pin.Digest, Ref: pin.Ref}
}

func helperRoleOrder(ordinal int, role string, previous string) bool {
	if ordinal == 1 {
		return role == "result"
	}
	switch role {
	case "preview":
		return previous == "result"
	case "evidence":
		return previous == "result" || previous == "preview" || previous == "evidence"
	case "artifact":
		return previous == "result" || previous == "preview" || previous == "evidence" || previous == "artifact"
	default:
		return false
	}
}

func safeOutputPath(value string) bool {
	if !strings.HasPrefix(value, "outputs/") || len([]byte(value)) > MaximumOutputPathBytes || strings.ContainsAny(value, `\\:`) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean != value || strings.Contains(value, "/../") || strings.HasSuffix(value, "/..") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".sock") {
			return false
		}
		for _, character := range part {
			if !((character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				character == '.' || character == '_' || character == '-') {
				return false
			}
		}
	}
	return true
}

func safeInputPath(value string) bool {
	if !strings.HasPrefix(value, "inputs/") || len(value) > 2048 || strings.ContainsAny(value, `\\:`) {
		return false
	}
	return safeOutputPath("outputs/" + strings.TrimPrefix(value, "inputs/"))
}

func jsonUnmarshalKind(line []byte, target *frameKind) error {
	// DecodeCanonicalJSON into the one-field projection would reject every
	// legitimate frame as having extra fields. A preliminary generic unmarshal
	// selects the closed concrete schema; that concrete decode then rejects
	// duplicates, extras, and noncanonical bytes before any state change.
	if err := json.Unmarshal(line, target); err != nil || target.Kind == "" {
		return errors.New("helper frame kind is invalid")
	}
	return nil
}
