// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/daytonaio/runner/pkg/generationstop"
)

const (
	officePDFRequestContract    = "ambit.c18-specialist-render-command-request/v3"
	officePDFResultContract     = "ambit.c18-specialist-render-command-result/v3"
	officePDFOperation          = "convert_to_pdf"
	officePDFPack               = "ambit.runtime-pack/office-authoring@2"
	officePDFExecutor           = "ambit://specialist-render-executors/office-authoring@2"
	officePDFMaximumSourceBytes = 64 * 1024 * 1024
	officePDFMaximumBytes       = 256 * 1024 * 1024
)

var officePDFMediaTypes = map[string]bool{
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         true,
}

type helperPDFRenderer struct {
	ExecutablePath string `json:"executablePath"`
	PolicyRef      string `json:"policyRef"`
	RendererRef    string `json:"rendererRef"`
}

type helperPDFOutput struct {
	JobOutputRoot   string `json:"jobOutputRoot"`
	MaximumPDFBytes int64  `json:"maximumPdfBytes"`
	PDFPath         string `json:"pdfPath"`
	ResultPath      string `json:"resultPath"`
}

type helperPDFRuntime struct {
	PackRevisions              []Pin `json:"packRevisions"`
	ProfileRevision            Pin   `json:"profileRevision"`
	WorkspaceExecutionManifest Pin   `json:"workspaceExecutionManifest"`
}

type helperPDFCommandBody struct {
	Contract    string              `json:"contract"`
	DeadlineAt  string              `json:"deadlineAt"`
	JobRef      string              `json:"jobRef"`
	JobRoot     string              `json:"jobRoot"`
	Operation   string              `json:"operation"`
	Output      helperPDFOutput     `json:"output"`
	RequestPath string              `json:"requestPath"`
	Renderer    helperPDFRenderer   `json:"renderer"`
	Runtime     helperPDFRuntime    `json:"runtime"`
	Source      helperCommandSource `json:"source"`
}

type helperPDFCommand struct {
	helperPDFCommandBody
	Digest string `json:"digest"`
}

func parseOfficePDFCommand(value []byte, authority Request, policy Policy) (helperCommand, error) {
	var command helperPDFCommand
	if err := generationstop.DecodeCanonicalJSON(value, &command); err != nil {
		return helperCommand{}, errors.New("Office PDF command is not exact canonical JSON")
	}
	body, err := generationstop.CanonicalJSON(command.helperPDFCommandBody)
	jobID := strings.TrimPrefix(authority.ArtifactRenderJobRef, "ambit://artifact-render-jobs/")
	output := command.Output
	if err != nil || command.Contract != officePDFRequestContract || command.Operation != officePDFOperation ||
		command.Digest != sha256Digest(body) || command.JobRef != authority.ArtifactRenderJobRef ||
		command.JobRoot != "/workspace/.ambit/render-jobs/"+jobID ||
		command.Source.ByteLength < 1 || command.Source.ByteLength > officePDFMaximumSourceBytes ||
		command.Source.ByteLength != authority.SourceBytes || command.Source.Digest != authority.SourceDigest ||
		!exactDigest(command.Source.Digest) || !officePDFMediaTypes[command.Source.MediaType] ||
		!boundedOperationalRef(command.Source.Ref, 512) || !bytes.Equal(command.Source.SchemaURI, []byte("null")) ||
		!safeInputPath(command.Source.Path) || command.Source.Path == command.RequestPath ||
		command.RequestPath != "inputs/request.json" ||
		policy.Image.PackRef != officePDFPack || policy.Executor.Ref != officePDFExecutor ||
		command.Renderer.ExecutablePath != policy.Executable ||
		command.Renderer.RendererRef != "ambit.renderer/office-pdf@1" ||
		command.Renderer.PolicyRef != "ambit.render-policy/office-pdf@1" ||
		output.MaximumPDFBytes < 1 || output.MaximumPDFBytes > officePDFMaximumBytes ||
		!safeOutputPath(output.JobOutputRoot+"/sentinel") ||
		!safeOutputPath(output.ResultPath) || !safeOutputPath(output.PDFPath) || output.ResultPath == output.PDFPath ||
		!strings.HasPrefix(output.ResultPath, output.JobOutputRoot+"/") || !strings.HasPrefix(output.PDFPath, output.JobOutputRoot+"/") ||
		!validPin(command.Runtime.ProfileRevision) || !validPin(command.Runtime.WorkspaceExecutionManifest) ||
		len(command.Runtime.PackRevisions) < 1 || len(command.Runtime.PackRevisions) > 32 {
		return helperCommand{}, errors.New("Office PDF command authority, bounds or seal differs")
	}
	if _, err := parseProviderTime(command.DeadlineAt); err != nil {
		return helperCommand{}, errors.New("Office PDF command deadline is invalid")
	}
	refs := make([]string, len(command.Runtime.PackRevisions))
	for index, pin := range command.Runtime.PackRevisions {
		if !validPin(pin) {
			return helperCommand{}, errors.New("Office PDF runtime pack pin is invalid")
		}
		refs[index] = pin.Ref
	}
	if !strictlySorted(refs) || !containsString(refs, officePDFPack) {
		return helperCommand{}, errors.New("Office PDF runtime does not own the exact executor pack")
	}
	return helperCommand{
		pdfConversion: &command, Contract: command.Contract, DeadlineAt: command.DeadlineAt,
		Digest: command.Digest, JobRef: command.JobRef, JobRoot: command.JobRoot,
		Operation: command.Operation, Source: command.Source,
		Output: helperCommandOutput{ResultPath: output.ResultPath, JobOutputRoot: output.JobOutputRoot},
	}, nil
}

type helperPDFSourceIdentity struct {
	ByteLength int64  `json:"byteLength"`
	Digest     string `json:"digest"`
	MediaType  string `json:"mediaType"`
}

type helperPDFResultBody struct {
	Contract  string                    `json:"contract"`
	Execution helperResultExecution     `json:"execution"`
	Failure   *helperResultFailure      `json:"failure"`
	Operation string                    `json:"operation"`
	Outcome   string                    `json:"outcome"`
	PDF       *helperArtifactDescriptor `json:"pdf"`
	Request   helperRequestIdentity     `json:"request"`
	Source    helperPDFSourceIdentity   `json:"source"`
}

type helperPDFResult struct {
	helperPDFResultBody
	Digest string `json:"digest"`
}

func (collector *helperCollector) validateOfficePDFResult(start helperResponseStart, resultBytes []byte) error {
	var result helperPDFResult
	if err := generationstop.DecodeCanonicalJSON(resultBytes, &result); err != nil {
		return errors.New("Office PDF result is not exact canonical JSON")
	}
	body, err := generationstop.CanonicalJSON(result.helperPDFResultBody)
	command := collector.command.pdfConversion
	source := helperPDFSourceIdentity{ByteLength: command.Source.ByteLength, Digest: command.Source.Digest, MediaType: command.Source.MediaType}
	file := collector.files[0].File
	if err != nil || result.Contract != officePDFResultContract || result.Operation != officePDFOperation ||
		result.Digest != sha256Digest(body) || result.Digest != start.ResultDigest ||
		result.Request != collector.request || result.Source != source || result.Outcome != start.Outcome ||
		result.Execution.ExecutorRevision != pinToHelper(collector.policy.Executor) ||
		file.Path != command.Output.ResultPath || file.MediaType != "application/vnd.ambit.c18-specialist-render-command-result+json" {
		return errors.New("Office PDF result identity, source or seal differs")
	}
	started, startErr := parseProviderTime(result.Execution.StartedAt)
	completed, completeErr := parseProviderTime(result.Execution.CompletedAt)
	if startErr != nil || completeErr != nil || completed.Before(started) {
		return errors.New("Office PDF execution time is invalid")
	}
	if result.Outcome != "succeeded" {
		if result.PDF != nil || len(collector.files) != 1 || result.Failure == nil ||
			!helperTokenPattern.MatchString(result.Failure.Code) || len(result.Failure.Code) > 128 ||
			result.Failure.Message == "" || len(result.Failure.Message) > 2048 || strings.TrimSpace(result.Failure.Message) != result.Failure.Message {
			return errors.New("failed Office PDF conversion retained output or lacks a bounded failure")
		}
		return nil
	}
	if result.PDF == nil || result.Failure != nil || len(collector.files) != 2 ||
		result.PDF.Path != command.Output.PDFPath || result.PDF.MediaType != "application/pdf" ||
		result.PDF.ByteLength < 1 || result.PDF.ByteLength > command.Output.MaximumPDFBytes ||
		collector.files[1].File.Role != "artifact" || !descriptorMatchesFile(collector.files[1].File, *result.PDF) {
		return errors.New("Office PDF output differs from its admitted descriptor")
	}
	reader, err := collector.files[1].Open(context.Background())
	if err != nil {
		return err
	}
	defer reader.Close()
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil || !bytes.Equal(header, []byte("%PDF-")) {
		return errors.New("Office PDF output has no PDF header")
	}
	// Framing has already hashed every byte. Check completeness in bounded
	// memory without introducing a second PDF parser into the provider.
	remaining := result.PDF.ByteLength - 5
	if remaining > 1024 {
		if _, err := io.CopyN(io.Discard, reader, remaining-1024); err != nil {
			return err
		}
	}
	trailer, err := io.ReadAll(io.LimitReader(reader, 1025))
	if err != nil || !bytes.Contains(trailer, []byte("%%EOF")) {
		return errors.New("Office PDF output has no completion marker")
	}
	return nil
}
