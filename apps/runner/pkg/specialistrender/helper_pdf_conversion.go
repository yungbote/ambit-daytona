// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/daytonaio/runner/pkg/generationstop"
)

const helperPDFRequestContract = "ambit.c18-specialist-render-command-request/v3"
const helperPDFResultContract = "ambit.c18-specialist-render-command-result/v3"
const maximumOfficeSourceBytes int64 = 64 * 1024 * 1024
const maximumOfficePDFBytes int64 = 256 * 1024 * 1024

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

type helperPDFCommand struct {
	Contract    string              `json:"contract"`
	DeadlineAt  string              `json:"deadlineAt"`
	Digest      string              `json:"digest"`
	JobRef      string              `json:"jobRef"`
	JobRoot     string              `json:"jobRoot"`
	Operation   string              `json:"operation"`
	Output      helperPDFOutput     `json:"output"`
	Renderer    helperPDFRenderer   `json:"renderer"`
	RequestPath string              `json:"requestPath"`
	Runtime     json.RawMessage     `json:"runtime"`
	Source      helperCommandSource `json:"source"`
}

type helperPDFSource struct {
	ByteLength int64  `json:"byteLength"`
	Digest     string `json:"digest"`
	MediaType  string `json:"mediaType"`
}

type helperPDFResult struct {
	Contract  string                    `json:"contract"`
	Digest    string                    `json:"digest"`
	Execution helperResultExecution     `json:"execution"`
	Failure   *helperResultFailure      `json:"failure"`
	Operation string                    `json:"operation"`
	Outcome   string                    `json:"outcome"`
	PDF       *helperArtifactDescriptor `json:"pdf"`
	Request   helperRequestIdentity     `json:"request"`
	Source    helperPDFSource           `json:"source"`
}

func officeSourceMediaType(mediaType string) bool {
	switch mediaType {
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return true
	default:
		return false
	}
}

func exactSemanticSeal(value any, digest string) bool {
	encoded, err := generationstop.CanonicalJSON(value)
	if err != nil || !exactDigest(digest) {
		return false
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &body); err != nil {
		return false
	}
	delete(body, "digest")
	unsealed, err := generationstop.CanonicalJSON(body)
	return err == nil && sha256Digest(unsealed) == digest
}

// Only semantic conversion admission differs; framing, process ownership,
// provider custody, cancellation and parent-generation proofs are shared.
func parseHelperPDFCommand(value []byte, authority Request, policy Policy) (helperCommand, error) {
	var command helperPDFCommand
	if err := generationstop.DecodeCanonicalJSON(value, &command); err != nil {
		return helperCommand{}, err
	}
	jobID := strings.TrimPrefix(authority.ArtifactRenderJobRef, "ambit://artifact-render-jobs/")
	if command.Contract != helperPDFRequestContract || command.Operation != "convert_to_pdf" ||
		!exactSemanticSeal(command, command.Digest) || command.JobRef != authority.ArtifactRenderJobRef ||
		command.JobRoot != "/workspace/.ambit/render-jobs/"+jobID || command.RequestPath != "inputs/request.json" ||
		command.Source.ByteLength <= 0 || command.Source.ByteLength > maximumOfficeSourceBytes ||
		command.Source.ByteLength != authority.SourceBytes || command.Source.Digest != authority.SourceDigest ||
		!officeSourceMediaType(command.Source.MediaType) || !safeInputPath(command.Source.Path) ||
		!boundedOperationalRef(command.Source.Ref, 512) || !bytes.Equal(command.Source.SchemaURI, []byte("null")) ||
		command.Renderer.ExecutablePath != policy.Executable || policy.Image.PackID != "office-authoring" ||
		command.Renderer.RendererRef != "ambit.renderer/office-pdf@1" || command.Renderer.PolicyRef != "ambit.render-policy/office-pdf@1" ||
		command.Output.MaximumPDFBytes <= 0 || command.Output.MaximumPDFBytes > maximumOfficePDFBytes ||
		!safeOutputPath(command.Output.ResultPath) || !safeOutputPath(command.Output.PDFPath) ||
		command.Output.PDFPath == command.Output.ResultPath ||
		!safeOutputPath(command.Output.JobOutputRoot+"/sentinel") ||
		!strings.HasPrefix(command.Output.PDFPath, command.Output.JobOutputRoot+"/") ||
		!strings.HasPrefix(command.Output.ResultPath, command.Output.JobOutputRoot+"/") || len(command.Runtime) == 0 {
		return helperCommand{}, errors.New("Office PDF command authority, bounds or seal differs")
	}
	if _, err := parseProviderTime(command.DeadlineAt); err != nil {
		return helperCommand{}, errors.New("Office PDF command deadline is invalid")
	}
	return helperCommand{
		conversion: &command, Contract: command.Contract, Digest: command.Digest,
		JobRef: command.JobRef, JobRoot: command.JobRoot, Source: command.Source,
		RequestPath: command.RequestPath, DeadlineAt: command.DeadlineAt, Operation: command.Operation,
		Output: helperCommandOutput{JobOutputRoot: command.Output.JobOutputRoot, ResultPath: command.Output.ResultPath},
	}, nil
}

func (collector *helperCollector) validatePDFSemantics(start helperResponseStart) error {
	command := collector.command.conversion
	if command == nil || len(collector.files) < 1 {
		return errors.New("Office PDF result is absent")
	}
	resultFile := collector.files[0]
	if resultFile.File.Path != command.Output.ResultPath || resultFile.File.MediaType != "application/vnd.ambit.c18-specialist-render-command-result+json" {
		return errors.New("Office PDF result file identity differs")
	}
	payload, err := readPayloadBounded(resultFile, MaximumRequestBytes)
	if err != nil {
		return err
	}
	var result helperPDFResult
	if err := generationstop.DecodeCanonicalJSON(payload, &result); err != nil {
		return err
	}
	source := helperPDFSource{ByteLength: command.Source.ByteLength, Digest: command.Source.Digest, MediaType: command.Source.MediaType}
	if result.Contract != helperPDFResultContract || result.Operation != "convert_to_pdf" ||
		!exactSemanticSeal(result, result.Digest) || result.Digest != start.ResultDigest ||
		result.Request != collector.request || result.Source != source || result.Outcome != start.Outcome ||
		result.Execution.ExecutorRevision != pinToHelper(collector.policy.Executor) {
		return errors.New("Office PDF result source, operation or seal differs")
	}
	started, startErr := parseProviderTime(result.Execution.StartedAt)
	completed, endErr := parseProviderTime(result.Execution.CompletedAt)
	if startErr != nil || endErr != nil || completed.Before(started) {
		return errors.New("Office PDF result times are invalid")
	}
	if result.Outcome == "succeeded" {
		if result.Failure != nil || result.PDF == nil || len(collector.files) != 2 ||
			result.PDF.MediaType != "application/pdf" || result.PDF.Path != command.Output.PDFPath ||
			result.PDF.ByteLength <= 0 || result.PDF.ByteLength > command.Output.MaximumPDFBytes ||
			collector.files[1].File.Role != "artifact" || !descriptorMatchesFile(collector.files[1].File, *result.PDF) {
			return errors.New("Office PDF result does not match its exact transported PDF")
		}
		return nil
	}
	if result.PDF != nil || len(collector.files) != 1 || result.Failure == nil ||
		!helperTokenPattern.MatchString(result.Failure.Code) || len(result.Failure.Code) > 128 ||
		result.Failure.Message == "" || len(result.Failure.Message) > 2048 || strings.TrimSpace(result.Failure.Message) != result.Failure.Message {
		return errors.New("Office PDF failure retains output or lacks a bounded reason")
	}
	return nil
}
