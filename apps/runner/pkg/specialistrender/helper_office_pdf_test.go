// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
)

func officePDFCommandFixture(t *testing.T) (helperPDFCommand, Request, Policy) {
	t.Helper()
	data, err := os.ReadFile("testdata/office-pdf-request.v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var command helperPDFCommand
	if err := generationstop.DecodeCanonicalJSON(data, &command); err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(t)
	policy.Image.PackID, policy.Image.PackRef = "office-authoring", officePDFPack
	policy.Executor.Ref, policy.Executable = officePDFExecutor, "/opt/ambit/runtime-pack/office-authoring/bin/ambit-specialist-render"
	authority := Request{ArtifactRenderJobRef: command.JobRef, SourceBytes: command.Source.ByteLength, SourceDigest: command.Source.Digest, RequestDigest: sha256Digest(data)}
	return command, authority, policy
}

func TestOfficePDFCommandBindsSourcePolicyAndBounds(t *testing.T) {
	command, authority, policy := officePDFCommandFixture(t)
	for mediaType := range officePDFMediaTypes {
		candidate := command
		candidate.Source.MediaType = mediaType
		body, _ := generationstop.CanonicalJSON(candidate.helperPDFCommandBody)
		candidate.Digest = sha256Digest(body)
		data, _ := generationstop.CanonicalJSON(candidate)
		authority.RequestDigest = sha256Digest(data)
		input := Input{ByteLength: int64(len(data)), Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }}
		if _, err := parseHelperCommand(input, authority, policy); err != nil {
			t.Fatalf("admitted Office kind failed: %v", err)
		}
	}
	for _, mutate := range []func(*helperPDFCommand){
		func(c *helperPDFCommand) { c.Source.ByteLength++ },
		func(c *helperPDFCommand) { c.Source.ByteLength = officePDFMaximumSourceBytes + 1 },
		func(c *helperPDFCommand) { c.Source.MediaType = "application/pdf" },
		func(c *helperPDFCommand) { c.Source.Path = "inputs/request.json" },
		func(c *helperPDFCommand) { c.Source.Path = "inputs/../source.docx" },
		func(c *helperPDFCommand) { c.Renderer.PolicyRef = "ambit.render-policy/other@1" },
		func(c *helperPDFCommand) { c.Output.MaximumPDFBytes = officePDFMaximumBytes + 1 },
		func(c *helperPDFCommand) { c.Output.PDFPath = c.Output.ResultPath },
		func(c *helperPDFCommand) { c.Output.PDFPath = "outputs/foreign/document.pdf" },
		func(c *helperPDFCommand) {
			c.Runtime.PackRevisions = []Pin{{Ref: "ambit.runtime-pack/office-authoring@1", Digest: c.Source.Digest}}
		},
		func(c *helperPDFCommand) { c.Operation = "render_validate" },
	} {
		candidate := command
		mutate(&candidate)
		body, _ := generationstop.CanonicalJSON(candidate.helperPDFCommandBody)
		candidate.Digest = sha256Digest(body)
		data, _ := generationstop.CanonicalJSON(candidate)
		if _, err := parseOfficePDFCommand(data, authority, policy); err == nil {
			t.Fatal("forged Office command was admitted")
		}
	}
	policy.Image.PackRef = "ambit.runtime-pack/office-authoring@1"
	data, _ := generationstop.CanonicalJSON(command)
	if _, err := parseOfficePDFCommand(data, authority, policy); err == nil {
		t.Fatal("revision one authorized the PDF operation")
	}
}

func TestOfficePDFResultAdmitsOnlyItsSourceBoundCompletePDF(t *testing.T) {
	command, authority, policy := officePDFCommandFixture(t)
	data, _ := generationstop.CanonicalJSON(command)
	normalized, err := parseOfficePDFCommand(data, authority, policy)
	if err != nil {
		t.Fatal(err)
	}
	pdf := []byte("%PDF-1.7\nprotocol custody fixture\n%%EOF\n")
	result := helperPDFResult{helperPDFResultBody: helperPDFResultBody{
		Contract: officePDFResultContract, Operation: officePDFOperation, Outcome: "succeeded",
		Request:   helperRequestIdentity{Digest: command.Digest, JobRef: command.JobRef, JobRoot: command.JobRoot},
		Source:    helperPDFSourceIdentity{ByteLength: command.Source.ByteLength, Digest: command.Source.Digest, MediaType: command.Source.MediaType},
		Execution: helperResultExecution{ExecutorRevision: pinToHelper(policy.Executor), StartedAt: "2026-09-09T23:00:00.000Z", CompletedAt: "2026-09-09T23:00:01.000Z"},
		PDF:       &helperArtifactDescriptor{Path: command.Output.PDFPath, MediaType: "application/pdf", ByteLength: int64(len(pdf)), Digest: sha256Digest(pdf)},
	}}
	validate := func(candidate helperPDFResult, payload []byte, count int) error {
		body, _ := generationstop.CanonicalJSON(candidate.helperPDFResultBody)
		candidate.Digest = sha256Digest(body)
		encoded, _ := generationstop.CanonicalJSON(candidate)
		files := []Payload{{File: OutputFile{Path: command.Output.ResultPath, MediaType: "application/vnd.ambit.c18-specialist-render-command-result+json"}},
			{File: OutputFile{Role: "artifact", Path: command.Output.PDFPath, MediaType: "application/pdf", ByteLength: int64(len(pdf)), Digest: sha256Digest(pdf)}, Open: func(context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil }}}
		collector := helperCollector{command: normalized, policy: policy, request: result.Request, files: files[:count]}
		return collector.validateOfficePDFResult(helperResponseStart{ResultDigest: candidate.Digest, Outcome: candidate.Outcome}, encoded)
	}
	if err := validate(result, pdf, 2); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*helperPDFResult){
		func(r *helperPDFResult) { r.Source.Digest = sha256Digest([]byte("other source")) },
		func(r *helperPDFResult) { r.Request.JobRef += "-other" },
		func(r *helperPDFResult) {
			r.Execution.ExecutorRevision.Ref = "ambit://specialist-render-executors/office-authoring@1"
		},
		func(r *helperPDFResult) { r.Execution.CompletedAt = "2026-09-08T23:00:00.000Z" },
		func(r *helperPDFResult) { r.PDF.Path = "outputs/render/other.pdf" },
		func(r *helperPDFResult) { r.PDF.ByteLength = officePDFMaximumBytes + 1 },
		func(r *helperPDFResult) {
			r.Outcome = "failed"
			r.Failure = &helperResultFailure{Code: "invalid_office_source", Message: "Invalid Office source."}
		},
	} {
		candidate := result
		descriptor := *result.PDF
		candidate.PDF = &descriptor
		mutate(&candidate)
		if err := validate(candidate, pdf, 2); err == nil {
			t.Fatal("forged Office result was admitted")
		}
	}
	for _, invalid := range [][]byte{[]byte("invalid\n%%EOF"), []byte("%PDF-1.7\ntruncated")} {
		if err := validate(result, invalid, 2); err == nil {
			t.Fatal("incomplete PDF was admitted")
		}
	}
	failure := result
	failure.Outcome = "failed"
	failure.PDF = nil
	failure.Failure = &helperResultFailure{Code: "invalid_office_source", Message: "Invalid Office source."}
	if err := validate(failure, nil, 1); err != nil {
		t.Fatal(err)
	}
	if err := validate(failure, pdf, 2); err == nil {
		t.Fatal("failed conversion retained PDF output")
	}
}

func TestOfficePDFRejectsUnknownAndMissingFields(t *testing.T) {
	command, authority, policy := officePDFCommandFixture(t)
	data, _ := generationstop.CanonicalJSON(command)
	var fields map[string]any
	json.Unmarshal(data, &fields)
	fields["facet"] = "document"
	data, _ = generationstop.CanonicalJSON(fields)
	if _, err := parseOfficePDFCommand(data, authority, policy); err == nil {
		t.Fatal("unknown command fields were admitted")
	}
	delete(fields, "facet")
	delete(fields, "deadlineAt")
	data, _ = generationstop.CanonicalJSON(fields)
	if _, err := parseOfficePDFCommand(data, authority, policy); err == nil {
		t.Fatal("missing command field was admitted")
	}
}
