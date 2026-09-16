// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import "github.com/daytonaio/runner/pkg/generationstop"

const SandboxFileCaptureContract = "daytona.sandbox-file-capture/v1"

// SandboxFileRequest is sent only by the authenticated provider API. The API
// derives OrganizationID from current sandbox ownership, never from public JSON.
type SandboxFileRequest struct {
	OrganizationID string `json:"organizationId" validate:"required"`
	OperationID    string `json:"operationId" validate:"required"`
	Path           string `json:"path" validate:"required"`
}

type SandboxFileObserveRequest struct {
	OrganizationID string  `json:"organizationId" validate:"required"`
	OperationID    string  `json:"operationId" validate:"required"`
	Path           *string `json:"path,omitempty"`
}

// SandboxFileSource freezes native authority and implementation once, in the
// same private intent that owns capture publication and recovery.
type SandboxFileSource struct {
	Contract       string                            `json:"contract"`
	OrganizationID string                            `json:"organizationId"`
	SandboxID      string                            `json:"sandboxId"`
	OperationID    string                            `json:"operationId"`
	Generation     generationstop.ExpectedGeneration `json:"generation"`
	Component      CaptureComponent                  `json:"component"`
}

type SandboxFileReceipt struct {
	Contract        string                            `json:"contract" validate:"required"`
	CaptureID       string                            `json:"captureId" validate:"required"`
	OperationID     string                            `json:"operationId" validate:"required"`
	OrganizationID  string                            `json:"organizationId" validate:"required"`
	SandboxID       string                            `json:"sandboxId" validate:"required"`
	Path            string                            `json:"path" validate:"required"`
	Generation      generationstop.ExpectedGeneration `json:"generation" validate:"required"`
	Component       CaptureComponent                  `json:"component" validate:"required"`
	TotalByteLength int64                             `json:"totalByteLength" validate:"required"`
	SHA256          string                            `json:"sha256" validate:"required"`
	CapturedAt      string                            `json:"capturedAt" validate:"required"`
}

type SandboxFileObservation struct {
	Status  string              `json:"status" validate:"required" enums:"absent,pending,complete,retired"`
	Receipt *SandboxFileReceipt `json:"receipt,omitempty"`
}

type SandboxFileReadRequest struct {
	Receipt      SandboxFileReceipt `json:"receipt" validate:"required"`
	Offset       int64              `json:"offset" validate:"required"`
	MaximumBytes int64              `json:"maximumBytes" validate:"required"`
}

type SandboxFileReadResponse struct {
	CaptureID       string `json:"captureId" validate:"required"`
	TotalByteLength int64  `json:"totalByteLength" validate:"required"`
	SHA256          string `json:"sha256" validate:"required"`
	Offset          int64  `json:"offset" validate:"required"`
	ByteLength      int64  `json:"byteLength" validate:"required"`
	EOF             bool   `json:"eof" validate:"required"`
	BytesBase64     string `json:"bytesBase64" validate:"required"`
}

type SandboxFileDeleteRequest struct {
	Receipt        *SandboxFileReceipt `json:"receipt,omitempty"`
	OrganizationID string              `json:"organizationId,omitempty"`
	OperationID    string              `json:"operationId,omitempty"`
	Path           string              `json:"path,omitempty"`
}

type SandboxFileDeleteReceipt struct {
	CaptureID *string `json:"captureId" validate:"required" extensions:"x-nullable"`
	Outcome   string  `json:"outcome" validate:"required" enums:"deleted,already_absent"`
}

// Retirement precedes cleanup and can exist before a source generation was
// admitted. It fences an operation without inventing a capture or Product grant.
type sandboxFileRetirement struct {
	SandboxID string             `json:"sandboxId"`
	Request   SandboxFileRequest `json:"request"`
}
