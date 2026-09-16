// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/google/uuid"
)

const sandboxFileCaptureIDPrefix = "daytona-sandbox-file-capture:v1:sha256:"

type sandboxFileObserver interface {
	ObserveSandboxGeneration(context.Context, string, string) (generationstop.SandboxGenerationObservation, error)
}

// CaptureSandboxFile admits an ordinary filesystem operation. Native provider
// ownership selects the source; Product execution authority is never fabricated.
func (s *Service) CaptureSandboxFile(ctx context.Context, sandboxID string, request SandboxFileRequest) (SandboxFileReceipt, error) {
	selector, err := validateSandboxFileRequest(sandboxID, request)
	if err != nil {
		return SandboxFileReceipt{}, err
	}
	root := sandboxFileObjectRoot(request.OrganizationID, sandboxID, request.OperationID)
	release := s.locks.acquire(root)
	defer release()
	if retired, err := s.sandboxFileRetired(ctx, root, sandboxID, request); err != nil {
		return SandboxFileReceipt{}, err
	} else if retired {
		return SandboxFileReceipt{}, fmt.Errorf("%w: capture operation is retired", ErrConflict)
	}
	intent, exists, err := s.readIntent(ctx, root)
	if err != nil {
		return SandboxFileReceipt{}, err
	}
	var binding CaptureBinding
	if exists {
		if err := requireSandboxFileRequest(intent.Binding, sandboxID, request); err != nil {
			return SandboxFileReceipt{}, err
		}
		binding = intent.Binding
	} else {
		observer, ok := s.fileSnapshots.(sandboxFileObserver)
		if !ok {
			return SandboxFileReceipt{}, fmt.Errorf("%w: native sandbox capture is unavailable", ErrUnavailable)
		}
		if err := ctx.Err(); err != nil {
			return SandboxFileReceipt{}, err
		}
		observed, err := observer.ObserveSandboxGeneration(ctx, sandboxID, request.OrganizationID)
		if err != nil {
			return SandboxFileReceipt{}, err
		}
		binding = CaptureBinding{Selector: selector, SandboxFile: SandboxFileSource{
			Contract: SandboxFileCaptureContract, OrganizationID: request.OrganizationID, SandboxID: sandboxID,
			OperationID: request.OperationID, Generation: observed.Generation.ExpectedGeneration, Component: s.component,
		}}
	}
	zonePath, err := s.validateBinding(sandboxID, binding)
	if err != nil {
		return SandboxFileReceipt{}, err
	}
	receipt, err := s.captureLocked(ctx, zonePath, root, binding)
	if err != nil {
		return SandboxFileReceipt{}, err
	}
	return sandboxFileReceipt(receipt), nil
}

func (s *Service) ObserveSandboxFile(ctx context.Context, sandboxID string, request SandboxFileObserveRequest) (SandboxFileObservation, error) {
	if err := validateSandboxFileOperation(sandboxID, request.OrganizationID, request.OperationID); err != nil {
		return SandboxFileObservation{}, err
	}
	if request.Path != nil {
		if _, err := sandboxFileSelector(*request.Path); err != nil {
			return SandboxFileObservation{}, err
		}
	}
	root := sandboxFileObjectRoot(request.OrganizationID, sandboxID, request.OperationID)
	release := s.locks.acquire(root)
	defer release()
	if deletion, retired, err := s.readDeletion(ctx, root); err != nil {
		return SandboxFileObservation{}, err
	} else if retired {
		if request.Path != nil {
			expected := SandboxFileRequest{OrganizationID: request.OrganizationID, OperationID: request.OperationID, Path: *request.Path}
			if err := requireSandboxFileRetirement(deletion, sandboxID, expected); err != nil {
				return SandboxFileObservation{}, err
			}
		}
		return SandboxFileObservation{Status: "retired"}, nil
	}
	intent, exists, err := s.readIntent(ctx, root)
	if err != nil {
		return SandboxFileObservation{}, err
	}
	if !exists {
		return SandboxFileObservation{Status: "absent"}, nil
	}
	zone, _ := semanticZoneRoot(intent.Binding.Selector.SemanticZoneRef)
	path := zone + "/" + intent.Binding.Selector.ZoneRelativePath
	if request.Path != nil {
		path = *request.Path
	}
	if err := requireSandboxFileRequest(intent.Binding, sandboxID, SandboxFileRequest{OrganizationID: request.OrganizationID, OperationID: request.OperationID, Path: path}); err != nil {
		return SandboxFileObservation{}, err
	}
	observed, err := s.observeLocked(ctx, intent.Binding, nil)
	if err != nil {
		return SandboxFileObservation{}, err
	}
	if observed.Status == "complete" {
		receipt := sandboxFileReceipt(*observed.Receipt)
		return SandboxFileObservation{Status: "complete", Receipt: &receipt}, nil
	}
	return SandboxFileObservation{Status: "pending"}, nil
}

func (s *Service) ReadSandboxFile(ctx context.Context, sandboxID string, request SandboxFileReadRequest) (SandboxFileReadResponse, error) {
	receipt, err := validateSandboxFileReceipt(sandboxID, request.Receipt)
	if err != nil {
		return SandboxFileReadResponse{}, err
	}
	result, err := s.readCapture(ctx, sandboxID, CaptureReadRequest{
		CaptureIdentity: receipt.CaptureIdentity, ExpectedTotalByteLength: receipt.TotalByteLength,
		ExpectedProviderSHA256Digest: receipt.ProviderSHA256Digest, Offset: request.Offset, MaximumBytes: request.MaximumBytes,
	}, &receipt)
	if err != nil {
		return SandboxFileReadResponse{}, err
	}
	return SandboxFileReadResponse{CaptureID: result.ProviderResourceID, TotalByteLength: result.TotalByteLength,
		SHA256: result.ProviderSHA256Digest, Offset: result.Offset, ByteLength: result.ByteLength,
		EOF: result.EOF, BytesBase64: result.BytesBase64}, nil
}

func (s *Service) DeleteSandboxFile(ctx context.Context, sandboxID string, request SandboxFileDeleteRequest) (SandboxFileDeleteReceipt, error) {
	native := SandboxFileRequest{OrganizationID: request.OrganizationID, OperationID: request.OperationID, Path: request.Path}
	var expected *CaptureReceipt
	if request.Receipt != nil {
		if native != (SandboxFileRequest{}) {
			return SandboxFileDeleteReceipt{}, invalidf("delete requires exactly a receipt or an operation")
		}
		receipt, err := validateSandboxFileReceipt(sandboxID, *request.Receipt)
		if err != nil {
			return SandboxFileDeleteReceipt{}, err
		}
		expected = &receipt
		native = SandboxFileRequest{OrganizationID: request.Receipt.OrganizationID, OperationID: request.Receipt.OperationID, Path: request.Receipt.Path}
	}
	if _, err := validateSandboxFileRequest(sandboxID, native); err != nil {
		return SandboxFileDeleteReceipt{}, err
	}
	root := sandboxFileObjectRoot(native.OrganizationID, sandboxID, native.OperationID)
	release := s.locks.acquire(root)
	defer release()
	deletion, retired, err := s.readDeletion(ctx, root)
	if err != nil {
		return SandboxFileDeleteReceipt{}, err
	}
	if retired {
		if err := requireSandboxFileRetirement(deletion, sandboxID, native); err != nil {
			return SandboxFileDeleteReceipt{}, err
		}
	} else {
		deletion = captureDeletion{Version: 2, SandboxFile: sandboxFileRetirement{SandboxID: sandboxID, Request: native}}
	}
	intent, exists, err := s.readIntent(ctx, root)
	if err != nil {
		return SandboxFileDeleteReceipt{}, err
	}
	if exists {
		if err := requireSandboxFileRequest(intent.Binding, sandboxID, native); err != nil {
			return SandboxFileDeleteReceipt{}, err
		}
		if expected != nil && expected.CaptureIdentity != identityFromIntent(intent) {
			return SandboxFileDeleteReceipt{}, fmt.Errorf("%w: native deletion receipt differs", ErrConflict)
		}
		if !retired {
			deletion.Identity = identityFromIntent(intent)
		}
	}
	if expected != nil && deletion.Identity != (CaptureIdentity{}) && deletion.Identity != expected.CaptureIdentity {
		return SandboxFileDeleteReceipt{}, fmt.Errorf("%w: native retirement identity differs", ErrConflict)
	}
	if !retired {
		data, err := json.Marshal(deletion)
		if err != nil {
			return SandboxFileDeleteReceipt{}, err
		}
		if createErr := s.objects.CreatePrivateObject(ctx, deletionKey(root), data, "application/json", map[string]string{"contract": "daytona-sandbox-file-retirement-v1"}); createErr != nil {
			winner, found, readErr := s.readDeletion(ctx, root)
			if readErr != nil || !found {
				return SandboxFileDeleteReceipt{}, errors.Join(fmt.Errorf("%w: retire native file operation: %w", ErrOutcomeUnknown, createErr), readErr)
			}
			if err := requireSandboxFileRetirement(winner, sandboxID, native); err != nil {
				return SandboxFileDeleteReceipt{}, err
			}
			deletion = winner
		}
	}
	// Read once after retirement: an in-flight creator must now fail its normal
	// pre-publication retirement check. Cleanup retains the same exact object
	// keys and can be retried without inspecting a live source.
	intent, exists, err = s.readIntent(ctx, root)
	if err != nil {
		return SandboxFileDeleteReceipt{}, err
	}
	identity := deletion.Identity
	if exists {
		if err := requireSandboxFileRequest(intent.Binding, sandboxID, native); err != nil {
			return SandboxFileDeleteReceipt{}, err
		}
		identity = identityFromIntent(intent)
	}
	result := SandboxFileDeleteReceipt{Outcome: "already_absent"}
	if identity != (CaptureIdentity{}) {
		id := identity.ProviderResourceID
		result.CaptureID = &id
		present, err := s.operationalObjectsPresent(ctx, identity)
		if err != nil {
			return SandboxFileDeleteReceipt{}, err
		}
		if err := s.deleteOperationalObjects(ctx, identity); err != nil {
			return SandboxFileDeleteReceipt{}, err
		}
		if present {
			result.Outcome = "deleted"
		}
	}
	return result, nil
}

func validateSandboxFileRetirement(deletion captureDeletion, root string) error {
	native := deletion.SandboxFile
	if _, err := validateSandboxFileRequest(native.SandboxID, native.Request); err != nil {
		return fmt.Errorf("%w: native retirement request is invalid", ErrConflict)
	}
	if root != sandboxFileObjectRoot(native.Request.OrganizationID, native.SandboxID, native.Request.OperationID) {
		return fmt.Errorf("%w: native retirement scope differs", ErrConflict)
	}
	if deletion.Identity != (CaptureIdentity{}) {
		binding := deletion.Identity.CaptureBinding
		if validateSandboxFileBinding(native.SandboxID, binding) != nil || requireSandboxFileRequest(binding, native.SandboxID, native.Request) != nil ||
			deletion.Identity.ProviderResourceID != providerResourceID(binding, generationstop.TerminalGeneration{}) {
			return fmt.Errorf("%w: native retirement identity is invalid", ErrConflict)
		}
	}
	return nil
}

func requireSandboxFileRetirement(deletion captureDeletion, sandboxID string, request SandboxFileRequest) error {
	if deletion.Version == 2 {
		if deletion.SandboxFile.SandboxID != sandboxID || deletion.SandboxFile.Request != request {
			return fmt.Errorf("%w: native operation retirement differs", ErrConflict)
		}
		return nil
	}
	return requireSandboxFileRequest(deletion.Identity.CaptureBinding, sandboxID, request)
}

func requireProductCapture(binding CaptureBinding) error {
	if binding.SandboxFile != (SandboxFileSource{}) {
		return invalidf("native sandbox authority is not a Product capture binding")
	}
	return nil
}

func (s *Service) requireBindingComponent(binding CaptureBinding) error {
	if binding.SandboxFile == (SandboxFileSource{}) {
		return s.requireCurrentComponent(binding.Authority)
	}
	if binding.SandboxFile.Component != s.component {
		return fmt.Errorf("%w: recorded capture component is not implemented by this Runner", ErrUnavailable)
	}
	return nil
}

func validateSandboxFileRequest(sandboxID string, request SandboxFileRequest) (CaptureSelector, error) {
	if err := validateSandboxFileOperation(sandboxID, request.OrganizationID, request.OperationID); err != nil {
		return CaptureSelector{}, err
	}
	return sandboxFileSelector(request.Path)
}

func validateSandboxFileOperation(sandboxID, organizationID, operationID string) error {
	if !canonicalNativeID(organizationID) || !canonicalNativeID(sandboxID) || !canonicalOperationID(operationID) {
		return invalidf("native sandbox capture owner or operation is invalid")
	}
	return nil
}

func canonicalNativeID(value string) bool {
	// Native sandbox and organization entities are canonical UUIDs. Operation
	// IDs are caller idempotency keys, never disguised Product authority UUIDs.
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func canonicalOperationID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for i, c := range value {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		if i > 0 && (c == '.' || c == '_' || c == ':' || c == '-') {
			continue
		}
		return false
	}
	return true
}

func sandboxFileSelector(value string) (CaptureSelector, error) {
	for _, zone := range []string{"ambit.workspace-zone/work@1", "ambit.workspace-zone/outputs@1"} {
		root, _ := semanticZoneRoot(zone)
		if strings.HasPrefix(value, root+"/") {
			relative := strings.TrimPrefix(value, root+"/")
			if len(value) <= 4096 && canonicalRelativePath(relative) {
				return CaptureSelector{SemanticZoneRef: zone, ZoneRelativePath: relative}, nil
			}
		}
	}
	return CaptureSelector{}, invalidf("native file capture requires a canonical file within /workspace/work or /workspace/outputs")
}

func validateSandboxFileBinding(sandboxID string, binding CaptureBinding) error {
	source := binding.SandboxFile
	root, _ := semanticZoneRoot(binding.Selector.SemanticZoneRef)
	request := SandboxFileRequest{OrganizationID: source.OrganizationID, OperationID: source.OperationID, Path: root + "/" + binding.Selector.ZoneRelativePath}
	selector, err := validateSandboxFileRequest(sandboxID, request)
	if err != nil {
		return err
	}
	if source.Contract != SandboxFileCaptureContract || source.SandboxID != sandboxID || selector != binding.Selector ||
		source.Component.validate() != nil || generationstop.ValidateExpectedGeneration(source.Generation) != nil ||
		binding.ProviderName != "" || binding.RequestFingerprint != "" || binding.Authority != (CaptureAuthority{}) ||
		binding.Source != (SourceAddress{}) || binding.Owner != (CaptureOwner{}) ||
		binding.StopAuthority != (generationstop.StopAuthority{}) || binding.FileSnapshot != (FileSnapshotSource{}) {
		return invalidf("native file capture requires exactly its provider-owned source authority")
	}
	return nil
}

func requireSandboxFileRequest(binding CaptureBinding, sandboxID string, request SandboxFileRequest) error {
	selector, err := validateSandboxFileRequest(sandboxID, request)
	if err != nil {
		return err
	}
	source := binding.SandboxFile
	if source.Contract != SandboxFileCaptureContract || source.OrganizationID != request.OrganizationID ||
		source.SandboxID != sandboxID || source.OperationID != request.OperationID || binding.Selector != selector {
		return fmt.Errorf("%w: native operation is already bound to a different source or path", ErrConflict)
	}
	return nil
}

func (s *Service) sandboxFileRetired(ctx context.Context, root, sandboxID string, request SandboxFileRequest) (bool, error) {
	deletion, retired, err := s.readDeletion(ctx, root)
	if err != nil || !retired {
		return false, err
	}
	if err := requireSandboxFileRetirement(deletion, sandboxID, request); err != nil {
		return false, err
	}
	return true, nil
}

func sandboxFileObjectRoot(organizationID, sandboxID, operationID string) string {
	return privateRoot + "/sandbox-files/" + hashHex("daytona-sandbox-file-owner/v1\n"+organizationID+"\n"+sandboxID) + "/" + hashHex("daytona-sandbox-file-operation/v1\n"+operationID)
}

func sandboxFileReceipt(receipt CaptureReceipt) SandboxFileReceipt {
	source := receipt.SandboxFile
	root, _ := semanticZoneRoot(receipt.Selector.SemanticZoneRef)
	return SandboxFileReceipt{Contract: SandboxFileCaptureContract, CaptureID: receipt.ProviderResourceID,
		OperationID: source.OperationID, OrganizationID: source.OrganizationID, SandboxID: source.SandboxID,
		Path: root + "/" + receipt.Selector.ZoneRelativePath, Generation: source.Generation, Component: source.Component,
		TotalByteLength: receipt.TotalByteLength, SHA256: receipt.ProviderSHA256Digest, CapturedAt: receipt.CapturedAt}
}

func validateSandboxFileReceipt(sandboxID string, receipt SandboxFileReceipt) (CaptureReceipt, error) {
	selector, err := validateSandboxFileRequest(sandboxID, SandboxFileRequest{OrganizationID: receipt.OrganizationID, OperationID: receipt.OperationID, Path: receipt.Path})
	if err != nil {
		return CaptureReceipt{}, err
	}
	binding := CaptureBinding{Selector: selector, SandboxFile: SandboxFileSource{
		Contract: receipt.Contract, OrganizationID: receipt.OrganizationID, SandboxID: receipt.SandboxID,
		OperationID: receipt.OperationID, Generation: receipt.Generation, Component: receipt.Component,
	}}
	if err := validateSandboxFileBinding(sandboxID, binding); err != nil {
		return CaptureReceipt{}, err
	}
	instant, err := time.Parse("2006-01-02T15:04:05.000Z", receipt.CapturedAt)
	if err != nil || instant.Format("2006-01-02T15:04:05.000Z") != receipt.CapturedAt ||
		receipt.CaptureID != providerResourceID(binding, generationstop.TerminalGeneration{}) ||
		receipt.TotalByteLength < 0 || receipt.TotalByteLength > MaximumCaptureBytes || !isSHA256Digest(receipt.SHA256) {
		return CaptureReceipt{}, invalidf("native file capture receipt is invalid")
	}
	return CaptureReceipt{CaptureIdentity: CaptureIdentity{CaptureBinding: binding, ProviderResourceID: receipt.CaptureID},
		TotalByteLength: receipt.TotalByteLength, ProviderSHA256Digest: receipt.SHA256, CapturedAt: receipt.CapturedAt}, nil
}

// Kept separate from Product's byte-stable serializer; this identity is native
// source-owned data and carries no fabricated Product lineage.
func sameSandboxFileRequest(left, right CaptureBinding) bool {
	return left.SandboxFile != (SandboxFileSource{}) && right.SandboxFile != (SandboxFileSource{}) &&
		left.SandboxFile.OrganizationID == right.SandboxFile.OrganizationID && left.SandboxFile.SandboxID == right.SandboxFile.SandboxID &&
		left.SandboxFile.OperationID == right.SandboxFile.OperationID && left.Selector == right.Selector
}
