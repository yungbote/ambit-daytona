// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// CaptureComponent identifies the native implementation, independently of the
// caller's workspace image, current qualification, or historical capture lineage.
// The host runtime owns those authorities. This process owns these measured bytes.
type CaptureComponent struct {
	RoleRef  string                   `json:"roleRef"`
	Protocol CaptureAuthorityArtifact `json:"protocol"`
	Helper   CaptureAuthorityArtifact `json:"helper"`
}

// MeasureCaptureComponent pins the actual running executable through its open
// proc descriptor. The caller supplies the source-owned canonical wire contract.
// This is a local measurement, not a supply or filesystem conformance attestation.
func MeasureCaptureComponent(protocol []byte) (CaptureComponent, error) {
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		return CaptureComponent{}, fmt.Errorf("%w: open current capture executable: %w", ErrUnavailable, err)
	}
	defer executable.Close()
	return measureCaptureComponent(executable, protocol)
}

func measureCaptureComponent(executable io.Reader, protocol []byte) (CaptureComponent, error) {
	if len(protocol) == 0 || !json.Valid(protocol) {
		return CaptureComponent{}, fmt.Errorf("%w: capture interface bytes are invalid", ErrUnavailable)
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, executable); err != nil {
		return CaptureComponent{}, fmt.Errorf("%w: measure current capture executable: %w", ErrUnavailable, err)
	}
	helperDigest := "sha256:" + hex.EncodeToString(digest.Sum(nil))
	return CaptureComponent{
		RoleRef:  captureRoleRef,
		Protocol: CaptureAuthorityArtifact{Ref: captureProtocolRef, Digest: sha256Digest(protocol)},
		Helper:   CaptureAuthorityArtifact{Ref: "runtime-component-artifact:" + helperDigest, Digest: helperDigest},
	}, nil
}

func (component CaptureComponent) validate() error {
	if component.RoleRef != captureRoleRef || component.Protocol.Ref != captureProtocolRef ||
		!isSHA256Digest(component.Protocol.Digest) || !isSHA256Digest(component.Helper.Digest) ||
		component.Helper.Ref != "runtime-component-artifact:"+component.Helper.Digest {
		return fmt.Errorf("%w: current capture component is invalid", ErrUnavailable)
	}
	return nil
}

// requireCurrentComponent belongs only at discovery and fresh source-effect
// boundaries. Stored custody is validated against its own exact historical
// binding; changing this executable must not strand its immutable bytes.
func (s *Service) requireCurrentComponent(authority CaptureAuthority) error {
	if err := validateAuthority(authority); err != nil {
		return err
	}
	if authority.RoleRef != s.component.RoleRef || authority.Protocol != s.component.Protocol || authority.Helper != s.component.Helper {
		return fmt.Errorf("%w: requested capture component is not implemented by this Runner", ErrUnavailable)
	}
	return nil
}
