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
	RoleRef  string                   `json:"roleRef" validate:"required"`
	Protocol CaptureAuthorityArtifact `json:"protocol" validate:"required"`
	Helper   CaptureAuthorityArtifact `json:"helper" validate:"required"`
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

// component is the capture component an authority names.
func (authority CaptureAuthority) component() CaptureComponent {
	return CaptureComponent{RoleRef: authority.RoleRef, Protocol: authority.Protocol, Helper: authority.Helper}
}

// PinState names how this Runner's build relates to its deployment's pin.
type PinState string

const (
	// PinUnbound: the deployment names no source revision, as local and test
	// runs do. The Runner states its measured component.
	PinUnbound PinState = "unbound"
	// PinBound: the build is exactly the pinned source revision.
	PinBound PinState = "bound"
	// PinMismatch: the build is another revision, and fresh capture work is refused.
	PinMismatch PinState = "mismatch"
)

// Pin relates this Runner's build to the source revision its deployment pins,
// AMBIT_RUNNER_SOURCE_REVISION, which production takes from the pod's
// ambit.sh/source-revision annotation. The comparison is exact: no prefix,
// case or whitespace folding.
type Pin struct {
	Build    string
	Revision string
}

func (pin Pin) State() PinState {
	switch {
	case pin.Revision == "":
		return PinUnbound
	case pin.Build == pin.Revision:
		return PinBound
	default:
		return PinMismatch
	}
}

// refusal is what every fresh capture effect answers under a mismatched pin.
func (pin Pin) refusal() error {
	if pin.State() != PinMismatch {
		return nil
	}
	return fmt.Errorf("%w: runner build %s is not its pin's source revision %s", ErrPinMismatch, pin.Build, pin.Revision)
}

func (component CaptureComponent) validate() error {
	if component.RoleRef != captureRoleRef || component.Protocol.Ref != captureProtocolRef ||
		!isSHA256Digest(component.Protocol.Digest) || !isSHA256Digest(component.Helper.Digest) ||
		component.Helper.Ref != "runtime-component-artifact:"+component.Helper.Digest {
		return fmt.Errorf("%w: current capture component is invalid", ErrUnavailable)
	}
	return nil
}

// currentComponent is the capture component this Runner states in discovery
// and every fresh source effect requires. A build outside its deployment's pin
// has none. Stored custody never consults it: a stored capture is validated
// against its own exact historical binding, so changing this executable must
// not strand its immutable bytes.
func (s *Service) currentComponent() (CaptureComponent, error) {
	if err := s.pin.refusal(); err != nil {
		return CaptureComponent{}, err
	}
	return s.component, nil
}

// requireCurrentComponent belongs only at fresh source-effect boundaries.
func (s *Service) requireCurrentComponent(authority CaptureAuthority) error {
	if err := validateAuthority(authority); err != nil {
		return err
	}
	current, err := s.currentComponent()
	if err != nil {
		return err
	}
	if authority.component() != current {
		return fmt.Errorf("%w: requested capture component is not implemented by this Runner", ErrUnavailable)
	}
	return nil
}
