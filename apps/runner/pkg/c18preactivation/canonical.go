// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/daytonaio/runner/pkg/c18oci"
	"github.com/daytonaio/runner/pkg/generationstop"
)

var exactSHA256 = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var exactHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var corpusAuthorityRef = regexp.MustCompile(`^ambit\.skill-eval-corpus/[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*@[1-9][0-9]*$`)
var caseAuthorityRef = regexp.MustCompile(`^ambit\.skill-eval-case/[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*@[1-9][0-9]*$`)
var runtimeCapabilityAuthorityRef = regexp.MustCompile(`^ambit\.runtime/[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*@[1-9][0-9]*$`)
var skillAuthorityRef = regexp.MustCompile(`^skill_ref_1_[0-9a-f]{64}$`)
var skillManifestAuthorityRef = regexp.MustCompile(`^skill_manifest_ref_1_[0-9a-f]{64}$`)

func semanticDigest(value any) (string, error) {
	encoded, err := generationstop.CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// verifySealedDigest verifies the common C18 contract convention: the digest
// is SHA-256 over canonical object bytes with the top-level digest field
// omitted. It accepts only typed values already decoded through an exact wire
// schema.
func verifySealedDigest(value any, expected string) error {
	if !exactSHA256.MatchString(expected) {
		return errors.New("sealed C18 digest is invalid")
	}
	actual, err := sealedDigest(value)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("sealed C18 contract digest is forged")
	}
	return nil
}

func sealedDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal sealed C18 contract: %w", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return "", fmt.Errorf("decode sealed C18 contract body: %w", err)
	}
	if _, present := body["digest"]; !present {
		return "", errors.New("sealed C18 contract has no digest field")
	}
	delete(body, "digest")
	actual, err := semanticDigest(body)
	if err != nil {
		return "", fmt.Errorf("hash sealed C18 contract body: %w", err)
	}
	return actual, nil
}

func validPin(ref, digest string) bool {
	return printable(ref, 1_024) && len([]byte(ref)) <= 2_048 && exactSHA256.MatchString(digest)
}

func validIdentityPin(ref, digest string) bool {
	return printable(ref, 512) && len([]byte(ref)) <= 1_024 && exactSHA256.MatchString(digest)
}

func validOperationalPin(ref, digest string) bool {
	return validOperationalRef(ref) && exactSHA256.MatchString(digest)
}

func validImmutableOCIReference(value string) bool {
	return c18oci.ValidImmutableReference(value)
}
