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

	"github.com/daytonaio/runner/pkg/generationstop"
)

var exactSHA256 = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

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
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal sealed C18 contract: %w", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return fmt.Errorf("decode sealed C18 contract body: %w", err)
	}
	if _, present := body["digest"]; !present {
		return errors.New("sealed C18 contract has no digest field")
	}
	delete(body, "digest")
	actual, err := semanticDigest(body)
	if err != nil {
		return fmt.Errorf("hash sealed C18 contract body: %w", err)
	}
	if actual != expected {
		return errors.New("sealed C18 contract digest is forged")
	}
	return nil
}

func validPin(ref, digest string) bool {
	return ref != "" && len(ref) <= 2_048 && exactSHA256.MatchString(digest)
}
