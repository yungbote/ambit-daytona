// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const semanticCanonicalizerV1 = "ambit.strict_canonical_json.v1"

// DeriveProviderOperationIDV2 is the exact Go projection of the backend's
// deriveSemanticUuidV8 domain for one preactivation sample journey stage.
func DeriveProviderOperationIDV2(requestDigest, sampleRef, stage string) (string, error) {
	if !exactSHA256.MatchString(requestDigest) || !validOperationalRef(sampleRef) || !validJourneyStage(stage) {
		return "", errors.New("C18 provider operation identity input is invalid")
	}
	digest, err := semanticDigest(struct {
		CanonicalizerVersion    string `json:"canonicalizerVersion"`
		Content                 any    `json:"content"`
		ContractKind            string `json:"contractKind"`
		ContractSchemaVersion   int    `json:"contractSchemaVersion"`
		IdentityContractVersion int    `json:"identityContractVersion"`
	}{
		CanonicalizerVersion: semanticCanonicalizerV1,
		Content: struct {
			RequestDigest string `json:"requestDigest"`
			SampleRef     string `json:"sampleRef"`
			Stage         string `json:"stage"`
		}{RequestDigest: requestDigest, SampleRef: sampleRef, Stage: stage},
		ContractKind:            "c18_preactivation_physical_evaluation_stage",
		ContractSchemaVersion:   2,
		IdentityContractVersion: 1,
	})
	if err != nil {
		return "", fmt.Errorf("hash C18 provider operation identity: %w", err)
	}
	hexadecimal := strings.TrimPrefix(digest, "sha256:")
	nibble, err := strconv.ParseUint(hexadecimal[16:17], 16, 4)
	if err != nil {
		return "", errors.New("C18 provider operation digest is invalid")
	}
	return fmt.Sprintf(
		"%s-%s-8%s-%x%s-%s",
		hexadecimal[0:8], hexadecimal[8:12], hexadecimal[13:16],
		(nibble&0x3)|0x8, hexadecimal[17:20], hexadecimal[20:32],
	), nil
}

func validOperationalRef(value string) bool {
	return len(value) >= len("ambit://a/b") && len(value) <= 2_048 &&
		strings.HasPrefix(value, "ambit://") && !strings.ContainsAny(value, "\x00\r\n\t ")
}

func validJourneyStage(value string) bool {
	switch value {
	case "source", "edited", "rebuilt", "browser_validated", "reopened":
		return true
	default:
		return false
	}
}
