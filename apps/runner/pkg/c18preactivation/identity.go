// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const semanticCanonicalizerV1 = "ambit.strict_canonical_json.v1"

var operationalRefAuthority = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)

const operationalRefPathSegmentASCII = "!$&'()*+,-.0123456789:;=@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
const operationalRefQueryOrFragmentASCII = "!$&'()*+,-./0123456789:;=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"

const (
	operationalRefMaximumQueryBytes     = 512
	operationalRefMaximumFragmentBytes  = 512
	operationalRefMaximumReferenceBytes = 2_048
)

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
	if len(value) < len("ambit://a/b") || len(value) > operationalRefMaximumReferenceBytes || !strings.HasPrefix(value, "ambit://") {
		return false
	}
	body := strings.TrimPrefix(value, "ambit://")
	firstSlash := strings.IndexByte(body, '/')
	if firstSlash < 1 || !operationalRefAuthority.MatchString(body[:firstSlash]) {
		return false
	}
	resource := body[firstSlash:]
	beforeFragment, fragment, hasFragment := strings.Cut(resource, "#")
	path, query, hasQuery := strings.Cut(beforeFragment, "?")
	if !strings.HasPrefix(path, "/") {
		return false
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, segment := range segments {
		decoded, ok := parseOperationalRefComponent(segment, operationalRefPathSegmentASCII)
		if !ok || decoded == "." || decoded == ".." {
			return false
		}
	}
	return (!hasQuery || query != "" && len(query) <= operationalRefMaximumQueryBytes && validOperationalRefComponent(query, operationalRefQueryOrFragmentASCII)) &&
		(!hasFragment || fragment != "" && len(fragment) <= operationalRefMaximumFragmentBytes && validOperationalRefComponent(fragment, operationalRefQueryOrFragmentASCII))
}

func validOperationalRefComponent(value, rawASCII string) bool {
	_, ok := parseOperationalRefComponent(value, rawASCII)
	return ok
}

func parseOperationalRefComponent(value, rawASCII string) (string, bool) {
	if value == "" {
		return "", false
	}
	decodedBytes := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '%' {
			if index+2 >= len(value) || !uppercaseHexadecimalByte(value[index+1]) || !uppercaseHexadecimalByte(value[index+2]) {
				return "", false
			}
			byteValue, err := strconv.ParseUint(value[index+1:index+3], 16, 8)
			if err != nil || operationalRefUnreservedASCII(byte(byteValue)) {
				return "", false
			}
			decodedBytes = append(decodedBytes, byte(byteValue))
			index += 2
			continue
		}
		if character > 0x7e || !strings.ContainsRune(rawASCII, rune(character)) {
			return "", false
		}
		decodedBytes = append(decodedBytes, character)
	}
	if !utf8.Valid(decodedBytes) {
		return "", false
	}
	decoded := string(decodedBytes)
	if !norm.NFC.IsNormalString(decoded) || strings.ContainsAny(decoded, "\\`|") {
		return "", false
	}
	for _, character := range decoded {
		if unicode.Is(unicode.Cc, character) || unicode.Is(unicode.Cf, character) || character == '\u2028' || character == '\u2029' {
			return "", false
		}
	}
	return decoded, true
}

func uppercaseHexadecimalByte(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'A' && value <= 'F')
}

func operationalRefUnreservedASCII(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' ||
		value == '-' || value == '.' || value == '_' || value == '~'
}

func validJourneyStage(value string) bool {
	switch value {
	case "source", "edited", "rebuilt", "browser_validated", "reopened":
		return true
	default:
		return false
	}
}
