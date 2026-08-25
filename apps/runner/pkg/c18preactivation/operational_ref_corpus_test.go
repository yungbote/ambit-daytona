// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type operationalRefCorpus struct {
	Contract string `json:"contract"`
	ASCII    struct {
		PathSegment string `json:"pathSegment"`
		Query       string `json:"query"`
		Fragment    string `json:"fragment"`
	} `json:"ascii"`
	Limits struct {
		MaximumFragmentBytes  int `json:"maximumFragmentBytes"`
		MaximumQueryBytes     int `json:"maximumQueryBytes"`
		MaximumReferenceBytes int `json:"maximumReferenceBytes"`
	} `json:"limits"`
	Vectors []struct {
		Reference string `json:"reference"`
		Accepted  bool   `json:"accepted"`
	} `json:"vectors"`
}

func TestOperationalRefCrossLanguageCharacterCorpus(t *testing.T) {
	bytes, err := os.ReadFile("testdata/operational-context-reference-character-corpus.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	if actual := hex.EncodeToString(sum[:]); actual != "8377c7519e989367a1fea443360e84fb0eff1c86cecb1d07c90f15cb5d367ec6" {
		t.Fatalf("cross-language operational-ref corpus drifted: %s", actual)
	}
	var corpus operationalRefCorpus
	if err := json.Unmarshal(bytes, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Contract != "OperationalContextReferenceCharacterCorpus@1" ||
		corpus.ASCII.PathSegment != operationalRefPathSegmentASCII ||
		corpus.ASCII.Query != operationalRefQueryOrFragmentASCII ||
		corpus.ASCII.Fragment != operationalRefQueryOrFragmentASCII ||
		corpus.Limits.MaximumFragmentBytes != operationalRefMaximumFragmentBytes ||
		corpus.Limits.MaximumQueryBytes != operationalRefMaximumQueryBytes ||
		corpus.Limits.MaximumReferenceBytes != operationalRefMaximumReferenceBytes {
		t.Fatal("cross-language operational-ref grammar vocabulary drifted")
	}
	for codePoint := 0; codePoint <= 0x7f; codePoint++ {
		character := byte(codePoint)
		if containsASCII(corpus.ASCII.PathSegment, character) != expectedPathASCII(character) {
			t.Fatalf("path ASCII classification drifted for 0x%02x", codePoint)
		}
		if containsASCII(corpus.ASCII.Query, character) != expectedQueryOrFragmentASCII(character) ||
			containsASCII(corpus.ASCII.Fragment, character) != expectedQueryOrFragmentASCII(character) {
			t.Fatalf("query/fragment ASCII classification drifted for 0x%02x", codePoint)
		}
	}
	for _, vector := range corpus.Vectors {
		if actual := validOperationalRef(vector.Reference); actual != vector.Accepted {
			t.Fatalf("operational ref %q accepted=%t, want %t", vector.Reference, actual, vector.Accepted)
		}
	}
	prefix := "ambit://samples/"
	exactReference := prefix + repeatASCII('a', operationalRefMaximumReferenceBytes-len(prefix))
	if !validOperationalRef(exactReference) || validOperationalRef(exactReference+"a") {
		t.Fatal("whole operational-ref byte bound drifted")
	}
	for _, bound := range []struct {
		delimiter byte
		maximum   int
	}{{'?', operationalRefMaximumQueryBytes}, {'#', operationalRefMaximumFragmentBytes}} {
		exact := prefix + "one" + string(bound.delimiter) + repeatASCII('a', bound.maximum)
		if !validOperationalRef(exact) || validOperationalRef(exact+"a") {
			t.Fatalf("operational-ref %q suffix bound drifted", bound.delimiter)
		}
	}
}

func expectedPathASCII(value byte) bool {
	return operationalRefUnreservedASCII(value) || containsASCII("!$&'()*+,;=:@", value)
}

func expectedQueryOrFragmentASCII(value byte) bool {
	return expectedPathASCII(value) || value == '/' || value == '?'
}

func containsASCII(values string, value byte) bool {
	for index := 0; index < len(values); index++ {
		if values[index] == value {
			return true
		}
	}
	return false
}

func repeatASCII(value byte, count int) string {
	output := make([]byte, count)
	for index := range output {
		output[index] = value
	}
	return string(output)
}
