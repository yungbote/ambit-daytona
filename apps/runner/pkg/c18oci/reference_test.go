// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18oci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type referenceCorpus struct {
	Contract              string `json:"contract"`
	MaximumReferenceBytes int    `json:"maximumReferenceBytes"`
	Authorities           []struct {
		Authority                   string `json:"authority"`
		SourceAccepted              bool   `json:"sourceAccepted"`
		RuntimeAccepted             bool   `json:"runtimeAccepted"`
		RuntimeRequiredPortAccepted bool   `json:"runtimeRequiredPortAccepted"`
	} `json:"authorities"`
	References []struct {
		Reference       string `json:"reference"`
		SourceAccepted  bool   `json:"sourceAccepted"`
		RuntimeAccepted bool   `json:"runtimeAccepted"`
	} `json:"references"`
}

func TestImmutableReferenceMatchesSharedCrossLanguageCorpus(t *testing.T) {
	bytes, err := os.ReadFile("testdata/immutable-oci-reference-corpus.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	if actual := hex.EncodeToString(sum[:]); actual != "b584f503874db319eb7f87c873fb6ddc26889cfec49037d084708fddf5cc0267" {
		t.Fatalf("cross-language immutable OCI corpus drifted: %s", actual)
	}
	var corpus referenceCorpus
	if err := json.Unmarshal(bytes, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Contract != "ImmutableOciReferenceCorpus@1" || corpus.MaximumReferenceBytes != 512 {
		t.Fatal("cross-language immutable OCI corpus contract drifted")
	}
	for _, vector := range corpus.Authorities {
		if actual := ValidRegistryAuthority(vector.Authority, false, true); actual != vector.SourceAccepted {
			t.Fatalf("source authority %q accepted=%t, want %t", vector.Authority, actual, vector.SourceAccepted)
		}
		if actual := ValidRegistryAuthority(vector.Authority, false, false); actual != vector.RuntimeAccepted {
			t.Fatalf("runtime authority %q accepted=%t, want %t", vector.Authority, actual, vector.RuntimeAccepted)
		}
		if actual := ValidRegistryAuthority(vector.Authority, true, false); actual != vector.RuntimeRequiredPortAccepted {
			t.Fatalf("required-port authority %q accepted=%t, want %t", vector.Authority, actual, vector.RuntimeRequiredPortAccepted)
		}
	}
	for _, vector := range corpus.References {
		if actual := ValidImmutableSourceReference(vector.Reference); actual != vector.SourceAccepted {
			t.Fatalf("source reference %q accepted=%t, want %t", vector.Reference, actual, vector.SourceAccepted)
		}
		if actual := ValidImmutableReference(vector.Reference); actual != vector.RuntimeAccepted {
			t.Fatalf("runtime reference %q accepted=%t, want %t", vector.Reference, actual, vector.RuntimeAccepted)
		}
	}

	suffix := "@sha256:" + strings.Repeat("d", 64)
	prefix := "registry/"
	boundary := prefix + strings.Repeat("a", corpus.MaximumReferenceBytes-len(prefix)-len(suffix)) + suffix
	if len(boundary) != corpus.MaximumReferenceBytes || !ValidImmutableReference(boundary) ||
		ValidImmutableReference(prefix+strings.Repeat("a", corpus.MaximumReferenceBytes+1-len(prefix)-len(suffix))+suffix) {
		t.Fatal("immutable OCI reference byte bound drifted")
	}
}
