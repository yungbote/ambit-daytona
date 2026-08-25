// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalOutputReconcilesOwnedSiblingStagingAfterHardCrash(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outputDirectory := filepath.Join(root, "sealed-output")
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(outputDirectory, "provider-live.json")
	staging := canonicalOutputStagingPath(output)
	if err := os.WriteFile(staging, []byte("hard-crash-partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	value := MinIOIntegrationRun{
		Contract:        MinIOIntegrationRunContract,
		SourceRevision:  "1111111111111111111111111111111111111111",
		SourceTree:      "2222222222222222222222222222222222222222",
		SourceSetDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000001",
		RunID:           "66666666-6666-4666-8666-666666666666",
	}
	if err := WriteCanonicalExclusive(output, value); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(staging); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned output staging remains: %v", err)
	}
}

func TestCanonicalOutputRejectsStagingSubstitution(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outputDirectory := filepath.Join(root, "sealed-output")
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(outputDirectory, "provider-live.json")
	staging := canonicalOutputStagingPath(output)
	target := filepath.Join(root, "do-not-delete")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, staging); err != nil {
		t.Fatal(err)
	}
	if err := WriteCanonicalExclusive(output, map[string]string{"value": "test"}); err == nil {
		t.Fatal("substituted output staging was accepted")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "target" {
		t.Fatalf("output staging substitution damaged target: %q %v", data, err)
	}
}
