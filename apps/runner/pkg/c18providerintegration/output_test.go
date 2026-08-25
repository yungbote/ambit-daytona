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
	if err := os.Chmod(staging, 0o000); err != nil {
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
	var resynced []string
	if err := writeCanonicalExclusive(output, value, func(path string) error {
		resynced = append(resynced, path)
		return syncDirectory(path)
	}); err != nil {
		t.Fatalf("lost-return replay did not admit exact final bytes: %v", err)
	}
	if len(resynced) != 2 || resynced[0] != outputDirectory || resynced[1] != root {
		t.Fatalf("lost-return replay did not resync both rename directories: %#v", resynced)
	}
	changed := value
	changed.RunID = "77777777-7777-4777-8777-777777777777"
	if err := WriteCanonicalExclusive(output, changed); err == nil {
		t.Fatal("different output bytes replaced an existing final")
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

func TestCanonicalOutputRequiresPrivateOwnedStagingParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outputDirectory := filepath.Join(root, "sealed-output")
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(outputDirectory, "provider-live.json")
	if err := WriteCanonicalExclusive(output, map[string]string{"value": "test"}); err == nil {
		t.Fatal("non-private output staging parent was accepted")
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("output appeared without private staging custody: %v", err)
	}
}

func TestCanonicalOutputSiblingLockExcludesConcurrentWriter(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outputDirectory := filepath.Join(root, "sealed-output")
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(outputDirectory, "provider-live.json")
	lock, err := lockPrivateOwnedDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteCanonicalExclusive(output, map[string]string{"value": "test"}); err == nil {
		t.Fatal("concurrent output writer crossed sibling directory lock")
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("output appeared during lock contention: %v", err)
	}
	if err := closeLockedDirectory(lock); err != nil {
		t.Fatal(err)
	}
	if err := WriteCanonicalExclusive(output, map[string]string{"value": "test"}); err != nil {
		t.Fatalf("output lock did not release: %v", err)
	}
}
