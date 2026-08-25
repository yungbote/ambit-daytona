// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsIncompleteInvocation(t *testing.T) {
	var stderr bytes.Buffer
	if exitCode := run(nil, &stderr); exitCode != 64 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("unexpected usage result: exit=%d stderr=%q", exitCode, stderr.String())
	}
}

func TestRunPreflightsReceiptBeforeReadingOrPublishing(t *testing.T) {
	output := filepath.Join(t.TempDir(), "occupied.json")
	if err := os.WriteFile(output, []byte("do-not-replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	exitCode := run([]string{
		"--request", "/does/not/exist.json",
		"--request-sha256", "sha256:" + strings.Repeat("0", 64),
		"--output", output,
	}, &stderr)
	if exitCode != 1 || !strings.Contains(stderr.String(), "output already exists") {
		t.Fatalf("output preflight was not authoritative: exit=%d stderr=%q", exitCode, stderr.String())
	}
	encoded, err := os.ReadFile(output)
	if err != nil || string(encoded) != "do-not-replace" {
		t.Fatalf("occupied output changed: %v %q", err, encoded)
	}
}
