package main

import (
	"strings"
	"syscall"
	"testing"
)

func TestPublicConflictCodesAreExhaustiveAndClosed(t *testing.T) {
	t.Parallel()
	terminal := []struct {
		err  error
		code string
	}{
		{existingMismatch, "existing_mismatch"},
		{linkCountInvalid, "link_count_invalid"},
		{nonRegularFile, "non_regular_file"},
		{pathRace, "path_race"},
		{syscall.ELOOP, "unsafe_path"},
		{syscall.ENOTDIR, "unsafe_path"},
		{syscall.ENOENT, "path_race"},
		{syscall.ESTALE, "path_race"},
		{syscall.EBUSY, "path_race"},
	}
	for _, test := range terminal {
		actual, ok := publicConflictCode(test.err)
		if !ok || actual != test.code {
			t.Fatalf("publicConflictCode(%v) = %q, %v; want %q, true", test.err, actual, ok, test.code)
		}
	}
	for _, err := range []error{syscall.EIO, syscall.EMFILE, syscall.EPERM, syscall.ENOMEM} {
		if code, ok := publicConflictCode(err); ok || code != "" {
			t.Fatalf("publicConflictCode(%v) = %q, %v; want empty, false", err, code, ok)
		}
		if failure := verificationFailure(err, nil); failure.exitCode != exitIO {
			t.Fatalf("verificationFailure(%v) exit = %d; want %d", err, failure.exitCode, exitIO)
		}
		if failure := reachabilityFailure(err, nil); failure.exitCode != exitIO {
			t.Fatalf("reachabilityFailure(%v) exit = %d; want %d", err, failure.exitCode, exitIO)
		}
	}
}

func TestErrorReceiptCanonicalEncodingWritesPathOnce(t *testing.T) {
	t.Parallel()
	relativePath := "artifacts/<>&\u2028-report.bin"
	encoded := string(encodeErrorReceipt(errorReceipt{
		Code:         "path_race",
		Kind:         "ambit_atomic_materialization_error",
		RelativePath: &relativePath,
		Version:      1,
	}))
	if strings.Count(encoded, relativePath) != 1 {
		t.Fatalf("relative path occurrence count = %d in %q", strings.Count(encoded, relativePath), encoded)
	}
	want := `{"code":"path_race","kind":"ambit_atomic_materialization_error","relativePath":"artifacts/<>& -report.bin","version":1}`
	if encoded != want {
		t.Fatalf("encoded error = %q; want %q", encoded, want)
	}
}
