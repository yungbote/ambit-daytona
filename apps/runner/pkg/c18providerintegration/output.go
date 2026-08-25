// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// WriteCanonicalExclusive commits one canonical output or idempotently admits
// the already-committed exact bytes after a lost fsync/return. A process lock
// on the private sibling staging directory covers orphan reconciliation,
// no-replace rename, and both directory syncs.
func WriteCanonicalExclusive(path string, value any) error {
	return writeCanonicalExclusive(path, value, syncDirectory)
}

func writeCanonicalExclusive(
	path string,
	value any,
	syncDirectoryFn func(string) error,
) (returnErr error) {
	if !absoluteCleanPath(path) {
		return fmt.Errorf("output path is invalid")
	}
	directory := filepath.Dir(path)
	if err := validatePrivateOwnedDirectory(directory); err != nil {
		return fmt.Errorf("output directory is not private: %w", err)
	}
	stagingDirectory := filepath.Dir(directory)
	lock, err := lockPrivateOwnedDirectory(stagingDirectory)
	if err != nil {
		return fmt.Errorf("output staging directory is not privately locked: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, closeLockedDirectory(lock))
	}()
	encoded, err := EncodeCanonical(value)
	if err != nil {
		return fmt.Errorf("encode canonical output: %w", err)
	}
	temporaryPath := canonicalOutputStagingPath(path)
	if err := reconcileOwnedStaging(temporaryPath); err != nil {
		return fmt.Errorf("reconcile private output staging: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		if err := validateOwnedRegularFile(path); err != nil {
			return fmt.Errorf("existing output is not private: %w", err)
		}
		existing, err := readCanonicalConfig(path, maximumProviderJournalBytes)
		if err != nil {
			return fmt.Errorf("read existing output: %w", err)
		}
		if !bytes.Equal(existing, encoded) {
			return fmt.Errorf("output already exists with different bytes")
		}
		if err := syncDirectoryFn(directory); err != nil {
			return fmt.Errorf("resync existing output directory: %w", err)
		}
		if err := syncDirectoryFn(stagingDirectory); err != nil {
			return fmt.Errorf("resync existing output staging directory: %w", err)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output path: %w", err)
	}
	temporary, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private output: %w", err)
	}
	committed := false
	defer func() {
		closeErr := temporary.Close()
		if errors.Is(closeErr, os.ErrClosed) {
			closeErr = nil
		}
		if !committed {
			removeErr := os.Remove(temporaryPath)
			if errors.Is(removeErr, os.ErrNotExist) {
				removeErr = nil
			}
			returnErr = errors.Join(returnErr, removeErr)
		}
		returnErr = errors.Join(returnErr, closeErr)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect private output: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		return fmt.Errorf("write private output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync private output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close private output: %w", err)
	}
	if err := unix.Renameat2(
		unix.AT_FDCWD,
		temporaryPath,
		unix.AT_FDCWD,
		path,
		unix.RENAME_NOREPLACE,
	); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("output appeared during commit")
		}
		return fmt.Errorf("commit private output: %w", err)
	}
	committed = true
	if err := syncDirectoryFn(directory); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	if err := syncDirectoryFn(stagingDirectory); err != nil {
		return fmt.Errorf("sync output staging directory: %w", err)
	}
	return nil
}

func canonicalOutputStagingPath(path string) string {
	directory := filepath.Dir(path)
	return filepath.Join(
		filepath.Dir(directory),
		"."+filepath.Base(directory)+"."+filepath.Base(path)+".c18-integration-staging",
	)
}
