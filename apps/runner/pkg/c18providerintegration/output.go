// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func WriteCanonicalExclusive(path string, value any) error {
	if !absoluteCleanPath(path) {
		return fmt.Errorf("output path is invalid")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output path: %w", err)
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output directory is invalid")
	}
	encoded, err := EncodeCanonical(value)
	if err != nil {
		return fmt.Errorf("encode canonical output: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".c18-integration-*")
	if err != nil {
		return fmt.Errorf("create private output: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
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
	if err := unix.Renameat2(unix.AT_FDCWD, temporaryPath, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("output already exists")
		}
		return fmt.Errorf("commit private output: %w", err)
	}
	committed = true
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open output directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	return nil
}
