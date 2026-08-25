// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/daytonaio/runner/pkg/specialistrender"
)

type temporaryCustodyState uint8

const (
	temporaryCustodyOpen temporaryCustodyState = iota
	temporaryCustodyCommitted
	temporaryCustodyAborted
	temporaryCustodyCleaned
)

type temporaryCustodyFile struct {
	descriptor specialistrender.OutputFile
	path       string
	file       *os.File
}

// TemporaryProviderResponseCustody stages large provider output through exact
// private file descriptors. Successful commit unlinks every name and removes
// the directory; later reads duplicate only the retained descriptors. Cleanup
// closes those descriptors. No provider path is ever used as a host path.
type TemporaryProviderResponseCustody struct {
	mu    sync.Mutex
	root  string
	state temporaryCustodyState
	files []temporaryCustodyFile
}

func NewTemporaryProviderResponseCustody() (*TemporaryProviderResponseCustody, error) {
	root, err := os.MkdirTemp("", "ambit-c18-provider-response-")
	if err != nil {
		return nil, fmt.Errorf("create C18 provider response custody: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("protect C18 provider response custody: %w", err)
	}
	return &TemporaryProviderResponseCustody{root: root, state: temporaryCustodyOpen}, nil
}

func (custody *TemporaryProviderResponseCustody) OpenFile(
	_ context.Context,
	descriptor specialistrender.OutputFile,
) (io.Writer, error) {
	if custody == nil {
		return nil, errors.New("C18 provider response custody is unavailable")
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if custody.state != temporaryCustodyOpen || descriptor.Ordinal != len(custody.files) {
		return nil, errors.New("C18 provider response custody descriptor order is invalid")
	}
	path := filepath.Join(custody.root, fmt.Sprintf("%03d.payload", descriptor.Ordinal))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create C18 provider response object: %w", err)
	}
	custody.files = append(custody.files, temporaryCustodyFile{
		descriptor: descriptor, path: path, file: file,
	})
	return file, nil
}

func (custody *TemporaryProviderResponseCustody) Commit(
	_ context.Context,
	observation ProviderResponseObservation,
) error {
	if custody == nil {
		return errors.New("C18 provider response custody is unavailable")
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if custody.state != temporaryCustodyOpen || len(custody.files) != len(observation.Receipt.Files) {
		return errors.New("C18 provider response custody commit roster is invalid")
	}
	for index := range custody.files {
		entry := &custody.files[index]
		if entry.descriptor != observation.Receipt.Files[index] {
			return errors.New("C18 provider response custody descriptor differs from receipt")
		}
		if err := entry.file.Sync(); err != nil {
			return fmt.Errorf("sync C18 provider response object: %w", err)
		}
		metadata, err := entry.file.Stat()
		if err != nil || !metadata.Mode().IsRegular() || metadata.Size() != entry.descriptor.ByteLength {
			return errors.New("C18 provider response custody object is invalid")
		}
		if err := entry.file.Chmod(0o400); err != nil {
			return fmt.Errorf("seal C18 provider response object: %w", err)
		}
	}
	for index := range custody.files {
		if err := os.Remove(custody.files[index].path); err != nil {
			return fmt.Errorf("unlink C18 provider response object: %w", err)
		}
		custody.files[index].path = ""
	}
	if err := os.Remove(custody.root); err != nil {
		return fmt.Errorf("remove C18 provider response directory: %w", err)
	}
	custody.root = ""
	custody.state = temporaryCustodyCommitted
	return nil
}

func (custody *TemporaryProviderResponseCustody) Abort() {
	if custody == nil {
		return
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if custody.state != temporaryCustodyOpen {
		return
	}
	custody.closeAndRemoveLocked()
	custody.state = temporaryCustodyAborted
}

// Open returns a fresh reader for one exact committed receipt descriptor.
func (custody *TemporaryProviderResponseCustody) Open(
	descriptor specialistrender.OutputFile,
) (io.ReadCloser, error) {
	if custody == nil {
		return nil, errors.New("C18 provider response custody is unavailable")
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if custody.state != temporaryCustodyCommitted || descriptor.Ordinal < 0 ||
		descriptor.Ordinal >= len(custody.files) || custody.files[descriptor.Ordinal].descriptor != descriptor {
		return nil, errors.New("C18 provider response object is not committed")
	}
	entry := custody.files[descriptor.Ordinal]
	return io.NopCloser(io.NewSectionReader(entry.file, 0, descriptor.ByteLength)), nil
}

// Cleanup closes committed descriptor custody. It is idempotent.
func (custody *TemporaryProviderResponseCustody) Cleanup() error {
	if custody == nil {
		return nil
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if custody.state == temporaryCustodyCleaned || custody.state == temporaryCustodyAborted {
		return nil
	}
	if custody.state != temporaryCustodyCommitted {
		return errors.New("C18 provider response custody is not committed")
	}
	var cleanupErr error
	for index := range custody.files {
		if err := custody.files[index].file.Close(); err != nil && cleanupErr == nil {
			cleanupErr = err
		}
		custody.files[index].file = nil
	}
	custody.files = nil
	custody.state = temporaryCustodyCleaned
	if cleanupErr != nil {
		return fmt.Errorf("close C18 provider response custody: %w", cleanupErr)
	}
	return nil
}

func (custody *TemporaryProviderResponseCustody) closeAndRemoveLocked() {
	for index := range custody.files {
		_ = custody.files[index].file.Close()
		custody.files[index].file = nil
	}
	custody.files = nil
	if custody.root != "" {
		_ = os.RemoveAll(custody.root)
		custody.root = ""
	}
}
