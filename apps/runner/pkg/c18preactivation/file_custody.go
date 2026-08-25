// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/daytonaio/runner/pkg/specialistrender"
)

const temporaryCustodyCleanupTimeout = 30 * time.Second

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
	mu        sync.Mutex
	root      string
	state     temporaryCustodyState
	receipt   specialistrender.Receipt
	admitted  bool
	files     []temporaryCustodyFile
	remove    func(string) error
	removeAll func(string) error
}

func (custody *TemporaryProviderResponseCustody) AdmitReceipt(
	ctx context.Context,
	receipt specialistrender.Receipt,
) error {
	if custody == nil {
		return errors.New("C18 provider response custody is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if custody.state != temporaryCustodyOpen || custody.admitted {
		return errors.New("C18 provider response custody receipt state is invalid")
	}
	custody.receipt = receipt
	custody.admitted = true
	return nil
}

func NewTemporaryProviderResponseCustody() (*TemporaryProviderResponseCustody, error) {
	root, err := os.MkdirTemp("", "ambit-c18-provider-response-")
	if err != nil {
		return nil, fmt.Errorf("create C18 provider response custody: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		protectErr := fmt.Errorf("protect C18 provider response custody: %w", err)
		if cleanupErr := os.RemoveAll(root); cleanupErr != nil {
			return nil, errors.Join(
				protectErr,
				fmt.Errorf("remove unprotected C18 provider response custody: %w", cleanupErr),
			)
		}
		return nil, protectErr
	}
	return &TemporaryProviderResponseCustody{
		root: root, state: temporaryCustodyOpen, remove: os.Remove, removeAll: os.RemoveAll,
	}, nil
}

func (custody *TemporaryProviderResponseCustody) OpenFile(
	_ context.Context,
	descriptor specialistrender.OutputFile,
) (ProviderResponseFileWriter, error) {
	if custody == nil {
		return nil, errors.New("C18 provider response custody is unavailable")
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if custody.state != temporaryCustodyOpen || !custody.admitted || descriptor.Ordinal != len(custody.files) ||
		descriptor.Ordinal >= len(custody.receipt.Files) || custody.receipt.Files[descriptor.Ordinal] != descriptor {
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
	return temporaryProviderResponseWriter{file: file}, nil
}

func (custody *TemporaryProviderResponseCustody) Commit(
	ctx context.Context,
	observation ProviderResponseObservation,
) error {
	if custody == nil {
		return errors.New("C18 provider response custody is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if custody.state != temporaryCustodyOpen || !custody.admitted ||
		!canonicalEqual(custody.receipt, observation.Receipt) ||
		len(custody.files) != len(observation.Receipt.Files) {
		return errors.New("C18 provider response custody commit roster is invalid")
	}
	for index := range custody.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry := &custody.files[index]
		if entry.descriptor != observation.Receipt.Files[index] {
			return errors.New("C18 provider response custody descriptor differs from receipt")
		}
		if err := entry.file.Sync(); err != nil {
			return fmt.Errorf("sync C18 provider response object: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		metadata, err := entry.file.Stat()
		if err != nil || !metadata.Mode().IsRegular() || metadata.Size() != entry.descriptor.ByteLength {
			return errors.New("C18 provider response custody object is invalid")
		}
		digest, err := hashCustodyFile(ctx, entry.file, metadata.Size())
		if err != nil {
			return err
		}
		if digest != entry.descriptor.Digest {
			return errors.New("C18 provider response custody rehash differs from receipt")
		}
		if err := entry.file.Chmod(0o400); err != nil {
			return fmt.Errorf("seal C18 provider response object: %w", err)
		}
	}
	for index := range custody.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := custody.remove(custody.files[index].path); err != nil {
			return fmt.Errorf("unlink C18 provider response object: %w", err)
		}
		custody.files[index].path = ""
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := custody.remove(custody.root); err != nil {
		return fmt.Errorf("remove C18 provider response directory: %w", err)
	}
	custody.root = ""
	custody.state = temporaryCustodyCommitted
	return nil
}

func (custody *TemporaryProviderResponseCustody) Abort(ctx context.Context) error {
	if custody == nil {
		return nil
	}
	custody.mu.Lock()
	defer custody.mu.Unlock()
	if custody.state != temporaryCustodyOpen {
		return nil
	}
	cleanupBase := ctx
	if ctx.Err() != nil {
		cleanupBase = context.WithoutCancel(ctx)
	}
	cleanupCtx, cancel := context.WithTimeout(cleanupBase, temporaryCustodyCleanupTimeout)
	defer cancel()
	err := custody.closeAndRemoveLocked(cleanupCtx)
	custody.state = temporaryCustodyAborted
	return err
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
	if custody.state == temporaryCustodyCleaned {
		return nil
	}
	if custody.state == temporaryCustodyAborted {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), temporaryCustodyCleanupTimeout)
		defer cancel()
		if err := custody.closeAndRemoveLocked(cleanupCtx); err != nil {
			return err
		}
		custody.state = temporaryCustodyCleaned
		return nil
	}
	if custody.state != temporaryCustodyCommitted {
		return errors.New("C18 provider response custody is not committed")
	}
	var cleanupErr error
	for index := range custody.files {
		if err := custody.files[index].file.Close(); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
		custody.files[index].file = nil
	}
	custody.files = nil
	custody.receipt = specialistrender.Receipt{}
	custody.admitted = false
	custody.state = temporaryCustodyCleaned
	if cleanupErr != nil {
		return fmt.Errorf("close C18 provider response custody: %w", cleanupErr)
	}
	return nil
}

func (custody *TemporaryProviderResponseCustody) closeAndRemoveLocked(ctx context.Context) error {
	var cleanupErr error
	for index := range custody.files {
		if err := ctx.Err(); err != nil {
			return errors.Join(cleanupErr, err)
		}
		if custody.files[index].file != nil {
			if err := custody.files[index].file.Close(); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
			}
		}
		custody.files[index].file = nil
	}
	custody.files = nil
	custody.receipt = specialistrender.Receipt{}
	custody.admitted = false
	if err := ctx.Err(); err != nil {
		return errors.Join(cleanupErr, err)
	}
	if custody.root != "" {
		if err := custody.removeAll(custody.root); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		} else {
			custody.root = ""
		}
		if err := ctx.Err(); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if cleanupErr != nil {
		return fmt.Errorf("abort C18 provider response custody: %w", cleanupErr)
	}
	return nil
}

func hashCustodyFile(ctx context.Context, file *os.File, size int64) (string, error) {
	digest := sha256.New()
	reader := io.NewSectionReader(file, 0, size)
	buffer := make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		read, err := reader.Read(buffer)
		if read > 0 {
			_, _ = digest.Write(buffer[:read])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("rehash C18 provider response object: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

type temporaryProviderResponseWriter struct{ file *os.File }

func (writer temporaryProviderResponseWriter) WriteContext(
	ctx context.Context,
	value []byte,
) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return writer.file.Write(value)
}
