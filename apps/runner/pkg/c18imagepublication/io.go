// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18imagepublication

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const maximumRequestBytes = int64(2 * 1024 * 1024)

type ReceiptCommitAmbiguityError struct {
	Path  string
	Cause error
}

func (value *ReceiptCommitAmbiguityError) Error() string {
	return fmt.Sprintf("receipt was committed at %s but durable directory confirmation failed: %v", value.Path, value.Cause)
}

func (value *ReceiptCommitAmbiguityError) Unwrap() error { return value.Cause }

type ReceiptOutput struct {
	path          string
	directoryPath string
	name          string
	directory     *os.File
	directoryInfo os.FileInfo
	committed     bool
	closed        bool
	syncDirectory func(int) error
}

func ReadRequest(ctx context.Context, path, expectedSHA256 string) (Request, []byte, error) {
	if ctx == nil {
		return Request{}, nil, errors.New("request read context is required")
	}
	if !exactSHA256(expectedSHA256) {
		return Request{}, nil, errors.New("request SHA-256 is invalid")
	}
	encoded, err := readRegularFileSnapshot(ctx, path, maximumRequestBytes)
	if err != nil {
		return Request{}, nil, err
	}
	if digestBytes(encoded) != expectedSHA256 {
		return Request{}, nil, errors.New("request file differs from the pinned SHA-256")
	}
	request, err := ParseRequest(encoded)
	if err != nil {
		return Request{}, nil, err
	}
	return request, encoded, nil
}

func ExecutableSHA256(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", errors.New("executable read context is required")
	}
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", fmt.Errorf("open publisher executable: %w", err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 1024*1024*1024 {
		return "", errors.New("publisher executable metadata is invalid")
	}
	hasher := sha256.New()
	count, err := io.CopyBuffer(hasher,
		io.LimitReader(contextReader{ctx: ctx, reader: file}, before.Size()+1), make([]byte, 1024*1024))
	if err != nil {
		return "", fmt.Errorf("read publisher executable: %w", err)
	}
	if count != before.Size() {
		return "", errors.New("publisher executable could not be read exactly")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) {
		return "", errors.New("publisher executable changed while read")
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func WriteReceiptExclusive(path string, receipt Receipt) error {
	output, err := OpenReceiptOutput(path)
	if err != nil {
		return err
	}
	return output.CommitAndClose(receipt)
}

func (value *ReceiptOutput) CommitAndClose(receipt Receipt) error {
	if value == nil {
		return errors.New("receipt output handle is required")
	}
	commitErr := value.Commit(receipt)
	closeErr := value.Close()
	if commitErr == nil && closeErr != nil && value.committed {
		closeErr = &ReceiptCommitAmbiguityError{Path: value.path, Cause: closeErr}
	}
	return errors.Join(commitErr, closeErr)
}

func OpenReceiptOutput(path string) (*ReceiptOutput, error) {
	if !absoluteNormalizedPath(path) {
		return nil, errors.New("receipt output path is invalid")
	}
	directoryPath := filepath.Dir(path)
	name := filepath.Base(path)
	if name == "." || name == ".." || name == "" {
		return nil, errors.New("receipt output name is invalid")
	}
	directoryInfo, err := os.Lstat(directoryPath)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("receipt output directory is invalid")
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directoryPath)
	if err != nil || resolvedDirectory != directoryPath {
		return nil, errors.New("receipt output directory may not contain symlinks")
	}
	descriptor, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open receipt output directory: %w", err)
	}
	directory := os.NewFile(uintptr(descriptor), directoryPath)
	if directory == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("receipt output directory descriptor is invalid")
	}
	openedInfo, err := directory.Stat()
	if err != nil || !openedInfo.IsDir() || !os.SameFile(directoryInfo, openedInfo) {
		return nil, errors.Join(errors.New("receipt output directory changed while opened"), directory.Close())
	}
	output := &ReceiptOutput{
		path: path, directoryPath: directoryPath, name: name, directory: directory,
		directoryInfo: openedInfo, syncDirectory: unix.Fsync,
	}
	if err := output.requireTargetAbsent(); err != nil {
		return nil, errors.Join(err, output.Close())
	}
	return output, nil
}

func (value *ReceiptOutput) Commit(receipt Receipt) (result error) {
	if value == nil || value.directory == nil || value.closed || value.committed {
		return errors.New("receipt output handle is not open for one commit")
	}
	if err := value.verifyDirectoryBinding(); err != nil {
		return err
	}
	if err := value.requireTargetAbsent(); err != nil {
		return err
	}
	encoded, err := CanonicalJSON(receipt)
	if err != nil {
		return err
	}
	parsed, err := ParseReceipt(encoded)
	if err != nil || parsed.Digest != receipt.Digest {
		return errors.New("receipt output is not a valid sealed receipt")
	}
	temporaryName, err := privateTemporaryName()
	if err != nil {
		return err
	}
	descriptor, err := unix.Openat(int(value.directory.Fd()), temporaryName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create private receipt output: %w", err)
	}
	temporary := os.NewFile(uintptr(descriptor), temporaryName)
	if temporary == nil {
		_ = unix.Close(descriptor)
		return errors.New("private receipt output descriptor is invalid")
	}
	staged := true
	defer func() {
		if temporary != nil {
			result = errors.Join(result, temporary.Close())
		}
		if staged {
			if cleanupErr := unix.Unlinkat(int(value.directory.Fd()), temporaryName, 0); cleanupErr != nil &&
				!errors.Is(cleanupErr, unix.ENOENT) {
				result = errors.Join(result, fmt.Errorf("clean staged receipt output: %w", cleanupErr))
			}
		}
	}()
	if err := unix.Fchmod(descriptor, 0o600); err != nil {
		return err
	}
	if count, err := temporary.Write(encoded); err != nil || count != len(encoded) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		temporary = nil
		return err
	}
	temporary = nil
	if err := value.verifyDirectoryBinding(); err != nil {
		return err
	}
	if err := unix.Renameat2(int(value.directory.Fd()), temporaryName,
		int(value.directory.Fd()), value.name, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errors.New("receipt output already exists")
		}
		return fmt.Errorf("commit receipt output: %w", err)
	}
	staged = false
	value.committed = true
	if err := value.verifyCommittedReceipt(encoded); err != nil {
		return &ReceiptCommitAmbiguityError{Path: value.path, Cause: err}
	}
	if err := value.verifyDirectoryBinding(); err != nil {
		return &ReceiptCommitAmbiguityError{Path: value.path, Cause: err}
	}
	if err := value.syncDirectory(int(value.directory.Fd())); err != nil {
		return &ReceiptCommitAmbiguityError{Path: value.path, Cause: err}
	}
	return nil
}

func PreflightReceiptOutput(path string) error {
	output, err := OpenReceiptOutput(path)
	if err != nil {
		return err
	}
	return output.Close()
}

func (value *ReceiptOutput) Close() error {
	if value == nil || value.closed {
		return nil
	}
	value.closed = true
	return value.directory.Close()
}

func (value *ReceiptOutput) requireTargetAbsent() error {
	var status unix.Stat_t
	err := unix.Fstatat(int(value.directory.Fd()), value.name, &status, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return errors.New("receipt output already exists")
	}
	if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect receipt output: %w", err)
	}
	return nil
}

func (value *ReceiptOutput) verifyDirectoryBinding() error {
	literal, err := os.Lstat(value.directoryPath)
	if err != nil || !literal.IsDir() || literal.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(value.directoryInfo, literal) {
		return errors.New("receipt output directory no longer names the held descriptor")
	}
	return nil
}

func (value *ReceiptOutput) verifyCommittedReceipt(encoded []byte) error {
	descriptor, err := unix.Openat(int(value.directory.Fd()), value.name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("committed receipt could not be reopened")
	}
	file := os.NewFile(uintptr(descriptor), value.name)
	if file == nil {
		_ = unix.Close(descriptor)
		return errors.New("committed receipt descriptor is invalid")
	}
	status, err := file.Stat()
	if err != nil || !status.Mode().IsRegular() || status.Mode().Perm() != 0o600 || status.Size() != int64(len(encoded)) {
		_ = file.Close()
		return errors.New("committed receipt metadata is invalid")
	}
	observed, readErr := io.ReadAll(io.LimitReader(file, int64(len(encoded))+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(observed) != len(encoded) || digestBytes(observed) != digestBytes(encoded) {
		return errors.New("committed receipt bytes are invalid")
	}
	return nil
}

func privateTemporaryName() (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("generate receipt staging name: %w", err)
	}
	return ".c18-oci-publication-" + hex.EncodeToString(entropy[:]), nil
}

func readRegularFileSnapshot(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("input read context is required")
	}
	if !absoluteNormalizedPath(path) || maximum < 1 {
		return nil, errors.New("input path or bound is invalid")
	}
	parent := filepath.Dir(path)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return nil, errors.New("input parent may not contain symlinks")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("input descriptor is invalid")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum {
		return nil, errors.New("input metadata is invalid")
	}
	encoded, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: file}, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read input bytes: %w", err)
	}
	if int64(len(encoded)) != before.Size() {
		return nil, errors.New("input bytes are invalid")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("input changed while read")
	}
	return encoded, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (value contextReader) Read(target []byte) (int, error) {
	select {
	case <-value.ctx.Done():
		return 0, context.Cause(value.ctx)
	default:
		return value.reader.Read(target)
	}
}
