// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"golang.org/x/sys/unix"
)

// FileSnapshotReader shares the capture owner's private scratch and durable
// publication. It must return only a coherent, bounded copy of one source file.
type FileSnapshotReader interface {
	Capture(context.Context, CaptureBinding, io.Writer, int64) (capturedFile, error)
}

type NativeFileSnapshotReader struct {
	generations generationstop.GenerationInspector
}

func NewNativeFileSnapshotReader(generations generationstop.GenerationInspector) *NativeFileSnapshotReader {
	return &NativeFileSnapshotReader{generations: generations}
}

func (s *Service) validateCaptureSource(sandboxID string, binding CaptureBinding) error {
	if binding.FileSnapshot == (FileSnapshotSource{}) {
		return s.validateGenerationBinding(sandboxID, binding.generationBinding())
	}
	if binding.StopAuthority != (generationstop.StopAuthority{}) ||
		binding.FileSnapshot.Contract != FileSnapshotContract ||
		!boundedRef(binding.FileSnapshot.Fence.WorkspaceExecutionManifestRef, 2048) {
		return invalidf("file snapshot requires exactly one canonical source authority")
	}
	if err := generationstop.ValidateSource(binding.Source); err != nil {
		return invalidf("file snapshot source is invalid")
	}
	if err := generationstop.ValidateOwner(binding.Owner); err != nil {
		return invalidf("file snapshot owner is invalid")
	}
	if err := generationstop.ValidateExpectedGeneration(binding.FileSnapshot.Generation); err != nil {
		return invalidf("file snapshot generation is invalid")
	}
	if !boundedRef(sandboxID, 512) || binding.Source.ProviderResourceID != sandboxID ||
		binding.Source.ExpectedProfile != "managed-container" || binding.Source.ExpectedRuntimeKind != "full_image_runtime_pack" ||
		!boundedRef(binding.ProviderName, 512) || len(binding.RequestFingerprint) != 64 || !isLowerHex(binding.RequestFingerprint) {
		return invalidf("file snapshot binding is invalid")
	}
	if err := validateAuthority(binding.Authority); err != nil {
		return err
	}
	if binding.Authority != s.admittedAuthority {
		return invalidf("file snapshot authority is not the admitted current lineage")
	}
	if binding.Selector.SemanticZoneRef == userFilesSemanticZoneRef {
		return invalidf("file snapshot cannot substitute for private working-tree capture")
	}
	return nil
}

func (s *NativeFileSnapshotReader) requireCurrent(ctx context.Context, binding CaptureBinding) (int, error) {
	if s == nil || s.generations == nil {
		return 0, fmt.Errorf("%w: file snapshot generation inspector is unavailable", ErrUnavailable)
	}
	current, err := s.generations.InspectGeneration(ctx, binding.Source.ProviderResourceID)
	if err != nil {
		return 0, fmt.Errorf("%w: inspect file snapshot generation: %w", ErrUnavailable, err)
	}
	owner := generationstop.ProviderOwner{
		TenantID: binding.Owner.TenantID, UserID: binding.Owner.UserID, WorkspaceID: binding.Owner.WorkspaceID,
		RunID: binding.Owner.RunID, GrantID: binding.Owner.GrantID,
	}
	if current.Source != binding.Source || current.Owner != owner || current.Fence != binding.FileSnapshot.Fence ||
		current.Generation.ExpectedGeneration != binding.FileSnapshot.Generation || current.Generation.ExecutionFinishedAt != "" ||
		current.State.Status != "running" || !current.State.Running || current.State.Paused || current.State.Restarting ||
		current.State.Dead || current.State.PID <= 0 {
		return 0, fmt.Errorf("%w: file snapshot lost its exact running source generation", ErrConflict)
	}
	return current.State.PID, nil
}

func (s *NativeFileSnapshotReader) Capture(ctx context.Context, binding CaptureBinding, output io.Writer, maximumBytes int64) (capturedFile, error) {
	pid, err := s.requireCurrent(ctx, binding)
	if err != nil {
		return capturedFile{}, err
	}
	// The proc directory pins this task. If it exits, root resolution fails;
	// it cannot silently resolve a replacement process that reuses the PID.
	process, err := unix.Open("/proc/"+strconv.Itoa(pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return capturedFile{}, fmt.Errorf("%w: open source process: %w", ErrUnavailable, err)
	}
	defer unix.Close(process)
	root, err := unix.Openat(process, "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return capturedFile{}, fmt.Errorf("%w: open source root: %w", ErrUnavailable, err)
	}
	defer unix.Close(root)
	zone, ok := semanticZoneRoot(binding.Selector.SemanticZoneRef)
	if !ok || !canonicalRelativePath(binding.Selector.ZoneRelativePath) {
		return capturedFile{}, invalidf("file snapshot selector is invalid")
	}
	// Opening the semantic root allows its admitted mount. Descendant traversal
	// cannot cross any other mount or follow symlinks, including magic links.
	zoneFD, err := unix.Openat2(root, strings.TrimPrefix(zone, "/"), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return capturedFile{}, fmt.Errorf("%w: resolve file snapshot zone: %w", ErrConflict, err)
	}
	defer unix.Close(zoneFD)
	file, err := unix.Openat2(zoneFD, binding.Selector.ZoneRelativePath, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return capturedFile{}, fmt.Errorf("%w: resolve file snapshot: %w", ErrConflict, err)
	}
	source := os.NewFile(uintptr(file), "working-copy-source")
	defer source.Close()
	if currentPID, err := s.requireCurrent(ctx, binding); err != nil || currentPID != pid {
		return capturedFile{}, fmt.Errorf("%w: source generation changed while opening file: %v", ErrConflict, err)
	}
	captured, err := copyLeasedFile(ctx, source, output, maximumBytes)
	if err != nil {
		return capturedFile{}, err
	}
	// Resolve from the pinned container root again, including the semantic
	// zone itself. Reusing only zoneFD would miss a replaced/moved zone.
	currentZone, err := unix.Openat2(root, strings.TrimPrefix(zone, "/"), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return capturedFile{}, fmt.Errorf("%w: file snapshot zone changed: %w", ErrConflict, err)
	}
	defer unix.Close(currentZone)
	var originalZone, resolvedZone unix.Statx_t
	if unix.Statx(zoneFD, "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_MNT_ID, &originalZone) != nil ||
		unix.Statx(currentZone, "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_MNT_ID, &resolvedZone) != nil ||
		originalZone.Ino != resolvedZone.Ino || originalZone.Mnt_id != resolvedZone.Mnt_id ||
		originalZone.Dev_major != resolvedZone.Dev_major || originalZone.Dev_minor != resolvedZone.Dev_minor {
		return capturedFile{}, fmt.Errorf("%w: file snapshot semantic zone was replaced", ErrConflict)
	}
	currentFile, err := unix.Openat2(currentZone, binding.Selector.ZoneRelativePath, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return capturedFile{}, fmt.Errorf("%w: file snapshot path changed: %w", ErrConflict, err)
	}
	defer unix.Close(currentFile)
	var selected, current unix.Stat_t
	if unix.Fstat(file, &selected) != nil || unix.Fstat(currentFile, &current) != nil ||
		selected.Dev != current.Dev || selected.Ino != current.Ino || current.Nlink != 1 {
		return capturedFile{}, fmt.Errorf("%w: file snapshot path names different source bytes", ErrConflict)
	}
	if currentPID, err := s.requireCurrent(ctx, binding); err != nil || currentPID != pid {
		return capturedFile{}, fmt.Errorf("%w: source generation changed during file snapshot: %v", ErrConflict, err)
	}
	return captured, nil
}

// A read lease excludes existing writable descriptions/mappings and prevents
// new writable opens/truncation while held. It is not an advisory file lock.
// A conflicting open marks the lease breaking before the writer can proceed;
// F_GETLEASE then returns F_UNLCK, so even a forced timeout discards the copy.
// Never publish bytes on a metadata-only or ordinary-stream fallback.
func copyLeasedFile(ctx context.Context, source *os.File, output io.Writer, maximumBytes int64) (capturedFile, error) {
	fd := source.Fd()
	var before unix.Stat_t
	if err := unix.Fstat(int(fd), &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 {
		return capturedFile{}, fmt.Errorf("%w: file snapshot requires one regular file without hardlink aliases", ErrConflict)
	}
	if before.Size < 0 || before.Size > maximumBytes {
		return capturedFile{}, fmt.Errorf("%w: file snapshot exceeds its byte bound", ErrConflict)
	}
	if _, err := unix.FcntlInt(fd, unix.F_SETLEASE, unix.F_RDLCK); err != nil {
		return capturedFile{}, fmt.Errorf("%w: file is being written or its filesystem cannot exclude writers: %w", ErrUnavailable, err)
	}
	defer unix.FcntlInt(fd, unix.F_SETLEASE, unix.F_UNLCK)
	// The reader polls the lease at the proof boundary. Do not deliver a
	// process-wide asynchronous signal to the long-lived Runner.
	if _, err := unix.FcntlInt(fd, unix.F_SETOWN, 0); err != nil {
		return capturedFile{}, fmt.Errorf("%w: configure file snapshot lease: %w", ErrUnavailable, err)
	}
	if err := unix.Fstat(int(fd), &before); err != nil || before.Nlink != 1 || before.Size < 0 || before.Size > maximumBytes {
		return capturedFile{}, fmt.Errorf("%w: file changed before writer exclusion", ErrConflict)
	}
	digest := sha256.New()
	bytes, err := io.CopyBuffer(io.MultiWriter(output, digest), io.LimitReader(captureContextReader{ctx: ctx, reader: source}, before.Size+1), make([]byte, captureStreamBufferBytes))
	if err != nil {
		return capturedFile{}, fmt.Errorf("%w: file snapshot copy interrupted: %w", ErrUnavailable, err)
	}
	var after unix.Stat_t
	statErr := unix.Fstat(int(fd), &after)
	lease, leaseErr := unix.FcntlInt(fd, unix.F_GETLEASE, 0)
	if ctx.Err() != nil {
		return capturedFile{}, ctx.Err()
	}
	if statErr != nil || leaseErr != nil || lease != unix.F_RDLCK || bytes != before.Size ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Nlink != after.Nlink ||
		before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return capturedFile{}, fmt.Errorf("%w: file changed or writer exclusion was withdrawn during snapshot", ErrConflict)
	}
	return capturedFile{byteLength: bytes, digest: "sha256:" + hex.EncodeToString(digest.Sum(nil)), capturedAt: time.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")}, nil
}
