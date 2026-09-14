// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
// publication. ObserveGeneration proves the binding's exact source generation
// and reports whether it is still running or has already exited; Capture must
// return only a coherent, bounded copy of one file from a running source.
type FileSnapshotReader interface {
	ObserveGeneration(context.Context, CaptureBinding) (generationstop.CurrentGenerationObservation, error)
	Capture(context.Context, CaptureBinding, io.Writer, int64) (capturedFile, error)
}

// UpperLayerResolver reports the directory the storage driver mounts as a
// container root filesystem's writable upper layer. On overlayfs that layer
// holds the inode every writer of a copied-up file actually references.
type UpperLayerResolver interface {
	InspectUpperLayer(ctx context.Context, providerResourceID string) (string, error)
}

type NativeFileSnapshotReader struct {
	generations generationstop.GenerationInspector
	upperLayers UpperLayerResolver
}

func NewNativeFileSnapshotReader(generations generationstop.GenerationInspector, upperLayers UpperLayerResolver) *NativeFileSnapshotReader {
	return &NativeFileSnapshotReader{generations: generations, upperLayers: upperLayers}
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

func (s *NativeFileSnapshotReader) ObserveGeneration(ctx context.Context, binding CaptureBinding) (generationstop.CurrentGenerationObservation, error) {
	if s == nil || s.generations == nil {
		return generationstop.CurrentGenerationObservation{}, fmt.Errorf("%w: file snapshot generation inspector is unavailable", ErrUnavailable)
	}
	current, err := s.generations.InspectGeneration(ctx, binding.Source.ProviderResourceID)
	if err != nil {
		return current, fmt.Errorf("%w: inspect file snapshot generation: %w", ErrUnavailable, err)
	}
	owner := generationstop.ProviderOwner{
		TenantID: binding.Owner.TenantID, UserID: binding.Owner.UserID, WorkspaceID: binding.Owner.WorkspaceID,
		RunID: binding.Owner.RunID, GrantID: binding.Owner.GrantID,
	}
	// Exactly two source states are admitted: the bound generation still
	// running, or that same generation already exited. Anything else, including
	// a restarted generation, is a conflict rather than a different source.
	state := current.State
	running := state.Status == "running" && state.Running && state.PID > 0 && current.Generation.ExecutionFinishedAt == ""
	stopped := state.Status == "exited" && !state.Running && state.PID == 0 && current.Generation.ExecutionFinishedAt != ""
	if current.Source != binding.Source || current.Owner != owner || current.Fence != binding.FileSnapshot.Fence ||
		current.Generation.ExpectedGeneration != binding.FileSnapshot.Generation ||
		state.Paused || state.Restarting || state.Dead || (!running && !stopped) {
		return current, fmt.Errorf("%w: file snapshot lost its exact source generation", ErrConflict)
	}
	if stopped {
		finished, err := time.Parse(time.RFC3339Nano, current.Generation.ExecutionFinishedAt)
		started, startErr := time.Parse(time.RFC3339Nano, current.Generation.ExecutionStartedAt)
		if err != nil || startErr != nil || finished.Before(started) {
			return current, fmt.Errorf("%w: file snapshot source has invalid terminal facts", ErrConflict)
		}
	}
	return current, nil
}

func (s *NativeFileSnapshotReader) requireCurrent(ctx context.Context, binding CaptureBinding) (int, error) {
	current, err := s.ObserveGeneration(ctx, binding)
	if err != nil {
		return 0, err
	}
	if !current.State.Running {
		return 0, fmt.Errorf("%w: source stopped before live file snapshot", ErrConflict)
	}
	return current.State.PID, nil
}

// requireSamePID re-proves the running generation and that its init task is
// still the pinned one. An observation failure keeps its own classification.
func (s *NativeFileSnapshotReader) requireSamePID(ctx context.Context, binding CaptureBinding, pid int) error {
	currentPID, err := s.requireCurrent(ctx, binding)
	if err != nil {
		return err
	}
	if currentPID != pid {
		return fmt.Errorf("%w: source generation changed during file snapshot", ErrConflict)
	}
	return nil
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
	if err := s.requireSamePID(ctx, binding, pid); err != nil {
		return capturedFile{}, err
	}
	captured, err := copyLeasedFile(ctx, source, func() (*os.File, error) {
		return s.openWriterBearingFile(ctx, binding, root, source, zone+"/"+binding.Selector.ZoneRelativePath)
	}, output, maximumBytes)
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
		originalZone.Mask&(unix.STATX_INO|unix.STATX_MNT_ID) != unix.STATX_INO|unix.STATX_MNT_ID ||
		resolvedZone.Mask&(unix.STATX_INO|unix.STATX_MNT_ID) != unix.STATX_INO|unix.STATX_MNT_ID ||
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
	if err := s.requireSamePID(ctx, binding, pid); err != nil {
		return capturedFile{}, err
	}
	return captured, nil
}

// openWriterBearingFile returns the file whose inode carries every write
// reference to the selected file. On overlayfs the writable descriptions and
// shared mappings of a copied-up file belong to the upper inode; the overlay
// inode a lease would otherwise watch reports no writer once those descriptors
// close, so a mapping that outlived its descriptor could keep storing while a
// lease there was granted. The upper file is therefore opened directly under
// the storage driver's upper layer with the same path restrictions. A file
// that is not copied up, or that lives on an admitted non-overlay mount, has no
// such hidden writer: every write must first open it through the selected path,
// which breaks the lease held there. That argument needs the selected file's
// lease to be held already, so the caller resolves the bearing file only
// inside the exclusion window. The upper layer belongs to the container root
// filesystem alone; an admitted zone mount that is itself a foreign overlayfs
// has no known upper layer and is refused.
func (s *NativeFileSnapshotReader) openWriterBearingFile(ctx context.Context, binding CaptureBinding, root int, selected *os.File, containerPath string) (*os.File, error) {
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(int(selected.Fd()), &filesystem); err != nil {
		return nil, fmt.Errorf("%w: inspect file snapshot filesystem: %w", ErrUnavailable, err)
	}
	if filesystem.Type != unix.OVERLAYFS_SUPER_MAGIC {
		return selected, nil
	}
	var rootMount, selectedMount unix.Statx_t
	if unix.Statx(root, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &rootMount) != nil ||
		unix.Statx(int(selected.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &selectedMount) != nil ||
		rootMount.Mask&unix.STATX_MNT_ID == 0 || selectedMount.Mask&unix.STATX_MNT_ID == 0 ||
		rootMount.Mnt_id != selectedMount.Mnt_id {
		return nil, fmt.Errorf("%w: file snapshot cannot exclude writers on an overlay mount other than the container root", ErrUnavailable)
	}
	if s.upperLayers == nil {
		return nil, fmt.Errorf("%w: file snapshot upper layer resolver is unavailable", ErrUnavailable)
	}
	upperDir, err := s.upperLayers.InspectUpperLayer(ctx, binding.Source.ProviderResourceID)
	if err != nil {
		return nil, fmt.Errorf("%w: locate file snapshot upper layer: %w", ErrUnavailable, err)
	}
	upperRoot, err := unix.Open(upperDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open file snapshot upper layer: %w", ErrUnavailable, err)
	}
	defer unix.Close(upperRoot)
	fd, err := unix.Openat2(upperRoot, strings.TrimPrefix(containerPath, "/"), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if errors.Is(err, unix.ENOENT) {
		// Not copied up: no writable description or mapping can exist yet.
		return selected, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: resolve file snapshot upper file: %w", ErrConflict, err)
	}
	return os.NewFile(uintptr(fd), "working-copy-upper"), nil
}

// A read lease excludes existing writable descriptions/mappings of its inode
// and prevents new writable opens/truncation while held. It is not an
// advisory file lock. A conflicting open marks the lease breaking before the
// writer can proceed; F_GETLEASE then returns F_UNLCK, so even a forced
// timeout discards the copy. The reader polls the lease at the proof boundary
// and never delivers a process-wide asynchronous signal to the Runner.
type readLease struct{ fd int }

func acquireReadLease(fd int) (readLease, error) {
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETLEASE, unix.F_RDLCK); err != nil {
		return readLease{}, fmt.Errorf("%w: file is being written or its filesystem cannot exclude writers: %w", ErrUnavailable, err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETOWN, 0); err != nil {
		unix.FcntlInt(uintptr(fd), unix.F_SETLEASE, unix.F_UNLCK)
		return readLease{}, fmt.Errorf("%w: configure file snapshot lease: %w", ErrUnavailable, err)
	}
	return readLease{fd: fd}, nil
}

func (lease readLease) intact() bool {
	kind, err := unix.FcntlInt(uintptr(lease.fd), unix.F_GETLEASE, 0)
	return err == nil && kind == unix.F_RDLCK
}

func (lease readLease) release() {
	unix.FcntlInt(uintptr(lease.fd), unix.F_SETLEASE, unix.F_UNLCK)
}

// leasedFile is one regular file whose writers are excluded, with the exact
// metadata observed after that exclusion took effect.
type leasedFile struct {
	file  *os.File
	lease readLease
	stat  unix.Stat_t
}

func leaseFile(file *os.File, maximumBytes int64) (leasedFile, error) {
	fd := int(file.Fd())
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return leasedFile{}, fmt.Errorf("%w: file snapshot requires one regular file without hardlink aliases", ErrConflict)
	}
	if stat.Size < 0 || stat.Size > maximumBytes {
		return leasedFile{}, fmt.Errorf("%w: file snapshot exceeds its byte bound", ErrConflict)
	}
	lease, err := acquireReadLease(fd)
	if err != nil {
		return leasedFile{}, err
	}
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size < 0 || stat.Size > maximumBytes {
		lease.release()
		return leasedFile{}, fmt.Errorf("%w: file changed before writer exclusion", ErrConflict)
	}
	return leasedFile{file: file, lease: lease, stat: stat}, nil
}

// unchanged reports whether the lease is still held and the inode metadata
// still equals what was observed after writer exclusion.
func (leased leasedFile) unchanged() bool {
	var after unix.Stat_t
	if unix.Fstat(int(leased.file.Fd()), &after) != nil || !leased.lease.intact() {
		return false
	}
	before := leased.stat
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Size == after.Size &&
		before.Nlink == after.Nlink && before.Mtim == after.Mtim && before.Ctim == after.Ctim
}

// copyLeasedFile copies the selected file while both it and the file bearing
// its write references are leased. The bearing file is resolved only after
// the selected file's lease is held, so a copy-up racing that resolution must
// open through the selected path and break the lease. The two are the same
// file unless the selected path is a copied-up overlayfs file. Leases do not
// stop a read-only open with O_TRUNC or a copy-up caused by a metadata
// change; the metadata reproof after the copy rejects those. Never publish
// bytes on a metadata-only or ordinary-stream fallback.
func copyLeasedFile(ctx context.Context, selected *os.File, bearing func() (*os.File, error), output io.Writer, maximumBytes int64) (capturedFile, error) {
	leased, err := leaseFile(selected, maximumBytes)
	if err != nil {
		return capturedFile{}, err
	}
	defer leased.lease.release()
	writerBearing := leased
	if bearingFile, err := bearing(); err != nil {
		return capturedFile{}, err
	} else if bearingFile != selected {
		defer bearingFile.Close()
		if writerBearing, err = leaseFile(bearingFile, maximumBytes); err != nil {
			return capturedFile{}, err
		}
		defer writerBearing.lease.release()
		// Overlayfs answers getattr for a copied-up file from its upper inode,
		// so the upper file must describe exactly the selected file's bytes.
		if selectedStat, upperStat := leased.stat, writerBearing.stat; selectedStat.Size != upperStat.Size ||
			selectedStat.Mtim != upperStat.Mtim || selectedStat.Ctim != upperStat.Ctim {
			return capturedFile{}, fmt.Errorf("%w: file snapshot upper layer does not describe the selected file", ErrConflict)
		}
	}
	digest := sha256.New()
	bytes, err := io.CopyBuffer(io.MultiWriter(output, digest), io.LimitReader(captureContextReader{ctx: ctx, reader: selected}, leased.stat.Size+1), make([]byte, captureStreamBufferBytes))
	if err != nil {
		return capturedFile{}, fmt.Errorf("%w: file snapshot copy interrupted: %w", ErrUnavailable, err)
	}
	selectedIntact := leased.unchanged()
	bearingIntact := writerBearing.unchanged()
	if ctx.Err() != nil {
		return capturedFile{}, fmt.Errorf("%w: file snapshot canceled: %w", ErrUnavailable, ctx.Err())
	}
	if bytes != leased.stat.Size || !selectedIntact || !bearingIntact {
		return capturedFile{}, fmt.Errorf("%w: file changed or writer exclusion was withdrawn during snapshot", ErrConflict)
	}
	return capturedFile{byteLength: bytes, digest: "sha256:" + hex.EncodeToString(digest.Sum(nil)), capturedAt: time.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")}, nil
}
