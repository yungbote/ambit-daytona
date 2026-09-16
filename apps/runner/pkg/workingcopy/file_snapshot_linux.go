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
// publication. ObserveGeneration proves the binding's exact source generation
// and reports whether it is still running or has already exited; Capture must
// return only a coherent, bounded copy of one file from a running source.
type FileSnapshotReader interface {
	ObserveGeneration(context.Context, CaptureBinding) (generationstop.CurrentGenerationObservation, error)
	Capture(context.Context, CaptureBinding, io.Writer, int64) (capturedFile, error)
}

type NativeFileSnapshotReader struct {
	generations generationstop.GenerationInspector
}

func NewNativeFileSnapshotReader(generations generationstop.GenerationInspector) *NativeFileSnapshotReader {
	return &NativeFileSnapshotReader{generations: generations}
}

func (s *Service) validateCaptureSource(sandboxID string, binding CaptureBinding) error {
	if binding.SandboxFile != (SandboxFileSource{}) {
		return validateSandboxFileBinding(sandboxID, binding)
	}
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
	if binding.Selector.SemanticZoneRef == userFilesSemanticZoneRef {
		return invalidf("file snapshot cannot substitute for private working-tree capture")
	}
	return nil
}

func (s *NativeFileSnapshotReader) ObserveGeneration(ctx context.Context, binding CaptureBinding) (generationstop.CurrentGenerationObservation, error) {
	if binding.SandboxFile != (SandboxFileSource{}) {
		current, err := s.ObserveSandboxGeneration(ctx, binding.SandboxFile.SandboxID, binding.SandboxFile.OrganizationID)
		if err != nil {
			return generationstop.CurrentGenerationObservation{}, err
		}
		if current.Generation.ExpectedGeneration != binding.SandboxFile.Generation {
			return generationstop.CurrentGenerationObservation{}, fmt.Errorf("%w: native file snapshot lost its exact source generation", ErrConflict)
		}
		return generationstop.CurrentGenerationObservation{Generation: current.Generation, State: current.State}, nil
	}
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

// ObserveSandboxGeneration is native provider authority. It does not reinterpret
// Product labels or create a Product owner, fence, stop grant, or qualification.
func (s *NativeFileSnapshotReader) ObserveSandboxGeneration(ctx context.Context, sandboxID, organizationID string) (generationstop.SandboxGenerationObservation, error) {
	if s == nil {
		return generationstop.SandboxGenerationObservation{}, fmt.Errorf("%w: native sandbox inspector is unavailable", ErrUnavailable)
	}
	inspector, ok := s.generations.(generationstop.SandboxGenerationInspector)
	if !ok {
		return generationstop.SandboxGenerationObservation{}, fmt.Errorf("%w: native sandbox inspector is unavailable", ErrUnavailable)
	}
	current, err := inspector.InspectSandboxGeneration(ctx, sandboxID)
	if err != nil {
		return current, fmt.Errorf("%w: inspect native sandbox generation: %w", ErrUnavailable, err)
	}
	state := current.State
	if current.SandboxID != sandboxID || current.OrganizationID != organizationID ||
		generationstop.ValidateExpectedGeneration(current.Generation.ExpectedGeneration) != nil ||
		state.Status != "running" || !state.Running || state.PID <= 0 || state.Paused || state.Restarting || state.Dead ||
		current.Generation.ExecutionFinishedAt != "" {
		return current, fmt.Errorf("%w: native file snapshot requires its exact owned running sandbox", ErrConflict)
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
	captured, err := copyClonedFile(ctx, source, zoneFD, output, maximumBytes, unix.IoctlFileClone)
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

// copyClonedFile obtains a kernel-owned point-in-time copy of the selected
// descriptor. Both descriptors belong to the admitted zone's mount; OverlayFS
// resolves its own backing files. No upper-layer pathname or metadata match
// stands in for backing-file identity. Unsupported reflink or O_TMPFILE support
// returns unavailable, without a stream-copy or workspace-pause fallback.
//
// clone is the single kernel operation, supplied explicitly so deterministic
// tests can exercise publication and cleanup without claiming filesystem
// qualification. Production always supplies unix.IoctlFileClone.
func copyClonedFile(ctx context.Context, selected *os.File, zoneFD int, output io.Writer, maximumBytes int64, clone func(int, int) error) (capturedFile, error) {
	if err := ctx.Err(); err != nil {
		return capturedFile{}, fmt.Errorf("%w: file snapshot canceled: %w", ErrUnavailable, err)
	}
	if maximumBytes < 0 || maximumBytes > MaximumCaptureBytes {
		return capturedFile{}, invalidf("file snapshot byte bound is invalid")
	}
	var sourceStat unix.Stat_t
	if err := unix.Fstat(int(selected.Fd()), &sourceStat); err != nil || sourceStat.Mode&unix.S_IFMT != unix.S_IFREG || sourceStat.Nlink != 1 {
		return capturedFile{}, fmt.Errorf("%w: file snapshot requires one regular file without hardlink aliases", ErrConflict)
	}
	// O_TMPFILE never gives workspace processes a pathname to the snapshot.
	// O_EXCL also forbids linking it later. The host alone retains its descriptor;
	// closing it on every exit releases this temporary filesystem custody.
	fd, err := unix.Openat(zoneFD, ".", unix.O_TMPFILE|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		return capturedFile{}, fmt.Errorf("%w: create private same-mount file snapshot: %w", ErrUnavailable, err)
	}
	snapshot := os.NewFile(uintptr(fd), "working-copy-file-snapshot")
	defer snapshot.Close()
	if err := ctx.Err(); err != nil {
		return capturedFile{}, fmt.Errorf("%w: file snapshot canceled: %w", ErrUnavailable, err)
	}
	// FICLONE may block in the filesystem. Cancellation cannot interrupt every
	// kernel wait; check again before releasing any bytes. No worker goroutine
	// outlives this call or retains the temporary descriptor after it returns.
	cloneErr := clone(fd, int(selected.Fd()))
	capturedAt := time.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	if err := ctx.Err(); err != nil {
		return capturedFile{}, fmt.Errorf("%w: file snapshot canceled: %w", ErrUnavailable, err)
	}
	if cloneErr != nil {
		return capturedFile{}, fmt.Errorf("%w: atomic file cloning is unavailable on the source filesystem: %w", ErrUnavailable, cloneErr)
	}
	var snapshotStat unix.Stat_t
	if err := unix.Fstat(fd, &snapshotStat); err != nil || snapshotStat.Mode&unix.S_IFMT != unix.S_IFREG ||
		snapshotStat.Nlink != 0 || snapshotStat.Mode&0077 != 0 {
		return capturedFile{}, fmt.Errorf("%w: file snapshot lost private temporary custody", ErrConflict)
	}
	// The source can change while being selected. Its earlier size is not the
	// clone's size: bound and hash only the exact immutable copy obtained.
	if snapshotStat.Size < 0 || snapshotStat.Size > maximumBytes {
		return capturedFile{}, fmt.Errorf("%w: file snapshot exceeds its byte bound", ErrConflict)
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		return capturedFile{}, fmt.Errorf("%w: rewind file snapshot: %w", ErrUnavailable, err)
	}
	digest := sha256.New()
	bytes, err := io.CopyBuffer(io.MultiWriter(output, digest), io.LimitReader(captureContextReader{ctx: ctx, reader: snapshot}, snapshotStat.Size+1), make([]byte, captureStreamBufferBytes))
	if err != nil {
		return capturedFile{}, fmt.Errorf("%w: file snapshot copy interrupted: %w", ErrUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return capturedFile{}, fmt.Errorf("%w: file snapshot canceled: %w", ErrUnavailable, err)
	}
	if bytes != snapshotStat.Size {
		return capturedFile{}, fmt.Errorf("%w: file snapshot byte length changed", ErrConflict)
	}
	return capturedFile{byteLength: bytes, digest: "sha256:" + hex.EncodeToString(digest.Sum(nil)), capturedAt: capturedAt}, nil
}
