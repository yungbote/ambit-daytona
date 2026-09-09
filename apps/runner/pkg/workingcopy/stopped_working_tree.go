// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	MaximumWorkingTreeDepth = 64

	MaximumWorkingTreeAggregateBytes int64 = 8 * 1024 * 1024 * 1024

	userFilesSemanticZoneRef = "ambit.workspace-zone/user-files@1"
)

func (s *Service) visitStoppedWorkingTreeArchive(ctx context.Context, generation CaptureGenerationBinding, visit func(io.Reader) error) error {
	beforeStop, err := s.requireGenerationStop(ctx, generation)
	if err != nil {
		return err
	}
	terminal := generation.StopAuthority.TerminalGeneration
	if beforeStop.TerminalGeneration != terminal {
		return fmt.Errorf("%w: stopped generation changed before working-tree roster", ErrConflict)
	}
	before, err := s.statDirectoryPathChain(ctx, terminal.ContainerID, "/workspace")
	if err != nil {
		return err
	}
	archive, copyStat, err := s.containers.CopyFromContainer(ctx, terminal.ContainerID, "/workspace")
	if err != nil {
		return dockerReadError("open stopped working-tree Docker archive", err)
	}
	defer archive.Close()
	stopClosing := context.AfterFunc(ctx, func() { _ = archive.Close() })
	defer stopClosing()
	if !samePathStat(before[len(before)-1], copyStat) {
		return fmt.Errorf("%w: working-tree descriptor changed before archive read", ErrConflict)
	}
	if err := visit(archive); err != nil {
		return err
	}
	after, err := s.statDirectoryPathChain(ctx, terminal.ContainerID, "/workspace")
	if err != nil {
		return err
	}
	if !samePathStatChain(before, after) {
		return fmt.Errorf("%w: working-tree path changed during roster", ErrConflict)
	}
	afterStop, err := s.requireGenerationStop(ctx, generation)
	if err != nil {
		return err
	}
	if afterStop.TerminalGeneration != terminal {
		return fmt.Errorf("%w: stopped generation changed during working-tree roster", ErrConflict)
	}
	return nil
}

func canonicalWorkingTreePath(value string) bool {
	return canonicalRelativePath(value) && norm.NFC.IsNormalString(value)
}

func reservedWorkingTreePath(relative string) bool {
	root, _, _ := strings.Cut(relative, "/")
	return root == ".ambit" || strings.HasPrefix(root, ".ambit-skill-")
}

func excludedWorkingTreePath(relative string, exclusions map[string]struct{}) bool {
	if reservedWorkingTreePath(relative) {
		return true
	}
	for candidate := relative; candidate != "."; candidate = path.Dir(candidate) {
		if _, excluded := exclusions[candidate]; excluded {
			return true
		}
	}
	return false
}

// The archive walker owns filesystem and physical-byte admission. Its visitor
// owns metadata custody, allowing a bounded receipt or externally sorted pages.
func visitStoppedWorkingTreeTar(ctx context.Context, archive io.Reader, request WorkingTreeInventoryRequest, maximumArchiveBytes int64, content io.Writer, visit func(StoppedWorkingTreeEntry, string) error) error {
	bounded := &io.LimitedReader{R: captureContextReader{ctx: ctx, reader: archive}, N: maximumArchiveBytes + 1}
	reader := tar.NewReader(bounded)
	root, err := reader.Next()
	if err != nil {
		return captureArchiveError(ctx, "read working-tree root archive header", err)
	}
	if !canonicalRosterArchiveName(root.Name) || path.Clean(root.Name) != "workspace" ||
		root.Linkname != "" || root.Typeflag != tar.TypeDir || root.Size != 0 {
		return fmt.Errorf("%w: working-tree archive root is invalid", ErrConflict)
	}
	exclusions := make(map[string]struct{}, len(request.ExcludedPaths))
	for _, excluded := range request.ExcludedPaths {
		exclusions[excluded] = struct{}{}
	}
	buffer := make([]byte, captureStreamBufferBytes)
	var aggregate, archiveBodyBytes int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return captureArchiveError(ctx, "read working-tree archive entry", err)
		}
		if !canonicalRosterArchiveName(header.Name) || !strings.HasPrefix(header.Name, "workspace/") {
			return fmt.Errorf("%w: working-tree archive path escaped its root", ErrConflict)
		}
		if header.Size < 0 || header.Size > maximumArchiveBytes-archiveBodyBytes {
			return fmt.Errorf("%w: working-tree physical archive body bound exceeded", ErrConflict)
		}
		archiveBodyBytes += header.Size
		relative := strings.TrimSuffix(strings.TrimPrefix(header.Name, "workspace/"), "/")
		if excludedWorkingTreePath(relative, exclusions) {
			if _, err := io.CopyBuffer(io.Discard, reader, buffer); err != nil {
				return captureArchiveError(ctx, "skip excluded working-tree archive entry", err)
			}
			continue
		}
		if !canonicalWorkingTreePath(relative) || len(strings.Split(relative, "/")) > request.MaximumDepth {
			return fmt.Errorf("%w: working-tree path, depth or entry bound exceeded", ErrConflict)
		}
		if header.Linkname != "" && header.Typeflag != tar.TypeSymlink && header.Typeflag != tar.TypeLink {
			return fmt.Errorf("%w: working-tree entry has unsupported link metadata", ErrConflict)
		}
		if header.Typeflag != tar.TypeDir && strings.HasSuffix(header.Name, "/") {
			return fmt.Errorf("%w: non-directory working-tree entry has a directory path", ErrConflict)
		}
		var hardlinkTarget string
		mode := fmt.Sprintf("%04o", header.FileInfo().Mode().Perm())
		entry := StoppedWorkingTreeEntry{ZoneRelativePath: relative, Name: path.Base(relative), Mode: &mode}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 || !header.FileInfo().Mode().IsDir() {
				return fmt.Errorf("%w: working-tree directory descriptor is invalid", ErrConflict)
			}
			entry.Kind = "directory"
		case tar.TypeSymlink:
			if header.Size != 0 || !validWorkingTreeLinkTarget(header.Linkname) {
				return fmt.Errorf("%w: working-tree symlink target or size is invalid", ErrConflict)
			}
			entry.Kind = "symlink"
			target := header.Linkname
			entry.LinkTarget = &target
		case tar.TypeLink:
			// Docker represents repeated inodes as archive links. Resolve only
			// against admitted regular entries after the whole archive is read;
			// no path from link metadata is ever opened or followed.
			target := strings.TrimPrefix(header.Linkname, "workspace/")
			if header.Size != 0 || !strings.HasPrefix(header.Linkname, "workspace/") ||
				!canonicalWorkingTreePath(target) || excludedWorkingTreePath(target, exclusions) {
				return fmt.Errorf("%w: working-tree hardlink target is not an admitted archive path", ErrConflict)
			}
			entry.Kind = "regular_file"
			hardlinkTarget = target
		case tar.TypeFifo, tar.TypeChar, tar.TypeBlock:
			if header.Size != 0 {
				return fmt.Errorf("%w: non-portable working-tree entry contains data", ErrConflict)
			}
			entry.Kind = "excluded"
			entry.ExcludedKind = map[byte]string{
				tar.TypeFifo: "fifo", tar.TypeChar: "character_device", tar.TypeBlock: "block_device",
			}[header.Typeflag]
		case tar.TypeReg, tar.TypeRegA:
			if !header.FileInfo().Mode().IsRegular() || header.Size < 0 || header.Size > request.MaximumFileBytes || header.Size > request.MaximumAggregateBytes-aggregate {
				return fmt.Errorf("%w: working-tree file or aggregate byte bound exceeded", ErrConflict)
			}
			entry.Kind, entry.Size = "regular_file", header.Size
			offset := aggregate
			entry.ByteOffset = &offset
			aggregate += header.Size
			hasher := sha256.New()
			count, err := io.CopyBuffer(io.MultiWriter(content, hasher), reader, buffer)
			if err != nil {
				return captureArchiveError(ctx, "hash working-tree archive file", err)
			}
			if count != header.Size {
				return fmt.Errorf("%w: working-tree file length drifted", ErrConflict)
			}
			digest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
			entry.SHA256 = &digest
		default:
			return fmt.Errorf("%w: working-tree archive entry kind is unsupported", ErrConflict)
		}
		if err := visit(entry, hardlinkTarget); err != nil {
			return err
		}
	}
	for {
		count, err := bounded.Read(buffer)
		if bounded.N == 0 {
			return fmt.Errorf("%w: working-tree physical archive bound exceeded", ErrConflict)
		}
		for _, value := range buffer[:count] {
			if value != 0 {
				return fmt.Errorf("%w: working-tree archive contains trailing content", ErrConflict)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return captureArchiveError(ctx, "finish working-tree archive", err)
		}
	}
	return nil
}

func validWorkingTreeLinkTarget(value string) bool {
	return value != "" && len(value) <= 4096 && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
