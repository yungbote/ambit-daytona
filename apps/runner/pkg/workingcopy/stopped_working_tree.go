// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/daytonaio/runner/pkg/generationstop"
	"golang.org/x/text/unicode/norm"
)

const (
	MaximumWorkingTreeDepth                = 64
	MaximumWorkingTreeEntries              = 4096
	MaximumWorkingTreeAggregateBytes int64 = 8 * 1024 * 1024 * 1024
	MaximumWorkingTreeReceiptBytes         = 4 * 1024 * 1024
	userFilesSemanticZoneRef               = "ambit.workspace-zone/user-files@1"
	stoppedWorkingTreeContract             = "ambit.working-copy-stopped-working-tree/v1"
	// The transport includes excluded bodies even though they are neither
	// hashed nor retained. Keep this physical bound independent from the
	// caller's smaller user-file budget and consume it without buffering.
	maximumWorkingTreeArchiveBytes = MaximumWorkingTreeAggregateBytes +
		(MaximumWorkingTreeEntries+1)*4*1024 + 1024*1024
)

// StoppedWorkingTree enumerates user files through host Docker authority. The
// managed runtime roots and exact host-supplied exclusions describe custody;
// they do not classify arbitrary user file contents as free of secrets.
func (s *Service) StoppedWorkingTree(ctx context.Context, sandboxID string, request StoppedWorkingTreeRequest) (StoppedWorkingTreeReceipt, error) {
	if err := s.validateWorkingTreeRequest(sandboxID, request); err != nil {
		return StoppedWorkingTreeReceipt{}, err
	}
	beforeStop, err := s.requireGenerationStop(ctx, request.Generation)
	if err != nil {
		return StoppedWorkingTreeReceipt{}, err
	}
	terminal := request.Generation.StopAuthority.TerminalGeneration
	if beforeStop.TerminalGeneration != terminal {
		return StoppedWorkingTreeReceipt{}, fmt.Errorf("%w: stopped generation changed before working-tree roster", ErrConflict)
	}
	before, err := s.statDirectoryPathChain(ctx, terminal.ContainerID, "/workspace")
	if err != nil {
		return StoppedWorkingTreeReceipt{}, err
	}
	archive, copyStat, err := s.containers.CopyFromContainer(ctx, terminal.ContainerID, "/workspace")
	if err != nil {
		return StoppedWorkingTreeReceipt{}, dockerReadError("open stopped working-tree Docker archive", err)
	}
	defer archive.Close()
	stopClosing := context.AfterFunc(ctx, func() { _ = archive.Close() })
	defer stopClosing()
	if !samePathStat(before[len(before)-1], copyStat) {
		return StoppedWorkingTreeReceipt{}, fmt.Errorf("%w: working-tree descriptor changed before archive read", ErrConflict)
	}
	receipt := StoppedWorkingTreeReceipt{
		Request: request, TerminalGeneration: terminal, Entries: []StoppedWorkingTreeEntry{},
		RosterDigest: "sha256:" + strings.Repeat("0", 64),
		ObservedAt:   "2000-01-01T00:00:00.000Z",
	}
	base, err := json.Marshal(receipt)
	if err != nil || len(base) > MaximumWorkingTreeReceiptBytes {
		return StoppedWorkingTreeReceipt{}, invalidf("working-tree request exceeds the receipt envelope")
	}
	receipt.Entries, err = readStoppedWorkingTreeTar(ctx, archive, request, MaximumWorkingTreeReceiptBytes-len(base))
	if err != nil {
		return StoppedWorkingTreeReceipt{}, err
	}
	after, err := s.statDirectoryPathChain(ctx, terminal.ContainerID, "/workspace")
	if err != nil {
		return StoppedWorkingTreeReceipt{}, err
	}
	if !samePathStatChain(before, after) {
		return StoppedWorkingTreeReceipt{}, fmt.Errorf("%w: working-tree path changed during roster", ErrConflict)
	}
	afterStop, err := s.requireGenerationStop(ctx, request.Generation)
	if err != nil {
		return StoppedWorkingTreeReceipt{}, err
	}
	if afterStop.TerminalGeneration != terminal {
		return StoppedWorkingTreeReceipt{}, fmt.Errorf("%w: stopped generation changed during working-tree roster", ErrConflict)
	}
	canonical, err := generationstop.CanonicalJSON(map[string]any{
		"contract": stoppedWorkingTreeContract, "request": request,
		"terminalGeneration": terminal, "entries": receipt.Entries,
	})
	if err != nil {
		return StoppedWorkingTreeReceipt{}, fmt.Errorf("%w: canonicalize working-tree roster: %w", ErrUnavailable, err)
	}
	receipt.RosterDigest = sha256Digest(canonical)
	receipt.ObservedAt = s.now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	return receipt, nil
}

func (s *Service) validateWorkingTreeRequest(sandboxID string, request StoppedWorkingTreeRequest) error {
	if err := s.validateGenerationBinding(sandboxID, request.Generation); err != nil {
		return err
	}
	if request.MaximumDepth < 1 || request.MaximumDepth > MaximumWorkingTreeDepth ||
		request.MaximumEntries < 1 || request.MaximumEntries > MaximumWorkingTreeEntries ||
		request.MaximumFileBytes < 1 || request.MaximumFileBytes > MaximumCaptureBytes ||
		request.MaximumAggregateBytes < request.MaximumFileBytes || request.MaximumAggregateBytes > MaximumWorkingTreeAggregateBytes ||
		request.ExcludedPaths == nil || len(request.ExcludedPaths) > MaximumWorkingTreeEntries {
		return invalidf("working-tree bounds or exclusions are invalid")
	}
	seen := make(map[string]struct{}, len(request.ExcludedPaths))
	for index, excluded := range request.ExcludedPaths {
		if !canonicalWorkingTreePath(excluded) ||
			(index > 0 && compareUTF8Lexicographic(request.ExcludedPaths[index-1], excluded) >= 0) {
			return invalidf("working-tree exclusions must be exact sorted unique relative paths")
		}
		for parent := path.Dir(excluded); parent != "."; parent = path.Dir(parent) {
			if _, exists := seen[parent]; exists {
				return invalidf("working-tree exclusions repeat an excluded ancestor")
			}
		}
		seen[excluded] = struct{}{}
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

func readStoppedWorkingTreeTar(ctx context.Context, archive io.Reader, request StoppedWorkingTreeRequest, entryBudget int) ([]StoppedWorkingTreeEntry, error) {
	initialEntryBudget := entryBudget
	bounded := &io.LimitedReader{R: captureContextReader{ctx: ctx, reader: archive}, N: maximumWorkingTreeArchiveBytes + 1}
	reader := tar.NewReader(bounded)
	root, err := reader.Next()
	if err != nil {
		return nil, captureArchiveError(ctx, "read working-tree root archive header", err)
	}
	if !canonicalRosterArchiveName(root.Name) || path.Clean(root.Name) != "workspace" ||
		root.Linkname != "" || root.Typeflag != tar.TypeDir || root.Size != 0 {
		return nil, fmt.Errorf("%w: working-tree archive root is invalid", ErrConflict)
	}
	exclusions := make(map[string]struct{}, len(request.ExcludedPaths))
	for _, excluded := range request.ExcludedPaths {
		exclusions[excluded] = struct{}{}
	}
	entries := make([]StoppedWorkingTreeEntry, 0)
	hardlinks := make(map[string]string)
	buffer := make([]byte, captureStreamBufferBytes)
	var aggregate, archiveBodyBytes int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, captureArchiveError(ctx, "read working-tree archive entry", err)
		}
		if !canonicalRosterArchiveName(header.Name) || !strings.HasPrefix(header.Name, "workspace/") {
			return nil, fmt.Errorf("%w: working-tree archive path escaped its root", ErrConflict)
		}
		if header.Size < 0 || header.Size > maximumWorkingTreeArchiveBytes-archiveBodyBytes {
			return nil, fmt.Errorf("%w: working-tree physical archive body bound exceeded", ErrConflict)
		}
		archiveBodyBytes += header.Size
		relative := strings.TrimSuffix(strings.TrimPrefix(header.Name, "workspace/"), "/")
		if excludedWorkingTreePath(relative, exclusions) {
			if _, err := io.CopyBuffer(io.Discard, reader, buffer); err != nil {
				return nil, captureArchiveError(ctx, "skip excluded working-tree archive entry", err)
			}
			continue
		}
		if !canonicalWorkingTreePath(relative) || len(strings.Split(relative, "/")) > request.MaximumDepth || len(entries) >= request.MaximumEntries {
			return nil, fmt.Errorf("%w: working-tree path, depth or entry bound exceeded", ErrConflict)
		}
		if header.Linkname != "" && header.Typeflag != tar.TypeSymlink && header.Typeflag != tar.TypeLink {
			return nil, fmt.Errorf("%w: working-tree entry has unsupported link metadata", ErrConflict)
		}
		if header.Typeflag != tar.TypeDir && strings.HasSuffix(header.Name, "/") {
			return nil, fmt.Errorf("%w: non-directory working-tree entry has a directory path", ErrConflict)
		}
		mode := fmt.Sprintf("%04o", header.FileInfo().Mode().Perm())
		entry := StoppedWorkingTreeEntry{ZoneRelativePath: relative, Name: path.Base(relative), Mode: &mode}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 || !header.FileInfo().Mode().IsDir() {
				return nil, fmt.Errorf("%w: working-tree directory descriptor is invalid", ErrConflict)
			}
			entry.Kind = "directory"
		case tar.TypeSymlink:
			if header.Size != 0 || !validWorkingTreeLinkTarget(header.Linkname) {
				return nil, fmt.Errorf("%w: working-tree symlink target or size is invalid", ErrConflict)
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
				return nil, fmt.Errorf("%w: working-tree hardlink target is not an admitted archive path", ErrConflict)
			}
			entry.Kind = "regular_file"
			hardlinks[relative] = target
		case tar.TypeFifo, tar.TypeChar, tar.TypeBlock:
			if header.Size != 0 {
				return nil, fmt.Errorf("%w: non-portable working-tree entry contains data", ErrConflict)
			}
			entry.Kind = "excluded"
			entry.ExcludedKind = map[byte]string{
				tar.TypeFifo: "fifo", tar.TypeChar: "character_device", tar.TypeBlock: "block_device",
			}[header.Typeflag]
		case tar.TypeReg, tar.TypeRegA:
			if !header.FileInfo().Mode().IsRegular() || header.Size < 0 || header.Size > request.MaximumFileBytes || header.Size > request.MaximumAggregateBytes-aggregate {
				return nil, fmt.Errorf("%w: working-tree file or aggregate byte bound exceeded", ErrConflict)
			}
			entry.Kind, entry.Size = "regular_file", header.Size
			aggregate += header.Size
			hasher := sha256.New()
			count, err := io.CopyBuffer(hasher, reader, buffer)
			if err != nil {
				return nil, captureArchiveError(ctx, "hash working-tree archive file", err)
			}
			if count != header.Size {
				return nil, fmt.Errorf("%w: working-tree file length drifted", ErrConflict)
			}
			digest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
			entry.SHA256 = &digest
		default:
			return nil, fmt.Errorf("%w: working-tree archive entry kind is unsupported", ErrConflict)
		}
		encoded, err := json.Marshal(entry)
		if err != nil {
			return nil, fmt.Errorf("%w: encode working-tree entry: %w", ErrUnavailable, err)
		}
		entryBudget -= len(encoded)
		if len(entries) > 0 {
			entryBudget--
		}
		if entryBudget < 0 {
			return nil, fmt.Errorf("%w: working-tree receipt exceeds its byte bound", ErrConflict)
		}
		entries = append(entries, entry)
	}
	for {
		count, err := bounded.Read(buffer)
		if bounded.N == 0 {
			return nil, fmt.Errorf("%w: working-tree physical archive bound exceeded", ErrConflict)
		}
		for _, value := range buffer[:count] {
			if value != 0 {
				return nil, fmt.Errorf("%w: working-tree archive contains trailing content", ErrConflict)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, captureArchiveError(ctx, "finish working-tree archive", err)
		}
	}
	sort.Slice(entries, func(left, right int) bool {
		return compareUTF8Lexicographic(entries[left].ZoneRelativePath, entries[right].ZoneRelativePath) < 0
	})
	paths := make(map[string]int, len(entries))
	for index, entry := range entries {
		if _, exists := paths[entry.ZoneRelativePath]; exists {
			return nil, fmt.Errorf("%w: working-tree roster repeats a path", ErrConflict)
		}
		for parent := path.Dir(entry.ZoneRelativePath); parent != "."; parent = path.Dir(parent) {
			if parentIndex, exists := paths[parent]; !exists || entries[parentIndex].Kind != "directory" {
				return nil, fmt.Errorf("%w: working-tree roster has no exact directory ancestry", ErrConflict)
			}
		}
		paths[entry.ZoneRelativePath] = index
	}
	resolving := make(map[string]bool)
	var resolveHardlink func(int) error
	resolveHardlink = func(index int) error {
		entry := &entries[index]
		if entry.Kind != "regular_file" {
			return fmt.Errorf("%w: working-tree hardlink target is not a regular file", ErrConflict)
		}
		if entry.SHA256 != nil {
			return nil
		}
		if resolving[entry.ZoneRelativePath] {
			return fmt.Errorf("%w: working-tree hardlinks contain a cycle", ErrConflict)
		}
		targetIndex, exists := paths[hardlinks[entry.ZoneRelativePath]]
		if !exists {
			return fmt.Errorf("%w: working-tree hardlink target is absent", ErrConflict)
		}
		resolving[entry.ZoneRelativePath] = true
		if err := resolveHardlink(targetIndex); err != nil {
			return err
		}
		target := entries[targetIndex]
		if target.Size > request.MaximumAggregateBytes-aggregate {
			return fmt.Errorf("%w: materialized working-tree hardlinks exceed aggregate byte bound", ErrConflict)
		}
		aggregate += target.Size
		entry.Size, entry.SHA256 = target.Size, target.SHA256
		delete(resolving, entry.ZoneRelativePath)
		return nil
	}
	for relative := range hardlinks {
		if err := resolveHardlink(paths[relative]); err != nil {
			return nil, err
		}
	}
	if len(hardlinks) > 0 {
		encoded, err := json.Marshal(entries)
		if err != nil || len(encoded)-2 > initialEntryBudget {
			return nil, fmt.Errorf("%w: materialized working-tree receipt exceeds its byte bound", ErrConflict)
		}
	}
	return entries, nil
}

func validWorkingTreeLinkTarget(value string) bool {
	return value != "" && len(value) <= 4096 && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
