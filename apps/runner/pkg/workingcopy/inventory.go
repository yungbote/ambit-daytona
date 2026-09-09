// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/storage"
)

type inventoryDeletion struct {
	Request            WorkingTreeInventoryRequest `json:"request"`
	ProviderResourceID string                      `json:"providerResourceId"`
	PageCount          int                         `json:"pageCount"`
	BytePartCount      int                         `json:"bytePartCount"`
}

func (s *Service) validateInventoryRequest(sandboxID string, request WorkingTreeInventoryRequest) error {
	if err := s.validateGenerationBinding(sandboxID, request.Generation); err != nil {
		return err
	}
	if request.MaximumDepth < 1 || request.MaximumDepth > MaximumWorkingTreeDepth || request.MaximumFileBytes < 1 || request.MaximumFileBytes > MaximumWorkingTreeAggregateBytes || request.MaximumAggregateBytes < request.MaximumFileBytes || request.MaximumAggregateBytes > MaximumWorkingTreeAggregateBytes || request.ExcludedPaths == nil || len(request.ExcludedPaths) > 4096 {
		return invalidf("inventory bounds or exclusions are invalid")
	}
	seen := make(map[string]struct{}, len(request.ExcludedPaths))
	for index, excluded := range request.ExcludedPaths {
		if !canonicalWorkingTreePath(excluded) || (index > 0 && compareUTF8Lexicographic(request.ExcludedPaths[index-1], excluded) >= 0) {
			return invalidf("inventory exclusions must be sorted unique paths")
		}
		for parent := path.Dir(excluded); parent != "."; parent = path.Dir(parent) {
			if _, exists := seen[parent]; exists {
				return invalidf("inventory exclusions repeat an excluded ancestor")
			}
		}
		seen[excluded] = struct{}{}
	}
	if request.MaximumPageEntries < 1 || request.MaximumPageEntries > MaximumWorkingTreeInventoryPageEntries ||
		request.MaximumPageBytes < 2 || request.MaximumPageBytes > MaximumWorkingTreeInventoryPageBytes {
		return invalidf("working-tree inventory page bounds are invalid")
	}
	return nil
}

func inventoryRoot(request WorkingTreeInventoryRequest) string {
	generation := request.Generation
	return bindingObjectRoot(CaptureBinding{ProviderName: generation.ProviderName, RequestFingerprint: generation.RequestFingerprint, Owner: generation.Owner}) + "/tree-inventory-v1"
}

func inventoryResourceID(request WorkingTreeInventoryRequest) string {
	canonical, _ := generationstop.CanonicalJSON(request)
	return "daytona-working-tree-inventory:v1:" + sha256Digest(canonical)
}

func inventoryPageKey(root string, index int) string {
	return fmt.Sprintf("%s/pages/%012d.json", root, index)
}

func inventoryDigest(receipt WorkingTreeInventoryReceipt) (string, error) {
	canonical, err := generationstop.CanonicalJSON(map[string]any{
		"contract": workingTreeInventoryContract, "request": receipt.Request,
		"terminalGeneration": receipt.TerminalGeneration, "pages": receipt.Pages,
		"entryCount": receipt.EntryCount, "aggregateBytes": receipt.AggregateBytes, "bytePack": receipt.BytePack,
	})
	if err != nil {
		return "", err
	}
	return sha256Digest(canonical), nil
}

func (s *Service) inventoryObject(ctx context.Context, key string, maximum int64) ([]byte, bool, error) {
	data, err := s.objects.GetPrivateObject(ctx, key, maximum)
	if errors.Is(err, storage.ErrPrivateObjectNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, objectReadError("read working-tree inventory", err)
	}
	return data, true, nil
}

func (s *Service) createInventoryObject(ctx context.Context, key string, data []byte) error {
	err := s.objects.CreatePrivateObject(ctx, key, data, "application/json", map[string]string{"contract": workingTreeInventoryContract})
	if err == nil {
		return nil
	}
	winner, exists, readErr := s.inventoryObject(ctx, key, int64(len(data)+1))
	if readErr != nil {
		return errors.Join(fmt.Errorf("%w: publish inventory object: %w", ErrOutcomeUnknown, err), readErr)
	}
	if !exists {
		return fmt.Errorf("%w: inventory publication is unresolved: %w", ErrOutcomeUnknown, err)
	}
	if !bytes.Equal(winner, data) {
		return fmt.Errorf("%w: immutable inventory object differs from its exact request", ErrConflict)
	}
	return nil
}

func (s *Service) inventoryDeleting(ctx context.Context, request WorkingTreeInventoryRequest) (inventoryDeletion, bool, error) {
	data, exists, err := s.inventoryObject(ctx, inventoryRoot(request)+"/deletion.json", maximumIntentBytes)
	if err != nil || !exists {
		return inventoryDeletion{}, exists, err
	}
	var deletion inventoryDeletion
	if err := decodeInventoryJSON(data, &deletion); err != nil {
		return deletion, false, fmt.Errorf("%w: inventory deletion is invalid", ErrConflict)
	}
	actual, _ := generationstop.CanonicalJSON(deletion.Request)
	expected, _ := generationstop.CanonicalJSON(request)
	if !bytes.Equal(actual, expected) || deletion.ProviderResourceID != inventoryResourceID(request) || deletion.PageCount < 0 || deletion.PageCount > MaximumWorkingTreeInventoryIndexBytes || deletion.BytePartCount < 0 || deletion.BytePartCount > MaximumWorkingTreeInventoryIndexBytes {
		return deletion, false, fmt.Errorf("%w: inventory deletion belongs to another request", ErrConflict)
	}
	return deletion, true, nil
}

func (s *Service) requireInventoryNotDeleting(ctx context.Context, request WorkingTreeInventoryRequest) error {
	_, deleting, err := s.inventoryDeleting(ctx, request)
	if err != nil {
		return err
	}
	if deleting {
		return fmt.Errorf("%w: working-tree inventory has been retired", ErrConflict)
	}
	return nil
}

// PrepareWorkingTreeInventory streams one stopped archive into bounded sorted
// runs, then publishes immutable metadata pages and the complete index last.
// A completed replay reads only that index; it never traverses the source again.
func (s *Service) PrepareWorkingTreeInventory(ctx context.Context, sandboxID string, request WorkingTreeInventoryRequest) (WorkingTreeInventoryReceipt, error) {
	if err := s.validateInventoryRequest(sandboxID, request); err != nil {
		return WorkingTreeInventoryReceipt{}, err
	}
	root := inventoryRoot(request)
	release := s.locks.acquire(root)
	defer release()
	if err := s.requireInventoryNotDeleting(ctx, request); err != nil {
		return WorkingTreeInventoryReceipt{}, err
	}
	if receipt, exists, err := s.readInventoryIndex(ctx, request); err != nil || exists {
		return receipt, err
	}
	if _, err := s.requireGenerationStop(ctx, request.Generation); err != nil {
		return WorkingTreeInventoryReceipt{}, err
	}
	intent, err := generationstop.CanonicalJSON(request)
	if err != nil || len(intent) > maximumIntentBytes {
		return WorkingTreeInventoryReceipt{}, invalidf("inventory request exceeds its intent bound")
	}
	if err := s.createInventoryObject(ctx, root+"/intent.json", intent); err != nil {
		return WorkingTreeInventoryReceipt{}, err
	}
	sorter, err := newInventorySorter()
	if err != nil {
		return WorkingTreeInventoryReceipt{}, fmt.Errorf("%w: open inventory scratch: %w", ErrUnavailable, err)
	}
	defer sorter.Close()
	byteWriter, err := newInventoryBytePackWriter()
	if err != nil {
		return WorkingTreeInventoryReceipt{}, fmt.Errorf("%w: open inventory byte scratch: %w", ErrUnavailable, err)
	}
	defer byteWriter.Close()
	err = s.visitStoppedWorkingTreeArchive(ctx, request.Generation, func(archive io.Reader) error {
		return visitStoppedWorkingTreeTar(ctx, archive, request, maximumInventoryArchiveBytes, byteWriter, func(entry StoppedWorkingTreeEntry, hardlinkTarget string) error {
			return sorter.Add(ctx, entry, hardlinkTarget)
		})
	})
	if err != nil {
		return WorkingTreeInventoryReceipt{}, err
	}
	pack := byteWriter.Seal()
	rows, err := sorter.Seal(ctx)
	if err != nil {
		return WorkingTreeInventoryReceipt{}, err
	}
	receipt := WorkingTreeInventoryReceipt{Request: request, ProviderResourceID: inventoryResourceID(request),
		TerminalGeneration: request.Generation.StopAuthority.TerminalGeneration, Pages: []WorkingTreeInventoryPageDescriptor{}, BytePack: pack,
		InventoryDigest: "sha256:" + strings.Repeat("0", 64), ObservedAt: s.now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")}
	base, _ := generationstop.CanonicalJSON(receipt)
	indexBytes := len(base)
	page := make([]StoppedWorkingTreeEntry, 0)
	pageBytes := 2
	flush := func() error {
		if len(page) == 0 {
			return nil
		}
		data, err := generationstop.CanonicalJSON(page)
		if err != nil {
			return err
		}
		if len(data) > request.MaximumPageBytes {
			return fmt.Errorf("%w: inventory page exceeds its byte bound", ErrConflict)
		}
		descriptor := WorkingTreeInventoryPageDescriptor{PageIndex: len(receipt.Pages), EntryCount: len(page), ByteLength: len(data), SHA256: sha256Digest(data), FirstPath: page[0].ZoneRelativePath, LastPath: page[len(page)-1].ZoneRelativePath}
		encoded, _ := generationstop.CanonicalJSON(descriptor)
		indexBytes += len(encoded) + 1
		if indexBytes > MaximumWorkingTreeInventoryIndexBytes {
			return fmt.Errorf("%w: inventory index exceeds its byte bound", ErrConflict)
		}
		if err := s.requireInventoryNotDeleting(ctx, request); err != nil {
			return err
		}
		if err := s.createInventoryObject(ctx, inventoryPageKey(root, descriptor.PageIndex), data); err != nil {
			return err
		}
		receipt.Pages = append(receipt.Pages, descriptor)
		receipt.EntryCount += int64(len(page))
		page = nil
		pageBytes = 2
		return nil
	}
	directories := make(map[string]struct{})
	previous := ""
	err = rows.Walk(ctx, func(record inventoryArchiveEntry) error {
		entry, err := rows.ResolveFile(ctx, record)
		if err != nil {
			return err
		}
		if entry.Kind == "regular_file" {
			if entry.ByteOffset == nil || entry.SHA256 == nil || entry.Size < 0 || entry.Size > request.MaximumFileBytes || *entry.ByteOffset < 0 || entry.Size > pack.ByteLength-*entry.ByteOffset || entry.Size > request.MaximumAggregateBytes-receipt.AggregateBytes {
				return fmt.Errorf("%w: inventory file lies outside captured byte custody", ErrConflict)
			}
			receipt.AggregateBytes += entry.Size
		}
		current := entry.ZoneRelativePath
		if previous != "" && compareUTF8Lexicographic(previous, current) >= 0 {
			return fmt.Errorf("%w: inventory repeats a path", ErrConflict)
		}
		for directory := range directories {
			prefix := directory + "/"
			if compareUTF8Lexicographic(current, prefix) > 0 && !strings.HasPrefix(current, prefix) {
				delete(directories, directory)
			}
		}
		for parent := path.Dir(current); parent != "."; parent = path.Dir(parent) {
			if _, exists := directories[parent]; !exists {
				return fmt.Errorf("%w: inventory has no exact directory ancestry", ErrConflict)
			}
		}
		if entry.Kind == "directory" {
			directories[current] = struct{}{}
		}
		previous = current
		encoded, err := generationstop.CanonicalJSON(entry)
		if err != nil {
			return err
		}
		if len(encoded)+2 > request.MaximumPageBytes {
			return fmt.Errorf("%w: one inventory entry exceeds its page bound", ErrConflict)
		}
		additional := len(encoded)
		if len(page) > 0 {
			additional++
		}
		if len(page) > 0 && (len(page) >= request.MaximumPageEntries || pageBytes+additional > request.MaximumPageBytes) {
			if err := flush(); err != nil {
				return err
			}
			additional = len(encoded)
		}
		page = append(page, entry)
		pageBytes += additional
		return nil
	})
	if err != nil {
		return WorkingTreeInventoryReceipt{}, err
	}
	if err := flush(); err != nil {
		return WorkingTreeInventoryReceipt{}, err
	}
	if _, err := s.objects.StatPrivateObject(ctx, inventoryPageKey(root, len(receipt.Pages))); err == nil {
		return WorkingTreeInventoryReceipt{}, fmt.Errorf("%w: inventory has pages from another traversal", ErrConflict)
	} else if !errors.Is(err, storage.ErrPrivateObjectNotFound) {
		return WorkingTreeInventoryReceipt{}, objectReadError("probe inventory page tail", err)
	}
	if err := s.publishInventoryBytes(ctx, request, pack, byteWriter.file); err != nil {
		return WorkingTreeInventoryReceipt{}, err
	}
	if _, err := s.objects.StatPrivateObject(ctx, inventoryBytePartKey(root, len(pack.Parts))); err == nil {
		return WorkingTreeInventoryReceipt{}, fmt.Errorf("%w: inventory has byte parts from another traversal", ErrConflict)
	} else if !errors.Is(err, storage.ErrPrivateObjectNotFound) {
		return WorkingTreeInventoryReceipt{}, objectReadError("probe inventory byte tail", err)
	}
	receipt.InventoryDigest, err = inventoryDigest(receipt)
	if err != nil {
		return WorkingTreeInventoryReceipt{}, err
	}
	data, err := generationstop.CanonicalJSON(receipt)
	if err != nil || len(data) > MaximumWorkingTreeInventoryIndexBytes {
		return WorkingTreeInventoryReceipt{}, fmt.Errorf("%w: inventory index exceeds its byte bound", ErrConflict)
	}
	if err := s.requireInventoryNotDeleting(ctx, request); err != nil {
		return WorkingTreeInventoryReceipt{}, err
	}
	if err := s.objects.CreatePrivateObject(ctx, root+"/index.json", data, "application/json", map[string]string{"contract": workingTreeInventoryContract}); err != nil {
		winner, exists, readErr := s.readInventoryIndex(ctx, request)
		if readErr != nil {
			return WorkingTreeInventoryReceipt{}, readErr
		}
		if !exists {
			return WorkingTreeInventoryReceipt{}, fmt.Errorf("%w: inventory index publication is unresolved: %w", ErrOutcomeUnknown, err)
		}
		if winner.InventoryDigest != receipt.InventoryDigest {
			return WorkingTreeInventoryReceipt{}, fmt.Errorf("%w: inventory publication changed", ErrConflict)
		}
		receipt = winner
	}
	if err := s.requireInventoryNotDeleting(ctx, request); err != nil {
		return WorkingTreeInventoryReceipt{}, err
	}
	return receipt, nil
}

func (s *Service) readInventoryIndex(ctx context.Context, request WorkingTreeInventoryRequest) (WorkingTreeInventoryReceipt, bool, error) {
	data, exists, err := s.inventoryObject(ctx, inventoryRoot(request)+"/index.json", MaximumWorkingTreeInventoryIndexBytes)
	if err != nil || !exists {
		return WorkingTreeInventoryReceipt{}, exists, err
	}
	var receipt WorkingTreeInventoryReceipt
	if err := decodeInventoryJSON(data, &receipt); err != nil {
		return receipt, false, fmt.Errorf("%w: stored inventory index is not canonical", ErrConflict)
	}
	actual, _ := generationstop.CanonicalJSON(receipt.Request)
	expected, _ := generationstop.CanonicalJSON(request)
	if !bytes.Equal(actual, expected) || receipt.ProviderResourceID != inventoryResourceID(request) || receipt.TerminalGeneration != request.Generation.StopAuthority.TerminalGeneration || receipt.Pages == nil || receipt.EntryCount < 0 || receipt.AggregateBytes < 0 || receipt.AggregateBytes > request.MaximumAggregateBytes {
		return receipt, false, fmt.Errorf("%w: stored inventory index authority changed", ErrConflict)
	}
	if err := validateInventoryBytePack(receipt.BytePack, request.MaximumAggregateBytes); err != nil {
		return receipt, false, err
	}
	if receipt.BytePack.ByteLength > receipt.AggregateBytes {
		return receipt, false, fmt.Errorf("%w: inventory byte pack exceeds logical file custody", ErrConflict)
	}
	var count int64
	previous := ""
	for index, page := range receipt.Pages {
		if page.PageIndex != index || page.EntryCount < 1 || page.EntryCount > request.MaximumPageEntries || page.ByteLength < 2 || page.ByteLength > request.MaximumPageBytes || !isSHA256Digest(page.SHA256) || !canonicalWorkingTreePath(page.FirstPath) || !canonicalWorkingTreePath(page.LastPath) || compareUTF8Lexicographic(page.FirstPath, page.LastPath) > 0 || (previous != "" && compareUTF8Lexicographic(previous, page.FirstPath) >= 0) {
			return receipt, false, fmt.Errorf("%w: stored inventory page index is invalid", ErrConflict)
		}
		count += int64(page.EntryCount)
		previous = page.LastPath
	}
	digest, err := inventoryDigest(receipt)
	observed, parseErr := time.Parse("2006-01-02T15:04:05.000Z", receipt.ObservedAt)
	if err != nil || count != receipt.EntryCount || digest != receipt.InventoryDigest || parseErr != nil || observed.Format("2006-01-02T15:04:05.000Z") != receipt.ObservedAt {
		return receipt, false, fmt.Errorf("%w: stored inventory index digest, count, or time changed", ErrConflict)
	}
	return receipt, true, nil
}

func (s *Service) ReadWorkingTreeInventoryPage(ctx context.Context, sandboxID string, request WorkingTreeInventoryPageRequest) (WorkingTreeInventoryPage, error) {
	if err := s.validateInventoryRequest(sandboxID, request.Request); err != nil {
		return WorkingTreeInventoryPage{}, err
	}
	if request.ProviderResourceID != inventoryResourceID(request.Request) || request.PageIndex < 0 {
		return WorkingTreeInventoryPage{}, invalidf("inventory page identity is invalid")
	}
	root := inventoryRoot(request.Request)
	release := s.locks.acquire(root)
	defer release()
	if err := s.requireInventoryNotDeleting(ctx, request.Request); err != nil {
		return WorkingTreeInventoryPage{}, err
	}
	index, exists, err := s.readInventoryIndex(ctx, request.Request)
	if err != nil {
		return WorkingTreeInventoryPage{}, err
	}
	if !exists {
		return WorkingTreeInventoryPage{}, fmt.Errorf("%w: working-tree inventory is not complete", ErrUnavailable)
	}
	if request.PageIndex >= len(index.Pages) {
		return WorkingTreeInventoryPage{}, invalidf("inventory page index is outside its receipt")
	}
	descriptor := index.Pages[request.PageIndex]
	data, exists, err := s.inventoryObject(ctx, inventoryPageKey(root, request.PageIndex), int64(request.Request.MaximumPageBytes))
	if err != nil {
		return WorkingTreeInventoryPage{}, err
	}
	if !exists || len(data) != descriptor.ByteLength || sha256Digest(data) != descriptor.SHA256 {
		return WorkingTreeInventoryPage{}, fmt.Errorf("%w: inventory page bytes differ from their immutable index", ErrConflict)
	}
	var entries []StoppedWorkingTreeEntry
	if err := decodeInventoryJSON(data, &entries); err != nil || len(entries) != descriptor.EntryCount || len(entries) == 0 || entries[0].ZoneRelativePath != descriptor.FirstPath || entries[len(entries)-1].ZoneRelativePath != descriptor.LastPath {
		return WorkingTreeInventoryPage{}, fmt.Errorf("%w: inventory page contents differ from their index", ErrConflict)
	}
	return WorkingTreeInventoryPage{ProviderResourceID: index.ProviderResourceID, PageIndex: request.PageIndex, Entries: entries, PageDigest: descriptor.SHA256}, nil
}

// Delete persists the exact page count before removing anything, so partial
// cleanup can resume even after page zero or the complete index is gone.
func (s *Service) DeleteWorkingTreeInventory(ctx context.Context, sandboxID string, request WorkingTreeInventoryRequest) (WorkingTreeInventoryDeletionReceipt, error) {
	if err := s.validateInventoryRequest(sandboxID, request); err != nil {
		return WorkingTreeInventoryDeletionReceipt{}, err
	}
	root := inventoryRoot(request)
	release := s.locks.acquire(root)
	defer release()
	deletion, deleting, err := s.inventoryDeleting(ctx, request)
	if err != nil {
		return WorkingTreeInventoryDeletionReceipt{}, err
	}
	if !deleting {
		index, complete, err := s.readInventoryIndex(ctx, request)
		if err != nil {
			return WorkingTreeInventoryDeletionReceipt{}, err
		}
		intent, exists, err := s.inventoryObject(ctx, root+"/intent.json", maximumIntentBytes)
		if err != nil {
			return WorkingTreeInventoryDeletionReceipt{}, err
		}
		expected, _ := generationstop.CanonicalJSON(request)
		if exists && !bytes.Equal(intent, expected) {
			return WorkingTreeInventoryDeletionReceipt{}, fmt.Errorf("%w: inventory intent belongs to another request", ErrConflict)
		}
		deletion = inventoryDeletion{Request: request, ProviderResourceID: inventoryResourceID(request)}
		if complete {
			deletion.PageCount = len(index.Pages)
			deletion.BytePartCount = len(index.BytePack.Parts)
		} else if exists {
			for deletion.PageCount < MaximumWorkingTreeInventoryIndexBytes {
				_, err := s.objects.StatPrivateObject(ctx, inventoryPageKey(root, deletion.PageCount))
				if errors.Is(err, storage.ErrPrivateObjectNotFound) {
					break
				}
				if err != nil {
					return WorkingTreeInventoryDeletionReceipt{}, objectReadError("observe partial inventory pages", err)
				}
				deletion.PageCount++
			}
			for deletion.BytePartCount < MaximumWorkingTreeInventoryIndexBytes {
				_, err := s.objects.StatPrivateObject(ctx, inventoryBytePartKey(root, deletion.BytePartCount))
				if errors.Is(err, storage.ErrPrivateObjectNotFound) {
					break
				}
				if err != nil {
					return WorkingTreeInventoryDeletionReceipt{}, objectReadError("observe partial inventory bytes", err)
				}
				deletion.BytePartCount++
			}
		} else {
			for _, prefix := range []string{"pages/", "bytes/"} {
				keys, err := s.objects.ListPrivateObjects(ctx, root+"/"+prefix, 1)
				if err != nil || len(keys) != 0 {
					return WorkingTreeInventoryDeletionReceipt{}, fmt.Errorf("%w: inventory custody has no request intent", ErrConflict)
				}
			}
		}
		data, _ := generationstop.CanonicalJSON(deletion)
		if err := s.createInventoryObject(ctx, root+"/deletion.json", data); err != nil {
			return WorkingTreeInventoryDeletionReceipt{}, err
		}
	}
	for part := 0; part < deletion.BytePartCount; part++ {
		if err := s.objects.DeletePrivateObject(ctx, inventoryBytePartKey(root, part)); err != nil {
			return WorkingTreeInventoryDeletionReceipt{}, fmt.Errorf("%w: delete inventory byte part: %w", ErrOutcomeUnknown, err)
		}
	}
	for page := 0; page < deletion.PageCount; page++ {
		if err := s.objects.DeletePrivateObject(ctx, inventoryPageKey(root, page)); err != nil {
			return WorkingTreeInventoryDeletionReceipt{}, fmt.Errorf("%w: delete inventory page %s: %w", ErrOutcomeUnknown, strconv.Itoa(page), err)
		}
	}
	for _, name := range []string{"index.json", "intent.json"} {
		if err := s.objects.DeletePrivateObject(ctx, root+"/"+name); err != nil {
			return WorkingTreeInventoryDeletionReceipt{}, fmt.Errorf("%w: delete inventory control object: %w", ErrOutcomeUnknown, err)
		}
		if _, err := s.objects.StatPrivateObject(ctx, root+"/"+name); !errors.Is(err, storage.ErrPrivateObjectNotFound) {
			return WorkingTreeInventoryDeletionReceipt{}, fmt.Errorf("%w: inventory control absence is not established", ErrOutcomeUnknown)
		}
	}
	for _, prefix := range []string{"pages/", "bytes/"} {
		keys, err := s.objects.ListPrivateObjects(ctx, root+"/"+prefix, 1)
		if err != nil || len(keys) != 0 {
			return WorkingTreeInventoryDeletionReceipt{}, fmt.Errorf("%w: inventory custody absence is not established", ErrOutcomeUnknown)
		}
	}
	return WorkingTreeInventoryDeletionReceipt{Request: request, ProviderResourceID: deletion.ProviderResourceID, Status: "absent"}, nil
}

func decodeInventoryJSON(data []byte, target any) error {
	if err := DecodeExactJSON(data, target); err != nil {
		return err
	}
	canonical, err := generationstop.CanonicalJSON(target)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, canonical) {
		return fmt.Errorf("inventory JSON is not canonical")
	}
	return nil
}
