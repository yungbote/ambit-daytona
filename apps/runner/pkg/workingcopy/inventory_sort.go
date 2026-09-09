// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

const inventoryMergeFanIn = 32

// A path and target are each at most 4 KiB. Even JSON's longest scalar escape
// leaves one entry below 64 KiB. Scanner/merge memory never follows tree size.
const maximumInventoryEntryBytes = 64 * 1024

type inventorySortRun struct{ offset, length int64 }
type inventoryArchiveEntry struct {
	Entry          StoppedWorkingTreeEntry `json:"entry"`
	HardlinkTarget string                  `json:"hardlinkTarget,omitempty"`
}

type inventorySortEntry struct {
	record inventoryArchiveEntry
	bytes  []byte
}

// Sorted runs share one immediately unlinked file. The OS releases all scratch
// on cancellation or process exit; there are no durable temporary pathnames.
// Leveled merges retain at most 31 runs per level and use at most 32 readers.
type inventorySorter struct {
	file          *os.File
	entries       []inventorySortEntry
	entryBytes    int
	metadataBytes int64
	end           int64
	levels        [][]inventorySortRun
}

func newInventorySorter() (*inventorySorter, error) {
	file, err := newPrivateScratchFile("ambit-working-tree-inventory-*")
	if err != nil {
		return nil, err
	}
	return &inventorySorter{file: file}, nil
}

func (s *inventorySorter) Close() error { return s.file.Close() }

func (s *inventorySorter) Add(ctx context.Context, entry StoppedWorkingTreeEntry, hardlinkTarget string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	record := inventoryArchiveEntry{Entry: entry, HardlinkTarget: hardlinkTarget}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(encoded) > maximumInventoryEntryBytes {
		return fmt.Errorf("%w: inventory entry exceeds its metadata bound", ErrConflict)
	}
	s.metadataBytes += int64(len(encoded) + 1)
	if s.metadataBytes > maximumInventoryMetadataBytes {
		return fmt.Errorf("%w: inventory metadata exceeds its scratch budget", ErrConflict)
	}
	if len(s.entries) > 0 && (s.entryBytes+len(encoded)+1 > MaximumWorkingTreeInventoryPageBytes || len(s.entries) >= MaximumWorkingTreeInventoryPageEntries) {
		if err := s.flush(ctx); err != nil {
			return err
		}
	}
	s.entries = append(s.entries, inventorySortEntry{record: record, bytes: encoded})
	s.entryBytes += len(encoded) + 1
	return nil
}

func (s *inventorySorter) appendRow(ctx context.Context, row []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if int64(len(row)+1) > maximumInventoryScratchBytes-s.end {
		return fmt.Errorf("%w: inventory sort exceeded its scratch budget", ErrConflict)
	}
	n, err := s.file.Write(row)
	s.end += int64(n)
	if err != nil {
		return err
	}
	n, err = s.file.Write([]byte{'\n'})
	s.end += int64(n)
	return err
}

func (s *inventorySorter) flush(ctx context.Context) error {
	if len(s.entries) == 0 {
		return nil
	}
	sort.Slice(s.entries, func(i, j int) bool {
		return compareUTF8Lexicographic(s.entries[i].record.Entry.ZoneRelativePath, s.entries[j].record.Entry.ZoneRelativePath) < 0
	})
	run := inventorySortRun{offset: s.end}
	for _, entry := range s.entries {
		if err := s.appendRow(ctx, entry.bytes); err != nil {
			return err
		}
	}
	run.length = s.end - run.offset
	s.entries = nil
	s.entryBytes = 0
	return s.addRun(ctx, 0, run)
}

func (s *inventorySorter) addRun(ctx context.Context, level int, run inventorySortRun) error {
	for len(s.levels) <= level {
		s.levels = append(s.levels, nil)
	}
	s.levels[level] = append(s.levels[level], run)
	if len(s.levels[level]) < inventoryMergeFanIn {
		return nil
	}
	merged, err := s.mergeToRun(ctx, s.levels[level])
	if err != nil {
		return err
	}
	s.levels[level] = nil
	return s.addRun(ctx, level+1, merged)
}

func (s *inventorySorter) mergeToRun(ctx context.Context, runs []inventorySortRun) (inventorySortRun, error) {
	merged := inventorySortRun{offset: s.end}
	err := s.merge(ctx, runs, func(_ inventoryArchiveEntry, row []byte) error { return s.appendRow(ctx, row) })
	merged.length = s.end - merged.offset
	return merged, err
}

func (s *inventorySorter) Seal(ctx context.Context) (*inventorySortedRows, error) {
	if err := s.flush(ctx); err != nil {
		return nil, err
	}
	var runs []inventorySortRun
	for _, level := range s.levels {
		runs = append(runs, level...)
	}
	for len(runs) > inventoryMergeFanIn {
		var next []inventorySortRun
		for start := 0; start < len(runs); start += inventoryMergeFanIn {
			merged, err := s.mergeToRun(ctx, runs[start:min(start+inventoryMergeFanIn, len(runs))])
			if err != nil {
				return nil, err
			}
			next = append(next, merged)
		}
		runs = next
	}
	if len(runs) == 0 {
		return &inventorySortedRows{sorter: s}, nil
	}
	run := runs[0]
	if len(runs) > 1 {
		merged, err := s.mergeToRun(ctx, runs)
		if err != nil {
			return nil, err
		}
		run = merged
	}
	return &inventorySortedRows{sorter: s, run: run}, nil
}

type inventoryRunCursor struct {
	scanner *bufio.Scanner
	record  inventoryArchiveEntry
}

func (c *inventoryRunCursor) next() (bool, error) {
	if !c.scanner.Scan() {
		return false, c.scanner.Err()
	}
	var record inventoryArchiveEntry
	if err := json.Unmarshal(c.scanner.Bytes(), &record); err != nil {
		return false, err
	}
	c.record = record
	return true, nil
}

type inventoryMergeHeap []*inventoryRunCursor

func (h inventoryMergeHeap) Len() int { return len(h) }
func (h inventoryMergeHeap) Less(i, j int) bool {
	return compareUTF8Lexicographic(h[i].record.Entry.ZoneRelativePath, h[j].record.Entry.ZoneRelativePath) < 0
}
func (h inventoryMergeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *inventoryMergeHeap) Push(v any)   { *h = append(*h, v.(*inventoryRunCursor)) }
func (h *inventoryMergeHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

func (s *inventorySorter) merge(ctx context.Context, runs []inventorySortRun, visit func(inventoryArchiveEntry, []byte) error) error {
	if len(runs) > inventoryMergeFanIn {
		return fmt.Errorf("inventory merge exceeds its reader bound")
	}
	queue := inventoryMergeHeap{}
	for _, run := range runs {
		scanner := bufio.NewScanner(io.NewSectionReader(s.file, run.offset, run.length))
		scanner.Buffer(make([]byte, maximumInventoryEntryBytes+1), maximumInventoryEntryBytes+1)
		cursor := &inventoryRunCursor{scanner: scanner}
		ok, err := cursor.next()
		if err != nil {
			return err
		}
		if ok {
			heap.Push(&queue, cursor)
		}
	}
	for queue.Len() > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		cursor := heap.Pop(&queue).(*inventoryRunCursor)
		if err := visit(cursor.record, cursor.scanner.Bytes()); err != nil {
			return err
		}
		ok, err := cursor.next()
		if err != nil {
			return err
		}
		if ok {
			heap.Push(&queue, cursor)
		}
	}
	return nil
}

// A sealed sorted run supports bounded random lookup for archive hardlinks.
// It uses the same unlinked file; no per-file database or inode map is needed.
type inventorySortedRows struct {
	sorter       *inventorySorter
	run          inventorySortRun
	lookupBuffer []byte
}

func (rows *inventorySortedRows) Walk(ctx context.Context, visit func(inventoryArchiveEntry) error) error {
	if rows.run.length == 0 {
		return nil
	}
	return rows.sorter.merge(ctx, []inventorySortRun{rows.run}, func(record inventoryArchiveEntry, _ []byte) error { return visit(record) })
}

func (rows *inventorySortedRows) Lookup(ctx context.Context, path string) (inventoryArchiveEntry, error) {
	low, high := rows.run.offset, rows.run.offset+rows.run.length
	if rows.lookupBuffer == nil {
		rows.lookupBuffer = make([]byte, maximumInventoryEntryBytes+1)
	}
	buffer := rows.lookupBuffer
	for low < high {
		if err := ctx.Err(); err != nil {
			return inventoryArchiveEntry{}, err
		}
		middle := low + (high-low)/2
		start := max(low, middle-maximumInventoryEntryBytes)
		count := int(middle - start)
		if count > 0 {
			if _, err := rows.sorter.file.ReadAt(buffer[:count], start); err != nil {
				return inventoryArchiveEntry{}, err
			}
			if newline := bytes.LastIndexByte(buffer[:count], '\n'); newline >= 0 {
				start += int64(newline + 1)
			}
		}
		length := 0
		for {
			chunk := int(min(int64(4096), high-start-int64(length), int64(len(buffer)-length)))
			if chunk <= 0 {
				return inventoryArchiveEntry{}, fmt.Errorf("%w: inventory lookup record is unbounded", ErrConflict)
			}
			n, err := rows.sorter.file.ReadAt(buffer[length:length+chunk], start+int64(length))
			if err != nil && err != io.EOF {
				return inventoryArchiveEntry{}, err
			}
			length += n
			if newline := bytes.IndexByte(buffer[:length], '\n'); newline >= 0 {
				length = newline + 1
				break
			}
			if n != chunk {
				return inventoryArchiveEntry{}, fmt.Errorf("%w: inventory lookup record is incomplete", ErrConflict)
			}
		}
		var key struct {
			Entry struct {
				ZoneRelativePath string `json:"zoneRelativePath"`
			} `json:"entry"`
		}
		if err := json.Unmarshal(buffer[:length-1], &key); err != nil {
			return inventoryArchiveEntry{}, err
		}
		comparison := compareUTF8Lexicographic(key.Entry.ZoneRelativePath, path)
		if comparison == 0 {
			var record inventoryArchiveEntry
			if err := json.Unmarshal(buffer[:length-1], &record); err != nil {
				return record, err
			}
			return record, nil
		}
		if comparison < 0 {
			low = start + int64(length)
		} else {
			high = start
		}
	}
	return inventoryArchiveEntry{}, fmt.Errorf("%w: hardlink target is absent from the admitted inventory", ErrConflict)
}

func (rows *inventorySortedRows) ResolveFile(ctx context.Context, record inventoryArchiveEntry) (StoppedWorkingTreeEntry, error) {
	original := record.Entry
	if record.HardlinkTarget == "" {
		return original, nil
	}
	next := func(current inventoryArchiveEntry) (inventoryArchiveEntry, bool, error) {
		if current.Entry.Kind != "regular_file" {
			return current, false, fmt.Errorf("%w: hardlink target is not a regular file", ErrConflict)
		}
		if current.HardlinkTarget == "" {
			if current.Entry.ByteOffset == nil || current.Entry.SHA256 == nil {
				return current, false, fmt.Errorf("%w: hardlink target has no captured bytes", ErrConflict)
			}
			return current, true, nil
		}
		found, err := rows.Lookup(ctx, current.HardlinkTarget)
		return found, false, err
	}
	slow, fast := record, record
	for {
		var done bool
		var err error
		slow, done, err = next(slow)
		if err != nil {
			return original, err
		}
		if done {
			original.Size, original.SHA256, original.ByteOffset = slow.Entry.Size, slow.Entry.SHA256, slow.Entry.ByteOffset
			return original, nil
		}
		for range 2 {
			fast, done, err = next(fast)
			if err != nil {
				return original, err
			}
			if done {
				original.Size, original.SHA256, original.ByteOffset = fast.Entry.Size, fast.Entry.SHA256, fast.Entry.ByteOffset
				return original, nil
			}
		}
		if slow.Entry.ZoneRelativePath == fast.Entry.ZoneRelativePath {
			return original, fmt.Errorf("%w: inventory hardlinks contain a cycle", ErrConflict)
		}
	}
}
