// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
	"golang.org/x/sys/unix"
)

const (
	providerCollectionJournalContract = "C18ProviderCollectionJournal@1"
	maximumProviderJournalBytes       = 64 * 1024 * 1024
)

var ErrProviderCollectionAbandoned = errors.New("C18 provider collection attempt is abandoned")

type ProviderCollectionJournalEntry struct {
	Facet                string                   `json:"facet"`
	Mode                 string                   `json:"mode"`
	Receipt              specialistrender.Receipt `json:"receipt"`
	RequestStreamSHA256  string                   `json:"requestStreamSha256"`
	ResponseStreamSHA256 string                   `json:"responseStreamSha256"`
}

type ProviderCollectionAbandonmentSettlement struct {
	Facet   string                    `json:"facet"`
	Mode    string                    `json:"mode"`
	Status  string                    `json:"status"`
	Receipt *specialistrender.Receipt `json:"receipt"`
}

type ProviderCollectionJournal struct {
	Contract      string                                    `json:"contract"`
	RunSHA256     string                                    `json:"runSha256"`
	Complete      bool                                      `json:"complete"`
	Abandoned     bool                                      `json:"abandoned"`
	ObservedFrom  string                                    `json:"observedFrom"`
	ObservedUntil string                                    `json:"observedUntil"`
	Entries       []ProviderCollectionJournalEntry          `json:"entries"`
	Settlements   []ProviderCollectionAbandonmentSettlement `json:"settlements"`
	Digest        string                                    `json:"digest"`
}

type providerCollectionJournalBody struct {
	Contract      string                                    `json:"contract"`
	RunSHA256     string                                    `json:"runSha256"`
	Complete      bool                                      `json:"complete"`
	Abandoned     bool                                      `json:"abandoned"`
	ObservedFrom  string                                    `json:"observedFrom"`
	ObservedUntil string                                    `json:"observedUntil"`
	Entries       []ProviderCollectionJournalEntry          `json:"entries"`
	Settlements   []ProviderCollectionAbandonmentSettlement `json:"settlements"`
}

type ProviderCollectionJournalStore interface {
	Snapshot() ProviderCollectionJournal
	Append(entry ProviderCollectionJournalEntry) error
	MarkAbandoned(settlements []ProviderCollectionAbandonmentSettlement) error
}

type fileProviderCollectionJournalStore struct {
	mu   sync.Mutex
	path string
	run  ProviderLiveRun
	data ProviderCollectionJournal
}

func OpenProviderCollectionJournal(path string, run ProviderLiveRun) (ProviderCollectionJournalStore, error) {
	if !absoluteCleanPath(path) {
		return nil, fmt.Errorf("provider collection journal path is invalid")
	}
	if err := validatePrivateOwnedDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("provider collection journal directory is invalid: %w", err)
	}
	if err := ValidateProviderLiveRun(run); err != nil {
		return nil, err
	}
	if err := reconcileOwnedStaging(providerJournalStagingPath(path)); err != nil {
		return nil, err
	}
	runSHA256, err := providerRunSHA256(run)
	if err != nil {
		return nil, err
	}
	store := &fileProviderCollectionJournalStore{path: path, run: run}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		journal, sealErr := sealProviderCollectionJournal(ProviderCollectionJournal{
			RunSHA256:   runSHA256,
			Entries:     []ProviderCollectionJournalEntry{},
			Settlements: []ProviderCollectionAbandonmentSettlement{},
		})
		if sealErr != nil {
			return nil, sealErr
		}
		if err := writeProviderJournal(path, journal, ""); err != nil {
			return nil, err
		}
		store.data = journal
		return store, nil
	} else if err != nil {
		return nil, fmt.Errorf("inspect provider collection journal: %w", err)
	}
	encoded, err := readCanonicalConfig(path, maximumProviderJournalBytes)
	if err != nil {
		return nil, err
	}
	journal, err := ParseProviderCollectionJournal(encoded, run)
	if err != nil {
		return nil, err
	}
	if journal.RunSHA256 != runSHA256 {
		return nil, fmt.Errorf("provider collection journal changed run authority")
	}
	store.data = journal
	return store, nil
}

func NewMemoryProviderCollectionJournal(run ProviderLiveRun) (ProviderCollectionJournalStore, error) {
	runSHA256, err := providerRunSHA256(run)
	if err != nil {
		return nil, err
	}
	journal, err := sealProviderCollectionJournal(ProviderCollectionJournal{
		RunSHA256:   runSHA256,
		Entries:     []ProviderCollectionJournalEntry{},
		Settlements: []ProviderCollectionAbandonmentSettlement{},
	})
	if err != nil {
		return nil, err
	}
	return &memoryProviderCollectionJournalStore{run: run, data: journal}, nil
}

func (store *fileProviderCollectionJournalStore) Snapshot() ProviderCollectionJournal {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneProviderCollectionJournal(store.data)
}

func (store *fileProviderCollectionJournalStore) Append(entry ProviderCollectionJournalEntry) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	next, changed, err := appendProviderJournalEntry(store.data, store.run, entry)
	if err != nil || !changed {
		return err
	}
	if err := writeProviderJournal(store.path, next, store.data.Digest); err != nil {
		return err
	}
	store.data = next
	return nil
}

func (store *fileProviderCollectionJournalStore) MarkAbandoned(
	settlements []ProviderCollectionAbandonmentSettlement,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	next, changed, err := abandonProviderCollectionJournal(store.data, store.run, settlements)
	if err != nil || !changed {
		return err
	}
	if err := writeProviderJournal(store.path, next, store.data.Digest); err != nil {
		return err
	}
	store.data = next
	return nil
}

type memoryProviderCollectionJournalStore struct {
	mu   sync.Mutex
	run  ProviderLiveRun
	data ProviderCollectionJournal
}

func (store *memoryProviderCollectionJournalStore) Snapshot() ProviderCollectionJournal {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneProviderCollectionJournal(store.data)
}

func (store *memoryProviderCollectionJournalStore) Append(entry ProviderCollectionJournalEntry) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	next, _, err := appendProviderJournalEntry(store.data, store.run, entry)
	if err == nil {
		store.data = next
	}
	return err
}

func (store *memoryProviderCollectionJournalStore) MarkAbandoned(
	settlements []ProviderCollectionAbandonmentSettlement,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	next, _, err := abandonProviderCollectionJournal(store.data, store.run, settlements)
	if err == nil {
		store.data = next
	}
	return err
}

func ParseProviderCollectionJournal(data []byte, run ProviderLiveRun) (ProviderCollectionJournal, error) {
	var value ProviderCollectionJournal
	if err := generationstop.DecodeCanonicalJSON(data, &value); err != nil {
		return ProviderCollectionJournal{}, fmt.Errorf("decode canonical provider collection journal: %w", err)
	}
	if err := validateProviderCollectionJournal(value, run); err != nil {
		return ProviderCollectionJournal{}, err
	}
	body, err := generationstop.CanonicalJSON(providerJournalBody(value))
	if err != nil || value.Digest != digestBytes(body) {
		return ProviderCollectionJournal{}, fmt.Errorf("provider collection journal digest is invalid")
	}
	return cloneProviderCollectionJournal(value), nil
}

func appendProviderJournalEntry(
	current ProviderCollectionJournal,
	run ProviderLiveRun,
	entry ProviderCollectionJournalEntry,
) (ProviderCollectionJournal, bool, error) {
	if current.Complete || current.Abandoned {
		return ProviderCollectionJournal{}, false, fmt.Errorf("provider collection journal is already complete")
	}
	entries := append([]ProviderCollectionJournalEntry(nil), current.Entries...)
	key := providerJournalEntryKey(entry)
	for _, existing := range entries {
		if providerJournalEntryKey(existing) != key {
			continue
		}
		left, _ := generationstop.CanonicalJSON(existing)
		right, _ := generationstop.CanonicalJSON(entry)
		if !bytes.Equal(left, right) {
			return ProviderCollectionJournal{}, false, fmt.Errorf("provider collection journal entry was substituted")
		}
		return current, false, nil
	}
	entries = append(entries, entry)
	sort.Slice(entries, func(left, right int) bool {
		return providerJournalEntryKey(entries[left]) < providerJournalEntryKey(entries[right])
	})
	next := ProviderCollectionJournal{
		RunSHA256:   current.RunSHA256,
		Entries:     entries,
		Settlements: []ProviderCollectionAbandonmentSettlement{},
	}
	if len(entries) == len(run.Executions) {
		next.Complete = true
		for index, item := range entries {
			if index == 0 || item.Receipt.StartedAt < next.ObservedFrom {
				next.ObservedFrom = item.Receipt.StartedAt
			}
			if index == 0 || item.Receipt.CompletedAt > next.ObservedUntil {
				next.ObservedUntil = item.Receipt.CompletedAt
			}
		}
	}
	sealed, err := sealProviderCollectionJournal(next)
	if err != nil {
		return ProviderCollectionJournal{}, false, err
	}
	if err := validateProviderCollectionJournal(sealed, run); err != nil {
		return ProviderCollectionJournal{}, false, err
	}
	return sealed, true, nil
}

func abandonProviderCollectionJournal(
	current ProviderCollectionJournal,
	run ProviderLiveRun,
	settlements []ProviderCollectionAbandonmentSettlement,
) (ProviderCollectionJournal, bool, error) {
	settlements = append([]ProviderCollectionAbandonmentSettlement(nil), settlements...)
	sort.Slice(settlements, func(left, right int) bool {
		return settlements[left].Facet+"\x00"+settlements[left].Mode <
			settlements[right].Facet+"\x00"+settlements[right].Mode
	})
	if current.Complete {
		return ProviderCollectionJournal{}, false, fmt.Errorf("complete provider journal cannot be abandoned")
	}
	if current.Abandoned {
		left, _ := generationstop.CanonicalJSON(current.Settlements)
		right, _ := generationstop.CanonicalJSON(settlements)
		if !bytes.Equal(left, right) {
			return ProviderCollectionJournal{}, false, fmt.Errorf("provider abandonment settlements were substituted")
		}
		return current, false, nil
	}
	next := ProviderCollectionJournal{
		RunSHA256:   current.RunSHA256,
		Abandoned:   true,
		Entries:     append([]ProviderCollectionJournalEntry(nil), current.Entries...),
		Settlements: settlements,
	}
	sealed, err := sealProviderCollectionJournal(next)
	if err != nil {
		return ProviderCollectionJournal{}, false, err
	}
	if err := validateProviderCollectionJournal(sealed, run); err != nil {
		return ProviderCollectionJournal{}, false, err
	}
	return sealed, true, nil
}

func sealProviderCollectionJournal(value ProviderCollectionJournal) (ProviderCollectionJournal, error) {
	value.Contract = providerCollectionJournalContract
	value.Digest = ""
	if value.Entries == nil {
		value.Entries = []ProviderCollectionJournalEntry{}
	}
	if value.Settlements == nil {
		value.Settlements = []ProviderCollectionAbandonmentSettlement{}
	}
	body, err := generationstop.CanonicalJSON(providerJournalBody(value))
	if err != nil {
		return ProviderCollectionJournal{}, err
	}
	value.Digest = digestBytes(body)
	encoded, err := generationstop.CanonicalJSON(value)
	if err != nil {
		return ProviderCollectionJournal{}, err
	}
	var sealed ProviderCollectionJournal
	if err := generationstop.DecodeCanonicalJSON(encoded, &sealed); err != nil {
		return ProviderCollectionJournal{}, err
	}
	return sealed, nil
}

func validateProviderCollectionJournal(value ProviderCollectionJournal, run ProviderLiveRun) error {
	if value.Contract != providerCollectionJournalContract || !exactDigest(value.RunSHA256) ||
		value.Entries == nil || value.Settlements == nil || (value.Complete && value.Abandoned) {
		return fmt.Errorf("provider collection journal identity is invalid")
	}
	runSHA256, err := providerRunSHA256(run)
	if err != nil || value.RunSHA256 != runSHA256 {
		return fmt.Errorf("provider collection journal run authority is invalid")
	}
	executions := make(map[string]ProviderLiveExecution, len(run.Executions))
	for _, execution := range run.Executions {
		executions[execution.Facet+"\x00"+execution.Mode] = execution
	}
	previous := ""
	for _, entry := range value.Entries {
		key := providerJournalEntryKey(entry)
		execution, exists := executions[key]
		if !exists || (previous != "" && previous >= key) {
			return fmt.Errorf("provider collection journal entries are not exact and ordered")
		}
		previous = key
		if err := specialistrender.ValidateReceipt(entry.Receipt); err != nil ||
			entry.Receipt.Request.OperationID != execution.OperationID ||
			entry.Receipt.Request.ArtifactRenderJobRef != execution.ArtifactRenderJobRef {
			return fmt.Errorf("provider collection journal receipt differs from execution")
		}
		switch entry.Mode {
		case "cancel":
			if entry.Receipt.Outcome != "cancelled" || entry.RequestStreamSHA256 != "" || entry.ResponseStreamSHA256 != "" {
				return fmt.Errorf("provider collection journal cancellation is invalid")
			}
		case "success":
			if entry.Receipt.Outcome != "succeeded" || !exactDigest(entry.RequestStreamSHA256) || !exactDigest(entry.ResponseStreamSHA256) {
				return fmt.Errorf("provider collection journal success is invalid")
			}
		default:
			return fmt.Errorf("provider collection journal mode is invalid")
		}
	}
	if value.Abandoned {
		if len(value.Settlements) != len(run.Executions) || value.ObservedFrom != "" || value.ObservedUntil != "" {
			return fmt.Errorf("abandoned provider collection journal is incomplete")
		}
		previous = ""
		for _, settlement := range value.Settlements {
			key := settlement.Facet + "\x00" + settlement.Mode
			execution, exists := executions[key]
			if !exists || (previous != "" && previous >= key) {
				return fmt.Errorf("provider abandonment settlements are not exact and ordered")
			}
			previous = key
			switch settlement.Status {
			case "absent":
				if settlement.Receipt != nil {
					return fmt.Errorf("absent provider abandonment settlement contains a receipt")
				}
			case "complete":
				if settlement.Receipt == nil || !settlement.Receipt.Quiescence.ContainerAbsent ||
					specialistrender.ValidateReceipt(*settlement.Receipt) != nil ||
					settlement.Receipt.Request.OperationID != execution.OperationID ||
					settlement.Receipt.Request.ArtifactRenderJobRef != execution.ArtifactRenderJobRef {
					return fmt.Errorf("complete provider abandonment settlement is invalid")
				}
				if entry, journaled := providerJournalEntry(value.Entries, execution); journaled &&
					entry.Receipt.ReceiptDigest != settlement.Receipt.ReceiptDigest {
					return fmt.Errorf("provider abandonment settlement differs from journal entry")
				}
			default:
				return fmt.Errorf("provider abandonment settlement status is invalid")
			}
		}
		return nil
	}
	if value.Complete {
		if len(value.Entries) != len(run.Executions) || len(value.Settlements) != 0 ||
			!validInterval(value.ObservedFrom, value.ObservedUntil) {
			return fmt.Errorf("complete provider collection journal is incomplete")
		}
	} else if value.ObservedFrom != "" || value.ObservedUntil != "" ||
		len(value.Entries) >= len(run.Executions) || len(value.Settlements) != 0 {
		return fmt.Errorf("partial provider collection journal claims completion")
	}
	return nil
}

func ProviderCollectionFromJournal(
	journal ProviderCollectionJournal,
	run ProviderLiveRun,
	policyBytes []byte,
) (ProviderLiveCollection, error) {
	if err := validateProviderCollectionJournal(journal, run); err != nil || !journal.Complete {
		return ProviderLiveCollection{}, fmt.Errorf("provider collection journal is not complete")
	}
	receipts := make([]ProviderReceiptRow, 0, len(journal.Entries))
	streams := make([]AuthenticatedStreamingCase, 0, providerSuccessConcurrency)
	loads := make([]ConcurrentLoadCase, 0, providerSuccessConcurrency)
	for _, entry := range journal.Entries {
		receipts = append(receipts, ProviderReceiptRow{Facet: entry.Facet, Mode: entry.Mode, Receipt: entry.Receipt})
		if entry.Mode != "success" {
			continue
		}
		startedAt, _ := parseObservationTime(entry.Receipt.StartedAt)
		completedAt, _ := parseObservationTime(entry.Receipt.CompletedAt)
		streams = append(streams, AuthenticatedStreamingCase{
			Facet: entry.Facet, OperationID: entry.Receipt.Request.OperationID, HTTPStatus: 200,
			Authenticated: true, RequestStreamSHA256: entry.RequestStreamSHA256,
			ResponseStreamSHA256: entry.ResponseStreamSHA256, ReceiptDigest: entry.Receipt.ReceiptDigest,
		})
		loads = append(loads, ConcurrentLoadCase{
			Facet: entry.Facet, StartedAt: entry.Receipt.StartedAt, CompletedAt: entry.Receipt.CompletedAt,
			DurationMilliseconds: completedAt.Sub(startedAt).Milliseconds(), ReceiptDigest: entry.Receipt.ReceiptDigest,
		})
	}
	return SealProviderLiveCollection(ProviderLiveCollection{
		SourceRevision: run.SourceRevision, SourceTree: run.SourceTree, SourceSetDigest: run.SourceSetDigest,
		RunnerPolicy:     RunnerPolicyPin{CanonicalJSON: string(policyBytes), ContentSHA256: digestBytes(policyBytes)},
		ProviderReceipts: receipts,
		AuthenticatedStreaming: AuthenticatedStreamingObservation{
			Outcome: "passed", ObservedFrom: journal.ObservedFrom, ObservedUntil: journal.ObservedUntil, Cases: streams,
		},
		ConcurrentLoad: ConcurrentLoadObservation{
			PredeclaredConcurrency: providerSuccessConcurrency, MaximumDurationMilliseconds: providerExecuteSeconds * 1000,
			AllSucceeded: true, Outcome: "passed", Cases: loads,
		},
	})
}

func providerRunSHA256(run ProviderLiveRun) (string, error) {
	encoded, err := CanonicalProviderLiveRun(run)
	if err != nil {
		return "", err
	}
	return digestBytes(encoded), nil
}

func providerJournalEntryKey(entry ProviderCollectionJournalEntry) string {
	return entry.Facet + "\x00" + entry.Mode
}

func providerJournalBody(value ProviderCollectionJournal) providerCollectionJournalBody {
	return providerCollectionJournalBody{
		Contract: value.Contract, RunSHA256: value.RunSHA256, Complete: value.Complete,
		Abandoned: value.Abandoned, ObservedFrom: value.ObservedFrom, ObservedUntil: value.ObservedUntil,
		Entries: value.Entries, Settlements: value.Settlements,
	}
}

func cloneProviderCollectionJournal(value ProviderCollectionJournal) ProviderCollectionJournal {
	encoded, _ := generationstop.CanonicalJSON(value)
	var clone ProviderCollectionJournal
	_ = generationstop.DecodeCanonicalJSON(encoded, &clone)
	return clone
}

func providerJournalStagingPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".c18-journal-staging")
}

func writeProviderJournal(path string, journal ProviderCollectionJournal, expectedCurrentDigest string) error {
	encoded, err := generationstop.CanonicalJSON(journal)
	if err != nil {
		return err
	}
	staging := providerJournalStagingPath(path)
	if err := reconcileOwnedStaging(staging); err != nil {
		return err
	}
	file, err := os.OpenFile(staging, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create provider journal staging: %w", err)
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(staging)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if expectedCurrentDigest == "" {
		if err := unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
			return fmt.Errorf("commit new provider journal: %w", err)
		}
	} else {
		if err := validateOwnedRegularFile(path); err != nil {
			return err
		}
		currentBytes, err := readCanonicalConfig(path, maximumProviderJournalBytes)
		if err != nil {
			return err
		}
		var current ProviderCollectionJournal
		if err := generationstop.DecodeCanonicalJSON(currentBytes, &current); err != nil ||
			current.Digest != expectedCurrentDigest {
			return fmt.Errorf("provider journal replacement lost current file identity")
		}
		if err := os.Rename(staging, path); err != nil {
			return fmt.Errorf("replace provider journal: %w", err)
		}
	}
	committed = true
	return syncDirectory(filepath.Dir(path))
}

func reconcileOwnedStaging(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := validateOwnedRegularFile(path); err != nil {
		return fmt.Errorf("owned staging substitution: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove owned staging: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func validateOwnedRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("file is not one private owned regular file")
	}
	return nil
}

func validatePrivateOwnedDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("directory is not one private owned physical directory")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
