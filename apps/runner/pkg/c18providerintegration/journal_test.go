// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
)

func TestProviderCollectionJournalReplaysAfterSettlementBeforeOutput(t *testing.T) {
	fixture := newProviderCollectorFixture(t)
	defer fixture.close()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journalDirectory := filepath.Join(root, "journal")
	outputDirectory := filepath.Join(root, "output")
	if err := os.Mkdir(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(journalDirectory, "provider-collection-journal.json")
	outputPath := filepath.Join(outputDirectory, "provider-live-collection.json")

	first, err := fixture.collector.CollectAndPublishWithJournal(
		context.Background(), fixture.run, journalPath, outputPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := generationstop.CanonicalJSON(first)
	if err != nil {
		t.Fatal(err)
	}
	before := providerEffectCount(fixture.harness)
	fixture.collector.now = func() time.Time {
		return time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	}
	second, err := fixture.collector.CollectAndPublishWithJournal(
		context.Background(), fixture.run, journalPath, outputPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := generationstop.CanonicalJSON(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("complete provider journal replay changed collection bytes")
	}
	if after := providerEffectCount(fixture.harness); after != before {
		t.Fatalf("complete journal replay duplicated provider effects: before=%d after=%d", before, after)
	}
	store, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	journal := store.Snapshot()
	defer store.Close()
	if !journal.Complete || journal.Abandoned || len(journal.Entries) != 12 {
		t.Fatalf("complete provider journal differs: %#v", journal)
	}
}

func TestProviderCollectionJournalAbandonsPartialBatchWithoutRetryingIDs(t *testing.T) {
	fixture := newProviderCollectorFixture(t)
	defer fixture.close()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(root, "provider-collection-journal.json")
	for _, execution := range fixture.run.Executions {
		if execution.Facet == "presentation" && execution.Mode == "success" {
			fixture.harness.failedSuccessOperation = execution.OperationID
		}
	}
	if _, err := fixture.collector.CollectWithJournal(context.Background(), fixture.run, journalPath); err == nil {
		t.Fatal("partial released batch unexpectedly completed")
	}
	before := providerEffectCount(fixture.harness)
	if _, err := fixture.collector.CollectWithJournal(context.Background(), fixture.run, journalPath); !errors.Is(err, ErrProviderCollectionAbandoned) {
		t.Fatalf("partial batch retry was not durably abandoned: %v", err)
	}
	after := providerEffectCount(fixture.harness)
	if after != before {
		t.Fatalf("partial batch retry duplicated provider effects: before=%d after=%d", before, after)
	}
	store, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	journal := store.Snapshot()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if !journal.Abandoned || journal.Complete || len(journal.Settlements) != 12 {
		t.Fatalf("abandoned provider journal differs: %#v", journal)
	}
	for _, settlement := range journal.Settlements {
		if settlement.Status == "complete" && (settlement.Receipt == nil || !settlement.Receipt.Quiescence.ContainerAbsent) {
			t.Fatalf("abandoned settlement is not quiescent: %#v", settlement)
		}
	}
	if _, err := fixture.collector.CollectWithJournal(context.Background(), fixture.run, journalPath); !errors.Is(err, ErrProviderCollectionAbandoned) {
		t.Fatalf("abandoned journal replay changed disposition: %v", err)
	}
	if final := providerEffectCount(fixture.harness); final != before {
		t.Fatalf("abandoned replay duplicated provider effects: before=%d after=%d", before, final)
	}
}

func TestProviderCollectionJournalAbandonsUnjournaledSettledRoster(t *testing.T) {
	fixture := newProviderCollectorFixture(t)
	defer fixture.close()
	if _, err := fixture.collector.Collect(context.Background(), fixture.run); err != nil {
		t.Fatal(err)
	}
	before := providerEffectCount(fixture.harness)
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(root, "provider-collection-journal.json")
	if _, err := fixture.collector.CollectWithJournal(context.Background(), fixture.run, journalPath); !errors.Is(err, ErrProviderCollectionAbandoned) {
		t.Fatalf("unjournaled settled roster was not abandoned: %v", err)
	}
	if after := providerEffectCount(fixture.harness); after != before {
		t.Fatalf("unjournaled roster reconciliation duplicated effects: before=%d after=%d", before, after)
	}
	store, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	journal := store.Snapshot()
	defer store.Close()
	if !journal.Abandoned || len(journal.Settlements) != 12 {
		t.Fatalf("unjournaled roster abandonment is incomplete: %#v", journal)
	}
	for _, settlement := range journal.Settlements {
		if settlement.Status != "complete" || settlement.Receipt == nil || !settlement.Receipt.Quiescence.ContainerAbsent {
			t.Fatalf("settled roster abandonment lost quiescence: %#v", settlement)
		}
	}
}

func TestExistingEmptyJournalNeverReusesAmbiguousOperationIDs(t *testing.T) {
	fixture := newProviderCollectorFixture(t)
	defer fixture.close()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(root, "provider-collection-journal.json")
	created, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.harness.mu.Lock()
	fixture.harness.observationDelay = 2 * time.Millisecond
	fixture.harness.mu.Unlock()
	if _, err := fixture.collector.CollectWithJournal(context.Background(), fixture.run, journalPath); !errors.Is(err, ErrProviderCollectionAbandoned) {
		t.Fatalf("existing empty journal reused ambiguous operation IDs: %v", err)
	}
	if effects := providerEffectCount(fixture.harness); effects != 0 {
		t.Fatalf("existing empty journal caused provider effects: %d", effects)
	}
	store, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	journal := store.Snapshot()
	defer store.Close()
	if !journal.Abandoned || len(journal.Settlements) != 12 {
		t.Fatalf("empty ambiguous attempt was not durably abandoned: %#v", journal)
	}
	for _, settlement := range journal.Settlements {
		if settlement.Status != "absent" || settlement.Receipt != nil {
			t.Fatalf("empty ambiguous attempt has non-absent settlement: %#v", settlement)
		}
		from, fromErr := parseObservationTime(settlement.ObservedFrom)
		until, untilErr := parseObservationTime(settlement.ObservedUntil)
		if fromErr != nil || untilErr != nil || until.Sub(from) < providerObservationSeconds*time.Second {
			t.Fatalf("absent settlement omitted its full window: %#v", settlement)
		}
	}
	shortened := cloneProviderCollectionJournal(journal)
	shortened.Settlements[0].ObservedUntil = shortened.Settlements[0].ObservedFrom
	assertProviderJournalMutationRejected(t, shortened, fixture.run)
	substituted := cloneProviderCollectionJournal(journal)
	substituted.Settlements[0].ObservedFrom = "2026-08-24T00:00:00Z"
	assertProviderJournalMutationRejected(t, substituted, fixture.run)
}

func TestRecoveredEmptyJournalCatchesClaimsArrivingAfterInitialAbsentScan(t *testing.T) {
	fixture := newProviderCollectorFixture(t)
	defer fixture.close()
	if _, err := fixture.collector.Collect(context.Background(), fixture.run); err != nil {
		t.Fatal(err)
	}
	before := providerEffectCount(fixture.harness)
	fixture.harness.mu.Lock()
	fixture.harness.hideFirstObservation = true
	fixture.harness.observationCalls = make(map[string]int)
	fixture.harness.mu.Unlock()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(root, "provider-collection-journal.json")
	created, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.collector.CollectWithJournal(context.Background(), fixture.run, journalPath); !errors.Is(err, ErrProviderCollectionAbandoned) {
		t.Fatalf("late durable claims were not abandoned: %v", err)
	}
	if after := providerEffectCount(fixture.harness); after != before {
		t.Fatalf("late-claim reconciliation duplicated effects: before=%d after=%d", before, after)
	}
	store, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	journal := store.Snapshot()
	defer store.Close()
	if !journal.Abandoned || len(journal.Settlements) != 12 {
		t.Fatalf("late-claim abandonment is incomplete: %#v", journal)
	}
	for _, settlement := range journal.Settlements {
		if settlement.Status != "complete" || settlement.Receipt == nil || !settlement.Receipt.Quiescence.ContainerAbsent {
			t.Fatalf("late claim did not reconcile terminal/quiescent: %#v", settlement)
		}
	}
}

func TestProviderJournalReconcilesOnlyExactOwnedStaging(t *testing.T) {
	fixture := newProviderCollectorFixture(t)
	defer fixture.close()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(root, "provider-collection-journal.json")
	created, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	staging := providerJournalStagingPath(journalPath)
	if err := os.WriteFile(staging, []byte("hard-crash-partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(staging, 0o000); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatalf("owned hard-crash staging did not reconcile: %v", err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(staging); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned journal staging remains after recovery: %v", err)
	}
	target := filepath.Join(root, "do-not-delete")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, staging); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenProviderCollectionJournal(journalPath, fixture.run); err == nil {
		t.Fatal("substituted journal staging was removed")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "target" {
		t.Fatalf("staging substitution damaged target: %q %v", data, err)
	}
}

func TestProviderJournalDirectoryLockExcludesConcurrentCollectorsAndReleases(t *testing.T) {
	fixture := newProviderCollectorFixture(t)
	defer fixture.close()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(root, "provider-collection-journal.json")
	first, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.collector.CollectWithJournal(
		context.Background(), fixture.run, journalPath,
	); err == nil {
		t.Fatal("second collector acquired active provider journal directory")
	}
	if effects := providerEffectCount(fixture.harness); effects != 0 {
		t.Fatalf("journal lock contention caused provider effects: %d", effects)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatalf("provider journal lock did not release: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProviderJournalFinalizeWriteFailureLeavesTwelveEntriesRetryable(t *testing.T) {
	fixture := newProviderCollectorFixture(t)
	defer fixture.close()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(root, "provider-collection-journal.json")
	if _, err := fixture.collector.CollectWithJournal(context.Background(), fixture.run, journalPath); err != nil {
		t.Fatal(err)
	}
	completedStore, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	completed := completedStore.Snapshot()
	if err := completedStore.Close(); err != nil {
		t.Fatal(err)
	}
	collecting := cloneProviderCollectionJournal(completed)
	collecting.Complete = false
	collecting.ObservedFrom = ""
	collecting.ObservedUntil = ""
	collecting.Digest = ""
	collecting, err = sealProviderCollectionJournal(collecting)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeProviderJournal(journalPath, collecting, completed.Digest); err != nil {
		t.Fatal(err)
	}
	store, err := OpenProviderCollectionJournal(journalPath, fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, err := readPinnedFile(fixture.run.RunnerPolicy, 32*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := store.FinalizeComplete(policyBytes); err == nil || errors.Is(err, ErrProviderJournalCompletionInvalid) {
		t.Fatalf("injected finalize write failure changed semantic disposition: %v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.FinalizeComplete(policyBytes); err != nil {
		t.Fatalf("retryable journal completion did not recover: %v", err)
	}
	if !store.Snapshot().Complete {
		t.Fatal("retryable journal did not become complete")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func providerEffectCount(harness *providerHarness) int {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	return harness.cancelledOperations + harness.settledSuccessRequests
}

func assertProviderJournalMutationRejected(
	t *testing.T,
	journal ProviderCollectionJournal,
	run ProviderLiveRun,
) {
	t.Helper()
	sealed, err := sealProviderCollectionJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := generationstop.CanonicalJSON(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProviderCollectionJournal(encoded, run); err == nil {
		t.Fatal("forged provider journal mutation was accepted")
	}
}
