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
	journalPath := filepath.Join(root, "provider-collection-journal.json")

	first, err := fixture.collector.CollectWithJournal(context.Background(), fixture.run, journalPath)
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
	second, err := fixture.collector.CollectWithJournal(context.Background(), fixture.run, journalPath)
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
	if !journal.Abandoned || len(journal.Settlements) != 12 {
		t.Fatalf("unjournaled roster abandonment is incomplete: %#v", journal)
	}
	for _, settlement := range journal.Settlements {
		if settlement.Status != "complete" || settlement.Receipt == nil || !settlement.Receipt.Quiescence.ContainerAbsent {
			t.Fatalf("settled roster abandonment lost quiescence: %#v", settlement)
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
	if _, err := OpenProviderCollectionJournal(journalPath, fixture.run); err != nil {
		t.Fatal(err)
	}
	staging := providerJournalStagingPath(journalPath)
	if err := os.WriteFile(staging, []byte("hard-crash-partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenProviderCollectionJournal(journalPath, fixture.run); err != nil {
		t.Fatalf("owned hard-crash staging did not reconcile: %v", err)
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

func providerEffectCount(harness *providerHarness) int {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	return harness.cancelledOperations + harness.settledSuccessRequests
}
