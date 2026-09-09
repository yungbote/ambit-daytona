// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
)

func inventoryFixture(t *testing.T, entries ...tarEntry) (*Service, *fakeContainer, *fakeObjectStore, WorkingTreeInventoryRequest) {
	t.Helper()
	return workingTreeFixture(t, entries...)
}

func TestWorkingTreeInventoryPagesLargerDependencyTreesWithoutRepeatedArchives(t *testing.T) {
	var source []tarEntry
	source = append(source, tarEntry{name: "workspace/node_modules", typeflag: tar.TypeDir})
	for i := 9000; i >= 0; i-- {
		source = append(source, tarEntry{name: fmt.Sprintf("workspace/node_modules/package-%05d.js", i), typeflag: tar.TypeReg, body: []byte("x")})
	}
	service, containers, objects, request := inventoryFixture(t, source...)
	request.MaximumPageEntries = 1000
	receipt, err := service.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.EntryCount != 9002 || receipt.AggregateBytes != 9001 || len(receipt.Pages) != 10 {
		t.Fatalf("incomplete dependency tree: %#v", receipt)
	}
	var previous string
	var count int
	for _, descriptor := range receipt.Pages {
		page, err := service.ReadWorkingTreeInventoryPage(context.Background(), request.Generation.Source.ProviderResourceID, WorkingTreeInventoryPageRequest{Request: request, ProviderResourceID: receipt.ProviderResourceID, PageIndex: descriptor.PageIndex})
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := generationstop.CanonicalJSON(page.Entries)
		if len(encoded) != descriptor.ByteLength || sha256Digest(encoded) != descriptor.SHA256 || len(page.Entries) > 1000 {
			t.Fatal("page does not match complete index")
		}
		for _, entry := range page.Entries {
			if previous != "" && compareUTF8Lexicographic(previous, entry.ZoneRelativePath) >= 0 {
				t.Fatal("pages lost global ordering")
			}
			previous = entry.ZoneRelativePath
			count++
		}
	}
	if count != 9002 || containers.copyCalls != 1 {
		t.Fatalf("paging reread source or lost entries: count=%d archives=%d", count, containers.copyCalls)
	}
	replayed, err := service.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request)
	if err != nil || replayed.InventoryDigest != receipt.InventoryDigest || containers.copyCalls != 1 {
		t.Fatalf("complete replay reread the archive: %v", err)
	}
	for key, object := range objects.objects {
		if !strings.HasPrefix(key, inventoryRoot(request)+"/") || bytes.Contains(object.data, []byte("bytesBase64")) {
			t.Fatal("inventory wrote source payload custody")
		}
	}
	deleted, err := service.DeleteWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request)
	if err != nil || deleted.Status != "absent" || len(objects.objects) != 1 {
		t.Fatalf("inventory absence not established: %#v %v", deleted, err)
	}
	if _, err := service.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); !errors.Is(err, ErrConflict) {
		t.Fatal("retired inventory was recreated")
	}
}

func TestWorkingTreeInventoryKeepsPrefixAncestryAcrossPages(t *testing.T) {
	service, _, _, request := inventoryFixture(t,
		tarEntry{name: "workspace/a", typeflag: tar.TypeDir},
		tarEntry{name: "workspace/a/x", typeflag: tar.TypeReg},
		tarEntry{name: "workspace/a.txt", typeflag: tar.TypeReg},
	)
	request.MaximumPageEntries = 1
	receipt, err := service.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request)
	if err != nil || len(receipt.Pages) != 3 || receipt.Pages[1].FirstPath != "a.txt" || receipt.Pages[2].FirstPath != "a/x" {
		t.Fatalf("valid interleaved ancestry failed: %#v %v", receipt, err)
	}
	for name, entries := range map[string][]tarEntry{
		"missing":     {{name: "workspace/a/x", typeflag: tar.TypeReg}},
		"file-parent": {{name: "workspace/a", typeflag: tar.TypeReg}, {name: "workspace/a.txt", typeflag: tar.TypeReg}, {name: "workspace/a/x", typeflag: tar.TypeReg}},
		"link-parent": {{name: "workspace/a", typeflag: tar.TypeSymlink, linkname: "target"}, {name: "workspace/a/x", typeflag: tar.TypeReg}},
		"duplicate":   {{name: "workspace/a", typeflag: tar.TypeReg}, {name: "workspace/a", typeflag: tar.TypeReg}},
	} {
		t.Run(name, func(t *testing.T) {
			service, _, _, request := inventoryFixture(t, entries...)
			request.MaximumPageEntries = 1
			if _, err := service.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); !errors.Is(err, ErrConflict) {
				t.Fatalf("invalid namespace admitted: %v", err)
			}
		})
	}
}

func TestWorkingTreeInventoryRecoversPartialPreparationAndDeletion(t *testing.T) {
	for _, cut := range []string{"/pages/000000000001.json", "/index.json"} {
		t.Run(cut, func(t *testing.T) {
			service, containers, objects, request := inventoryFixture(t, tarEntry{name: "workspace/a", typeflag: tar.TypeReg}, tarEntry{name: "workspace/b", typeflag: tar.TypeReg}, tarEntry{name: "workspace/c", typeflag: tar.TypeReg})
			request.MaximumPageEntries = 1
			objects.failBeforeStoreSuffix = cut
			if _, err := service.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("partial prepare claimed completion: %v", err)
			}
			if _, exists := objects.objects[inventoryRoot(request)+"/index.json"]; exists {
				t.Fatal("index published before all pages")
			}
			objects.failBeforeStoreSuffix = ""
			receipt, err := service.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request)
			if err != nil || len(receipt.Pages) != 3 || containers.copyCalls != 2 {
				t.Fatalf("partial prepare did not converge: %v", err)
			}
			objects.failAfterDeleteSuffix = "/pages/000000000001.json"
			if _, err := service.DeleteWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("partial delete claimed absence: %v", err)
			}
			objects.failAfterDeleteSuffix = ""
			if _, err := service.DeleteWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); err != nil || len(objects.objects) != 1 {
				t.Fatalf("delete did not resume after page zero disappeared: %v", err)
			}
		})
	}
	service, containers, objects, request := inventoryFixture(t, tarEntry{name: "workspace/a", typeflag: tar.TypeReg}, tarEntry{name: "workspace/b", typeflag: tar.TypeReg})
	request.MaximumPageEntries = 1
	objects.failBeforeStoreSuffix = "/index.json"
	_, _ = service.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request)
	objects.failBeforeStoreSuffix = ""
	if _, err := service.DeleteWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); err != nil || len(objects.objects) != 1 || containers.copyCalls != 1 {
		t.Fatalf("unknown prepare could not retire partial custody without an index: %v", err)
	}
}

func TestWorkingTreeInventoryValidatesImmutablePagesAndAbsentCustody(t *testing.T) {
	service, _, objects, request := inventoryFixture(t, tarEntry{name: "workspace/a", typeflag: tar.TypeReg, body: []byte("payload")})
	receipt, err := service.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request)
	if err != nil {
		t.Fatal(err)
	}
	key := inventoryPageKey(inventoryRoot(request), 0)
	object := objects.objects[key]
	object.data = append(object.data, ' ')
	objects.objects[key] = object
	if _, err := service.ReadWorkingTreeInventoryPage(context.Background(), request.Generation.Source.ProviderResourceID, WorkingTreeInventoryPageRequest{Request: request, ProviderResourceID: receipt.ProviderResourceID}); !errors.Is(err, ErrConflict) {
		t.Fatal("changed page bytes were admitted")
	}
	foreign := request
	foreign.Generation.Owner.GrantID = "99999999-9999-4999-8999-999999999999"
	if _, err := service.DeleteWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, foreign); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign request could delete inventory custody")
	}
	service, containers, objects, request := inventoryFixture(t)
	if deleted, err := service.DeleteWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); err != nil || deleted.Status != "absent" || containers.copyCalls != 0 {
		t.Fatalf("absent inventory required a source read: %v", err)
	}
	if _, err := service.DeleteWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); err != nil {
		t.Fatal(err)
	}
	service, _, objects, request = inventoryFixture(t)
	objects.objects[inventoryPageKey(inventoryRoot(request), 1)] = fakeStoredObject{data: []byte("[]")}
	if _, err := service.DeleteWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request); err == nil {
		t.Fatal("orphan page without owner intent was called absent")
	}
}

func TestInventorySorterBoundsRunsAndReleasesUnlinkedScratch(t *testing.T) {
	sorter, err := newInventorySorter()
	if err != nil {
		t.Fatal(err)
	}
	defer sorter.Close()
	if _, err := os.Stat(sorter.file.Name()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inventory scratch retained a durable pathname")
	}
	mode := "0644"
	hash := sha256Digest(nil)
	const count = 140000
	for i := count - 1; i >= 0; i-- {
		name := fmt.Sprintf("file-%08d", i)
		if err := sorter.Add(context.Background(), StoppedWorkingTreeEntry{ZoneRelativePath: name, Name: name, Kind: "regular_file", Mode: &mode, SHA256: &hash}, ""); err != nil {
			t.Fatal(err)
		}
		if len(sorter.entries) > MaximumWorkingTreeInventoryPageEntries || sorter.entryBytes > MaximumWorkingTreeInventoryPageBytes {
			t.Fatal("sorter retained unbounded entry metadata")
		}
		for _, runs := range sorter.levels {
			if len(runs) >= inventoryMergeFanIn {
				t.Fatal("sorter retained an unmerged run tier")
			}
		}
	}
	observed := 0
	rows, err := sorter.Seal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := rows.Walk(context.Background(), func(record inventoryArchiveEntry) error {
		entry := record.Entry
		if entry.ZoneRelativePath != fmt.Sprintf("file-%08d", observed) {
			return fmt.Errorf("sort order changed at %d", observed)
		}
		observed++
		return nil
	}); err != nil || observed != count {
		t.Fatalf("bounded merge lost rows: %d %v", observed, err)
	}
}

func TestWorkingTreeInventoryMatchesCrossLanguagePages(t *testing.T) {
	var fixture struct {
		Receipt WorkingTreeInventoryReceipt `json:"receipt"`
		Pages   []WorkingTreeInventoryPage  `json:"pages"`
	}
	golden, err := os.ReadFile("testdata/stopped-working-tree-inventory.canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(golden, &fixture); err != nil {
		t.Fatal(err)
	}
	service, _, _, request := inventoryFixture(t, workingTreeLinkEntries()...)
	request.MaximumPageEntries = 3
	receipt, err := service.PrepareWorkingTreeInventory(context.Background(), request.Generation.Source.ProviderResourceID, request)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := generationstop.CanonicalJSON(receipt)
	want, _ := generationstop.CanonicalJSON(fixture.Receipt)
	if !bytes.Equal(got, want) {
		t.Fatalf("cross-language inventory differs:\n%s\n%s", got, want)
	}
	for _, expected := range fixture.Pages {
		page, err := service.ReadWorkingTreeInventoryPage(context.Background(), request.Generation.Source.ProviderResourceID, WorkingTreeInventoryPageRequest{Request: request, ProviderResourceID: receipt.ProviderResourceID, PageIndex: expected.PageIndex})
		if err != nil {
			t.Fatal(err)
		}
		got, _ := generationstop.CanonicalJSON(page)
		want, _ := generationstop.CanonicalJSON(expected)
		if !bytes.Equal(got, want) {
			t.Fatal("cross-language metadata page differs")
		}
	}
}
