// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
)

func TestInventoryBytePackSharesHardlinkOffsetsAndSurvivesSourceLoss(t *testing.T) {
	service, containers, objects, request := inventoryFixture(t,
		tarEntry{name: "workspace/z", typeflag: tar.TypeReg, body: []byte("first")},
		tarEntry{name: "workspace/a", typeflag: tar.TypeReg, body: []byte("second")},
		tarEntry{name: "workspace/link", typeflag: tar.TypeLink, linkname: "workspace/z"},
		tarEntry{name: "workspace/empty", typeflag: tar.TypeReg},
	)
	ctx := context.Background()
	receipt, err := service.PrepareWorkingTreeInventory(ctx, request.Generation.Source.ProviderResourceID, request)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.AggregateBytes != 16 || receipt.BytePack.ByteLength != 11 || receipt.BytePack.SHA256 != sha256Digest([]byte("firstsecond")) || len(receipt.BytePack.Parts) != 1 {
		t.Fatalf("pack does not distinguish physical bytes from restored hardlinks: %#v", receipt)
	}
	containers.beforeCopy = func() error { return errors.New("source no longer exists") }
	for _, entry := range readInventoryTestEntries(t, service, receipt) {
		expected := map[string]string{"a": "second", "z": "first", "link": "first", "empty": ""}[entry.Name]
		read, err := service.ReadWorkingTreeInventoryRange(ctx, request.Generation.Source.ProviderResourceID, WorkingTreeInventoryRangeRequest{
			Request: request, ProviderResourceID: receipt.ProviderResourceID, InventoryDigest: receipt.InventoryDigest,
			Offset: *entry.ByteOffset, MaximumBytes: max(entry.Size, 1),
		})
		if err != nil {
			t.Fatal(err)
		}
		data, err := base64.StdEncoding.DecodeString(read.BytesBase64)
		if err != nil || !bytes.Equal(data[:entry.Size], []byte(expected)) || *entry.SHA256 != sha256Digest([]byte(expected)) {
			t.Fatalf("entry %s did not restore from its archive offset: %v", entry.Name, err)
		}
	}
	if containers.copyCalls != 1 || len(objects.objects) != len(receipt.Pages)+3 {
		t.Fatalf("inventory created per-file custody: archives=%d objects=%d", containers.copyCalls, len(objects.objects))
	}
}

func TestInventoryByteRangeCrossesPartsAndRejectsChangedCustody(t *testing.T) {
	service, _, objects, request := inventoryFixture(t, tarEntry{name: "workspace/file", typeflag: tar.TypeReg, body: []byte("abcdefgh")})
	ctx := context.Background()
	receipt, err := service.PrepareWorkingTreeInventory(ctx, request.Generation.Source.ProviderResourceID, request)
	if err != nil {
		t.Fatal(err)
	}
	// A transport range may span immutable storage parts; the reader follows
	// descriptor offsets, independently of the writer's current part size.
	root := inventoryRoot(request)
	original := objects.objects[inventoryBytePartKey(root, 0)]
	receipt.BytePack.Parts = []WorkingTreeInventoryBytePart{
		{ByteOffset: 0, ByteLength: 3, SHA256: sha256Digest([]byte("abc"))},
		{ByteOffset: 3, ByteLength: 5, SHA256: sha256Digest([]byte("defgh"))},
	}
	for index, part := range receipt.BytePack.Parts {
		metadata := lowerMetadata(original.metadata)
		metadata["sha256"] = part.SHA256
		metadata["byte-offset"] = []string{"0", "3"}[index]
		metadata["byte-length"] = []string{"3", "5"}[index]
		objects.objects[inventoryBytePartKey(root, index)] = fakeStoredObject{data: []byte("abcdefgh")[part.ByteOffset : part.ByteOffset+part.ByteLength], contentSHA256: part.SHA256, metadata: metadata}
	}
	receipt.InventoryDigest, _ = inventoryDigest(receipt)
	data, _ := generationstop.CanonicalJSON(receipt)
	objects.objects[root+"/index.json"] = fakeStoredObject{data: data}
	readRequest := WorkingTreeInventoryRangeRequest{Request: request, ProviderResourceID: receipt.ProviderResourceID, InventoryDigest: receipt.InventoryDigest, Offset: 1, MaximumBytes: 5}
	read, err := service.ReadWorkingTreeInventoryRange(ctx, request.Generation.Source.ProviderResourceID, readRequest)
	if err != nil || read.BytesBase64 != base64.StdEncoding.EncodeToString([]byte("bcdef")) || read.EOF || len(objects.rangeReads) != 2 {
		t.Fatalf("range did not cross part boundaries: %#v %v", read, err)
	}
	for name, mutate := range map[string]func(*WorkingTreeInventoryRangeRequest){
		"negative":   func(r *WorkingTreeInventoryRangeRequest) { r.Offset = -1 },
		"past-end":   func(r *WorkingTreeInventoryRangeRequest) { r.Offset = 9 },
		"zero-bound": func(r *WorkingTreeInventoryRangeRequest) { r.MaximumBytes = 0 },
		"oversize":   func(r *WorkingTreeInventoryRangeRequest) { r.MaximumBytes = MaximumReadBytes + 1 },
		"foreign":    func(r *WorkingTreeInventoryRangeRequest) { r.InventoryDigest = "sha256:" + strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := readRequest
			mutate(&changed)
			if _, err := service.ReadWorkingTreeInventoryRange(ctx, request.Generation.Source.ProviderResourceID, changed); err == nil {
				t.Fatal("invalid byte range was admitted")
			}
		})
	}
	readRequest.Offset = 8
	read, err = service.ReadWorkingTreeInventoryRange(ctx, request.Generation.Source.ProviderResourceID, readRequest)
	if err != nil || !read.EOF || read.ByteLength != 0 || read.BytesBase64 != "" {
		t.Fatalf("exact end-of-pack read changed: %#v %v", read, err)
	}
	changed := objects.objects[inventoryBytePartKey(root, 1)]
	changed.contentSHA256 = sha256Digest([]byte("other"))
	objects.objects[inventoryBytePartKey(root, 1)] = changed
	readRequest.Offset = 3
	if _, err := service.ReadWorkingTreeInventoryRange(ctx, request.Generation.Source.ProviderResourceID, readRequest); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed object bytes were admitted: %v", err)
	}
}

func TestInventoryBytePublicationAndDeletionResumeAsOneOwner(t *testing.T) {
	for _, cut := range []string{"/bytes/000000000000.bin", "/index.json"} {
		t.Run(cut, func(t *testing.T) {
			service, containers, objects, request := inventoryFixture(t, tarEntry{name: "workspace/file", typeflag: tar.TypeReg, body: []byte("owned bytes")})
			ctx := context.Background()
			objects.failBeforeStoreSuffix = cut
			if _, err := service.PrepareWorkingTreeInventory(ctx, request.Generation.Source.ProviderResourceID, request); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("partial publication was called complete: %v", err)
			}
			if _, ok := objects.objects[inventoryRoot(request)+"/index.json"]; ok {
				t.Fatal("index preceded complete byte custody")
			}
			objects.failBeforeStoreSuffix = ""
			receipt, err := service.PrepareWorkingTreeInventory(ctx, request.Generation.Source.ProviderResourceID, request)
			if err != nil || containers.copyCalls != 2 {
				t.Fatalf("partial byte publication did not converge: %v", err)
			}
			objects.failAfterDeleteSuffix = "/bytes/000000000000.bin"
			if _, err := service.DeleteWorkingTreeInventory(ctx, request.Generation.Source.ProviderResourceID, request); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("lost deletion acknowledgement was called absent: %v", err)
			}
			if _, err := service.ReadWorkingTreeInventoryRange(ctx, request.Generation.Source.ProviderResourceID, WorkingTreeInventoryRangeRequest{Request: request, ProviderResourceID: receipt.ProviderResourceID, InventoryDigest: receipt.InventoryDigest, MaximumBytes: 1}); !errors.Is(err, ErrConflict) {
				t.Fatalf("retired byte custody remained readable: %v", err)
			}
			objects.failAfterDeleteSuffix = ""
			if _, err := service.DeleteWorkingTreeInventory(ctx, request.Generation.Source.ProviderResourceID, request); err != nil || len(objects.objects) != 1 {
				t.Fatalf("inventory deletion did not own both pages and bytes: %v", err)
			}
		})
	}
}
