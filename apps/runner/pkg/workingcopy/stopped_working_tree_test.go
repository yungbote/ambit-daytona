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
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	containertypes "github.com/docker/docker/api/types/container"
)

func workingTreeFixture(t *testing.T, entries ...tarEntry) (*Service, *fakeContainer, *fakeObjectStore, StoppedWorkingTreeRequest) {
	t.Helper()
	binding := validBinding()
	request := StoppedWorkingTreeRequest{
		Generation: binding.generationBinding(), ExcludedPaths: []string{},
		MaximumDepth: MaximumWorkingTreeDepth, MaximumEntries: MaximumWorkingTreeEntries,
		MaximumFileBytes: MaximumCaptureBytes, MaximumAggregateBytes: MaximumWorkingTreeAggregateBytes,
	}
	containers := newFakeContainer(nil)
	containers.copyStatMode = os.ModeDir | 0o755
	containers.archive = tarArchive(append([]tarEntry{{name: "workspace/", typeflag: tar.TypeDir, mode: 0o755}}, entries...)...)
	objects := newFakeObjectStore()
	service := mustService(t, containers, objects, binding.Authority)
	service.now = func() time.Time { return time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC) }
	return service, containers, objects, request
}

func TestStoppedWorkingTreeAdmitsEmptyRootWithoutAnAnchor(t *testing.T) {
	service, containers, objects, request := workingTreeFixture(t)
	receipt, err := service.StoppedWorkingTree(context.Background(), request.Generation.Source.ProviderResourceID, request)
	if err != nil || receipt.Entries == nil || len(receipt.Entries) != 0 {
		t.Fatalf("empty root did not yield a complete empty roster: %#v %v", receipt, err)
	}
	if containers.copyCalls != 1 || containers.copyPaths[0] != "/workspace" || containers.copyContainerIDs[0] != request.Generation.StopAuthority.TerminalGeneration.ContainerID || len(objects.objects) != 0 {
		t.Fatal("root roster did not use one exact host archive without object writes")
	}
	encoded, err := json.Marshal(request)
	if err != nil || bytes.Contains(encoded, []byte("selector")) || bytes.Contains(encoded, []byte("anchor")) {
		t.Fatalf("generation request fabricated file selection: %s %v", encoded, err)
	}
	var decoded StoppedWorkingTreeRequest
	if err := DecodeExactJSON(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		bytes.Replace(encoded, []byte(`,"excludedPaths":[]`), nil, 1),
		bytes.Replace(encoded, []byte(`"excludedPaths":[]`), []byte(`"excludedPaths":null`), 1),
	} {
		if err := DecodeExactJSON(invalid, &decoded); err == nil {
			if _, err := service.StoppedWorkingTree(context.Background(), request.Generation.Source.ProviderResourceID, decoded); !errors.Is(err, ErrInvalidRequest) {
				t.Fatal("missing/null exclusions bypassed request admission")
			}
		}
	}
	canonical, err := generationstop.CanonicalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile("testdata/stopped-working-tree.canonical.json")
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(golden)) {
		t.Fatalf("working-tree Go/TypeScript fixture drifted: %v", err)
	}
}

func TestStoppedWorkingTreeHashesLargeCustomFilesAndExcludesOnlyOwnedPaths(t *testing.T) {
	service, containers, objects, request := workingTreeFixture(t)
	request.ExcludedPaths = []string{"mounted"}
	const size = 102 << 20
	var maximumRead int
	containers.archiveReader = func(context.Context) io.ReadCloser {
		prefix := append(workingTreeTarHeader("workspace/", tar.TypeDir, 0), workingTreeTarHeader("workspace/customer.bin", tar.TypeReg, size)...)
		remainder := tarArchive(
			tarEntry{name: "workspace/.ambit/", typeflag: tar.TypeDir},
			tarEntry{name: "workspace/.ambit/runtime", typeflag: tar.TypeReg, body: []byte("managed bytes")},
			tarEntry{name: "workspace/.ambit/" + strings.Repeat("deep/", 900) + "runtime", typeflag: tar.TypeReg, body: []byte("excluded independent of user path bounds")},
			tarEntry{name: "workspace/.ambit-skill-research", typeflag: tar.TypeSymlink, linkname: "/opt/skill"},
			tarEntry{name: "workspace/mounted", typeflag: tar.TypeSymlink, linkname: "/volume"},
			tarEntry{name: "workspace/mounted/private.bin", typeflag: tar.TypeReg, body: []byte("mounted bytes")},
			tarEntry{name: "workspace/custom/", typeflag: tar.TypeDir},
			tarEntry{name: "workspace/custom/.ambit", typeflag: tar.TypeReg, body: []byte("ordinary user file")},
			tarEntry{name: "workspace/custom/notes.txt", typeflag: tar.TypeReg, body: []byte("notes")},
			tarEntry{name: "workspace/mounted-other.txt", typeflag: tar.TypeReg, body: []byte("retained")},
		)
		return &observedReadCloser{
			ReadCloser: io.NopCloser(io.MultiReader(bytes.NewReader(prefix), &generatedFileReader{remaining: size}, bytes.NewReader(remainder))),
			observe:    func(requested, _ int) { maximumRead = max(maximumRead, requested) },
		}
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	receipt, err := service.StoppedWorkingTree(context.Background(), request.Generation.Source.ProviderResourceID, request)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if after.TotalAlloc-before.TotalAlloc > 16<<20 || maximumRead > captureStreamBufferBytes {
		t.Fatalf("roster buffered file content: allocated=%d read=%d", after.TotalAlloc-before.TotalAlloc, maximumRead)
	}
	expected := []string{"custom", "custom/.ambit", "custom/notes.txt", "customer.bin", "mounted-other.txt"}
	if len(receipt.Entries) != len(expected) {
		t.Fatalf("excluded wrong paths: %#v", receipt.Entries)
	}
	for index, entry := range receipt.Entries {
		if entry.ZoneRelativePath != expected[index] {
			t.Fatalf("wrong canonical roster: %#v", receipt.Entries)
		}
	}
	if receipt.Entries[3].Size != size || receipt.Entries[3].SHA256 == nil || *receipt.Entries[3].SHA256 != generatedDigest(size) {
		t.Fatal("large user file digest changed")
	}
	payload, err := generationstop.CanonicalJSON(map[string]any{
		"contract": "ambit.working-copy-stopped-working-tree/v1", "request": request,
		"terminalGeneration": request.Generation.StopAuthority.TerminalGeneration, "entries": receipt.Entries,
	})
	if err != nil || receipt.RosterDigest != sha256Digest(payload) {
		t.Fatalf("complete roster digest differs: %v", err)
	}
	if len(objects.objects) != 0 {
		t.Fatal("roster persisted archive bytes")
	}
}

func TestStoppedWorkingTreeRejectsNoncanonicalAndRedundantExclusions(t *testing.T) {
	for _, paths := range [][]string{nil, {""}, {"."}, {"../outside"}, {"/workspace/x"}, {"x/"}, {"x\\y"}, {"z", "a"}, {"a", "a"}, {"a", "a/b"}, {"e\u0301"}} {
		t.Run(fmt.Sprint(paths), func(t *testing.T) {
			service, containers, _, request := workingTreeFixture(t)
			request.ExcludedPaths = paths
			if _, err := service.StoppedWorkingTree(context.Background(), request.Generation.Source.ProviderResourceID, request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("invalid exclusions admitted: %v", err)
			}
			if containers.inspectCalls != 0 || containers.copyCalls != 0 {
				t.Fatal("invalid exclusions reached Docker")
			}
		})
	}
}

func TestStoppedWorkingTreeRejectsLinksEscapesDuplicatePathsAndMissingParents(t *testing.T) {
	for name, entries := range map[string][]tarEntry{
		"symlink":        {{name: "workspace/link", typeflag: tar.TypeSymlink, linkname: "/outside"}},
		"hardlink":       {{name: "workspace/link", typeflag: tar.TypeLink, linkname: "workspace/file"}},
		"special":        {{name: "workspace/pipe", typeflag: tar.TypeFifo}},
		"escape":         {{name: "workspace/../outside", typeflag: tar.TypeReg, body: []byte("x")}},
		"duplicate":      {{name: "workspace/a", typeflag: tar.TypeReg}, {name: "workspace/a", typeflag: tar.TypeReg}},
		"missing-parent": {{name: "workspace/a/b", typeflag: tar.TypeReg}},
		"file-parent":    {{name: "workspace/a", typeflag: tar.TypeReg}, {name: "workspace/a/b", typeflag: tar.TypeReg}},
		"non-nfc":        {{name: "workspace/e\u0301", typeflag: tar.TypeReg}},
	} {
		t.Run(name, func(t *testing.T) {
			service, _, _, request := workingTreeFixture(t, entries...)
			if _, err := service.StoppedWorkingTree(context.Background(), request.Generation.Source.ProviderResourceID, request); !errors.Is(err, ErrConflict) {
				t.Fatalf("invalid user tree was admitted: %v", err)
			}
		})
	}
}

func TestStoppedWorkingTreeFailsCompleteOnBoundsAndGenerationDrift(t *testing.T) {
	for name, mutate := range map[string]func(*StoppedWorkingTreeRequest, *fakeContainer){
		"entries":    func(r *StoppedWorkingTreeRequest, _ *fakeContainer) { r.MaximumEntries = 1 },
		"file-bytes": func(r *StoppedWorkingTreeRequest, _ *fakeContainer) { r.MaximumFileBytes = 1 },
		"aggregate": func(r *StoppedWorkingTreeRequest, _ *fakeContainer) {
			r.MaximumFileBytes = 2
			r.MaximumAggregateBytes = 2
		},
		"depth": func(r *StoppedWorkingTreeRequest, _ *fakeContainer) { r.MaximumDepth = 1 },
		"generation-before": func(r *StoppedWorkingTreeRequest, _ *fakeContainer) {
			r.Generation.StopAuthority.TerminalGeneration.RestartCount++
		},
		"generation-after": func(_ *StoppedWorkingTreeRequest, c *fakeContainer) {
			changed := c.generation
			changed.RestartCount++
			c.inspectMutations[2] = changed
		},
		"root-descriptor": func(_ *StoppedWorkingTreeRequest, c *fakeContainer) {
			c.afterStatMutation = func(stat containertypes.PathStat) containertypes.PathStat {
				stat.Mtime = stat.Mtime.Add(time.Second)
				return stat
			}
		},
		"symlink-root": func(_ *StoppedWorkingTreeRequest, c *fakeContainer) {
			c.statMutation = func(stat containertypes.PathStat) containertypes.PathStat { stat.Mode = os.ModeSymlink; return stat }
		},
	} {
		t.Run(name, func(t *testing.T) {
			service, containers, _, request := workingTreeFixture(t, tarEntry{name: "workspace/a/", typeflag: tar.TypeDir}, tarEntry{name: "workspace/a/b", typeflag: tar.TypeReg, body: []byte("xx")}, tarEntry{name: "workspace/c", typeflag: tar.TypeReg, body: []byte("xx")})
			mutate(&request, containers)
			if _, err := service.StoppedWorkingTree(context.Background(), request.Generation.Source.ProviderResourceID, request); err == nil {
				t.Fatal("incomplete or changed roster returned success")
			}
		})
	}
	_, containers, _, request := workingTreeFixture(t, tarEntry{name: "workspace/a", typeflag: tar.TypeReg})
	if _, err := readStoppedWorkingTreeTar(context.Background(), bytes.NewReader(containers.archive), request, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("receipt budget was ignored: %v", err)
	}
}

func TestStoppedWorkingTreeSupportsLongUtf8PathsAndExactByteOrdering(t *testing.T) {
	entries := []tarEntry{}
	parts := []string{}
	for range 12 {
		parts = append(parts, strings.Repeat("a", 200))
		entries = append(entries, tarEntry{name: "workspace/" + strings.Join(parts, "/") + "/", typeflag: tar.TypeDir})
	}
	longPath := strings.Join(parts, "/") + "/report.txt"
	entries = append(entries, tarEntry{name: "workspace/" + longPath, typeflag: tar.TypeReg}, tarEntry{name: "workspace/😀", typeflag: tar.TypeReg}, tarEntry{name: "workspace/\uE000", typeflag: tar.TypeReg})
	service, _, _, request := workingTreeFixture(t, entries...)
	receipt, err := service.StoppedWorkingTree(context.Background(), request.Generation.Source.ProviderResourceID, request)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Entries[len(receipt.Entries)-2].Name != "\uE000" || receipt.Entries[len(receipt.Entries)-1].Name != "😀" {
		t.Fatal("roster used UTF-16 order instead of UTF-8 bytes")
	}
	binding := validBinding()
	binding.Selector = CaptureSelector{SemanticZoneRef: userFilesSemanticZoneRef, ZoneRelativePath: longPath}
	if got, err := service.validateBinding(binding.Source.ProviderResourceID, binding); err != nil || got != "/workspace/"+longPath {
		t.Fatalf("private long path was rejected: %q %v", got, err)
	}
}

func TestPrivateRootCaptureRejectsManagedRootsWithoutGrantingAnchorRoster(t *testing.T) {
	for _, relative := range []string{".ambit", ".ambit/config", ".ambit-skill-research", ".ambit-skill-research/data"} {
		binding := validBinding()
		binding.Selector = CaptureSelector{SemanticZoneRef: userFilesSemanticZoneRef, ZoneRelativePath: relative}
		containers := newFakeContainer(nil)
		objects := newFakeObjectStore()
		service := mustService(t, containers, objects, binding.Authority)
		if _, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("reserved private path admitted: %v", err)
		}
		if containers.inspectCalls != 0 || len(objects.objects) != 0 {
			t.Fatal("reserved selector reached an effect")
		}
	}
	binding := validBinding()
	binding.Selector.SemanticZoneRef = userFilesSemanticZoneRef
	containers := newFakeContainer([]byte("root file"))
	objects := newFakeObjectStore()
	service := mustService(t, containers, objects, binding.Authority)
	if _, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding); err != nil {
		t.Fatal(err)
	}
	if containers.copyPaths[0] != "/workspace/report.txt" {
		t.Fatal("private selector did not address the workspace root")
	}
	request := validStoppedDirectoryRosterRequest()
	request.Anchor.Selector.SemanticZoneRef = userFilesSemanticZoneRef
	request.Selector.SemanticZoneRef = userFilesSemanticZoneRef
	if _, err := service.StoppedDirectoryRoster(context.Background(), binding.Source.ProviderResourceID, request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("private selector expanded the public anchor roster")
	}
}

func TestStoppedWorkingTreeCancellationClosesBlockedArchive(t *testing.T) {
	service, containers, _, request := workingTreeFixture(t)
	blocked, closed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	containers.archiveReader = func(context.Context) io.ReadCloser {
		header := append(workingTreeTarHeader("workspace/", tar.TypeDir, 0), workingTreeTarHeader("workspace/large.bin", tar.TypeReg, 102<<20)...)
		return &blockingCaptureArchive{header: bytes.NewReader(header), blocked: blocked, closed: closed, closeOnce: &once}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	completed := make(chan error, 1)
	go func() {
		_, err := service.StoppedWorkingTree(ctx, request.Generation.Source.ProviderResourceID, request)
		completed <- err
	}()
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("root traversal did not reach body read")
	}
	cancel()
	select {
	case err := <-completed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation cause lost: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("root traversal did not cancel")
	}
}

func workingTreeTarHeader(name string, kind byte, size int64) []byte {
	var header bytes.Buffer
	if err := tar.NewWriter(&header).WriteHeader(&tar.Header{Name: name, Typeflag: kind, Size: size, Mode: 0o755, Format: tar.FormatUSTAR}); err != nil {
		panic(err)
	}
	return header.Bytes()
}
