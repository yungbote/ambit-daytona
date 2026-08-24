// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/storage"
	containertypes "github.com/docker/docker/api/types/container"
)

func TestCapturePersistsIntentBeforeOneStableStoppedContainerFile(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	containers := newFakeContainer([]byte("exact bytes"))
	containers.beforeCopy = func() error {
		if _, ok := objects.findSuffix("/intent.json"); !ok {
			return errors.New("intent was not persisted before Docker effect")
		}
		return nil
	}
	service := mustService(t, containers, objects)
	service.now = func() time.Time { return time.Date(2026, 8, 23, 12, 34, 56, 789, time.UTC) }

	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	if receipt.ByteLength != 11 || receipt.ProviderSHA256Digest != sha256Digest([]byte("exact bytes")) {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	if receipt.CapturedAt != "2026-08-23T12:34:56.000000789Z" {
		t.Fatalf("unexpected capture time: %s", receipt.CapturedAt)
	}
	if receipt.CaptureBinding != binding {
		t.Fatal("receipt did not preserve the exact binding")
	}
	if containers.copyCalls != 1 {
		t.Fatalf("expected one Docker archive read, got %d", containers.copyCalls)
	}
	if got := containers.copyPaths[0]; got != "/workspace/work/report.txt" {
		t.Fatalf("unexpected provider path %q", got)
	}
	if !strings.HasPrefix(receipt.ProviderResourceID, "daytona-working-copy-capture:v1:sha256:") {
		t.Fatalf("provider identity is not opaque: %q", receipt.ProviderResourceID)
	}
	for key := range objects.objects {
		if strings.Contains(key, binding.ProviderName) ||
			strings.Contains(key, binding.Source.TenantID) ||
			strings.Contains(key, containers.generation.ID) {
			t.Fatalf("private object key leaked source identity: %q", key)
		}
	}

	observation, err := service.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || observation.Status != "complete" || observation.Receipt == nil || *observation.Receipt != receipt {
		t.Fatalf("unexpected complete observation: %#v, %v", observation, err)
	}
	replayed, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || replayed != receipt {
		t.Fatalf("exact replay did not converge: %#v, %v", replayed, err)
	}
	if containers.copyCalls != 1 {
		t.Fatalf("complete replay performed another Docker effect: %d", containers.copyCalls)
	}
}

func TestCaptureAllowsZeroBytesAndOutputsZone(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	binding.Selector = CaptureSelector{
		SemanticZoneRef:  "ambit.workspace-zone/outputs@1",
		ZoneRelativePath: "nested/empty.pdf",
	}
	objects := newFakeObjectStore()
	containers := newFakeContainer(nil)
	containers.archive = tarArchive(tarEntry{name: "empty.pdf", typeflag: tar.TypeReg})
	service := mustService(t, containers, objects)

	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("zero-byte capture failed: %v", err)
	}
	if receipt.ByteLength != 0 || receipt.ProviderSHA256Digest != sha256Digest(nil) {
		t.Fatalf("unexpected zero-byte receipt: %#v", receipt)
	}
	if got := containers.copyPaths[0]; got != "/workspace/outputs/nested/empty.pdf" {
		t.Fatalf("unexpected outputs path %q", got)
	}
}

func TestCaptureRejectsUnadmittedSelectorsBeforeDockerOrStorage(t *testing.T) {
	t.Parallel()
	tests := []CaptureSelector{
		{SemanticZoneRef: "ambit.workspace-zone/cache@1", ZoneRelativePath: "x"},
		{SemanticZoneRef: "ambit.workspace-zone/work@1", ZoneRelativePath: "/etc/passwd"},
		{SemanticZoneRef: "ambit.workspace-zone/work@1", ZoneRelativePath: "../secret"},
		{SemanticZoneRef: "ambit.workspace-zone/work@1", ZoneRelativePath: "dir//file"},
		{SemanticZoneRef: "ambit.workspace-zone/work@1", ZoneRelativePath: "dir/./file"},
		{SemanticZoneRef: "ambit.workspace-zone/work@1", ZoneRelativePath: "dir\\file"},
		{SemanticZoneRef: "ambit.workspace-zone/work@1", ZoneRelativePath: "file/"},
		{SemanticZoneRef: "ambit.workspace-zone/work@1", ZoneRelativePath: "line\nbreak"},
	}
	for _, selector := range tests {
		selector := selector
		t.Run(selector.SemanticZoneRef+selector.ZoneRelativePath, func(t *testing.T) {
			binding := validBinding()
			binding.Selector = selector
			objects := newFakeObjectStore()
			containers := newFakeContainer([]byte("x"))
			service := mustService(t, containers, objects)
			_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected invalid request, got %v", err)
			}
			if containers.inspectCalls != 0 || containers.copyCalls != 0 || len(objects.objects) != 0 {
				t.Fatal("invalid selector reached a provider effect")
			}
		})
	}
}

func TestCaptureRejectsNonCanonicalBindingAndWrongSource(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*CaptureBinding){
		"fingerprint":   func(value *CaptureBinding) { value.RequestFingerprint = strings.Repeat("A", 64) },
		"authority":     func(value *CaptureBinding) { value.Authority.AuthorityRef = "wrong" },
		"source-id":     func(value *CaptureBinding) { value.Source.ProviderResourceID = "another-sandbox" },
		"profile":       func(value *CaptureBinding) { value.Source.ExpectedProfile = "managed-linux-vm" },
		"runtime":       func(value *CaptureBinding) { value.Source.ExpectedRuntimeKind = "virtual-machine" },
		"provider-name": func(value *CaptureBinding) { value.ProviderName = " padded " },
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			binding := validBinding()
			mutate(&binding)
			service := mustService(t, newFakeContainer([]byte("x")), newFakeObjectStore())
			_, err := service.Capture(context.Background(), "sandbox-1", binding)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected invalid request, got %v", err)
			}
		})
	}
}

func TestCaptureRequiresExactStoppedGenerationBeforeAnyArchiveRead(t *testing.T) {
	t.Parallel()
	states := map[string]*containertypes.State{
		"running":    {Status: containertypes.StateRunning, Running: true, Pid: 42},
		"paused":     {Status: containertypes.StatePaused, Running: true, Paused: true, Pid: 42},
		"restarting": {Status: containertypes.StateRestarting, Restarting: true},
		"dead":       {Status: containertypes.StateDead, Dead: true},
		"created":    {Status: containertypes.StateCreated},
	}
	for name, state := range states {
		state := state
		t.Run(name, func(t *testing.T) {
			binding := validBinding()
			containers := newFakeContainer([]byte("x"))
			containers.state = state
			objects := newFakeObjectStore()
			service := mustService(t, containers, objects)
			_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("expected stopped-state conflict, got %v", err)
			}
			if containers.copyCalls != 0 || len(objects.objects) != 0 {
				t.Fatal("non-stopped generation reached durable or archive effect")
			}
		})
	}
}

func TestCaptureRejectsGenerationAndDescriptorDrift(t *testing.T) {
	t.Parallel()
	t.Run("generation", func(t *testing.T) {
		binding := validBinding()
		containers := newFakeContainer([]byte("x"))
		containers.inspectMutations[3] = containerGeneration{ID: strings.Repeat("b", 64), Created: "2026-08-23T00:00:01Z"}
		service := mustService(t, containers, newFakeObjectStore())
		_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "generation changed") {
			t.Fatalf("expected generation conflict, got %v", err)
		}
	})

	t.Run("same-size-mtime", func(t *testing.T) {
		binding := validBinding()
		containers := newFakeContainer([]byte("x"))
		containers.afterStatMutation = func(stat containertypes.PathStat) containertypes.PathStat {
			if stat.Name == "report.txt" {
				stat.Mtime = stat.Mtime.Add(time.Second)
			}
			return stat
		}
		service := mustService(t, containers, newFakeObjectStore())
		_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "source path changed") {
			t.Fatalf("expected descriptor conflict, got %v", err)
		}
	})
}

func TestCaptureRejectsUnsafeArchiveEntryKindsAndShapes(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*fakeContainer){
		"symlink-entry": func(container *fakeContainer) {
			container.archive = tarArchive(tarEntry{name: "report.txt", typeflag: tar.TypeSymlink, linkname: "target"})
		},
		"hardlink-entry": func(container *fakeContainer) {
			container.archive = tarArchive(tarEntry{name: "report.txt", typeflag: tar.TypeLink, linkname: "target"})
		},
		"device-entry": func(container *fakeContainer) {
			container.archive = tarArchive(tarEntry{name: "report.txt", typeflag: tar.TypeChar})
		},
		"socket-mode": func(container *fakeContainer) {
			container.archive = tarArchive(tarEntry{name: "report.txt", typeflag: tar.TypeReg, mode: int64(os.ModeSocket | 0o600)})
		},
		"traversal-name": func(container *fakeContainer) {
			container.archive = tarArchive(tarEntry{name: "../report.txt", typeflag: tar.TypeReg, body: []byte("x")})
		},
		"path-mismatch": func(container *fakeContainer) {
			container.archive = tarArchive(tarEntry{name: "other.txt", typeflag: tar.TypeReg, body: []byte("x")})
		},
		"multiple-entries": func(container *fakeContainer) {
			container.archive = tarArchive(
				tarEntry{name: "report.txt", typeflag: tar.TypeReg, body: []byte("x")},
				tarEntry{name: "other.txt", typeflag: tar.TypeReg, body: []byte("x")},
			)
		},
		"header-size-drift": func(container *fakeContainer) {
			container.statSizeOverride = 2
		},
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			binding := validBinding()
			containers := newFakeContainer([]byte("x"))
			mutate(containers)
			service := mustService(t, containers, newFakeObjectStore())
			_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("expected archive conflict, got %v", err)
			}
		})
	}
}

func TestCaptureRejectsSymlinkParentAndOversizeSentinel(t *testing.T) {
	t.Parallel()
	t.Run("symlink-parent", func(t *testing.T) {
		binding := validBinding()
		containers := newFakeContainer([]byte("x"))
		containers.statMutation = func(stat containertypes.PathStat) containertypes.PathStat {
			if stat.Name == "work" {
				stat.Mode = os.ModeSymlink | 0o777
				stat.LinkTarget = "/other"
			}
			return stat
		}
		service := mustService(t, containers, newFakeObjectStore())
		_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("expected symlink conflict, got %v", err)
		}
	})

	t.Run("maximum-plus-one", func(t *testing.T) {
		binding := validBinding()
		containers := newFakeContainer(nil)
		containers.statSizeOverride = MaximumCaptureBytes + 1
		service := mustService(t, containers, newFakeObjectStore())
		_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
		if !errors.Is(err, ErrInvalidRequest) || containers.copyCalls != 0 {
			t.Fatalf("expected pre-copy size rejection, got %v", err)
		}
	})
}

func TestPartialIntentIsObservableAndExactReplayResumesSameGeneration(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	containers := newFakeContainer([]byte("recover me"))
	containers.copyErrors = []error{errors.New("transport cut")}
	service := mustService(t, containers, objects)

	_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected first copy failure, got %v", err)
	}
	observation, err := service.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || observation.Status != "partial" || observation.Identity == nil {
		t.Fatalf("expected partial observation, got %#v, %v", observation, err)
	}
	partialID := observation.Identity.ProviderResourceID

	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("exact replay failed: %v", err)
	}
	if receipt.ProviderResourceID != partialID || containers.copyCalls != 2 {
		t.Fatalf("replay replaced partial generation: %#v, calls=%d", receipt, containers.copyCalls)
	}
}

func TestLostResponseReconcilesWithoutReplacingContentOrReceipt(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	containers := newFakeContainer([]byte("durable"))
	service := mustService(t, containers, objects)
	objects.failAfterStoreSuffix = "/content.bin"

	_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err == nil {
		t.Fatal("expected simulated lost content response")
	}
	partial, err := service.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || partial.Status != "partial" {
		t.Fatalf("content-only cut was not partial: %#v, %v", partial, err)
	}
	objects.failAfterStoreSuffix = ""
	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("content replay did not reconcile: %v", err)
	}
	if containers.copyCalls != 1 {
		t.Fatalf("content replay blindly recaptured source: %d", containers.copyCalls)
	}

	// A response lost after receipt publication is reconciled directly from the
	// immutable receipt and does not inspect or copy the container again.
	other := validBinding()
	other.ProviderName = "capture-receipt-cut"
	other.RequestFingerprint = strings.Repeat("b", 64)
	objects.failAfterStoreSuffix = "/receipt.json"
	_, err = service.Capture(context.Background(), other.Source.ProviderResourceID, other)
	if err == nil {
		t.Fatal("expected simulated lost receipt response")
	}
	copyCalls := containers.copyCalls
	objects.failAfterStoreSuffix = ""
	reconciled, err := service.Capture(context.Background(), other.Source.ProviderResourceID, other)
	if err != nil || reconciled.ByteLength != int64(len("durable")) {
		t.Fatalf("receipt replay did not reconcile: %#v, %v", reconciled, err)
	}
	if containers.copyCalls != copyCalls {
		t.Fatal("completed replay touched Docker")
	}
	_ = receipt
}

func TestConflictingReplayCannotReplaceExistingGeneration(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	containers := newFakeContainer([]byte("x"))
	service := mustService(t, containers, objects)
	if _, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding); err != nil {
		t.Fatalf("seed capture failed: %v", err)
	}
	conflicting := binding
	conflicting.Selector.ZoneRelativePath = "other.txt"
	_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, conflicting)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected binding conflict, got %v", err)
	}
	if containers.copyCalls != 1 {
		t.Fatal("conflicting replay reached Docker")
	}
}

func TestReadExistsAndDeleteRequireExactIdentity(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	service := mustService(t, newFakeContainer([]byte("readable")), objects)
	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	exists, err := service.Exists(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity)
	if err != nil || !exists {
		t.Fatalf("exact identity should exist: %v, %v", exists, err)
	}

	read := CaptureReadRequest{
		CaptureIdentity:    receipt.CaptureIdentity,
		ExpectedByteLength: receipt.ByteLength,
		MaximumBytes:       MaximumCaptureBytes,
	}
	data, err := service.Read(context.Background(), binding.Source.ProviderResourceID, read)
	if err != nil || string(data) != "readable" {
		t.Fatalf("exact read failed: %q, %v", data, err)
	}
	read.ExpectedByteLength++
	if _, err := service.Read(context.Background(), binding.Source.ProviderResourceID, read); !errors.Is(err, ErrConflict) {
		t.Fatalf("length drift was not rejected: %v", err)
	}
	read.ExpectedByteLength = receipt.ByteLength
	read.MaximumBytes = receipt.ByteLength - 1
	if _, err := service.Read(context.Background(), binding.Source.ProviderResourceID, read); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("maximum bound was not rejected: %v", err)
	}

	wrong := receipt.CaptureIdentity
	wrong.ProviderResourceID = "daytona-working-copy-capture:v1:sha256:" + strings.Repeat("f", 64)
	if _, err := service.Exists(context.Background(), binding.Source.ProviderResourceID, wrong); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong identity existence was not rejected: %v", err)
	}
	if err := service.Delete(context.Background(), binding.Source.ProviderResourceID, wrong); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong identity deletion was not rejected: %v", err)
	}
	if err := service.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	exists, err = service.Exists(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity)
	if err != nil || exists {
		t.Fatalf("deleted capture still exists: %v, %v", exists, err)
	}
	observation, err := service.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || observation.Status != "absent" || observation.Binding == nil || *observation.Binding != binding {
		t.Fatalf("deleted capture was not absent: %#v, %v", observation, err)
	}
	if err := service.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity); err != nil {
		t.Fatalf("idempotent exact delete failed: %v", err)
	}
}

func TestInterruptedDeleteRemainsPartialAndResumable(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	containers := newFakeContainer([]byte("restore"))
	service := mustService(t, containers, objects)
	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	objects.failDeleteSuffix = "/content.bin"
	if err := service.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity); err == nil {
		t.Fatal("expected interrupted deletion")
	}
	observation, err := service.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || observation.Status != "partial" || observation.Identity == nil {
		t.Fatalf("interrupted deletion was not partial: %#v, %v", observation, err)
	}
	objects.failDeleteSuffix = ""
	replayed, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || replayed.ProviderResourceID != receipt.ProviderResourceID {
		t.Fatalf("partial delete did not resume same generation: %#v, %v", replayed, err)
	}
	if containers.copyCalls != 1 {
		t.Fatal("resuming staged content unnecessarily recaptured source")
	}
}

func TestConcurrentExactCaptureSerializesToOneProviderEffect(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	containers := newFakeContainer([]byte("once"))
	service := mustService(t, containers, objects)
	const count = 16
	receipts := make(chan CaptureReceipt, count)
	errorsChannel := make(chan error, count)
	var group sync.WaitGroup
	for range count {
		group.Add(1)
		go func() {
			defer group.Done()
			receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
			receipts <- receipt
			errorsChannel <- err
		}()
	}
	group.Wait()
	close(receipts)
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent capture failed: %v", err)
		}
	}
	var expected *CaptureReceipt
	for receipt := range receipts {
		if expected == nil {
			copy := receipt
			expected = &copy
		} else if receipt != *expected {
			t.Fatalf("concurrent exact captures diverged: %#v != %#v", receipt, *expected)
		}
	}
	if containers.copyCalls != 1 {
		t.Fatalf("expected one provider effect, got %d", containers.copyCalls)
	}
}

func TestStoredContentDriftFailsClosed(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	service := mustService(t, newFakeContainer([]byte("original")), objects)
	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	key, ok := objects.findSuffix("/content.bin")
	if !ok {
		t.Fatal("content object missing")
	}
	object := objects.objects[key]
	object.data = []byte("tampered")
	objects.objects[key] = object
	request := CaptureReadRequest{
		CaptureIdentity:    receipt.CaptureIdentity,
		ExpectedByteLength: receipt.ByteLength,
		MaximumBytes:       MaximumCaptureBytes,
	}
	if _, err := service.Read(context.Background(), binding.Source.ProviderResourceID, request); !errors.Is(err, ErrConflict) {
		t.Fatalf("tampered content was not rejected: %v", err)
	}
}

type fakeContainer struct {
	mu                sync.Mutex
	generation        containerGeneration
	state             *containertypes.State
	content           []byte
	archive           []byte
	statSizeOverride  int64
	inspectCalls      int
	copyCalls         int
	statCalls         int
	copyPaths         []string
	inspectMutations  map[int]containerGeneration
	statMutation      func(containertypes.PathStat) containertypes.PathStat
	afterStatMutation func(containertypes.PathStat) containertypes.PathStat
	copyErrors        []error
	beforeCopy        func() error
}

func newFakeContainer(content []byte) *fakeContainer {
	copy := append([]byte(nil), content...)
	return &fakeContainer{
		generation:       containerGeneration{ID: strings.Repeat("a", 64), Created: "2026-08-23T00:00:00Z"},
		state:            &containertypes.State{Status: containertypes.StateExited},
		content:          copy,
		archive:          tarArchive(tarEntry{name: "report.txt", typeflag: tar.TypeReg, body: copy}),
		inspectMutations: make(map[int]containerGeneration),
	}
}

func (f *fakeContainer) ContainerInspect(
	_ context.Context,
	_ string,
) (containertypes.InspectResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inspectCalls++
	generation := f.generation
	if mutated, ok := f.inspectMutations[f.inspectCalls]; ok {
		generation = mutated
	}
	state := *f.state
	return containertypes.InspectResponse{ContainerJSONBase: &containertypes.ContainerJSONBase{
		ID: generation.ID, Created: generation.Created, State: &state,
	}}, nil
}

func (f *fakeContainer) ContainerStatPath(
	_ context.Context,
	_ string,
	containerPath string,
) (containertypes.PathStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statCalls++
	name := pathBase(containerPath)
	isFile := strings.Contains(name, ".")
	mode := os.FileMode(0o755 | os.ModeDir)
	size := int64(0)
	if isFile {
		mode = 0o600
		size = int64(len(f.content))
		if f.statSizeOverride != 0 {
			size = f.statSizeOverride
		}
	}
	stat := containertypes.PathStat{
		Name:  name,
		Size:  size,
		Mode:  mode,
		Mtime: time.Date(2026, 8, 23, 1, 2, 3, 0, time.UTC),
	}
	if f.statMutation != nil {
		stat = f.statMutation(stat)
	}
	// A full chain has three stats for report.txt and four for nested paths.
	// Mutate only the second chain after the copy has occurred.
	if f.copyCalls > 0 && f.afterStatMutation != nil {
		stat = f.afterStatMutation(stat)
	}
	return stat, nil
}

func (f *fakeContainer) CopyFromContainer(
	_ context.Context,
	_ string,
	containerPath string,
) (io.ReadCloser, containertypes.PathStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.copyCalls++
	f.copyPaths = append(f.copyPaths, containerPath)
	if f.beforeCopy != nil {
		if err := f.beforeCopy(); err != nil {
			return nil, containertypes.PathStat{}, err
		}
	}
	if len(f.copyErrors) > 0 {
		err := f.copyErrors[0]
		f.copyErrors = f.copyErrors[1:]
		return nil, containertypes.PathStat{}, err
	}
	size := int64(len(f.content))
	if f.statSizeOverride != 0 {
		size = f.statSizeOverride
	}
	stat := containertypes.PathStat{
		Name:  pathBase(containerPath),
		Size:  size,
		Mode:  0o600,
		Mtime: time.Date(2026, 8, 23, 1, 2, 3, 0, time.UTC),
	}
	return io.NopCloser(bytes.NewReader(f.archive)), stat, nil
}

type fakeStoredObject struct {
	data     []byte
	metadata map[string]string
}

type fakeObjectStore struct {
	mu                   sync.Mutex
	objects              map[string]fakeStoredObject
	failAfterStoreSuffix string
	failDeleteSuffix     string
}

func newFakeObjectStore() *fakeObjectStore {
	return &fakeObjectStore{objects: make(map[string]fakeStoredObject)}
}

func (f *fakeObjectStore) CreatePrivateObject(
	_ context.Context,
	key string,
	data []byte,
	_ string,
	metadata map[string]string,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.objects[key]; exists {
		return storage.ErrPrivateObjectAlreadyExists
	}
	f.objects[key] = fakeStoredObject{data: append([]byte(nil), data...), metadata: lowerMetadata(metadata)}
	if f.failAfterStoreSuffix != "" && strings.HasSuffix(key, f.failAfterStoreSuffix) {
		return errors.New("simulated lost object-store response")
	}
	return nil
}

func (f *fakeObjectStore) GetPrivateObject(
	_ context.Context,
	key string,
	maximumBytes int64,
) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	object, exists := f.objects[key]
	if !exists {
		return nil, storage.ErrPrivateObjectNotFound
	}
	if int64(len(object.data)) > maximumBytes {
		return nil, storage.ErrPrivateObjectTooLarge
	}
	return append([]byte(nil), object.data...), nil
}

func (f *fakeObjectStore) StatPrivateObject(
	_ context.Context,
	key string,
) (storage.PrivateObjectInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	object, exists := f.objects[key]
	if !exists {
		return storage.PrivateObjectInfo{}, storage.ErrPrivateObjectNotFound
	}
	return storage.PrivateObjectInfo{
		Size:         int64(len(object.data)),
		UserMetadata: lowerMetadata(object.metadata),
	}, nil
}

func (f *fakeObjectStore) DeletePrivateObject(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDeleteSuffix != "" && strings.HasSuffix(key, f.failDeleteSuffix) {
		return errors.New("simulated delete cut")
	}
	delete(f.objects, key)
	return nil
}

func (f *fakeObjectStore) findSuffix(suffix string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for key := range f.objects {
		if strings.HasSuffix(key, suffix) {
			return key, true
		}
	}
	return "", false
}

type tarEntry struct {
	name     string
	typeflag byte
	linkname string
	mode     int64
	body     []byte
}

func tarArchive(entries ...tarEntry) []byte {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range entries {
		mode := entry.mode
		if mode == 0 {
			mode = 0o600
		}
		header := &tar.Header{
			Name:     entry.name,
			Typeflag: entry.typeflag,
			Linkname: entry.linkname,
			Mode:     mode,
			Size:     int64(len(entry.body)),
			ModTime:  time.Date(2026, 8, 23, 1, 2, 3, 0, time.UTC),
		}
		if entry.typeflag != tar.TypeReg && entry.typeflag != tar.TypeRegA {
			header.Size = 0
		}
		if err := writer.WriteHeader(header); err != nil {
			panic(fmt.Sprintf("write test tar header: %v", err))
		}
		if len(entry.body) > 0 && header.Size > 0 {
			if _, err := writer.Write(entry.body); err != nil {
				panic(fmt.Sprintf("write test tar body: %v", err))
			}
		}
	}
	if err := writer.Close(); err != nil {
		panic(fmt.Sprintf("close test tar: %v", err))
	}
	return buffer.Bytes()
}

func validBinding() CaptureBinding {
	protocolDigest := "sha256:" + strings.Repeat("7", 64)
	helperDigest := "sha256:" + strings.Repeat("8", 64)
	authority := CaptureAuthority{
		RoleRef:  captureRoleRef,
		Protocol: CaptureAuthorityArtifact{Ref: captureProtocolRef, Digest: protocolDigest},
		Helper: CaptureAuthorityArtifact{
			Ref: "runtime-component-artifact:" + helperDigest, Digest: helperDigest,
		},
	}
	authority.AuthorityRef = captureAuthorityRef(authority)
	return CaptureBinding{
		ProviderName:       "ambit-private-working-copy-capture",
		RequestFingerprint: strings.Repeat("a", 64),
		Authority:          authority,
		Source: SourceAddress{
			ProviderResourceID:  "sandbox-1",
			WorkspaceID:         "workspace-1",
			TenantID:            "tenant-1",
			UserID:              "user-1",
			ExpectedProfile:     "managed-container",
			ExpectedRuntimeKind: "container",
		},
		Selector: CaptureSelector{
			SemanticZoneRef:  "ambit.workspace-zone/work@1",
			ZoneRelativePath: "report.txt",
		},
	}
}

func mustService(t *testing.T, containers ContainerClient, objects storage.PrivateObjectStorageClient) *Service {
	t.Helper()
	service, err := NewService(containers, objects)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

func pathBase(value string) string {
	parts := strings.Split(strings.TrimSuffix(value, "/"), "/")
	return parts[len(parts)-1]
}
