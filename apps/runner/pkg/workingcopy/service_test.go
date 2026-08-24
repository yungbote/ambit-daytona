// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
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
	service := mustService(t, containers, objects, binding.Authority)
	service.now = func() time.Time { return time.Date(2026, 8, 23, 12, 34, 56, 789, time.UTC) }

	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	if receipt.TotalByteLength != 11 || receipt.ProviderSHA256Digest != sha256Digest([]byte("exact bytes")) {
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
	if len(containers.copyContainerIDs) != 1 || containers.copyContainerIDs[0] != containers.generation.ID {
		t.Fatalf("archive read did not address the immutable terminal container ID: %#v", containers.copyContainerIDs)
	}
	for _, containerID := range containers.statContainerIDs {
		if containerID != containers.generation.ID {
			t.Fatalf("source stat addressed reusable sandbox name instead of terminal container ID: %q", containerID)
		}
	}
	if got := containers.copyPaths[0]; got != "/workspace/work/report.txt" {
		t.Fatalf("unexpected provider path %q", got)
	}
	if !strings.HasPrefix(receipt.ProviderResourceID, "daytona-working-copy-capture:v2:sha256:") {
		t.Fatalf("provider identity is not opaque: %q", receipt.ProviderResourceID)
	}
	for key := range objects.objects {
		if strings.Contains(key, binding.ProviderName) ||
			strings.Contains(key, binding.Owner.TenantID) ||
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
	service := mustService(t, containers, objects, binding.Authority)

	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("zero-byte capture failed: %v", err)
	}
	if receipt.TotalByteLength != 0 || receipt.ProviderSHA256Digest != sha256Digest(nil) {
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
			service := mustService(t, containers, objects, binding.Authority)
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
		"fingerprint":  func(value *CaptureBinding) { value.RequestFingerprint = strings.Repeat("A", 64) },
		"authority":    func(value *CaptureBinding) { value.Authority.AuthorityRef = "wrong" },
		"source-id":    func(value *CaptureBinding) { value.Source.ProviderResourceID = "another-sandbox" },
		"profile":      func(value *CaptureBinding) { value.Source.ExpectedProfile = "managed-linux-vm" },
		"runtime":      func(value *CaptureBinding) { value.Source.ExpectedRuntimeKind = "virtual-machine" },
		"tenant-owner": func(value *CaptureBinding) { value.Owner.TenantID = "tenant-1" },
		"run-owner": func(value *CaptureBinding) {
			value.Owner.RunID = "A" + value.Owner.RunID[1:]
		},
		"provider-name": func(value *CaptureBinding) { value.ProviderName = " padded " },
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			binding := validBinding()
			admittedAuthority := binding.Authority
			mutate(&binding)
			service := mustService(t, newFakeContainer([]byte("x")), newFakeObjectStore(), admittedAuthority)
			_, err := service.Capture(context.Background(), "sandbox-1", binding)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected invalid request, got %v", err)
			}
		})
	}
}

func TestCaptureRejectsSelfConsistentAuthorityOutsideAdmittedLineage(t *testing.T) {
	t.Parallel()
	admitted := validBinding()
	requested := admitted
	requested.Authority.LineageRef = "ambit.core-document-lineage:v5:sha256:" + strings.Repeat("9", 64)
	requested.Authority.AuthorityRef = captureAuthorityRef(requested.Authority)
	containers := newFakeContainer([]byte("must not be read"))
	objects := newFakeObjectStore()
	service := mustService(t, containers, objects, admitted.Authority)

	_, err := service.Capture(context.Background(), requested.Source.ProviderResourceID, requested)
	if !errors.Is(err, ErrInvalidRequest) || !strings.Contains(err.Error(), "admitted current lineage") {
		t.Fatalf("self-consistent but unadmitted authority was not rejected: %v", err)
	}
	if containers.inspectCalls != 0 || containers.statCalls != 0 || containers.copyCalls != 0 || len(objects.objects) != 0 {
		t.Fatal("unadmitted authority reached a provider effect")
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
			service := mustService(t, containers, objects, binding.Authority)
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

func TestCaptureReplayFreshlyReprovesStopReceiptWhileDurableObservationRemainsReadable(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	containers := newFakeContainer([]byte("immutable after capture"))
	service := mustService(t, containers, newFakeObjectStore(), binding.Authority)
	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("seed capture: %v", err)
	}
	copyCalls := containers.copyCalls
	containers.state = &containertypes.State{Status: containertypes.StateRunning, Running: true, Pid: 42}
	if _, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding); !errors.Is(err, ErrConflict) {
		t.Fatalf("complete replay trusted historical stop authority: %v", err)
	}
	if containers.copyCalls != copyCalls {
		t.Fatal("failed fresh stop reproof reached another archive read")
	}
	observation, err := service.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || observation.Status != "complete" || observation.Receipt == nil || *observation.Receipt != receipt {
		t.Fatalf("durable capture became unreadable after source restart: %#v, %v", observation, err)
	}
}

func TestCaptureRejectsGenerationAndDescriptorDrift(t *testing.T) {
	t.Parallel()
	t.Run("generation", func(t *testing.T) {
		binding := validBinding()
		containers := newFakeContainer([]byte("x"))
		mutated := containers.generation
		mutated.ID = strings.Repeat("b", 64)
		mutated.Created = "2026-08-23T00:00:01Z"
		containers.inspectMutations[3] = mutated
		service := mustService(t, containers, newFakeObjectStore(), binding.Authority)
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
		service := mustService(t, containers, newFakeObjectStore(), binding.Authority)
		_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "source path changed") {
			t.Fatalf("expected descriptor conflict, got %v", err)
		}
	})
}

func TestCaptureRejectsLaterExecutionEpochWithSameContainerIdentity(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	containers := newFakeContainer([]byte("x"))
	later := containers.generation
	later.StartedAt = "2026-08-23T00:03:00Z"
	later.FinishedAt = "2026-08-23T00:04:00Z"
	later.RestartCount++
	containers.inspectMutations[3] = later
	service := mustService(t, containers, newFakeObjectStore(), binding.Authority)

	_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "generation changed") {
		t.Fatalf("later execution epoch was not rejected: %v", err)
	}
	if containers.generation.ID != later.ID || containers.generation.Created != later.Created {
		t.Fatal("test no longer holds container ID and Created constant")
	}
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
			service := mustService(t, containers, newFakeObjectStore(), binding.Authority)
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
		service := mustService(t, containers, newFakeObjectStore(), binding.Authority)
		_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("expected symlink conflict, got %v", err)
		}
	})

	t.Run("maximum-plus-one", func(t *testing.T) {
		binding := validBinding()
		containers := newFakeContainer(nil)
		containers.statSizeOverride = MaximumCaptureBytes + 1
		service := mustService(t, containers, newFakeObjectStore(), binding.Authority)
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
	service := mustService(t, containers, objects, binding.Authority)

	_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrConflict) {
		t.Fatalf("expected transient copy failure to be unavailable, got %v", err)
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

func TestLostCreateResponsesReconcileWithoutReplacingDurableObjects(t *testing.T) {
	t.Parallel()
	for _, suffix := range []string{"/intent.json", "/content.bin", "/receipt.json"} {
		suffix := suffix
		t.Run(suffix, func(t *testing.T) {
			binding := validBinding()
			binding.ProviderName += "-lost-create" + strings.ReplaceAll(suffix, "/", "-")
			binding.RequestFingerprint = hashHex(binding.ProviderName)
			objects := newFakeObjectStore()
			containers := newFakeContainer([]byte("durable"))
			service := mustService(t, containers, objects, binding.Authority)
			objects.failAfterStoreSuffix = suffix

			receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
			if err != nil {
				t.Fatalf("lost %s create response was not reconciled in-call: %v", suffix, err)
			}
			observation, err := service.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
			if err != nil || observation.Status != "complete" || observation.Receipt == nil || *observation.Receipt != receipt {
				t.Fatalf("reconciled publication was not complete: %#v, %v", observation, err)
			}
			objects.failAfterStoreSuffix = ""
			inspectCalls := containers.inspectCalls
			replayed, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
			if err != nil || replayed != receipt {
				t.Fatalf("exact replay diverged after lost response: %#v, %v", replayed, err)
			}
			if containers.copyCalls != 1 || containers.inspectCalls != inspectCalls+1 {
				t.Fatalf("completed replay did not perform exactly one fresh stop reproof: copies=%d inspect=%d->%d", containers.copyCalls, inspectCalls, containers.inspectCalls)
			}
		})
	}
}

func TestConflictingReplayCannotReplaceExistingGeneration(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	containers := newFakeContainer([]byte("x"))
	service := mustService(t, containers, objects, binding.Authority)
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
	service := mustService(t, newFakeContainer([]byte("readable")), objects, binding.Authority)
	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	exists, err := service.Exists(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity)
	if err != nil || !exists.Exists || exists.Status != "complete" || exists.Receipt == nil || *exists.Receipt != receipt {
		t.Fatalf("exact identity should have a complete receipt: %#v, %v", exists, err)
	}

	read := CaptureReadRequest{
		CaptureIdentity:              receipt.CaptureIdentity,
		ExpectedTotalByteLength:      receipt.TotalByteLength,
		ExpectedProviderSHA256Digest: receipt.ProviderSHA256Digest,
		Offset:                       0,
		MaximumBytes:                 MaximumReadBytes,
	}
	response, err := service.Read(context.Background(), binding.Source.ProviderResourceID, read)
	data, decodeErr := base64.StdEncoding.DecodeString(response.BytesBase64)
	if err != nil || decodeErr != nil || string(data) != "readable" ||
		response.ByteLength != int64(len("readable")) || !response.EOF || response.Offset != 0 ||
		response.TotalByteLength != receipt.TotalByteLength ||
		response.ProviderSHA256Digest != receipt.ProviderSHA256Digest {
		t.Fatalf("exact read failed: %#v, decoded=%q, decode=%v, read=%v", response, data, decodeErr, err)
	}
	read.ExpectedTotalByteLength++
	if _, err := service.Read(context.Background(), binding.Source.ProviderResourceID, read); !errors.Is(err, ErrConflict) {
		t.Fatalf("length drift was not rejected: %v", err)
	}
	read.ExpectedTotalByteLength = receipt.TotalByteLength
	read.ExpectedProviderSHA256Digest = "sha256:" + strings.Repeat("f", 64)
	if _, err := service.Read(context.Background(), binding.Source.ProviderResourceID, read); !errors.Is(err, ErrConflict) {
		t.Fatalf("digest drift was not rejected: %v", err)
	}
	read.ExpectedProviderSHA256Digest = receipt.ProviderSHA256Digest
	read.MaximumBytes = MaximumReadBytes + 1
	if _, err := service.Read(context.Background(), binding.Source.ProviderResourceID, read); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("maximum bound was not rejected: %v", err)
	}

	wrong := receipt.CaptureIdentity
	wrong.ProviderResourceID = "daytona-working-copy-capture:v2:sha256:" + strings.Repeat("f", 64)
	if _, err := service.Exists(context.Background(), binding.Source.ProviderResourceID, wrong); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong identity existence was not rejected: %v", err)
	}
	if _, err := service.Delete(context.Background(), binding.Source.ProviderResourceID, wrong); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong identity deletion was not rejected: %v", err)
	}
	deleted, err := service.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity)
	if err != nil || deleted.CaptureIdentity != receipt.CaptureIdentity || deleted.Outcome != "deleted" {
		t.Fatalf("delete failed: %#v, %v", deleted, err)
	}
	exists, err = service.Exists(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity)
	if err != nil || exists.Exists || exists.Status != "absent" || exists.Receipt != nil {
		t.Fatalf("deleted capture still exists: %#v, %v", exists, err)
	}
	observation, err := service.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || observation.Status != "absent" || observation.Binding == nil || *observation.Binding != binding {
		t.Fatalf("deleted capture was not absent: %#v, %v", observation, err)
	}
	alreadyAbsent, err := service.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity)
	if err != nil || alreadyAbsent.CaptureIdentity != receipt.CaptureIdentity || alreadyAbsent.Outcome != "already_absent" {
		t.Fatalf("idempotent exact delete failed: %#v, %v", alreadyAbsent, err)
	}
}

func TestInterruptedDeleteRemainsPartialAndResumable(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	containers := newFakeContainer([]byte("restore"))
	service := mustService(t, containers, objects, binding.Authority)
	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	objects.failDeleteSuffix = "/content.bin"
	if _, err := service.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity); err == nil {
		t.Fatal("expected interrupted deletion")
	}
	observation, err := service.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || observation.Status != "partial" || observation.Identity == nil {
		t.Fatalf("interrupted deletion was not partial: %#v, %v", observation, err)
	}
	objects.failDeleteSuffix = ""
	if _, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding); !errors.Is(err, ErrConflict) {
		t.Fatalf("capture recreated a tombstoned generation: %v", err)
	}
	if containers.copyCalls != 1 {
		t.Fatal("tombstone cleanup unnecessarily recaptured source")
	}
	observation, err = service.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || observation.Status != "absent" {
		t.Fatalf("tombstone did not converge after retry: %#v, %v", observation, err)
	}
}

func TestConcurrentExactCaptureSerializesToOneProviderEffect(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	containers := newFakeContainer([]byte("once"))
	service := mustService(t, containers, objects, binding.Authority)
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
	service := mustService(t, newFakeContainer([]byte("original")), objects, binding.Authority)
	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	key, ok := objects.findSuffix("/content.bin")
	if !ok {
		t.Fatal("content object missing")
	}
	objects.mu.Lock()
	object := objects.objects[key]
	object.data = []byte("tampered")
	object.contentSHA256 = sha256Digest(object.data)
	object.metadata["sha256"] = object.contentSHA256
	objects.objects[key] = object
	objects.mu.Unlock()
	if int64(len(object.data)) != receipt.TotalByteLength {
		t.Fatal("test corruption must preserve the receipt length")
	}
	if _, err := service.Observe(context.Background(), binding.Source.ProviderResourceID, binding); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-length content and metadata corruption was not rejected by Observe: %v", err)
	}
	if _, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-length content and metadata corruption was not rejected by replay: %v", err)
	}
	request := CaptureReadRequest{
		CaptureIdentity:              receipt.CaptureIdentity,
		ExpectedTotalByteLength:      receipt.TotalByteLength,
		ExpectedProviderSHA256Digest: receipt.ProviderSHA256Digest,
		MaximumBytes:                 MaximumReadBytes,
	}
	if _, err := service.Read(context.Background(), binding.Source.ProviderResourceID, request); !errors.Is(err, ErrConflict) {
		t.Fatalf("tampered content was not rejected: %v", err)
	}
}

func TestDurableJSONReadersRejectEquivalentNonCanonicalBytes(t *testing.T) {
	t.Parallel()
	for _, durableKind := range []string{"intent", "receipt", "deletion"} {
		durableKind := durableKind
		t.Run(durableKind, func(t *testing.T) {
			binding := validBinding()
			binding.ProviderName += "-noncanonical-" + durableKind
			binding.RequestFingerprint = hashHex(binding.ProviderName)
			objects := newFakeObjectStore()
			service := mustService(t, newFakeContainer([]byte("canonical custody")), objects, binding.Authority)
			receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
			if err != nil {
				t.Fatalf("capture failed: %v", err)
			}
			if durableKind == "deletion" {
				if _, err := service.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity); err != nil {
					t.Fatalf("seed deletion failed: %v", err)
				}
			}
			keys := keysForIdentity(receipt.CaptureIdentity)
			key := map[string]string{
				"intent":   keys.intent,
				"receipt":  keys.receipt,
				"deletion": keys.deletion,
			}[durableKind]
			objects.mu.Lock()
			object := objects.objects[key]
			var equivalent any
			if err := json.Unmarshal(object.data, &equivalent); err != nil {
				objects.mu.Unlock()
				t.Fatalf("decode fixture: %v", err)
			}
			reformatted, err := json.MarshalIndent(equivalent, "", "  ")
			if err != nil {
				objects.mu.Unlock()
				t.Fatalf("reformat fixture: %v", err)
			}
			object.data = reformatted
			object.contentSHA256 = sha256Digest(reformatted)
			objects.objects[key] = object
			objects.mu.Unlock()

			_, readErr := service.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
			if !errors.Is(readErr, ErrConflict) {
				t.Fatalf("equivalent non-canonical %s bytes were admitted: %v", durableKind, readErr)
			}
		})
	}
}

func TestReadUsesExactBoundedRangesAndReportsOffsetsAndEOF(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	content := make([]byte, MaximumReadBytes+37)
	for index := range content {
		content[index] = byte(index % 251)
	}
	objects := newFakeObjectStore()
	service := mustService(t, newFakeContainer(content), objects, binding.Authority)
	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	objects.mu.Lock()
	objects.rangeReads = nil
	objects.fullContentReads = 0
	objects.mu.Unlock()

	request := CaptureReadRequest{
		CaptureIdentity:              receipt.CaptureIdentity,
		ExpectedTotalByteLength:      receipt.TotalByteLength,
		ExpectedProviderSHA256Digest: receipt.ProviderSHA256Digest,
		Offset:                       0,
		MaximumBytes:                 MaximumReadBytes,
	}
	first, err := service.Read(context.Background(), binding.Source.ProviderResourceID, request)
	firstBytes, decodeErr := base64.StdEncoding.DecodeString(first.BytesBase64)
	if err != nil || decodeErr != nil || first.Offset != 0 || first.ByteLength != MaximumReadBytes || first.EOF ||
		!bytes.Equal(firstBytes, content[:MaximumReadBytes]) {
		t.Fatalf("first range mismatch: %#v, decode=%v, read=%v", first, decodeErr, err)
	}

	request.Offset = MaximumReadBytes
	second, err := service.Read(context.Background(), binding.Source.ProviderResourceID, request)
	secondBytes, decodeErr := base64.StdEncoding.DecodeString(second.BytesBase64)
	if err != nil || decodeErr != nil || second.Offset != MaximumReadBytes || second.ByteLength != 37 || !second.EOF ||
		!bytes.Equal(secondBytes, content[MaximumReadBytes:]) {
		t.Fatalf("terminal range mismatch: %#v, decode=%v, read=%v", second, decodeErr, err)
	}

	request.Offset = receipt.TotalByteLength
	atEOF, err := service.Read(context.Background(), binding.Source.ProviderResourceID, request)
	if err != nil || atEOF.Offset != receipt.TotalByteLength || atEOF.ByteLength != 0 || !atEOF.EOF || atEOF.BytesBase64 != "" {
		t.Fatalf("exact-EOF read mismatch: %#v, %v", atEOF, err)
	}

	invalid := []CaptureReadRequest{request, request, request, request}
	invalid[0].Offset = -1
	invalid[1].Offset = receipt.TotalByteLength + 1
	invalid[2].Offset = 0
	invalid[2].MaximumBytes = 0
	invalid[3].Offset = 0
	invalid[3].MaximumBytes = MaximumReadBytes + 1
	for index, candidate := range invalid {
		if _, err := service.Read(context.Background(), binding.Source.ProviderResourceID, candidate); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid bounds case %d was not rejected: %v", index, err)
		}
	}

	objects.mu.Lock()
	ranges := append([]fakeRangeRead(nil), objects.rangeReads...)
	fullContentReads := objects.fullContentReads
	objects.mu.Unlock()
	if fullContentReads != 0 {
		t.Fatalf("completed ranged reads loaded the full content object %d times", fullContentReads)
	}
	if len(ranges) != 2 || ranges[0].offset != 0 || ranges[0].maximumBytes != MaximumReadBytes ||
		ranges[1].offset != MaximumReadBytes || ranges[1].maximumBytes != 37 {
		t.Fatalf("storage did not receive the exact two bounded ranges: %#v", ranges)
	}
}

func TestDeleteReconcilesLostResponsesForEveryOperationalObject(t *testing.T) {
	t.Parallel()
	for _, suffix := range []string{"/receipt.json", "/content.bin", "/intent.json"} {
		suffix := suffix
		t.Run(suffix, func(t *testing.T) {
			binding := validBinding()
			binding.ProviderName += strings.ReplaceAll(suffix, "/", "-")
			binding.RequestFingerprint = hashHex(binding.ProviderName)
			objects := newFakeObjectStore()
			service := mustService(t, newFakeContainer([]byte("delete me")), objects, binding.Authority)
			receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
			if err != nil {
				t.Fatalf("capture failed: %v", err)
			}
			objects.failAfterDeleteSuffix = suffix
			deleted, err := service.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity)
			if err != nil || deleted.CaptureIdentity != receipt.CaptureIdentity || deleted.Outcome != "deleted" {
				t.Fatalf("lost %s delete response did not reconcile: %#v, %v", suffix, deleted, err)
			}
			keys := keysForIdentity(receipt.CaptureIdentity)
			objects.mu.Lock()
			_, intentPresent := objects.objects[keys.intent]
			_, contentPresent := objects.objects[keys.content]
			_, receiptPresent := objects.objects[keys.receipt]
			_, tombstonePresent := objects.objects[keys.deletion]
			objects.mu.Unlock()
			if intentPresent || contentPresent || receiptPresent || !tombstonePresent {
				t.Fatalf("delete did not retain only the tombstone: intent=%v content=%v receipt=%v tombstone=%v", intentPresent, contentPresent, receiptPresent, tombstonePresent)
			}
		})
	}
}

func TestDeleteCleansExactOrphansWhenIntentIsMissing(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	service := mustService(t, newFakeContainer([]byte("orphaned")), objects, binding.Authority)
	receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	keys := keysForIdentity(receipt.CaptureIdentity)
	objects.mu.Lock()
	delete(objects.objects, keys.intent)
	objects.deletedKeys[keys.intent] = true
	objects.mu.Unlock()

	observation, err := service.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || observation.Status != "absent" {
		t.Fatalf("missing intent was not authoritative absence: %#v, %v", observation, err)
	}
	deleted, err := service.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity)
	if err != nil || deleted.Outcome != "deleted" {
		t.Fatalf("exact orphan cleanup failed: %#v, %v", deleted, err)
	}
	objects.mu.Lock()
	_, contentPresent := objects.objects[keys.content]
	_, receiptPresent := objects.objects[keys.receipt]
	_, tombstonePresent := objects.objects[keys.deletion]
	objects.mu.Unlock()
	if contentPresent || receiptPresent || !tombstonePresent {
		t.Fatalf("orphan cleanup did not converge to its tombstone: content=%v receipt=%v tombstone=%v", contentPresent, receiptPresent, tombstonePresent)
	}
}

func TestDeleteWithoutIntentRequiresIdentityDerivedFromCurrentTerminalGeneration(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	containers := newFakeContainer([]byte("never captured"))
	service := mustService(t, containers, objects, binding.Authority)
	forged := CaptureIdentity{
		CaptureBinding:     binding,
		ProviderResourceID: "daytona-working-copy-capture:v2:sha256:" + strings.Repeat("f", 64),
	}

	if _, err := service.Delete(context.Background(), binding.Source.ProviderResourceID, forged); !errors.Is(err, ErrConflict) {
		t.Fatalf("opaque-shaped identity retired an absent binding without terminal derivation: %v", err)
	}
	objects.mu.Lock()
	_, forgedTombstoneExists := objects.objects[deletionKey(bindingObjectRoot(binding))]
	objects.mu.Unlock()
	if forgedTombstoneExists {
		t.Fatal("rejected absent identity published a poisoning tombstone")
	}

	exact := CaptureIdentity{
		CaptureBinding:     binding,
		ProviderResourceID: providerResourceID(binding, containers.generation.terminal()),
	}
	receipt, err := service.Delete(context.Background(), binding.Source.ProviderResourceID, exact)
	if err != nil || receipt.CaptureIdentity != exact || receipt.Outcome != "already_absent" {
		t.Fatalf("terminal-derived absent identity did not converge: %#v, %v", receipt, err)
	}
	objects.mu.Lock()
	_, exactTombstoneExists := objects.objects[deletionKey(bindingObjectRoot(binding))]
	objects.mu.Unlock()
	if !exactTombstoneExists {
		t.Fatal("terminal-derived absent identity did not publish its retirement tombstone")
	}
}

func TestCrossServiceCaptureAndDeleteConvergeThroughDurableAuthority(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	objects := newFakeObjectStore()
	containers := newFakeContainer([]byte("shared durable truth"))
	first := mustService(t, containers, objects, binding.Authority)
	second := mustService(t, containers, objects, binding.Authority)

	receipt, err := first.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatalf("first capture failed: %v", err)
	}
	inspectCalls := containers.inspectCalls
	replayed, err := second.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || replayed != receipt {
		t.Fatalf("second service did not converge on the exact receipt: %#v, %v", replayed, err)
	}
	if containers.copyCalls != 1 || containers.inspectCalls != inspectCalls+1 {
		t.Fatalf("cross-service replay did not perform exactly one fresh stop reproof: copies=%d inspect=%d->%d", containers.copyCalls, inspectCalls, containers.inspectCalls)
	}

	deleted, err := second.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity)
	if err != nil || deleted.Outcome != "deleted" {
		t.Fatalf("cross-service delete failed: %#v, %v", deleted, err)
	}
	if _, err := first.Capture(context.Background(), binding.Source.ProviderResourceID, binding); !errors.Is(err, ErrConflict) {
		t.Fatalf("first service recreated a tombstoned capture: %v", err)
	}
	observation, err := first.Observe(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil || observation.Status != "absent" {
		t.Fatalf("first service did not observe durable deletion: %#v, %v", observation, err)
	}
	keys := keysForIdentity(receipt.CaptureIdentity)
	objects.mu.Lock()
	_, tombstonePresent := objects.objects[keys.deletion]
	objects.mu.Unlock()
	if !tombstonePresent || containers.copyCalls != 1 {
		t.Fatalf("durable tombstone was lost or capture repeated: tombstone=%v copies=%d", tombstonePresent, containers.copyCalls)
	}
}

func TestDeleteReportsOutcomeUnknownWhenDurableAbsenceCannotBeProven(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*fakeObjectStore){
		"delete-rejected-object-remains": func(objects *fakeObjectStore) {
			objects.failDeleteSuffix = "/receipt.json"
		},
		"post-delete-stat-unavailable": func(objects *fakeObjectStore) {
			objects.postDeleteStatErrors["/receipt.json"] = []error{errors.New("transient stat transport failure")}
		},
	}
	for name, inject := range tests {
		inject := inject
		t.Run(name, func(t *testing.T) {
			binding := validBinding()
			binding.ProviderName += "-" + name
			binding.RequestFingerprint = hashHex(binding.ProviderName)
			objects := newFakeObjectStore()
			service := mustService(t, newFakeContainer([]byte("delete uncertainty")), objects, binding.Authority)
			receipt, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
			if err != nil {
				t.Fatalf("capture failed: %v", err)
			}
			inject(objects)
			if _, err := service.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("unproven deletion outcome was not classified outcome-unknown: %v", err)
			}
		})
	}
}

func TestTransientDockerFailuresAreUnavailableNotConflicts(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*fakeContainer){
		"inspect": func(container *fakeContainer) {
			container.inspectErrors = []error{errors.New("transient inspect transport failure")}
		},
		"stat": func(container *fakeContainer) {
			container.statErrors = []error{errors.New("transient stat transport failure")}
		},
		"copy": func(container *fakeContainer) {
			container.copyErrors = []error{errors.New("transient copy transport failure")}
		},
	}
	for name, inject := range tests {
		inject := inject
		t.Run(name, func(t *testing.T) {
			binding := validBinding()
			binding.ProviderName += "-docker-" + name
			binding.RequestFingerprint = hashHex(binding.ProviderName)
			container := newFakeContainer([]byte("x"))
			inject(container)
			service := mustService(t, container, newFakeObjectStore(), binding.Authority)
			_, err := service.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
			if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrConflict) {
				t.Fatalf("transient Docker %s failure had the wrong classification: %v", name, err)
			}
		})
	}
}

func TestDecodeExactJSONRejectsDuplicateMissingZeroAndNullFields(t *testing.T) {
	t.Parallel()
	binding := validBinding()
	canonical, err := json.Marshal(binding)
	if err != nil {
		t.Fatalf("marshal canonical binding: %v", err)
	}
	var decoded CaptureBinding
	if err := DecodeExactJSON(canonical, &decoded); err != nil || decoded != binding {
		t.Fatalf("canonical binding did not decode exactly: %#v, %v", decoded, err)
	}
	duplicates := map[string][]byte{
		"top-level": bytes.Replace(canonical, []byte("{"), []byte(`{"providerName":"shadow",`), 1),
		"nested": bytes.Replace(
			canonical,
			[]byte(`"owner":{`),
			[]byte(`"owner":{"tenantId":"77777777-7777-4777-8777-777777777777",`),
			1,
		),
	}
	for name, data := range duplicates {
		if err := DecodeExactJSON(data, &CaptureBinding{}); err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
			t.Fatalf("%s duplicate key was not rejected precisely: %v", name, err)
		}
	}
	missingOrNull := map[string][]byte{
		"missing-restart-count": bytes.Replace(canonical, []byte(`,"restartCount":0`), nil, 1),
		"missing-exit-code":     bytes.Replace(canonical, []byte(`,"exitCode":0`), nil, 1),
		"missing-oom-killed":    bytes.Replace(canonical, []byte(`,"oomKilled":false`), nil, 1),
		"null-oom-killed":       bytes.Replace(canonical, []byte(`"oomKilled":false`), []byte(`"oomKilled":null`), 1),
	}
	for name, data := range missingOrNull {
		if err := DecodeExactJSON(data, &CaptureBinding{}); err == nil ||
			!strings.Contains(err.Error(), "exact declared nested contract") {
			t.Fatalf("%s exact-schema drift was accepted: %v", name, err)
		}
	}
	read := CaptureReadRequest{
		CaptureIdentity:              CaptureIdentity{CaptureBinding: binding, ProviderResourceID: "daytona-working-copy-capture:v2:sha256:" + strings.Repeat("d", 64)},
		ExpectedTotalByteLength:      0,
		ExpectedProviderSHA256Digest: "sha256:" + strings.Repeat("e", 64),
		Offset:                       0,
		MaximumBytes:                 1,
	}
	readJSON, err := json.Marshal(read)
	if err != nil {
		t.Fatalf("marshal exact read: %v", err)
	}
	withoutOffset := bytes.Replace(readJSON, []byte(`,"offset":0`), nil, 1)
	if err := DecodeExactJSON(withoutOffset, &CaptureReadRequest{}); err == nil {
		t.Fatal("missing required zero offset was accepted")
	}
}

type fakeContainer struct {
	mu                sync.Mutex
	generation        testContainerGeneration
	state             *containertypes.State
	content           []byte
	archive           []byte
	statSizeOverride  int64
	inspectCalls      int
	copyCalls         int
	statCalls         int
	copyPaths         []string
	copyContainerIDs  []string
	statContainerIDs  []string
	inspectMutations  map[int]testContainerGeneration
	statMutation      func(containertypes.PathStat) containertypes.PathStat
	afterStatMutation func(containertypes.PathStat) containertypes.PathStat
	inspectErrors     []error
	statErrors        []error
	copyErrors        []error
	beforeCopy        func() error
}

func newFakeContainer(content []byte) *fakeContainer {
	copy := append([]byte(nil), content...)
	return &fakeContainer{
		generation:       defaultTestContainerGeneration(),
		state:            &containertypes.State{Status: containertypes.StateExited},
		content:          copy,
		archive:          tarArchive(tarEntry{name: "report.txt", typeflag: tar.TypeReg, body: copy}),
		inspectMutations: make(map[int]testContainerGeneration),
	}
}

func defaultTestContainerGeneration() testContainerGeneration {
	return testContainerGeneration{
		ID:           strings.Repeat("a", 64),
		Created:      "2026-08-23T00:00:00Z",
		StartedAt:    "2026-08-23T00:01:00Z",
		FinishedAt:   "2026-08-23T00:02:00Z",
		RestartCount: 0,
		ExitCode:     0,
		OOMKilled:    false,
	}
}

type testContainerGeneration struct {
	ID           string
	Created      string
	StartedAt    string
	FinishedAt   string
	RestartCount int
	ExitCode     int
	OOMKilled    bool
}

func (generation testContainerGeneration) terminal() generationstop.TerminalGeneration {
	return generationstop.TerminalGeneration{
		ExpectedGeneration: generationstop.ExpectedGeneration{
			ContainerID:        generation.ID,
			ContainerCreatedAt: generation.Created,
			ExecutionStartedAt: generation.StartedAt,
			RestartCount:       generation.RestartCount,
		},
		ExecutionFinishedAt: generation.FinishedAt,
		ExitCode:            generation.ExitCode,
		OOMKilled:           generation.OOMKilled,
	}
}

func (f *fakeContainer) ContainerInspect(
	_ context.Context,
	_ string,
) (containertypes.InspectResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inspectCalls++
	if len(f.inspectErrors) > 0 {
		err := f.inspectErrors[0]
		f.inspectErrors = f.inspectErrors[1:]
		return containertypes.InspectResponse{}, err
	}
	generation := f.generation
	if mutated, ok := f.inspectMutations[f.inspectCalls]; ok {
		generation = mutated
	}
	state := *f.state
	state.StartedAt = generation.StartedAt
	state.FinishedAt = generation.FinishedAt
	state.ExitCode = generation.ExitCode
	state.OOMKilled = generation.OOMKilled
	return containertypes.InspectResponse{ContainerJSONBase: &containertypes.ContainerJSONBase{
		ID: generation.ID, Created: generation.Created, State: &state, RestartCount: generation.RestartCount,
	}}, nil
}

type fakeStoppedGenerationAuthority struct {
	container *fakeContainer
}

func (authority *fakeStoppedGenerationAuthority) RequireCurrentReceipt(
	_ context.Context,
	expectedSource generationstop.Source,
	expectedOwner generationstop.Owner,
	expectedPurpose generationstop.Purpose,
	stopAuthority generationstop.StopAuthority,
) (generationstop.Receipt, error) {
	if err := generationstop.ValidateBinding(expectedSource, expectedOwner, stopAuthority); err != nil {
		return generationstop.Receipt{}, err
	}
	if expectedPurpose != (generationstop.Purpose{Kind: generationstop.PurposeWorkingCopyCapture}) {
		return generationstop.Receipt{}, fmt.Errorf("%w: purpose differs", generationstop.ErrConflict)
	}
	container := authority.container
	container.mu.Lock()
	defer container.mu.Unlock()
	container.inspectCalls++
	if len(container.inspectErrors) > 0 {
		err := container.inspectErrors[0]
		container.inspectErrors = container.inspectErrors[1:]
		return generationstop.Receipt{}, fmt.Errorf("%w: %v", generationstop.ErrUnavailable, err)
	}
	generation := container.generation
	if mutated, ok := container.inspectMutations[container.inspectCalls]; ok {
		generation = mutated
	}
	state := container.state
	if state == nil || state.Status != containertypes.StateExited || state.Running || state.Paused ||
		state.Restarting || state.Dead || state.Pid != 0 || generation.FinishedAt == "" {
		return generationstop.Receipt{}, fmt.Errorf("%w: generation is not exact exited PID-zero", generationstop.ErrConflict)
	}
	terminal := generation.terminal()
	if terminal != stopAuthority.TerminalGeneration {
		return generationstop.Receipt{}, fmt.Errorf("%w: terminal generation changed", generationstop.ErrConflict)
	}
	return generationstop.Receipt{
		Version:            1,
		Kind:               "agent_workspace_stopped_generation_receipt",
		ReceiptRef:         stopAuthority.ReceiptRef,
		ReceiptDigest:      stopAuthority.ReceiptDigest,
		TerminalGeneration: terminal,
		Request: generationstop.StopRequest{
			OperationID: stopAuthority.OperationID,
			Source:      expectedSource,
			Owner:       expectedOwner,
			Fence:       stopAuthority.Fence,
			Purpose:     expectedPurpose,
		},
	}, nil
}

func (f *fakeContainer) ContainerStatPath(
	_ context.Context,
	containerID string,
	containerPath string,
) (containertypes.PathStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statCalls++
	f.statContainerIDs = append(f.statContainerIDs, containerID)
	if len(f.statErrors) > 0 {
		err := f.statErrors[0]
		f.statErrors = f.statErrors[1:]
		return containertypes.PathStat{}, err
	}
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
	containerID string,
	containerPath string,
) (io.ReadCloser, containertypes.PathStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.copyCalls++
	f.copyPaths = append(f.copyPaths, containerPath)
	f.copyContainerIDs = append(f.copyContainerIDs, containerID)
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
	data          []byte
	contentSHA256 string
	metadata      map[string]string
}

type fakeRangeRead struct {
	key          string
	offset       int64
	maximumBytes int64
}

type fakeObjectStore struct {
	mu                    sync.Mutex
	objects               map[string]fakeStoredObject
	failAfterStoreSuffix  string
	failDeleteSuffix      string
	failAfterDeleteSuffix string
	postDeleteStatErrors  map[string][]error
	deletedKeys           map[string]bool
	rangeReads            []fakeRangeRead
	fullContentReads      int
}

func newFakeObjectStore() *fakeObjectStore {
	return &fakeObjectStore{
		objects:              make(map[string]fakeStoredObject),
		postDeleteStatErrors: make(map[string][]error),
		deletedKeys:          make(map[string]bool),
	}
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
	f.objects[key] = fakeStoredObject{
		data:          append([]byte(nil), data...),
		contentSHA256: sha256Digest(data),
		metadata:      lowerMetadata(metadata),
	}
	delete(f.deletedKeys, key)
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
	if strings.HasSuffix(key, "/content.bin") {
		f.fullContentReads++
	}
	return append([]byte(nil), object.data...), nil
}

func (f *fakeObjectStore) GetPrivateObjectRange(
	_ context.Context,
	key string,
	offset int64,
	maximumBytes int64,
) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	object, exists := f.objects[key]
	if !exists {
		return nil, storage.ErrPrivateObjectNotFound
	}
	if offset < 0 || maximumBytes <= 0 || offset > int64(len(object.data)) {
		return nil, storage.ErrPrivateObjectTooLarge
	}
	f.rangeReads = append(f.rangeReads, fakeRangeRead{key: key, offset: offset, maximumBytes: maximumBytes})
	end := min(offset+maximumBytes, int64(len(object.data)))
	return append([]byte(nil), object.data[offset:end]...), nil
}

func (f *fakeObjectStore) StatPrivateObject(
	_ context.Context,
	key string,
) (storage.PrivateObjectInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deletedKeys[key] {
		for suffix, queued := range f.postDeleteStatErrors {
			if strings.HasSuffix(key, suffix) && len(queued) > 0 {
				err := queued[0]
				f.postDeleteStatErrors[suffix] = queued[1:]
				return storage.PrivateObjectInfo{}, err
			}
		}
	}
	object, exists := f.objects[key]
	if !exists {
		return storage.PrivateObjectInfo{}, storage.ErrPrivateObjectNotFound
	}
	return storage.PrivateObjectInfo{
		Size:          int64(len(object.data)),
		ContentSHA256: object.contentSHA256,
		UserMetadata:  lowerMetadata(object.metadata),
	}, nil
}

func (f *fakeObjectStore) DeletePrivateObject(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDeleteSuffix != "" && strings.HasSuffix(key, f.failDeleteSuffix) {
		return errors.New("simulated delete cut")
	}
	delete(f.objects, key)
	f.deletedKeys[key] = true
	if f.failAfterDeleteSuffix != "" && strings.HasSuffix(key, f.failAfterDeleteSuffix) {
		return errors.New("simulated lost delete response")
	}
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
		LineageRef: "ambit.core-document-lineage:v5:sha256:" + strings.Repeat("6", 64),
		RoleRef:    captureRoleRef,
		Protocol:   CaptureAuthorityArtifact{Ref: captureProtocolRef, Digest: protocolDigest},
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
			ExpectedProfile:     "managed-container",
			ExpectedRuntimeKind: "full_image_runtime_pack",
		},
		Owner: CaptureOwner{
			TenantID:      "11111111-1111-4111-8111-111111111111",
			UserID:        "22222222-2222-4222-8222-222222222222",
			WorkspaceID:   "33333333-3333-4333-8333-333333333333",
			RunID:         "44444444-4444-4444-8444-444444444444",
			GrantID:       "55555555-5555-4555-8555-555555555555",
			WorkingCopyID: "66666666-6666-4666-8666-666666666666",
		},
		StopAuthority: generationstop.StopAuthority{
			OperationID:        "77777777-7777-4777-8777-777777777777",
			ReceiptRef:         "ambit.stopped-generation-receipt:v1:sha256:" + strings.Repeat("9", 64),
			ReceiptDigest:      "sha256:" + strings.Repeat("9", 64),
			TerminalGeneration: defaultTestContainerGeneration().terminal(),
			Fence: generationstop.Fence{
				WorkspaceExecutionManifestRef: "ambit.workspace-execution-manifest:v1:sha256:" + strings.Repeat("c", 64),
			},
		},
		Selector: CaptureSelector{
			SemanticZoneRef:  "ambit.workspace-zone/work@1",
			ZoneRelativePath: "report.txt",
		},
	}
}

func mustService(
	t *testing.T,
	containers *fakeContainer,
	objects storage.PrivateObjectStorageClient,
	authority CaptureAuthority,
) *Service {
	t.Helper()
	service, err := NewService(
		containers,
		objects,
		&fakeStoppedGenerationAuthority{container: containers},
		authority,
	)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

func pathBase(value string) string {
	parts := strings.Split(strings.TrimSuffix(value, "/"), "/")
	return parts[len(parts)-1]
}
