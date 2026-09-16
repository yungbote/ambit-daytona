// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
)

const nativeSandboxID = "00000000-0000-4000-8000-000000000001"

type nativeSnapshotFixture struct {
	observation                generationstop.SandboxGenerationObservation
	content                    []byte
	inspectCalls, captureCalls int
	failure                    error
	beforeCapture              func(context.Context) error
}

func (f *nativeSnapshotFixture) ObserveSandboxGeneration(_ context.Context, sandboxID, organizationID string) (generationstop.SandboxGenerationObservation, error) {
	f.inspectCalls++
	if sandboxID != f.observation.SandboxID || organizationID != f.observation.OrganizationID {
		return generationstop.SandboxGenerationObservation{}, ErrConflict
	}
	return f.observation, nil
}

func (f *nativeSnapshotFixture) ObserveGeneration(_ context.Context, binding CaptureBinding) (generationstop.CurrentGenerationObservation, error) {
	if binding.SandboxFile.Generation != f.observation.Generation.ExpectedGeneration {
		return generationstop.CurrentGenerationObservation{}, ErrConflict
	}
	return generationstop.CurrentGenerationObservation{Generation: f.observation.Generation, State: f.observation.State}, nil
}

func (f *nativeSnapshotFixture) Capture(ctx context.Context, binding CaptureBinding, output io.Writer, maximum int64) (capturedFile, error) {
	f.captureCalls++
	if f.beforeCapture != nil {
		if err := f.beforeCapture(ctx); err != nil {
			return capturedFile{}, err
		}
	}
	if f.failure != nil {
		return capturedFile{}, f.failure
	}
	if _, err := f.ObserveGeneration(ctx, binding); err != nil {
		return capturedFile{}, err
	}
	if int64(len(f.content)) > maximum {
		return capturedFile{}, ErrConflict
	}
	if _, err := output.Write(f.content); err != nil {
		return capturedFile{}, err
	}
	return capturedFile{byteLength: int64(len(f.content)), digest: sha256Digest(f.content), capturedAt: "2026-09-16T12:34:56.789Z"}, nil
}

func nativeFixture(t *testing.T) (*Service, *fakeObjectStore, *nativeSnapshotFixture, SandboxFileRequest) {
	t.Helper()
	objects := newFakeObjectStore()
	service := mustService(t, newFakeContainer(nil), objects, validBinding().Authority)
	request := SandboxFileRequest{OrganizationID: "11111111-1111-4111-8111-111111111111", OperationID: "download-1", Path: "/workspace/outputs/downloads/result.txt"}
	generation := defaultTestContainerGeneration().terminal().ExpectedGeneration
	snapshot := &nativeSnapshotFixture{content: []byte("native immutable bytes\x00"), observation: generationstop.SandboxGenerationObservation{
		SandboxID: nativeSandboxID, OrganizationID: request.OrganizationID, Generation: generationstop.ContainerGeneration{ExpectedGeneration: generation},
		State: generationstop.RuntimeState{Status: "running", Running: true, PID: 123},
	}}
	service.fileSnapshots = snapshot
	return service, objects, snapshot, request
}

func TestNativeFileCaptureReplayRangesAndRetirement(t *testing.T) {
	s, _, physical, request := nativeFixture(t)
	ctx := context.Background()
	receipt, err := s.CaptureSandboxFile(ctx, nativeSandboxID, request)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Generation != physical.observation.Generation.ExpectedGeneration || receipt.Component != s.component || receipt.SHA256 != sha256Digest(physical.content) {
		t.Fatalf("lost actual source identity: %#v", receipt)
	}
	physical.observation.Generation.RestartCount++
	s.component.Helper.Digest = "sha256:" + strings.Repeat("1", 64)
	s.component.Helper.Ref = "runtime-component-artifact:" + s.component.Helper.Digest
	got, err := s.CaptureSandboxFile(ctx, nativeSandboxID, request)
	if err != nil || got != receipt || physical.captureCalls != 1 || physical.inspectCalls != 1 {
		t.Fatalf("historical replay re-read a changed source: %#v %v", got, err)
	}
	var contents []byte
	for offset := int64(0); offset < receipt.TotalByteLength; {
		part, err := s.ReadSandboxFile(ctx, nativeSandboxID, SandboxFileReadRequest{Receipt: receipt, Offset: offset, MaximumBytes: 7})
		if err != nil {
			t.Fatal(err)
		}
		bytes, err := base64.StdEncoding.DecodeString(part.BytesBase64)
		if err != nil || int64(len(bytes)) != part.ByteLength || part.CaptureID != receipt.CaptureID || part.SHA256 != receipt.SHA256 {
			t.Fatalf("range lost custody: %#v %v", part, err)
		}
		contents = append(contents, bytes...)
		offset += part.ByteLength
		if part.EOF != (offset == receipt.TotalByteLength) {
			t.Fatal("incorrect EOF")
		}
	}
	if string(contents) != string(physical.content) {
		t.Fatal("content differs")
	}
	bad := receipt
	bad.CapturedAt = "2026-09-16T12:34:55.000Z"
	if _, err := s.ReadSandboxFile(ctx, nativeSandboxID, SandboxFileReadRequest{Receipt: bad, MaximumBytes: 1}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed receipt accepted: %v", err)
	}
	result, err := s.DeleteSandboxFile(ctx, nativeSandboxID, SandboxFileDeleteRequest{Receipt: &receipt})
	if err != nil || result.Outcome != "deleted" || result.CaptureID == nil || *result.CaptureID != receipt.CaptureID {
		t.Fatalf("delete: %#v %v", result, err)
	}
	result, err = s.DeleteSandboxFile(ctx, nativeSandboxID, SandboxFileDeleteRequest{Receipt: &receipt})
	if err != nil || result.Outcome != "already_absent" {
		t.Fatalf("delete replay: %#v %v", result, err)
	}
	if _, err = s.CaptureSandboxFile(ctx, nativeSandboxID, request); !errors.Is(err, ErrConflict) {
		t.Fatalf("retired operation restarted: %v", err)
	}
	observed, err := s.ObserveSandboxFile(ctx, nativeSandboxID, SandboxFileObserveRequest{OrganizationID: request.OrganizationID, OperationID: request.OperationID})
	if err != nil || observed.Status != "retired" {
		t.Fatalf("retirement observation: %#v %v", observed, err)
	}
}

func TestNativeFileCaptureFreezesPendingGenerationAndRecoversStagedBytes(t *testing.T) {
	for _, stage := range []string{"source", "receipt"} {
		t.Run(stage, func(t *testing.T) {
			s, objects, physical, request := nativeFixture(t)
			if stage == "source" {
				physical.failure = ErrUnavailable
			} else {
				objects.failBeforeStoreSuffix = "/receipt.json"
			}
			if _, err := s.CaptureSandboxFile(context.Background(), nativeSandboxID, request); err == nil {
				t.Fatal("failure not observed")
			}
			physical.observation.Generation.RestartCount++
			physical.failure = nil
			objects.failBeforeStoreSuffix = ""
			receipt, err := s.CaptureSandboxFile(context.Background(), nativeSandboxID, request)
			if stage == "source" {
				if !errors.Is(err, ErrConflict) {
					t.Fatalf("unfinished operation rebound to new generation: %#v %v", receipt, err)
				}
			} else if err != nil || receipt.Generation.RestartCount == physical.observation.Generation.RestartCount || physical.captureCalls != 1 {
				t.Fatalf("staged bytes recaptured: %#v %v", receipt, err)
			}
			if physical.inspectCalls != 1 {
				t.Fatalf("generation selected %d times", physical.inspectCalls)
			}
		})
	}
}

func TestNativeFileObservationRecoversWithoutTheMutablePath(t *testing.T) {
	s, _, physical, request := nativeFixture(t)
	receipt, err := s.CaptureSandboxFile(context.Background(), nativeSandboxID, request)
	if err != nil {
		t.Fatal(err)
	}
	physical.failure = errors.New("original file removed")
	physical.observation.Generation.RestartCount++
	lookup := SandboxFileObserveRequest{OrganizationID: request.OrganizationID, OperationID: request.OperationID}
	observed, err := s.ObserveSandboxFile(context.Background(), nativeSandboxID, lookup)
	if err != nil || observed.Status != "complete" || observed.Receipt == nil || *observed.Receipt != receipt || physical.inspectCalls != 1 || physical.captureCalls != 1 {
		t.Fatalf("retained lookup depended on a mutable source: %#v %v", observed, err)
	}
	otherPath := "/workspace/outputs/different.txt"
	lookup.Path = &otherPath
	if _, err := s.ObserveSandboxFile(context.Background(), nativeSandboxID, lookup); !errors.Is(err, ErrConflict) {
		t.Fatalf("supplied wrong original path accepted: %v", err)
	}
}

func TestNativeFileOperationCancellationBeforeAndAfterAdmission(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[admitted], func(t *testing.T) {
			s, _, physical, request := nativeFixture(t)
			if admitted {
				physical.failure = ErrUnavailable
				_, _ = s.CaptureSandboxFile(context.Background(), nativeSandboxID, request)
			}
			retired, err := s.DeleteSandboxFile(context.Background(), nativeSandboxID, SandboxFileDeleteRequest{OrganizationID: request.OrganizationID, OperationID: request.OperationID, Path: request.Path})
			if err != nil {
				t.Fatal(err)
			}
			if (retired.CaptureID != nil) != admitted {
				t.Fatalf("invented or lost capture identity: %#v", retired)
			}
			physical.failure = nil
			if _, err := s.CaptureSandboxFile(context.Background(), nativeSandboxID, request); !errors.Is(err, ErrConflict) {
				t.Fatalf("canceled operation restarted: %v", err)
			}
		})
	}
}

func TestNativeFileCaptureRejectsOperationSubstitutionAndProductDowngrade(t *testing.T) {
	s, objects, _, request := nativeFixture(t)
	receipt, err := s.CaptureSandboxFile(context.Background(), nativeSandboxID, request)
	if err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.Path = "/workspace/outputs/other.txt"
	if _, err := s.CaptureSandboxFile(context.Background(), nativeSandboxID, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("operation path changed: %v", err)
	}
	internal, err := validateSandboxFileReceipt(nativeSandboxID, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Capture(context.Background(), nativeSandboxID, internal.CaptureBinding); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Product endpoint admitted native authority: %v", err)
	}
	if _, err := s.Read(context.Background(), nativeSandboxID, CaptureReadRequest{CaptureIdentity: internal.CaptureIdentity, MaximumBytes: 1}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Product read admitted native authority: %v", err)
	}
	wrong := internal.CaptureBinding
	wrong.Owner = validBinding().Owner
	if err := validateSandboxFileBinding(nativeSandboxID, wrong); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("mixed authority admitted: %v", err)
	}
	for key := range objects.objects {
		if strings.Contains(key, request.OrganizationID) || strings.Contains(key, nativeSandboxID) || strings.Contains(key, request.OperationID) {
			t.Fatalf("custody key leaked identity: %s", key)
		}
	}
}

func TestNativeFilePathAndOperationBounds(t *testing.T) {
	for _, path := range []string{"/etc/shadow", "/workspace", "/workspace/work", "/workspace/outputs/../work/x", "/workspace/outputs/x/", "/workspace/outputs//x", "/workspace/outputs/x\\y", "/workspace/outputs/x\x00", "/workspace/worked/x"} {
		if _, err := sandboxFileSelector(path); err == nil {
			t.Fatalf("invalid path admitted: %q", path)
		}
	}
	for _, id := range []string{"", " white", "a/b", strings.Repeat("a", 129), "é", "-start"} {
		if canonicalOperationID(id) {
			t.Fatalf("invalid operation admitted: %q", id)
		}
	}
	for _, id := range []string{"a", strings.Repeat("a", 128), "file:1_ab.cd-ef"} {
		if !canonicalOperationID(id) {
			t.Fatalf("valid operation refused: %q", id)
		}
	}
}

func TestNativeCaptureLeavesLegacyProductBytesUnchanged(t *testing.T) {
	binding := validBinding()
	data, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sandboxFile") {
		t.Fatal("native field changed legacy Product JSON")
	}
	s, objects, _, _ := nativeFixture(t)
	receipt, err := s.Capture(context.Background(), binding.Source.ProviderResourceID, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Delete(context.Background(), binding.Source.ProviderResourceID, receipt.CaptureIdentity); err != nil {
		t.Fatal(err)
	}
	for key, object := range objects.objects {
		if strings.HasSuffix(key, "/deletion.json") && strings.Contains(string(object.data), "sandboxFile") {
			t.Fatal("native field changed legacy deletion bytes")
		}
	}
}

type nativePhysicalInspector struct {
	observation generationstop.SandboxGenerationObservation
}

func (i *nativePhysicalInspector) InspectGeneration(context.Context, string) (generationstop.CurrentGenerationObservation, error) {
	return generationstop.CurrentGenerationObservation{}, errors.New("native observation must not require Product labels")
}

func (i *nativePhysicalInspector) InspectSandboxGeneration(context.Context, string) (generationstop.SandboxGenerationObservation, error) {
	return i.observation, nil
}

func TestNativeSnapshotReaderReprovesOwnerAndRunningGeneration(t *testing.T) {
	s, _, fixture, request := nativeFixture(t)
	selector, err := sandboxFileSelector(request.Path)
	if err != nil {
		t.Fatal(err)
	}
	binding := CaptureBinding{Selector: selector, SandboxFile: SandboxFileSource{Contract: SandboxFileCaptureContract,
		OrganizationID: request.OrganizationID, SandboxID: nativeSandboxID, OperationID: request.OperationID,
		Generation: fixture.observation.Generation.ExpectedGeneration, Component: s.component}}
	for name, change := range map[string]func(*generationstop.SandboxGenerationObservation){
		"owner":      func(o *generationstop.SandboxGenerationObservation) { o.OrganizationID = nativeSandboxID },
		"sandbox":    func(o *generationstop.SandboxGenerationObservation) { o.SandboxID = request.OrganizationID },
		"generation": func(o *generationstop.SandboxGenerationObservation) { o.Generation.RestartCount++ },
		"stopped": func(o *generationstop.SandboxGenerationObservation) {
			o.State.Running = false
			o.State.PID = 0
			o.State.Status = "exited"
		},
		"paused":     func(o *generationstop.SandboxGenerationObservation) { o.State.Paused = true },
		"restarting": func(o *generationstop.SandboxGenerationObservation) { o.State.Restarting = true },
		"terminal": func(o *generationstop.SandboxGenerationObservation) {
			o.Generation.ExecutionFinishedAt = "2026-09-16T12:00:00.000Z"
		},
	} {
		t.Run(name, func(t *testing.T) {
			inspector := &nativePhysicalInspector{observation: fixture.observation}
			reader := NewNativeFileSnapshotReader(inspector)
			if _, err := reader.ObserveGeneration(context.Background(), binding); err != nil {
				t.Fatal(err)
			}
			change(&inspector.observation)
			if _, err := reader.ObserveGeneration(context.Background(), binding); !errors.Is(err, ErrConflict) {
				t.Fatalf("changed native source admitted: %v", err)
			}
		})
	}
}
