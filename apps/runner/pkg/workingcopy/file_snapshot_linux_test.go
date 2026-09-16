// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"golang.org/x/sys/unix"
)

// These tests replace only the FICLONE syscall. They prove descriptor custody,
// byte admission and failure behavior, not a backing filesystem's atomicity.
// The opt-in Docker test exercises the real kernel operation on a separately
// qualified native target.
func TestFileSnapshotClonedBytesAndPrivateDescriptorCustody(t *testing.T) {
	for _, body := range [][]byte{{}, []byte("exact bytes\x00"), bytes.Repeat([]byte("bounded chunk"), 30000)} {
		t.Run(fmt.Sprintf("%d bytes", len(body)), func(t *testing.T) {
			source, zone := snapshotSourceFixture(t, []byte("source descriptor"))
			cloneFD := -1
			var output bytes.Buffer
			before := time.Now().UTC().Truncate(time.Millisecond)
			captured, err := copyClonedFile(context.Background(), source, int(zone.Fd()), &output, int64(len(body)), fixtureSnapshotClone(t, source, body, &cloneFD))
			if err != nil || !bytes.Equal(output.Bytes(), body) || captured.digest != sha256Digest(body) || captured.byteLength != int64(len(body)) {
				t.Fatalf("cloned snapshot differs: %#v bytes=%d err=%v", captured, output.Len(), err)
			}
			capturedAt, err := time.Parse(time.RFC3339Nano, captured.capturedAt)
			if err != nil || capturedAt.Before(before) || capturedAt.After(time.Now()) {
				t.Fatalf("invalid capture time: %q %v", captured.capturedAt, err)
			}
			assertSnapshotDescriptorClosed(t, cloneFD)
			entries, err := os.ReadDir(zone.Name())
			if err != nil || len(entries) != 1 || entries[0].Name() != "source" {
				t.Fatalf("snapshot left a workspace pathname: %v %v", entries, err)
			}
			if content, err := os.ReadFile(source.Name()); err != nil || string(content) != "source descriptor" {
				t.Fatalf("capture changed source bytes: %q %v", content, err)
			}
		})
	}
}

func TestFileSnapshotCloneFailureNeverFallsBackToMutableSource(t *testing.T) {
	for _, failure := range []error{unix.EOPNOTSUPP, unix.EXDEV, unix.ENOSPC, unix.EIO} {
		t.Run(failure.Error(), func(t *testing.T) {
			source, zone := snapshotSourceFixture(t, []byte("must not be streamed"))
			cloneFD, calls := -1, 0
			clone := func(destination, selected int) error {
				calls++
				cloneFD = destination
				if selected != int(source.Fd()) {
					t.Fatal("clone did not receive selected descriptor")
				}
				return failure
			}
			var output bytes.Buffer
			captured, err := copyClonedFile(context.Background(), source, int(zone.Fd()), &output, MaximumCaptureBytes, clone)
			if !errors.Is(err, ErrUnavailable) || !errors.Is(err, failure) || calls != 1 || output.Len() != 0 || captured != (capturedFile{}) {
				t.Fatalf("clone error fell back or lost its classification: %#v bytes=%d calls=%d err=%v", captured, output.Len(), calls, err)
			}
			assertSnapshotDescriptorClosed(t, cloneFD)
		})
	}
}

func TestFileSnapshotBoundsTheObtainedClone(t *testing.T) {
	for _, test := range []struct {
		name          string
		source, clone []byte
		maximum       int64
		wantErr       bool
	}{
		{name: "larger clone refused", source: []byte("small"), clone: bytes.Repeat([]byte("x"), 64), maximum: 32, wantErr: true},
		{name: "smaller clone admitted", source: bytes.Repeat([]byte("x"), 64), clone: []byte("small"), maximum: 5},
		{name: "zero byte clone admitted", source: []byte("before"), clone: []byte{}, maximum: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, zone := snapshotSourceFixture(t, test.source)
			cloneFD := -1
			var output bytes.Buffer
			captured, err := copyClonedFile(context.Background(), source, int(zone.Fd()), &output, test.maximum, fixtureSnapshotClone(t, source, test.clone, &cloneFD))
			if test.wantErr {
				if !errors.Is(err, ErrConflict) || output.Len() != 0 || captured != (capturedFile{}) {
					t.Fatalf("oversized cloned bytes escaped: %#v bytes=%d err=%v", captured, output.Len(), err)
				}
			} else if err != nil || !bytes.Equal(output.Bytes(), test.clone) || captured.byteLength != int64(len(test.clone)) {
				t.Fatalf("valid bounded clone refused: %#v bytes=%d err=%v", captured, output.Len(), err)
			}
			assertSnapshotDescriptorClosed(t, cloneFD)
		})
	}
}

func TestFileSnapshotCancellationAndOutputFailuresReleaseTemporaryCustody(t *testing.T) {
	for _, scenario := range []string{"before clone", "during clone", "interrupted clone", "during copy", "output failure"} {
		t.Run(scenario, func(t *testing.T) {
			source, zone := snapshotSourceFixture(t, []byte("source"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cloneFD, calls := -1, 0
			body := bytes.Repeat([]byte("x"), captureStreamBufferBytes+1)
			fixtureClone := fixtureSnapshotClone(t, source, body, &cloneFD)
			clone := func(destination, selected int) error {
				calls++
				if err := fixtureClone(destination, selected); err != nil {
					return err
				}
				if scenario == "during clone" || scenario == "interrupted clone" {
					cancel()
				}
				if scenario == "interrupted clone" {
					return unix.EINTR
				}
				return nil
			}
			written := 0
			output := snapshotWriterFunc(func(data []byte) (int, error) {
				if len(data) > captureStreamBufferBytes {
					t.Fatalf("unbounded copy chunk: %d", len(data))
				}
				if scenario == "output failure" {
					return 0, io.ErrClosedPipe
				}
				written += len(data)
				if scenario == "during copy" {
					cancel()
				}
				return len(data), nil
			})
			if scenario == "before clone" {
				cancel()
			}
			captured, err := copyClonedFile(ctx, source, int(zone.Fd()), output, MaximumCaptureBytes, clone)
			wantCause := error(context.Canceled)
			if scenario == "output failure" {
				wantCause = io.ErrClosedPipe
			}
			if !errors.Is(err, ErrUnavailable) || !errors.Is(err, wantCause) || captured != (capturedFile{}) {
				t.Fatalf("failed capture acquired a receipt or lost its cause: %#v %v", captured, err)
			}
			if scenario == "before clone" {
				if calls != 0 || cloneFD != -1 || written != 0 {
					t.Fatal("canceled request acquired snapshot custody")
				}
			} else {
				assertSnapshotDescriptorClosed(t, cloneFD)
			}
			if scenario != "during copy" && written != 0 {
				t.Fatal("failed clone exposed bytes")
			}
		})
	}
}

func TestFileSnapshotInvalidSourcesAndBoundsNeverClone(t *testing.T) {
	for _, scenario := range []string{"directory", "hardlink", "closed source", "negative bound", "excessive bound", "invalid zone"} {
		t.Run(scenario, func(t *testing.T) {
			source, zone := snapshotSourceFixture(t, []byte("source"))
			maximum := MaximumCaptureBytes
			zoneFD := int(zone.Fd())
			want := ErrConflict
			switch scenario {
			case "directory":
				source = zone
			case "hardlink":
				if err := os.Link(source.Name(), filepath.Join(zone.Name(), "alias")); err != nil {
					t.Fatal(err)
				}
			case "closed source":
				source.Close()
			case "negative bound":
				maximum, want = -1, ErrInvalidRequest
			case "excessive bound":
				maximum, want = MaximumCaptureBytes+1, ErrInvalidRequest
			case "invalid zone":
				zoneFD, want = -1, ErrUnavailable
			}
			clone := func(int, int) error { t.Fatal("invalid admission reached clone"); return nil }
			var output bytes.Buffer
			if captured, err := copyClonedFile(context.Background(), source, zoneFD, &output, maximum, clone); !errors.Is(err, want) || captured != (capturedFile{}) || output.Len() != 0 {
				t.Fatalf("invalid snapshot admitted: %#v bytes=%d err=%v", captured, output.Len(), err)
			}
		})
	}
}

func TestFileSnapshotExactGenerationAdmission(t *testing.T) {
	binding := validBinding()
	binding.FileSnapshot = FileSnapshotSource{Contract: FileSnapshotContract, Fence: binding.StopAuthority.Fence, Generation: binding.StopAuthority.TerminalGeneration.ExpectedGeneration}
	binding.StopAuthority = generationstop.StopAuthority{}
	physical := generationstop.CurrentGenerationObservation{
		Source:     binding.Source,
		Owner:      generationstop.ProviderOwner{TenantID: binding.Owner.TenantID, UserID: binding.Owner.UserID, WorkspaceID: binding.Owner.WorkspaceID, RunID: binding.Owner.RunID, GrantID: binding.Owner.GrantID},
		Fence:      binding.FileSnapshot.Fence,
		Generation: generationstop.ContainerGeneration{ExpectedGeneration: binding.FileSnapshot.Generation},
		State:      generationstop.RuntimeState{Status: "running", Running: true, PID: 42},
	}
	for name, mutate := range map[string]func(*generationstop.CurrentGenerationObservation){
		"source":    func(o *generationstop.CurrentGenerationObservation) { o.Source.ExpectedProfile += "-other" },
		"tenant":    func(o *generationstop.CurrentGenerationObservation) { o.Owner.TenantID += "-other" },
		"user":      func(o *generationstop.CurrentGenerationObservation) { o.Owner.UserID += "-other" },
		"workspace": func(o *generationstop.CurrentGenerationObservation) { o.Owner.WorkspaceID += "-other" },
		"run":       func(o *generationstop.CurrentGenerationObservation) { o.Owner.RunID += "-other" },
		"grant":     func(o *generationstop.CurrentGenerationObservation) { o.Owner.GrantID += "-other" },
		"fence": func(o *generationstop.CurrentGenerationObservation) {
			o.Fence.WorkspaceExecutionManifestRef += "-other"
		},
		"container": func(o *generationstop.CurrentGenerationObservation) {
			o.Generation.ContainerID = strings.Repeat("e", 64)
		},
		"epoch": func(o *generationstop.CurrentGenerationObservation) {
			o.Generation.ExecutionStartedAt = "2026-09-16T00:00:00.000Z"
		},
		"restarted":   func(o *generationstop.CurrentGenerationObservation) { o.Generation.RestartCount++ },
		"paused":      func(o *generationstop.CurrentGenerationObservation) { o.State.Paused = true },
		"restarting":  func(o *generationstop.CurrentGenerationObservation) { o.State.Restarting = true },
		"dead":        func(o *generationstop.CurrentGenerationObservation) { o.State.Dead = true },
		"pid missing": func(o *generationstop.CurrentGenerationObservation) { o.State.PID = 0 },
		"terminal facts while running": func(o *generationstop.CurrentGenerationObservation) {
			o.Generation.ExecutionFinishedAt = "2026-09-16T01:00:00.000Z"
		},
	} {
		t.Run(name, func(t *testing.T) {
			inspector := &capturePhysicalInspector{observation: physical}
			reader := NewNativeFileSnapshotReader(inspector)
			if _, err := reader.ObserveGeneration(context.Background(), binding); err != nil {
				t.Fatalf("valid generation refused: %v", err)
			}
			mutate(&inspector.observation)
			if _, err := reader.ObserveGeneration(context.Background(), binding); !errors.Is(err, ErrConflict) {
				t.Fatalf("changed source authority admitted: %v", err)
			}
		})
	}
}

func snapshotSourceFixture(t *testing.T, body []byte) (*os.File, *os.File) {
	t.Helper()
	directory := t.TempDir()
	name := filepath.Join(directory, "source")
	if err := os.WriteFile(name, body, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	zone, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { zone.Close() })
	return source, zone
}

func fixtureSnapshotClone(t *testing.T, source *os.File, body []byte, descriptor *int) func(int, int) error {
	t.Helper()
	return func(destination, selected int) error {
		t.Helper()
		*descriptor = destination
		if selected != int(source.Fd()) {
			t.Fatal("clone did not receive the exact selected descriptor")
		}
		var stat unix.Stat_t
		if err := unix.Fstat(destination, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 0 || stat.Mode&0077 != 0 {
			t.Fatalf("clone destination is not private: %#v %v", stat, err)
		}
		flags, err := unix.FcntlInt(uintptr(destination), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("snapshot descriptor can escape through exec: %d %v", flags, err)
		}
		status, err := unix.FcntlInt(uintptr(destination), unix.F_GETFL, 0)
		if err != nil || status&unix.O_TMPFILE != unix.O_TMPFILE {
			t.Fatalf("snapshot descriptor is not an anonymous temporary: %d %v", status, err)
		}
		for offset := 0; offset < len(body); {
			n, err := unix.Pwrite(destination, body[offset:], int64(offset))
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			offset += n
		}
		return nil
	}
}

func assertSnapshotDescriptorClosed(t *testing.T, descriptor int) {
	t.Helper()
	if descriptor < 0 {
		t.Fatal("snapshot descriptor was never observed")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); !errors.Is(err, unix.EBADF) {
		t.Fatalf("snapshot descriptor retained after return: %d %v", descriptor, err)
	}
}

type snapshotWriterFunc func([]byte) (int, error)

func (f snapshotWriterFunc) Write(data []byte) (int, error) { return f(data) }
