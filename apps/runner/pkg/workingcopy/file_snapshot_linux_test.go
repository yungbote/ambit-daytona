// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFileSnapshotLeaseCopiesExactBytesAndReleasesWriterExclusion(t *testing.T) {
	for _, body := range [][]byte{{}, bytes.Repeat([]byte("exact bytes\x00"), 30000)} {
		path := filepath.Join(t.TempDir(), "output.bin")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		source, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		var result bytes.Buffer
		captured, err := copyLeasedFile(context.Background(), source, &result, MaximumCaptureBytes)
		if err != nil || !bytes.Equal(result.Bytes(), body) || captured.digest != sha256Digest(body) || captured.byteLength != int64(len(body)) {
			t.Fatalf("snapshot differs: %#v %v", captured, err)
		}
		lease, err := unix.FcntlInt(source.Fd(), unix.F_GETLEASE, 0)
		if err != nil || lease != unix.F_UNLCK {
			t.Fatalf("lease leaked: %d %v", lease, err)
		}
		if err := os.WriteFile(path, []byte("later"), 0600); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(result.Bytes(), body) {
			t.Fatal("snapshot followed later writes")
		}
	}
}

func TestFileSnapshotRejectsExistingWritableDescriptionsAndMappings(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "output")
		if err := os.WriteFile(path, bytes.Repeat([]byte("a"), 4096), 0600); err != nil {
			t.Fatal(err)
		}
		writer, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		if mapped {
			memory, err := unix.Mmap(int(writer.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Munmap(memory)
			writer.Close() // A writable mmap remains a writer after close(fd).
		}
		source, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		var result bytes.Buffer
		if _, err := copyLeasedFile(context.Background(), source, &result, MaximumCaptureBytes); !errors.Is(err, ErrUnavailable) || result.Len() != 0 {
			t.Fatalf("existing writer/mapping admitted: mapped=%v bytes=%d err=%v", mapped, result.Len(), err)
		}
	}
}

func TestFileSnapshotRejectsConcurrentWriterWithoutAdmittingMixedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), 256*1024), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	called := false
	writer := snapshotWriterFunc(func(data []byte) (int, error) {
		if !called {
			called = true
			fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
			if err == nil {
				unix.Close(fd)
				t.Fatal("writer entered while lease held")
			}
			if !errors.Is(err, unix.EWOULDBLOCK) {
				t.Fatalf("writer had unexpected error: %v", err)
			}
		}
		return len(data), nil
	})
	if _, err := copyLeasedFile(context.Background(), source, writer, MaximumCaptureBytes); !errors.Is(err, ErrConflict) {
		t.Fatalf("lease break did not discard capture: %v", err)
	}
	if err := os.WriteFile(path, []byte("writer progresses"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestFileSnapshotCancellationBoundsAndHardlinksReleaseCustody(t *testing.T) {
	for _, scenario := range []string{"cancel", "output failure", "hardlink", "too large"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "output")
			if err := os.WriteFile(path, bytes.Repeat([]byte("a"), 4096), 0600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			maximum := MaximumCaptureBytes
			var writer io.Writer = io.Discard
			switch scenario {
			case "cancel":
				writer = snapshotWriterFunc(func(data []byte) (int, error) { cancel(); return len(data), nil })
			case "output failure":
				writer = snapshotWriterFunc(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
			case "hardlink":
				if err := os.Link(path, path+"-alias"); err != nil {
					t.Fatal(err)
				}
			case "too large":
				maximum = 2048
			}
			if _, err := copyLeasedFile(ctx, source, writer, maximum); err == nil {
				t.Fatal("invalid snapshot succeeded")
			}
			lease, err := unix.FcntlInt(source.Fd(), unix.F_GETLEASE, 0)
			if err != nil || lease != unix.F_UNLCK {
				t.Fatalf("failed copy leaked lease: %d %v", lease, err)
			}
		})
	}
}

type snapshotWriterFunc func([]byte) (int, error)

func (f snapshotWriterFunc) Write(data []byte) (int, error) { return f(data) }

func TestFileSnapshotKernelForcedLeaseBreakDiscardsCopy(t *testing.T) {
	if os.Getenv("DAYTONA_FILE_SNAPSHOT_FORCE_BREAK_TEST") != "1" {
		t.Skip("opt in to the real kernel lease-break timeout")
	}
	raw, err := os.ReadFile("/proc/sys/fs/lease-break-time")
	if err != nil {
		t.Fatal(err)
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || seconds < 1 || seconds > 60 {
		t.Fatalf("unsupported test timeout: %s %v", raw, err)
	}
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds+10)*time.Second)
	defer cancel()
	started := time.Now()
	writer := snapshotWriterFunc(func(data []byte) (int, error) {
		finished := make(chan error, 1)
		go func() { finished <- os.WriteFile(path, []byte("after!"), 0600) }()
		select {
		case err := <-finished:
			return len(data), err
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	if _, err := copyLeasedFile(ctx, source, writer, MaximumCaptureBytes); !errors.Is(err, ErrConflict) {
		t.Fatalf("forced lease break admitted bytes: %v", err)
	}
	if time.Since(started) < time.Duration(seconds-1)*time.Second {
		t.Fatal("writer entered before kernel timeout")
	}
	if lease, err := unix.FcntlInt(source.Fd(), unix.F_GETLEASE, 0); err != nil || lease != unix.F_UNLCK {
		t.Fatalf("lease remains after force break: %d %v", lease, err)
	}
	t.Logf("kernel forced lease break after %s; capture rejected and writer progressed", time.Since(started))
}
