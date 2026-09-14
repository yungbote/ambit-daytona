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
	"os/exec"
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
		captured, err := copyLeasedFile(context.Background(), source, sameFile(source), &result, MaximumCaptureBytes)
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
		if _, err := copyLeasedFile(context.Background(), source, sameFile(source), &result, MaximumCaptureBytes); !errors.Is(err, ErrUnavailable) || result.Len() != 0 {
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
	if _, err := copyLeasedFile(context.Background(), source, sameFile(source), writer, MaximumCaptureBytes); !errors.Is(err, ErrConflict) {
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
			if _, err := copyLeasedFile(ctx, source, sameFile(source), writer, maximum); err == nil {
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
	if _, err := copyLeasedFile(ctx, source, sameFile(source), writer, MaximumCaptureBytes); !errors.Is(err, ErrConflict) {
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

func sameFile(file *os.File) func() (*os.File, error) {
	return func() (*os.File, error) { return file, nil }
}

type fakeUpperLayer string

func (upper fakeUpperLayer) InspectUpperLayer(context.Context, string) (string, error) {
	return string(upper), nil
}

// TestFileSnapshotOverlayWriterBearingInode mounts a private overlayfs in a
// user namespace and drives the reader's bearing-file resolution through it:
// a lower-only file is leased directly, a copied-up file additionally leases
// its upper inode (and refuses a shared writable mapping that outlived its
// descriptor), a mismatched upper is rejected, and a zone on a foreign
// overlay mount is refused.
func TestFileSnapshotOverlayWriterBearingInode(t *testing.T) {
	if os.Getenv("DAYTONA_OVERLAY_TEST_INNER") == "" {
		for _, tool := range []string{"unshare", "python3"} {
			if _, err := exec.LookPath(tool); err != nil {
				t.Skipf("%s is unavailable", tool)
			}
		}
		if out, err := exec.Command("unshare", "-Urm", "true").CombinedOutput(); err != nil {
			t.Skipf("unprivileged user and mount namespaces are unavailable: %s %v", out, err)
		}
		inner := exec.Command("unshare", "-Urm", os.Args[0], "-test.run", "^TestFileSnapshotOverlayWriterBearingInode$", "-test.v", "-test.count=1")
		inner.Env = append(os.Environ(), "DAYTONA_OVERLAY_TEST_INNER=1")
		out, err := inner.CombinedOutput()
		if err != nil {
			if strings.Contains(string(out), "overlay mount unsupported") {
				t.Skipf("user namespace overlay mount unsupported: %s", out)
			}
			t.Fatalf("inner overlay test failed: %s %v", out, err)
		}
		if !strings.Contains(string(out), "--- PASS: TestFileSnapshotOverlayWriterBearingInode") {
			t.Fatalf("inner overlay test did not run to a pass: %s", out)
		}
		t.Logf("inner overlay test:\n%s", out)
		return
	}
	root := t.TempDir()
	for _, dir := range []string{"lower/zone", "upper", "work", "merged", "other/zone", "lower2", "upper2", "work2"} {
		if err := os.MkdirAll(root+"/"+dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(root+"/lower/zone/only", []byte("lower-only-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/lower/zone/promoted", []byte("promoted-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	options := fmt.Sprintf("lowerdir=%s/lower,upperdir=%s/upper,workdir=%s/work", root, root, root)
	if err := unix.Mount("overlay", root+"/merged", "overlay", 0, options); err != nil {
		t.Fatalf("overlay mount unsupported: %v", err)
	}
	defer unix.Unmount(root+"/merged", unix.MNT_DETACH)
	// Copy up "promoted" through the merged view and create a pure-upper file.
	if err := os.Chmod(root+"/merged/zone/promoted", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/merged/zone/fresh", []byte("fresh-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	rootFD, err := unix.Open(root+"/merged", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	reader := &NativeFileSnapshotReader{upperLayers: fakeUpperLayer(root + "/upper")}
	binding := validBinding()
	capture := func(path string, r *NativeFileSnapshotReader) (capturedFile, *bytes.Buffer, error) {
		selected, err := os.OpenFile(root+"/merged"+path, os.O_RDONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer selected.Close()
		var result bytes.Buffer
		captured, err := copyLeasedFile(context.Background(), selected, func() (*os.File, error) {
			return r.openWriterBearingFile(context.Background(), binding, rootFD, selected, path)
		}, &result, MaximumCaptureBytes)
		return captured, &result, err
	}
	for _, path := range []string{"/zone/only", "/zone/promoted", "/zone/fresh"} {
		captured, result, err := capture(path, reader)
		expected, readErr := os.ReadFile(root + "/merged" + path)
		if err != nil || readErr != nil || !bytes.Equal(result.Bytes(), expected) || captured.byteLength != int64(len(expected)) {
			t.Fatalf("%s: coherent copy failed: %v %v %q", path, err, readErr, result.Bytes())
		}
	}
	if _, err := os.Stat(root + "/upper/zone/only"); !os.IsNotExist(err) {
		t.Fatalf("lower-only file was copied up by the reader: %v", err)
	}
	// A shared writable mapping whose only descriptor is closed must be
	// refused for a copied-up file: only the upper inode still counts it.
	holder := exec.Command("python3", "-c", `
import ctypes, os, sys, time
libc=ctypes.CDLL(None, use_errno=True); libc.mmap.restype=ctypes.c_void_p
libc.mmap.argtypes=[ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
fd=os.open(sys.argv[1], os.O_RDWR); size=os.fstat(fd).st_size
addr=libc.mmap(None, size, 3, 1, fd, 0); os.close(fd)
assert not any(os.readlink('/proc/self/fd/'+x).endswith('/fresh') for x in os.listdir('/proc/self/fd') if os.path.exists('/proc/self/fd/'+x))
ctypes.memset(addr, ord('z'), size)
print('ready', flush=True)
time.sleep(60)
`, root+"/merged/zone/fresh")
	ready, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer holder.Process.Kill()
	if line := make([]byte, 6); func() error { _, err := io.ReadFull(ready, line); return err }() != nil || string(line) != "ready\n" {
		t.Fatalf("mapping holder did not become ready: %q", line)
	}
	// The overlay inode alone still grants a lease to this mapping; only the
	// upper inode refuses it, so the refusal below must come from that lease.
	overlayOnly, err := os.OpenFile(root+"/merged/zone/fresh", os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	var overlayCopy bytes.Buffer
	if _, err := copyLeasedFile(context.Background(), overlayOnly, sameFile(overlayOnly), &overlayCopy, MaximumCaptureBytes); err != nil {
		t.Fatalf("overlay-only lease unexpectedly refused the descriptorless mapping: %v", err)
	}
	overlayOnly.Close()
	if _, _, err := capture("/zone/fresh", reader); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("descriptorless writable mapping was not refused as unavailable: %v", err)
	}
	holder.Process.Kill()
	// An upper layer that does not describe the selected file is a conflict.
	if err := os.MkdirAll(root+"/other/zone", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/other/zone/promoted", []byte("someone else"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := capture("/zone/promoted", &NativeFileSnapshotReader{upperLayers: fakeUpperLayer(root + "/other")}); !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched upper layer was not rejected as a conflict: %v", err)
	}
	// A zone that is itself a foreign overlay mount has no known upper layer.
	if err := os.WriteFile(root+"/lower2/foreign", []byte("foreign-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root+"/merged/foreign-zone", 0o755); err != nil {
		t.Fatal(err)
	}
	options2 := fmt.Sprintf("lowerdir=%s/lower2,upperdir=%s/upper2,workdir=%s/work2", root, root, root)
	if err := unix.Mount("overlay", root+"/merged/foreign-zone", "overlay", 0, options2); err != nil {
		t.Fatalf("second overlay mount: %v", err)
	}
	defer unix.Unmount(root+"/merged/foreign-zone", unix.MNT_DETACH)
	if _, _, err := capture("/foreign-zone/foreign", reader); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("foreign overlay zone was not refused as unavailable: %v", err)
	}
}
