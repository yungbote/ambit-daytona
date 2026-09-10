// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type inventoryDockerClient struct {
	*client.Client
	archives int
}

func (c *inventoryDockerClient) CopyFromContainer(ctx context.Context, containerID, path string) (io.ReadCloser, containertypes.PathStat, error) {
	c.archives++
	return c.Client.CopyFromContainer(ctx, containerID, path)
}

func TestInventoryDockerRestores25000FilesAfterSourceDeletion(t *testing.T) {
	image := os.Getenv("DAYTONA_WORKINGCOPY_DOCKER_TEST_IMAGE")
	if image == "" {
		t.Skip("set DAYTONA_WORKINGCOPY_DOCKER_TEST_IMAGE to an installed python3 image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	name := fmt.Sprintf("workingcopy-inventory-%d-%d", os.Getpid(), time.Now().UnixNano())
	present := true
	t.Cleanup(func() {
		if !present {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if output, err := exec.CommandContext(cleanup, "docker", "rm", "-f", name).CombinedOutput(); err != nil {
			t.Errorf("remove task container: %s %v", output, err)
		}
	})
	create := `import os, pathlib, shutil
p = pathlib.Path('/workspace')
if p.exists():
    shutil.rmtree(p)
(p/'node_modules/.bin').mkdir(parents=True, exist_ok=True)
(p/'empty').mkdir()
for index in range(25000):
    name = f'package-{index:05d}-' + 'dependency-' * 8 + '.js'
    (p/'node_modules'/name).write_bytes(f'payload-{index:05d}\n'.encode() * 32)
(p/'large.bin').write_bytes(b'V' * (6 * 1024 * 1024))
os.chmod(p/'large.bin', 0o640)
os.link(p/'large.bin', p/'large-copy.bin')
os.symlink('../package-00000-' + 'dependency-' * 8 + '.js', p/'node_modules/.bin/tool')
`
	if output, err := exec.CommandContext(ctx, "docker", "run", "--pull=never", "--network", "none", "--name", name, "--user", "0", "--entrypoint", "python3", image, "-c", create).CombinedOutput(); err != nil {
		t.Fatalf("create actual dependency corpus: %s %v", output, err)
	}
	client, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	containers := &inventoryDockerClient{Client: client}
	container, err := client.ContainerInspect(ctx, name)
	if err != nil || container.State == nil || container.State.Running || container.State.ExitCode != 0 {
		t.Fatalf("corpus container did not stop successfully: %v", err)
	}
	binding := validBinding()
	binding.Source.ProviderResourceID = container.ID
	binding.StopAuthority.TerminalGeneration = generationstop.TerminalGeneration{
		ExpectedGeneration:  generationstop.ExpectedGeneration{ContainerID: container.ID, ContainerCreatedAt: container.Created, ExecutionStartedAt: container.State.StartedAt, RestartCount: container.RestartCount},
		ExecutionFinishedAt: container.State.FinishedAt, ExitCode: container.State.ExitCode, OOMKilled: container.State.OOMKilled,
	}
	objects := newFakeObjectStore()
	objects.directory = t.TempDir()
	service, err := NewService(containers, objects, dockerTestStoppedAuthority{client}, binding.Authority)
	if err != nil {
		t.Fatal(err)
	}
	request := WorkingTreeInventoryRequest{
		Generation: binding.generationBinding(), ExcludedPaths: []string{}, MaximumDepth: MaximumWorkingTreeDepth,
		MaximumFileBytes: MaximumWorkingTreeAggregateBytes, MaximumAggregateBytes: MaximumWorkingTreeAggregateBytes,
		MaximumPageEntries: MaximumWorkingTreeInventoryPageEntries, MaximumPageBytes: MaximumWorkingTreeInventoryPageBytes,
	}
	receipt, err := service.PrepareWorkingTreeInventory(ctx, container.ID, request)
	if err != nil {
		t.Fatal(err)
	}
	metadataBytes := 0
	for _, page := range receipt.Pages {
		metadataBytes += page.ByteLength
		if page.EntryCount > MaximumWorkingTreeInventoryPageEntries || page.ByteLength > MaximumWorkingTreeInventoryPageBytes {
			t.Fatal("page exceeded its transport budget")
		}
	}
	if receipt.EntryCount != 25006 || metadataBytes <= MaximumWorkingTreeInventoryPageBytes || containers.archives != 1 || objects.streamWrites != 1 || len(objects.objects) != len(receipt.Pages)+3 {
		t.Fatalf("corpus did not establish one archive, one pack and bounded pages: entries=%d metadata=%d archives=%d writes=%d objects=%d", receipt.EntryCount, metadataBytes, containers.archives, objects.streamWrites, len(objects.objects))
	}
	if err := client.ContainerRemove(ctx, container.ID, containertypes.RemoveOptions{}); err != nil {
		t.Fatal(err)
	}
	present = false
	// Restart the service and remove the source before replay and restore. All
	// subsequent operations must depend only on the inventory's object custody.
	service, err = NewService(containers, objects, dockerTestStoppedAuthority{client}, binding.Authority)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.PrepareWorkingTreeInventory(ctx, container.ID, request)
	if err != nil || replayed.InventoryDigest != receipt.InventoryDigest {
		t.Fatalf("immutable inventory replay depended on source lifetime: %v", err)
	}
	pack, err := os.CreateTemp(t.TempDir(), "restored-pack-*")
	if err != nil {
		t.Fatal(err)
	}
	defer pack.Close()
	packHash := sha256.New()
	for offset := int64(0); offset < receipt.BytePack.ByteLength; {
		read, err := service.ReadWorkingTreeInventoryRange(ctx, container.ID, WorkingTreeInventoryRangeRequest{Request: request, ProviderResourceID: receipt.ProviderResourceID, InventoryDigest: receipt.InventoryDigest, Offset: offset, MaximumBytes: MaximumReadBytes})
		if err != nil {
			t.Fatal(err)
		}
		data, err := base64.StdEncoding.DecodeString(read.BytesBase64)
		if err != nil || len(data) == 0 || int64(len(data)) > MaximumReadBytes {
			t.Fatalf("invalid bounded pack range: %v", err)
		}
		if _, err := io.MultiWriter(pack, packHash).Write(data); err != nil {
			t.Fatal(err)
		}
		offset += int64(len(data))
	}
	if "sha256:"+hex.EncodeToString(packHash.Sum(nil)) != receipt.BytePack.SHA256 {
		t.Fatal("restored physical pack digest changed")
	}
	restored := t.TempDir()
	buffer := make([]byte, captureStreamBufferBytes)
	var restoredFiles int
	for _, descriptor := range receipt.Pages {
		page, err := service.ReadWorkingTreeInventoryPage(ctx, container.ID, WorkingTreeInventoryPageRequest{Request: request, ProviderResourceID: receipt.ProviderResourceID, PageIndex: descriptor.PageIndex})
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range page.Entries {
			target := filepath.Join(restored, filepath.FromSlash(entry.ZoneRelativePath))
			switch entry.Kind {
			case "directory":
				if err := os.Mkdir(target, 0o755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(*entry.LinkTarget, target); err != nil {
					t.Fatal(err)
				}
			case "regular_file":
				var mode uint32
				if _, err := fmt.Sscanf(*entry.Mode, "%o", &mode); err != nil {
					t.Fatal(err)
				}
				file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(mode))
				if err != nil {
					t.Fatal(err)
				}
				hash := sha256.New()
				written, copyErr := io.CopyBuffer(io.MultiWriter(file, hash), io.NewSectionReader(pack, *entry.ByteOffset, entry.Size), buffer)
				closeErr := file.Close()
				if copyErr != nil || closeErr != nil || written != entry.Size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != *entry.SHA256 {
					t.Fatalf("restore changed %s: %v %v", entry.Name, copyErr, closeErr)
				}
				restoredFiles++
			default:
				t.Fatalf("unexpected corpus entry kind %s", entry.Kind)
			}
		}
	}
	verify := `import os, pathlib, stat
p = pathlib.Path('/restored')
assert len(list(p.rglob('*'))) == 25006
for index in range(25000):
    name = f'package-{index:05d}-' + 'dependency-' * 8 + '.js'
    assert (p/'node_modules'/name).read_bytes() == f'payload-{index:05d}\n'.encode() * 32
for name in ['large.bin', 'large-copy.bin']:
    assert (p/name).read_bytes() == b'V' * (6 * 1024 * 1024)
    assert stat.S_IMODE((p/name).stat().st_mode) == 0o640
assert os.readlink(p/'node_modules/.bin/tool') == '../package-00000-' + 'dependency-' * 8 + '.js'
assert list((p/'empty').iterdir()) == []
print('Restored 25002 files, exact bytes and permissions, lexical symlink and empty directory.')
`
	if output, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--pull=never", "--network", "none", "--user", "0", "--mount", "type=bind,src="+restored+",dst=/restored,readonly", "--entrypoint", "python3", image, "-c", verify).CombinedOutput(); err != nil {
		t.Fatalf("fresh Docker consumer rejected restored corpus: %s %v", output, err)
	} else {
		t.Log(string(output))
	}
	if containers.archives != 1 || int64(len(objects.rangeReads)) != (receipt.BytePack.ByteLength+MaximumReadBytes-1)/MaximumReadBytes {
		t.Fatalf("restore made per-file provider requests: archives=%d ranges=%d", containers.archives, len(objects.rangeReads))
	}
	if _, err := service.DeleteWorkingTreeInventory(ctx, container.ID, request); err != nil || len(objects.objects) != 1 {
		t.Fatalf("inventory did not retire all page and byte custody: %v", err)
	}
	t.Logf("entries=%d files=%d metadata_bytes=%d pages=%d pack_bytes=%d aggregate_restored_bytes=%d archive_passes=%d pack_objects=%d range_requests=%d maximum_range_bytes=%d remaining_objects=%d", receipt.EntryCount, restoredFiles, metadataBytes, len(receipt.Pages), receipt.BytePack.ByteLength, receipt.AggregateBytes, containers.archives, objects.streamWrites, len(objects.rangeReads), MaximumReadBytes, len(objects.objects))
}
