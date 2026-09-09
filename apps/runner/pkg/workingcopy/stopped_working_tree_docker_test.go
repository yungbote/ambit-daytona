// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/docker/docker/client"
)

// Opt-in because the suite must never pull an image or require Docker merely
// to test deterministic archive admission. Supply an already-installed image
// with python3; the container and its bind mount belong only to this test.
func TestStoppedWorkingTreeDockerArchive(t *testing.T) {
	image := os.Getenv("DAYTONA_WORKINGCOPY_DOCKER_TEST_IMAGE")
	if image == "" {
		t.Skip("set DAYTONA_WORKINGCOPY_DOCKER_TEST_IMAGE to an installed python3 image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	name := fmt.Sprintf("workingcopy-portable-%d-%d", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if output, err := exec.CommandContext(cleanup, "docker", "rm", "-f", name).CombinedOutput(); err != nil {
			t.Errorf("remove task container: %s %v", output, err)
		}
	})
	mounted := t.TempDir()
	if err := os.WriteFile(mounted+"/private.txt", []byte("mount custody"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `import os, pathlib, socket, stat
p = pathlib.Path('/workspace')
p.mkdir(exist_ok=True)
for d in ['packages/pkg', 'node_modules/@scope', '.ambit']:
    (p/d).mkdir(parents=True, exist_ok=True)
(p/'packages/pkg/index.js').write_bytes(b'package bytes')
os.link(p/'packages/pkg/index.js', p/'hardlinked.js')
(p/'customer-large.bin').write_bytes(b'x' * (6 * 1024 * 1024))
(p/'.ambit/managed').write_text('managed runtime')
for name, target in [('node_modules/@scope/pkg', '../../packages/pkg'), ('dangling-link', '../missing'), ('absolute-link', '/outside'), ('unicode-link', '../e\u0301'), ('control-link', '../a\nb')]:
    os.symlink(target, p/name)
os.mkfifo(p/'runtime.pipe')
os.mknod(p/'runtime.char', stat.S_IFCHR | 0o600, os.makedev(1, 3))
os.mknod(p/'runtime.block', stat.S_IFBLK | 0o600, os.makedev(7, 0))
s = socket.socket(socket.AF_UNIX)
s.bind(str(p/'runtime.sock'))
s.close()
`
	if output, err := exec.CommandContext(ctx, "docker", "run", "--pull=never", "--name", name,
		"--network", "none", "--user", "0", "--mount", "type=bind,src="+mounted+",dst=/workspace/mounted,readonly",
		"--entrypoint", "python3", image, "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("prepare task container: %s %v", output, err)
	}
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	defer docker.Close()
	container, err := docker.ContainerInspect(ctx, name)
	if err != nil || container.State == nil || container.State.Running || container.State.ExitCode != 0 {
		t.Fatalf("task container did not exit successfully: %v", err)
	}
	binding := validBinding()
	binding.Source.ProviderResourceID = container.ID
	binding.Selector = CaptureSelector{SemanticZoneRef: userFilesSemanticZoneRef, ZoneRelativePath: "customer-large.bin"}
	binding.StopAuthority.TerminalGeneration = generationstop.TerminalGeneration{
		ExpectedGeneration: generationstop.ExpectedGeneration{
			ContainerID: container.ID, ContainerCreatedAt: container.Created,
			ExecutionStartedAt: container.State.StartedAt, RestartCount: container.RestartCount,
		},
		ExecutionFinishedAt: container.State.FinishedAt, ExitCode: container.State.ExitCode, OOMKilled: container.State.OOMKilled,
	}
	objects := newFakeObjectStore()
	service, err := NewService(docker, objects, dockerTestStoppedAuthority{docker}, binding.Authority)
	if err != nil {
		t.Fatal(err)
	}
	request := StoppedWorkingTreeRequest{
		Generation: binding.generationBinding(), ExcludedPaths: []string{"mounted"},
		MaximumDepth: MaximumWorkingTreeDepth, MaximumEntries: MaximumWorkingTreeEntries,
		MaximumFileBytes: MaximumCaptureBytes, MaximumAggregateBytes: MaximumWorkingTreeAggregateBytes,
	}
	roster, err := service.StoppedWorkingTree(ctx, container.ID, request)
	if err != nil {
		t.Fatal(err)
	}
	entries := make(map[string]StoppedWorkingTreeEntry, len(roster.Entries))
	for _, entry := range roster.Entries {
		if reservedWorkingTreePath(entry.ZoneRelativePath) || strings.HasPrefix(entry.ZoneRelativePath, "mounted") {
			t.Fatalf("managed or mounted bytes entered private roster: %#v", entry)
		}
		entries[entry.ZoneRelativePath] = entry
	}
	if original, linked := entries["packages/pkg/index.js"], entries["hardlinked.js"]; original.Kind != "regular_file" || linked.Kind != "regular_file" || original.SHA256 == nil || linked.SHA256 == nil || *original.SHA256 != *linked.SHA256 || original.Size != linked.Size {
		t.Fatalf("Docker hardlink did not materialize as ordinary file bytes: original=%#v linked=%#v", original, linked)
	}
	for name, target := range map[string]string{
		"node_modules/@scope/pkg": "../../packages/pkg", "dangling-link": "../missing",
		"absolute-link": "/outside", "unicode-link": "../e\u0301", "control-link": "../a\nb",
	} {
		entry := entries[name]
		if entry.Kind != "symlink" || entry.LinkTarget == nil || *entry.LinkTarget != target {
			t.Fatalf("Docker symlink target changed: %#v", entry)
		}
	}
	for name, kind := range map[string]string{"runtime.pipe": "fifo", "runtime.char": "character_device", "runtime.block": "block_device"} {
		if entry := entries[name]; entry.Kind != "excluded" || entry.ExcludedKind != kind {
			t.Fatalf("runtime omission was not explicit: %#v", entry)
		}
	}
	if _, exists := entries["runtime.sock"]; exists {
		t.Fatal("Docker socket omission unexpectedly changed; reassess archive custody")
	}
	if len(objects.objects) != 0 {
		t.Fatal("roster wrote durable file bytes")
	}
	receipt, err := service.Capture(ctx, container.ID, binding)
	if err != nil || receipt.TotalByteLength != 6*1024*1024 || entries["customer-large.bin"].SHA256 == nil ||
		receipt.ProviderSHA256Digest != *entries["customer-large.bin"].SHA256 {
		t.Fatalf("Docker streamed capture differs from roster: %#v %v", receipt, err)
	}
	var recovered []byte
	for offset := int64(0); offset < receipt.TotalByteLength; {
		rangeRead, err := service.Read(ctx, container.ID, CaptureReadRequest{
			CaptureIdentity: receipt.CaptureIdentity, ExpectedTotalByteLength: receipt.TotalByteLength,
			ExpectedProviderSHA256Digest: receipt.ProviderSHA256Digest, Offset: offset, MaximumBytes: MaximumReadBytes,
		})
		if err != nil {
			t.Fatal(err)
		}
		part, err := base64.StdEncoding.DecodeString(rangeRead.BytesBase64)
		if err != nil || len(part) == 0 || int64(len(part)) > MaximumReadBytes {
			t.Fatalf("invalid private range: %v", err)
		}
		recovered = append(recovered, part...)
		offset += int64(len(part))
	}
	if sha256Digest(recovered) != receipt.ProviderSHA256Digest {
		t.Fatal("Docker capture did not round trip through bounded reads")
	}
	for _, selected := range []string{"packages/pkg/index.js", "hardlinked.js"} {
		changed := binding
		changed.Selector.ZoneRelativePath = selected
		changed.RequestFingerprint = hashHex(selected)
		captured, err := service.Capture(ctx, container.ID, changed)
		if err != nil || captured.TotalByteLength != 13 || captured.ProviderSHA256Digest != sha256Digest([]byte("package bytes")) {
			t.Fatalf("Docker hardlink file capture changed bytes %s: %#v %v", selected, captured, err)
		}
	}
	for _, selected := range []string{"absolute-link", "node_modules/@scope/pkg/index.js"} {
		changed := binding
		changed.Selector.ZoneRelativePath = selected
		changed.RequestFingerprint = hashHex(selected)
		if _, err := service.Capture(ctx, container.ID, changed); !errors.Is(err, ErrConflict) {
			t.Fatalf("private file capture followed symlink %s: %v", selected, err)
		}
	}
	if _, err := service.Delete(ctx, container.ID, receipt.CaptureIdentity); err != nil {
		t.Fatal(err)
	}
	t.Log("Real Docker: lexical links preserved; FIFO/devices recorded; socket omitted; managed roots and bind mount excluded; 6MiB file captured and read in 4MiB ranges without following links.")
}

type dockerTestStoppedAuthority struct{ docker *client.Client }

func (a dockerTestStoppedAuthority) RequireCurrentReceipt(ctx context.Context, source generationstop.Source, owner generationstop.Owner, purpose generationstop.Purpose, authority generationstop.StopAuthority) (generationstop.Receipt, error) {
	if err := generationstop.ValidateBinding(source, owner, authority); err != nil {
		return generationstop.Receipt{}, err
	}
	container, err := a.docker.ContainerInspect(ctx, authority.TerminalGeneration.ContainerID)
	if err != nil {
		return generationstop.Receipt{}, err
	}
	terminal := authority.TerminalGeneration
	if container.State == nil || container.State.Running || container.State.Pid != 0 ||
		container.ID != source.ProviderResourceID || container.Created != terminal.ContainerCreatedAt ||
		container.State.StartedAt != terminal.ExecutionStartedAt || container.State.FinishedAt != terminal.ExecutionFinishedAt ||
		container.RestartCount != terminal.RestartCount || container.State.ExitCode != terminal.ExitCode ||
		container.State.OOMKilled != terminal.OOMKilled || purpose.Kind != generationstop.PurposeWorkingCopyCapture {
		return generationstop.Receipt{}, generationstop.ErrConflict
	}
	return generationstop.Receipt{TerminalGeneration: terminal}, nil
}
