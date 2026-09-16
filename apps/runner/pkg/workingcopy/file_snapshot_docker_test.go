// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/generationstopdocker"
	"github.com/daytonaio/runner/pkg/sandboxsecurity"
	"github.com/docker/docker/client"
)

// Run this binary inside a disposable DinD Runner to exercise the production
// daemon/PID/mount relationship on a separately qualified reflink-backed
// filesystem. The browser image must already be installed. An unsupported
// filesystem fails this acceptance; it never substitutes a non-atomic copy.
func TestFileSnapshotDockerBrowserAndCustody(t *testing.T) {
	image := os.Getenv("DAYTONA_FILE_SNAPSHOT_BROWSER_IMAGE")
	if image == "" {
		t.Skip("requires an installed browser image and Docker in the Runner PID namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	name := fmt.Sprintf("file-snapshot-browser-%d-%d", os.Getpid(), time.Now().UnixNano())
	// The image reference selects what to run; the config ID proves what ran.
	// It must come from an independent inspection of the approved registry
	// digest, never from the daemon this test drives.
	expectedImage := os.Getenv("DAYTONA_FILE_SNAPSHOT_EXPECTED_IMAGE_ID")
	if len(expectedImage) != len("sha256:")+64 || !strings.HasPrefix(expectedImage, "sha256:") {
		t.Fatal("require an independently resolved immutable Docker image config ID")
	}
	run := func(args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %v: %s %v", args, out, err)
		}
		return out
	}
	binding := validBinding()
	binding.Source.ProviderResourceID = name
	labels := map[string]string{
		"ambitTenantId": binding.Owner.TenantID, "ambitPrincipalId": binding.Owner.UserID,
		"ambitWorkspaceId": binding.Owner.WorkspaceID, "ambitTaskId": binding.Owner.RunID,
		"ambitGrantId": binding.Owner.GrantID, "ambitProfile": binding.Source.ExpectedProfile,
		"ambitWorkspaceExecutionManifestRef": binding.StopAuthority.Fence.WorkspaceExecutionManifestRef,
		"ambitRuntimeKind":                   "full_image_runtime_pack_provider_observation",
		"ambitRuntimeWorkspaceId":            binding.Owner.WorkspaceID, "ambitRuntimeProductRunId": binding.Owner.RunID,
		"ambitRuntimeGrantId": binding.Owner.GrantID, "ambitRuntimeManifestRef": binding.StopAuthority.Fence.WorkspaceExecutionManifestRef,
	}
	seccomp := t.TempDir() + "/seccomp.json"
	if err := os.WriteFile(seccomp, []byte(sandboxsecurity.RootlessSeccomp()), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + seccomp, "--pull=never", "--detach", "--name", name, "--network", "none", "--entrypoint", "sh"}
	for key, value := range labels {
		args = append(args, "--label", key+"="+value)
	}
	args = append(args, image, "-c", "mkdir -p /workspace/work /workspace/outputs && exec sleep 600")
	run(args...)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if out, err := exec.CommandContext(cleanup, "docker", "rm", "-f", name).CombinedOutput(); err != nil {
			t.Errorf("container cleanup: %s %v", out, err)
		}
	})
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	defer docker.Close()
	inspected, err := docker.ContainerInspect(ctx, name)
	if err != nil || inspected.Image != expectedImage {
		t.Fatalf("source image differs from independent immutable image proof: actual=%s expected=%s err=%v", inspected.Image, expectedImage, err)
	}
	t.Logf("source image identity: config=%s sandbox=%s", inspected.Image, inspected.ID)
	adapter, err := generationstopdocker.New(docker)
	if err != nil {
		t.Fatal(err)
	}
	before, err := adapter.InspectGeneration(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	binding.FileSnapshot = FileSnapshotSource{Contract: FileSnapshotContract, Fence: before.Fence, Generation: before.Generation.ExpectedGeneration}
	binding.StopAuthority = generationstop.StopAuthority{}
	binding.Selector = CaptureSelector{SemanticZoneRef: "ambit.workspace-zone/outputs@1", ZoneRelativePath: "browser.png"}
	encoded, _ := json.Marshal(binding)
	var wire CaptureBinding
	if err := DecodeExactJSON(encoded, &wire); err != nil || wire != binding {
		t.Fatalf("snapshot wire differs: %s %v", encoded, err)
	}
	run("exec", name, "agent-browser", "open", "data:text/html,<title>Live capture</title><button onclick='this.textContent=Number(this.textContent)+1'>0</button>")
	run("exec", name, "agent-browser", "screenshot", "/workspace/outputs/browser.png")
	body := run("exec", name, "cat", "/workspace/outputs/browser.png")
	reader := NewNativeFileSnapshotReader(adapter)
	var snapshot bytes.Buffer
	// A browser control operation runs while the private clone is streamed.
	// The browser and the workspace generation must remain alive.
	once := false
	writer := snapshotWriterFunc(func(data []byte) (int, error) {
		if !once {
			once = true
			run("exec", name, "agent-browser", "click", "button")
		}
		return snapshot.Write(data)
	})
	proof, err := reader.Capture(ctx, binding, writer, MaximumCaptureBytes)
	if err != nil || !bytes.Equal(snapshot.Bytes(), body) || proof.digest != sha256Digest(body) {
		t.Fatalf("browser snapshot differs: %#v %v", proof, err)
	}
	if out := run("exec", name, "agent-browser", "get", "text", "button"); !strings.Contains("\n"+strings.TrimSpace(string(out))+"\n", "\n1\n") {
		t.Fatalf("live browser lost control: %s", out)
	}
	after, err := adapter.InspectGeneration(ctx, name)
	if err != nil || after.Generation != before.Generation || after.State.PID != before.State.PID || !after.State.Running {
		t.Fatalf("capture altered workspace generation: %#v %v", after, err)
	}
	objects := newFakeObjectStore()
	objects.directory = t.TempDir()
	service, err := NewService(docker, objects, rejectSnapshotStopAuthority{}, testCaptureComponent(binding.Authority), nil, reader)
	if err != nil {
		t.Fatal(err)
	}
	objects.failAfterStoreSuffix = "/content.bin"
	first, err := service.Capture(ctx, name, binding)
	if err != nil {
		t.Fatal(err)
	}
	objects.failAfterStoreSuffix = ""
	// Browser close is a file-independent process control, not sandbox stop.
	run("exec", name, "agent-browser", "close")
	run("exec", name, "sh", "-c", "printf later > /workspace/outputs/browser.png")
	restarted, err := NewService(docker, objects, rejectSnapshotStopAuthority{}, testCaptureComponent(binding.Authority), nil, reader)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Capture(ctx, name, binding)
	if err != nil || first != replayed {
		t.Fatalf("restart recaptured source: %#v %v", replayed, err)
	}
	download, err := restarted.Read(ctx, name, CaptureReadRequest{CaptureIdentity: first.CaptureIdentity, ExpectedTotalByteLength: first.TotalByteLength, ExpectedProviderSHA256Digest: first.ProviderSHA256Digest, MaximumBytes: MaximumReadBytes})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(download.BytesBase64)
	if err != nil || !bytes.Equal(decoded, body) {
		t.Fatalf("download differs: %v", err)
	}
	if _, err := restarted.Delete(ctx, name, first.CaptureIdentity); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Capture(ctx, name, binding); !errors.Is(err, ErrConflict) {
		t.Fatalf("retired capture recreated: %v", err)
	}
	if evidence := os.Getenv("DAYTONA_FILE_SNAPSHOT_EVIDENCE_DIR"); evidence != "" {
		if err := os.MkdirAll(evidence, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(evidence+"/browser.png", body, 0600); err != nil {
			t.Fatal(err)
		}
		data, _ := json.MarshalIndent(map[string]any{"before": before, "after": after, "receipt": first, "bytes": len(body), "sourceImageId": inspected.Image, "sourceContainerId": inspected.ID}, "", "  ")
		if err := os.WriteFile(evidence+"/native-proof.json", data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("exact browser bytes=%d digest=%s generation=%s PID=%d; no stop authority invoked", len(body), proof.digest, before.Generation.ExecutionStartedAt, before.State.PID)

	run("exec", name, "sh", "-c", "mkdir -p /workspace/outputs/sub && printf intact > /workspace/outputs/sub/source")
	// A later ordinary file may be published after an independent stop. It
	// reuses the observed stopped-file reader without waking or stopping it.
	run("stop", name)
	stopped, err := adapter.InspectGeneration(ctx, name)
	if err != nil || stopped.State.Running || stopped.State.PID != 0 {
		t.Fatalf("source did not become stopped: %#v %v", stopped, err)
	}
	stoppedBinding := binding
	stoppedBinding.ProviderName += "-already-stopped"
	stoppedBinding.RequestFingerprint = strings.Repeat("e", 64)
	stoppedBinding.FileSnapshot.Generation = stopped.Generation.ExpectedGeneration
	stoppedBinding.Selector.ZoneRelativePath = "sub/source"
	stoppedReceipt, err := restarted.Capture(ctx, name, stoppedBinding)
	if err != nil || stoppedReceipt.ProviderSHA256Digest != sha256Digest([]byte("intact")) {
		t.Fatalf("already-stopped file capture failed: %#v %v", stoppedReceipt, err)
	}
	stoppedRange, err := restarted.Read(ctx, name, CaptureReadRequest{CaptureIdentity: stoppedReceipt.CaptureIdentity, ExpectedTotalByteLength: stoppedReceipt.TotalByteLength, ExpectedProviderSHA256Digest: stoppedReceipt.ProviderSHA256Digest, MaximumBytes: MaximumReadBytes})
	if err != nil {
		t.Fatal(err)
	}
	stoppedBytes, err := base64.StdEncoding.DecodeString(stoppedRange.BytesBase64)
	if err != nil || string(stoppedBytes) != "intact" {
		t.Fatalf("stopped source download differs: %q %v", stoppedBytes, err)
	}
	stillStopped, err := adapter.InspectGeneration(ctx, name)
	if err != nil || stillStopped != stopped {
		t.Fatalf("file publication mutated stopped source: %#v %v", stillStopped, err)
	}
	if evidence := os.Getenv("DAYTONA_FILE_SNAPSHOT_EVIDENCE_DIR"); evidence != "" {
		proof, _ := json.MarshalIndent(map[string]any{"before": stopped, "after": stillStopped, "receipt": stoppedReceipt, "sourceImageId": inspected.Image, "sourceContainerId": inspected.ID}, "", "  ")
		if err := os.WriteFile(evidence+"/stopped-source-proof.json", proof, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := restarted.Delete(ctx, name, stoppedReceipt.CaptureIdentity); err != nil {
		t.Fatal(err)
	}
	t.Logf("already-stopped publication passed without wake or stop dispatch: epoch=%s", stopped.Generation.ExecutionStartedAt)

}

type rejectSnapshotStopAuthority struct{}

func (rejectSnapshotStopAuthority) RequireCurrentReceipt(context.Context, generationstop.Source, generationstop.Owner, generationstop.Purpose, generationstop.StopAuthority) (generationstop.Receipt, error) {
	return generationstop.Receipt{}, errors.New("file snapshot invoked stop authority")
}

var _ io.Writer = snapshotWriterFunc(nil)
