// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package specialistrenderdocker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/google/uuid"
)

// This opt-in integration test uses the production Docker adapter. The parent
// and every child are task-owned containers; no product workspace is entered.
// Inputs are Office fixtures plus their canonical convert_to_pdf commands.
func TestOfficePDFPrivateIntegration(t *testing.T) {
	imageRef := os.Getenv("AMBIT_OFFICE_TEST_IMAGE")
	if imageRef == "" {
		t.Skip("AMBIT_OFFICE_TEST_IMAGE is required for private native integration")
	}
	inputRoot := os.Getenv("AMBIT_OFFICE_TEST_INPUTS")
	outputRoot := os.Getenv("AMBIT_OFFICE_TEST_OUTPUTS")
	sourceRoot := os.Getenv("AMBIT_OFFICE_TEST_SOURCE")
	for _, path := range []string{inputRoot, outputRoot, sourceRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatal("absolute fixture, output and exact specialist source directories are required")
		}
	}
	if err := os.Mkdir(outputRoot, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	defer docker.Close()
	image, err := docker.ImageInspect(ctx, imageRef)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(imageRef, "@sha256:") || image.Config == nil ||
		image.Config.Labels["io.ambit.runtime-pack"] != "ambit.runtime-pack/office-authoring@2" {
		t.Fatal("the immutable Office revision two image is required")
	}
	info, err := docker.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy := specialistrender.Policy{
		Authority:         specialistrender.Pin{Ref: "ambit.runtime-provider/specialist-render-office-authoring@2"},
		Composition:       specialistrender.Pin{Ref: "ambit.office-qualification/composition@1", Digest: officeTestDigest([]byte(imageRef))},
		Image:             specialistrender.ImagePin{Ref: imageRef, ConfigDigest: image.ID, PackID: "office-authoring", PackRef: "ambit.runtime-pack/office-authoring@2"},
		Executable:        "/opt/ambit/runtime-pack/office-authoring/bin/ambit-specialist-render",
		EnvironmentDigest: officeTestDigest(officeTestJSON(t, image.Config.Env)),
		Seccomp:           officeTestRead(t, filepath.Join(sourceRoot, "policy/specialist-seccomp-v1.json")),
		PIDsLimit:         512, MemoryBytes: 4 * 1024 * 1024 * 1024, NanoCPUs: 4_000_000_000,
		WorkspaceSize: 1024 * 1024 * 1024, ScratchSize: 2 * 1024 * 1024 * 1024,
		ShmSize: 64 * 1024 * 1024, Runtime: "runc",
		RuntimeStatusDigest:   officeTestDigest(officeTestJSON(t, info.Runtimes["runc"].Status)),
		CustodyBytesPerSecond: 4 * 1024 * 1024, SettlementBaseSeconds: 30, SettlementMaximumSeconds: 180,
	}
	var executor struct {
		Ref       string               `json:"ref"`
		Digest    string               `json:"digest"`
		Transport specialistrender.Pin `json:"transport"`
	}
	if err := json.Unmarshal(officeTestRead(t, filepath.Join(sourceRoot, "office-authoring/executor.lock.json")), &executor); err != nil {
		t.Fatal(err)
	}
	policy.Executor = specialistrender.Pin{Ref: executor.Ref, Digest: executor.Digest}
	policy.Interface = executor.Transport
	// Probe immutable interpreter bytes before policy construction. The adapter
	// independently observes the launched helper's /proc identity and security.
	probe, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--entrypoint", "python3", imageRef, "-c", "import os,hashlib; p=os.readlink('/proc/self/exe'); print(p); print('sha256:'+hashlib.sha256(open(p,'rb').read()).hexdigest())").Output()
	if err != nil {
		t.Fatal(err)
	}
	identity := strings.Fields(string(probe))
	if len(identity) != 2 {
		t.Fatal("interpreter probe did not return its path and digest")
	}
	policy.ProcessExecutablePath, policy.ProcessExecutableDigest = identity[0], identity[1]
	policy.Authority.Digest, err = specialistrender.ComputePolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := specialistrender.NewStaticPolicyRegistry([]specialistrender.Policy{policy}); err != nil {
		t.Fatal(err)
	}
	parent, err := docker.ContainerCreate(ctx, &containertypes.Config{
		Image: image.ID, User: "1000:1000", Entrypoint: []string{"sleep"}, Cmd: []string{"infinity"},
	}, &containertypes.HostConfig{NetworkMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}}, nil, nil, "office-qualification-parent-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if err := docker.ContainerRemove(cleanupCtx, parent.ID, containertypes.RemoveOptions{Force: true}); err != nil {
			t.Error(err)
		}
	})
	if err := docker.ContainerStart(ctx, parent.ID, containertypes.StartOptions{}); err != nil {
		t.Fatal(err)
	}
	parentState, err := docker.ContainerInspect(ctx, parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(docker)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"docx", "pptx", "xlsx", "malformed", "cancel"} {
		t.Run(name, func(t *testing.T) {
			requestBytes := officeTestRead(t, filepath.Join(inputRoot, name+".request.json"))
			sourceBytes := officeTestRead(t, filepath.Join(inputRoot, name+".source"))
			var command map[string]any
			if err := json.Unmarshal(requestBytes, &command); err != nil {
				t.Fatal(err)
			}
			jobRef := command["jobRef"].(string)
			operationID := strings.TrimPrefix(jobRef, "ambit://artifact-render-jobs/")
			authority := specialistrender.Request{
				OperationID: operationID, ArtifactRenderJobRef: jobRef,
				RequestFingerprint: strings.TrimPrefix(officeTestDigest(requestBytes), "sha256:"),
				ExpectedParentGeneration: generationstop.ExpectedGeneration{
					ContainerID: parent.ID, ContainerCreatedAt: parentState.Created,
					ExecutionStartedAt: parentState.State.StartedAt, RestartCount: parentState.RestartCount,
				},
				RequestBytes: int64(len(requestBytes)), RequestDigest: officeTestDigest(requestBytes),
				SourceBytes: int64(len(sourceBytes)), SourceDigest: officeTestDigest(sourceBytes),
			}
			runCtx, stop := context.WithCancel(ctx)
			defer stop()
			if name == "cancel" {
				// Cancel after native work starts, using the actual process list.
				go func() {
					ticker := time.NewTicker(20 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-runCtx.Done():
							return
						case <-ticker.C:
							containers, err := docker.ContainerList(runCtx, containertypes.ListOptions{})
							if err != nil {
								continue
							}
							for _, candidate := range containers {
								if candidate.Labels[operationLabel] != operationID {
									continue
								}
								processes, err := docker.ContainerTop(runCtx, candidate.ID, []string{"-eo", "pid,args"})
								if err == nil {
									for _, process := range processes.Processes {
										if strings.Contains(strings.Join(process, " "), "soffice.bin") {
											stop()
											return
										}
									}
								}
							}
						}
					}
				}()
			}
			result, err := adapter.Execute(runCtx, specialistrender.ProviderExecutionRequest{
				OperationID: operationID, Nonce: strings.ReplaceAll(uuid.NewString(), "-", ""),
				Authority: authority, Policy: policy,
				Request: officeTestInput(requestBytes), Source: officeTestInput(sourceBytes),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer specialistrender.CleanupPayloads(result.Files)
			if !result.Quiescence.ContainerAbsent || result.Launch.MountCount != 0 ||
				result.Launch.NetworkMode != "none" || !result.Launch.ReadonlyRootfs ||
				result.Launch.MountNamespace == result.Launch.ParentMountNamespace ||
				result.Launch.ProcessNamespace == result.Launch.ParentProcessNamespace {
				t.Fatal("private child isolation or removal was not proved")
			}
			if name == "cancel" {
				if result.TerminalOutcome != "cancelled" || result.HelperExitCode != 130 {
					t.Fatalf("native cancellation did not win: %s/%d", result.TerminalOutcome, result.HelperExitCode)
				}
			} else if name == "malformed" {
				if result.TerminalOutcome != "failed" || len(result.Files) != 1 {
					t.Fatal("malformed source did not fail without a PDF")
				}
			} else if result.TerminalOutcome != "succeeded" || len(result.Files) != 2 {
				t.Fatalf("Office conversion failed: %s", result.TerminalOutcome)
			}
			caseRoot := filepath.Join(outputRoot, name)
			if err := os.Mkdir(caseRoot, 0700); err != nil {
				t.Fatal(err)
			}
			for _, payload := range result.Files {
				reader, err := payload.Open(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(reader)
				reader.Close()
				if err != nil {
					t.Fatal(err)
				}
				if int64(len(body)) != payload.File.ByteLength || officeTestDigest(body) != payload.File.Digest {
					t.Fatal("provider output custody differs")
				}
				if err := os.WriteFile(filepath.Join(caseRoot, filepath.Base(payload.File.Path)), body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			result.Files = nil
			if err := os.WriteFile(filepath.Join(caseRoot, "private-operation.json"), officeTestJSON(t, result), 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func officeTestRead(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func officeTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := generationstop.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func officeTestDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
func officeTestInput(value []byte) specialistrender.Input {
	return specialistrender.Input{ByteLength: int64(len(value)), Digest: officeTestDigest(value), Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(value)), nil }}
}
