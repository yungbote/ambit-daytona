// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrenderdocker

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

func TestContainerConfigurationIsProviderOwnedAndIsolated(t *testing.T) {
	environment := []string{
		"HOME=/workspace", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
		"PATH=/opt/ambit/runtime-pack/data-research/python/bin:/usr/local/bin:/usr/bin:/bin",
		"PYTHONHASHSEED=0", "PYTHONDONTWRITEBYTECODE=1", "TZ=UTC",
	}
	policy := dockerTestPolicy(t, "data-research", nil, environment)
	request := dockerTestRequest(policy)
	config, host, command, environmentDigest, err := containerConfiguration(request, environment)
	if err != nil {
		t.Fatal(err)
	}
	if config.Image != policy.Image.ConfigDigest || config.User != "1000:1000" ||
		!config.Tty || !config.OpenStdin || !config.AttachStdin || !config.AttachStdout || !config.AttachStderr ||
		config.WorkingDir != "/workspace" || environmentDigest != policy.EnvironmentDigest ||
		len(config.Entrypoint) != 1 || config.Entrypoint[0] != "/bin/sh" ||
		strings.Join(append(config.Entrypoint, config.Cmd...), "\x00") != strings.Join(command, "\x00") {
		t.Fatalf("container config differs: %#v", config)
	}
	if host.NetworkMode != "none" || !host.ReadonlyRootfs || host.Privileged || host.AutoRemove ||
		len(host.CapDrop) != 1 || host.CapDrop[0] != "ALL" || len(host.Mounts) != 0 ||
		len(host.Binds) != 0 || len(host.VolumesFrom) != 0 || len(host.SecurityOpt) != 2 ||
		host.SecurityOpt[0] != "no-new-privileges" || !strings.HasPrefix(host.SecurityOpt[1], "seccomp=") || host.PidsLimit == nil ||
		*host.PidsLimit != policy.PIDsLimit || host.Memory != policy.MemoryBytes ||
		host.MemorySwap != policy.MemoryBytes || host.NanoCPUs != policy.NanoCPUs ||
		host.Tmpfs["/workspace"] == "" || host.Tmpfs["/tmp/ambit-task"] == "" {
		t.Fatalf("host isolation differs: %#v", host)
	}
	if config.Labels["daytona.runner.container-kind"] != "specialist-render" ||
		config.Labels[operationLabel] != request.OperationID ||
		config.Labels[parentLabel] != request.Authority.ExpectedParentGeneration.ContainerID {
		t.Fatalf("provider labels differ: %#v", config.Labels)
	}
}

func TestContainerConfigurationRequiresWebSeccompAndRejectsSecretEnvironment(t *testing.T) {
	environment := []string{"HOME=/workspace", "PATH=/usr/bin:/bin"}
	policy := dockerTestPolicy(t, "web-browser", nil, environment)
	request := dockerTestRequest(policy)
	_, host, _, _, err := containerConfiguration(request, environment)
	if err != nil {
		t.Fatal(err)
	}
	if len(host.SecurityOpt) != 2 || !strings.HasPrefix(host.SecurityOpt[1], "seccomp=") {
		t.Fatalf("web seccomp was not applied exactly: %#v", host.SecurityOpt)
	}
	if _, _, _, _, err := containerConfiguration(request, append(environment, "API_TOKEN=forbidden")); err == nil {
		t.Fatal("secret-shaped environment reached the task container")
	}
}

func TestContextWriterStopsPayloadAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var target strings.Builder
	writer := &contextWriter{ctx: ctx, writer: &target}
	if _, err := writer.Write([]byte("payload")); err == nil || target.Len() != 0 {
		t.Fatalf("cancelled context wrote payload: len=%d err=%v", target.Len(), err)
	}
}

func dockerTestPolicy(t *testing.T, pack string, seccomp []byte, environment []string) specialistrender.Policy {
	t.Helper()
	environmentBytes, err := generationstop.CanonicalJSON(environment)
	if err != nil {
		t.Fatal(err)
	}
	if len(seccomp) == 0 {
		_, current, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("caller path unavailable")
		}
		seccomp, err = os.ReadFile(filepath.Clean(filepath.Join(
			filepath.Dir(current),
			"../../../../images/ambit-agent-workspace/capabilities/c18-specialist-packs/policy/specialist-seccomp-v1.json",
		)))
		if err != nil {
			t.Fatal(err)
		}
	}
	policy := specialistrender.Policy{
		Authority:             specialistrender.Pin{Ref: "ambit.runtime-provider/specialist-render-" + pack + "@1"},
		Composition:           specialistrender.Pin{Ref: "ambit.runtime-composition/test@2", Digest: "sha256:" + strings.Repeat("b", 64)},
		Image:                 specialistrender.ImagePin{Ref: "image:" + pack, ConfigDigest: "sha256:" + strings.Repeat("1", 64), PackID: pack, PackRef: "ambit.runtime-pack/" + pack + "@1"},
		Interface:             specialistrender.Pin{Ref: specialistrender.InterfaceRef, Digest: "sha256:" + strings.Repeat("2", 64)},
		Executor:              specialistrender.Pin{Ref: "ambit://specialist-render-executors/" + pack + "@1", Digest: "sha256:" + strings.Repeat("3", 64)},
		Executable:            "/opt/ambit/runtime-pack/" + pack + "/bin/ambit-specialist-render",
		ProcessExecutablePath: "/usr/bin/python3", ProcessExecutableDigest: "sha256:" + strings.Repeat("4", 64),
		EnvironmentDigest: digestBytes(environmentBytes), Seccomp: seccomp,
		PIDsLimit: 512, MemoryBytes: 4 * 1024 * 1024 * 1024, NanoCPUs: 4_000_000_000,
		WorkspaceSize: 1024 * 1024 * 1024, ScratchSize: 2 * 1024 * 1024 * 1024,
		ShmSize:                  64 * 1024 * 1024,
		Runtime:                  "runc",
		RuntimeStatusDigest:      "sha256:" + strings.Repeat("c", 64),
		CustodyBytesPerSecond:    4 * 1024 * 1024,
		SettlementBaseSeconds:    30,
		SettlementMaximumSeconds: 180,
	}
	if pack == "web-browser" {
		policy.PIDsLimit = 1024
		policy.MemoryBytes = 6 * 1024 * 1024 * 1024
		policy.ShmSize = 1024 * 1024 * 1024
	}
	policy.Authority.Digest, err = specialistrender.ComputePolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func dockerTestRequest(policy specialistrender.Policy) specialistrender.ProviderExecutionRequest {
	authority := specialistrender.Request{
		OperationID:              "11111111-1111-4111-8111-111111111111",
		ExpectedParentGeneration: generationstop.ExpectedGeneration{ContainerID: strings.Repeat("7", 64)},
		RequestFingerprint:       strings.Repeat("8", 64),
	}
	return specialistrender.ProviderExecutionRequest{
		OperationID: authority.OperationID, Nonce: strings.Repeat("a", 32),
		Authority: authority, Policy: policy,
	}
}
