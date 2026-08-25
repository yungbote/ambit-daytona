// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

// Command specialist-render-policy derives one canonical runner policy set
// from locally loaded immutable C18 images and a caller-authoritative
// composition pin. It is build/deployment tooling, never request-time policy.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
	imagetypes "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"golang.org/x/sys/unix"
)

type interfaceLock struct {
	Digest   string          `json:"digest"`
	Contract json.RawMessage `json:"contract"`
	Schema   string          `json:"schema"`
	State    string          `json:"state"`
}

type executorLock struct {
	Digest    string               `json:"digest"`
	Facets    []string             `json:"facets"`
	Ref       string               `json:"ref"`
	Schema    string               `json:"schema"`
	Transport specialistrender.Pin `json:"transport"`
}

type executorDigestBody struct {
	Facets    []string             `json:"facets"`
	Ref       string               `json:"ref"`
	Schema    string               `json:"schema"`
	Transport specialistrender.Pin `json:"transport"`
}

func main() {
	os.Exit(run())
}

func run() int {
	compositionPath := flag.String("composition", "", "absolute exact full-image composition v2 document")
	routingPath := flag.String("routing", "", "absolute exact composition routing v1 document")
	sourceRoot := flag.String("source-root", "", "absolute C18 specialist source root")
	seccompPath := flag.String("seccomp", "", "absolute canonical specialist seccomp source profile")
	seccompRuntimePath := flag.String("seccomp-runtime-path", "", "absolute fixed in-container seccomp path")
	outputRoot := flag.String("output-root", "", "absolute new authority directory")
	sourceRevision := flag.String("revision", "", "exact Daytona source revision")
	sourceTree := flag.String("tree", "", "exact Daytona source tree")
	sourceSetDigest := flag.String("source-set", "", "exact C18 source-set SHA-256")
	registryInspectAuthority := flag.String("registry-inspect-authority", "", "host registry authority used only to pull and inspect exact image digests")
	flag.Parse()
	if flag.NArg() != 0 || !absoluteNormalizedPath(*sourceRoot) || !absoluteNormalizedPath(*seccompPath) ||
		!absoluteNormalizedPath(*compositionPath) || !absoluteNormalizedPath(*routingPath) ||
		!absoluteNormalizedPath(*outputRoot) || *seccompRuntimePath != runtimeSeccompPath ||
		!gitObject(*sourceRevision) || !gitObject(*sourceTree) || !exactSHA256(*sourceSetDigest) ||
		!registryAuthority(*registryInspectAuthority) {
		fmt.Fprintln(os.Stderr, "exact source identity, source inputs, runtime seccomp path, and new output root are required")
		return 64
	}
	if err := preflightAuthorityOutputRoot(*outputRoot); err != nil {
		return fail(err)
	}
	sourceRootInfo, err := os.Lstat(*sourceRoot)
	if err != nil || !sourceRootInfo.IsDir() || sourceRootInfo.Mode()&os.ModeSymlink != 0 {
		return fail(errors.New("specialist source root is invalid"))
	}
	compositionBytes, err := readRegularFileSnapshot(*compositionPath, 1024*1024)
	if err != nil {
		return fail(err)
	}
	routingBytes, err := readRegularFileSnapshot(*routingPath, 512*1024)
	if err != nil {
		return fail(err)
	}
	composition, err := specialistrender.DecodeCompositionAdmission(compositionBytes, routingBytes)
	if err != nil {
		return fail(err)
	}

	sourceContractsBytes, err := readRegularFileSnapshot(filepath.Join(*sourceRoot, "source-contracts.sha256"), 16*1024*1024)
	if err != nil || digestBytes(sourceContractsBytes) != *sourceSetDigest {
		return fail(errors.New("source contracts file differs from the exact source set"))
	}
	generatorBytes, err := readExecutableSnapshot()
	if err != nil {
		return fail(err)
	}
	interfaceData, err := readRegularFileSnapshot(filepath.Join(*sourceRoot, "protocol/specialist-render-interface.lock.json"), 1024*1024)
	if err != nil {
		return fail(err)
	}
	var transport interfaceLock
	var interfaceContract struct {
		InterfaceRef string `json:"interfaceRef"`
	}
	if err := generationstop.DecodeExactJSON(interfaceData, &transport); err != nil {
		return fail(errors.New("specialist-render interface lock is invalid"))
	}
	contractBytes, contractErr := generationstop.CanonicalJSON(transport.Contract)
	if jsonErr := json.Unmarshal(transport.Contract, &interfaceContract); jsonErr != nil ||
		contractErr != nil || transport.Digest != digestBytes(contractBytes) ||
		transport.Schema != "ambit.runtime-interface-lock/v1" || transport.State != "candidate-ready" ||
		interfaceContract.InterfaceRef != specialistrender.InterfaceRef {
		return fail(errors.New("specialist-render interface lock is invalid"))
	}
	seccomp, err := readRegularFileSnapshot(*seccompPath, 4*1024*1024)
	if err != nil {
		return fail(err)
	}
	seccompDigest := digestBytes(seccomp)
	if seccompDigest != specialistrender.SpecialistSeccompDigest {
		return fail(errors.New("seccomp bytes differ from the certified provider profile"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fail(err)
	}
	defer docker.Close()
	providerInfo, err := docker.Info(ctx)
	if err != nil {
		return fail(err)
	}
	runtimeStatus, exists := providerInfo.Runtimes["runc"]
	runtimeStatusBytes, err := generationstop.CanonicalJSON(runtimeStatus.Status)
	if !exists || err != nil {
		return fail(errors.New("certified runc runtime status is unavailable"))
	}
	runtimeStatusDigest := digestBytes(runtimeStatusBytes)

	packs := specialistrender.SortedCompositionPacks(composition)
	documents := make([]specialistrender.PolicyDocument, 0, len(packs))
	policies := make([]specialistrender.Policy, 0, len(packs))
	images := make([]policyReceiptImage, 0, len(packs))
	runtimeRegistryAuthority := ""
	for _, pack := range packs {
		if pack != "data-research" && pack != "office-authoring" && pack != "pdf-ocr" && pack != "web-browser" {
			return fail(fmt.Errorf("unsupported pack %q", pack))
		}
		executorEvidence := composition.Executors[pack]
		if executorEvidence.Image.SourceIdentity.Digest != *sourceSetDigest {
			return fail(fmt.Errorf("%s composition source identity differs", pack))
		}
		imageRef := executorEvidence.Image.OCIReference
		inspectImageRef, observedRuntimeAuthority, manifestDigest, err := rewriteRegistryAuthority(
			imageRef, *registryInspectAuthority,
		)
		if err != nil || manifestDigest != executorEvidence.Image.IndexDigest ||
			(runtimeRegistryAuthority != "" && observedRuntimeAuthority != runtimeRegistryAuthority) {
			return fail(fmt.Errorf("%s registry authority or manifest differs", pack))
		}
		if runtimeRegistryAuthority == "" {
			runtimeRegistryAuthority = observedRuntimeAuthority
		}
		if err := pullExactImage(ctx, docker, inspectImageRef); err != nil {
			return fail(fmt.Errorf("pull %s exact image: %w", pack, err))
		}
		image, err := docker.ImageInspect(ctx, inspectImageRef)
		if err != nil || image.ID != executorEvidence.Image.ConfigDigest ||
			!contains(image.RepoDigests, inspectImageRef) ||
			image.Config == nil || image.Config.User != "1000:1000" ||
			image.Config.Labels["io.ambit.runtime-pack"] != "ambit.runtime-pack/"+pack+"@1" ||
			image.Config.Labels["io.ambit.activation"] != "provider-policy-and-composition-bound-only" ||
			image.Config.Labels["org.opencontainers.image.revision"] != *sourceRevision ||
			image.Config.Labels["io.ambit.source-tree"] != *sourceTree ||
			image.Config.Labels["io.ambit.source-set-sha256"] != strings.TrimPrefix(*sourceSetDigest, "sha256:") {
			return fail(fmt.Errorf("image %q identity or activation differs", imageRef))
		}
		executorData, err := readRegularFileSnapshot(filepath.Join(*sourceRoot, pack, "executor.lock.json"), 1024*1024)
		if err != nil {
			return fail(err)
		}
		var executor executorLock
		if err := generationstop.DecodeExactJSON(executorData, &executor); err != nil {
			return fail(fmt.Errorf("%s executor lock is invalid", pack))
		}
		executorBody, bodyErr := generationstop.CanonicalJSON(executorDigestBody{
			Facets: executor.Facets, Ref: executor.Ref, Schema: executor.Schema, Transport: executor.Transport,
		})
		if bodyErr != nil || executor.Digest != digestBytes(executorBody) ||
			executor.Transport.Ref != interfaceContract.InterfaceRef || executor.Transport.Digest != transport.Digest ||
			executor.Ref != "ambit://specialist-render-executors/"+pack+"@1" ||
			!contains(executorEvidence.PackRevisionRefs, "ambit.runtime-pack/"+pack+"@1") {
			return fail(fmt.Errorf("%s executor lock differs from interface", pack))
		}
		environment, err := generationstop.CanonicalJSON(image.Config.Env)
		if err != nil {
			return fail(err)
		}
		processPath, processDigest, err := probeProcessExecutable(ctx, image.ID, seccomp)
		if err != nil {
			return fail(fmt.Errorf("probe %s helper interpreter: %w", pack, err))
		}
		policy := specialistrender.Policy{
			Authority:             specialistrender.Pin{Ref: "ambit.runtime-provider/specialist-render-" + pack + "@1"},
			Composition:           composition.Pin,
			Image:                 specialistrender.ImagePin{Ref: imageRef, ConfigDigest: image.ID, PackID: pack, PackRef: "ambit.runtime-pack/" + pack + "@1"},
			Interface:             specialistrender.Pin{Ref: interfaceContract.InterfaceRef, Digest: transport.Digest},
			Executor:              specialistrender.Pin{Ref: executor.Ref, Digest: executor.Digest},
			Executable:            "/opt/ambit/runtime-pack/" + pack + "/bin/ambit-specialist-render",
			ProcessExecutablePath: processPath, ProcessExecutableDigest: processDigest,
			EnvironmentDigest: digestBytes(environment), Seccomp: seccomp,
			PIDsLimit: 512, MemoryBytes: 4 * 1024 * 1024 * 1024, NanoCPUs: 4_000_000_000,
			WorkspaceSize: 1024 * 1024 * 1024, ScratchSize: 2 * 1024 * 1024 * 1024,
			ShmSize: 64 * 1024 * 1024, Runtime: "runc",
			RuntimeStatusDigest:   runtimeStatusDigest,
			CustodyBytesPerSecond: 4 * 1024 * 1024,
			SettlementBaseSeconds: 30, SettlementMaximumSeconds: 180,
		}
		if pack == "web-browser" {
			policy.PIDsLimit = 1024
			policy.MemoryBytes = 6 * 1024 * 1024 * 1024
			policy.ShmSize = 1024 * 1024 * 1024
		}
		policy.Authority.Digest, err = specialistrender.ComputePolicyDigest(policy)
		if err != nil {
			return fail(err)
		}
		policies = append(policies, policy)
		images = append(images, policyReceiptImage{
			PackID: pack, RuntimeImageRef: imageRef, InspectImageRef: inspectImageRef,
			ManifestDigest: manifestDigest, ConfigDigest: image.ID,
		})
		documents = append(documents, specialistrender.PolicyDocument{
			Authority: policy.Authority, Composition: policy.Composition,
			Image: policy.Image, Interface: policy.Interface, Executor: policy.Executor,
			Executable: policy.Executable, ProcessExecutablePath: policy.ProcessExecutablePath,
			ProcessExecutableDigest: policy.ProcessExecutableDigest,
			EnvironmentDigest:       policy.EnvironmentDigest,
			SeccompPath:             *seccompRuntimePath, SeccompDigest: seccompDigest,
			PIDsLimit: policy.PIDsLimit, MemoryBytes: policy.MemoryBytes, NanoCPUs: policy.NanoCPUs,
			WorkspaceSize: policy.WorkspaceSize, ScratchSize: policy.ScratchSize,
			ShmSize: policy.ShmSize, Runtime: policy.Runtime,
			RuntimeStatusDigest:      policy.RuntimeStatusDigest,
			CustodyBytesPerSecond:    policy.CustodyBytesPerSecond,
			SettlementBaseSeconds:    policy.SettlementBaseSeconds,
			SettlementMaximumSeconds: policy.SettlementMaximumSeconds,
		})
	}
	if _, err := specialistrender.NewStaticPolicyRegistry(policies); err != nil {
		return fail(err)
	}
	encoded, err := generationstop.CanonicalJSON(specialistrender.PolicySet{
		Schema: specialistrender.PolicySetSchema, Policies: documents,
	})
	if err != nil {
		return fail(err)
	}
	receipt, err := sealPolicyGenerationReceipt(policyGenerationReceipt{
		ObservedAt: time.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"),
		Source: policyReceiptSource{
			Revision: *sourceRevision, Tree: *sourceTree, SourceSetDigest: *sourceSetDigest,
			SourceContractsFileSHA256: digestBytes(sourceContractsBytes),
		},
		Generator: policyReceiptGenerator{ExecutableSHA256: digestBytes(generatorBytes)},
		Registry: policyReceiptRegistry{
			InspectAuthority: *registryInspectAuthority, RuntimeAuthority: runtimeRegistryAuthority,
		},
		Inputs: policyReceiptInputs{
			CompositionFileSHA256: digestBytes(compositionBytes), RoutingFileSHA256: digestBytes(routingBytes),
			SeccompSourceFileSHA256: seccompDigest, SeccompCopiedFileSHA256: digestBytes(seccomp),
			SeccompRuntimePath: *seccompRuntimePath,
		},
		Images: images,
		Policy: policyReceiptPolicy{Schema: specialistrender.PolicySetSchema, RowCount: len(documents), FileSHA256: digestBytes(encoded)},
	})
	if err != nil {
		return fail(err)
	}
	receiptBytes, err := generationstop.CanonicalJSON(receipt)
	if err != nil {
		return fail(err)
	}
	if err := publishAuthorityDirectory(*outputRoot, encoded, receiptBytes, seccomp); err != nil {
		return fail(err)
	}
	return 0
}

func pullExactImage(ctx context.Context, docker *client.Client, imageRef string) error {
	stream, err := docker.ImagePull(ctx, imageRef, imagetypes.PullOptions{})
	if err != nil {
		return err
	}
	defer stream.Close()
	const maximumProgressBytes = 64 * 1024 * 1024
	progress, err := io.ReadAll(io.LimitReader(stream, maximumProgressBytes+1))
	if err != nil || len(progress) > maximumProgressBytes {
		return errors.New("exact image pull progress is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(progress)))
	for {
		var message struct {
			Error       string `json:"error"`
			ErrorDetail *struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := decoder.Decode(&message); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return errors.New("exact image pull progress is malformed")
		}
		if message.Error != "" || message.ErrorDetail != nil {
			return errors.New("exact image pull failed")
		}
	}
}

func probeProcessExecutable(ctx context.Context, imageID string, seccomp []byte) (string, string, error) {
	profile, err := sealedMemfd("ambit-specialist-seccomp", seccomp)
	if err != nil {
		return "", "", err
	}
	defer profile.Close()
	command := exec.CommandContext(
		ctx, "docker", "run", "--rm", "--network", "none", "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=/proc/self/fd/3", "--runtime", "runc",
		"--entrypoint", "/bin/sh", imageID, "-c",
		`set -eu; executable=$(readlink -f "$(command -v python3)"); printf '%s\n' "$executable"; sha256sum "$executable"`,
	)
	command.ExtraFiles = []*os.File{profile}
	output, err := command.Output()
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "/") {
		return "", "", errors.New("interpreter probe output is invalid")
	}
	fields := strings.Fields(lines[1])
	if len(fields) != 2 || fields[1] != lines[0] || len(fields[0]) != 64 {
		return "", "", errors.New("interpreter digest probe is invalid")
	}
	return lines[0], "sha256:" + fields[0], nil
}

func sealedMemfd(name string, value []byte) (*os.File, error) {
	descriptor, err := unix.MemfdCreate(name, unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("create sealed seccomp file handle")
	}
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = file.Close()
		return nil, err
	}
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, err)
	return 1
}
