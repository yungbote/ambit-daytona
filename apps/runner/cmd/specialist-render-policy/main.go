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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
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
	seccompPath := flag.String("seccomp", "", "absolute canonical specialist seccomp profile")
	output := flag.String("output", "", "absolute output policy-set path")
	flag.Parse()
	if !filepath.IsAbs(*sourceRoot) || !filepath.IsAbs(*seccompPath) || !filepath.IsAbs(*output) ||
		!filepath.IsAbs(*compositionPath) || !filepath.IsAbs(*routingPath) {
		fmt.Fprintln(os.Stderr, "exact source, seccomp, output, composition, and routing documents are required")
		return 64
	}
	compositionBytes, err := os.ReadFile(*compositionPath)
	if err != nil {
		return fail(err)
	}
	routingBytes, err := os.ReadFile(*routingPath)
	if err != nil {
		return fail(err)
	}
	composition, err := specialistrender.DecodeCompositionAdmission(compositionBytes, routingBytes)
	if err != nil {
		return fail(err)
	}

	interfaceData, err := os.ReadFile(filepath.Join(*sourceRoot, "protocol/specialist-render-interface.lock.json"))
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
	seccomp, err := os.ReadFile(*seccompPath)
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
	for _, pack := range packs {
		if pack != "data-research" && pack != "office-authoring" && pack != "pdf-ocr" && pack != "web-browser" {
			return fail(fmt.Errorf("unsupported pack %q", pack))
		}
		executorEvidence := composition.Executors[pack]
		imageRef := executorEvidence.Image.OCIReference
		image, err := docker.ImageInspect(ctx, imageRef)
		if err != nil || image.ID != executorEvidence.Image.ConfigDigest ||
			image.Config == nil || image.Config.User != "1000:1000" ||
			image.Config.Labels["io.ambit.runtime-pack"] != "ambit.runtime-pack/"+pack+"@1" ||
			image.Config.Labels["io.ambit.activation"] != "provider-policy-and-composition-bound-only" {
			return fail(fmt.Errorf("image %q identity or activation differs", imageRef))
		}
		executorData, err := os.ReadFile(filepath.Join(*sourceRoot, pack, "executor.lock.json"))
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
		documents = append(documents, specialistrender.PolicyDocument{
			Authority: policy.Authority, Composition: policy.Composition,
			Image: policy.Image, Interface: policy.Interface, Executor: policy.Executor,
			Executable: policy.Executable, ProcessExecutablePath: policy.ProcessExecutablePath,
			ProcessExecutableDigest: policy.ProcessExecutableDigest,
			EnvironmentDigest:       policy.EnvironmentDigest,
			SeccompPath:             *seccompPath, SeccompDigest: seccompDigest,
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
	if err := writeAtomic(*output, encoded); err != nil {
		return fail(err)
	}
	return 0
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

func writeAtomic(path string, value []byte) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("policy output already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".specialist-render-policy-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(value); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, name, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("policy output already exists: %s", path)
		}
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
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
