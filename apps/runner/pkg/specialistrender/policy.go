// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/daytonaio/runner/pkg/generationstop"
)

const PolicySetSchema = "ambit.runtime-provider-specialist-render-policy-set/v1"
const PolicyEntrySchema = "ambit.runtime-provider-specialist-render-policy/v1"
const SpecialistSeccompDigest = "sha256:9de0b08286e0c0ba068eb8f6bf9e2aa49860327b654b8f0b20bcabc4fdc796f2"

var packExecutables = map[string]string{
	"data-research":    "/opt/ambit/runtime-pack/data-research/bin/ambit-specialist-render",
	"office-authoring": "/opt/ambit/runtime-pack/office-authoring/bin/ambit-specialist-render",
	"pdf-ocr":          "/opt/ambit/runtime-pack/pdf-ocr/bin/ambit-specialist-render",
	"web-browser":      "/opt/ambit/runtime-pack/web-browser/bin/ambit-specialist-render",
}

type PolicySet struct {
	Schema   string           `json:"schema" validate:"required"`
	Policies []PolicyDocument `json:"policies" validate:"required"`
}

type PolicyDocument struct {
	Authority                Pin      `json:"authority" validate:"required"`
	Composition              Pin      `json:"composition" validate:"required"`
	Image                    ImagePin `json:"image" validate:"required"`
	Interface                Pin      `json:"interface" validate:"required"`
	Executor                 Pin      `json:"executor" validate:"required"`
	Executable               string   `json:"executable" validate:"required"`
	ProcessExecutablePath    string   `json:"processExecutablePath" validate:"required"`
	ProcessExecutableDigest  string   `json:"processExecutableDigest" validate:"required"`
	EnvironmentDigest        string   `json:"environmentDigest" validate:"required"`
	SeccompPath              string   `json:"seccompPath"`
	SeccompDigest            string   `json:"seccompDigest"`
	PIDsLimit                int64    `json:"pidsLimit" validate:"required"`
	MemoryBytes              int64    `json:"memoryBytes" validate:"required"`
	NanoCPUs                 int64    `json:"nanoCpus" validate:"required"`
	WorkspaceSize            int64    `json:"workspaceSize" validate:"required"`
	ScratchSize              int64    `json:"scratchSize" validate:"required"`
	ShmSize                  int64    `json:"shmSize"`
	Runtime                  string   `json:"runtime" validate:"required"`
	RuntimeStatusDigest      string   `json:"runtimeStatusDigest" validate:"required"`
	CustodyBytesPerSecond    int64    `json:"custodyBytesPerSecond" validate:"required"`
	SettlementBaseSeconds    int64    `json:"settlementBaseSeconds" validate:"required"`
	SettlementMaximumSeconds int64    `json:"settlementMaximumSeconds" validate:"required"`
}

type StaticPolicyRegistry struct {
	policies []Policy
}

func NewStaticPolicyRegistry(policies []Policy) (*StaticPolicyRegistry, error) {
	if len(policies) == 0 {
		return nil, fmt.Errorf("policy set is empty")
	}
	cloned := make([]Policy, len(policies))
	seen := make(map[string]struct{}, len(policies))
	for index, policy := range policies {
		if err := validatePolicy(policy); err != nil {
			return nil, fmt.Errorf("policy %d: %w", index, err)
		}
		key := policyKey(policy.Authority, policy.Composition, policy.Image, policy.Interface, policy.Executor, policy.Executable)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("policy %d duplicates an exact selector", index)
		}
		seen[key] = struct{}{}
		cloned[index] = clonePolicy(policy)
	}
	sort.Slice(cloned, func(left, right int) bool {
		return policyKey(cloned[left].Authority, cloned[left].Composition, cloned[left].Image, cloned[left].Interface, cloned[left].Executor, cloned[left].Executable) <
			policyKey(cloned[right].Authority, cloned[right].Composition, cloned[right].Image, cloned[right].Interface, cloned[right].Executor, cloned[right].Executable)
	})
	return &StaticPolicyRegistry{policies: cloned}, nil
}

func LoadPolicyRegistry(path string) (*StaticPolicyRegistry, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("specialist-render policy path must be absolute")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document PolicySet
	if err := generationstop.DecodeExactJSON(data, &document); err != nil {
		return nil, fmt.Errorf("decode exact specialist-render policy set: %w", err)
	}
	if document.Schema != PolicySetSchema {
		return nil, fmt.Errorf("specialist-render policy schema is invalid")
	}
	policies := make([]Policy, len(document.Policies))
	for index, item := range document.Policies {
		var seccomp []byte
		if !filepath.IsAbs(item.SeccompPath) || item.SeccompDigest != SpecialistSeccompDigest {
			return nil, fmt.Errorf("policy requires an absolute pinned seccomp profile")
		}
		seccomp, err = os.ReadFile(item.SeccompPath)
		if err != nil {
			return nil, fmt.Errorf("read specialist seccomp profile: %w", err)
		}
		if sha256Digest(seccomp) != item.SeccompDigest {
			return nil, fmt.Errorf("specialist seccomp profile differs from its digest")
		}
		var seccompDocument map[string]any
		if err := generationstop.DecodeCanonicalJSON(seccomp, &seccompDocument); err != nil {
			return nil, fmt.Errorf("specialist seccomp profile is not canonical JSON: %w", err)
		}
		policies[index] = Policy{
			Authority: item.Authority, Composition: item.Composition,
			Image: item.Image, Interface: item.Interface, Executor: item.Executor,
			Executable: item.Executable, Seccomp: seccomp,
			ProcessExecutablePath:   item.ProcessExecutablePath,
			ProcessExecutableDigest: item.ProcessExecutableDigest,
			EnvironmentDigest:       item.EnvironmentDigest,
			PIDsLimit:               item.PIDsLimit, MemoryBytes: item.MemoryBytes,
			NanoCPUs: item.NanoCPUs, WorkspaceSize: item.WorkspaceSize,
			ScratchSize: item.ScratchSize, ShmSize: item.ShmSize,
			Runtime:                  item.Runtime,
			RuntimeStatusDigest:      item.RuntimeStatusDigest,
			CustodyBytesPerSecond:    item.CustodyBytesPerSecond,
			SettlementBaseSeconds:    item.SettlementBaseSeconds,
			SettlementMaximumSeconds: item.SettlementMaximumSeconds,
		}
	}
	return NewStaticPolicyRegistry(policies)
}

func (registry *StaticPolicyRegistry) Resolve(request Request) (Policy, error) {
	wanted := policyKey(request.ProviderPolicy, request.Composition, request.Image, request.Interface, request.Executor, request.Executable)
	for _, policy := range registry.policies {
		if policyKey(policy.Authority, policy.Composition, policy.Image, policy.Interface, policy.Executor, policy.Executable) == wanted {
			return clonePolicy(policy), nil
		}
	}
	return Policy{}, fmt.Errorf("no exact specialist-render policy admits the supplied pins")
}

func validatePolicy(policy Policy) error {
	executable, exists := packExecutables[policy.Image.PackID]
	if !exists || executable != policy.Executable ||
		!boundedOperationalRef(policy.Authority.Ref, 512) || !exactDigest(policy.Authority.Digest) ||
		!boundedOperationalRef(policy.Composition.Ref, 512) || !exactDigest(policy.Composition.Digest) ||
		policy.Interface.Ref != InterfaceRef || !exactDigest(policy.Interface.Digest) ||
		!immutableOCIReference(policy.Image.Ref) || !exactDigest(policy.Image.ConfigDigest) ||
		!boundedOperationalRef(policy.Image.PackRef, 512) ||
		!boundedOperationalRef(policy.Executor.Ref, 512) || !exactDigest(policy.Executor.Digest) ||
		policy.ProcessExecutablePath == "" || !exactDigest(policy.ProcessExecutableDigest) ||
		!exactDigest(policy.EnvironmentDigest) ||
		policy.PIDsLimit <= 0 || policy.MemoryBytes <= 0 || policy.NanoCPUs <= 0 ||
		policy.WorkspaceSize <= 0 || policy.ScratchSize <= 0 || policy.ShmSize < 0 ||
		policy.PIDsLimit > 4096 || policy.MemoryBytes > 16*1024*1024*1024 ||
		policy.NanoCPUs > 8_000_000_000 || policy.WorkspaceSize > 4*1024*1024*1024 ||
		policy.ScratchSize > 8*1024*1024*1024 || policy.ShmSize > 2*1024*1024*1024 {
		return fmt.Errorf("policy pins, executable, or resources are incomplete")
	}
	if len(bytes.TrimSpace(policy.Seccomp)) == 0 {
		return fmt.Errorf("policy requires exact custom seccomp")
	}
	if sha256Digest(policy.Seccomp) != SpecialistSeccompDigest {
		return fmt.Errorf("policy seccomp digest is not the certified profile")
	}
	if policy.Image.PackID == "web-browser" && policy.ShmSize <= 0 {
		return fmt.Errorf("web-browser policy requires private shm")
	}
	if policy.Runtime != "runc" {
		return fmt.Errorf("policy OCI runtime is not the certified runc runtime")
	}
	if !exactDigest(policy.RuntimeStatusDigest) {
		return fmt.Errorf("policy OCI runtime status digest is invalid")
	}
	if policy.CustodyBytesPerSecond < 1024*1024 || policy.CustodyBytesPerSecond > 1024*1024*1024 ||
		policy.SettlementBaseSeconds < 30 || policy.SettlementBaseSeconds > 300 ||
		policy.SettlementMaximumSeconds < policy.SettlementBaseSeconds ||
		policy.SettlementMaximumSeconds > 1800 ||
		policy.SettlementMaximumSeconds < policy.SettlementBaseSeconds+
			(MaximumOutputBytes+policy.CustodyBytesPerSecond-1)/policy.CustodyBytesPerSecond {
		return fmt.Errorf("policy durable settlement budget is invalid")
	}
	expectedDigest, err := ComputePolicyDigest(policy)
	if err != nil || policy.Authority.Digest != expectedDigest {
		return fmt.Errorf("policy authority digest does not bind the exact policy")
	}
	return nil
}

type policyDigestPayload struct {
	Schema                   string   `json:"schema"`
	Ref                      string   `json:"ref"`
	Composition              Pin      `json:"composition"`
	Image                    ImagePin `json:"image"`
	Interface                Pin      `json:"interface"`
	Executor                 Pin      `json:"executor"`
	Executable               string   `json:"executable"`
	ProcessExecutablePath    string   `json:"processExecutablePath"`
	ProcessExecutableDigest  string   `json:"processExecutableDigest"`
	EnvironmentDigest        string   `json:"environmentDigest"`
	SeccompDigest            string   `json:"seccompDigest"`
	PIDsLimit                int64    `json:"pidsLimit"`
	MemoryBytes              int64    `json:"memoryBytes"`
	NanoCPUs                 int64    `json:"nanoCpus"`
	WorkspaceSize            int64    `json:"workspaceSize"`
	ScratchSize              int64    `json:"scratchSize"`
	ShmSize                  int64    `json:"shmSize"`
	Runtime                  string   `json:"runtime"`
	RuntimeStatusDigest      string   `json:"runtimeStatusDigest"`
	CustodyBytesPerSecond    int64    `json:"custodyBytesPerSecond"`
	SettlementBaseSeconds    int64    `json:"settlementBaseSeconds"`
	SettlementMaximumSeconds int64    `json:"settlementMaximumSeconds"`
}

func ComputePolicyDigest(policy Policy) (string, error) {
	seccompDigest := ""
	if len(policy.Seccomp) != 0 {
		seccompDigest = sha256Digest(policy.Seccomp)
	}
	data, err := generationstop.CanonicalJSON(policyDigestPayload{
		Schema: PolicyEntrySchema, Ref: policy.Authority.Ref, Composition: policy.Composition,
		Image: policy.Image, Interface: policy.Interface, Executor: policy.Executor,
		Executable: policy.Executable, ProcessExecutablePath: policy.ProcessExecutablePath,
		ProcessExecutableDigest: policy.ProcessExecutableDigest,
		EnvironmentDigest:       policy.EnvironmentDigest, SeccompDigest: seccompDigest,
		PIDsLimit: policy.PIDsLimit, MemoryBytes: policy.MemoryBytes, NanoCPUs: policy.NanoCPUs,
		WorkspaceSize: policy.WorkspaceSize, ScratchSize: policy.ScratchSize, ShmSize: policy.ShmSize,
		Runtime:                  policy.Runtime,
		RuntimeStatusDigest:      policy.RuntimeStatusDigest,
		CustodyBytesPerSecond:    policy.CustodyBytesPerSecond,
		SettlementBaseSeconds:    policy.SettlementBaseSeconds,
		SettlementMaximumSeconds: policy.SettlementMaximumSeconds,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func policyKey(authority Pin, composition Pin, image ImagePin, transport Pin, executor Pin, executable string) string {
	return authority.Ref + "\x00" + authority.Digest + "\x00" + composition.Ref + "\x00" + composition.Digest + "\x00" + image.Ref + "\x00" + image.ConfigDigest + "\x00" + image.PackID + "\x00" + image.PackRef +
		"\x00" + transport.Ref + "\x00" + transport.Digest + "\x00" + executor.Ref + "\x00" +
		executor.Digest + "\x00" + executable
}
