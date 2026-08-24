// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

// Package specialistrender owns the provider-side authority for one isolated
// C18 specialist-render operation. Product workspace processes never receive
// the task container, PTY, nonce, or private roots.
package specialistrender

import (
	"context"
	"io"

	"github.com/daytonaio/runner/pkg/generationstop"
)

const (
	RequestSchema        = "ambit.runtime-provider-specialist-render-request/v1"
	ObserveRequestSchema = "ambit.runtime-provider-specialist-render-observe-request/v1"
	ReceiptSchema        = "ambit.runtime-provider-specialist-render-receipt/v1"
	ObservationSchema    = "ambit.runtime-provider-specialist-render-observation/v1"
	QuiescenceSchema     = "ambit.runtime-provider-quiescence-receipt/v1"
	ProviderFrameSchema  = "ambit.runtime-provider-specialist-render-jsonl@1"
	FrameSchema          = "ambit.runtime-interface/specialist-render-jsonl@1"
	InterfaceRef         = "ambit.runtime-interface/specialist-render@1"
	RoleRef              = "ambit.runtime-component/specialist-renderer@1"

	RequestChunkBytes      = 49_152
	MaximumRequestBytes    = 2 * 1024 * 1024
	MaximumSourceBytes     = 512 * 1024 * 1024
	MaximumFrameBytes      = 70_000
	MaximumOutputBytes     = 512 * 1024 * 1024
	MaximumOutputFiles     = 128
	MaximumOutputPathBytes = 128
	MaximumReceiptBytes    = 64 * 1024
)

type Pin struct {
	Ref    string `json:"ref" validate:"required"`
	Digest string `json:"digest" validate:"required"`
}

type ImagePin struct {
	Ref          string `json:"ref" validate:"required"`
	ConfigDigest string `json:"configDigest" validate:"required"`
	PackID       string `json:"packId" validate:"required"`
	PackRef      string `json:"packRef" validate:"required"`
}

// Request is the exact authority header carried by provider_request_start.
// Payload bytes are carried in later bounded frames and never embedded in this
// JSON document.
type Request struct {
	Schema                   string                            `json:"schema" validate:"required"`
	OperationID              string                            `json:"operationId" validate:"required"`
	RequestFingerprint       string                            `json:"requestFingerprint" validate:"required"`
	ArtifactRenderJobRef     string                            `json:"artifactRenderJobRef" validate:"required"`
	Source                   generationstop.Source             `json:"source" validate:"required"`
	Owner                    generationstop.ProviderOwner      `json:"owner" validate:"required"`
	Fence                    generationstop.Fence              `json:"fence" validate:"required"`
	ExpectedParentGeneration generationstop.ExpectedGeneration `json:"expectedParentGeneration" validate:"required"`
	Image                    ImagePin                          `json:"image" validate:"required"`
	Interface                Pin                               `json:"interface" validate:"required"`
	Executor                 Pin                               `json:"executor" validate:"required"`
	Executable               string                            `json:"executable" validate:"required"`
	ProviderPolicy           Pin                               `json:"providerPolicy" validate:"required"`
	RequestBytes             int64                             `json:"requestBytes" validate:"required"`
	RequestChunkCount        int                               `json:"requestChunkCount" validate:"required"`
	RequestDigest            string                            `json:"requestSha256" validate:"required"`
	SourceBytes              int64                             `json:"sourceBytes" validate:"required"`
	SourceChunkCount         int                               `json:"sourceChunkCount" validate:"required"`
	SourceDigest             string                            `json:"sourceSha256" validate:"required"`
}

type ObserveRequest struct {
	Schema             string                       `json:"schema" validate:"required"`
	OperationID        string                       `json:"operationId" validate:"required"`
	RequestFingerprint string                       `json:"requestFingerprint" validate:"required"`
	Source             generationstop.Source        `json:"source" validate:"required"`
	Owner              generationstop.ProviderOwner `json:"owner" validate:"required"`
	Fence              generationstop.Fence         `json:"fence" validate:"required"`
}

type ProcessIdentity struct {
	PID        int    `json:"pid" validate:"required"`
	StartTicks string `json:"startTicks" validate:"required"`
}

type LaunchObservation struct {
	ObservedAt             string                            `json:"observedAt" validate:"required"`
	ContainerID            string                            `json:"containerId" validate:"required"`
	ContainerName          string                            `json:"containerName" validate:"required"`
	ImageID                string                            `json:"imageId" validate:"required"`
	Command                []string                          `json:"command" validate:"required"`
	ProcessIdentity        ProcessIdentity                   `json:"processIdentity" validate:"required"`
	HostPID                int                               `json:"hostPid" validate:"required"`
	ExecutablePath         string                            `json:"executablePath" validate:"required"`
	ExecutableDigest       string                            `json:"executableDigest" validate:"required"`
	RoleRef                string                            `json:"roleRef" validate:"required"`
	User                   string                            `json:"user" validate:"required"`
	EnvironmentDigest      string                            `json:"environmentDigest" validate:"required"`
	MountNamespace         string                            `json:"mountNamespace" validate:"required"`
	ProcessNamespace       string                            `json:"processNamespace" validate:"required"`
	ParentMountNamespace   string                            `json:"parentMountNamespace" validate:"required"`
	ParentProcessNamespace string                            `json:"parentProcessNamespace" validate:"required"`
	ProcessCount           int                               `json:"processCount" validate:"required"`
	NetworkMode            string                            `json:"networkMode" validate:"required"`
	ReadonlyRootfs         bool                              `json:"readonlyRootfs" validate:"required"`
	CapDrop                []string                          `json:"capDrop" validate:"required"`
	NoNewPrivileges        bool                              `json:"noNewPrivileges" validate:"required"`
	SeccompMode            string                            `json:"seccompMode" validate:"required"`
	SeccompDigest          string                            `json:"seccompDigest"`
	Tmpfs                  map[string]string                 `json:"tmpfs" validate:"required"`
	MountCount             int                               `json:"mountCount"`
	PIDsLimit              int64                             `json:"pidsLimit" validate:"required"`
	MemoryBytes            int64                             `json:"memoryBytes" validate:"required"`
	NanoCPUs               int64                             `json:"nanoCpus" validate:"required"`
	ShmSize                int64                             `json:"shmSize"`
	ParentGeneration       generationstop.ExpectedGeneration `json:"parentGeneration" validate:"required"`
}

type QuiescenceReceipt struct {
	Schema          string `json:"schema" validate:"required"`
	ContainerID     string `json:"containerId" validate:"required"`
	ContainerAbsent bool   `json:"containerAbsent" validate:"required"`
	ObservedAt      string `json:"observedAt" validate:"required"`
}

type OutputFile struct {
	Ordinal    int    `json:"ordinal" validate:"required"`
	Role       string `json:"role" validate:"required"`
	Path       string `json:"path" validate:"required"`
	MediaType  string `json:"mediaType" validate:"required"`
	ByteLength int64  `json:"byteLength" validate:"required"`
	Digest     string `json:"sha256" validate:"required"`
}

// Payload is provider-private custody. Open returns a fresh reader positioned
// at byte zero; Cleanup removes only the operation-private backing object.
// Neither member is serialized into a receipt.
type Payload struct {
	File    OutputFile
	Open    func() (io.ReadCloser, error)
	Cleanup func() error
}

// ProviderExecution contains only already-validated helper facts plus
// provider-private output handles. It deliberately excludes raw response
// frames so durable receipts cannot duplicate or smuggle payload bytes.
type ProviderExecution struct {
	Launch          LaunchObservation
	ReadyDigest     string
	TerminalDigest  string
	TerminalKind    string
	TerminalOutcome string
	HelperExitCode  int
	Files           []Payload
	Quiescence      QuiescenceReceipt
}

type Provider interface {
	Execute(ctx context.Context, request ProviderExecutionRequest) (ProviderExecution, error)
}

// Input is an exact bounded provider-private payload. Open must return a fresh
// byte-zero reader on each call; the adapter never accepts a workspace path.
type Input struct {
	ByteLength int64
	Digest     string
	Open       func() (io.ReadCloser, error)
}

type ProviderExecutionRequest struct {
	OperationID string
	Nonce       string
	Authority   Request
	Policy      Policy
	Request     Input
	Source      Input
}

// Policy is resolved from runner-owned configuration. The caller's pins only
// select an exactly equal entry; they cannot supply executable or seccomp
// policy to Docker.
type Policy struct {
	Authority               Pin
	Image                   ImagePin
	Interface               Pin
	Executor                Pin
	Executable              string
	ProcessExecutablePath   string
	ProcessExecutableDigest string
	EnvironmentDigest       string
	Seccomp                 []byte
	PIDsLimit               int64
	MemoryBytes             int64
	NanoCPUs                int64
	WorkspaceSize           int64
	ScratchSize             int64
	ShmSize                 int64
}

type Receipt struct {
	Schema           string            `json:"schema" validate:"required"`
	ReceiptDigest    string            `json:"receiptDigest" validate:"required"`
	Outcome          string            `json:"outcome" validate:"required"`
	Request          Request           `json:"request" validate:"required"`
	Nonce            string            `json:"nonce" validate:"required"`
	Launch           LaunchObservation `json:"launch" validate:"required"`
	ReadyDigest      string            `json:"readyDigest" validate:"required"`
	TerminalDigest   string            `json:"terminalDigest" validate:"required"`
	TerminalKind     string            `json:"terminalKind" validate:"required"`
	TerminalOutcome  string            `json:"terminalOutcome" validate:"required"`
	HelperExitCode   int               `json:"helperExitCode" validate:"required"`
	Files            []OutputFile      `json:"files" validate:"required"`
	TotalOutputBytes int64             `json:"totalOutputBytes" validate:"required"`
	StartedAt        string            `json:"startedAt" validate:"required"`
	Quiescence       QuiescenceReceipt `json:"quiescence" validate:"required"`
	CompletedAt      string            `json:"completedAt" validate:"required"`
}

type Observation struct {
	Schema  string   `json:"schema" validate:"required"`
	Status  string   `json:"status" validate:"required"`
	Receipt *Receipt `json:"receipt,omitempty"`
}
