// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

// Package generationstop owns the durable, provider-side contract for
// stopping one exact sandbox container generation.  It deliberately does not
// know about Docker, HTTP, or the product database; adapters must translate
// those representations into the exact authority types below.
package generationstop

const (
	PurposeWorkingCopyCapture         = "working_copy_capture"
	PurposeDocumentRendererQuiescence = "document_renderer_quiescence"

	ObservationAbsent   = "absent"
	ObservationPartial  = "partial"
	ObservationComplete = "complete"
)

// Source is the exact provider-owned sandbox address admitted by the caller.
type Source struct {
	ProviderResourceID  string `json:"providerResourceId" validate:"required"`
	ExpectedProfile     string `json:"expectedProfile" validate:"required"`
	ExpectedRuntimeKind string `json:"expectedRuntimeKind" validate:"required"`
}

// Owner is the complete product authority whose provider effect is being
// stopped.  Keeping every dimension in the durable claim prevents a replay
// from silently crossing a tenant, principal, run, grant, or working copy.
type Owner struct {
	TenantID      string `json:"tenantId" validate:"required"`
	UserID        string `json:"userId" validate:"required"`
	WorkspaceID   string `json:"workspaceId" validate:"required"`
	RunID         string `json:"runId" validate:"required"`
	GrantID       string `json:"grantId" validate:"required"`
	WorkingCopyID string `json:"workingCopyId" validate:"required"`
}

// ProviderOwner is the exact subset of Owner that is bound to provider-owned
// container metadata. WorkingCopyID intentionally does not appear: it is
// operation-local claim authority and no container label can honestly prove
// it. RunID corresponds to the provider's task/run label.
type ProviderOwner struct {
	TenantID    string `json:"tenantId"`
	UserID      string `json:"userId"`
	WorkspaceID string `json:"workspaceId"`
	RunID       string `json:"runId"`
	GrantID     string `json:"grantId"`
}

// Fence is the caller-authoritative workspace execution manifest.  The
// container adapter must derive the same value from the inspected generation;
// it must never accept the request value on trust.
type Fence struct {
	WorkspaceExecutionManifestRef string `json:"workspaceExecutionManifestRef" validate:"required"`
}

// RendererProcessIdentity is the exact renderer process generation inside a
// sandbox.  StartTicks closes PID reuse without coupling this provider
// contract to a particular cgroup layout.
type RendererProcessIdentity struct {
	PID        int64  `json:"pid" validate:"required"`
	StartTicks string `json:"startTicks" validate:"required"`
}

// Purpose is a closed tagged union at this contract version.  Each variant is
// validated exactly; fields belonging to another variant are rejected rather
// than ignored.  New variants can be added without changing StopRequest.
type Purpose struct {
	Kind                    string                   `json:"kind" validate:"required"`
	SessionID               string                   `json:"sessionId,omitempty"`
	Nonce                   string                   `json:"nonce,omitempty"`
	RendererProcessIdentity *RendererProcessIdentity `json:"rendererProcessIdentity,omitempty"`
}

// ExpectedGeneration is the immutable execution epoch the caller authorizes
// the provider to stop.  ContainerID must identify the container itself, not a
// reusable name.
type ExpectedGeneration struct {
	ContainerID        string `json:"containerId" validate:"required"`
	ContainerCreatedAt string `json:"containerCreatedAt" validate:"required"`
	ExecutionStartedAt string `json:"executionStartedAt" validate:"required"`
	RestartCount       int    `json:"restartCount" validate:"required"`
}

// StopRequest is the full authority captured before any container effect.
// RequestFingerprint is the frozen cross-layer idempotency authority and must
// equal ComputeRequestFingerprint for these exact fields and purpose variant.
type StopRequest struct {
	OperationID        string             `json:"operationId" validate:"required"`
	RequestFingerprint string             `json:"requestFingerprint" validate:"required"`
	Source             Source             `json:"source" validate:"required"`
	Owner              Owner              `json:"owner" validate:"required"`
	Fence              Fence              `json:"fence" validate:"required"`
	ExpectedGeneration ExpectedGeneration `json:"expectedGeneration" validate:"required"`
	Purpose            Purpose            `json:"purpose" validate:"required"`
}

// TerminalGeneration is the exact expected epoch plus the immutable exit
// facts observed after the provider stop completed.
type TerminalGeneration struct {
	ExpectedGeneration
	ExecutionFinishedAt string `json:"executionFinishedAt" validate:"required"`
	ExitCode            int    `json:"exitCode" validate:"required"`
	OOMKilled           bool   `json:"oomKilled" validate:"required"`
}

// Receipt is an immutable historical proof that the exact requested
// generation was observed in the terminal exited state.  It echoes the full
// request so a receipt cannot be detached from its authority.
type Receipt struct {
	Version            int                `json:"version" validate:"required"`
	Kind               string             `json:"kind" validate:"required"`
	Request            StopRequest        `json:"request" validate:"required"`
	ReceiptRef         string             `json:"receiptRef" validate:"required"`
	ReceiptDigest      string             `json:"receiptDigest" validate:"required"`
	TerminalGeneration TerminalGeneration `json:"terminalGeneration" validate:"required"`
	StoppedAt          string             `json:"stoppedAt" validate:"required"`
}

// StopAuthority is the minimal exact proof carried by a downstream operation.
// RequireCurrentReceipt resolves it back to the full immutable claim and
// receipt before freshly re-proving provider state.
type StopAuthority struct {
	OperationID        string             `json:"operationId" validate:"required"`
	ReceiptRef         string             `json:"receiptRef" validate:"required"`
	ReceiptDigest      string             `json:"receiptDigest" validate:"required"`
	TerminalGeneration TerminalGeneration `json:"terminalGeneration" validate:"required"`
	Fence              Fence              `json:"fence" validate:"required"`
}

// Observation reports only durable operation state.  A partial observation
// means the immutable claim exists but no immutable terminal receipt does.
type Observation struct {
	Status  string       `json:"status" validate:"required"`
	Request *StopRequest `json:"request,omitempty"`
	Receipt *Receipt     `json:"receipt,omitempty"`
}

// GenerationObservationRequest authorizes a read-only provider inspection
// before the caller knows the current container generation.
type GenerationObservationRequest struct {
	Source Source `json:"source" validate:"required"`
	Owner  Owner  `json:"owner" validate:"required"`
	Fence  Fence  `json:"fence" validate:"required"`
}

// GenerationObservation is the stable public discovery response. State is
// closed to running|stopped; ambiguous provider states fail instead of leaking
// through as authority. Owner includes the operation-local WorkingCopyID after
// the provider-owned subset has been verified against container metadata.
type GenerationObservation struct {
	Source     Source             `json:"source" validate:"required"`
	Owner      Owner              `json:"owner" validate:"required"`
	Fence      Fence              `json:"fence" validate:"required"`
	Generation ExpectedGeneration `json:"generation" validate:"required"`
	State      string             `json:"state" validate:"required"`
	ObservedAt string             `json:"observedAt" validate:"required"`
}

// ProviderGenerationObservationRequest is the provider-owned form of current
// generation discovery. Unlike GenerationObservationRequest it contains no
// operation-local WorkingCopyID, so document rendering and future provider
// effects do not have to invent an unrelated business identifier.
type ProviderGenerationObservationRequest struct {
	Source Source        `json:"source" validate:"required"`
	Owner  ProviderOwner `json:"owner" validate:"required"`
	Fence  Fence         `json:"fence" validate:"required"`
}

// ProviderGenerationObservation binds the complete provider-observable owner,
// fence, immutable container epoch, and closed runtime state.
type ProviderGenerationObservation struct {
	Source     Source             `json:"source" validate:"required"`
	Owner      ProviderOwner      `json:"owner" validate:"required"`
	Fence      Fence              `json:"fence" validate:"required"`
	Generation ExpectedGeneration `json:"generation" validate:"required"`
	State      string             `json:"state" validate:"required"`
	ObservedAt string             `json:"observedAt" validate:"required"`
}

// RuntimeState is the narrow state surface needed to distinguish an exact
// exited generation from running, paused, restarting, dead, or ambiguous
// provider states.
type RuntimeState struct {
	Status     string `json:"status"`
	Running    bool   `json:"running"`
	Paused     bool   `json:"paused"`
	Restarting bool   `json:"restarting"`
	Dead       bool   `json:"dead"`
	PID        int    `json:"pid"`
}

// ContainerGeneration is the provider observation used internally and by the
// read-only current-generation endpoint.  Exit fields may be empty/default
// while the generation is running; StopOnce publishes them only after strict
// terminal validation.
type ContainerGeneration struct {
	ExpectedGeneration
	ExecutionFinishedAt string `json:"executionFinishedAt"`
	ExitCode            int    `json:"exitCode"`
	OOMKilled           bool   `json:"oomKilled"`
}

// CurrentGenerationObservation is produced by the narrow ContainerClient.
// Source, Owner, and Fence are provider-observed values, not request echoes.
type CurrentGenerationObservation struct {
	Source     Source              `json:"source"`
	Owner      ProviderOwner       `json:"owner"`
	Fence      Fence               `json:"fence"`
	Generation ContainerGeneration `json:"generation"`
	State      RuntimeState        `json:"state"`
}

// ExactStopTarget is the only mutable provider command exposed by this
// package.  An adapter must address ExpectedGeneration.ContainerID directly
// and reject identity or fence drift; it must not list containers or stop by a
// reusable sandbox name.
type ExactStopTarget struct {
	Source             Source             `json:"source"`
	Owner              Owner              `json:"owner"`
	Fence              Fence              `json:"fence"`
	ExpectedGeneration ExpectedGeneration `json:"expectedGeneration"`
}
