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
	ProviderResourceID  string `json:"providerResourceId"`
	ExpectedProfile     string `json:"expectedProfile"`
	ExpectedRuntimeKind string `json:"expectedRuntimeKind"`
}

// Owner is the complete product authority whose provider effect is being
// stopped.  Keeping every dimension in the durable claim prevents a replay
// from silently crossing a tenant, principal, run, grant, or working copy.
type Owner struct {
	TenantID      string `json:"tenantId"`
	UserID        string `json:"userId"`
	WorkspaceID   string `json:"workspaceId"`
	RunID         string `json:"runId"`
	GrantID       string `json:"grantId"`
	WorkingCopyID string `json:"workingCopyId"`
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
	WorkspaceExecutionManifestRef string `json:"workspaceExecutionManifestRef"`
}

// RendererProcessIdentity is the exact renderer process generation inside a
// sandbox.  StartTicks closes PID reuse without coupling this provider
// contract to a particular cgroup layout.
type RendererProcessIdentity struct {
	PID        int64  `json:"pid"`
	StartTicks string `json:"startTicks"`
}

// Purpose is a closed tagged union at this contract version.  Each variant is
// validated exactly; fields belonging to another variant are rejected rather
// than ignored.  New variants can be added without changing StopRequest.
type Purpose struct {
	Kind                    string                   `json:"kind"`
	SessionID               string                   `json:"sessionId,omitempty"`
	Nonce                   string                   `json:"nonce,omitempty"`
	RendererProcessIdentity *RendererProcessIdentity `json:"rendererProcessIdentity,omitempty"`
}

// ExpectedGeneration is the immutable execution epoch the caller authorizes
// the provider to stop.  ContainerID must identify the container itself, not a
// reusable name.
type ExpectedGeneration struct {
	ContainerID        string `json:"containerId"`
	ContainerCreatedAt string `json:"containerCreatedAt"`
	ExecutionStartedAt string `json:"executionStartedAt"`
	RestartCount       int    `json:"restartCount"`
}

// StopRequest is the full authority captured before any container effect.
// RequestFingerprint is an upstream domain idempotency authority.  The runner
// validates its shape but does not attempt to recompute a second authority
// from the narrower provider-visible fields.
type StopRequest struct {
	OperationID        string             `json:"operationId"`
	RequestFingerprint string             `json:"requestFingerprint"`
	Source             Source             `json:"source"`
	Owner              Owner              `json:"owner"`
	Fence              Fence              `json:"fence"`
	ExpectedGeneration ExpectedGeneration `json:"expectedGeneration"`
	Purpose            Purpose            `json:"purpose"`
}

// TerminalGeneration is the exact expected epoch plus the immutable exit
// facts observed after the provider stop completed.
type TerminalGeneration struct {
	ExpectedGeneration
	ExecutionFinishedAt string `json:"executionFinishedAt"`
	ExitCode            int    `json:"exitCode"`
	OOMKilled           bool   `json:"oomKilled"`
}

// Receipt is an immutable historical proof that the exact requested
// generation was observed in the terminal exited state.  It echoes the full
// request so a receipt cannot be detached from its authority.
type Receipt struct {
	Version            int                `json:"version"`
	Kind               string             `json:"kind"`
	Request            StopRequest        `json:"request"`
	ReceiptRef         string             `json:"receiptRef"`
	ReceiptDigest      string             `json:"receiptDigest"`
	TerminalGeneration TerminalGeneration `json:"terminalGeneration"`
	StoppedAt          string             `json:"stoppedAt"`
}

// StopAuthority is the minimal exact proof carried by a downstream operation.
// RequireCurrentReceipt resolves it back to the full immutable claim and
// receipt before freshly re-proving provider state.
type StopAuthority struct {
	OperationID        string             `json:"operationId"`
	ReceiptRef         string             `json:"receiptRef"`
	ReceiptDigest      string             `json:"receiptDigest"`
	TerminalGeneration TerminalGeneration `json:"terminalGeneration"`
	Fence              Fence              `json:"fence"`
}

// Observation reports only durable operation state.  A partial observation
// means the immutable claim exists but no immutable terminal receipt does.
type Observation struct {
	Status  string       `json:"status"`
	Request *StopRequest `json:"request,omitempty"`
	Receipt *Receipt     `json:"receipt,omitempty"`
}

// GenerationObservationRequest authorizes a read-only provider inspection
// before the caller knows the current container generation.
type GenerationObservationRequest struct {
	Source Source `json:"source"`
	Owner  Owner  `json:"owner"`
	Fence  Fence  `json:"fence"`
}

// GenerationObservation is the stable public discovery response. State is
// closed to running|stopped; ambiguous provider states fail instead of leaking
// through as authority. Owner includes the operation-local WorkingCopyID after
// the provider-owned subset has been verified against container metadata.
type GenerationObservation struct {
	Source     Source             `json:"source"`
	Owner      Owner              `json:"owner"`
	Fence      Fence              `json:"fence"`
	Generation ExpectedGeneration `json:"generation"`
	State      string             `json:"state"`
	ObservedAt string             `json:"observedAt"`
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
