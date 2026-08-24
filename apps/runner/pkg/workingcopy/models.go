// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

const MaximumCaptureBytes int64 = 64 * 1024 * 1024

type CaptureAuthorityArtifact struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

type CaptureAuthority struct {
	AuthorityRef string                   `json:"authorityRef"`
	RoleRef      string                   `json:"roleRef"`
	Protocol     CaptureAuthorityArtifact `json:"protocol"`
	Helper       CaptureAuthorityArtifact `json:"helper"`
}

// SourceAddress is the exact provider-owned workspace generation address.
// ExpectedRuntimeKind is intentionally explicit instead of inferred from the
// profile so future provider profiles cannot silently widen this primitive.
type SourceAddress struct {
	ProviderResourceID  string `json:"providerResourceId"`
	WorkspaceID         string `json:"workspaceId"`
	TenantID            string `json:"tenantId"`
	UserID              string `json:"userId"`
	ExpectedProfile     string `json:"expectedProfile"`
	ExpectedRuntimeKind string `json:"expectedRuntimeKind"`
}

type CaptureSelector struct {
	SemanticZoneRef  string `json:"semanticZoneRef"`
	ZoneRelativePath string `json:"zoneRelativePath"`
}

type CaptureBinding struct {
	ProviderName       string           `json:"providerName"`
	RequestFingerprint string           `json:"requestFingerprint"`
	Authority          CaptureAuthority `json:"authority"`
	Source             SourceAddress    `json:"source"`
	Selector           CaptureSelector  `json:"selector"`
}

type CaptureIdentity struct {
	CaptureBinding
	ProviderResourceID string `json:"providerResourceId"`
}

type CaptureReceipt struct {
	CaptureIdentity
	ByteLength           int64  `json:"byteLength"`
	ProviderSHA256Digest string `json:"providerSha256Digest"`
	CapturedAt           string `json:"capturedAt"`
}

type CaptureObservation struct {
	Status   string           `json:"status"`
	Binding  *CaptureBinding  `json:"binding,omitempty"`
	Identity *CaptureIdentity `json:"identity,omitempty"`
	Receipt  *CaptureReceipt  `json:"receipt,omitempty"`
}

type CaptureReadRequest struct {
	CaptureIdentity
	ExpectedByteLength int64 `json:"expectedByteLength"`
	MaximumBytes       int64 `json:"maximumBytes"`
}

type CaptureReadResponse struct {
	BytesBase64 string `json:"bytesBase64"`
}

type CaptureExistsResponse struct {
	Exists bool `json:"exists"`
}
