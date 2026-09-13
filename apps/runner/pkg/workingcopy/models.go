// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import "github.com/daytonaio/runner/pkg/generationstop"

const (
	// Bound per-capture temporary disk custody independently from the fixed
	// streaming buffer. Larger files require a deliberate capacity decision.
	MaximumCaptureBytes         int64 = 1024 * 1024 * 1024
	MaximumReadBytes            int64 = 4 * 1024 * 1024
	MaximumRosterDepth                = 32
	MaximumRosterEntries              = 1024
	MaximumRosterFileBytes      int64 = 8 * 1024 * 1024
	MaximumRosterAggregateBytes int64 = 16 * 1024 * 1024
)

type CaptureAuthorityArtifact struct {
	Ref    string `json:"ref" validate:"required"`
	Digest string `json:"digest" validate:"required"`
}

type CaptureAuthority struct {
	AuthorityRef string                   `json:"authorityRef" validate:"required"`
	LineageRef   string                   `json:"lineageRef" validate:"required"`
	RoleRef      string                   `json:"roleRef" validate:"required"`
	Protocol     CaptureAuthorityArtifact `json:"protocol" validate:"required"`
	Helper       CaptureAuthorityArtifact `json:"helper" validate:"required"`
}

type SourceAddress = generationstop.Source
type CaptureOwner = generationstop.Owner

type CaptureSelector struct {
	SemanticZoneRef  string `json:"semanticZoneRef" validate:"required"`
	ZoneRelativePath string `json:"zoneRelativePath" validate:"required"`
}

type CaptureCapabilitiesRequest struct {
	Authority CaptureAuthority     `json:"authority" validate:"required"`
	Source    SourceAddress        `json:"source" validate:"required"`
	Owner     CaptureOwner         `json:"owner" validate:"required"`
	Fence     generationstop.Fence `json:"fence" validate:"required"`
}

type CaptureCapabilities struct {
	Authority                   CaptureAuthority               `json:"authority" validate:"required"`
	StoppedWorkingTreeInventory WorkingTreeInventoryCapability `json:"stoppedWorkingTreeInventory" validate:"required"`
	FileSnapshot                *FileSnapshotCapability        `json:"fileSnapshot,omitempty"`
}

const FileSnapshotContract = "ambit.working-copy-file-snapshot/v1"

// FileSnapshotSource selects bytes from one execution epoch without authorizing
// its termination. The native reader must exclude writers while copying bytes.
type FileSnapshotSource struct {
	Contract   string                            `json:"contract" validate:"required"`
	Fence      generationstop.Fence              `json:"fence" validate:"required"`
	Generation generationstop.ExpectedGeneration `json:"generation" validate:"required"`
}

type FileSnapshotCapability struct {
	Contract     string `json:"contract" validate:"required"`
	MaximumBytes int64  `json:"maximumBytes" validate:"required"`
}

type CaptureBinding struct {
	ProviderName       string                       `json:"providerName" validate:"required"`
	RequestFingerprint string                       `json:"requestFingerprint" validate:"required"`
	Authority          CaptureAuthority             `json:"authority" validate:"required"`
	Source             SourceAddress                `json:"source" validate:"required"`
	Owner              CaptureOwner                 `json:"owner" validate:"required"`
	StopAuthority      generationstop.StopAuthority `json:"stopAuthority,omitzero"`
	FileSnapshot       FileSnapshotSource           `json:"fileSnapshot,omitzero"`
	Selector           CaptureSelector              `json:"selector" validate:"required"`
}

// CaptureGenerationBinding admits a stopped generation independently from
// selecting any individual file within it.
type CaptureGenerationBinding struct {
	ProviderName       string                       `json:"providerName" validate:"required"`
	RequestFingerprint string                       `json:"requestFingerprint" validate:"required"`
	Authority          CaptureAuthority             `json:"authority" validate:"required"`
	Source             SourceAddress                `json:"source" validate:"required"`
	Owner              CaptureOwner                 `json:"owner" validate:"required"`
	StopAuthority      generationstop.StopAuthority `json:"stopAuthority" validate:"required"`
}

func (binding CaptureBinding) generationBinding() CaptureGenerationBinding {
	return CaptureGenerationBinding{
		ProviderName: binding.ProviderName, RequestFingerprint: binding.RequestFingerprint,
		Authority: binding.Authority, Source: binding.Source,
		Owner: binding.Owner, StopAuthority: binding.StopAuthority,
	}
}

// Private working-tree entries preserve link targets as lexical data and
// explicitly record runtime entries that are not portable. Docker archives
// may omit sockets, so this roster is not a per-path socket inventory.
type StoppedWorkingTreeEntry struct {
	ZoneRelativePath string  `json:"zoneRelativePath" validate:"required"`
	Name             string  `json:"name" validate:"required"`
	Kind             string  `json:"kind" validate:"required" enums:"regular_file,directory,symlink,excluded"`
	Size             int64   `json:"size" validate:"required"`
	Mode             *string `json:"mode" validate:"required" extensions:"x-nullable"`
	SHA256           *string `json:"sha256" validate:"required" extensions:"x-nullable"`
	ByteOffset       *int64  `json:"byteOffset,omitempty"`
	LinkTarget       *string `json:"linkTarget,omitempty"`
	ExcludedKind     string  `json:"excludedKind,omitempty" enums:"fifo,character_device,block_device"`
}

type CaptureIdentity struct {
	CaptureBinding
	ProviderResourceID string `json:"providerResourceId" validate:"required"`
}

type CaptureReceipt struct {
	CaptureIdentity
	TotalByteLength      int64  `json:"totalByteLength" validate:"required"`
	ProviderSHA256Digest string `json:"providerSha256Digest" validate:"required"`
	CapturedAt           string `json:"capturedAt" validate:"required"`
}

type CaptureObservation struct {
	Status   string           `json:"status" validate:"required"`
	Binding  *CaptureBinding  `json:"binding,omitempty"`
	Identity *CaptureIdentity `json:"identity,omitempty"`
	Receipt  *CaptureReceipt  `json:"receipt,omitempty"`
}

type CaptureReadRequest struct {
	CaptureIdentity
	ExpectedTotalByteLength      int64  `json:"expectedTotalByteLength" validate:"required"`
	ExpectedProviderSHA256Digest string `json:"expectedProviderSha256Digest" validate:"required"`
	Offset                       int64  `json:"offset" validate:"required"`
	MaximumBytes                 int64  `json:"maximumBytes" validate:"required"`
}

type CaptureReadResponse struct {
	CaptureIdentity
	TotalByteLength      int64  `json:"totalByteLength" validate:"required"`
	ProviderSHA256Digest string `json:"providerSha256Digest" validate:"required"`
	Offset               int64  `json:"offset" validate:"required"`
	ByteLength           int64  `json:"byteLength"`
	EOF                  bool   `json:"eof"`
	BytesBase64          string `json:"bytesBase64"`
}

type CaptureDeleteReceipt struct {
	CaptureIdentity
	Outcome string `json:"outcome" validate:"required"`
}

type CaptureExistsResponse struct {
	CaptureIdentity
	Status  string          `json:"status" validate:"required"`
	Exists  bool            `json:"exists"`
	Receipt *CaptureReceipt `json:"receipt,omitempty"`
}

type StoppedDirectoryRosterEntry struct {
	ZoneRelativePath string  `json:"zoneRelativePath" validate:"required"`
	Name             string  `json:"name" validate:"required"`
	Kind             string  `json:"kind" validate:"required"`
	Size             int64   `json:"size" validate:"required"`
	Mode             *string `json:"mode" validate:"required" extensions:"x-nullable"`
	SHA256           *string `json:"sha256" validate:"required" extensions:"x-nullable"`
}

type StoppedDirectoryRosterRequest struct {
	Anchor                CaptureBinding  `json:"anchor" validate:"required"`
	Selector              CaptureSelector `json:"selector" validate:"required"`
	MaximumDepth          int             `json:"maximumDepth" validate:"required"`
	MaximumEntries        int             `json:"maximumEntries" validate:"required"`
	MaximumFileBytes      int64           `json:"maximumFileBytes" validate:"required"`
	MaximumAggregateBytes int64           `json:"maximumAggregateBytes" validate:"required"`
}

type StoppedDirectoryRosterReceipt struct {
	Request            StoppedDirectoryRosterRequest     `json:"request" validate:"required"`
	TerminalGeneration generationstop.TerminalGeneration `json:"terminalGeneration" validate:"required"`
	Entries            []StoppedDirectoryRosterEntry     `json:"entries" validate:"required"`
	RosterDigest       string                            `json:"rosterDigest" validate:"required"`
	ObservedAt         string                            `json:"observedAt" validate:"required"`
}
