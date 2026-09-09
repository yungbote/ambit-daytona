// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import "github.com/daytonaio/runner/pkg/generationstop"

const (
	MaximumWorkingTreeInventoryPageBytes   = 4 * 1024 * 1024
	MaximumWorkingTreeInventoryPageEntries = 4096
	MaximumWorkingTreeInventoryIndexBytes  = 4 * 1024 * 1024
	workingTreeInventoryContract           = "ambit.working-copy-stopped-working-tree-inventory/v1"
	// These are physical scratch/transport budgets, independent of page or
	// total entry counts. User file bytes retain their separate 8 GiB budget.
	maximumInventoryMetadataBytes int64 = 8 * 1024 * 1024 * 1024
	maximumInventoryArchiveBytes  int64 = 16 * 1024 * 1024 * 1024
	maximumInventoryScratchBytes  int64 = 64 * 1024 * 1024 * 1024
)

type WorkingTreeInventoryRequest struct {
	Generation            CaptureGenerationBinding `json:"generation" validate:"required"`
	ExcludedPaths         []string                 `json:"excludedPaths" validate:"required"`
	MaximumDepth          int                      `json:"maximumDepth" validate:"required"`
	MaximumFileBytes      int64                    `json:"maximumFileBytes" validate:"required"`
	MaximumAggregateBytes int64                    `json:"maximumAggregateBytes" validate:"required"`
	MaximumPageEntries    int                      `json:"maximumPageEntries" validate:"required"`
	MaximumPageBytes      int                      `json:"maximumPageBytes" validate:"required"`
}

type WorkingTreeInventoryPageDescriptor struct {
	PageIndex  int    `json:"pageIndex" validate:"required"`
	EntryCount int    `json:"entryCount" validate:"required"`
	ByteLength int    `json:"byteLength" validate:"required"`
	SHA256     string `json:"sha256" validate:"required"`
	FirstPath  string `json:"firstPath" validate:"required"`
	LastPath   string `json:"lastPath" validate:"required"`
}

type WorkingTreeInventoryReceipt struct {
	Request            WorkingTreeInventoryRequest          `json:"request" validate:"required"`
	ProviderResourceID string                               `json:"providerResourceId" validate:"required"`
	TerminalGeneration generationstop.TerminalGeneration    `json:"terminalGeneration" validate:"required"`
	Pages              []WorkingTreeInventoryPageDescriptor `json:"pages" validate:"required"`
	EntryCount         int64                                `json:"entryCount" validate:"required"`
	AggregateBytes     int64                                `json:"aggregateBytes" validate:"required"`
	BytePack           WorkingTreeInventoryBytePack         `json:"bytePack" validate:"required"`
	InventoryDigest    string                               `json:"inventoryDigest" validate:"required"`
	ObservedAt         string                               `json:"observedAt" validate:"required"`
}

type WorkingTreeInventoryBytePart struct {
	ByteOffset int64  `json:"byteOffset" validate:"required"`
	ByteLength int64  `json:"byteLength" validate:"required"`
	SHA256     string `json:"sha256" validate:"required"`
}

type WorkingTreeInventoryBytePack struct {
	ByteLength int64                          `json:"byteLength" validate:"required"`
	SHA256     string                         `json:"sha256" validate:"required"`
	Parts      []WorkingTreeInventoryBytePart `json:"parts" validate:"required"`
}

type WorkingTreeInventoryRangeRequest struct {
	Request            WorkingTreeInventoryRequest `json:"request" validate:"required"`
	ProviderResourceID string                      `json:"providerResourceId" validate:"required"`
	InventoryDigest    string                      `json:"inventoryDigest" validate:"required"`
	Offset             int64                       `json:"offset" validate:"required"`
	MaximumBytes       int64                       `json:"maximumBytes" validate:"required"`
}

type WorkingTreeInventoryRange struct {
	ProviderResourceID string `json:"providerResourceId" validate:"required"`
	InventoryDigest    string `json:"inventoryDigest" validate:"required"`
	Offset             int64  `json:"offset" validate:"required"`
	ByteLength         int64  `json:"byteLength" validate:"required"`
	TotalByteLength    int64  `json:"totalByteLength" validate:"required"`
	EOF                bool   `json:"eof" validate:"required"`
	BytesBase64        string `json:"bytesBase64" validate:"required"`
}

type WorkingTreeInventoryPageRequest struct {
	Request            WorkingTreeInventoryRequest `json:"request" validate:"required"`
	ProviderResourceID string                      `json:"providerResourceId" validate:"required"`
	PageIndex          int                         `json:"pageIndex" validate:"required"`
}

type WorkingTreeInventoryPage struct {
	ProviderResourceID string                    `json:"providerResourceId" validate:"required"`
	PageIndex          int                       `json:"pageIndex" validate:"required"`
	Entries            []StoppedWorkingTreeEntry `json:"entries" validate:"required"`
	PageDigest         string                    `json:"pageDigest" validate:"required"`
}

type WorkingTreeInventoryDeletionReceipt struct {
	Request            WorkingTreeInventoryRequest `json:"request" validate:"required"`
	ProviderResourceID string                      `json:"providerResourceId" validate:"required"`
	Status             string                      `json:"status" validate:"required" enums:"absent"`
}

type WorkingTreeInventoryCapability struct {
	Contract              string `json:"contract" validate:"required"`
	SemanticZoneRef       string `json:"semanticZoneRef" validate:"required"`
	MaximumDepth          int    `json:"maximumDepth" validate:"required"`
	MaximumFileBytes      int64  `json:"maximumFileBytes" validate:"required"`
	MaximumAggregateBytes int64  `json:"maximumAggregateBytes" validate:"required"`
	MaximumPageEntries    int    `json:"maximumPageEntries" validate:"required"`
	MaximumPageBytes      int    `json:"maximumPageBytes" validate:"required"`
	MaximumIndexBytes     int    `json:"maximumIndexBytes" validate:"required"`
	MaximumReadBytes      int64  `json:"maximumReadBytes" validate:"required"`
}
