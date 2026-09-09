/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { Type } from 'class-transformer'
import {
  ArrayMaxSize,
  Equals,
  IsArray,
  IsBoolean,
  IsDateString,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
  MinLength,
  ValidateIf,
  ValidateNested,
} from 'class-validator'
import { ApiProperty, ApiPropertyOptional, ApiSchema, OmitType } from '@nestjs/swagger'
import {
  SandboxExecutionOwnerDto as WorkingCopyCaptureOwnerDto,
  SandboxExecutionSourceDto as WorkingCopyCaptureSourceDto,
} from './sandbox-execution-authority.dto'
import {
  SandboxGenerationObservationRequestDto,
  SandboxGenerationStopAuthorityDto,
  SandboxTerminalGenerationDto,
} from './sandbox-generation-stop.dto'

export { WorkingCopyCaptureOwnerDto, WorkingCopyCaptureSourceDto }

export const MAXIMUM_WORKING_COPY_CAPTURE_BYTES = 64 * 1024 * 1024
export const MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES = 1 * 1024 * 1024
export const USER_FILES_SEMANTIC_ZONE_REF = 'ambit.workspace-zone/user-files@1'
export const MAXIMUM_USER_FILE_CAPTURE_BYTES = 1024 * 1024 * 1024
export const MAXIMUM_USER_FILE_READ_BYTES = 4 * 1024 * 1024
export const MAXIMUM_WORKING_TREE_DEPTH = 64
export const MAXIMUM_WORKING_TREE_AGGREGATE_BYTES = 8 * 1024 * 1024 * 1024
export const MAXIMUM_WORKING_TREE_INVENTORY_PAGE_BYTES = 4 * 1024 * 1024
export const MAXIMUM_WORKING_TREE_INVENTORY_PAGE_ENTRIES = 4096
export const MAXIMUM_WORKING_TREE_INVENTORY_INDEX_BYTES = 4 * 1024 * 1024
export const MAXIMUM_WORKING_COPY_ROSTER_DEPTH = 32
export const MAXIMUM_WORKING_COPY_ROSTER_ENTRIES = 1024
export const MAXIMUM_WORKING_COPY_ROSTER_FILE_BYTES = 8 * 1024 * 1024
export const MAXIMUM_WORKING_COPY_ROSTER_AGGREGATE_BYTES = 16 * 1024 * 1024

@ApiSchema({ name: 'WorkingCopyCaptureAuthorityArtifact' })
export class WorkingCopyCaptureAuthorityArtifactDto {
  @ApiProperty({ example: 'ambit.runtime-interface/working-copy-capture@2' })
  @IsString()
  @MinLength(1)
  @MaxLength(512)
  ref: string

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  digest: string
}

@ApiSchema({ name: 'WorkingCopyCaptureAuthority' })
export class WorkingCopyCaptureAuthorityDto {
  @ApiProperty({
    pattern: '^ambit\\.working-copy-capture-authority:v2:sha256:[0-9a-f]{64}$',
  })
  @Matches(/^ambit\.working-copy-capture-authority:v2:sha256:[0-9a-f]{64}$/)
  authorityRef: string

  @ApiProperty({ maxLength: 512 })
  @IsString()
  @MinLength(1)
  @MaxLength(512)
  lineageRef: string

  @ApiProperty({ enum: ['ambit.runtime-component/working-copy-capture@2'] })
  @Equals('ambit.runtime-component/working-copy-capture@2')
  roleRef: 'ambit.runtime-component/working-copy-capture@2'

  @ApiProperty({ type: WorkingCopyCaptureAuthorityArtifactDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureAuthorityArtifactDto)
  protocol: WorkingCopyCaptureAuthorityArtifactDto

  @ApiProperty({ type: WorkingCopyCaptureAuthorityArtifactDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureAuthorityArtifactDto)
  helper: WorkingCopyCaptureAuthorityArtifactDto
}

@ApiSchema({ name: 'WorkingCopyCaptureCapabilitiesRequest' })
export class WorkingCopyCaptureCapabilitiesRequestDto extends SandboxGenerationObservationRequestDto {
  @ApiProperty({ type: WorkingCopyCaptureAuthorityDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureAuthorityDto)
  authority: WorkingCopyCaptureAuthorityDto
}

@ApiSchema({ name: 'WorkingTreeInventoryCapability' })
export class WorkingTreeInventoryCapabilityDto {
  @ApiProperty({ enum: [USER_FILES_SEMANTIC_ZONE_REF] })
  @Equals(USER_FILES_SEMANTIC_ZONE_REF)
  semanticZoneRef: typeof USER_FILES_SEMANTIC_ZONE_REF

  @ApiProperty({ minimum: 1, example: MAXIMUM_WORKING_TREE_DEPTH })
  @IsInt()
  @Min(1)
  maximumDepth: number

  @ApiProperty({ minimum: 1, example: MAXIMUM_WORKING_TREE_AGGREGATE_BYTES })
  @IsInt()
  @Min(1)
  maximumFileBytes: number

  @ApiProperty({ minimum: 1, example: MAXIMUM_WORKING_TREE_AGGREGATE_BYTES })
  @IsInt()
  @Min(1)
  maximumAggregateBytes: number

  @ApiProperty({ minimum: 1, example: MAXIMUM_USER_FILE_READ_BYTES })
  @IsInt()
  @Min(1)
  maximumReadBytes: number

  @ApiProperty({ enum: ['ambit.working-copy-stopped-working-tree-inventory/v1'] })
  @Equals('ambit.working-copy-stopped-working-tree-inventory/v1')
  contract: 'ambit.working-copy-stopped-working-tree-inventory/v1'

  @ApiProperty({ minimum: 1, example: MAXIMUM_WORKING_TREE_INVENTORY_PAGE_ENTRIES })
  @IsInt()
  @Min(1)
  maximumPageEntries: number

  @ApiProperty({ minimum: 1, example: MAXIMUM_WORKING_TREE_INVENTORY_PAGE_BYTES })
  @IsInt()
  @Min(1)
  maximumPageBytes: number

  @ApiProperty({ minimum: 1, example: MAXIMUM_WORKING_TREE_INVENTORY_INDEX_BYTES })
  @IsInt()
  @Min(1)
  maximumIndexBytes: number
}

@ApiSchema({ name: 'WorkingCopyCaptureCapabilities' })
export class WorkingCopyCaptureCapabilitiesDto {
  @ApiProperty({ type: WorkingCopyCaptureAuthorityDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureAuthorityDto)
  authority: WorkingCopyCaptureAuthorityDto

  @ApiPropertyOptional({ type: WorkingTreeInventoryCapabilityDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => WorkingTreeInventoryCapabilityDto)
  stoppedWorkingTreeInventory?: WorkingTreeInventoryCapabilityDto
}

@ApiSchema({ name: 'WorkingCopyCaptureSelector' })
export class WorkingCopyCaptureSelectorDto {
  @ApiProperty({
    enum: ['ambit.workspace-zone/work@1', 'ambit.workspace-zone/outputs@1', USER_FILES_SEMANTIC_ZONE_REF],
  })
  @IsIn(['ambit.workspace-zone/work@1', 'ambit.workspace-zone/outputs@1', USER_FILES_SEMANTIC_ZONE_REF])
  semanticZoneRef:
    | 'ambit.workspace-zone/work@1'
    | 'ambit.workspace-zone/outputs@1'
    | typeof USER_FILES_SEMANTIC_ZONE_REF

  @ApiProperty({ description: 'Bounded canonical path relative to the admitted semantic zone.' })
  @IsString()
  @MinLength(1)
  @MaxLength(4096)
  zoneRelativePath: string
}

@ApiSchema({ name: 'WorkingCopyCaptureBinding' })
export class WorkingCopyCaptureBindingDto {
  @ApiProperty()
  @IsString()
  @MinLength(1)
  @MaxLength(512)
  providerName: string

  @ApiProperty({ pattern: '^[0-9a-f]{64}$' })
  @Matches(/^[0-9a-f]{64}$/)
  requestFingerprint: string

  @ApiProperty({ type: WorkingCopyCaptureAuthorityDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureAuthorityDto)
  authority: WorkingCopyCaptureAuthorityDto

  @ApiProperty({ type: WorkingCopyCaptureSourceDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureSourceDto)
  source: WorkingCopyCaptureSourceDto

  @ApiProperty({ type: WorkingCopyCaptureOwnerDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureOwnerDto)
  owner: WorkingCopyCaptureOwnerDto

  @ApiProperty({ type: SandboxGenerationStopAuthorityDto })
  @ValidateNested()
  @Type(() => SandboxGenerationStopAuthorityDto)
  stopAuthority: SandboxGenerationStopAuthorityDto

  @ApiProperty({ type: WorkingCopyCaptureSelectorDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureSelectorDto)
  selector: WorkingCopyCaptureSelectorDto
}

@ApiSchema({ name: 'WorkingCopyCaptureIdentity' })
export class WorkingCopyCaptureIdentityDto extends WorkingCopyCaptureBindingDto {
  @ApiProperty({
    pattern: '^daytona-working-copy-capture:v2:sha256:[0-9a-f]{64}$',
  })
  @Matches(/^daytona-working-copy-capture:v2:sha256:[0-9a-f]{64}$/)
  providerResourceId: string
}

@ApiSchema({ name: 'WorkingCopyCaptureReceipt' })
export class WorkingCopyCaptureReceiptDto extends WorkingCopyCaptureIdentityDto {
  @ApiProperty({ minimum: 0, maximum: MAXIMUM_USER_FILE_CAPTURE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_USER_FILE_CAPTURE_BYTES)
  totalByteLength: number

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  providerSha256Digest: string

  @ApiProperty({ format: 'date-time' })
  @IsDateString({ strict: true })
  capturedAt: string
}

@ApiSchema({ name: 'WorkingCopyCaptureObservation' })
export class WorkingCopyCaptureObservationDto {
  @ApiProperty({ enum: ['absent', 'partial', 'complete'] })
  @IsIn(['absent', 'partial', 'complete'])
  status: 'absent' | 'partial' | 'complete'

  @ApiPropertyOptional({ type: WorkingCopyCaptureBindingDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => WorkingCopyCaptureBindingDto)
  binding?: WorkingCopyCaptureBindingDto

  @ApiPropertyOptional({ type: WorkingCopyCaptureIdentityDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => WorkingCopyCaptureIdentityDto)
  identity?: WorkingCopyCaptureIdentityDto

  @ApiPropertyOptional({ type: WorkingCopyCaptureReceiptDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => WorkingCopyCaptureReceiptDto)
  receipt?: WorkingCopyCaptureReceiptDto
}

@ApiSchema({ name: 'WorkingCopyCaptureRead' })
export class WorkingCopyCaptureReadDto extends WorkingCopyCaptureIdentityDto {
  @ApiProperty({ minimum: 0, maximum: MAXIMUM_USER_FILE_CAPTURE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_USER_FILE_CAPTURE_BYTES)
  expectedTotalByteLength: number

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  expectedProviderSha256Digest: string

  @ApiProperty({ minimum: 0, maximum: MAXIMUM_USER_FILE_CAPTURE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_USER_FILE_CAPTURE_BYTES)
  offset: number

  @ApiProperty({ minimum: 1, maximum: MAXIMUM_USER_FILE_READ_BYTES })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_USER_FILE_READ_BYTES)
  maximumBytes: number
}

@ApiSchema({ name: 'WorkingCopyCaptureReadResponse' })
export class WorkingCopyCaptureReadResponseDto extends WorkingCopyCaptureIdentityDto {
  @ApiProperty({ minimum: 0, maximum: MAXIMUM_USER_FILE_CAPTURE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_USER_FILE_CAPTURE_BYTES)
  totalByteLength: number

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  providerSha256Digest: string

  @ApiProperty({ minimum: 0, maximum: MAXIMUM_USER_FILE_CAPTURE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_USER_FILE_CAPTURE_BYTES)
  offset: number

  @ApiProperty({ minimum: 0, maximum: MAXIMUM_USER_FILE_READ_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_USER_FILE_READ_BYTES)
  byteLength: number

  @ApiProperty()
  @IsBoolean()
  eof: boolean

  @ApiProperty({ description: 'Canonical RFC 4648 base64 encoding of the exact capture bytes.' })
  @IsString()
  bytesBase64: string
}

@ApiSchema({ name: 'WorkingCopyCaptureDeleteReceipt' })
export class WorkingCopyCaptureDeleteReceiptDto extends WorkingCopyCaptureIdentityDto {
  @ApiProperty({ enum: ['deleted', 'already_absent'] })
  @IsIn(['deleted', 'already_absent'])
  outcome: 'deleted' | 'already_absent'
}

@ApiSchema({ name: 'WorkingCopyCaptureExistsResponse' })
export class WorkingCopyCaptureExistsResponseDto extends WorkingCopyCaptureIdentityDto {
  @ApiProperty({ enum: ['absent', 'partial', 'complete'] })
  @IsIn(['absent', 'partial', 'complete'])
  status: 'absent' | 'partial' | 'complete'

  @ApiProperty()
  @IsBoolean()
  exists: boolean

  @ApiPropertyOptional({ type: WorkingCopyCaptureReceiptDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => WorkingCopyCaptureReceiptDto)
  receipt?: WorkingCopyCaptureReceiptDto
}

@ApiSchema({ name: 'StoppedWorkingCopyDirectoryRosterEntry' })
export class StoppedWorkingCopyDirectoryRosterEntryDto {
  @ApiProperty({ maxLength: 2048 })
  @IsString()
  @MinLength(1)
  @MaxLength(2048)
  zoneRelativePath: string

  @ApiProperty({ maxLength: 255 })
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  name: string

  @ApiProperty({ enum: ['regular_file', 'directory'] })
  @IsIn(['regular_file', 'directory'])
  kind: 'regular_file' | 'directory'

  @ApiProperty({ minimum: 0, maximum: MAXIMUM_WORKING_COPY_ROSTER_FILE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_WORKING_COPY_ROSTER_FILE_BYTES)
  size: number

  @ApiProperty({ nullable: true, pattern: '^[0-7]{3,4}$' })
  @ValidateIf((_object, value) => value !== null)
  @Matches(/^[0-7]{3,4}$/)
  mode: string | null

  @ApiProperty({ nullable: true, pattern: '^sha256:[0-9a-f]{64}$' })
  @ValidateIf((_object, value) => value !== null)
  @Matches(/^sha256:[0-9a-f]{64}$/)
  sha256: string | null
}

@ApiSchema({ name: 'StoppedWorkingCopyDirectoryRosterRequest' })
export class StoppedWorkingCopyDirectoryRosterRequestDto {
  @ApiProperty({ type: WorkingCopyCaptureBindingDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureBindingDto)
  anchor: WorkingCopyCaptureBindingDto

  @ApiProperty({ type: WorkingCopyCaptureSelectorDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureSelectorDto)
  selector: WorkingCopyCaptureSelectorDto

  @ApiProperty({ minimum: 1, maximum: MAXIMUM_WORKING_COPY_ROSTER_DEPTH })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_WORKING_COPY_ROSTER_DEPTH)
  maximumDepth: number

  @ApiProperty({ minimum: 1, maximum: MAXIMUM_WORKING_COPY_ROSTER_ENTRIES })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_WORKING_COPY_ROSTER_ENTRIES)
  maximumEntries: number

  @ApiProperty({ minimum: 1, maximum: MAXIMUM_WORKING_COPY_ROSTER_FILE_BYTES })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_WORKING_COPY_ROSTER_FILE_BYTES)
  maximumFileBytes: number

  @ApiProperty({ minimum: 1, maximum: MAXIMUM_WORKING_COPY_ROSTER_AGGREGATE_BYTES })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_WORKING_COPY_ROSTER_AGGREGATE_BYTES)
  maximumAggregateBytes: number
}

@ApiSchema({ name: 'StoppedWorkingCopyDirectoryRosterReceipt' })
export class StoppedWorkingCopyDirectoryRosterReceiptDto {
  @ApiProperty({ type: StoppedWorkingCopyDirectoryRosterRequestDto })
  @ValidateNested()
  @Type(() => StoppedWorkingCopyDirectoryRosterRequestDto)
  request: StoppedWorkingCopyDirectoryRosterRequestDto

  @ApiProperty({ type: SandboxTerminalGenerationDto })
  @ValidateNested()
  @Type(() => SandboxTerminalGenerationDto)
  terminalGeneration: SandboxTerminalGenerationDto

  @ApiProperty({ type: [StoppedWorkingCopyDirectoryRosterEntryDto] })
  @IsArray()
  @ArrayMaxSize(MAXIMUM_WORKING_COPY_ROSTER_ENTRIES)
  @ValidateNested({ each: true })
  @Type(() => StoppedWorkingCopyDirectoryRosterEntryDto)
  entries: StoppedWorkingCopyDirectoryRosterEntryDto[]

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  rosterDigest: string

  @ApiProperty({ format: 'date-time' })
  @IsDateString({ strict: true })
  observedAt: string
}

@ApiSchema({ name: 'WorkingCopyCaptureGeneration' })
export class WorkingCopyCaptureGenerationDto extends OmitType(WorkingCopyCaptureBindingDto, ['selector'] as const) {}

@ApiSchema({ name: 'StoppedWorkingCopyWorkingTreeEntry' })
export class StoppedWorkingCopyWorkingTreeEntryDto extends OmitType(StoppedWorkingCopyDirectoryRosterEntryDto, [
  'zoneRelativePath',
  'size',
  'kind',
] as const) {
  @ApiProperty({ enum: ['regular_file', 'directory', 'symlink', 'excluded'] })
  @IsIn(['regular_file', 'directory', 'symlink', 'excluded'])
  kind: 'regular_file' | 'directory' | 'symlink' | 'excluded'

  @ApiPropertyOptional({ description: 'Lexical symlink target; never resolved by roster capture.', maxLength: 4096 })
  @ValidateIf((entry) => entry.kind === 'symlink')
  @IsString()
  @MinLength(1)
  @MaxLength(4096)
  linkTarget?: string

  @ApiPropertyOptional({ enum: ['fifo', 'character_device', 'block_device'] })
  @ValidateIf((entry) => entry.kind === 'excluded')
  @IsIn(['fifo', 'character_device', 'block_device'])
  excludedKind?: 'fifo' | 'character_device' | 'block_device'

  @ApiProperty({ maxLength: 4096 })
  @IsString()
  @MinLength(1)
  @MaxLength(4096)
  zoneRelativePath: string

  @ApiProperty({ minimum: 0, maximum: MAXIMUM_WORKING_TREE_AGGREGATE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_WORKING_TREE_AGGREGATE_BYTES)
  size: number
  @ApiPropertyOptional({ minimum: 0, maximum: MAXIMUM_WORKING_TREE_AGGREGATE_BYTES })
  @ValidateIf((entry: StoppedWorkingCopyWorkingTreeEntryDto) => entry.kind === 'regular_file')
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_WORKING_TREE_AGGREGATE_BYTES)
  byteOffset?: number
}

@ApiSchema({ name: 'WorkingTreeInventoryRequest' })
export class WorkingTreeInventoryRequestDto {
  @ApiProperty({ type: WorkingCopyCaptureGenerationDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureGenerationDto)
  generation: WorkingCopyCaptureGenerationDto

  @ApiProperty({ type: [String] })
  @IsArray()
  @ArrayMaxSize(4096)
  @IsString({ each: true })
  @MaxLength(4096, { each: true })
  excludedPaths: string[]

  @ApiProperty({ minimum: 1, maximum: MAXIMUM_WORKING_TREE_DEPTH })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_WORKING_TREE_DEPTH)
  maximumDepth: number

  @ApiProperty({ minimum: 1, maximum: MAXIMUM_WORKING_TREE_AGGREGATE_BYTES })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_WORKING_TREE_AGGREGATE_BYTES)
  maximumFileBytes: number

  @ApiProperty({ minimum: 1, maximum: MAXIMUM_WORKING_TREE_AGGREGATE_BYTES })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_WORKING_TREE_AGGREGATE_BYTES)
  maximumAggregateBytes: number

  @ApiProperty({ minimum: 1, maximum: MAXIMUM_WORKING_TREE_INVENTORY_PAGE_ENTRIES })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_WORKING_TREE_INVENTORY_PAGE_ENTRIES)
  maximumPageEntries: number

  @ApiProperty({ minimum: 2, maximum: MAXIMUM_WORKING_TREE_INVENTORY_PAGE_BYTES })
  @IsInt()
  @Min(2)
  @Max(MAXIMUM_WORKING_TREE_INVENTORY_PAGE_BYTES)
  maximumPageBytes: number
}

@ApiSchema({ name: 'WorkingTreeInventoryPageDescriptor' })
export class WorkingTreeInventoryPageDescriptorDto {
  @ApiProperty({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER })
  @IsInt()
  @Min(0)
  @Max(Number.MAX_SAFE_INTEGER)
  pageIndex: number

  @ApiProperty({ minimum: 1, maximum: MAXIMUM_WORKING_TREE_INVENTORY_PAGE_ENTRIES })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_WORKING_TREE_INVENTORY_PAGE_ENTRIES)
  entryCount: number

  @ApiProperty({ minimum: 2, maximum: MAXIMUM_WORKING_TREE_INVENTORY_PAGE_BYTES })
  @IsInt()
  @Min(2)
  @Max(MAXIMUM_WORKING_TREE_INVENTORY_PAGE_BYTES)
  byteLength: number

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  sha256: string

  @ApiProperty({ minLength: 1, maxLength: 4096 })
  @IsString()
  @MinLength(1)
  @MaxLength(4096)
  firstPath: string

  @ApiProperty({ minLength: 1, maxLength: 4096 })
  @IsString()
  @MinLength(1)
  @MaxLength(4096)
  lastPath: string
}

@ApiSchema({ name: 'WorkingTreeInventoryBytePart' })
export class WorkingTreeInventoryBytePartDto {
  @ApiProperty({ minimum: 0 })
  @IsInt()
  @Min(0)
  byteOffset: number
  @ApiProperty({ minimum: 1, maximum: MAXIMUM_WORKING_TREE_AGGREGATE_BYTES })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_WORKING_TREE_AGGREGATE_BYTES)
  byteLength: number
  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  sha256: string
}

@ApiSchema({ name: 'WorkingTreeInventoryBytePack' })
export class WorkingTreeInventoryBytePackDto {
  @ApiProperty({ minimum: 0, maximum: MAXIMUM_WORKING_TREE_AGGREGATE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_WORKING_TREE_AGGREGATE_BYTES)
  byteLength: number
  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  sha256: string
  @ApiProperty({ type: [WorkingTreeInventoryBytePartDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => WorkingTreeInventoryBytePartDto)
  parts: WorkingTreeInventoryBytePartDto[]
}

@ApiSchema({ name: 'WorkingTreeInventoryReceipt' })
export class WorkingTreeInventoryReceiptDto {
  @ApiProperty({ type: WorkingTreeInventoryRequestDto })
  @ValidateNested()
  @Type(() => WorkingTreeInventoryRequestDto)
  request: WorkingTreeInventoryRequestDto

  @ApiProperty({ pattern: '^daytona-working-tree-inventory:v1:sha256:[0-9a-f]{64}$' })
  @Matches(/^daytona-working-tree-inventory:v1:sha256:[0-9a-f]{64}$/)
  providerResourceId: string

  @ApiProperty({ type: SandboxTerminalGenerationDto })
  @ValidateNested()
  @Type(() => SandboxTerminalGenerationDto)
  terminalGeneration: SandboxTerminalGenerationDto

  @ApiProperty({ type: [WorkingTreeInventoryPageDescriptorDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => WorkingTreeInventoryPageDescriptorDto)
  pages: WorkingTreeInventoryPageDescriptorDto[]

  @ApiProperty({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER })
  @IsInt()
  @Min(0)
  @Max(Number.MAX_SAFE_INTEGER)
  entryCount: number

  @ApiProperty({ minimum: 0, maximum: MAXIMUM_WORKING_TREE_AGGREGATE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_WORKING_TREE_AGGREGATE_BYTES)
  aggregateBytes: number

  @ApiProperty({ type: WorkingTreeInventoryBytePackDto })
  @ValidateNested()
  @Type(() => WorkingTreeInventoryBytePackDto)
  bytePack: WorkingTreeInventoryBytePackDto

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  inventoryDigest: string

  @ApiProperty({ format: 'date-time' })
  @IsDateString({ strict: true })
  observedAt: string
}

@ApiSchema({ name: 'WorkingTreeInventoryPageRequest' })
export class WorkingTreeInventoryPageRequestDto {
  @ApiProperty({ type: WorkingTreeInventoryRequestDto })
  @ValidateNested()
  @Type(() => WorkingTreeInventoryRequestDto)
  request: WorkingTreeInventoryRequestDto

  @ApiProperty({ pattern: '^daytona-working-tree-inventory:v1:sha256:[0-9a-f]{64}$' })
  @Matches(/^daytona-working-tree-inventory:v1:sha256:[0-9a-f]{64}$/)
  providerResourceId: string

  @ApiProperty({ minimum: 0 })
  @IsInt()
  @Min(0)
  pageIndex: number
}

@ApiSchema({ name: 'WorkingTreeInventoryPage' })
export class WorkingTreeInventoryPageDto {
  @ApiProperty({ pattern: '^daytona-working-tree-inventory:v1:sha256:[0-9a-f]{64}$' })
  @Matches(/^daytona-working-tree-inventory:v1:sha256:[0-9a-f]{64}$/)
  providerResourceId: string

  @ApiProperty({ minimum: 0 })
  @IsInt()
  @Min(0)
  pageIndex: number

  @ApiProperty({ type: [StoppedWorkingCopyWorkingTreeEntryDto] })
  @IsArray()
  @ArrayMaxSize(MAXIMUM_WORKING_TREE_INVENTORY_PAGE_ENTRIES)
  @ValidateNested({ each: true })
  @Type(() => StoppedWorkingCopyWorkingTreeEntryDto)
  entries: StoppedWorkingCopyWorkingTreeEntryDto[]

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  pageDigest: string
}

@ApiSchema({ name: 'WorkingTreeInventoryDeletionReceipt' })
export class WorkingTreeInventoryDeletionReceiptDto {
  @ApiProperty({ type: WorkingTreeInventoryRequestDto })
  @ValidateNested()
  @Type(() => WorkingTreeInventoryRequestDto)
  request: WorkingTreeInventoryRequestDto

  @ApiProperty({ pattern: '^daytona-working-tree-inventory:v1:sha256:[0-9a-f]{64}$' })
  @Matches(/^daytona-working-tree-inventory:v1:sha256:[0-9a-f]{64}$/)
  providerResourceId: string

  @ApiProperty({ enum: ['absent'] })
  @Equals('absent')
  status: 'absent'
}

@ApiSchema({ name: 'WorkingTreeInventoryRangeRequest' })
export class WorkingTreeInventoryRangeRequestDto extends OmitType(WorkingTreeInventoryPageRequestDto, [
  'pageIndex',
] as const) {
  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  inventoryDigest: string
  @ApiProperty({ minimum: 0 })
  @IsInt()
  @Min(0)
  offset: number
  @ApiProperty({ minimum: 1, maximum: MAXIMUM_USER_FILE_READ_BYTES })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_USER_FILE_READ_BYTES)
  maximumBytes: number
}

@ApiSchema({ name: 'WorkingTreeInventoryRange' })
export class WorkingTreeInventoryRangeDto {
  @ApiProperty({ pattern: '^daytona-working-tree-inventory:v1:sha256:[0-9a-f]{64}$' })
  @Matches(/^daytona-working-tree-inventory:v1:sha256:[0-9a-f]{64}$/)
  providerResourceId: string
  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  inventoryDigest: string
  @ApiProperty({ minimum: 0 })
  @IsInt()
  @Min(0)
  offset: number
  @ApiProperty({ minimum: 0, maximum: MAXIMUM_USER_FILE_READ_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_USER_FILE_READ_BYTES)
  byteLength: number
  @ApiProperty({ minimum: 0, maximum: MAXIMUM_WORKING_TREE_AGGREGATE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_WORKING_TREE_AGGREGATE_BYTES)
  totalByteLength: number
  @ApiProperty()
  @IsBoolean()
  eof: boolean
  @ApiProperty()
  @IsString()
  bytesBase64: string
}
