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
import { ApiProperty, ApiPropertyOptional, ApiSchema } from '@nestjs/swagger'
import {
  SandboxExecutionOwnerDto as WorkingCopyCaptureOwnerDto,
  SandboxExecutionSourceDto as WorkingCopyCaptureSourceDto,
} from './sandbox-execution-authority.dto'
import { SandboxGenerationStopAuthorityDto, SandboxTerminalGenerationDto } from './sandbox-generation-stop.dto'

export { WorkingCopyCaptureOwnerDto, WorkingCopyCaptureSourceDto }

export const MAXIMUM_WORKING_COPY_CAPTURE_BYTES = 64 * 1024 * 1024
export const MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES = 1 * 1024 * 1024
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

@ApiSchema({ name: 'WorkingCopyCaptureSelector' })
export class WorkingCopyCaptureSelectorDto {
  @ApiProperty({
    enum: ['ambit.workspace-zone/work@1', 'ambit.workspace-zone/outputs@1'],
  })
  @IsIn(['ambit.workspace-zone/work@1', 'ambit.workspace-zone/outputs@1'])
  semanticZoneRef: 'ambit.workspace-zone/work@1' | 'ambit.workspace-zone/outputs@1'

  @ApiProperty({ description: 'Bounded canonical path relative to the admitted semantic zone.' })
  @IsString()
  @MinLength(1)
  @MaxLength(2048)
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
  @ApiProperty({ minimum: 0, maximum: MAXIMUM_WORKING_COPY_CAPTURE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_WORKING_COPY_CAPTURE_BYTES)
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
  @ApiProperty({ minimum: 0, maximum: MAXIMUM_WORKING_COPY_CAPTURE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_WORKING_COPY_CAPTURE_BYTES)
  expectedTotalByteLength: number

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  expectedProviderSha256Digest: string

  @ApiProperty({ minimum: 0, maximum: MAXIMUM_WORKING_COPY_CAPTURE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_WORKING_COPY_CAPTURE_BYTES)
  offset: number

  @ApiProperty({ minimum: 1, maximum: MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES)
  maximumBytes: number
}

@ApiSchema({ name: 'WorkingCopyCaptureReadResponse' })
export class WorkingCopyCaptureReadResponseDto extends WorkingCopyCaptureIdentityDto {
  @ApiProperty({ minimum: 0, maximum: MAXIMUM_WORKING_COPY_CAPTURE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_WORKING_COPY_CAPTURE_BYTES)
  totalByteLength: number

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  providerSha256Digest: string

  @ApiProperty({ minimum: 0, maximum: MAXIMUM_WORKING_COPY_CAPTURE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_WORKING_COPY_CAPTURE_BYTES)
  offset: number

  @ApiProperty({ minimum: 0, maximum: MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES)
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
