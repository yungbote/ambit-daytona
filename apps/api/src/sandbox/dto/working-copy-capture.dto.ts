/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { Type } from 'class-transformer'
import {
  Equals,
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
  ValidateNested,
} from 'class-validator'
import { ApiProperty, ApiPropertyOptional, ApiSchema } from '@nestjs/swagger'
import {
  SandboxExecutionOwnerDto as WorkingCopyCaptureOwnerDto,
  SandboxExecutionSourceDto as WorkingCopyCaptureSourceDto,
} from './sandbox-execution-authority.dto'
import { SandboxGenerationStopAuthorityDto } from './sandbox-generation-stop.dto'

export { WorkingCopyCaptureOwnerDto, WorkingCopyCaptureSourceDto }

export const MAXIMUM_WORKING_COPY_CAPTURE_BYTES = 64 * 1024 * 1024
export const MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES = 1 * 1024 * 1024

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
