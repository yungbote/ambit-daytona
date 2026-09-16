/* Copyright 2026 Ambit. SPDX-License-Identifier: AGPL-3.0 */

import { ApiProperty, ApiPropertyOptional, ApiSchema } from '@nestjs/swagger'
import { Type } from 'class-transformer'
import {
  Equals,
  IsBoolean,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
  ValidateNested,
} from 'class-validator'
import { SandboxExecutionGenerationDto } from './sandbox-generation-stop.dto'
import {
  WorkingCopyCaptureAuthorityArtifactDto,
  MAXIMUM_USER_FILE_CAPTURE_BYTES,
  MAXIMUM_USER_FILE_READ_BYTES,
} from './working-copy-capture.dto'

export const SANDBOX_FILE_CAPTURE_CONTRACT = 'daytona.sandbox-file-capture/v1'
export const SANDBOX_FILE_OPERATION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/

@ApiSchema({ name: 'SandboxFileCaptureRequest' })
export class SandboxFileCaptureRequestDto {
  @ApiProperty({
    pattern: SANDBOX_FILE_OPERATION_PATTERN.source,
    description: 'Stable caller idempotency key. Reusing it never selects a new source generation.',
  })
  @Matches(SANDBOX_FILE_OPERATION_PATTERN)
  operationId: string

  @ApiProperty({
    maxLength: 4096,
    description: 'Canonical regular-file path within /workspace/work or /workspace/outputs.',
  })
  @IsString()
  @MaxLength(4096)
  path: string
}

export type SandboxFileCaptureRunnerRequest = SandboxFileCaptureRequestDto & { organizationId: string }

@ApiSchema({ name: 'SandboxFileCaptureObserveRequest' })
export class SandboxFileCaptureObserveRequestDto {
  @ApiProperty({ pattern: SANDBOX_FILE_OPERATION_PATTERN.source })
  @Matches(SANDBOX_FILE_OPERATION_PATTERN)
  operationId: string

  @ApiPropertyOptional({
    maxLength: 4096,
    description: 'Optional assertion of the originally admitted path; observation does not access the live file.',
  })
  @IsOptional()
  @IsString()
  @MaxLength(4096)
  path?: string
}

export type SandboxFileCaptureRunnerObserveRequest = SandboxFileCaptureObserveRequestDto & { organizationId: string }

@ApiSchema({ name: 'SandboxFileCaptureComponent' })
export class SandboxFileCaptureComponentDto {
  @ApiProperty({ enum: ['ambit.runtime-component/working-copy-capture@2'] })
  @Equals('ambit.runtime-component/working-copy-capture@2')
  roleRef: string

  @ApiProperty({ type: WorkingCopyCaptureAuthorityArtifactDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureAuthorityArtifactDto)
  protocol: WorkingCopyCaptureAuthorityArtifactDto

  @ApiProperty({ type: WorkingCopyCaptureAuthorityArtifactDto })
  @ValidateNested()
  @Type(() => WorkingCopyCaptureAuthorityArtifactDto)
  helper: WorkingCopyCaptureAuthorityArtifactDto
}

@ApiSchema({ name: 'SandboxFileCaptureReceipt' })
export class SandboxFileCaptureReceiptDto extends SandboxFileCaptureRequestDto {
  @ApiProperty({ enum: [SANDBOX_FILE_CAPTURE_CONTRACT] })
  @Equals(SANDBOX_FILE_CAPTURE_CONTRACT)
  contract: typeof SANDBOX_FILE_CAPTURE_CONTRACT

  @ApiProperty({ pattern: '^daytona-sandbox-file-capture:v1:sha256:[0-9a-f]{64}$' })
  @Matches(/^daytona-sandbox-file-capture:v1:sha256:[0-9a-f]{64}$/)
  captureId: string

  @ApiProperty({ format: 'uuid' })
  @IsString()
  organizationId: string

  @ApiProperty({ format: 'uuid' })
  @IsString()
  sandboxId: string

  @ApiProperty({ type: SandboxExecutionGenerationDto })
  @ValidateNested()
  @Type(() => SandboxExecutionGenerationDto)
  generation: SandboxExecutionGenerationDto

  @ApiProperty({
    type: SandboxFileCaptureComponentDto,
    description: 'Measured native implementation identity; does not certify a Product runtime.',
  })
  @ValidateNested()
  @Type(() => SandboxFileCaptureComponentDto)
  component: SandboxFileCaptureComponentDto

  @ApiProperty({ minimum: 0, maximum: MAXIMUM_USER_FILE_CAPTURE_BYTES })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_USER_FILE_CAPTURE_BYTES)
  totalByteLength: number

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  sha256: string

  @ApiProperty({ format: 'date-time' })
  @IsString()
  capturedAt: string
}

@ApiSchema({ name: 'SandboxFileCaptureObservation' })
export class SandboxFileCaptureObservationDto {
  @ApiProperty({ enum: ['absent', 'pending', 'complete', 'retired'] })
  @IsIn(['absent', 'pending', 'complete', 'retired'])
  status: 'absent' | 'pending' | 'complete' | 'retired'

  @ApiPropertyOptional({ type: SandboxFileCaptureReceiptDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => SandboxFileCaptureReceiptDto)
  receipt?: SandboxFileCaptureReceiptDto
}

@ApiSchema({ name: 'SandboxFileCaptureReadRequest' })
export class SandboxFileCaptureReadRequestDto {
  @ApiProperty({ type: SandboxFileCaptureReceiptDto })
  @ValidateNested()
  @Type(() => SandboxFileCaptureReceiptDto)
  receipt: SandboxFileCaptureReceiptDto

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

@ApiSchema({ name: 'SandboxFileCaptureReadResponse' })
export class SandboxFileCaptureReadResponseDto {
  @ApiProperty()
  captureId: string
  @ApiProperty({ minimum: 0 })
  totalByteLength: number
  @ApiProperty()
  sha256: string
  @ApiProperty({ minimum: 0 })
  offset: number
  @ApiProperty({ minimum: 0 })
  byteLength: number
  @ApiProperty()
  @IsBoolean()
  eof: boolean
  @ApiProperty()
  bytesBase64: string
}

@ApiSchema({ name: 'SandboxFileCaptureDeleteRequest' })
export class SandboxFileCaptureDeleteRequestDto {
  @ApiPropertyOptional({
    type: SandboxFileCaptureReceiptDto,
    description:
      'Exact receipt, or operationId with an optional original-path assertion when retiring or retrying cleanup.',
  })
  @IsOptional()
  @ValidateNested()
  @Type(() => SandboxFileCaptureReceiptDto)
  receipt?: SandboxFileCaptureReceiptDto

  @ApiPropertyOptional({ pattern: SANDBOX_FILE_OPERATION_PATTERN.source })
  @IsOptional()
  @Matches(SANDBOX_FILE_OPERATION_PATTERN)
  operationId?: string

  @ApiPropertyOptional({ maxLength: 4096 })
  @IsOptional()
  @IsString()
  @MaxLength(4096)
  path?: string
}

export type SandboxFileCaptureRunnerDeleteRequest = SandboxFileCaptureDeleteRequestDto & { organizationId?: string }

@ApiSchema({ name: 'SandboxFileCaptureDeleteReceipt' })
export class SandboxFileCaptureDeleteReceiptDto {
  @ApiProperty({
    nullable: true,
    type: String,
    description: 'Null when the operation was retired before a source was selected.',
  })
  captureId: string | null

  @ApiProperty({ enum: ['deleted', 'already_absent'] })
  @IsIn(['deleted', 'already_absent'])
  outcome: 'deleted' | 'already_absent'
}
