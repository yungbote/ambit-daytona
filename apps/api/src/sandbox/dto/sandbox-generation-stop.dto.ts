/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { Type } from 'class-transformer'
import {
  Equals,
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

import { SandboxExecutionOwnerDto, SandboxExecutionSourceDto } from './sandbox-execution-authority.dto'

const MAXIMUM_SAFE_JSON_INTEGER = 9_007_199_254_740_991

@ApiSchema({ name: 'SandboxGenerationFence' })
export class SandboxGenerationFenceDto {
  @ApiProperty({ maxLength: 2048 })
  @IsString()
  @MinLength(1)
  @MaxLength(2048)
  workspaceExecutionManifestRef: string
}

@ApiSchema({ name: 'SandboxExecutionGeneration' })
export class SandboxExecutionGenerationDto {
  @ApiProperty({ pattern: '^[0-9a-f]{64}$' })
  @Matches(/^[0-9a-f]{64}$/)
  containerId: string

  @ApiProperty({ format: 'date-time' })
  @IsDateString({ strict: true })
  containerCreatedAt: string

  @ApiProperty({ format: 'date-time' })
  @IsDateString({ strict: true })
  executionStartedAt: string

  @ApiProperty({ minimum: 0, maximum: MAXIMUM_SAFE_JSON_INTEGER })
  @IsInt()
  @Min(0)
  @Max(MAXIMUM_SAFE_JSON_INTEGER)
  restartCount: number
}

@ApiSchema({ name: 'SandboxTerminalGeneration' })
export class SandboxTerminalGenerationDto extends SandboxExecutionGenerationDto {
  @ApiProperty({ format: 'date-time' })
  @IsDateString({ strict: true })
  executionFinishedAt: string

  @ApiProperty({ minimum: -2147483648, maximum: 2147483647 })
  @IsInt()
  @Min(-2147483648)
  @Max(2147483647)
  exitCode: number

  @ApiProperty()
  @IsIn([true, false])
  oomKilled: boolean
}

@ApiSchema({ name: 'SandboxRendererProcessIdentity' })
export class SandboxRendererProcessIdentityDto {
  @ApiProperty({ minimum: 1, maximum: MAXIMUM_SAFE_JSON_INTEGER })
  @IsInt()
  @Min(1)
  @Max(MAXIMUM_SAFE_JSON_INTEGER)
  pid: number

  @ApiProperty({ pattern: '^[1-9][0-9]{0,31}$' })
  @Matches(/^[1-9][0-9]{0,31}$/)
  startTicks: string
}

@ApiSchema({ name: 'SandboxGenerationStopPurpose' })
export class SandboxGenerationStopPurposeDto {
  @ApiProperty({ enum: ['working_copy_capture', 'document_renderer_quiescence'] })
  @IsIn(['working_copy_capture', 'document_renderer_quiescence'])
  kind: 'working_copy_capture' | 'document_renderer_quiescence'

  @ApiPropertyOptional({ pattern: '^ambit-document-render-[0-9a-f]{40}$' })
  @IsOptional()
  @Matches(/^ambit-document-render-[0-9a-f]{40}$/)
  sessionId?: string

  @ApiPropertyOptional({ pattern: '^[0-9a-f]{32}$' })
  @IsOptional()
  @Matches(/^[0-9a-f]{32}$/)
  nonce?: string

  @ApiPropertyOptional({ type: SandboxRendererProcessIdentityDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => SandboxRendererProcessIdentityDto)
  rendererProcessIdentity?: SandboxRendererProcessIdentityDto
}

@ApiSchema({ name: 'SandboxGenerationObservationRequest' })
export class SandboxGenerationObservationRequestDto {
  @ApiProperty({ type: SandboxExecutionSourceDto })
  @ValidateNested()
  @Type(() => SandboxExecutionSourceDto)
  source: SandboxExecutionSourceDto

  @ApiProperty({ type: SandboxExecutionOwnerDto })
  @ValidateNested()
  @Type(() => SandboxExecutionOwnerDto)
  owner: SandboxExecutionOwnerDto

  @ApiProperty({ type: SandboxGenerationFenceDto })
  @ValidateNested()
  @Type(() => SandboxGenerationFenceDto)
  fence: SandboxGenerationFenceDto
}

@ApiSchema({ name: 'SandboxGenerationObservation' })
export class SandboxGenerationObservationDto extends SandboxGenerationObservationRequestDto {
  @ApiProperty({ type: SandboxExecutionGenerationDto })
  @ValidateNested()
  @Type(() => SandboxExecutionGenerationDto)
  generation: SandboxExecutionGenerationDto

  @ApiProperty({ enum: ['running', 'stopped'] })
  @IsIn(['running', 'stopped'])
  state: 'running' | 'stopped'

  @ApiProperty({ format: 'date-time' })
  @IsDateString({ strict: true })
  observedAt: string
}

@ApiSchema({ name: 'StopSandboxGenerationRequest' })
export class StopSandboxGenerationRequestDto extends SandboxGenerationObservationRequestDto {
  @ApiProperty({ format: 'uuid' })
  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
  operationId: string

  @ApiProperty({ pattern: '^[0-9a-f]{64}$' })
  @Matches(/^[0-9a-f]{64}$/)
  requestFingerprint: string

  @ApiProperty({ type: SandboxExecutionGenerationDto })
  @ValidateNested()
  @Type(() => SandboxExecutionGenerationDto)
  expectedGeneration: SandboxExecutionGenerationDto

  @ApiProperty({ type: SandboxGenerationStopPurposeDto })
  @ValidateNested()
  @Type(() => SandboxGenerationStopPurposeDto)
  purpose: SandboxGenerationStopPurposeDto
}

@ApiSchema({ name: 'StoppedSandboxGenerationReceipt' })
export class StoppedSandboxGenerationReceiptDto {
  @ApiProperty({ enum: [1] })
  @Equals(1)
  version: 1

  @ApiProperty({ enum: ['agent_workspace_stopped_generation_receipt'] })
  @Equals('agent_workspace_stopped_generation_receipt')
  kind: 'agent_workspace_stopped_generation_receipt'

  @ApiProperty({ type: StopSandboxGenerationRequestDto })
  @ValidateNested()
  @Type(() => StopSandboxGenerationRequestDto)
  request: StopSandboxGenerationRequestDto

  @ApiProperty({ pattern: '^ambit\\.stopped-generation-receipt:v1:sha256:[0-9a-f]{64}$' })
  @Matches(/^ambit\.stopped-generation-receipt:v1:sha256:[0-9a-f]{64}$/)
  receiptRef: string

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  receiptDigest: string

  @ApiProperty({ type: SandboxTerminalGenerationDto })
  @ValidateNested()
  @Type(() => SandboxTerminalGenerationDto)
  terminalGeneration: SandboxTerminalGenerationDto

  @ApiProperty({ format: 'date-time' })
  @IsDateString({ strict: true })
  stoppedAt: string
}

@ApiSchema({ name: 'SandboxGenerationStopObservation' })
export class SandboxGenerationStopObservationDto {
  @ApiProperty({ enum: ['absent', 'partial', 'complete'] })
  @IsIn(['absent', 'partial', 'complete'])
  status: 'absent' | 'partial' | 'complete'

  @ApiPropertyOptional({ type: StopSandboxGenerationRequestDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => StopSandboxGenerationRequestDto)
  request?: StopSandboxGenerationRequestDto

  @ApiPropertyOptional({ type: StoppedSandboxGenerationReceiptDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => StoppedSandboxGenerationReceiptDto)
  receipt?: StoppedSandboxGenerationReceiptDto
}

@ApiSchema({ name: 'SandboxGenerationStopAuthority' })
export class SandboxGenerationStopAuthorityDto {
  @ApiProperty({ format: 'uuid' })
  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
  operationId: string

  @ApiProperty({ pattern: '^ambit\\.stopped-generation-receipt:v1:sha256:[0-9a-f]{64}$' })
  @Matches(/^ambit\.stopped-generation-receipt:v1:sha256:[0-9a-f]{64}$/)
  receiptRef: string

  @ApiProperty({ pattern: '^sha256:[0-9a-f]{64}$' })
  @Matches(/^sha256:[0-9a-f]{64}$/)
  receiptDigest: string

  @ApiProperty({ type: SandboxTerminalGenerationDto })
  @ValidateNested()
  @Type(() => SandboxTerminalGenerationDto)
  terminalGeneration: SandboxTerminalGenerationDto

  @ApiProperty({ type: SandboxGenerationFenceDto })
  @ValidateNested()
  @Type(() => SandboxGenerationFenceDto)
  fence: SandboxGenerationFenceDto
}
