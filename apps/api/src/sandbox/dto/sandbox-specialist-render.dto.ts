/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { Type } from 'class-transformer'
import { Equals, IsIn, IsString, Matches, MaxLength, MinLength, ValidateNested } from 'class-validator'
import { ApiProperty, ApiSchema } from '@nestjs/swagger'

import { SandboxGenerationFenceDto } from './sandbox-generation-stop.dto'

@ApiSchema({ name: 'SandboxProviderGenerationSource' })
export class SandboxProviderGenerationSourceDto {
  @IsString()
  @MinLength(1)
  @MaxLength(512)
  providerResourceId: string

  @IsString()
  @MinLength(1)
  @MaxLength(128)
  expectedProfile: string

  @ApiProperty({ enum: ['base_profile', 'full_image_runtime_pack'] })
  @IsIn(['base_profile', 'full_image_runtime_pack'])
  expectedRuntimeKind: 'base_profile' | 'full_image_runtime_pack'
}

@ApiSchema({ name: 'SandboxProviderGenerationOwner' })
export class SandboxProviderGenerationOwnerDto {
  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  tenantId: string

  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  userId: string

  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  workspaceId: string

  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  runId: string

  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  grantId: string
}

export class SandboxProviderGenerationObservationRequestDto {
  @ValidateNested()
  @Type(() => SandboxProviderGenerationSourceDto)
  source: SandboxProviderGenerationSourceDto

  @ValidateNested()
  @Type(() => SandboxProviderGenerationOwnerDto)
  owner: SandboxProviderGenerationOwnerDto

  @ValidateNested()
  @Type(() => SandboxGenerationFenceDto)
  fence: SandboxGenerationFenceDto
}

export class SandboxSpecialistRenderObserveRequestDto extends SandboxProviderGenerationObservationRequestDto {
  @Equals('ambit.runtime-provider-specialist-render-observe-request/v1')
  schema: 'ambit.runtime-provider-specialist-render-observe-request/v1'

  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  operationId: string

  @Matches(/^[0-9a-f]{64}$/)
  requestFingerprint: string
}

export type SandboxSpecialistRenderRequestAuthority = Readonly<{
  source: SandboxProviderGenerationSourceDto
  owner: SandboxProviderGenerationOwnerDto
  fence: SandboxGenerationFenceDto
}>
