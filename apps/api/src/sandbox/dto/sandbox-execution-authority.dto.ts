/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { Equals, IsString, Matches, MaxLength, MinLength } from 'class-validator'
import { ApiProperty, ApiSchema } from '@nestjs/swagger'

@ApiSchema({ name: 'SandboxExecutionSource' })
export class SandboxExecutionSourceDto {
  @ApiProperty({ description: 'Exact Daytona sandbox identity.' })
  @IsString()
  @MinLength(1)
  @MaxLength(512)
  providerResourceId: string

  @ApiProperty({ enum: ['managed-container'] })
  @Equals('managed-container')
  expectedProfile: 'managed-container'

  @ApiProperty({ enum: ['full_image_runtime_pack'] })
  @Equals('full_image_runtime_pack')
  expectedRuntimeKind: 'full_image_runtime_pack'
}

@ApiSchema({ name: 'SandboxExecutionOwner' })
export class SandboxExecutionOwnerDto {
  @ApiProperty({ format: 'uuid' })
  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
  tenantId: string

  @ApiProperty({ format: 'uuid' })
  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
  userId: string

  @ApiProperty({ format: 'uuid' })
  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
  workspaceId: string

  @ApiProperty({ format: 'uuid' })
  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
  runId: string

  @ApiProperty({ format: 'uuid' })
  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
  grantId: string

  @ApiProperty({ format: 'uuid' })
  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
  workingCopyId: string
}
