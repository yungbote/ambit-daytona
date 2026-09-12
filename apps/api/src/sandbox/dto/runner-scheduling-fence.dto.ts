/*
 * Copyright 2026 Ambit Platforms
 * SPDX-License-Identifier: AGPL-3.0
 */

import { ApiProperty, ApiSchema } from '@nestjs/swagger'
import { IsNotEmpty, IsString, MaxLength } from 'class-validator'

@ApiSchema({ name: 'CreateRunnerSchedulingFence' })
export class CreateRunnerSchedulingFenceDto {
  @ApiProperty({ description: 'Controller that owns this scheduling fence', maxLength: 128 })
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  owner: string
}

@ApiSchema({ name: 'RunnerSchedulingFence' })
export class RunnerSchedulingFenceDto {
  @ApiProperty()
  owner: string

  @ApiProperty({ format: 'uuid', description: 'Only this token can release the fence' })
  token: string
}
