/*
 * Copyright 2026 Ambit
 * SPDX-License-Identifier: AGPL-3.0
 */

import { ApiProperty, ApiSchema } from '@nestjs/swagger'
import { IsNotEmpty, IsString } from 'class-validator'
import { IsSafeDisplayString } from '../../common/validators'

@ApiSchema({ name: 'AdminCreateRegion' })
export class AdminCreateRegionDto {
  @ApiProperty({ description: 'Name of the operator-managed region', example: 'us-east4-qualified' })
  @IsString()
  @IsNotEmpty()
  @IsSafeDisplayString()
  name: string
}
