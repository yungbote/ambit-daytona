/*
 * Copyright 2026 Ambit
 * SPDX-License-Identifier: AGPL-3.0
 */

import { ApiProperty, ApiSchema } from '@nestjs/swagger'
import { RegionDto } from '../../region/dto/region.dto'
import { Region } from '../../region/entities/region.entity'

@ApiSchema({ name: 'AdminRegion' })
export class AdminRegionDto extends RegionDto {
  @ApiProperty({ description: 'Whether organizations need an explicit region quota for admission' })
  enforceQuotas: boolean

  static override fromRegion(region: Region): AdminRegionDto {
    return { ...RegionDto.fromRegion(region), enforceQuotas: region.enforceQuotas }
  }
}
