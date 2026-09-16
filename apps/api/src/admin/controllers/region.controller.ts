/*
 * Copyright 2026 Ambit
 * SPDX-License-Identifier: AGPL-3.0
 */

import {
  Body,
  Controller,
  Get,
  HttpCode,
  NotFoundException,
  Param,
  Post,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common'
import { ApiBearerAuth, ApiOAuth2, ApiOperation, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger'
import { Audit, TypedRequest } from '../../audit/decorators/audit.decorator'
import { AuditAction } from '../../audit/enums/audit-action.enum'
import { AuditTarget } from '../../audit/enums/audit-target.enum'
import { AuthStrategy } from '../../auth/decorators/auth-strategy.decorator'
import { AuthStrategyType } from '../../auth/enums/auth-strategy-type.enum'
import { AuthenticatedRateLimitGuard } from '../../common/guards/authenticated-rate-limit.guard'
import { CreateRegionResponseDto } from '../../region/dto/create-region.dto'
import { RegionType } from '../../region/enums/region-type.enum'
import { RegionService } from '../../region/services/region.service'
import { RequiredSystemRole } from '../../user/decorators/required-system-role.decorator'
import { SystemRole } from '../../user/enums/system-role.enum'
import { AdminCreateRegionDto } from '../dto/create-region.dto'
import { AdminRegionDto } from '../dto/region.dto'

@Controller('admin/regions')
@ApiTags('admin')
@ApiOAuth2(['openid', 'profile', 'email'])
@ApiBearerAuth()
@AuthStrategy([AuthStrategyType.API_KEY, AuthStrategyType.JWT])
@RequiredSystemRole(SystemRole.ADMIN)
@UseGuards(AuthenticatedRateLimitGuard)
export class AdminRegionController {
  constructor(private readonly regionService: RegionService) {}

  @Post()
  @HttpCode(201)
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true, forbidNonWhitelisted: true }))
  @ApiOperation({ summary: 'Create an operator-managed region', operationId: 'adminCreateRegion' })
  @ApiResponse({ status: 201, type: CreateRegionResponseDto })
  @Audit({
    action: AuditAction.CREATE,
    targetType: AuditTarget.REGION,
    targetIdFromResult: (result: CreateRegionResponseDto) => result.id,
    requestMetadata: { body: (req: TypedRequest<AdminCreateRegionDto>) => ({ name: req.body?.name }) },
  })
  async create(@Body() input: AdminCreateRegionDto): Promise<CreateRegionResponseDto> {
    return this.regionService.create({ name: input.name, regionType: RegionType.DEDICATED, enforceQuotas: true }, null)
  }

  @Get(':id')
  @HttpCode(200)
  @ApiOperation({ summary: 'Get an operator region', operationId: 'adminGetRegionById' })
  @ApiParam({ name: 'id', description: 'Exact region ID', type: String })
  @ApiResponse({ status: 200, type: AdminRegionDto })
  @ApiResponse({ status: 404, description: 'Region not found' })
  async findOne(@Param('id') id: string): Promise<AdminRegionDto> {
    const region = await this.regionService.findOne(id)
    if (!region) {
      throw new NotFoundException('Region not found')
    }
    return AdminRegionDto.fromRegion(region)
  }
}
