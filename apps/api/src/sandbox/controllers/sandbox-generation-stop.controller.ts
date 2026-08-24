/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { Body, Controller, HttpCode, Param, Post, UseGuards } from '@nestjs/common'
import { ApiBearerAuth, ApiHeader, ApiOAuth2, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger'

import { Audit } from '../../audit/decorators/audit.decorator'
import { AuditAction } from '../../audit/enums/audit-action.enum'
import { AuditTarget } from '../../audit/enums/audit-target.enum'
import { AuthStrategy } from '../../auth/decorators/auth-strategy.decorator'
import { AuthStrategyType } from '../../auth/enums/auth-strategy-type.enum'
import { CustomHeaders } from '../../common/constants/header.constants'
import { IsOrganizationAuthContext } from '../../common/decorators/auth-context.decorator'
import { AuthenticatedRateLimitGuard } from '../../common/guards/authenticated-rate-limit.guard'
import { OrganizationAuthContext } from '../../common/interfaces/organization-auth-context.interface'
import { RequiredOrganizationResourcePermissions } from '../../organization/decorators/required-organization-resource-permissions.decorator'
import { OrganizationResourcePermission } from '../../organization/enums/organization-resource-permission.enum'
import { OrganizationAuthContextGuard } from '../../organization/guards/organization-auth-context.guard'
import {
  SandboxGenerationObservationDto,
  SandboxGenerationObservationRequestDto,
  SandboxGenerationStopObservationDto,
  StopSandboxGenerationRequestDto,
  StoppedSandboxGenerationReceiptDto,
} from '../dto/sandbox-generation-stop.dto'
import { SandboxAccessGuard } from '../guards/sandbox-access.guard'
import { SandboxGenerationStopService } from '../services/sandbox-generation-stop.service'

@Controller('sandbox/:sandboxIdOrName')
@ApiTags('sandbox')
@ApiOAuth2(['openid', 'profile', 'email'])
@ApiBearerAuth()
@ApiHeader(CustomHeaders.ORGANIZATION_ID)
@AuthStrategy([AuthStrategyType.API_KEY, AuthStrategyType.JWT])
@UseGuards(AuthenticatedRateLimitGuard, OrganizationAuthContextGuard, SandboxAccessGuard)
@RequiredOrganizationResourcePermissions([OrganizationResourcePermission.WRITE_SANDBOXES])
export class SandboxGenerationStopController {
  constructor(private readonly generations: SandboxGenerationStopService) {}

  @Post('generation/observe')
  @HttpCode(200)
  @ApiOperation({ operationId: 'observeSandboxGeneration', summary: 'Observe one exact sandbox execution generation' })
  @ApiResponse({ status: 200, type: SandboxGenerationObservationDto })
  @Audit({
    action: AuditAction.READ,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  observeCurrent(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() request: SandboxGenerationObservationRequestDto,
  ): Promise<SandboxGenerationObservationDto> {
    return this.generations.observeCurrent(auth.organizationId, sandboxIdOrName, request)
  }

  @Post('stop-generation-once')
  @HttpCode(200)
  @ApiOperation({ operationId: 'stopSandboxGenerationOnce', summary: 'Durably stop one exact sandbox generation once' })
  @ApiResponse({ status: 200, type: StoppedSandboxGenerationReceiptDto })
  @Audit({
    action: AuditAction.STOP,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  stopOnce(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() request: StopSandboxGenerationRequestDto,
  ): Promise<StoppedSandboxGenerationReceiptDto> {
    return this.generations.stopOnce(auth.organizationId, sandboxIdOrName, request)
  }

  @Post('stop-generation-once/observe')
  @HttpCode(200)
  @ApiOperation({ operationId: 'observeSandboxGenerationStop', summary: 'Observe one durable exact-generation stop' })
  @ApiResponse({ status: 200, type: SandboxGenerationStopObservationDto })
  @Audit({
    action: AuditAction.READ,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  observeStop(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() request: StopSandboxGenerationRequestDto,
  ): Promise<SandboxGenerationStopObservationDto> {
    return this.generations.observeStop(auth.organizationId, sandboxIdOrName, request)
  }
}
