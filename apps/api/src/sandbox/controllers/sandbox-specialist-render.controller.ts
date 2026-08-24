/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { BadRequestException, Body, Controller, HttpCode, Param, Post, Req, Res, UseGuards } from '@nestjs/common'
import { ApiBearerAuth, ApiHeader, ApiOAuth2, ApiOperation, ApiTags } from '@nestjs/swagger'
import { IncomingMessage, ServerResponse } from 'node:http'
import { pipeline } from 'node:stream/promises'

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
  SandboxProviderGenerationObservationRequestDto,
  SandboxSpecialistRenderObserveRequestDto,
} from '../dto/sandbox-specialist-render.dto'
import { SandboxAccessGuard } from '../guards/sandbox-access.guard'
import { SPECIALIST_RENDER_CONTENT_TYPE } from '../runner-adapter/runner-specialist-render.transport'
import { SandboxSpecialistRenderService } from '../services/sandbox-specialist-render.service'

@Controller('sandbox/:sandboxIdOrName')
@ApiTags('sandbox')
@ApiOAuth2(['openid', 'profile', 'email'])
@ApiBearerAuth()
@ApiHeader(CustomHeaders.ORGANIZATION_ID)
@AuthStrategy([AuthStrategyType.API_KEY, AuthStrategyType.JWT])
@UseGuards(AuthenticatedRateLimitGuard, OrganizationAuthContextGuard, SandboxAccessGuard)
@RequiredOrganizationResourcePermissions([OrganizationResourcePermission.WRITE_SANDBOXES])
export class SandboxSpecialistRenderController {
  constructor(private readonly renders: SandboxSpecialistRenderService) {}

  @Post('generation/observe-current')
  @HttpCode(200)
  @ApiOperation({ operationId: 'observeCurrentSandboxProviderGeneration' })
  @Audit({
    action: AuditAction.READ,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => String(request.params.sandboxIdOrName),
  })
  async observeCurrent(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() body: SandboxProviderGenerationObservationRequestDto,
    @Req() request: IncomingMessage,
  ): Promise<unknown> {
    const signal = requestSignal(request)
    return this.renders.observeCurrent(auth.organizationId, sandboxIdOrName, body, signal)
  }

  @Post('specialist-renders/observe')
  @HttpCode(200)
  @ApiOperation({ operationId: 'observeSpecialistRender' })
  @Audit({
    action: AuditAction.READ,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => String(request.params.sandboxIdOrName),
  })
  async observeRender(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() body: SandboxSpecialistRenderObserveRequestDto,
    @Req() request: IncomingMessage,
  ): Promise<unknown> {
    const signal = requestSignal(request)
    return this.renders.observeRender(auth.organizationId, sandboxIdOrName, body, signal)
  }

  @Post('specialist-renders')
  @ApiOperation({ operationId: 'executeSpecialistRender' })
  @Audit({
    action: AuditAction.CREATE,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => String(request.params.sandboxIdOrName),
  })
  async execute(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Req() request: IncomingMessage,
    @Res() response: ServerResponse<IncomingMessage>,
  ): Promise<void> {
    if (request.headers['content-type'] !== SPECIALIST_RENDER_CONTENT_TYPE) {
      throw new BadRequestException('Specialist-render content type is invalid.')
    }
    const signal = responseSignal(request, response)
    const result = await this.renders.execute(auth.organizationId, sandboxIdOrName, request, signal)
    const successfulStream = result.status === 200 || result.status === 422
    if (successfulStream && result.contentType !== SPECIALIST_RENDER_CONTENT_TYPE) {
      result.body.destroy()
      throw new BadRequestException('Runner specialist-render response content type differs.')
    }
    response.statusCode = result.status
    response.setHeader('Content-Type', result.contentType || 'application/json')
    response.setHeader('X-Content-Type-Options', 'nosniff')
    try {
      await pipeline(result.body, response, { signal })
    } catch (error) {
      if (response.headersSent) {
        response.destroy(error instanceof Error ? error : undefined)
        return
      }
      throw error
    }
  }
}

function requestSignal(request: IncomingMessage): AbortSignal {
  const controller = new AbortController()
  if (request.aborted || request.destroyed) controller.abort()
  else request.once('aborted', () => controller.abort())
  return controller.signal
}

function responseSignal(request: IncomingMessage, response: ServerResponse<IncomingMessage>): AbortSignal {
  const controller = new AbortController()
  const abort = () => controller.abort()
  if (request.aborted || request.destroyed) controller.abort()
  else request.once('aborted', abort)
  response.once('close', () => {
    if (!response.writableEnded) abort()
  })
  return controller.signal
}
