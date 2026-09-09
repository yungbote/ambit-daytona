/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { Body, Controller, HttpCode, Param, Post, Req, Res, UseGuards } from '@nestjs/common'
import { ApiBearerAuth, ApiHeader, ApiOAuth2, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger'
import { IncomingMessage, ServerResponse } from 'node:http'

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
  WorkingCopyCaptureBindingDto,
  WorkingTreeInventoryRequestDto,
  WorkingTreeInventoryRangeRequestDto,
  WorkingTreeInventoryRangeDto,
  WorkingTreeInventoryReceiptDto,
  WorkingTreeInventoryPageRequestDto,
  WorkingTreeInventoryPageDto,
  WorkingTreeInventoryDeletionReceiptDto,
  WorkingCopyCaptureCapabilitiesRequestDto,
  WorkingCopyCaptureCapabilitiesDto,
  WorkingCopyCaptureDeleteReceiptDto,
  WorkingCopyCaptureExistsResponseDto,
  WorkingCopyCaptureIdentityDto,
  WorkingCopyCaptureObservationDto,
  WorkingCopyCaptureReadDto,
  WorkingCopyCaptureReadResponseDto,
  WorkingCopyCaptureReceiptDto,
  StoppedWorkingCopyDirectoryRosterRequestDto,
  StoppedWorkingCopyDirectoryRosterReceiptDto,
} from '../dto/working-copy-capture.dto'
import { SandboxAccessGuard } from '../guards/sandbox-access.guard'
import { WorkingCopyCaptureService } from '../services/working-copy-capture.service'

@Controller('sandbox/:sandboxIdOrName/working-copy-captures')
@ApiTags('sandbox')
@ApiOAuth2(['openid', 'profile', 'email'])
@ApiBearerAuth()
@ApiHeader(CustomHeaders.ORGANIZATION_ID)
@AuthStrategy([AuthStrategyType.API_KEY, AuthStrategyType.JWT])
@UseGuards(AuthenticatedRateLimitGuard, OrganizationAuthContextGuard, SandboxAccessGuard)
@RequiredOrganizationResourcePermissions([OrganizationResourcePermission.WRITE_SANDBOXES])
export class WorkingCopyCaptureController {
  constructor(private readonly captures: WorkingCopyCaptureService) {}

  @Post('capabilities')
  @HttpCode(200)
  @ApiOperation({
    operationId: 'sandboxWorkingCopyCaptureCapabilities',
    summary: 'Discover the assigned Runner capture surface before stopping a generation',
  })
  @ApiResponse({ status: 200, type: WorkingCopyCaptureCapabilitiesDto })
  @Audit({
    action: AuditAction.READ,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  capabilities(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() request: WorkingCopyCaptureCapabilitiesRequestDto,
    @Req() incoming: IncomingMessage,
    @Res({ passthrough: true }) outgoing: ServerResponse<IncomingMessage>,
  ): Promise<WorkingCopyCaptureCapabilitiesDto> {
    return this.captures.capabilities(auth.organizationId, sandboxIdOrName, request, responseSignal(incoming, outgoing))
  }

  @Post('stopped-working-tree-inventories')
  @HttpCode(200)
  @ApiOperation({
    operationId: 'sandboxPrepareInventory',
    summary: 'Prepare immutable pages of an exact stopped working tree',
  })
  @ApiResponse({ status: 200, type: WorkingTreeInventoryReceiptDto })
  @Audit({
    action: AuditAction.CREATE,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  prepareInventory(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() request: WorkingTreeInventoryRequestDto,
    @Req() incoming: IncomingMessage,
    @Res({ passthrough: true }) outgoing: ServerResponse<IncomingMessage>,
  ): Promise<WorkingTreeInventoryReceiptDto> {
    return this.captures.prepareInventory(
      auth.organizationId,
      sandboxIdOrName,
      request,
      responseSignal(incoming, outgoing),
    )
  }

  @Post('stopped-working-tree-inventories/read')
  @HttpCode(200)
  @ApiOperation({
    operationId: 'sandboxReadInventoryPage',
    summary: 'Read an immutable stopped working-tree inventory page',
  })
  @ApiResponse({ status: 200, type: WorkingTreeInventoryPageDto })
  @Audit({
    action: AuditAction.READ,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  readInventoryPage(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() request: WorkingTreeInventoryPageRequestDto,
    @Req() incoming: IncomingMessage,
    @Res({ passthrough: true }) outgoing: ServerResponse<IncomingMessage>,
  ): Promise<WorkingTreeInventoryPageDto> {
    return this.captures.readInventoryPage(
      auth.organizationId,
      sandboxIdOrName,
      request,
      responseSignal(incoming, outgoing),
    )
  }

  @Post('stopped-working-tree-inventories/read-range')
  @HttpCode(200)
  @ApiOperation({operationId:'sandboxReadInventoryRange',summary:'Read a bounded immutable working-tree byte range'})
  @ApiResponse({status:200,type:WorkingTreeInventoryRangeDto})
  @Audit({action:AuditAction.READ,targetType:AuditTarget.SANDBOX,targetIdFromRequest:(request)=>request.params.sandboxIdOrName})
  readInventoryRange(@IsOrganizationAuthContext() auth:OrganizationAuthContext,@Param('sandboxIdOrName') sandboxIdOrName:string,@Body() request:WorkingTreeInventoryRangeRequestDto,@Req() incoming:IncomingMessage,@Res({passthrough:true}) outgoing:ServerResponse<IncomingMessage>):Promise<WorkingTreeInventoryRangeDto> {
    return this.captures.readInventoryRange(auth.organizationId,sandboxIdOrName,request,responseSignal(incoming,outgoing))
  }

  @Post('stopped-working-tree-inventories/delete')
  @HttpCode(200)
  @ApiOperation({
    operationId: 'sandboxDeleteInventory',
    summary: 'Delete exact inventory custody and prove its absence',
  })
  @ApiResponse({ status: 200, type: WorkingTreeInventoryDeletionReceiptDto })
  @Audit({
    action: AuditAction.DELETE,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  deleteInventory(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() request: WorkingTreeInventoryRequestDto,
    @Req() incoming: IncomingMessage,
    @Res({ passthrough: true }) outgoing: ServerResponse<IncomingMessage>,
  ): Promise<WorkingTreeInventoryDeletionReceiptDto> {
    return this.captures.deleteInventory(
      auth.organizationId,
      sandboxIdOrName,
      request,
      responseSignal(incoming, outgoing),
    )
  }

  @Post()
  @HttpCode(200)
  @ApiOperation({
    operationId: 'captureSandboxWorkingCopy',
    summary: 'Capture one file from an exact stopped sandbox generation',
  })
  @ApiResponse({ status: 200, type: WorkingCopyCaptureReceiptDto })
  @Audit({
    action: AuditAction.CREATE,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  capture(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() binding: WorkingCopyCaptureBindingDto,
    @Req() incoming: IncomingMessage,
    @Res({ passthrough: true }) outgoing: ServerResponse<IncomingMessage>,
  ): Promise<WorkingCopyCaptureReceiptDto> {
    return this.captures.capture(auth.organizationId, sandboxIdOrName, binding, responseSignal(incoming, outgoing))
  }

  @Post('observe')
  @HttpCode(200)
  @ApiOperation({
    operationId: 'observeSandboxWorkingCopyCapture',
    summary: 'Observe an exact private working-copy capture',
  })
  @ApiResponse({ status: 200, type: WorkingCopyCaptureObservationDto })
  @Audit({
    action: AuditAction.READ,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  observe(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() binding: WorkingCopyCaptureBindingDto,
  ): Promise<WorkingCopyCaptureObservationDto> {
    return this.captures.observe(auth.organizationId, sandboxIdOrName, binding)
  }

  @Post('read')
  @HttpCode(200)
  @ApiOperation({
    operationId: 'readSandboxWorkingCopyCapture',
    summary: 'Read an exact immutable private working-copy capture',
  })
  @ApiResponse({ status: 200, type: WorkingCopyCaptureReadResponseDto })
  @Audit({
    action: AuditAction.READ,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  read(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() request: WorkingCopyCaptureReadDto,
    @Req() incoming: IncomingMessage,
    @Res({ passthrough: true }) outgoing: ServerResponse<IncomingMessage>,
  ): Promise<WorkingCopyCaptureReadResponseDto> {
    return this.captures.read(auth.organizationId, sandboxIdOrName, request, responseSignal(incoming, outgoing))
  }

  @Post('stopped-directory-roster')
  @HttpCode(200)
  @ApiOperation({
    operationId: 'stoppedSandboxWorkingCopyDirectoryRoster',
    summary: 'List a bounded directory from an exact stopped sandbox generation',
  })
  @ApiResponse({ status: 200, type: StoppedWorkingCopyDirectoryRosterReceiptDto })
  @Audit({
    action: AuditAction.READ,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  stoppedDirectoryRoster(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() request: StoppedWorkingCopyDirectoryRosterRequestDto,
    @Req() incoming: IncomingMessage,
    @Res({ passthrough: true }) outgoing: ServerResponse<IncomingMessage>,
  ): Promise<StoppedWorkingCopyDirectoryRosterReceiptDto> {
    return this.captures.stoppedDirectoryRoster(
      auth.organizationId,
      sandboxIdOrName,
      request,
      responseSignal(incoming, outgoing),
    )
  }

  @Post('delete')
  @HttpCode(200)
  @ApiOperation({
    operationId: 'deleteSandboxWorkingCopyCapture',
    summary: 'Delete an exact private working-copy capture',
  })
  @ApiResponse({ status: 200, type: WorkingCopyCaptureDeleteReceiptDto })
  @Audit({
    action: AuditAction.DELETE,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  delete(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() identity: WorkingCopyCaptureIdentityDto,
  ): Promise<WorkingCopyCaptureDeleteReceiptDto> {
    return this.captures.delete(auth.organizationId, sandboxIdOrName, identity)
  }

  @Post('exists')
  @HttpCode(200)
  @ApiOperation({
    operationId: 'sandboxWorkingCopyCaptureExists',
    summary: 'Check an exact private working-copy capture identity',
  })
  @ApiResponse({ status: 200, type: WorkingCopyCaptureExistsResponseDto })
  @Audit({
    action: AuditAction.READ,
    targetType: AuditTarget.SANDBOX,
    targetIdFromRequest: (request) => request.params.sandboxIdOrName,
  })
  exists(
    @IsOrganizationAuthContext() auth: OrganizationAuthContext,
    @Param('sandboxIdOrName') sandboxIdOrName: string,
    @Body() identity: WorkingCopyCaptureIdentityDto,
  ): Promise<WorkingCopyCaptureExistsResponseDto> {
    return this.captures.exists(auth.organizationId, sandboxIdOrName, identity)
  }
}

function responseSignal(request: IncomingMessage, response: ServerResponse<IncomingMessage>): AbortSignal {
  const controller = new AbortController()
  const abort = () => controller.abort()
  // `request.destroyed` is true for every POST once its body has been read
  // (Node 24 autoDestroy), which aborted every capture before it reached the
  // runner ("ERR_CANCELED", 2026-09-03). Only a client that went away aborts:
  // the request stream reporting `aborted`, or the response closing unsent.
  if (request.aborted) controller.abort()
  else request.once('aborted', abort)
  response.once('close', () => {
    if (!response.writableEnded) abort()
  })
  return controller.signal
}
