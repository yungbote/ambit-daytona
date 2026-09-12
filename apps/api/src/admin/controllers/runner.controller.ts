/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common'
import { AuthenticatedRateLimitGuard } from '../../common/guards/authenticated-rate-limit.guard'
import { ApiBearerAuth, ApiOAuth2, ApiOperation, ApiParam, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger'
import { AdminCreateRunnerDto } from '../dto/create-runner.dto'
import { Audit, MASKED_AUDIT_VALUE, TypedRequest } from '../../audit/decorators/audit.decorator'
import { AuditAction } from '../../audit/enums/audit-action.enum'
import { AuditTarget } from '../../audit/enums/audit-target.enum'
import { RequiredSystemRole } from '../../user/decorators/required-system-role.decorator'
import { RegionService } from '../../region/services/region.service'
import { CreateRunnerResponseDto } from '../../sandbox/dto/create-runner-response.dto'
import { RunnerFullDto } from '../../sandbox/dto/runner-full.dto'
import { RunnerDto } from '../../sandbox/dto/runner.dto'
import { RunnerService, RunnerCapacity } from '../../sandbox/services/runner.service'
import { SystemRole } from '../../user/enums/system-role.enum'
import { AuthStrategy } from '../../auth/decorators/auth-strategy.decorator'
import { AuthStrategyType } from '../../auth/enums/auth-strategy-type.enum'
import { CreateRunnerSchedulingFenceDto, RunnerSchedulingFenceDto } from '../../sandbox/dto/runner-scheduling-fence.dto'

@Controller('admin/runners')
@ApiTags('admin')
@ApiOAuth2(['openid', 'profile', 'email'])
@ApiBearerAuth()
@AuthStrategy([AuthStrategyType.API_KEY, AuthStrategyType.JWT])
@RequiredSystemRole(SystemRole.ADMIN)
@UseGuards(AuthenticatedRateLimitGuard)
export class AdminRunnerController {
  constructor(
    private readonly runnerService: RunnerService,
    private readonly regionService: RegionService,
  ) {}

  @Post()
  @HttpCode(201)
  @ApiOperation({
    summary: 'Create runner',
    operationId: 'adminCreateRunner',
  })
  @ApiResponse({
    status: 201,
    type: CreateRunnerResponseDto,
  })
  @Audit({
    action: AuditAction.CREATE,
    targetType: AuditTarget.RUNNER,
    targetIdFromResult: (result: RunnerDto) => result?.id,
    requestMetadata: {
      body: (req: TypedRequest<AdminCreateRunnerDto>) => ({
        domain: req.body?.domain,
        apiUrl: req.body?.apiUrl,
        proxyUrl: req.body?.proxyUrl,
        regionId: req.body?.regionId,
        name: req.body?.name,
        apiKey: MASKED_AUDIT_VALUE,
        apiVersion: req.body?.apiVersion,
        tags: req.body?.tags,
      }),
    },
  })
  async create(@Body() createRunnerDto: AdminCreateRunnerDto): Promise<CreateRunnerResponseDto> {
    const region = await this.regionService.findOne(createRunnerDto.regionId)

    if (!region) {
      throw new NotFoundException('Region not found')
    }

    const { runner, apiKey } = await this.runnerService.create({
      domain: createRunnerDto.domain,
      apiUrl: createRunnerDto.apiUrl,
      proxyUrl: createRunnerDto.proxyUrl,
      regionId: createRunnerDto.regionId,
      name: createRunnerDto.name,
      apiKey: createRunnerDto.apiKey,
      apiVersion: createRunnerDto.apiVersion,
      cpu: createRunnerDto.cpu,
      memoryGiB: createRunnerDto.memoryGiB,
      diskGiB: createRunnerDto.diskGiB,
      tags: createRunnerDto.tags,
    })

    return CreateRunnerResponseDto.fromRunner(runner, apiKey)
  }

  @Get('capacity')
  @ApiOperation({
    summary: 'Runner capacity',
    operationId: 'getRunnerCapacity',
    description:
      'Every runner with its registered CPU/memory next to what active sandboxes reserve; the runner scaler and operators read this.',
  })
  @ApiResponse({ status: 200, description: 'Per-runner reservation view' })
  async getRunnerCapacity(): Promise<RunnerCapacity[]> {
    return this.runnerService.getRunnerCapacity()
  }

  @Get(':id')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Get runner by ID',
    operationId: 'adminGetRunnerById',
  })
  @ApiParam({
    name: 'id',
    description: 'Runner ID',
    type: String,
  })
  @ApiResponse({
    status: 200,
    type: RunnerFullDto,
  })
  async getRunnerById(@Param('id', ParseUUIDPipe) id: string): Promise<RunnerFullDto> {
    return this.runnerService.findOneFullOrFail(id)
  }

  @Get()
  @HttpCode(200)
  @ApiOperation({
    summary: 'List all runners',
    operationId: 'adminListRunners',
  })
  @ApiQuery({
    name: 'regionId',
    description: 'Filter runners by region ID',
    type: String,
    required: false,
  })
  @ApiResponse({
    status: 200,
    type: [RunnerFullDto],
  })
  async findAll(@Query('regionId') regionId?: string): Promise<RunnerFullDto[]> {
    if (regionId) {
      return this.runnerService.findAllByRegionFull(regionId)
    }
    return this.runnerService.findAllFull()
  }

  @Patch(':id/scheduling')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Update runner scheduling status',
    operationId: 'adminUpdateRunnerScheduling',
  })
  @ApiResponse({
    status: 204,
  })
  @Audit({
    action: AuditAction.UPDATE_SCHEDULING,
    targetType: AuditTarget.RUNNER,
    targetIdFromRequest: (req) => req.params.id,
    requestMetadata: {
      body: (req: TypedRequest<{ unschedulable: boolean }>) => ({
        unschedulable: req.body?.unschedulable,
      }),
    },
  })
  async updateSchedulingStatus(
    @Param('id', ParseUUIDPipe) id: string,
    @Body('unschedulable') unschedulable: boolean,
  ): Promise<void> {
    await this.runnerService.updateSchedulingStatus(id, unschedulable)
  }

  @Post(':id/scheduling/fences')
  @ApiOperation({
    summary: 'Acquire a controller-owned scheduling fence',
    operationId: 'adminAcquireRunnerSchedulingFence',
    description: 'Fences a schedulable runner. Explicit scheduling writes supersede the returned token.',
  })
  @ApiResponse({ status: 201, type: RunnerSchedulingFenceDto })
  @ApiResponse({ status: 409, description: 'Runner is already fenced or draining' })
  @Audit({
    action: AuditAction.UPDATE_SCHEDULING,
    targetType: AuditTarget.RUNNER,
    targetIdFromRequest: (req) => req.params.id,
    requestMetadata: {
      body: (req: TypedRequest<CreateRunnerSchedulingFenceDto>) => ({ owner: req.body?.owner }),
    },
  })
  async acquireSchedulingFence(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: CreateRunnerSchedulingFenceDto,
  ): Promise<RunnerSchedulingFenceDto> {
    return this.runnerService.acquireSchedulingFence(id, body.owner)
  }

  @Delete(':id/scheduling/fences/:token')
  @HttpCode(204)
  @ApiOperation({
    summary: 'Release a controller-owned scheduling fence',
    operationId: 'adminReleaseRunnerSchedulingFence',
    description: 'Reopens the runner only if this token still owns its scheduling fence.',
  })
  @ApiResponse({ status: 204 })
  @ApiResponse({ status: 409, description: 'Fence ownership changed or runner is draining' })
  @Audit({
    action: AuditAction.UPDATE_SCHEDULING,
    targetType: AuditTarget.RUNNER,
    targetIdFromRequest: (req) => req.params.id,
  })
  async releaseSchedulingFence(
    @Param('id', ParseUUIDPipe) id: string,
    @Param('token', ParseUUIDPipe) token: string,
  ): Promise<void> {
    await this.runnerService.releaseSchedulingFence(id, token)
  }

  @Patch(':id/capacity')
  @ApiOperation({
    summary: 'Update runner registered capacity',
    operationId: 'updateRunnerCapacity',
    description:
      'Sets the CPU, memory and disk the reservation-aware placement and the runner scaler count against. The runner heartbeat does not report memory or disk, so this is the operator record of the node behind the runner.',
  })
  @ApiParam({ name: 'id', description: 'Runner ID', type: 'string' })
  @ApiResponse({ status: 200, description: 'Capacity updated' })
  async updateCapacity(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() body: { cpu?: number; memoryGiB?: number; diskGiB?: number },
  ): Promise<void> {
    await this.runnerService.updateRegisteredCapacity(id, body)
  }

  @Delete(':id')
  @HttpCode(204)
  @ApiOperation({
    summary: 'Delete runner',
    operationId: 'adminDeleteRunner',
  })
  @ApiParam({
    name: 'id',
    description: 'Runner ID',
    type: String,
  })
  @ApiResponse({
    status: 204,
  })
  @Audit({
    action: AuditAction.DELETE,
    targetType: AuditTarget.RUNNER,
    targetIdFromRequest: (req) => req.params.id,
  })
  async delete(@Param('id', ParseUUIDPipe) id: string): Promise<void> {
    return this.runnerService.remove(id)
  }
}
