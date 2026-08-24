/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common'

import { SandboxExecutionOwnerDto, SandboxExecutionSourceDto } from '../dto/sandbox-execution-authority.dto'
import { SandboxGenerationFenceDto } from '../dto/sandbox-generation-stop.dto'
import { SandboxClass } from '../enums/sandbox-class.enum'
import { Sandbox } from '../entities/sandbox.entity'
import { RunnerAdapter, RunnerAdapterFactory } from '../runner-adapter/runnerAdapter'
import { RunnerService } from './runner.service'
import { SandboxService } from './sandbox.service'

@Injectable()
export class SandboxExecutionAuthorityService {
  constructor(
    private readonly sandboxes: SandboxService,
    private readonly runners: RunnerService,
    private readonly runnerAdapters: RunnerAdapterFactory,
  ) {}

  async authorize(
    organizationId: string,
    sandboxIdOrName: string,
    source: SandboxExecutionSourceDto,
    owner: SandboxExecutionOwnerDto,
    fence: SandboxGenerationFenceDto,
  ): Promise<{ sandbox: Sandbox; adapter: RunnerAdapter }> {
    const sandbox = await this.sandboxes.findOneByIdOrName(sandboxIdOrName, organizationId)
    if (source.providerResourceId !== sandbox.id) {
      throw new ForbiddenException('Execution source does not name the authorized sandbox.')
    }
    const labels = sandbox.labels ?? {}
    if (
      labels.ambitWorkspaceId !== owner.workspaceId ||
      labels.ambitTenantId !== owner.tenantId ||
      labels.ambitPrincipalId !== owner.userId ||
      labels.ambitTaskId !== owner.runId ||
      labels.ambitGrantId !== owner.grantId ||
      labels.ambitProfile !== source.expectedProfile ||
      labels.ambitWorkspaceExecutionManifestRef !== fence.workspaceExecutionManifestRef ||
      labels.ambitRuntimeKind !== 'full_image_runtime_pack_provider_observation' ||
      labels.ambitRuntimeWorkspaceId !== owner.workspaceId ||
      labels.ambitRuntimeManifestRef !== fence.workspaceExecutionManifestRef ||
      labels.ambitRuntimeProductRunId !== owner.runId ||
      labels.ambitRuntimeGrantId !== owner.grantId
    ) {
      throw new ForbiddenException('Execution ownership or runtime fence does not match the authorized sandbox.')
    }
    if (
      sandbox.sandboxClass !== SandboxClass.CONTAINER ||
      source.expectedProfile !== 'managed-container' ||
      source.expectedRuntimeKind !== 'full_image_runtime_pack'
    ) {
      throw new ConflictException('Generation authority is admitted only for managed full-image containers.')
    }
    if (!sandbox.runnerId) {
      throw new NotFoundException('The sandbox has no assigned runner.')
    }
    const runner = await this.runners.findOneOrFail(sandbox.runnerId)
    if (!runner.apiUrl) {
      throw new ServiceUnavailableException('The sandbox runner has not published a direct API address.')
    }
    return { sandbox, adapter: await this.runnerAdapters.create(runner) }
  }
}
