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
import { Runner } from '../entities/runner.entity'
import { RunnerService } from './runner.service'
import { SandboxService } from './sandbox.service'

export type SandboxProviderGenerationSource = Readonly<{
  providerResourceId: string
  expectedProfile: string
  expectedRuntimeKind: 'base_profile' | 'full_image_runtime_pack'
}>

export type SandboxProviderGenerationOwner = Readonly<{
  tenantId: string
  userId: string
  workspaceId: string
  runId: string
  grantId: string
}>

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
  ): Promise<{ sandbox: Sandbox; runner: Runner; adapter: RunnerAdapter }> {
    const authority = await this.authorizeProviderGeneration(organizationId, sandboxIdOrName, source, owner, fence)
    if (source.expectedProfile !== 'managed-container' || source.expectedRuntimeKind !== 'full_image_runtime_pack') {
      throw new ConflictException('Generation authority is admitted only for managed full-image containers.')
    }
    return authority
  }

  async authorizeProviderGeneration(
    organizationId: string,
    sandboxIdOrName: string,
    source: SandboxProviderGenerationSource,
    owner: SandboxProviderGenerationOwner,
    fence: SandboxGenerationFenceDto,
  ): Promise<{ sandbox: Sandbox; runner: Runner; adapter: RunnerAdapter }> {
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
      labels.ambitWorkspaceExecutionManifestRef !== fence.workspaceExecutionManifestRef
    ) {
      throw new ForbiddenException('Execution ownership or fence does not match the authorized sandbox.')
    }
    if (sandbox.sandboxClass !== SandboxClass.CONTAINER) {
      throw new ConflictException('Generation authority is admitted only for container sandboxes.')
    }
    if (source.expectedRuntimeKind === 'full_image_runtime_pack') {
      if (
        labels.ambitRuntimeKind !== 'full_image_runtime_pack_provider_observation' ||
        labels.ambitRuntimeWorkspaceId !== owner.workspaceId ||
        labels.ambitRuntimeManifestRef !== fence.workspaceExecutionManifestRef ||
        labels.ambitRuntimeProductRunId !== owner.runId ||
        labels.ambitRuntimeGrantId !== owner.grantId
      ) {
        throw new ForbiddenException('Full-image runtime authority differs from the authorized sandbox.')
      }
    } else if (source.expectedRuntimeKind === 'base_profile') {
      if (Object.keys(labels).some((key) => key.startsWith('ambitRuntime'))) {
        throw new ForbiddenException('Base-profile sandbox contains partial or substituted runtime-pack authority.')
      }
    } else {
      throw new ConflictException('Generation runtime kind is retired or unrecognized.')
    }
    if (!sandbox.runnerId) {
      throw new NotFoundException('The sandbox has no assigned runner.')
    }
    const runner = await this.runners.findOneOrFail(sandbox.runnerId)
    if (!runner.apiUrl) {
      throw new ServiceUnavailableException('The sandbox runner has not published a direct API address.')
    }
    return { sandbox, runner, adapter: await this.runnerAdapters.create(runner) }
  }
}
