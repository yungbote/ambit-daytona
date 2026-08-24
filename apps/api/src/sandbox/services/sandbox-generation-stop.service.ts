/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common'

import {
  assertGenerationObservation,
  assertGenerationObservationRequest,
  assertStopObservation,
  assertStopRequest,
  assertStoppedGenerationReceipt,
  sameCanonical,
} from '../dto/sandbox-generation-stop.contract'
import {
  SandboxGenerationObservationDto,
  SandboxGenerationObservationRequestDto,
  SandboxGenerationStopObservationDto,
  StopSandboxGenerationRequestDto,
  StoppedSandboxGenerationReceiptDto,
} from '../dto/sandbox-generation-stop.dto'
import { Sandbox } from '../entities/sandbox.entity'
import { SandboxState } from '../enums/sandbox-state.enum'
import { RunnerApiError } from '../errors/runner-api-error'
import { RunnerAdapter } from '../runner-adapter/runnerAdapter'
import { SandboxExecutionAuthorityService } from './sandbox-execution-authority.service'
import { SandboxService } from './sandbox.service'

@Injectable()
export class SandboxGenerationStopService {
  constructor(
    private readonly executionAuthority: SandboxExecutionAuthorityService,
    private readonly sandboxes: SandboxService,
  ) {}

  async observeCurrent(
    organizationId: string,
    sandboxIdOrName: string,
    request: SandboxGenerationObservationRequestDto,
  ): Promise<SandboxGenerationObservationDto> {
    requestGuard(() => assertGenerationObservationRequest(request))
    const { sandbox, adapter } = await this.authorized(organizationId, sandboxIdOrName, request)
    try {
      const observation = await adapter.observeSandboxGeneration(sandbox.id, request)
      responseGuard(() => assertGenerationObservation(observation, request))
      return observation
    } catch (error) {
      throw translateGenerationStopError(error)
    }
  }

  async stopOnce(
    organizationId: string,
    sandboxIdOrName: string,
    request: StopSandboxGenerationRequestDto,
  ): Promise<StoppedSandboxGenerationReceiptDto> {
    requestGuard(() => assertStopRequest(request))
    const { sandbox, adapter } = await this.authorized(organizationId, sandboxIdOrName, request)
    try {
      const receipt = await adapter.stopSandboxGenerationOnce(sandbox.id, request)
      responseGuard(() => assertStoppedGenerationReceipt(receipt, request))
      await this.reconcileStoppedState(sandbox, adapter, receipt)
      return receipt
    } catch (error) {
      throw translateGenerationStopError(error)
    }
  }

  async observeStop(
    organizationId: string,
    sandboxIdOrName: string,
    request: StopSandboxGenerationRequestDto,
  ): Promise<SandboxGenerationStopObservationDto> {
    requestGuard(() => assertStopRequest(request))
    const { sandbox, adapter } = await this.authorized(organizationId, sandboxIdOrName, request)
    try {
      const observation = await adapter.observeSandboxGenerationStop(sandbox.id, request)
      responseGuard(() => assertStopObservation(observation, request))
      if (observation.status === 'complete') {
        await this.reconcileStoppedState(sandbox, adapter, observation.receipt as StoppedSandboxGenerationReceiptDto)
      }
      return observation
    } catch (error) {
      throw translateGenerationStopError(error)
    }
  }

  private async authorized(
    organizationId: string,
    sandboxIdOrName: string,
    request: SandboxGenerationObservationRequestDto,
  ) {
    const authority = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      request.source,
      request.owner,
      request.fence,
    )
    if (authority.sandbox.pending || ![SandboxState.STARTED, SandboxState.STOPPED].includes(authority.sandbox.state)) {
      throw new ConflictException('Sandbox generation is not in a stable running or stopped state.')
    }
    return authority
  }

  private async reconcileStoppedState(
    sandbox: Sandbox,
    adapter: RunnerAdapter,
    receipt: StoppedSandboxGenerationReceiptDto,
  ): Promise<void> {
    const request = {
      source: receipt.request.source,
      owner: receipt.request.owner,
      fence: receipt.request.fence,
    }
    const current = await adapter.observeSandboxGeneration(sandbox.id, request)
    responseGuard(() => assertGenerationObservation(current, request))
    if (current.state !== 'stopped' || !sameCanonical(current.generation, receipt.request.expectedGeneration)) {
      // Immutable receipt truth remains observable after a later restart, but
      // it cannot mutate current host lifecycle state. WorkingCopy capture
      // separately requires a fresh current receipt proof and rejects staleness.
      return
    }
    if (sandbox.state === SandboxState.STOPPED) return
    await this.sandboxes.updateState(sandbox.id, SandboxState.STOPPED)
  }
}

function requestGuard(action: () => void): void {
  try {
    action()
  } catch (error) {
    throw new BadRequestException(error instanceof Error ? error.message : 'Stopped-generation request is invalid.')
  }
}

function responseGuard(action: () => void): void {
  try {
    action()
  } catch (error) {
    throw new ConflictException(error instanceof Error ? error.message : 'Stopped-generation response is invalid.')
  }
}

function translateGenerationStopError(error: unknown): unknown {
  if (!(error instanceof RunnerApiError)) return error
  switch (error.statusCode) {
    case 400:
      return new BadRequestException(error.message)
    case 404:
      return new NotFoundException(error.message)
    case 409:
      return new ConflictException(error.message)
    case 503:
      return new ServiceUnavailableException({
        statusCode: 503,
        message: error.message,
        error: 'Service Unavailable',
        code:
          error.code === 'STOPPED_GENERATION_OUTCOME_UNKNOWN'
            ? 'STOPPED_GENERATION_OUTCOME_UNKNOWN'
            : 'STOPPED_GENERATION_UNAVAILABLE',
      })
    default:
      return new ServiceUnavailableException('The sandbox runner could not settle stopped-generation authority.')
  }
}
