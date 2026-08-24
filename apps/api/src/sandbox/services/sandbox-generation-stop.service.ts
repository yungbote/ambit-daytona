/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
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
  private readonly logger = new Logger(SandboxGenerationStopService.name)

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
      throw translateGenerationStopError(error, false)
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
      mutationReceiptGuard(() => assertStoppedGenerationReceipt(receipt, request))
      await this.reconcileStoppedState(sandbox, adapter, receipt)
      return receipt
    } catch (error) {
      throw translateGenerationStopError(error, true)
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
      throw translateGenerationStopError(error, false)
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
    try {
      const request = {
        source: receipt.request.source,
        owner: receipt.request.owner,
        fence: receipt.request.fence,
      }
      const current = await adapter.observeSandboxGeneration(sandbox.id, request)
      responseGuard(() => assertGenerationObservation(current, request))
      if (current.state !== 'stopped' || !sameCanonical(current.generation, receipt.request.expectedGeneration)) {
        this.logger.warn(
          `Skipped stopped-state projection for sandbox ${sandbox.id}: current generation differs from receipt ${receipt.receiptRef}`,
        )
        return
      }
      if (sandbox.state === SandboxState.STOPPED) return
      await this.sandboxes.updateState(sandbox.id, SandboxState.STOPPED)
    } catch (error) {
      // Projection is a recoverable control-plane convenience. It must never
      // make an already validated immutable provider receipt inaccessible.
      this.logger.warn(
        `Stopped-generation receipt ${receipt.receiptRef} is durable, but sandbox ${sandbox.id} state projection failed: ${error instanceof Error ? error.message : 'unknown error'}`,
      )
    }
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

function mutationReceiptGuard(action: () => void): void {
  try {
    action()
  } catch {
    throw stoppedGenerationOutcomeUnknown()
  }
}

function stoppedGenerationOutcomeUnknown(): ServiceUnavailableException {
  return new ServiceUnavailableException({
    statusCode: 503,
    message: 'Stopped-generation outcome is unknown; observe the exact operation before retrying.',
    error: 'Service Unavailable',
    code: 'STOPPED_GENERATION_OUTCOME_UNKNOWN',
  })
}

function translateGenerationStopError(error: unknown, mutating: boolean): unknown {
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
      if (mutating) return stoppedGenerationOutcomeUnknown()
      return new ServiceUnavailableException('The sandbox runner could not settle stopped-generation authority.')
  }
}
