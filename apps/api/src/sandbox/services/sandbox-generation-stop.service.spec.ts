/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { ConflictException } from '@nestjs/common'

import {
  stopAuthorityFromReceipt,
  stoppedGenerationReceiptDigest,
  stoppedGenerationRequestFingerprint,
} from '../dto/sandbox-generation-stop.contract'
import {
  SandboxGenerationObservationDto,
  SandboxGenerationStopObservationDto,
  StopSandboxGenerationRequestDto,
  StoppedSandboxGenerationReceiptDto,
} from '../dto/sandbox-generation-stop.dto'
import { SandboxClass } from '../enums/sandbox-class.enum'
import { SandboxState } from '../enums/sandbox-state.enum'
import { RunnerApiError } from '../errors/runner-api-error'
import { RunnerAdapter, RunnerAdapterFactory } from '../runner-adapter/runnerAdapter'
import { RunnerService } from './runner.service'
import { SandboxExecutionAuthorityService } from './sandbox-execution-authority.service'
import { SandboxGenerationStopService } from './sandbox-generation-stop.service'
import { SandboxService } from './sandbox.service'

const TENANT_ID = '00000000-0000-4000-8000-000000000001'
const USER_ID = '00000000-0000-4000-8000-000000000002'
const WORKSPACE_ID = '00000000-0000-4000-8000-000000000003'
const RUN_ID = '00000000-0000-4000-8000-000000000004'
const GRANT_ID = '00000000-0000-4000-8000-000000000005'
const WORKING_COPY_ID = '00000000-0000-4000-8000-000000000006'
const MANIFEST_REF = `ambit.workspace-execution-manifest:v1:sha256:${'c'.repeat(64)}`

describe(SandboxGenerationStopService.name, () => {
  let adapter: jest.Mocked<RunnerAdapter>
  let sandboxes: Pick<SandboxService, 'findOneByIdOrName' | 'updateState'>
  let service: SandboxGenerationStopService

  beforeEach(() => {
    adapter = {
      observeSandboxGeneration: jest.fn(),
      stopSandboxGenerationOnce: jest.fn(),
      observeSandboxGenerationStop: jest.fn(),
    } as unknown as jest.Mocked<RunnerAdapter>
    adapter.observeSandboxGeneration.mockResolvedValue(validGenerationObservation('stopped'))
    sandboxes = {
      findOneByIdOrName: jest.fn().mockResolvedValue(validSandbox()),
      updateState: jest.fn().mockResolvedValue(undefined),
    }
    const runners = {
      findOneOrFail: jest.fn().mockResolvedValue({ id: 'runner-1', apiUrl: 'https://runner.test' }),
    }
    const adapters = { create: jest.fn().mockResolvedValue(adapter) }
    const authority = new SandboxExecutionAuthorityService(
      sandboxes as SandboxService,
      runners as unknown as RunnerService,
      adapters as unknown as RunnerAdapterFactory,
    )
    service = new SandboxGenerationStopService(authority, sandboxes as SandboxService)
  })

  it('matches the frozen Go request fingerprint vectors for both purposes', () => {
    const request = validStopRequest()
    expect(request.requestFingerprint).toBe('7dd5161b4b26b60ad12c5ca45331e1438f682a6d6a97725be8db497d10b76d3c')
    const renderer = validStopRequest()
    renderer.purpose = {
      kind: 'document_renderer_quiescence',
      sessionId: `ambit-document-render-${'a'.repeat(40)}`,
      nonce: 'b'.repeat(32),
      rendererProcessIdentity: { pid: 42, startTicks: '123456789' },
    }
    expect(stoppedGenerationRequestFingerprint(renderer)).toBe(
      '49c2dc4a258914ed71dba7709cf35d89497108555a1ab9b8c9d6a61506a9c7bc',
    )
  })

  it('observes an exact current generation without changing sandbox state', async () => {
    const request = generationRequest()
    const observation = validGenerationObservation()
    adapter.observeSandboxGeneration.mockResolvedValue(observation)

    await expect(service.observeCurrent('org-1', 'friendly', request)).resolves.toEqual(observation)
    expect(adapter.observeSandboxGeneration).toHaveBeenCalledWith('sandbox-1', request)
    expect(sandboxes.updateState).not.toHaveBeenCalled()
  })

  it('settles one exact stop receipt and reconciles the host sandbox state', async () => {
    const request = validStopRequest()
    const receipt = validReceipt(request)
    adapter.stopSandboxGenerationOnce.mockResolvedValue(receipt)

    await expect(service.stopOnce('org-1', 'sandbox-1', request)).resolves.toEqual(receipt)
    expect(adapter.stopSandboxGenerationOnce).toHaveBeenCalledWith('sandbox-1', request)
    expect(adapter.observeSandboxGeneration).toHaveBeenCalledWith('sandbox-1', generationRequest())
    expect(sandboxes.updateState).toHaveBeenCalledWith('sandbox-1', SandboxState.STOPPED)
    expect(stopAuthorityFromReceipt(receipt)).toEqual({
      operationId: request.operationId,
      receiptRef: receipt.receiptRef,
      receiptDigest: receipt.receiptDigest,
      terminalGeneration: receipt.terminalGeneration,
      fence: request.fence,
    })
  })

  it.each(['absent', 'partial', 'complete'] as const)(
    'validates and returns an exact %s durable observation',
    async (status) => {
      const request = validStopRequest()
      const observation: SandboxGenerationStopObservationDto =
        status === 'complete'
          ? { status, receipt: validReceipt(request) }
          : { status, request: structuredClone(request) }
      adapter.observeSandboxGenerationStop.mockResolvedValue(observation)

      await expect(service.observeStop('org-1', 'sandbox-1', request)).resolves.toEqual(observation)
      expect(sandboxes.updateState).toHaveBeenCalledTimes(status === 'complete' ? 1 : 0)
    },
  )

  it('does not rewrite an already-stopped host record after terminal reconciliation', async () => {
    const sandbox = validSandbox()
    sandbox.state = SandboxState.STOPPED
    ;(sandboxes.findOneByIdOrName as jest.Mock).mockResolvedValueOnce(sandbox)
    const request = validStopRequest()
    adapter.stopSandboxGenerationOnce.mockResolvedValue(validReceipt(request))

    await service.stopOnce('org-1', 'sandbox-1', request)
    expect(sandboxes.updateState).not.toHaveBeenCalled()
  })

  it('returns historical receipt truth without marking a restarted generation stopped', async () => {
    const request = validStopRequest()
    adapter.stopSandboxGenerationOnce.mockResolvedValue(validReceipt(request))
    const restarted = validGenerationObservation('running')
    restarted.generation.restartCount = 1
    restarted.generation.executionStartedAt = '2026-08-24T00:03:00Z'
    adapter.observeSandboxGeneration.mockResolvedValueOnce(restarted)

    await expect(service.stopOnce('org-1', 'sandbox-1', request)).resolves.toEqual(validReceipt(request))
    expect(sandboxes.updateState).not.toHaveBeenCalled()
  })

  it('returns durable receipt truth when fresh projection observation or DB update is unavailable', async () => {
    const request = validStopRequest()
    const receipt = validReceipt(request)
    adapter.stopSandboxGenerationOnce.mockResolvedValue(receipt)
    adapter.observeSandboxGeneration.mockRejectedValueOnce(new Error('projection observation unavailable'))

    await expect(service.stopOnce('org-1', 'sandbox-1', request)).resolves.toEqual(receipt)
    expect(sandboxes.updateState).not.toHaveBeenCalled()

    adapter.observeSandboxGeneration.mockResolvedValueOnce(validGenerationObservation('stopped'))
    ;(sandboxes.updateState as jest.Mock).mockRejectedValueOnce(new Error('projection database unavailable'))
    await expect(service.stopOnce('org-1', 'sandbox-1', request)).resolves.toEqual(receipt)
  })

  it('rejects stale fingerprints and non-exact purpose shapes before sandbox lookup', async () => {
    const stale = validStopRequest()
    stale.expectedGeneration.restartCount++
    await expect(service.stopOnce('org-1', 'sandbox-1', stale)).rejects.toThrow('fingerprint')

    const overScoped = validStopRequest()
    overScoped.purpose = { kind: 'working_copy_capture', nonce: 'a'.repeat(32) }
    overScoped.requestFingerprint = stoppedGenerationRequestFingerprint(overScoped)
    await expect(service.stopOnce('org-1', 'sandbox-1', overScoped)).rejects.toThrow('exact contract shape')
    expect(sandboxes.findOneByIdOrName).not.toHaveBeenCalled()
  })

  it('rejects unstable host lifecycle state before reaching the runner', async () => {
    for (const state of [SandboxState.STARTING, SandboxState.PAUSED, SandboxState.ERROR]) {
      const sandbox = validSandbox()
      sandbox.state = state
      ;(sandboxes.findOneByIdOrName as jest.Mock).mockResolvedValueOnce(sandbox)
      await expect(service.stopOnce('org-1', 'sandbox-1', validStopRequest())).rejects.toBeInstanceOf(ConflictException)
    }
    const pending = validSandbox()
    pending.pending = true
    ;(sandboxes.findOneByIdOrName as jest.Mock).mockResolvedValueOnce(pending)
    await expect(service.stopOnce('org-1', 'sandbox-1', validStopRequest())).rejects.toBeInstanceOf(ConflictException)
    expect(adapter.stopSandboxGenerationOnce).not.toHaveBeenCalled()
  })

  it('classifies unusable mutation receipts as outcome unknown and rejects observation-shape drift', async () => {
    const request = validStopRequest()
    const mutations: Array<(receipt: StoppedSandboxGenerationReceiptDto & Record<string, unknown>) => void> = [
      (receipt) => {
        receipt.request.owner.runId = '99999999-9999-4999-8999-999999999999'
      },
      (receipt) => {
        receipt.terminalGeneration.containerId = 'f'.repeat(64)
      },
      (receipt) => {
        receipt.receiptDigest = `sha256:${'f'.repeat(64)}`
      },
      (receipt) => {
        receipt.extra = true
      },
    ]
    for (const mutate of mutations) {
      const receipt = validReceipt(request) as StoppedSandboxGenerationReceiptDto & Record<string, unknown>
      mutate(receipt)
      adapter.stopSandboxGenerationOnce.mockResolvedValueOnce(receipt)
      await expect(service.stopOnce('org-1', 'sandbox-1', request)).rejects.toMatchObject({
        response: expect.objectContaining({ code: 'STOPPED_GENERATION_OUTCOME_UNKNOWN', statusCode: 503 }),
      })
    }

    adapter.stopSandboxGenerationOnce.mockResolvedValueOnce(undefined as never)
    await expect(service.stopOnce('org-1', 'sandbox-1', request)).rejects.toMatchObject({
      response: expect.objectContaining({ code: 'STOPPED_GENERATION_OUTCOME_UNKNOWN', statusCode: 503 }),
    })

    adapter.observeSandboxGenerationStop.mockResolvedValueOnce(undefined as never)
    await expect(service.observeStop('org-1', 'sandbox-1', request)).rejects.toBeInstanceOf(ConflictException)
  })

  it('preserves runner outcome-unknown status and hides unknown transport failures', async () => {
    const request = validStopRequest()
    adapter.stopSandboxGenerationOnce.mockRejectedValueOnce(
      new RunnerApiError('stop outcome unknown', 503, 'STOPPED_GENERATION_OUTCOME_UNKNOWN'),
    )
    await expect(service.stopOnce('org-1', 'sandbox-1', request)).rejects.toMatchObject({
      response: expect.objectContaining({ code: 'STOPPED_GENERATION_OUTCOME_UNKNOWN', statusCode: 503 }),
    })

    adapter.stopSandboxGenerationOnce.mockRejectedValueOnce(
      new RunnerApiError('gateway detail', undefined, 'ECONNRESET'),
    )
    await expect(service.stopOnce('org-1', 'sandbox-1', request)).rejects.toMatchObject({
      response: expect.objectContaining({
        message: 'Stopped-generation outcome is unknown; observe the exact operation before retrying.',
        statusCode: 503,
        code: 'STOPPED_GENERATION_OUTCOME_UNKNOWN',
      }),
    })

    adapter.observeSandboxGenerationStop.mockRejectedValueOnce(
      new RunnerApiError('gateway detail', undefined, 'ECONNRESET'),
    )
    await expect(service.observeStop('org-1', 'sandbox-1', request)).rejects.toMatchObject({
      response: expect.objectContaining({
        message: 'The sandbox runner could not settle stopped-generation authority.',
        statusCode: 503,
      }),
    })
  })
})

function generationRequest() {
  const request = validStopRequest()
  return { source: request.source, owner: request.owner, fence: request.fence }
}

function validStopRequest(): StopSandboxGenerationRequestDto {
  const request: StopSandboxGenerationRequestDto = {
    operationId: '10000000-0000-4000-8000-000000000009',
    requestFingerprint: '',
    source: {
      providerResourceId: 'sandbox-1',
      expectedProfile: 'managed-container',
      expectedRuntimeKind: 'full_image_runtime_pack',
    },
    owner: {
      tenantId: TENANT_ID,
      userId: USER_ID,
      workspaceId: WORKSPACE_ID,
      runId: RUN_ID,
      grantId: GRANT_ID,
      workingCopyId: WORKING_COPY_ID,
    },
    fence: { workspaceExecutionManifestRef: MANIFEST_REF },
    expectedGeneration: {
      containerId: 'a'.repeat(64),
      containerCreatedAt: '2026-08-23T23:59:00Z',
      executionStartedAt: '2026-08-24T00:00:00Z',
      restartCount: 0,
    },
    purpose: { kind: 'working_copy_capture' },
  }
  request.requestFingerprint = stoppedGenerationRequestFingerprint(request)
  return request
}

function validGenerationObservation(state: 'running' | 'stopped' = 'running'): SandboxGenerationObservationDto {
  const request = validStopRequest()
  return {
    source: structuredClone(request.source),
    owner: structuredClone(request.owner),
    fence: structuredClone(request.fence),
    generation: structuredClone(request.expectedGeneration),
    state,
    observedAt: '2026-08-24T00:00:30Z',
  }
}

function validReceipt(request: StopSandboxGenerationRequestDto): StoppedSandboxGenerationReceiptDto {
  const receipt: StoppedSandboxGenerationReceiptDto = {
    version: 1,
    kind: 'agent_workspace_stopped_generation_receipt',
    request: structuredClone(request),
    receiptRef: '',
    receiptDigest: '',
    terminalGeneration: {
      ...structuredClone(request.expectedGeneration),
      executionFinishedAt: '2026-08-24T00:01:00Z',
      exitCode: 0,
      oomKilled: false,
    },
    stoppedAt: '2026-08-24T00:02:00Z',
  }
  receipt.receiptDigest = stoppedGenerationReceiptDigest(receipt)
  receipt.receiptRef = `ambit.stopped-generation-receipt:v1:${receipt.receiptDigest}`
  return receipt
}

function validSandbox() {
  return {
    id: 'sandbox-1',
    runnerId: 'runner-1',
    sandboxClass: SandboxClass.CONTAINER,
    state: SandboxState.STARTED,
    pending: false,
    labels: {
      ambitWorkspaceId: WORKSPACE_ID,
      ambitTenantId: TENANT_ID,
      ambitPrincipalId: USER_ID,
      ambitTaskId: RUN_ID,
      ambitGrantId: GRANT_ID,
      ambitProfile: 'managed-container',
      ambitWorkspaceExecutionManifestRef: MANIFEST_REF,
      ambitRuntimeKind: 'full_image_runtime_pack_provider_observation',
      ambitRuntimeWorkspaceId: WORKSPACE_ID,
      ambitRuntimeManifestRef: MANIFEST_REF,
      ambitRuntimeProductRunId: RUN_ID,
      ambitRuntimeGrantId: GRANT_ID,
    },
  }
}
