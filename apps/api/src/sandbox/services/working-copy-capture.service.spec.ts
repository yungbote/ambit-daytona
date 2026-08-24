/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { createHash } from 'node:crypto'
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common'

import {
  MAXIMUM_WORKING_COPY_CAPTURE_BYTES,
  MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES,
  WorkingCopyCaptureBindingDto,
  WorkingCopyCaptureDeleteReceiptDto,
  WorkingCopyCaptureExistsResponseDto,
  WorkingCopyCaptureIdentityDto,
  WorkingCopyCaptureReadDto,
  WorkingCopyCaptureReadResponseDto,
  WorkingCopyCaptureReceiptDto,
} from '../dto/working-copy-capture.dto'
import { SandboxClass } from '../enums/sandbox-class.enum'
import { SandboxState } from '../enums/sandbox-state.enum'
import { RunnerApiError } from '../errors/runner-api-error'
import { RunnerAdapter, RunnerAdapterFactory } from '../runner-adapter/runnerAdapter'
import { RunnerService } from './runner.service'
import { SandboxService } from './sandbox.service'
import { SandboxExecutionAuthorityService } from './sandbox-execution-authority.service'
import { WorkingCopyCaptureService } from './working-copy-capture.service'

const TENANT_ID = '11111111-1111-4111-8111-111111111111'
const USER_ID = '22222222-2222-4222-8222-222222222222'
const WORKSPACE_ID = '33333333-3333-4333-8333-333333333333'
const RUN_ID = '44444444-4444-4444-8444-444444444444'
const GRANT_ID = '55555555-5555-4555-8555-555555555555'
const WORKING_COPY_ID = '66666666-6666-4666-8666-666666666666'
const OTHER_ID = '99999999-9999-4999-8999-999999999999'
const CAPTURE_ID = `daytona-working-copy-capture:v2:sha256:${'b'.repeat(64)}`
const CAPTURE_DIGEST = `sha256:${'c'.repeat(64)}`

describe(WorkingCopyCaptureService.name, () => {
  let adapter: jest.Mocked<RunnerAdapter>
  let sandboxService: Pick<SandboxService, 'findOneByIdOrName'>
  let runnerService: Pick<RunnerService, 'findOneOrFail'>
  let adapters: Pick<RunnerAdapterFactory, 'create'>
  let service: WorkingCopyCaptureService

  beforeEach(() => {
    adapter = {
      captureWorkingCopy: jest.fn(),
      observeWorkingCopyCapture: jest.fn(),
      readWorkingCopyCapture: jest.fn(),
      deleteWorkingCopyCapture: jest.fn(),
      workingCopyCaptureExists: jest.fn(),
    } as unknown as jest.Mocked<RunnerAdapter>
    sandboxService = {
      findOneByIdOrName: jest.fn().mockResolvedValue(validSandbox()),
    }
    runnerService = {
      findOneOrFail: jest.fn().mockResolvedValue({ id: 'runner-1', apiUrl: 'https://runner.test' }),
    }
    adapters = { create: jest.fn().mockResolvedValue(adapter) }
    const executionAuthority = new SandboxExecutionAuthorityService(
      sandboxService as SandboxService,
      runnerService as RunnerService,
      adapters as RunnerAdapterFactory,
    )
    service = new WorkingCopyCaptureService(executionAuthority)
  })

  it('authorizes the exact v2 owner, source, runtime and stopped-container labels before capture', async () => {
    const binding = validBinding()
    const receipt = validReceipt(binding)
    adapter.captureWorkingCopy.mockResolvedValue(receipt)

    await expect(service.capture('daytona-org-1', 'friendly-name', binding)).resolves.toEqual(receipt)

    expect(binding.owner).toEqual({
      tenantId: TENANT_ID,
      userId: USER_ID,
      workspaceId: WORKSPACE_ID,
      runId: RUN_ID,
      grantId: GRANT_ID,
      workingCopyId: WORKING_COPY_ID,
    })
    expect(receipt).toMatchObject({
      providerResourceId: CAPTURE_ID,
      totalByteLength: 5,
      providerSha256Digest: CAPTURE_DIGEST,
    })
    expect(sandboxService.findOneByIdOrName).toHaveBeenCalledWith('friendly-name', 'daytona-org-1')
    expect(runnerService.findOneOrFail).toHaveBeenCalledWith('runner-1')
    expect(adapters.create).toHaveBeenCalledTimes(1)
    expect(adapter.captureWorkingCopy).toHaveBeenCalledWith('sandbox-1', binding)
  })

  it('binds authority v2 to the exact lineage preimage and pinned protocol/helper artifacts', async () => {
    const binding = validBinding()
    const expectedRef = `ambit.working-copy-capture-authority:v2:sha256:${createHash('sha256')
      .update(['ambit.working-copy-capture-authority/v2', binding.authority.lineageRef].join('\n'), 'utf8')
      .digest('hex')}`

    expect(binding.authority).toEqual({
      authorityRef: expectedRef,
      lineageRef: 'ambit.runtime-lineage/full-image-runtime-pack@5',
      roleRef: 'ambit.runtime-component/working-copy-capture@2',
      protocol: {
        ref: 'ambit.runtime-interface/working-copy-capture@2',
        digest: `sha256:${'7'.repeat(64)}`,
      },
      helper: {
        ref: `runtime-component-artifact:sha256:${'8'.repeat(64)}`,
        digest: `sha256:${'8'.repeat(64)}`,
      },
    })

    const receipt = validReceipt(binding)
    adapter.captureWorkingCopy.mockResolvedValue(receipt)
    await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).resolves.toEqual(receipt)
  })

  it.each([
    ['absolute', '/etc/passwd'],
    ['traversal', '../secret'],
    ['noncanonical', 'dir//file'],
    ['dot', 'dir/./file'],
    ['backslash', 'dir\\file'],
    ['trailing slash', 'dir/'],
    ['control', 'line\nbreak'],
  ])('rejects %s selectors before lookup or provider effects', async (_name, path) => {
    const binding = validBinding()
    binding.selector.zoneRelativePath = path

    await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).rejects.toBeInstanceOf(BadRequestException)
    expect(sandboxService.findOneByIdOrName).not.toHaveBeenCalled()
    expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
  })

  it('rejects non-exact binding and nested authority shapes before lookup', async () => {
    const candidates: WorkingCopyCaptureBindingDto[] = []

    const extraBinding = validBinding() as WorkingCopyCaptureBindingDto & { absolutePath: string }
    extraBinding.absolutePath = '/etc/passwd'
    candidates.push(extraBinding)

    const extraOwner = validBinding()
    ;(extraOwner.owner as typeof extraOwner.owner & { organizationId: string }).organizationId = 'daytona-org-1'
    candidates.push(extraOwner)

    const extraSource = validBinding()
    ;(extraSource.source as typeof extraSource.source & { workspaceId: string }).workspaceId = WORKSPACE_ID
    candidates.push(extraSource)

    const extraAuthority = validBinding()
    ;(extraAuthority.authority as typeof extraAuthority.authority & { provider: string }).provider = 'daytona'
    candidates.push(extraAuthority)

    const forgedLineage = validBinding()
    forgedLineage.authority.lineageRef = 'ambit.runtime-lineage/forged@5'
    candidates.push(forgedLineage)

    const forgedRole = validBinding()
    ;(forgedRole.authority as { roleRef: string }).roleRef = 'ambit.runtime-component/working-copy-capture@1'
    candidates.push(forgedRole)

    const forgedProtocol = validBinding()
    forgedProtocol.authority.protocol.ref = 'ambit.runtime-interface/working-copy-capture@1'
    candidates.push(forgedProtocol)

    const forgedHelper = validBinding()
    forgedHelper.authority.helper.ref = `runtime-component-artifact:sha256:${'9'.repeat(64)}`
    candidates.push(forgedHelper)

    const extraStopAuthority = validBinding()
    ;(extraStopAuthority.stopAuthority as typeof extraStopAuthority.stopAuthority & { provider: string }).provider =
      'daytona'
    candidates.push(extraStopAuthority)

    const forgedStopReceipt = validBinding()
    forgedStopReceipt.stopAuthority.receiptDigest = `sha256:${'f'.repeat(64)}`
    candidates.push(forgedStopReceipt)

    const impossibleTerminal = validBinding()
    impossibleTerminal.stopAuthority.terminalGeneration.executionFinishedAt = '2026-08-23T23:58:00Z'
    candidates.push(impossibleTerminal)

    for (const candidate of candidates) {
      await expect(service.capture('daytona-org-1', 'sandbox-1', candidate)).rejects.toBeInstanceOf(BadRequestException)
    }
    expect(sandboxService.findOneByIdOrName).not.toHaveBeenCalled()
    expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
  })

  it.each(['tenantId', 'userId', 'workspaceId', 'runId', 'grantId', 'workingCopyId'] as const)(
    'rejects a non-canonical %s owner UUID before lookup',
    async (field) => {
      const binding = validBinding()
      binding.owner[field] = '00000000-0000-0000-0000-000000000000'

      await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).rejects.toBeInstanceOf(BadRequestException)
      expect(sandboxService.findOneByIdOrName).not.toHaveBeenCalled()
      expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
    },
  )

  it('fails closed on exact source and workspace, tenant, principal, run, grant and profile label drift', async () => {
    const labelCases = [
      'ambitWorkspaceId',
      'ambitTenantId',
      'ambitPrincipalId',
      'ambitTaskId',
      'ambitGrantId',
      'ambitProfile',
      'ambitRuntimeKind',
      'ambitRuntimeWorkspaceId',
      'ambitRuntimeManifestRef',
      'ambitRuntimeProductRunId',
      'ambitRuntimeGrantId',
    ] as const

    for (const label of labelCases) {
      const sandbox = validSandbox()
      sandbox.labels[label] = 'mismatched-authority'
      ;(sandboxService.findOneByIdOrName as jest.Mock).mockResolvedValueOnce(sandbox)
      await expect(service.capture('daytona-org-1', 'sandbox-1', validBinding())).rejects.toBeInstanceOf(
        ForbiddenException,
      )
    }

    const wrongSource = validBinding()
    wrongSource.source.providerResourceId = 'other-sandbox'
    await expect(service.capture('daytona-org-1', 'sandbox-1', wrongSource)).rejects.toBeInstanceOf(ForbiddenException)
    expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
  })

  it('fails closed on runtime manifest, runtime class, lifecycle, runner and direct-address drift', async () => {
    for (const manifestRef of ['', ' leading-space', 'x'.repeat(513), 'manifest\nref']) {
      const sandbox = validSandbox()
      sandbox.labels.ambitWorkspaceExecutionManifestRef = manifestRef
      ;(sandboxService.findOneByIdOrName as jest.Mock).mockResolvedValueOnce(sandbox)
      await expect(service.capture('daytona-org-1', 'sandbox-1', validBinding())).rejects.toBeInstanceOf(
        ForbiddenException,
      )
    }

    const wrongClass = validSandbox()
    wrongClass.sandboxClass = SandboxClass.LINUX_VM
    ;(sandboxService.findOneByIdOrName as jest.Mock).mockResolvedValueOnce(wrongClass)
    await expect(service.capture('daytona-org-1', 'sandbox-1', validBinding())).rejects.toBeInstanceOf(
      ConflictException,
    )

    const started = validSandbox()
    started.state = SandboxState.STARTED
    ;(sandboxService.findOneByIdOrName as jest.Mock).mockResolvedValueOnce(started)
    await expect(service.capture('daytona-org-1', 'sandbox-1', validBinding())).rejects.toBeInstanceOf(
      ConflictException,
    )

    const noRunner = validSandbox()
    noRunner.runnerId = undefined
    ;(sandboxService.findOneByIdOrName as jest.Mock).mockResolvedValueOnce(noRunner)
    await expect(service.capture('daytona-org-1', 'sandbox-1', validBinding())).rejects.toBeInstanceOf(
      NotFoundException,
    )
    ;(runnerService.findOneOrFail as jest.Mock).mockResolvedValueOnce({ id: 'runner-1', apiUrl: null })
    await expect(service.capture('daytona-org-1', 'sandbox-1', validBinding())).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    )
    expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
  })

  it('rejects an unadmitted runtime kind before sandbox lookup', async () => {
    const binding = validBinding()
    ;(binding.source as { expectedRuntimeKind: string }).expectedRuntimeKind = 'container'

    await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).rejects.toBeInstanceOf(BadRequestException)
    expect(sandboxService.findOneByIdOrName).not.toHaveBeenCalled()
  })

  it('rejects provider receipts that mutate exact shape, binding, total length, digest, identity or time', async () => {
    const binding = validBinding()
    const mutations: Array<(receipt: WorkingCopyCaptureReceiptDto & Record<string, unknown>) => void> = [
      (receipt) => {
        receipt.selector.zoneRelativePath = 'other.txt'
      },
      (receipt) => {
        receipt.owner.workingCopyId = OTHER_ID
      },
      (receipt) => {
        receipt.extra = true
      },
      (receipt) => {
        receipt.totalByteLength = MAXIMUM_WORKING_COPY_CAPTURE_BYTES + 1
      },
      (receipt) => {
        receipt.totalByteLength = 1.5
      },
      (receipt) => {
        receipt.providerSha256Digest = 'sha256:wrong'
      },
      (receipt) => {
        receipt.providerResourceId = 'not-an-identity'
      },
      (receipt) => {
        receipt.capturedAt = 'not-a-time'
      },
    ]

    for (const mutate of mutations) {
      const receipt = validReceipt(binding) as WorkingCopyCaptureReceiptDto & Record<string, unknown>
      mutate(receipt)
      adapter.captureWorkingCopy.mockResolvedValueOnce(receipt)
      await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).rejects.toBeInstanceOf(ConflictException)
    }
  })

  it('accepts only exact absent, partial and complete observations bound to the request', async () => {
    const binding = validBinding()
    const identity = validIdentity(binding)
    const receipt = validReceipt(binding)
    adapter.observeWorkingCopyCapture
      .mockResolvedValueOnce({ status: 'absent', binding })
      .mockResolvedValueOnce({ status: 'partial', identity })
      .mockResolvedValueOnce({ status: 'complete', receipt })

    await expect(service.observe('daytona-org-1', 'sandbox-1', binding)).resolves.toEqual({
      status: 'absent',
      binding,
    })
    await expect(service.observe('daytona-org-1', 'sandbox-1', binding)).resolves.toEqual({
      status: 'partial',
      identity,
    })
    await expect(service.observe('daytona-org-1', 'sandbox-1', binding)).resolves.toEqual({
      status: 'complete',
      receipt,
    })

    const wrongIdentity = validIdentity(binding)
    wrongIdentity.owner.workingCopyId = OTHER_ID
    const invalidObservations = [
      { status: 'absent', binding, identity },
      { status: 'partial', identity: wrongIdentity },
      { status: 'complete' },
      { status: 'unknown', binding },
    ]
    for (const observation of invalidObservations) {
      adapter.observeWorkingCopyCapture.mockResolvedValueOnce(observation as never)
      await expect(service.observe('daytona-org-1', 'sandbox-1', binding)).rejects.toBeInstanceOf(ConflictException)
    }
  })

  it('performs bounded ranged reads with exact identity, total, digest, range and EOF receipts', async () => {
    const middle = validRead({ expectedTotalByteLength: 8, offset: 2, maximumBytes: 3 })
    const middleResponse = validReadResponse(middle, 'cde')
    adapter.readWorkingCopyCapture.mockResolvedValueOnce(middleResponse)
    await expect(service.read('daytona-org-1', 'sandbox-1', middle)).resolves.toEqual(middleResponse)
    expect(adapter.readWorkingCopyCapture).toHaveBeenLastCalledWith('sandbox-1', middle)

    const terminal = validRead({ expectedTotalByteLength: 8, offset: 6, maximumBytes: 4 })
    const terminalResponse = validReadResponse(terminal, 'gh')
    adapter.readWorkingCopyCapture.mockResolvedValueOnce(terminalResponse)
    await expect(service.read('daytona-org-1', 'sandbox-1', terminal)).resolves.toEqual(terminalResponse)
    expect(terminalResponse).toMatchObject({ byteLength: 2, eof: true, offset: 6, totalByteLength: 8 })

    const atEof = validRead({ expectedTotalByteLength: 8, offset: 8, maximumBytes: 1 })
    const eofResponse = validReadResponse(atEof, '')
    adapter.readWorkingCopyCapture.mockResolvedValueOnce(eofResponse)
    await expect(service.read('daytona-org-1', 'sandbox-1', atEof)).resolves.toEqual(eofResponse)
    expect(eofResponse).toMatchObject({ byteLength: 0, bytesBase64: '', eof: true })
  })

  it('rejects invalid or unbounded read authority before lookup', async () => {
    const candidates: WorkingCopyCaptureReadDto[] = []
    for (const mutate of [
      (request: WorkingCopyCaptureReadDto) => (request.expectedTotalByteLength = -1),
      (request: WorkingCopyCaptureReadDto) =>
        (request.expectedTotalByteLength = MAXIMUM_WORKING_COPY_CAPTURE_BYTES + 1),
      (request: WorkingCopyCaptureReadDto) => (request.expectedProviderSha256Digest = 'sha256:wrong'),
      (request: WorkingCopyCaptureReadDto) => (request.offset = -1),
      (request: WorkingCopyCaptureReadDto) => (request.offset = request.expectedTotalByteLength + 1),
      (request: WorkingCopyCaptureReadDto) => (request.maximumBytes = 0),
      (request: WorkingCopyCaptureReadDto) => (request.maximumBytes = MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES + 1),
      (request: WorkingCopyCaptureReadDto) => (request.providerResourceId = CAPTURE_ID.replace(':v2:', ':v1:')),
    ]) {
      const request = validRead()
      mutate(request)
      candidates.push(request)
    }
    const extra = validRead() as WorkingCopyCaptureReadDto & { end: number }
    extra.end = 5
    candidates.push(extra)

    for (const candidate of candidates) {
      await expect(service.read('daytona-org-1', 'sandbox-1', candidate)).rejects.toBeInstanceOf(BadRequestException)
    }
    expect(sandboxService.findOneByIdOrName).not.toHaveBeenCalled()
    expect(adapter.readWorkingCopyCapture).not.toHaveBeenCalled()
  })

  it('rejects ranged read responses with non-exact shape, binding, identity, total, digest, range, EOF or body', async () => {
    const request = validRead({ expectedTotalByteLength: 8, offset: 2, maximumBytes: 3 })
    const mutations: Array<(response: WorkingCopyCaptureReadResponseDto & Record<string, unknown>) => void> = [
      (response) => {
        response.extra = true
      },
      (response) => {
        response.owner.runId = OTHER_ID
      },
      (response) => {
        response.providerResourceId = `daytona-working-copy-capture:v2:sha256:${'d'.repeat(64)}`
      },
      (response) => {
        response.totalByteLength = 9
      },
      (response) => {
        response.providerSha256Digest = `sha256:${'d'.repeat(64)}`
      },
      (response) => {
        response.offset = 3
      },
      (response) => {
        response.byteLength = 2
      },
      (response) => {
        response.eof = true
      },
      (response) => {
        response.bytesBase64 = Buffer.from('wrong').toString('base64')
      },
      (response) => {
        response.bytesBase64 = 'Y2Rl='
      },
    ]

    for (const mutate of mutations) {
      const response = validReadResponse(request, 'cde') as WorkingCopyCaptureReadResponseDto & Record<string, unknown>
      mutate(response)
      adapter.readWorkingCopyCapture.mockResolvedValueOnce(response)
      await expect(service.read('daytona-org-1', 'sandbox-1', request)).rejects.toBeInstanceOf(ConflictException)
    }
  })

  it('returns rich exact deletion receipts and does not require a completed capture to remain stopped', async () => {
    const identity = validIdentity(validBinding())
    const deleted = validDeleteReceipt(identity, 'deleted')
    const alreadyAbsent = validDeleteReceipt(identity, 'already_absent')
    ;(sandboxService.findOneByIdOrName as jest.Mock).mockResolvedValue({
      ...validSandbox(),
      state: SandboxState.STARTED,
    })
    adapter.deleteWorkingCopyCapture.mockResolvedValueOnce(deleted).mockResolvedValueOnce(alreadyAbsent)

    await expect(service.delete('daytona-org-1', 'sandbox-1', identity)).resolves.toEqual(deleted)
    await expect(service.delete('daytona-org-1', 'sandbox-1', identity)).resolves.toEqual(alreadyAbsent)
    expect(adapter.deleteWorkingCopyCapture).toHaveBeenNthCalledWith(1, 'sandbox-1', identity)
    expect(adapter.deleteWorkingCopyCapture).toHaveBeenNthCalledWith(2, 'sandbox-1', identity)
  })

  it('rejects deletion receipts with a non-exact shape, outcome, identity or binding', async () => {
    const identity = validIdentity(validBinding())
    const candidates: Array<WorkingCopyCaptureDeleteReceiptDto & Record<string, unknown>> = []

    const extra = validDeleteReceipt(identity, 'deleted') as WorkingCopyCaptureDeleteReceiptDto &
      Record<string, unknown>
    extra.deletedAt = '2026-08-23T12:34:56Z'
    candidates.push(extra)

    const unknownOutcome = validDeleteReceipt(identity, 'deleted') as WorkingCopyCaptureDeleteReceiptDto &
      Record<string, unknown>
    unknownOutcome.outcome = 'outcome_unknown' as never
    candidates.push(unknownOutcome)

    const wrongIdentity = validDeleteReceipt(identity, 'deleted') as WorkingCopyCaptureDeleteReceiptDto &
      Record<string, unknown>
    wrongIdentity.providerResourceId = `daytona-working-copy-capture:v2:sha256:${'d'.repeat(64)}`
    candidates.push(wrongIdentity)

    const wrongBinding = validDeleteReceipt(identity, 'deleted') as WorkingCopyCaptureDeleteReceiptDto &
      Record<string, unknown>
    wrongBinding.owner.grantId = OTHER_ID
    candidates.push(wrongBinding)

    for (const candidate of candidates) {
      adapter.deleteWorkingCopyCapture.mockResolvedValueOnce(candidate)
      await expect(service.delete('daytona-org-1', 'sandbox-1', identity)).rejects.toBeInstanceOf(ConflictException)
    }
  })

  it('returns exact absent, partial and complete existence observations with the complete receipt', async () => {
    const identity = validIdentity(validBinding())
    const absent = validExistsResponse(identity, 'absent')
    const partial = validExistsResponse(identity, 'partial')
    const complete = validExistsResponse(identity, 'complete')
    ;(sandboxService.findOneByIdOrName as jest.Mock).mockResolvedValue({
      ...validSandbox(),
      state: SandboxState.STARTED,
    })
    adapter.workingCopyCaptureExists
      .mockResolvedValueOnce(absent)
      .mockResolvedValueOnce(partial)
      .mockResolvedValueOnce(complete)

    await expect(service.exists('daytona-org-1', 'sandbox-1', identity)).resolves.toEqual(absent)
    await expect(service.exists('daytona-org-1', 'sandbox-1', identity)).resolves.toEqual(partial)
    await expect(service.exists('daytona-org-1', 'sandbox-1', identity)).resolves.toEqual(complete)
    expect(complete).toMatchObject({ exists: true, receipt: validReceipt(validBinding()), status: 'complete' })
  })

  it('rejects existence observations with shape, status, existence, receipt identity or binding drift', async () => {
    const identity = validIdentity(validBinding())
    const candidates: Array<WorkingCopyCaptureExistsResponseDto & Record<string, unknown>> = []

    const inconsistentAbsent = validExistsResponse(identity, 'absent')
    inconsistentAbsent.exists = true
    candidates.push(inconsistentAbsent)

    const inconsistentPartial = validExistsResponse(identity, 'partial')
    inconsistentPartial.exists = false
    candidates.push(inconsistentPartial)

    const completeWithoutReceipt = validExistsResponse(identity, 'complete')
    delete completeWithoutReceipt.receipt
    candidates.push(completeWithoutReceipt)

    const absentWithReceipt = validExistsResponse(identity, 'absent')
    absentWithReceipt.receipt = validReceipt(validBinding())
    candidates.push(absentWithReceipt)

    const wrongGeneration = validExistsResponse(identity, 'complete')
    ;(wrongGeneration.receipt as WorkingCopyCaptureReceiptDto).providerResourceId =
      `daytona-working-copy-capture:v2:sha256:${'d'.repeat(64)}`
    candidates.push(wrongGeneration)

    const wrongBinding = validExistsResponse(identity, 'complete')
    ;(wrongBinding.receipt as WorkingCopyCaptureReceiptDto).owner.workingCopyId = OTHER_ID
    candidates.push(wrongBinding)

    const extra = validExistsResponse(identity, 'partial') as WorkingCopyCaptureExistsResponseDto &
      Record<string, unknown>
    extra.observedAt = '2026-08-23T12:34:56Z'
    candidates.push(extra)

    const unknownStatus = validExistsResponse(identity, 'partial') as WorkingCopyCaptureExistsResponseDto &
      Record<string, unknown>
    unknownStatus.status = 'unknown' as never
    candidates.push(unknownStatus)

    for (const candidate of candidates) {
      adapter.workingCopyCaptureExists.mockResolvedValueOnce(candidate)
      await expect(service.exists('daytona-org-1', 'sandbox-1', identity)).rejects.toBeInstanceOf(ConflictException)
    }
  })

  it('maps all runner contract statuses, preserves 503 outcome-unknown detail and hides unknown transport failures', async () => {
    const binding = validBinding()
    const mapped = [
      [400, BadRequestException, 'invalid capture authority', 'capture_invalid'],
      [404, NotFoundException, 'capture is absent', 'capture_absent'],
      [409, ConflictException, 'capture conflicts with another generation', 'capture_conflict'],
      [503, ServiceUnavailableException, 'capture outcome is unknown; observe before retrying', 'outcome_unknown'],
    ] as const

    for (const [status, Exception, message, code] of mapped) {
      adapter.captureWorkingCopy.mockRejectedValueOnce(new RunnerApiError(message, status, code))
      await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).rejects.toBeInstanceOf(Exception)
      adapter.captureWorkingCopy.mockRejectedValueOnce(new RunnerApiError(message, status, code))
      await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).rejects.toMatchObject({
        response: expect.objectContaining({ message, statusCode: status }),
      })
    }

    adapter.captureWorkingCopy.mockRejectedValueOnce(new RunnerApiError('wire failure', 502, 'bad_gateway'))
    await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).rejects.toMatchObject({
      response: expect.objectContaining({
        message: 'The sandbox runner could not complete working-copy capture.',
        statusCode: 503,
      }),
    })
  })
})

function validBinding(): WorkingCopyCaptureBindingDto {
  const protocolDigest = `sha256:${'7'.repeat(64)}`
  const helperDigest = `sha256:${'8'.repeat(64)}`
  const lineageRef = 'ambit.runtime-lineage/full-image-runtime-pack@5'
  const preimage = ['ambit.working-copy-capture-authority/v2', lineageRef].join('\n')
  return {
    providerName: 'ambit-private-working-copy-capture',
    requestFingerprint: 'a'.repeat(64),
    authority: {
      authorityRef: `ambit.working-copy-capture-authority:v2:sha256:${createHash('sha256')
        .update(preimage, 'utf8')
        .digest('hex')}`,
      lineageRef,
      roleRef: 'ambit.runtime-component/working-copy-capture@2',
      protocol: {
        ref: 'ambit.runtime-interface/working-copy-capture@2',
        digest: protocolDigest,
      },
      helper: {
        ref: `runtime-component-artifact:${helperDigest}`,
        digest: helperDigest,
      },
    },
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
    stopAuthority: {
      operationId: '77777777-7777-4777-8777-777777777777',
      receiptRef: `ambit.stopped-generation-receipt:v1:sha256:${'9'.repeat(64)}`,
      receiptDigest: `sha256:${'9'.repeat(64)}`,
      terminalGeneration: {
        containerId: 'd'.repeat(64),
        containerCreatedAt: '2026-08-23T23:59:00Z',
        executionStartedAt: '2026-08-24T00:00:00Z',
        restartCount: 0,
        executionFinishedAt: '2026-08-24T00:01:00Z',
        exitCode: 0,
        oomKilled: false,
      },
      fence: {
        workspaceExecutionManifestRef: 'ambit.workspace-execution-manifest/example@1',
      },
    },
    selector: {
      semanticZoneRef: 'ambit.workspace-zone/work@1',
      zoneRelativePath: 'report.txt',
    },
  }
}

function exactBinding(binding: WorkingCopyCaptureBindingDto): WorkingCopyCaptureBindingDto {
  return {
    providerName: binding.providerName,
    requestFingerprint: binding.requestFingerprint,
    authority: structuredClone(binding.authority),
    source: structuredClone(binding.source),
    owner: structuredClone(binding.owner),
    stopAuthority: structuredClone(binding.stopAuthority),
    selector: structuredClone(binding.selector),
  }
}

function validIdentity(
  binding: WorkingCopyCaptureBindingDto,
  providerResourceId = CAPTURE_ID,
): WorkingCopyCaptureIdentityDto {
  return {
    ...exactBinding(binding),
    providerResourceId,
  }
}

function validReceipt(
  binding: WorkingCopyCaptureBindingDto,
  providerResourceId = CAPTURE_ID,
): WorkingCopyCaptureReceiptDto {
  return {
    ...validIdentity(binding, providerResourceId),
    totalByteLength: 5,
    providerSha256Digest: CAPTURE_DIGEST,
    capturedAt: '2026-08-23T12:34:56.123456789Z',
  }
}

function validRead(
  overrides: Partial<Pick<WorkingCopyCaptureReadDto, 'expectedTotalByteLength' | 'maximumBytes' | 'offset'>> = {},
): WorkingCopyCaptureReadDto {
  return {
    ...validIdentity(validBinding()),
    expectedTotalByteLength: 5,
    expectedProviderSha256Digest: CAPTURE_DIGEST,
    offset: 0,
    maximumBytes: 5,
    ...overrides,
  }
}

function validReadResponse(request: WorkingCopyCaptureReadDto, bytes: string): WorkingCopyCaptureReadResponseDto {
  const expectedRangeLength = Math.min(request.maximumBytes, request.expectedTotalByteLength - request.offset)
  if (Buffer.byteLength(bytes) !== expectedRangeLength) {
    throw new Error('test fixture bytes do not match the requested range')
  }
  return {
    ...validIdentity(request, request.providerResourceId),
    totalByteLength: request.expectedTotalByteLength,
    providerSha256Digest: request.expectedProviderSha256Digest,
    offset: request.offset,
    byteLength: expectedRangeLength,
    eof: request.offset + expectedRangeLength === request.expectedTotalByteLength,
    bytesBase64: Buffer.from(bytes).toString('base64'),
  }
}

function validDeleteReceipt(
  identity: WorkingCopyCaptureIdentityDto,
  outcome: WorkingCopyCaptureDeleteReceiptDto['outcome'],
): WorkingCopyCaptureDeleteReceiptDto {
  return {
    ...validIdentity(identity, identity.providerResourceId),
    outcome,
  }
}

function validExistsResponse(
  identity: WorkingCopyCaptureIdentityDto,
  status: WorkingCopyCaptureExistsResponseDto['status'],
): WorkingCopyCaptureExistsResponseDto & Record<string, unknown> {
  const response: WorkingCopyCaptureExistsResponseDto & Record<string, unknown> = {
    ...validIdentity(identity, identity.providerResourceId),
    status,
    exists: status !== 'absent',
  }
  if (status === 'complete') {
    response.receipt = validReceipt(exactBinding(identity), identity.providerResourceId)
  }
  return response
}

function validSandbox() {
  return {
    id: 'sandbox-1',
    organizationId: 'daytona-org-1',
    runnerId: 'runner-1' as string | undefined,
    sandboxClass: SandboxClass.CONTAINER,
    state: SandboxState.STOPPED,
    labels: {
      ambitWorkspaceId: WORKSPACE_ID,
      ambitTenantId: TENANT_ID,
      ambitPrincipalId: USER_ID,
      ambitTaskId: RUN_ID,
      ambitGrantId: GRANT_ID,
      ambitProfile: 'managed-container',
      ambitWorkspaceExecutionManifestRef: 'ambit.workspace-execution-manifest/example@1',
      ambitRuntimeKind: 'full_image_runtime_pack_provider_observation',
      ambitRuntimeWorkspaceId: WORKSPACE_ID,
      ambitRuntimeManifestRef: 'ambit.workspace-execution-manifest/example@1',
      ambitRuntimeProductRunId: RUN_ID,
      ambitRuntimeGrantId: GRANT_ID,
    },
  }
}
