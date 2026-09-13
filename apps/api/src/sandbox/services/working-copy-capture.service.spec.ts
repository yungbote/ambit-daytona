/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { plainToInstance } from 'class-transformer'
import { validateSync } from 'class-validator'
import { Configuration, SandboxApiAxiosParamCreator } from '@daytona/runner-api-client'
import {
  Configuration as HostConfiguration,
  SandboxApiAxiosParamCreator as HostSandboxApiAxiosParamCreator,
} from '@daytona/api-client'
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common'

import {
  MAXIMUM_WORKING_COPY_CAPTURE_BYTES,
  MAXIMUM_USER_FILE_CAPTURE_BYTES,
  MAXIMUM_USER_FILE_READ_BYTES,
  USER_FILES_SEMANTIC_ZONE_REF,
  MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES,
  MAXIMUM_WORKING_COPY_ROSTER_AGGREGATE_BYTES,
  MAXIMUM_WORKING_COPY_ROSTER_DEPTH,
  MAXIMUM_WORKING_COPY_ROSTER_ENTRIES,
  MAXIMUM_WORKING_COPY_ROSTER_FILE_BYTES,
  StoppedWorkingCopyDirectoryRosterReceiptDto,
  StoppedWorkingCopyDirectoryRosterRequestDto,
  WorkingCopyCaptureBindingDto,
  WorkingCopyCaptureCapabilitiesRequestDto,
  WorkingCopyCaptureCapabilitiesDto,
  WorkingTreeInventoryRequestDto,
  WorkingTreeInventoryReceiptDto,
  WorkingTreeInventoryPageRequestDto,
  WorkingTreeInventoryPageDto,
  WorkingTreeInventoryRangeRequestDto,
  WorkingTreeInventoryRangeDto,
  MAXIMUM_WORKING_TREE_INVENTORY_PAGE_BYTES,
  MAXIMUM_WORKING_TREE_INVENTORY_PAGE_ENTRIES,
  MAXIMUM_WORKING_TREE_INVENTORY_INDEX_BYTES,
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
      workingCopyCaptureCapabilities: jest.fn(),
      stoppedWorkingCopyDirectoryRoster: jest.fn(),
      prepareWorkingTreeInventory: jest.fn(),
      readWorkingTreeInventoryPage: jest.fn(),
      readWorkingTreeInventoryRange: jest.fn(),
      deleteWorkingTreeInventory: jest.fn(),
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

  it('routes exact file snapshot capture and replay without minting stopped-generation authority', async () => {
    const binding = liveFileBinding()
    const receipt = validReceipt(binding)
    adapter.captureWorkingCopy.mockResolvedValue(receipt)
    adapter.observeWorkingCopyCapture.mockResolvedValue({ status: 'complete', receipt })
    await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).resolves.toEqual(receipt)
    await expect(service.observe('daytona-org-1', 'sandbox-1', binding)).resolves.toEqual({
      status: 'complete',
      receipt,
    })
    expect(adapter.captureWorkingCopy.mock.calls[0][1]).not.toHaveProperty('stopAuthority')
    expect(validateSync(plainToInstance(WorkingCopyCaptureBindingDto, binding))).toEqual([])
  })

  it.each(['both', 'neither', 'wrong_contract', 'wrong_fence', 'generation_extra', 'generation_missing'])(
    'rejects %s file snapshot authority before dispatch',
    async (scenario) => {
      const binding = liveFileBinding()
      if (scenario === 'both') binding.stopAuthority = validBinding().stopAuthority
      if (scenario === 'neither') delete binding.fileSnapshot
      if (scenario === 'wrong_contract') Object.assign(binding.fileSnapshot, { contract: 'other' })
      if (scenario === 'wrong_fence') binding.fileSnapshot.fence.workspaceExecutionManifestRef = 'other'
      if (scenario === 'generation_extra') Object.assign(binding.fileSnapshot.generation, { exitCode: 0 })
      if (scenario === 'generation_missing')
        delete (binding.fileSnapshot.generation as Partial<typeof binding.fileSnapshot.generation>).containerId
      await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).rejects.toThrow()
      expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
    },
  )

  it('forwards advertised native file snapshot capability and rejects a substituted contract', async () => {
    const request = capabilityRequest()
    const response = {
      ...capabilities(request),
      fileSnapshot: { contract: 'ambit.working-copy-file-snapshot/v1' as const, maximumBytes: 1024 * 1024 * 1024 },
    }
    adapter.workingCopyCaptureCapabilities.mockResolvedValue(response)
    await expect(service.capabilities('daytona-org-1', 'sandbox-1', request)).resolves.toEqual(response)
    Object.assign(response.fileSnapshot, { contract: 'unsupported' })
    await expect(service.capabilities('daytona-org-1', 'sandbox-1', request)).rejects.toThrow(ConflictException)
  })

  function capabilityRequest(): WorkingCopyCaptureCapabilitiesRequestDto {
    const binding = validBinding()
    return {
      source: binding.source,
      owner: binding.owner,
      fence: binding.stopAuthority.fence,
      authority: binding.authority,
    }
  }

  function capabilities(request: WorkingCopyCaptureCapabilitiesRequestDto): WorkingCopyCaptureCapabilitiesDto {
    return {
      authority: request.authority,
      stoppedWorkingTreeInventory: {
        contract: 'ambit.working-copy-stopped-working-tree-inventory/v1',
        semanticZoneRef: USER_FILES_SEMANTIC_ZONE_REF,
        maximumDepth: 64,
        maximumPageEntries: MAXIMUM_WORKING_TREE_INVENTORY_PAGE_ENTRIES,
        maximumFileBytes: MAXIMUM_USER_FILE_CAPTURE_BYTES,
        maximumAggregateBytes: 8 * 1024 * 1024 * 1024,
        maximumReadBytes: MAXIMUM_USER_FILE_READ_BYTES,
        maximumIndexBytes: MAXIMUM_WORKING_TREE_INVENTORY_INDEX_BYTES,
        maximumPageBytes: MAXIMUM_WORKING_TREE_INVENTORY_PAGE_BYTES,
      },
    }
  }

  it('discovers the assigned Runner without a stopped generation or capture write', async () => {
    const request = capabilityRequest()
    const response = capabilities(request)
    const signal = new AbortController().signal
    adapter.workingCopyCaptureCapabilities.mockResolvedValue(response)
    await expect(service.capabilities('daytona-org-1', 'friendly-name', request, signal)).resolves.toEqual(response)
    expect(adapter.workingCopyCaptureCapabilities).toHaveBeenCalledWith('sandbox-1', request, signal)
    expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
    expect(adapter.prepareWorkingTreeInventory).not.toHaveBeenCalled()
    expect(validateSync(plainToInstance(WorkingCopyCaptureCapabilitiesRequestDto, request))).toEqual([])
    expect(validateSync(plainToInstance(WorkingCopyCaptureCapabilitiesDto, response))).toEqual([])
    const wire = await SandboxApiAxiosParamCreator(
      new Configuration({ apiKey: 'Bearer token' }),
    ).workingCopyCaptureCapabilities('sandbox-1', request, { signal })
    expect(wire.url).toBe('/sandboxes/sandbox-1/working-copy-captures/capabilities')
    expect(JSON.parse(wire.options.data as string)).toEqual(request)
    expect(wire.options.signal).toBe(signal)
  })

  it('preserves old Runner 404 as an unavailable discovery without writing or stopping', async () => {
    adapter.workingCopyCaptureCapabilities.mockRejectedValue(new RunnerApiError('route unavailable', 404))
    await expect(service.capabilities('daytona-org-1', 'sandbox-1', capabilityRequest())).rejects.toBeInstanceOf(
      NotFoundException,
    )
    expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
  })

  it('rejects foreign owners before contacting the Runner', async () => {
    const request = capabilityRequest()
    request.owner.tenantId = OTHER_ID
    await expect(service.capabilities('daytona-org-1', 'sandbox-1', request)).rejects.toBeInstanceOf(ForbiddenException)
    expect(adapter.workingCopyCaptureCapabilities).not.toHaveBeenCalled()
  })

  it('rejects substituted or malformed helper advertisements', async () => {
    const request = capabilityRequest()
    for (const mutate of [
      (r: WorkingCopyCaptureCapabilitiesDto) => {
        r.authority = { ...r.authority, lineageRef: 'other' }
      },
      (r: WorkingCopyCaptureCapabilitiesDto) => {
        r.stoppedWorkingTreeInventory!.maximumFileBytes = 1.5
      },
      (r: WorkingCopyCaptureCapabilitiesDto) => {
        Object.assign(r, { unexpected: true })
      },
    ]) {
      const response = capabilities(request)
      mutate(response)
      adapter.workingCopyCaptureCapabilities.mockResolvedValue(response)
      await expect(service.capabilities('daytona-org-1', 'sandbox-1', request)).rejects.toBeInstanceOf(
        ConflictException,
      )
    }
  })

  it.each(['capture', 'read'] as const)('propagates %s cancellation to the assigned Runner', async (operation) => {
    const controller = new AbortController()
    const reason = new Error('caller canceled')
    let dispatch: () => void
    const dispatched = new Promise<void>((resolve) => {
      dispatch = resolve
    })
    const pendingRunner = (_sandbox: string, _request: unknown, signal?: AbortSignal) =>
      new Promise<never>((_resolve, reject) => {
        expect(signal).toBe(controller.signal)
        signal?.addEventListener('abort', () => reject(signal.reason), { once: true })
        dispatch()
      })
    adapter.captureWorkingCopy.mockImplementation(pendingRunner)
    adapter.readWorkingCopyCapture.mockImplementation(pendingRunner)
    const pending =
      operation === 'capture'
        ? service.capture('daytona-org-1', 'sandbox-1', validBinding(), controller.signal)
        : service.read('daytona-org-1', 'sandbox-1', validRead(), controller.signal)
    await dispatched
    controller.abort(reason)
    await expect(pending).rejects.toBe(reason)
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
    expect(adapter.captureWorkingCopy).toHaveBeenCalledWith('sandbox-1', binding, undefined)
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

  it('fails closed on runtime manifest, runtime class, runner and direct-address drift', async () => {
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

  it('uses the runner stop receipt rather than stale host lifecycle projection as capture authority', async () => {
    const sandbox = validSandbox()
    sandbox.state = SandboxState.STARTED
    ;(sandboxService.findOneByIdOrName as jest.Mock).mockResolvedValueOnce(sandbox)
    const binding = validBinding()
    const receipt = validReceipt(binding)
    adapter.captureWorkingCopy.mockResolvedValue(receipt)

    await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).resolves.toEqual(receipt)
    expect(adapter.captureWorkingCopy).toHaveBeenCalledWith('sandbox-1', binding, undefined)
  })

  it('forwards and re-proves an exact bounded stopped-generation directory roster', async () => {
    const request = validRosterRequest()
    const receipt = validRosterReceipt(request)
    const signal = new AbortController().signal
    adapter.stoppedWorkingCopyDirectoryRoster.mockResolvedValue(receipt)

    await expect(service.stoppedDirectoryRoster('daytona-org-1', 'friendly-name', request, signal)).resolves.toEqual(
      receipt,
    )

    expect(sandboxService.findOneByIdOrName).toHaveBeenCalledWith('friendly-name', 'daytona-org-1')
    expect(adapter.stoppedWorkingCopyDirectoryRoster).toHaveBeenCalledWith('sandbox-1', request, signal)
    expect(receipt.entries).toEqual([
      {
        zoneRelativePath: 'site/assets',
        name: 'assets',
        kind: 'directory',
        size: 0,
        mode: null,
        sha256: null,
      },
      {
        zoneRelativePath: 'site/assets/app.js',
        name: 'app.js',
        kind: 'regular_file',
        size: 5,
        mode: '0644',
        sha256: `sha256:${'1'.repeat(64)}`,
      },
      {
        zoneRelativePath: 'site/index.html',
        name: 'index.html',
        kind: 'regular_file',
        size: 13,
        mode: '0644',
        sha256: `sha256:${'2'.repeat(64)}`,
      },
    ])
  })

  it('validates roster paths in portable UTF-8 byte order rather than JavaScript UTF-16 order', async () => {
    const request = validRosterRequest()
    const receipt = validRosterReceipt(request)
    receipt.entries = [
      {
        zoneRelativePath: 'site/index.html',
        name: 'index.html',
        kind: 'regular_file',
        size: 13,
        mode: '0644',
        sha256: `sha256:${'2'.repeat(64)}`,
      },
      {
        zoneRelativePath: 'site/\uE000.js',
        name: '\uE000.js',
        kind: 'regular_file',
        size: 1,
        mode: '0644',
        sha256: `sha256:${'3'.repeat(64)}`,
      },
      {
        zoneRelativePath: 'site/😀.js',
        name: '😀.js',
        kind: 'regular_file',
        size: 1,
        mode: '0644',
        sha256: `sha256:${'4'.repeat(64)}`,
      },
    ]
    receipt.rosterDigest = rosterDigest(receipt.request, receipt.terminalGeneration, receipt.entries)
    adapter.stoppedWorkingCopyDirectoryRoster.mockResolvedValueOnce(receipt)

    await expect(service.stoppedDirectoryRoster('daytona-org-1', 'sandbox-1', request)).resolves.toEqual(receipt)

    const utf16Ordered = structuredClone(receipt)
    ;[utf16Ordered.entries[1], utf16Ordered.entries[2]] = [utf16Ordered.entries[2], utf16Ordered.entries[1]]
    utf16Ordered.rosterDigest = rosterDigest(
      utf16Ordered.request,
      utf16Ordered.terminalGeneration,
      utf16Ordered.entries,
    )
    adapter.stoppedWorkingCopyDirectoryRoster.mockResolvedValueOnce(utf16Ordered)
    await expect(service.stoppedDirectoryRoster('daytona-org-1', 'sandbox-1', request)).rejects.toBeInstanceOf(
      ConflictException,
    )
  })

  it('rejects invalid stopped-directory roster authority and bounds before lookup', async () => {
    const candidates: StoppedWorkingCopyDirectoryRosterRequestDto[] = []
    for (const mutate of [
      (request: StoppedWorkingCopyDirectoryRosterRequestDto) =>
        (request.selector.semanticZoneRef = 'ambit.workspace-zone/outputs@1'),
      (request: StoppedWorkingCopyDirectoryRosterRequestDto) => (request.selector.zoneRelativePath = '../site'),
      (request: StoppedWorkingCopyDirectoryRosterRequestDto) => (request.selector.zoneRelativePath = 'other'),
      (request: StoppedWorkingCopyDirectoryRosterRequestDto) => (request.maximumDepth = 0),
      (request: StoppedWorkingCopyDirectoryRosterRequestDto) =>
        (request.maximumDepth = MAXIMUM_WORKING_COPY_ROSTER_DEPTH + 1),
      (request: StoppedWorkingCopyDirectoryRosterRequestDto) => (request.maximumEntries = 0),
      (request: StoppedWorkingCopyDirectoryRosterRequestDto) =>
        (request.maximumEntries = MAXIMUM_WORKING_COPY_ROSTER_ENTRIES + 1),
      (request: StoppedWorkingCopyDirectoryRosterRequestDto) => (request.maximumFileBytes = 0),
      (request: StoppedWorkingCopyDirectoryRosterRequestDto) =>
        (request.maximumFileBytes = MAXIMUM_WORKING_COPY_ROSTER_FILE_BYTES + 1),
      (request: StoppedWorkingCopyDirectoryRosterRequestDto) =>
        (request.maximumAggregateBytes = request.maximumFileBytes - 1),
      (request: StoppedWorkingCopyDirectoryRosterRequestDto) =>
        (request.maximumAggregateBytes = MAXIMUM_WORKING_COPY_ROSTER_AGGREGATE_BYTES + 1),
    ]) {
      const request = validRosterRequest()
      mutate(request)
      candidates.push(request)
    }
    const extra = validRosterRequest() as StoppedWorkingCopyDirectoryRosterRequestDto & { absolutePath: string }
    extra.absolutePath = '/workspace'
    candidates.push(extra)

    for (const candidate of candidates) {
      await expect(service.stoppedDirectoryRoster('daytona-org-1', 'sandbox-1', candidate)).rejects.toBeInstanceOf(
        BadRequestException,
      )
    }
    expect(sandboxService.findOneByIdOrName).not.toHaveBeenCalled()
    expect(adapter.stoppedWorkingCopyDirectoryRoster).not.toHaveBeenCalled()
  })

  it('rejects stopped-directory roster response drift in shape, request, generation, entries, bounds, digest or time', async () => {
    const request = validRosterRequest()
    const mutations: Array<(receipt: StoppedWorkingCopyDirectoryRosterReceiptDto & Record<string, unknown>) => void> = [
      (receipt) => {
        receipt.extra = true
      },
      (receipt) => {
        receipt.request.maximumDepth -= 1
      },
      (receipt) => {
        receipt.terminalGeneration.containerId = 'e'.repeat(64)
      },
      (receipt) => {
        receipt.entries.reverse()
      },
      (receipt) => {
        receipt.entries[0].zoneRelativePath = 'site'
      },
      (receipt) => {
        receipt.entries[0].name = 'wrong'
      },
      (receipt) => {
        receipt.entries[0].kind = 'regular_file'
        receipt.entries[0].size = request.maximumFileBytes + 1
      },
      (receipt) => {
        receipt.entries[0].mode = 'not-a-mode'
      },
      (receipt) => {
        receipt.entries[0].sha256 = `sha256:${'5'.repeat(64)}`
      },
      (receipt) => {
        receipt.entries[1].sha256 = 'sha256:wrong'
      },
      (receipt) => {
        receipt.entries = receipt.entries.filter(
          (entry) => entry.zoneRelativePath !== request.anchor.selector.zoneRelativePath,
        )
        receipt.rosterDigest = rosterDigest(receipt.request, receipt.terminalGeneration, receipt.entries)
      },
      (receipt) => {
        receipt.rosterDigest = `sha256:${'f'.repeat(64)}`
      },
      (receipt) => {
        receipt.observedAt = '2026-08-25T12:34:56Z'
      },
      (receipt) => {
        receipt.observedAt = '2026-02-31T12:34:56.789Z'
      },
    ]

    for (const mutate of mutations) {
      const receipt = validRosterReceipt(request) as StoppedWorkingCopyDirectoryRosterReceiptDto &
        Record<string, unknown>
      mutate(receipt)
      adapter.stoppedWorkingCopyDirectoryRoster.mockResolvedValueOnce(receipt)
      await expect(service.stoppedDirectoryRoster('daytona-org-1', 'sandbox-1', request)).rejects.toBeInstanceOf(
        ConflictException,
      )
    }
  })

  it('rejects an unadmitted runtime kind before sandbox lookup', async () => {
    const binding = validBinding()
    ;(binding.source as { expectedRuntimeKind: string }).expectedRuntimeKind = 'container'

    await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).rejects.toBeInstanceOf(BadRequestException)
    expect(sandboxService.findOneByIdOrName).not.toHaveBeenCalled()
  })

  it('classifies provider receipts outside exact shape, binding, length, digest, identity or time as outcome unknown', async () => {
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
      await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).rejects.toMatchObject({
        response: expect.objectContaining({
          code: 'WORKING_COPY_CAPTURE_OUTCOME_UNKNOWN',
          statusCode: 503,
        }),
      })
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
    expect(adapter.readWorkingCopyCapture).toHaveBeenLastCalledWith('sandbox-1', middle, undefined)

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

  it('classifies deletion receipts with non-exact shape, outcome, identity or binding as outcome unknown', async () => {
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
      await expect(service.delete('daytona-org-1', 'sandbox-1', identity)).rejects.toMatchObject({
        response: expect.objectContaining({
          code: 'WORKING_COPY_CAPTURE_OUTCOME_UNKNOWN',
          statusCode: 503,
        }),
      })
    }
  })

  it('classifies blank mutation responses as outcome unknown instead of a contract conflict', async () => {
    const binding = validBinding()
    const identity = validIdentity(binding)
    adapter.captureWorkingCopy.mockResolvedValueOnce(undefined as never)
    adapter.deleteWorkingCopyCapture.mockResolvedValueOnce(undefined as never)

    for (const operation of [
      () => service.capture('daytona-org-1', 'sandbox-1', binding),
      () => service.delete('daytona-org-1', 'sandbox-1', identity),
    ]) {
      await expect(operation()).rejects.toMatchObject({
        response: expect.objectContaining({
          code: 'WORKING_COPY_CAPTURE_OUTCOME_UNKNOWN',
          statusCode: 503,
        }),
      })
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

  it('maps runner statuses and treats response-less mutation transport as outcome unknown', async () => {
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

    const identity = validIdentity(binding)
    for (const invoke of [
      () => {
        adapter.captureWorkingCopy.mockRejectedValueOnce(new RunnerApiError('wire failure', undefined, 'ECONNRESET'))
        return service.capture('daytona-org-1', 'sandbox-1', binding)
      },
      () => {
        adapter.deleteWorkingCopyCapture.mockRejectedValueOnce(new RunnerApiError('wire failure', 502, 'bad_gateway'))
        return service.delete('daytona-org-1', 'sandbox-1', identity)
      },
    ]) {
      await expect(invoke()).rejects.toMatchObject({
        response: expect.objectContaining({
          code: 'WORKING_COPY_CAPTURE_OUTCOME_UNKNOWN',
          message: 'Working-copy capture outcome is unknown; observe the exact operation before retrying.',
          statusCode: 503,
        }),
      })
    }

    adapter.observeWorkingCopyCapture.mockRejectedValueOnce(new RunnerApiError('wire failure', 502, 'bad_gateway'))
    await expect(service.observe('daytona-org-1', 'sandbox-1', binding)).rejects.toMatchObject({
      response: expect.objectContaining({
        message:
          'The sandbox runner could not complete working-copy capture (runner status 502 code bad_gateway: wire failure).',
        statusCode: 503,
        code: 'WORKING_COPY_CAPTURE_UNAVAILABLE',
      }),
    })
  })

  function inventoryFixture(): { receipt: WorkingTreeInventoryReceiptDto; pages: WorkingTreeInventoryPageDto[] } {
    const fixture = JSON.parse(
      readFileSync(
        resolve(__dirname, '../../../../runner/pkg/workingcopy/testdata/stopped-working-tree-inventory.canonical.json'),
        'utf8',
      ),
    ) as { receipt: WorkingTreeInventoryReceiptDto; pages: WorkingTreeInventoryPageDto[] }
    const sandbox = validSandbox()
    sandbox.labels.ambitWorkspaceExecutionManifestRef =
      fixture.receipt.request.generation.stopAuthority.fence.workspaceExecutionManifestRef
    sandbox.labels.ambitRuntimeManifestRef = sandbox.labels.ambitWorkspaceExecutionManifestRef
    ;(sandboxService.findOneByIdOrName as jest.Mock).mockResolvedValue(sandbox)
    return fixture
  }

  it('admits the complete cross-language inventory and each bounded lexical page', async () => {
    const { receipt, pages } = inventoryFixture()
    const signal = new AbortController().signal
    adapter.prepareWorkingTreeInventory.mockResolvedValue(receipt)
    await expect(service.prepareInventory('daytona-org-1', 'friendly-name', receipt.request, signal)).resolves.toEqual(
      receipt,
    )
    expect(adapter.prepareWorkingTreeInventory).toHaveBeenCalledWith('sandbox-1', receipt.request, signal)
    expect(validateSync(plainToInstance(WorkingTreeInventoryRequestDto, receipt.request))).toEqual([])
    expect(validateSync(plainToInstance(WorkingTreeInventoryReceiptDto, receipt))).toEqual([])
    for (const page of pages) {
      const request = {
        request: receipt.request,
        providerResourceId: receipt.providerResourceId,
        pageIndex: page.pageIndex,
      }
      adapter.readWorkingTreeInventoryPage.mockResolvedValueOnce(page)
      await expect(service.readInventoryPage('daytona-org-1', 'friendly-name', request, signal)).resolves.toEqual(page)
      expect(adapter.readWorkingTreeInventoryPage).toHaveBeenLastCalledWith('sandbox-1', request, signal)
      expect(validateSync(plainToInstance(WorkingTreeInventoryPageRequestDto, request))).toEqual([])
      expect(validateSync(plainToInstance(WorkingTreeInventoryPageDto, page))).toEqual([])
    }
    const deletion = {
      request: receipt.request,
      providerResourceId: receipt.providerResourceId,
      status: 'absent' as const,
    }
    adapter.deleteWorkingTreeInventory.mockResolvedValue(deletion)
    await expect(service.deleteInventory('daytona-org-1', 'friendly-name', receipt.request, signal)).resolves.toEqual(
      deletion,
    )
    expect(adapter.deleteWorkingTreeInventory).toHaveBeenCalledWith('sandbox-1', receipt.request, signal)
    expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
  })

  it('uses authenticated generated inventory operations with exact source requests', async () => {
    const { receipt } = inventoryFixture()
    const signal = new AbortController().signal
    const client = SandboxApiAxiosParamCreator(new Configuration({ apiKey: 'Bearer token' }))
    const prepared = await client.prepareWorkingTreeInventory('sandbox/encoded', receipt.request, { signal })
    const pageRequest = { request: receipt.request, providerResourceId: receipt.providerResourceId, pageIndex: 0 }
    const page = await client.readWorkingTreeInventoryPage('sandbox/encoded', pageRequest, { signal })
    const rangeRequest = {
      request: receipt.request,
      providerResourceId: receipt.providerResourceId,
      inventoryDigest: receipt.inventoryDigest,
      offset: 0,
      maximumBytes: MAXIMUM_USER_FILE_READ_BYTES,
    }
    const range = await client.readWorkingTreeInventoryRange('sandbox/encoded', rangeRequest, { signal })
    const deleted = await client.deleteWorkingTreeInventory('sandbox/encoded', receipt.request, { signal })
    expect(prepared.url).toBe('/sandboxes/sandbox%2Fencoded/working-copy-captures/stopped-working-tree-inventories')
    expect(page.url).toBe(prepared.url + '/read')
    expect(range.url).toBe(prepared.url + '/read-range')
    expect(deleted.url).toBe(prepared.url + '/delete')
    expect(JSON.parse(prepared.options.data as string)).toEqual(receipt.request)
    expect(JSON.parse(page.options.data as string)).toEqual(pageRequest)
    expect(page.options.signal).toBe(signal)
    expect(JSON.parse(range.options.data as string)).toEqual(rangeRequest)
    expect(range.options.signal).toBe(signal)
    expect(range.options.headers).toMatchObject({ Authorization: 'Bearer token' })
    expect(prepared.options.headers).toMatchObject({ Authorization: 'Bearer token' })
  })

  function inventoryRangeFixture(): {
    request: WorkingTreeInventoryRangeRequestDto
    response: WorkingTreeInventoryRangeDto
  } {
    const { receipt } = inventoryFixture()
    const request = {
      request: receipt.request,
      providerResourceId: receipt.providerResourceId,
      inventoryDigest: receipt.inventoryDigest,
      offset: 2,
      maximumBytes: 3,
    }
    return {
      request,
      response: {
        providerResourceId: receipt.providerResourceId,
        inventoryDigest: receipt.inventoryDigest,
        offset: 2,
        byteLength: 3,
        totalByteLength: receipt.bytePack.byteLength,
        eof: false,
        bytesBase64: Buffer.from('abc').toString('base64'),
      },
    }
  }

  it('forwards bounded byte reads with owner authorization and exact response validation', async () => {
    const { request, response } = inventoryRangeFixture()
    const signal = new AbortController().signal
    adapter.readWorkingTreeInventoryRange.mockResolvedValue(response)
    await expect(service.readInventoryRange('daytona-org-1', 'friendly-name', request, signal)).resolves.toEqual(
      response,
    )
    expect(adapter.readWorkingTreeInventoryRange).toHaveBeenCalledWith('sandbox-1', request, signal)
    expect(validateSync(plainToInstance(WorkingTreeInventoryRangeRequestDto, request))).toEqual([])
    expect(validateSync(plainToInstance(WorkingTreeInventoryRangeDto, response))).toEqual([])
    request.offset = response.totalByteLength
    const eof = { ...response, offset: request.offset, byteLength: 0, bytesBase64: '', eof: true }
    adapter.readWorkingTreeInventoryRange.mockResolvedValue(eof)
    await expect(service.readInventoryRange('daytona-org-1', 'sandbox-1', request)).resolves.toEqual(eof)
    expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
  })

  it.each([
    [
      'owner',
      (r: WorkingTreeInventoryRangeRequestDto) => {
        r.request.generation.owner.tenantId = OTHER_ID
        r.providerResourceId = `daytona-working-tree-inventory:v1:sha256:${createHash('sha256').update(JSON.stringify(r.request)).digest('hex')}`
      },
      ForbiddenException,
    ],
    [
      'resource',
      (r: WorkingTreeInventoryRangeRequestDto) => {
        r.providerResourceId += 'x'
      },
      BadRequestException,
    ],
    [
      'negative offset',
      (r: WorkingTreeInventoryRangeRequestDto) => {
        r.offset = -1
      },
      BadRequestException,
    ],
    [
      'fractional offset',
      (r: WorkingTreeInventoryRangeRequestDto) => {
        r.offset = 0.5
      },
      BadRequestException,
    ],
    [
      'zero bound',
      (r: WorkingTreeInventoryRangeRequestDto) => {
        r.maximumBytes = 0
      },
      BadRequestException,
    ],
    [
      'oversize bound',
      (r: WorkingTreeInventoryRangeRequestDto) => {
        r.maximumBytes = MAXIMUM_USER_FILE_READ_BYTES + 1
      },
      BadRequestException,
    ],
  ])('rejects an invalid range %s before the Runner', async (_name, mutate, exception) => {
    const { request } = inventoryRangeFixture()
    mutate(request)
    await expect(service.readInventoryRange('daytona-org-1', 'sandbox-1', request)).rejects.toBeInstanceOf(exception)
    expect(adapter.readWorkingTreeInventoryRange).not.toHaveBeenCalled()
  })

  it.each([
    [
      'resource',
      (r: WorkingTreeInventoryRangeDto) => {
        r.providerResourceId += 'x'
      },
    ],
    [
      'digest',
      (r: WorkingTreeInventoryRangeDto) => {
        r.inventoryDigest = `sha256:${'0'.repeat(64)}`
      },
    ],
    [
      'offset',
      (r: WorkingTreeInventoryRangeDto) => {
        r.offset++
      },
    ],
    [
      'size',
      (r: WorkingTreeInventoryRangeDto) => {
        r.byteLength--
      },
    ],
    [
      'total size',
      (r: WorkingTreeInventoryRangeDto) => {
        r.totalByteLength = -1
      },
    ],
    [
      'truncation',
      (r: WorkingTreeInventoryRangeDto) => {
        r.bytesBase64 = 'YQ=='
      },
    ],
    [
      'noncanonical base64',
      (r: WorkingTreeInventoryRangeDto) => {
        r.bytesBase64 += '\n'
      },
    ],
    [
      'EOF',
      (r: WorkingTreeInventoryRangeDto) => {
        r.eof = true
      },
    ],
  ])('rejects a changed Runner range %s', async (_name, mutate) => {
    const { request, response } = inventoryRangeFixture()
    mutate(response)
    adapter.readWorkingTreeInventoryRange.mockResolvedValue(response)
    await expect(service.readInventoryRange('daytona-org-1', 'sandbox-1', request)).rejects.toBeInstanceOf(
      ConflictException,
    )
  })

  it('publishes matching authenticated inventory operations in the host client', async () => {
    const { receipt } = inventoryFixture()
    const { request } = inventoryRangeFixture()
    request.request.generation.stopAuthority.terminalGeneration.executionStartedAt = '2026-08-23T00:01:00.123456789Z'
    const signal = new AbortController().signal
    const client = HostSandboxApiAxiosParamCreator(new HostConfiguration({ accessToken: 'token' }))
    const prepared = await client.sandboxPrepareInventory('sandbox/encoded', receipt.request, 'org', { signal })
    const range = await client.sandboxReadInventoryRange('sandbox/encoded', request, 'org', { signal })
    const deleted = await client.sandboxDeleteInventory('sandbox/encoded', receipt.request, 'org', { signal })
    expect(prepared.url).toBe('/sandbox/sandbox%2Fencoded/working-copy-captures/stopped-working-tree-inventories')
    expect(range.url).toBe(prepared.url + '/read-range')
    expect(deleted.url).toBe(prepared.url + '/delete')
    expect(JSON.parse(range.options.data as string)).toEqual(request)
    expect(range.options.signal).toBe(signal)
    expect(range.options.headers).toMatchObject({ Authorization: 'Bearer token', 'X-Daytona-Organization-ID': 'org' })
  })

  it('rejects foreign inventory owners before contacting a Runner', async () => {
    const { receipt } = inventoryFixture()
    receipt.request.generation.owner.tenantId = OTHER_ID
    await expect(service.prepareInventory('daytona-org-1', 'sandbox-1', receipt.request)).rejects.toBeInstanceOf(
      ForbiddenException,
    )
    expect(adapter.prepareWorkingTreeInventory).not.toHaveBeenCalled()
  })

  it('does not return malformed complete indexes or pages as successful custody', async () => {
    const { receipt, pages } = inventoryFixture()
    adapter.prepareWorkingTreeInventory.mockResolvedValue({ ...receipt, entryCount: receipt.entryCount + 1 })
    await expect(service.prepareInventory('daytona-org-1', 'sandbox-1', receipt.request)).rejects.toBeInstanceOf(
      ConflictException,
    )
    const page = { ...pages[0], pageDigest: `sha256:${'a'.repeat(64)}` }
    adapter.readWorkingTreeInventoryPage.mockResolvedValue(page)
    await expect(
      service.readInventoryPage('daytona-org-1', 'sandbox-1', {
        request: receipt.request,
        providerResourceId: receipt.providerResourceId,
        pageIndex: 0,
      }),
    ).rejects.toBeInstanceOf(ConflictException)
  })

  it('admits private large capture and range bounds while preserving existing zone limits', async () => {
    const binding = validBinding()
    binding.selector = { semanticZoneRef: USER_FILES_SEMANTIC_ZONE_REF, zoneRelativePath: 'customer.bin' }
    const receipt = validReceipt(binding)
    receipt.totalByteLength = MAXIMUM_USER_FILE_CAPTURE_BYTES
    adapter.captureWorkingCopy.mockResolvedValue(receipt)
    await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).resolves.toEqual(receipt)
    expect(validateSync(plainToInstance(WorkingCopyCaptureReceiptDto, receipt))).toEqual([])

    const read = { ...validRead(), ...validIdentity(binding) }
    read.expectedTotalByteLength = receipt.totalByteLength
    read.offset = receipt.totalByteLength - 1
    read.maximumBytes = MAXIMUM_USER_FILE_READ_BYTES
    adapter.readWorkingCopyCapture.mockResolvedValue(validReadResponse(read, 'x'))
    await expect(service.read('daytona-org-1', 'sandbox-1', read)).resolves.toMatchObject({ byteLength: 1, eof: true })
    expect(validateSync(plainToInstance(WorkingCopyCaptureReadDto, read))).toEqual([])

    const bulk = { ...read, offset: 0 }
    adapter.readWorkingCopyCapture.mockResolvedValue(validReadResponse(bulk, 'x'.repeat(MAXIMUM_USER_FILE_READ_BYTES)))
    await expect(service.read('daytona-org-1', 'sandbox-1', bulk)).resolves.toMatchObject({
      byteLength: MAXIMUM_USER_FILE_READ_BYTES,
      eof: false,
    })

    const legacy = validRead()
    legacy.maximumBytes = MAXIMUM_USER_FILE_READ_BYTES
    await expect(service.read('daytona-org-1', 'sandbox-1', legacy)).rejects.toBeInstanceOf(BadRequestException)
    for (const zone of ['ambit.workspace-zone/work@1', 'ambit.workspace-zone/outputs@1'] as const) {
      const prior = validBinding()
      prior.selector.semanticZoneRef = zone
      adapter.captureWorkingCopy.mockResolvedValue({
        ...validReceipt(prior),
        totalByteLength: MAXIMUM_WORKING_COPY_CAPTURE_BYTES + 1,
      })
      await expect(service.capture('daytona-org-1', 'sandbox-1', prior)).rejects.toBeInstanceOf(
        ServiceUnavailableException,
      )
    }
  })

  it('admits private 4096-byte paths and rejects managed runtime selectors before forwarding', async () => {
    const binding = validBinding()
    const relative = Array.from({ length: 12 }, () => 'a'.repeat(200)).join('/') + '/file'
    binding.selector = { semanticZoneRef: USER_FILES_SEMANTIC_ZONE_REF, zoneRelativePath: relative }
    adapter.captureWorkingCopy.mockResolvedValue(validReceipt(binding))
    await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).resolves.toBeDefined()
    adapter.captureWorkingCopy.mockClear()
    for (const relative of ['.ambit', '.ambit/config', '.ambit-skill-python/data', '../outside', 'e\u0301']) {
      binding.selector.zoneRelativePath = relative
      await expect(service.capture('daytona-org-1', 'sandbox-1', binding)).rejects.toBeInstanceOf(BadRequestException)
    }
    expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
    const anchor = validRosterRequest()
    anchor.anchor.selector.semanticZoneRef = USER_FILES_SEMANTIC_ZONE_REF
    anchor.selector.semanticZoneRef = USER_FILES_SEMANTIC_ZONE_REF
    await expect(service.stoppedDirectoryRoster('daytona-org-1', 'sandbox-1', anchor)).rejects.toBeInstanceOf(
      BadRequestException,
    )
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

function liveFileBinding(): WorkingCopyCaptureBindingDto {
  const binding = validBinding()
  const source = binding.stopAuthority
  delete binding.stopAuthority
  binding.fileSnapshot = {
    contract: 'ambit.working-copy-file-snapshot/v1',
    fence: source.fence,
    generation: {
      containerId: source.terminalGeneration.containerId,
      containerCreatedAt: source.terminalGeneration.containerCreatedAt,
      executionStartedAt: source.terminalGeneration.executionStartedAt,
      restartCount: source.terminalGeneration.restartCount,
    },
  }
  return binding
}

function exactBinding(binding: WorkingCopyCaptureBindingDto): WorkingCopyCaptureBindingDto {
  return {
    providerName: binding.providerName,
    requestFingerprint: binding.requestFingerprint,
    authority: structuredClone(binding.authority),
    source: structuredClone(binding.source),
    owner: structuredClone(binding.owner),
    ...(binding.fileSnapshot
      ? { fileSnapshot: structuredClone(binding.fileSnapshot) }
      : { stopAuthority: structuredClone(binding.stopAuthority) }),
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

function validRosterRequest(): StoppedWorkingCopyDirectoryRosterRequestDto {
  const anchor = validBinding()
  anchor.selector.zoneRelativePath = 'site/index.html'
  return {
    anchor,
    selector: {
      semanticZoneRef: 'ambit.workspace-zone/work@1',
      zoneRelativePath: 'site',
    },
    maximumDepth: 8,
    maximumEntries: 64,
    maximumFileBytes: 1024,
    maximumAggregateBytes: 4096,
  }
}

function validRosterReceipt(
  request: StoppedWorkingCopyDirectoryRosterRequestDto,
): StoppedWorkingCopyDirectoryRosterReceiptDto {
  const entries: StoppedWorkingCopyDirectoryRosterReceiptDto['entries'] = [
    {
      zoneRelativePath: 'site/assets',
      name: 'assets',
      kind: 'directory',
      size: 0,
      mode: null,
      sha256: null,
    },
    {
      zoneRelativePath: 'site/assets/app.js',
      name: 'app.js',
      kind: 'regular_file',
      size: 5,
      mode: '0644',
      sha256: `sha256:${'1'.repeat(64)}`,
    },
    {
      zoneRelativePath: 'site/index.html',
      name: 'index.html',
      kind: 'regular_file',
      size: 13,
      mode: '0644',
      sha256: `sha256:${'2'.repeat(64)}`,
    },
  ]
  const exactRequest = structuredClone(request)
  const terminalGeneration = structuredClone(request.anchor.stopAuthority.terminalGeneration)
  return {
    request: exactRequest,
    terminalGeneration,
    entries,
    rosterDigest: rosterDigest(exactRequest, terminalGeneration, entries),
    observedAt: '2026-08-25T12:34:56.789Z',
  }
}

function rosterDigest(
  request: StoppedWorkingCopyDirectoryRosterRequestDto,
  terminalGeneration: StoppedWorkingCopyDirectoryRosterReceiptDto['terminalGeneration'],
  entries: StoppedWorkingCopyDirectoryRosterReceiptDto['entries'],
): string {
  const payload = {
    contract: 'ambit.working-copy-stopped-directory-roster/v1',
    request,
    terminalGeneration,
    entries,
  }
  return `sha256:${createHash('sha256').update(testCanonicalJson(payload), 'utf8').digest('hex')}`
}

function testCanonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean' || typeof value === 'number') {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(testCanonicalJson).join(',')}]`
  return `{${Object.keys(value as object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${testCanonicalJson((value as Record<string, unknown>)[key])}`)
    .join(',')}}`
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
