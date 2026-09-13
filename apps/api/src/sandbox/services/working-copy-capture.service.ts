/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { createHash } from 'node:crypto'
import { toUSVString } from 'node:util'
import { posix as posixPath } from 'node:path'
import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
  Logger,
} from '@nestjs/common'

import {
  MAXIMUM_WORKING_COPY_CAPTURE_BYTES,
  FILE_SNAPSHOT_CONTRACT,
  MAXIMUM_USER_FILE_CAPTURE_BYTES,
  MAXIMUM_USER_FILE_READ_BYTES,
  MAXIMUM_WORKING_TREE_DEPTH,
  MAXIMUM_WORKING_TREE_AGGREGATE_BYTES,
  USER_FILES_SEMANTIC_ZONE_REF,
  WorkingCopyCaptureGenerationDto,
  StoppedWorkingCopyWorkingTreeEntryDto,
  MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES,
  MAXIMUM_WORKING_COPY_ROSTER_AGGREGATE_BYTES,
  MAXIMUM_WORKING_COPY_ROSTER_DEPTH,
  MAXIMUM_WORKING_COPY_ROSTER_ENTRIES,
  MAXIMUM_WORKING_COPY_ROSTER_FILE_BYTES,
  StoppedWorkingCopyDirectoryRosterEntryDto,
  StoppedWorkingCopyDirectoryRosterRequestDto,
  StoppedWorkingCopyDirectoryRosterReceiptDto,
  WorkingCopyCaptureAuthorityDto,
  WorkingCopyCaptureBindingDto,
  MAXIMUM_WORKING_TREE_INVENTORY_PAGE_BYTES,
  MAXIMUM_WORKING_TREE_INVENTORY_PAGE_ENTRIES,
  MAXIMUM_WORKING_TREE_INVENTORY_INDEX_BYTES,
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
} from '../dto/working-copy-capture.dto'
import {
  assertGenerationObservationRequest,
  assertExpectedGeneration,
  assertStopAuthority as assertGenerationStopAuthority,
} from '../dto/sandbox-generation-stop.contract'
import { RunnerApiError } from '../errors/runner-api-error'
import { SandboxExecutionAuthorityService } from './sandbox-execution-authority.service'

const CAPTURE_ROLE_REF = 'ambit.runtime-component/working-copy-capture@2'
const CAPTURE_PROTOCOL_REF = 'ambit.runtime-interface/working-copy-capture@2'

@Injectable()
export class WorkingCopyCaptureService {
  constructor(private readonly executionAuthority: SandboxExecutionAuthorityService) {}

  async capabilities(
    organizationId: string,
    sandboxIdOrName: string,
    request: WorkingCopyCaptureCapabilitiesRequestDto,
    signal?: AbortSignal,
  ): Promise<WorkingCopyCaptureCapabilitiesDto> {
    signal?.throwIfAborted()
    assertExactKeys(
      request,
      ['authority', 'source', 'owner', 'fence'],
      'capture capability request',
      BadRequestException,
    )
    assertAuthority(request.authority)
    try {
      assertGenerationObservationRequest({ source: request.source, owner: request.owner, fence: request.fence })
    } catch {
      throw new BadRequestException('Working-copy capture capability authority is invalid.')
    }
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      request.source,
      request.owner,
      request.fence,
    )
    try {
      const response = await adapter.workingCopyCaptureCapabilities(sandbox.id, request, signal)
      const tree = response.stoppedWorkingTreeInventory
      assertExactKeys(
        response,
        [
          'authority',
          ...(tree !== undefined ? ['stoppedWorkingTreeInventory'] : []),
          ...(response.fileSnapshot !== undefined ? ['fileSnapshot'] : []),
        ],
        'capture capabilities',
        ConflictException,
      )
      if (canonicalJson(response.authority) !== canonicalJson(request.authority))
        throw new ConflictException('Runner capture capabilities name another helper authority.')
      if (tree !== undefined) {
        const bounds = [
          'maximumDepth',
          'maximumFileBytes',
          'maximumAggregateBytes',
          'maximumPageEntries',
          'maximumPageBytes',
          'maximumIndexBytes',
          'maximumReadBytes',
        ] as const
        assertExactKeys(
          tree,
          ['contract', 'semanticZoneRef', ...bounds],
          'working-tree inventory capability',
          ConflictException,
        )
        if (tree.contract !== INVENTORY_CONTRACT || tree.semanticZoneRef !== USER_FILES_SEMANTIC_ZONE_REF)
          throw new ConflictException('Runner working-tree inventory capability contract is unsupported.')
        for (const key of bounds) {
          if (!Number.isSafeInteger(tree[key]) || tree[key] < 1)
            throw new ConflictException('Runner working-tree inventory capability bound is invalid.')
        }
      }
      if (response.fileSnapshot !== undefined) {
        assertExactKeys(
          response.fileSnapshot,
          ['contract', 'maximumBytes'],
          'file snapshot capability',
          ConflictException,
        )
        if (
          response.fileSnapshot.contract !== FILE_SNAPSHOT_CONTRACT ||
          !Number.isSafeInteger(response.fileSnapshot.maximumBytes) ||
          response.fileSnapshot.maximumBytes < 1
        )
          throw new ConflictException('Runner file snapshot capability is invalid.')
      }
      signal?.throwIfAborted()
      return response
    } catch (error) {
      throw translateRunnerCaptureError(error, false)
    }
  }

  async prepareInventory(
    organizationId: string,
    sandboxIdOrName: string,
    request: WorkingTreeInventoryRequestDto,
    signal?: AbortSignal,
  ): Promise<WorkingTreeInventoryReceiptDto> {
    signal?.throwIfAborted()
    assertInventoryRequest(request)
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      request.generation.source,
      request.generation.owner,
      request.generation.stopAuthority.fence,
    )
    try {
      const receipt = await adapter.prepareWorkingTreeInventory(sandbox.id, request, signal)
      assertInventoryReceipt(receipt, request)
      return receipt
    } catch (error) {
      throw translateRunnerCaptureError(error, true)
    }
  }

  async readInventoryPage(
    organizationId: string,
    sandboxIdOrName: string,
    request: WorkingTreeInventoryPageRequestDto,
    signal?: AbortSignal,
  ): Promise<WorkingTreeInventoryPageDto> {
    signal?.throwIfAborted()
    assertExactKeys(
      request,
      ['request', 'providerResourceId', 'pageIndex'],
      'inventory page request',
      BadRequestException,
    )
    assertInventoryRequest(request.request)
    if (
      request.providerResourceId !== inventoryResourceId(request.request) ||
      !Number.isSafeInteger(request.pageIndex) ||
      request.pageIndex < 0
    )
      throw new BadRequestException('Inventory page identity is invalid.')
    const generation = request.request.generation
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      generation.source,
      generation.owner,
      generation.stopAuthority.fence,
    )
    try {
      const page = await adapter.readWorkingTreeInventoryPage(sandbox.id, request, signal)
      assertExactKeys(
        page,
        ['providerResourceId', 'pageIndex', 'entries', 'pageDigest'],
        'inventory page',
        ConflictException,
      )
      if (
        page.providerResourceId !== request.providerResourceId ||
        page.pageIndex !== request.pageIndex ||
        !Array.isArray(page.entries) ||
        page.entries.length < 1 ||
        page.entries.length > request.request.maximumPageEntries
      )
        throw new ConflictException('Runner inventory page identity or count changed.')
      const excluded = new Set(request.request.excludedPaths)
      for (const [index, entry] of page.entries.entries()) {
        assertWorkingTreeEntry(entry, request.request, excluded)
        if (
          index > 0 &&
          compareUtf8Lexicographic(page.entries[index - 1].zoneRelativePath, entry.zoneRelativePath) >= 0
        )
          throw new ConflictException('Runner inventory page is not sorted and unique.')
      }
      const body = canonicalJson(page.entries)
      if (
        Buffer.byteLength(body, 'utf8') > request.request.maximumPageBytes ||
        page.pageDigest !== jsonDigest(page.entries)
      )
        throw new ConflictException('Runner inventory page bytes exceed or differ from their digest.')
      return page
    } catch (error) {
      throw translateRunnerCaptureError(error, false)
    }
  }

  async readInventoryRange(
    organizationId: string,
    sandboxIdOrName: string,
    request: WorkingTreeInventoryRangeRequestDto,
    signal?: AbortSignal,
  ): Promise<WorkingTreeInventoryRangeDto> {
    signal?.throwIfAborted()
    assertExactKeys(
      request,
      ['request', 'providerResourceId', 'inventoryDigest', 'offset', 'maximumBytes'],
      'inventory range request',
      BadRequestException,
    )
    assertInventoryRequest(request.request)
    if (
      request.providerResourceId !== inventoryResourceId(request.request) ||
      typeof request.inventoryDigest !== 'string' ||
      !/^sha256:[0-9a-f]{64}$/.test(request.inventoryDigest) ||
      !Number.isSafeInteger(request.offset) ||
      request.offset < 0 ||
      !Number.isSafeInteger(request.maximumBytes) ||
      request.maximumBytes < 1 ||
      request.maximumBytes > MAXIMUM_USER_FILE_READ_BYTES
    )
      throw new BadRequestException('Inventory byte range is invalid.')
    const generation = request.request.generation
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      generation.source,
      generation.owner,
      generation.stopAuthority.fence,
    )
    try {
      const range = await adapter.readWorkingTreeInventoryRange(sandbox.id, request, signal)
      assertExactKeys(
        range,
        ['providerResourceId', 'inventoryDigest', 'offset', 'byteLength', 'totalByteLength', 'eof', 'bytesBase64'],
        'inventory byte range',
        ConflictException,
      )
      if (
        range.providerResourceId !== request.providerResourceId ||
        range.inventoryDigest !== request.inventoryDigest ||
        range.offset !== request.offset ||
        !Number.isSafeInteger(range.totalByteLength) ||
        range.totalByteLength < request.offset ||
        range.totalByteLength > request.request.maximumAggregateBytes ||
        typeof range.bytesBase64 !== 'string' ||
        !canonicalBase64(range.bytesBase64, request.maximumBytes)
      )
        throw new ConflictException('Runner inventory byte range authority changed.')
      const expected = Math.min(request.maximumBytes, range.totalByteLength - request.offset)
      if (
        range.byteLength !== expected ||
        Buffer.from(range.bytesBase64, 'base64').length !== expected ||
        range.eof !== (request.offset + expected === range.totalByteLength)
      )
        throw new ConflictException('Runner inventory byte range was truncated or changed.')
      return range
    } catch (error) {
      throw translateRunnerCaptureError(error, false)
    }
  }

  async deleteInventory(
    organizationId: string,
    sandboxIdOrName: string,
    request: WorkingTreeInventoryRequestDto,
    signal?: AbortSignal,
  ): Promise<WorkingTreeInventoryDeletionReceiptDto> {
    signal?.throwIfAborted()
    assertInventoryRequest(request)
    const generation = request.generation
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      generation.source,
      generation.owner,
      generation.stopAuthority.fence,
    )
    try {
      const receipt = await adapter.deleteWorkingTreeInventory(sandbox.id, request, signal)
      assertExactKeys(
        receipt,
        ['request', 'providerResourceId', 'status'],
        'inventory deletion receipt',
        ConflictException,
      )
      if (
        receipt.status !== 'absent' ||
        receipt.providerResourceId !== inventoryResourceId(request) ||
        canonicalJson(receipt.request) !== canonicalJson(request)
      )
        throw new ConflictException('Runner did not prove absence of the exact inventory.')
      return receipt
    } catch (error) {
      throw translateRunnerCaptureError(error, true)
    }
  }

  async capture(
    organizationId: string,
    sandboxIdOrName: string,
    binding: WorkingCopyCaptureBindingDto,
    signal?: AbortSignal,
  ): Promise<WorkingCopyCaptureReceiptDto> {
    signal?.throwIfAborted()
    assertBinding(binding)
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      binding.source,
      binding.owner,
      captureFence(binding),
    )
    try {
      const receipt = await adapter.captureWorkingCopy(sandbox.id, binding, signal)
      mutationReceiptGuard(() => assertReceipt(receipt, binding))
      return receipt
    } catch (error) {
      throw translateRunnerCaptureError(error, true)
    }
  }

  async observe(
    organizationId: string,
    sandboxIdOrName: string,
    binding: WorkingCopyCaptureBindingDto,
  ): Promise<WorkingCopyCaptureObservationDto> {
    assertBinding(binding)
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      binding.source,
      binding.owner,
      captureFence(binding),
    )
    try {
      const observation = await adapter.observeWorkingCopyCapture(sandbox.id, binding)
      assertObservation(observation, binding)
      return observation
    } catch (error) {
      throw translateRunnerCaptureError(error, false)
    }
  }

  async read(
    organizationId: string,
    sandboxIdOrName: string,
    request: WorkingCopyCaptureReadDto,
    signal?: AbortSignal,
  ): Promise<WorkingCopyCaptureReadResponseDto> {
    signal?.throwIfAborted()
    assertRead(request)
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      request.source,
      request.owner,
      captureFence(request),
    )
    try {
      const response = await adapter.readWorkingCopyCapture(sandbox.id, request, signal)
      assertExactKeys(
        response,
        [
          'authority',
          'byteLength',
          'bytesBase64',
          'eof',
          'offset',
          'owner',
          'providerName',
          'providerResourceId',
          'providerSha256Digest',
          'requestFingerprint',
          'selector',
          'source',
          captureSourceKey(request),
          'totalByteLength',
        ],
        'capture read response',
        ConflictException,
      )
      assertProviderIdentity(response)
      if (typeof response.bytesBase64 !== 'string' || !canonicalBase64(response.bytesBase64, request.maximumBytes)) {
        throw new ConflictException('Runner returned a non-canonical capture body.')
      }
      const bytes = Buffer.from(response.bytesBase64, 'base64')
      const expectedRangeLength = Math.min(request.maximumBytes, request.expectedTotalByteLength - request.offset)
      if (
        !sameBinding(response, request) ||
        response.providerResourceId !== request.providerResourceId ||
        response.totalByteLength !== request.expectedTotalByteLength ||
        response.providerSha256Digest !== request.expectedProviderSha256Digest ||
        response.offset !== request.offset ||
        response.byteLength !== expectedRangeLength ||
        bytes.byteLength !== expectedRangeLength ||
        response.eof !== (request.offset + expectedRangeLength === request.expectedTotalByteLength)
      ) {
        throw new ConflictException('Runner capture body conflicts with its exact read authority.')
      }
      return response
    } catch (error) {
      throw translateRunnerCaptureError(error, false)
    }
  }

  async stoppedDirectoryRoster(
    organizationId: string,
    sandboxIdOrName: string,
    request: StoppedWorkingCopyDirectoryRosterRequestDto,
    signal?: AbortSignal,
  ): Promise<StoppedWorkingCopyDirectoryRosterReceiptDto> {
    assertStoppedDirectoryRosterRequest(request)
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      request.anchor.source,
      request.anchor.owner,
      request.anchor.stopAuthority.fence,
    )
    try {
      const receipt = await adapter.stoppedWorkingCopyDirectoryRoster(sandbox.id, request, signal)
      assertStoppedDirectoryRosterReceipt(receipt, request)
      return receipt
    } catch (error) {
      throw translateRunnerCaptureError(error, false)
    }
  }

  async delete(
    organizationId: string,
    sandboxIdOrName: string,
    identity: WorkingCopyCaptureIdentityDto,
  ): Promise<WorkingCopyCaptureDeleteReceiptDto> {
    assertIdentity(identity)
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      identity.source,
      identity.owner,
      captureFence(identity),
    )
    try {
      const receipt = await adapter.deleteWorkingCopyCapture(sandbox.id, identity)
      mutationReceiptGuard(() => {
        assertExactKeys(
          receipt,
          [
            'authority',
            'outcome',
            'owner',
            'providerName',
            'providerResourceId',
            'requestFingerprint',
            'selector',
            'source',
            captureSourceKey(identity),
          ],
          'capture deletion receipt',
          ConflictException,
        )
        assertProviderIdentity(receipt)
        if (
          !sameBinding(receipt, identity) ||
          receipt.providerResourceId !== identity.providerResourceId ||
          !['deleted', 'already_absent'].includes(receipt.outcome)
        ) {
          throw new ConflictException('Runner returned a conflicting capture deletion receipt.')
        }
      })
      return receipt
    } catch (error) {
      throw translateRunnerCaptureError(error, true)
    }
  }

  async exists(
    organizationId: string,
    sandboxIdOrName: string,
    identity: WorkingCopyCaptureIdentityDto,
  ): Promise<WorkingCopyCaptureExistsResponseDto> {
    assertIdentity(identity)
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      identity.source,
      identity.owner,
      captureFence(identity),
    )
    try {
      const response = await adapter.workingCopyCaptureExists(sandbox.id, identity)
      const expectedKeys = [
        'authority',
        'exists',
        'owner',
        'providerName',
        'providerResourceId',
        'requestFingerprint',
        ...(response.status === 'complete' ? ['receipt'] : []),
        'selector',
        'source',
        'status',
        captureSourceKey(identity),
      ]
      assertExactKeys(response, expectedKeys, 'capture exists response', ConflictException)
      assertProviderIdentity(response)
      if (
        !sameBinding(response, identity) ||
        response.providerResourceId !== identity.providerResourceId ||
        typeof response.exists !== 'boolean' ||
        !['absent', 'partial', 'complete'].includes(response.status) ||
        response.exists !== (response.status !== 'absent')
      ) {
        throw new ConflictException('Runner returned an invalid capture existence observation.')
      }
      if (response.status === 'complete') {
        if (!response.receipt) {
          throw new ConflictException('Runner complete existence observation omitted its receipt.')
        }
        assertReceipt(response.receipt, identity)
        if (response.receipt.providerResourceId !== identity.providerResourceId) {
          throw new ConflictException('Runner existence receipt names another generation.')
        }
      } else if (response.receipt !== undefined) {
        throw new ConflictException('Runner non-complete existence observation included a receipt.')
      }
      return response
    } catch (error) {
      throw translateRunnerCaptureError(error, false)
    }
  }
}

function assertStoppedDirectoryRosterRequest(request: StoppedWorkingCopyDirectoryRosterRequestDto): void {
  assertExactKeys(
    request,
    ['anchor', 'maximumAggregateBytes', 'maximumDepth', 'maximumEntries', 'maximumFileBytes', 'selector'],
    'stopped-directory roster request',
    BadRequestException,
  )
  assertBinding(request.anchor)
  if (request.anchor.fileSnapshot !== undefined)
    throw new BadRequestException('Directory capture requires a stopped-generation anchor.')
  assertExactKeys(request.selector, ['semanticZoneRef', 'zoneRelativePath'], 'roster selector', BadRequestException)
  if (
    request.selector.semanticZoneRef === USER_FILES_SEMANTIC_ZONE_REF ||
    request.selector.semanticZoneRef !== request.anchor.selector.semanticZoneRef ||
    !canonicalRelativePath(request.selector.zoneRelativePath) ||
    !request.anchor.selector.zoneRelativePath.startsWith(`${request.selector.zoneRelativePath}/`) ||
    !Number.isSafeInteger(request.maximumDepth) ||
    request.maximumDepth < 1 ||
    request.maximumDepth > MAXIMUM_WORKING_COPY_ROSTER_DEPTH ||
    !Number.isSafeInteger(request.maximumEntries) ||
    request.maximumEntries < 1 ||
    request.maximumEntries > MAXIMUM_WORKING_COPY_ROSTER_ENTRIES ||
    !Number.isSafeInteger(request.maximumFileBytes) ||
    request.maximumFileBytes < 1 ||
    request.maximumFileBytes > MAXIMUM_WORKING_COPY_ROSTER_FILE_BYTES ||
    !Number.isSafeInteger(request.maximumAggregateBytes) ||
    request.maximumAggregateBytes < request.maximumFileBytes ||
    request.maximumAggregateBytes > MAXIMUM_WORKING_COPY_ROSTER_AGGREGATE_BYTES
  ) {
    throw new BadRequestException('Stopped-directory roster authority or bounds are invalid.')
  }
}

function assertStoppedDirectoryRosterReceipt(
  receipt: StoppedWorkingCopyDirectoryRosterReceiptDto,
  request: StoppedWorkingCopyDirectoryRosterRequestDto,
): void {
  assertExactKeys(
    receipt,
    ['entries', 'observedAt', 'request', 'rosterDigest', 'terminalGeneration'],
    'stopped-directory roster receipt',
    ConflictException,
  )
  if (
    canonicalJson(receipt.request) !== canonicalJson(request) ||
    canonicalJson(receipt.terminalGeneration) !== canonicalJson(request.anchor.stopAuthority.terminalGeneration) ||
    !Array.isArray(receipt.entries) ||
    receipt.entries.length > request.maximumEntries ||
    !/^sha256:[0-9a-f]{64}$/.test(receipt.rosterDigest) ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(receipt.observedAt) ||
    !Number.isFinite(Date.parse(receipt.observedAt)) ||
    new Date(Date.parse(receipt.observedAt)).toISOString() !== receipt.observedAt
  ) {
    throw new ConflictException('Runner returned a conflicting stopped-directory roster receipt.')
  }
  let aggregateBytes = 0
  for (const [index, entry] of receipt.entries.entries()) {
    assertStoppedDirectoryRosterEntry(entry, request)
    if (
      index > 0 &&
      compareUtf8Lexicographic(receipt.entries[index - 1].zoneRelativePath, entry.zoneRelativePath) >= 0
    ) {
      throw new ConflictException('Runner stopped-directory roster is not sorted and unique.')
    }
    if (entry.kind === 'regular_file') {
      aggregateBytes += entry.size
      if (!Number.isSafeInteger(aggregateBytes) || aggregateBytes > request.maximumAggregateBytes) {
        throw new ConflictException('Runner stopped-directory roster exceeds its aggregate bound.')
      }
    }
  }
  if (
    !receipt.entries.some(
      (entry) => entry.kind === 'regular_file' && entry.zoneRelativePath === request.anchor.selector.zoneRelativePath,
    )
  ) {
    throw new ConflictException('Runner stopped-directory roster omitted its exact anchor file.')
  }
  const payload = {
    contract: 'ambit.working-copy-stopped-directory-roster/v1',
    request,
    terminalGeneration: request.anchor.stopAuthority.terminalGeneration,
    entries: receipt.entries,
  }
  const expectedDigest = `sha256:${createHash('sha256').update(canonicalJson(payload), 'utf8').digest('hex')}`
  if (receipt.rosterDigest !== expectedDigest) {
    throw new ConflictException('Runner stopped-directory roster digest changed.')
  }
}

function compareUtf8Lexicographic(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'))
}

function assertStoppedDirectoryRosterEntry(
  entry: StoppedWorkingCopyDirectoryRosterEntryDto,
  request: StoppedWorkingCopyDirectoryRosterRequestDto,
): void {
  assertExactKeys(
    entry,
    ['kind', 'mode', 'name', 'sha256', 'size', 'zoneRelativePath'],
    'roster entry',
    ConflictException,
  )
  const prefix = `${request.selector.zoneRelativePath}/`
  const relativePath = entry.zoneRelativePath.startsWith(prefix) ? entry.zoneRelativePath.slice(prefix.length) : ''
  const depth = relativePath ? relativePath.split('/').length : 0
  if (
    !canonicalRelativePath(entry.zoneRelativePath) ||
    !relativePath ||
    entry.name !== posixPath.basename(entry.zoneRelativePath) ||
    (entry.kind !== 'regular_file' && entry.kind !== 'directory') ||
    !Number.isSafeInteger(entry.size) ||
    entry.size < 0 ||
    (entry.kind === 'directory' && (entry.size !== 0 || entry.sha256 !== null)) ||
    (entry.kind === 'regular_file' &&
      (entry.size > request.maximumFileBytes ||
        typeof entry.sha256 !== 'string' ||
        !/^sha256:[0-9a-f]{64}$/.test(entry.sha256))) ||
    depth > request.maximumDepth ||
    (entry.kind === 'directory' && depth >= request.maximumDepth) ||
    (entry.mode !== null && (typeof entry.mode !== 'string' || !/^[0-7]{3,4}$/.test(entry.mode)))
  ) {
    throw new ConflictException('Runner returned an invalid stopped-directory roster entry.')
  }
}

function assertBinding(binding: WorkingCopyCaptureBindingDto): void {
  assertExactKeys(
    binding,
    ['authority', 'owner', 'providerName', 'requestFingerprint', 'selector', 'source', captureSourceKey(binding)],
    'capture binding',
    BadRequestException,
  )
  assertBindingValues(binding)
}

function assertGenerationValues(binding: WorkingCopyCaptureGenerationDto | WorkingCopyCaptureBindingDto): void {
  if (!boundedRef(binding.providerName, 512) || !/^[0-9a-f]{64}$/.test(binding.requestFingerprint)) {
    throw new BadRequestException('Working-copy capture identity is not canonical.')
  }
  assertAuthority(binding.authority)
  try {
    if ('fileSnapshot' in binding && binding.fileSnapshot !== undefined) {
      if (binding.stopAuthority !== undefined) throw new Error('conflicting source authority')
      const snapshot = binding.fileSnapshot
      assertExactKeys(snapshot, ['contract', 'fence', 'generation'], 'file snapshot source', BadRequestException)
      if (snapshot.contract !== FILE_SNAPSHOT_CONTRACT) throw new Error('unsupported file snapshot')
      assertGenerationObservationRequest({ source: binding.source, owner: binding.owner, fence: snapshot.fence })
      assertExpectedGeneration(snapshot.generation)
    } else {
      assertGenerationStopAuthority(binding.stopAuthority)
    }
  } catch {
    throw new BadRequestException('Stopped-generation authority is invalid.')
  }
  assertExactKeys(
    binding.source,
    ['expectedProfile', 'expectedRuntimeKind', 'providerResourceId'],
    'capture source',
    BadRequestException,
  )
  if (
    !boundedRef(binding.source.providerResourceId, 512) ||
    binding.source.expectedProfile !== 'managed-container' ||
    binding.source.expectedRuntimeKind !== 'full_image_runtime_pack'
  ) {
    throw new BadRequestException('Working-copy capture source is not an admitted managed container.')
  }
  assertExactKeys(
    binding.owner,
    ['grantId', 'runId', 'tenantId', 'userId', 'workingCopyId', 'workspaceId'],
    'capture owner',
    BadRequestException,
  )
  if (
    !canonicalUuid(binding.owner.tenantId) ||
    !canonicalUuid(binding.owner.userId) ||
    !canonicalUuid(binding.owner.workspaceId) ||
    !canonicalUuid(binding.owner.runId) ||
    !canonicalUuid(binding.owner.grantId) ||
    !canonicalUuid(binding.owner.workingCopyId)
  ) {
    throw new BadRequestException('Working-copy capture owner is not canonical.')
  }
}

function assertBindingValues(binding: WorkingCopyCaptureBindingDto): void {
  assertGenerationValues(binding)
  if (binding.fileSnapshot !== undefined && binding.selector.semanticZoneRef === USER_FILES_SEMANTIC_ZONE_REF)
    throw new BadRequestException('File snapshot cannot replace whole-tree capture.')
  assertExactKeys(binding.selector, ['semanticZoneRef', 'zoneRelativePath'], 'capture selector', BadRequestException)
  if (
    !['ambit.workspace-zone/work@1', 'ambit.workspace-zone/outputs@1', USER_FILES_SEMANTIC_ZONE_REF].includes(
      binding.selector.semanticZoneRef,
    ) ||
    !(binding.selector.semanticZoneRef === USER_FILES_SEMANTIC_ZONE_REF
      ? canonicalWorkingTreePath(binding.selector.zoneRelativePath) &&
        !reservedWorkingTreePath(binding.selector.zoneRelativePath)
      : canonicalRelativePath(binding.selector.zoneRelativePath))
  ) {
    throw new BadRequestException('Working-copy capture selector is not canonical.')
  }
}

function assertAuthority(authority: WorkingCopyCaptureAuthorityDto): void {
  assertExactKeys(
    authority,
    ['authorityRef', 'helper', 'lineageRef', 'protocol', 'roleRef'],
    'capture authority',
    BadRequestException,
  )
  assertExactKeys(authority.protocol, ['digest', 'ref'], 'capture protocol', BadRequestException)
  assertExactKeys(authority.helper, ['digest', 'ref'], 'capture helper', BadRequestException)
  if (
    authority.roleRef !== CAPTURE_ROLE_REF ||
    !boundedRef(authority.lineageRef, 512) ||
    authority.protocol.ref !== CAPTURE_PROTOCOL_REF ||
    !/^sha256:[0-9a-f]{64}$/.test(authority.protocol.digest) ||
    !/^sha256:[0-9a-f]{64}$/.test(authority.helper.digest) ||
    authority.helper.ref !== `runtime-component-artifact:${authority.helper.digest}`
  ) {
    throw new BadRequestException('Working-copy capture authority lineage is invalid.')
  }
  const preimage = ['ambit.working-copy-capture-authority/v2', authority.lineageRef].join('\n')
  const expected = `ambit.working-copy-capture-authority:v2:sha256:${createHash('sha256')
    .update(preimage, 'utf8')
    .digest('hex')}`
  if (authority.authorityRef !== expected) {
    throw new BadRequestException('Working-copy capture authority reference is invalid.')
  }
}

function assertIdentity(identity: WorkingCopyCaptureIdentityDto): void {
  assertExactKeys(
    identity,
    [
      'authority',
      'owner',
      'providerName',
      'providerResourceId',
      'requestFingerprint',
      'selector',
      'source',
      captureSourceKey(identity),
    ],
    'capture identity',
    BadRequestException,
  )
  assertBindingValues(identity)
  if (!/^daytona-working-copy-capture:v2:sha256:[0-9a-f]{64}$/.test(identity.providerResourceId)) {
    throw new BadRequestException('Working-copy capture provider identity is invalid.')
  }
}

function assertRead(request: WorkingCopyCaptureReadDto): void {
  assertExactKeys(
    request,
    [
      'authority',
      'expectedProviderSha256Digest',
      'expectedTotalByteLength',
      'maximumBytes',
      'offset',
      'owner',
      'providerName',
      'providerResourceId',
      'requestFingerprint',
      'selector',
      'source',
      captureSourceKey(request),
    ],
    'capture read',
    BadRequestException,
  )
  assertBindingValues(request)
  if (!/^daytona-working-copy-capture:v2:sha256:[0-9a-f]{64}$/.test(request.providerResourceId)) {
    throw new BadRequestException('Working-copy capture provider identity is invalid.')
  }
  if (
    !Number.isSafeInteger(request.expectedTotalByteLength) ||
    !Number.isSafeInteger(request.maximumBytes) ||
    !Number.isSafeInteger(request.offset) ||
    request.expectedTotalByteLength < 0 ||
    request.expectedTotalByteLength > captureByteLimit(request) ||
    !/^sha256:[0-9a-f]{64}$/.test(request.expectedProviderSha256Digest) ||
    request.offset < 0 ||
    request.offset > request.expectedTotalByteLength ||
    request.maximumBytes <= 0 ||
    request.maximumBytes >
      (request.selector.semanticZoneRef === USER_FILES_SEMANTIC_ZONE_REF
        ? MAXIMUM_USER_FILE_READ_BYTES
        : MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES)
  ) {
    throw new BadRequestException('Working-copy capture read bounds are invalid.')
  }
}

function assertReceipt(receipt: WorkingCopyCaptureReceiptDto, expectedBinding: WorkingCopyCaptureBindingDto): void {
  assertExactKeys(
    receipt,
    [
      'authority',
      'capturedAt',
      'owner',
      'providerName',
      'providerResourceId',
      'providerSha256Digest',
      'requestFingerprint',
      'selector',
      'source',
      captureSourceKey(expectedBinding),
      'totalByteLength',
    ],
    'capture receipt',
    ConflictException,
  )
  assertProviderIdentity(receipt)
  if (
    !sameBinding(receipt, expectedBinding) ||
    !Number.isSafeInteger(receipt.totalByteLength) ||
    receipt.totalByteLength < 0 ||
    receipt.totalByteLength > captureByteLimit(expectedBinding) ||
    !/^sha256:[0-9a-f]{64}$/.test(receipt.providerSha256Digest) ||
    !canonicalUtcTimestamp(receipt.capturedAt)
  ) {
    throw new ConflictException('Runner returned a capture receipt outside the exact request authority.')
  }
}

function assertProviderIdentity(identity: WorkingCopyCaptureIdentityDto): void {
  try {
    assertBindingValues(identity)
  } catch {
    throw new ConflictException('Runner returned an invalid capture binding.')
  }
  if (!/^daytona-working-copy-capture:v2:sha256:[0-9a-f]{64}$/.test(identity.providerResourceId)) {
    throw new ConflictException('Runner returned an invalid capture generation identity.')
  }
}

function assertObservation(
  observation: WorkingCopyCaptureObservationDto,
  expectedBinding: WorkingCopyCaptureBindingDto,
): void {
  if (observation.status === 'absent') {
    assertExactKeys(observation, ['binding', 'status'], 'absent capture observation', ConflictException)
    if (!observation.binding) {
      throw new ConflictException('Runner absent observation omitted its capture binding.')
    }
    assertProviderBinding(observation.binding)
    if (!sameBinding(observation.binding, expectedBinding)) {
      throw new ConflictException('Runner absent observation names another capture binding.')
    }
    return
  }
  if (observation.status === 'partial') {
    assertExactKeys(observation, ['identity', 'status'], 'partial capture observation', ConflictException)
    if (!observation.identity) {
      throw new ConflictException('Runner partial observation omitted its capture identity.')
    }
    assertExactKeys(
      observation.identity,
      [
        'authority',
        'owner',
        'providerName',
        'providerResourceId',
        'requestFingerprint',
        'selector',
        'source',
        captureSourceKey(expectedBinding),
      ],
      'partial capture identity',
      ConflictException,
    )
    assertProviderIdentity(observation.identity)
    if (!sameBinding(observation.identity, expectedBinding)) {
      throw new ConflictException('Runner partial observation names another capture binding.')
    }
    return
  }
  if (observation.status === 'complete') {
    assertExactKeys(observation, ['receipt', 'status'], 'complete capture observation', ConflictException)
    if (!observation.receipt) {
      throw new ConflictException('Runner complete observation omitted its capture receipt.')
    }
    assertReceipt(observation.receipt, expectedBinding)
    return
  }
  throw new ConflictException('Runner returned an invalid capture observation state.')
}

function assertProviderBinding(binding: WorkingCopyCaptureBindingDto): void {
  assertExactKeys(
    binding,
    ['authority', 'owner', 'providerName', 'requestFingerprint', 'selector', 'source', captureSourceKey(binding)],
    'provider capture binding',
    ConflictException,
  )
  try {
    assertBindingValues(binding)
  } catch {
    throw new ConflictException('Runner returned an invalid capture binding.')
  }
}

function captureSourceKey(binding: WorkingCopyCaptureBindingDto): 'fileSnapshot' | 'stopAuthority' {
  return binding.fileSnapshot !== undefined ? 'fileSnapshot' : 'stopAuthority'
}

function captureFence(binding: WorkingCopyCaptureBindingDto) {
  return binding.fileSnapshot !== undefined ? binding.fileSnapshot.fence : binding.stopAuthority.fence
}

function sameBinding(left: WorkingCopyCaptureBindingDto, right: WorkingCopyCaptureBindingDto): boolean {
  return canonicalJson(bindingData(left)) === canonicalJson(bindingData(right))
}

function bindingData(value: WorkingCopyCaptureBindingDto): object {
  return {
    providerName: value.providerName,
    requestFingerprint: value.requestFingerprint,
    authority: {
      authorityRef: value.authority.authorityRef,
      lineageRef: value.authority.lineageRef,
      roleRef: value.authority.roleRef,
      protocol: { ref: value.authority.protocol.ref, digest: value.authority.protocol.digest },
      helper: { ref: value.authority.helper.ref, digest: value.authority.helper.digest },
    },
    source: {
      providerResourceId: value.source.providerResourceId,
      expectedProfile: value.source.expectedProfile,
      expectedRuntimeKind: value.source.expectedRuntimeKind,
    },
    owner: {
      tenantId: value.owner.tenantId,
      userId: value.owner.userId,
      workspaceId: value.owner.workspaceId,
      runId: value.owner.runId,
      grantId: value.owner.grantId,
      workingCopyId: value.owner.workingCopyId,
    },
    ...(value.fileSnapshot !== undefined
      ? { fileSnapshot: value.fileSnapshot }
      : { stopAuthority: value.stopAuthority }),
    selector: {
      semanticZoneRef: value.selector.semanticZoneRef,
      zoneRelativePath: value.selector.zoneRelativePath,
    },
  }
}

function canonicalRelativePath(value: unknown, maximumBytes = 2048): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > maximumBytes ||
    value.startsWith('/') ||
    value.endsWith('/') ||
    value.includes('\\') ||
    posixPath.normalize(value) !== value ||
    value === '.' ||
    value === '..' ||
    [...value].some((character) => {
      const code = character.codePointAt(0) as number
      return code < 32 || (code >= 127 && code <= 159)
    })
  ) {
    return false
  }
  return value
    .split('/')
    .every((segment) => segment && segment !== '.' && segment !== '..' && Buffer.byteLength(segment) <= 255)
}

function boundedRef(value: unknown, maximum: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maximum &&
    value === value.trim() &&
    ![...value].some((character) => {
      const code = character.codePointAt(0) as number
      return code < 32 || (code >= 127 && code <= 159)
    })
  )
}

function canonicalUuid(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) &&
    value !== '00000000-0000-0000-0000-000000000000'
  )
}

function canonicalBase64(value: string, maximumBytes: number): boolean {
  return (
    value.length <= Math.ceil(maximumBytes / 3) * 4 &&
    value.length % 4 === 0 &&
    Buffer.from(value, 'base64').toString('base64') === value
  )
}

function canonicalUtcTimestamp(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value) &&
    Number.isFinite(Date.parse(value))
  )
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new ConflictException('Canonical roster JSON contains a non-finite number.')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (!value || typeof value !== 'object') {
    throw new ConflictException('Canonical roster JSON contains an unsupported value.')
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`)
    .join(',')}}`
}

type HttpExceptionConstructor = new (message: string) => Error

function assertExactKeys(
  value: unknown,
  keys: readonly string[],
  label: string,
  Exception: HttpExceptionConstructor,
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Exception(`${label} is not an object.`)
  }
  // A class-transformed DTO carries its declared optional fields as own
  // properties valued undefined; only present values are part of the shape.
  const actual = Object.keys(value)
    .filter((key) => (value as Record<string, unknown>)[key] !== undefined)
    .sort()
  const expected = [...keys].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Exception(`${label} does not have the exact contract shape.`)
  }
}

function mutationReceiptGuard(action: () => void): void {
  try {
    action()
  } catch {
    throw captureOutcomeUnknown()
  }
}

function captureOutcomeUnknown(): ServiceUnavailableException {
  return new ServiceUnavailableException({
    statusCode: 503,
    message: 'Working-copy capture outcome is unknown; observe the exact operation before retrying.',
    error: 'Service Unavailable',
    code: 'WORKING_COPY_CAPTURE_OUTCOME_UNKNOWN',
  })
}

function translateRunnerCaptureError(error: unknown, mutating: boolean): unknown {
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
          error.code === 'WORKING_COPY_CAPTURE_OUTCOME_UNKNOWN'
            ? 'WORKING_COPY_CAPTURE_OUTCOME_UNKNOWN'
            : 'WORKING_COPY_CAPTURE_UNAVAILABLE',
      })
    default: {
      // An unmapped runner status is the one case this translation used to
      // erase: log the exact runner answer and carry a bounded copy of it so
      // the class stays diagnosable from the caller's side.
      const detail = `runner status ${error.statusCode ?? 'none'}${error.code ? ` code ${error.code}` : ''}: ${boundedRunnerMessage(error.message)}`
      runnerCaptureLogger.warn(`Working-copy capture failed with an unmapped runner answer (${detail})`)
      if (mutating) return captureOutcomeUnknown()
      return new ServiceUnavailableException({
        statusCode: 503,
        message: `The sandbox runner could not complete working-copy capture (${detail}).`,
        error: 'Service Unavailable',
        code: 'WORKING_COPY_CAPTURE_UNAVAILABLE',
      })
    }
  }
}

const runnerCaptureLogger = new Logger('WorkingCopyCaptureRunner')

function boundedRunnerMessage(message: string): string {
  const printable = message.replace(/[^\x20-\x7e]/g, ' ').trim()
  return printable.length > 240 ? `${printable.slice(0, 240)}...` : printable || '(no message)'
}

function captureByteLimit(binding: WorkingCopyCaptureBindingDto): number {
  return binding.selector.semanticZoneRef === USER_FILES_SEMANTIC_ZONE_REF
    ? MAXIMUM_USER_FILE_CAPTURE_BYTES
    : MAXIMUM_WORKING_COPY_CAPTURE_BYTES
}

function canonicalWorkingTreePath(value: unknown): value is string {
  return canonicalRelativePath(value, 4096) && toUSVString(value) === value && value.normalize('NFC') === value
}

function reservedWorkingTreePath(value: string): boolean {
  const root = value.split('/')[0]
  return root === '.ambit' || root.startsWith('.ambit-skill-')
}

function excludedWorkingTreePath(value: string, exclusions: ReadonlySet<string>): boolean {
  if (reservedWorkingTreePath(value)) return true
  for (let candidate = value; candidate !== '.'; candidate = posixPath.dirname(candidate)) {
    if (exclusions.has(candidate)) return true
  }
  return false
}

function validWorkingTreeEntryVariant(entry: StoppedWorkingCopyWorkingTreeEntryDto, maximumFileBytes: number): boolean {
  if (entry.kind === 'regular_file') {
    return (
      entry.size <= maximumFileBytes && typeof entry.sha256 === 'string' && /^sha256:[0-9a-f]{64}$/.test(entry.sha256)
    )
  }
  if (entry.size !== 0 || entry.sha256 !== null) return false
  switch (entry.kind) {
    case 'directory':
      return true
    case 'symlink':
      return (
        typeof entry.linkTarget === 'string' &&
        entry.linkTarget.length > 0 &&
        Buffer.byteLength(entry.linkTarget, 'utf8') <= 4096 &&
        toUSVString(entry.linkTarget) === entry.linkTarget &&
        !entry.linkTarget.includes(String.fromCharCode(0))
      )
    case 'excluded':
      return (
        entry.excludedKind === 'fifo' ||
        entry.excludedKind === 'character_device' ||
        entry.excludedKind === 'block_device'
      )
    default:
      return false
  }
}

function assertWorkingTreeEntry(
  entry: StoppedWorkingCopyWorkingTreeEntryDto,
  request: Pick<WorkingTreeInventoryRequestDto, 'maximumDepth' | 'maximumFileBytes'>,
  excluded: ReadonlySet<string>,
): void {
  assertExactKeys(
    entry,
    [
      'kind',
      'mode',
      'name',
      'sha256',
      'size',
      'zoneRelativePath',
      ...(entry.kind === 'regular_file' ? ['byteOffset'] : []),
      ...(entry.kind === 'symlink' ? ['linkTarget'] : []),
      ...(entry.kind === 'excluded' ? ['excludedKind'] : []),
    ],
    'working-tree entry',
    ConflictException,
  )
  if (
    !canonicalWorkingTreePath(entry.zoneRelativePath) ||
    excludedWorkingTreePath(entry.zoneRelativePath, excluded) ||
    entry.name !== posixPath.basename(entry.zoneRelativePath) ||
    entry.zoneRelativePath.split('/').length > request.maximumDepth ||
    !Number.isSafeInteger(entry.size) ||
    entry.size < 0 ||
    !validWorkingTreeEntryVariant(entry, request.maximumFileBytes) ||
    (entry.kind === 'regular_file' &&
      (typeof entry.byteOffset !== 'number' ||
        !Number.isSafeInteger(entry.byteOffset) ||
        entry.byteOffset < 0 ||
        entry.size > MAXIMUM_WORKING_TREE_AGGREGATE_BYTES - entry.byteOffset)) ||
    typeof entry.mode !== 'string' ||
    !/^[0-7]{4}$/.test(entry.mode)
  ) {
    throw new ConflictException('Runner returned an invalid working-tree entry.')
  }
}

const INVENTORY_CONTRACT = 'ambit.working-copy-stopped-working-tree-inventory/v1'
function jsonDigest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`
}
function inventoryResourceId(request: WorkingTreeInventoryRequestDto): string {
  return `daytona-working-tree-inventory:v1:${jsonDigest(request)}`
}

function assertInventoryRequest(request: WorkingTreeInventoryRequestDto): void {
  assertExactKeys(
    request,
    [
      'generation',
      'excludedPaths',
      'maximumDepth',
      'maximumFileBytes',
      'maximumAggregateBytes',
      'maximumPageEntries',
      'maximumPageBytes',
    ],
    'working-tree inventory request',
    BadRequestException,
  )
  assertExactKeys(
    request.generation,
    ['authority', 'owner', 'providerName', 'requestFingerprint', 'source', 'stopAuthority'],
    'inventory generation',
    BadRequestException,
  )
  assertGenerationValues(request.generation)
  const limits = {
    maximumDepth: MAXIMUM_WORKING_TREE_DEPTH,
    maximumFileBytes: MAXIMUM_WORKING_TREE_AGGREGATE_BYTES,
    maximumAggregateBytes: MAXIMUM_WORKING_TREE_AGGREGATE_BYTES,
    maximumPageEntries: MAXIMUM_WORKING_TREE_INVENTORY_PAGE_ENTRIES,
    maximumPageBytes: MAXIMUM_WORKING_TREE_INVENTORY_PAGE_BYTES,
  }
  for (const key of Object.keys(limits) as (keyof typeof limits)[]) {
    if (
      !Number.isSafeInteger(request[key]) ||
      request[key] < (key === 'maximumPageBytes' ? 2 : 1) ||
      request[key] > limits[key]
    )
      throw new BadRequestException('Working-tree inventory bounds are invalid.')
  }
  if (
    request.maximumAggregateBytes < request.maximumFileBytes ||
    !Array.isArray(request.excludedPaths) ||
    request.excludedPaths.length > 4096
  )
    throw new BadRequestException('Working-tree inventory bounds or exclusions are invalid.')
  const excluded = new Set<string>()
  for (const [index, path] of request.excludedPaths.entries()) {
    if (
      !canonicalWorkingTreePath(path) ||
      (index > 0 && compareUtf8Lexicographic(request.excludedPaths[index - 1], path) >= 0)
    )
      throw new BadRequestException('Inventory exclusions must be sorted unique roots.')
    for (let parent = posixPath.dirname(path); parent !== '.'; parent = posixPath.dirname(parent)) {
      if (excluded.has(parent)) throw new BadRequestException('Inventory exclusions repeat an excluded ancestor.')
    }
    excluded.add(path)
  }
}

function assertInventoryReceipt(
  receipt: WorkingTreeInventoryReceiptDto,
  request: WorkingTreeInventoryRequestDto,
): void {
  assertExactKeys(
    receipt,
    [
      'request',
      'providerResourceId',
      'terminalGeneration',
      'pages',
      'entryCount',
      'aggregateBytes',
      'bytePack',
      'inventoryDigest',
      'observedAt',
    ],
    'working-tree inventory',
    ConflictException,
  )
  if (
    canonicalJson(receipt.request) !== canonicalJson(request) ||
    receipt.providerResourceId !== inventoryResourceId(request) ||
    canonicalJson(receipt.terminalGeneration) !== canonicalJson(request.generation.stopAuthority.terminalGeneration) ||
    !Array.isArray(receipt.pages) ||
    Buffer.byteLength(canonicalJson(receipt), 'utf8') > MAXIMUM_WORKING_TREE_INVENTORY_INDEX_BYTES
  )
    throw new ConflictException('Runner inventory changed its exact source scope.')
  let count = 0
  let previous = ''
  for (const [index, page] of receipt.pages.entries()) {
    assertExactKeys(
      page,
      ['pageIndex', 'entryCount', 'byteLength', 'sha256', 'firstPath', 'lastPath'],
      'inventory page descriptor',
      ConflictException,
    )
    if (
      page.pageIndex !== index ||
      !Number.isSafeInteger(page.entryCount) ||
      page.entryCount < 1 ||
      page.entryCount > request.maximumPageEntries ||
      !Number.isSafeInteger(page.byteLength) ||
      page.byteLength < 2 ||
      page.byteLength > request.maximumPageBytes ||
      typeof page.sha256 !== 'string' ||
      !/^sha256:[0-9a-f]{64}$/.test(page.sha256) ||
      !canonicalWorkingTreePath(page.firstPath) ||
      !canonicalWorkingTreePath(page.lastPath) ||
      compareUtf8Lexicographic(page.firstPath, page.lastPath) > 0 ||
      (previous !== '' && compareUtf8Lexicographic(previous, page.firstPath) >= 0)
    )
      throw new ConflictException('Runner inventory page descriptor is invalid.')
    previous = page.lastPath
    count += page.entryCount
  }
  if (
    !Number.isSafeInteger(count) ||
    receipt.entryCount !== count ||
    !Number.isSafeInteger(receipt.aggregateBytes) ||
    receipt.aggregateBytes < 0 ||
    receipt.aggregateBytes > request.maximumAggregateBytes ||
    (count === 0 && receipt.aggregateBytes !== 0) ||
    !canonicalUtcTimestamp(receipt.observedAt)
  )
    throw new ConflictException('Runner inventory counts or observation time are invalid.')
  const pack = receipt.bytePack
  assertExactKeys(pack, ['byteLength', 'sha256', 'parts'], 'inventory byte pack', ConflictException)
  if (
    !Number.isSafeInteger(pack.byteLength) ||
    pack.byteLength < 0 ||
    pack.byteLength > receipt.aggregateBytes ||
    typeof pack.sha256 !== 'string' ||
    !/^sha256:[0-9a-f]{64}$/.test(pack.sha256) ||
    !Array.isArray(pack.parts)
  )
    throw new ConflictException('Runner inventory byte pack is invalid.')
  let byteOffset = 0
  for (const part of pack.parts) {
    assertExactKeys(part, ['byteOffset', 'byteLength', 'sha256'], 'inventory byte part', ConflictException)
    if (
      part.byteOffset !== byteOffset ||
      !Number.isSafeInteger(part.byteLength) ||
      part.byteLength < 1 ||
      part.byteLength > pack.byteLength - byteOffset ||
      typeof part.sha256 !== 'string' ||
      !/^sha256:[0-9a-f]{64}$/.test(part.sha256)
    )
      throw new ConflictException('Runner inventory byte parts do not cover the pack.')
    byteOffset += part.byteLength
  }
  if (
    byteOffset !== pack.byteLength ||
    (pack.byteLength === 0 && pack.sha256 !== `sha256:${createHash('sha256').digest('hex')}`)
  )
    throw new ConflictException('Runner inventory byte pack coverage changed.')
  const digest = jsonDigest({
    contract: INVENTORY_CONTRACT,
    request,
    terminalGeneration: receipt.terminalGeneration,
    pages: receipt.pages,
    entryCount: receipt.entryCount,
    aggregateBytes: receipt.aggregateBytes,
    bytePack: receipt.bytePack,
  })
  if (receipt.inventoryDigest !== digest) throw new ConflictException('Runner inventory digest changed.')
}
