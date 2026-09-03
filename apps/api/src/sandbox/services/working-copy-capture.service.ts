/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { createHash } from 'node:crypto'
import { posix as posixPath } from 'node:path'
import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common'

import {
  MAXIMUM_WORKING_COPY_CAPTURE_BYTES,
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
  WorkingCopyCaptureDeleteReceiptDto,
  WorkingCopyCaptureExistsResponseDto,
  WorkingCopyCaptureIdentityDto,
  WorkingCopyCaptureObservationDto,
  WorkingCopyCaptureReadDto,
  WorkingCopyCaptureReadResponseDto,
  WorkingCopyCaptureReceiptDto,
} from '../dto/working-copy-capture.dto'
import { assertStopAuthority as assertGenerationStopAuthority } from '../dto/sandbox-generation-stop.contract'
import { RunnerApiError } from '../errors/runner-api-error'
import { SandboxExecutionAuthorityService } from './sandbox-execution-authority.service'

const CAPTURE_ROLE_REF = 'ambit.runtime-component/working-copy-capture@2'
const CAPTURE_PROTOCOL_REF = 'ambit.runtime-interface/working-copy-capture@2'

@Injectable()
export class WorkingCopyCaptureService {
  constructor(private readonly executionAuthority: SandboxExecutionAuthorityService) {}

  async capture(
    organizationId: string,
    sandboxIdOrName: string,
    binding: WorkingCopyCaptureBindingDto,
  ): Promise<WorkingCopyCaptureReceiptDto> {
    assertBinding(binding)
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      binding.source,
      binding.owner,
      binding.stopAuthority.fence,
    )
    try {
      const receipt = await adapter.captureWorkingCopy(sandbox.id, binding)
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
      binding.stopAuthority.fence,
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
  ): Promise<WorkingCopyCaptureReadResponseDto> {
    assertRead(request)
    const { sandbox, adapter } = await this.executionAuthority.authorize(
      organizationId,
      sandboxIdOrName,
      request.source,
      request.owner,
      request.stopAuthority.fence,
    )
    try {
      const response = await adapter.readWorkingCopyCapture(sandbox.id, request)
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
          'stopAuthority',
          'totalByteLength',
        ],
        'capture read response',
        ConflictException,
      )
      assertProviderIdentity(response)
      if (typeof response.bytesBase64 !== 'string' || !canonicalBase64(response.bytesBase64)) {
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
      identity.stopAuthority.fence,
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
            'stopAuthority',
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
      identity.stopAuthority.fence,
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
        'stopAuthority',
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
  assertExactKeys(request.selector, ['semanticZoneRef', 'zoneRelativePath'], 'roster selector', BadRequestException)
  if (
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
    ['authority', 'owner', 'providerName', 'requestFingerprint', 'selector', 'source', 'stopAuthority'],
    'capture binding',
    BadRequestException,
  )
  assertBindingValues(binding)
}

function assertBindingValues(binding: WorkingCopyCaptureBindingDto): void {
  if (!boundedRef(binding.providerName, 512) || !/^[0-9a-f]{64}$/.test(binding.requestFingerprint)) {
    throw new BadRequestException('Working-copy capture identity is not canonical.')
  }
  assertAuthority(binding.authority)
  try {
    assertGenerationStopAuthority(binding.stopAuthority)
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
  assertExactKeys(binding.selector, ['semanticZoneRef', 'zoneRelativePath'], 'capture selector', BadRequestException)
  if (
    !['ambit.workspace-zone/work@1', 'ambit.workspace-zone/outputs@1'].includes(binding.selector.semanticZoneRef) ||
    !canonicalRelativePath(binding.selector.zoneRelativePath)
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
      'stopAuthority',
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
      'stopAuthority',
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
    request.expectedTotalByteLength > MAXIMUM_WORKING_COPY_CAPTURE_BYTES ||
    !/^sha256:[0-9a-f]{64}$/.test(request.expectedProviderSha256Digest) ||
    request.offset < 0 ||
    request.offset > request.expectedTotalByteLength ||
    request.maximumBytes <= 0 ||
    request.maximumBytes > MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES
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
      'stopAuthority',
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
    receipt.totalByteLength > MAXIMUM_WORKING_COPY_CAPTURE_BYTES ||
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
        'stopAuthority',
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
    ['authority', 'owner', 'providerName', 'requestFingerprint', 'selector', 'source', 'stopAuthority'],
    'provider capture binding',
    ConflictException,
  )
  try {
    assertBindingValues(binding)
  } catch {
    throw new ConflictException('Runner returned an invalid capture binding.')
  }
}

function sameBinding(left: WorkingCopyCaptureBindingDto, right: WorkingCopyCaptureBindingDto): boolean {
  return JSON.stringify(bindingData(left)) === JSON.stringify(bindingData(right))
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
    stopAuthority: {
      operationId: value.stopAuthority.operationId,
      receiptRef: value.stopAuthority.receiptRef,
      receiptDigest: value.stopAuthority.receiptDigest,
      terminalGeneration: { ...value.stopAuthority.terminalGeneration },
      fence: {
        workspaceExecutionManifestRef: value.stopAuthority.fence.workspaceExecutionManifestRef,
      },
    },
    selector: {
      semanticZoneRef: value.selector.semanticZoneRef,
      zoneRelativePath: value.selector.zoneRelativePath,
    },
  }
}

function canonicalRelativePath(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > 2048 ||
    value.startsWith('/') ||
    value.endsWith('/') ||
    value.includes('\\') ||
    posixPath.normalize(value) !== value ||
    value === '.' ||
    value === '..' ||
    [...value].some((character) => {
      const code = character.codePointAt(0) as number
      return code < 32 || code === 127
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
      return code < 32 || code === 127
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

function canonicalBase64(value: string): boolean {
  return (
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value) &&
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
    default:
      if (mutating) return captureOutcomeUnknown()
      return new ServiceUnavailableException('The sandbox runner could not complete working-copy capture.')
  }
}
