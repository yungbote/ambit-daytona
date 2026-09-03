/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { createHash } from 'node:crypto'

import {
  SandboxExecutionGenerationDto,
  SandboxGenerationFenceDto,
  SandboxGenerationObservationDto,
  SandboxGenerationObservationRequestDto,
  SandboxGenerationStopAuthorityDto,
  SandboxGenerationStopObservationDto,
  SandboxGenerationStopPurposeDto,
  SandboxTerminalGenerationDto,
  StopSandboxGenerationRequestDto,
  StoppedSandboxGenerationReceiptDto,
} from './sandbox-generation-stop.dto'
import { SandboxExecutionOwnerDto, SandboxExecutionSourceDto } from './sandbox-execution-authority.dto'

const RECEIPT_KIND = 'agent_workspace_stopped_generation_receipt' as const
const MAXIMUM_SAFE_JSON_INTEGER = 9_007_199_254_740_991

export function assertGenerationObservationRequest(
  value: SandboxGenerationObservationRequestDto,
  label = 'sandbox generation observation request',
): void {
  exactKeys(value, ['fence', 'owner', 'source'], label)
  assertSource(value.source)
  assertOwner(value.owner)
  assertFence(value.fence)
}

export function assertGenerationObservation(
  value: SandboxGenerationObservationDto,
  expected: SandboxGenerationObservationRequestDto,
): void {
  exactKeys(value, ['fence', 'generation', 'observedAt', 'owner', 'source', 'state'], 'sandbox generation observation')
  assertGenerationObservationRequest(
    { source: value.source, owner: value.owner, fence: value.fence },
    'sandbox generation observation authority',
  )
  if (!sameCanonical({ source: value.source, owner: value.owner, fence: value.fence }, expected)) {
    throw new Error('sandbox generation observation authority differs')
  }
  assertExpectedGeneration(value.generation)
  if (!['running', 'stopped'].includes(value.state) || !canonicalUtcTimestamp(value.observedAt)) {
    throw new Error('sandbox generation observation state or time is invalid')
  }
}

export function assertStopRequest(value: StopSandboxGenerationRequestDto): void {
  exactKeys(
    value,
    ['expectedGeneration', 'fence', 'operationId', 'owner', 'purpose', 'requestFingerprint', 'source'],
    'stopped-generation request',
  )
  assertGenerationObservationRequest({ source: value.source, owner: value.owner, fence: value.fence })
  if (!canonicalUuid(value.operationId)) throw new Error('stopped-generation operationId is invalid')
  assertExpectedGeneration(value.expectedGeneration)
  assertPurpose(value.purpose)
  if (value.requestFingerprint !== stoppedGenerationRequestFingerprint(value)) {
    throw new Error('stopped-generation request fingerprint is invalid')
  }
}

export function assertStopAuthority(value: SandboxGenerationStopAuthorityDto): void {
  exactKeys(
    value,
    ['fence', 'operationId', 'receiptDigest', 'receiptRef', 'terminalGeneration'],
    'stopped-generation authority',
  )
  assertFence(value.fence)
  assertTerminalGeneration(value.terminalGeneration)
  if (
    !canonicalUuid(value.operationId) ||
    !/^sha256:[0-9a-f]{64}$/.test(value.receiptDigest) ||
    value.receiptRef !== `ambit.stopped-generation-receipt:v1:${value.receiptDigest}`
  ) {
    throw new Error('stopped-generation authority receipt identity is invalid')
  }
}

export function assertStoppedGenerationReceipt(
  value: StoppedSandboxGenerationReceiptDto,
  expected?: StopSandboxGenerationRequestDto,
): void {
  exactKeys(
    value,
    ['kind', 'receiptDigest', 'receiptRef', 'request', 'stoppedAt', 'terminalGeneration', 'version'],
    'stopped-generation receipt',
  )
  if (value.version !== 1 || value.kind !== RECEIPT_KIND) {
    throw new Error('stopped-generation receipt version or kind is invalid')
  }
  assertStopRequest(value.request)
  if (expected && !sameCanonical(value.request, expected)) {
    throw new Error('stopped-generation receipt request differs')
  }
  assertTerminalGeneration(value.terminalGeneration)
  if (
    !sameCanonical(value.terminalGeneration, {
      ...value.request.expectedGeneration,
      executionFinishedAt: value.terminalGeneration.executionFinishedAt,
      exitCode: value.terminalGeneration.exitCode,
      oomKilled: value.terminalGeneration.oomKilled,
    }) ||
    !canonicalUtcTimestamp(value.stoppedAt) ||
    Date.parse(value.stoppedAt) < Date.parse(value.terminalGeneration.executionFinishedAt)
  ) {
    throw new Error('stopped-generation receipt terminal chronology is invalid')
  }
  const receiptDigest = stoppedGenerationReceiptDigest(value)
  if (
    value.receiptDigest !== receiptDigest ||
    value.receiptRef !== `ambit.stopped-generation-receipt:v1:${receiptDigest}`
  ) {
    throw new Error('stopped-generation receipt digest or reference is invalid')
  }
}

export function assertStopObservation(
  value: SandboxGenerationStopObservationDto,
  expected: StopSandboxGenerationRequestDto,
): void {
  switch (value.status) {
    case 'absent':
    case 'partial':
      exactKeys(value, ['request', 'status'], `${value.status} stopped-generation observation`)
      if (!value.request) throw new Error(`${value.status} stopped-generation observation omitted request`)
      assertStopRequest(value.request)
      if (!sameCanonical(value.request, expected)) throw new Error('stopped-generation observation request differs')
      return
    case 'complete':
      exactKeys(value, ['receipt', 'status'], 'complete stopped-generation observation')
      if (!value.receipt) throw new Error('complete stopped-generation observation omitted receipt')
      assertStoppedGenerationReceipt(value.receipt, expected)
      return
    default:
      throw new Error('stopped-generation observation state is invalid')
  }
}

export function stopAuthorityFromReceipt(
  receipt: StoppedSandboxGenerationReceiptDto,
): SandboxGenerationStopAuthorityDto {
  assertStoppedGenerationReceipt(receipt)
  return {
    operationId: receipt.request.operationId,
    receiptRef: receipt.receiptRef,
    receiptDigest: receipt.receiptDigest,
    terminalGeneration: { ...receipt.terminalGeneration },
    fence: { ...receipt.request.fence },
  }
}

export function stoppedGenerationRequestFingerprint(request: StopSandboxGenerationRequestDto): string {
  const fields = [
    'ambit.workspace-stop-generation-request/v1',
    request.operationId,
    request.source.providerResourceId,
    request.source.expectedProfile,
    request.source.expectedRuntimeKind,
    request.owner.tenantId,
    request.owner.userId,
    request.owner.workspaceId,
    request.owner.runId,
    request.owner.grantId,
    request.owner.workingCopyId,
    request.fence.workspaceExecutionManifestRef,
    request.expectedGeneration.containerId,
    request.expectedGeneration.containerCreatedAt,
    request.expectedGeneration.executionStartedAt,
    String(request.expectedGeneration.restartCount),
    request.purpose.kind,
  ]
  if (request.purpose.kind === 'document_renderer_quiescence') {
    fields.push(
      request.purpose.sessionId as string,
      request.purpose.nonce as string,
      String(request.purpose.rendererProcessIdentity?.pid),
      request.purpose.rendererProcessIdentity?.startTicks as string,
    )
  }
  return createHash('sha256').update(fields.join('\n'), 'utf8').digest('hex')
}

export function stoppedGenerationReceiptDigest(receipt: StoppedSandboxGenerationReceiptDto): string {
  const payload = {
    version: 1,
    kind: RECEIPT_KIND,
    request: receipt.request,
    terminalGeneration: receipt.terminalGeneration,
    stoppedAt: receipt.stoppedAt,
  }
  return `sha256:${createHash('sha256').update(strictCanonicalJson(payload), 'utf8').digest('hex')}`
}

export function sameCanonical(left: unknown, right: unknown): boolean {
  return strictCanonicalJson(left) === strictCanonicalJson(right)
}

export function strictCanonicalJson(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('canonical JSON contains a non-safe integer')
    return String(value)
  }
  if (Array.isArray(value)) return `[${value.map(strictCanonicalJson).join(',')}]`
  if (!value || typeof value !== 'object') throw new Error('canonical JSON contains an unsupported value')
  const record = value as Record<string, unknown>
  const entries = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${strictCanonicalJson(record[key])}`)
  return `{${entries.join(',')}}`
}

function assertSource(source: SandboxExecutionSourceDto): void {
  exactKeys(source, ['expectedProfile', 'expectedRuntimeKind', 'providerResourceId'], 'sandbox execution source')
  if (
    !boundedToken(source.providerResourceId, 512) ||
    source.expectedProfile !== 'managed-container' ||
    source.expectedRuntimeKind !== 'full_image_runtime_pack'
  ) {
    throw new Error('sandbox execution source is invalid')
  }
}

function assertOwner(owner: SandboxExecutionOwnerDto): void {
  exactKeys(
    owner,
    ['grantId', 'runId', 'tenantId', 'userId', 'workingCopyId', 'workspaceId'],
    'sandbox execution owner',
  )
  if (
    !canonicalUuid(owner.tenantId) ||
    !canonicalUuid(owner.userId) ||
    !canonicalUuid(owner.workspaceId) ||
    !canonicalUuid(owner.runId) ||
    !canonicalUuid(owner.grantId) ||
    !canonicalUuid(owner.workingCopyId)
  ) {
    throw new Error('sandbox execution owner is invalid')
  }
}

function assertFence(fence: SandboxGenerationFenceDto): void {
  exactKeys(fence, ['workspaceExecutionManifestRef'], 'sandbox execution fence')
  if (!boundedToken(fence.workspaceExecutionManifestRef, 2048)) {
    throw new Error('sandbox execution fence is invalid')
  }
}

function assertExpectedGeneration(generation: SandboxExecutionGenerationDto): void {
  exactKeys(
    generation,
    ['containerCreatedAt', 'containerId', 'executionStartedAt', 'restartCount'],
    'sandbox execution generation',
  )
  if (
    !/^[0-9a-f]{64}$/.test(generation.containerId) ||
    !canonicalUtcTimestamp(generation.containerCreatedAt) ||
    !canonicalUtcTimestamp(generation.executionStartedAt) ||
    Date.parse(generation.executionStartedAt) < Date.parse(generation.containerCreatedAt) ||
    !Number.isSafeInteger(generation.restartCount) ||
    generation.restartCount < 0 ||
    generation.restartCount > MAXIMUM_SAFE_JSON_INTEGER
  ) {
    throw new Error('sandbox execution generation is invalid')
  }
}

function assertTerminalGeneration(generation: SandboxTerminalGenerationDto): void {
  exactKeys(
    generation,
    [
      'containerCreatedAt',
      'containerId',
      'executionFinishedAt',
      'executionStartedAt',
      'exitCode',
      'oomKilled',
      'restartCount',
    ],
    'sandbox terminal generation',
  )
  assertExpectedGeneration({
    containerId: generation.containerId,
    containerCreatedAt: generation.containerCreatedAt,
    executionStartedAt: generation.executionStartedAt,
    restartCount: generation.restartCount,
  })
  if (
    !canonicalUtcTimestamp(generation.executionFinishedAt) ||
    Date.parse(generation.executionFinishedAt) < Date.parse(generation.executionStartedAt) ||
    !Number.isSafeInteger(generation.exitCode) ||
    generation.exitCode < -2147483648 ||
    generation.exitCode > 2147483647 ||
    typeof generation.oomKilled !== 'boolean'
  ) {
    throw new Error('sandbox terminal generation is invalid')
  }
}

function assertPurpose(purpose: SandboxGenerationStopPurposeDto): void {
  switch (purpose.kind) {
    case 'working_copy_capture':
      exactKeys(purpose, ['kind'], 'working-copy stop purpose')
      return
    case 'document_renderer_quiescence':
      exactKeys(purpose, ['kind', 'nonce', 'rendererProcessIdentity', 'sessionId'], 'document renderer stop purpose')
      exactKeys(purpose.rendererProcessIdentity, ['pid', 'startTicks'], 'document renderer process identity')
      if (
        !/^ambit-document-render-[0-9a-f]{40}$/.test(purpose.sessionId as string) ||
        !/^[0-9a-f]{32}$/.test(purpose.nonce as string) ||
        !Number.isSafeInteger(purpose.rendererProcessIdentity?.pid) ||
        (purpose.rendererProcessIdentity?.pid as number) <= 0 ||
        (purpose.rendererProcessIdentity?.pid as number) > MAXIMUM_SAFE_JSON_INTEGER ||
        !/^[1-9][0-9]{0,31}$/.test(purpose.rendererProcessIdentity?.startTicks as string)
      ) {
        throw new Error('document renderer stop purpose is invalid')
      }
      return
    default:
      throw new Error('stopped-generation purpose is invalid')
  }
}

function canonicalUuid(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) &&
    value !== '00000000-0000-0000-0000-000000000000'
  )
}

function canonicalUtcTimestamp(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value) &&
    Number.isFinite(Date.parse(value))
  )
}

function boundedToken(value: unknown, maximum: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= maximum &&
    value === value.trim() &&
    ![...value].some((character) => {
      const code = character.codePointAt(0) as number
      return code === 0 || code <= 32 || code === 127 || /\s/u.test(character)
    })
  )
}

function exactKeys(
  value: unknown,
  expectedKeys: readonly string[],
  label: string,
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} is not an object`)
  // A class-transformed DTO carries its declared optional fields as own
  // properties valued undefined; only present values are part of the shape.
  const actual = Object.keys(value)
    .filter((key) => (value as Record<string, unknown>)[key] !== undefined)
    .sort()
  const expected = [...expectedKeys].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} does not have the exact contract shape`)
  }
}
