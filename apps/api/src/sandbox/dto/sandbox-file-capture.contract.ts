/* Copyright 2026 Ambit. SPDX-License-Identifier: AGPL-3.0 */

import { posix } from 'node:path'
import { toUSVString } from 'node:util'
import {
  SANDBOX_FILE_CAPTURE_CONTRACT,
  SANDBOX_FILE_OPERATION_PATTERN,
  SandboxFileCaptureRequestDto,
  SandboxFileCaptureReceiptDto,
  SandboxFileCaptureReadRequestDto,
  SandboxFileCaptureReadResponseDto,
  SandboxFileCaptureObservationDto,
  SandboxFileCaptureObserveRequestDto,
  SandboxFileCaptureDeleteRequestDto,
  SandboxFileCaptureDeleteReceiptDto,
} from './sandbox-file-capture.dto'
import { assertExpectedGeneration } from './sandbox-generation-stop.contract'
import { MAXIMUM_USER_FILE_CAPTURE_BYTES, MAXIMUM_USER_FILE_READ_BYTES } from './working-copy-capture.dto'

const digest = /^sha256:[0-9a-f]{64}$/
const captureId = /^daytona-sandbox-file-capture:v1:sha256:[0-9a-f]{64}$/
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

function exact(value: unknown, keys: readonly string[]): void {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value)
      .filter((key) => (value as Record<string, unknown>)[key] !== undefined)
      .sort()
      .join('\n') !== [...keys].sort().join('\n')
  )
    throw new Error('Native file capture fields are invalid.')
}

function identity(value: unknown): boolean {
  return typeof value === 'string' && uuid.test(value) && value !== '00000000-0000-0000-0000-000000000000'
}

function requestFields(value: SandboxFileCaptureRequestDto): void {
  if (
    typeof value.operationId !== 'string' ||
    !SANDBOX_FILE_OPERATION_PATTERN.test(value.operationId) ||
    typeof value.path !== 'string' ||
    value.path !== toUSVString(value.path) ||
    Buffer.byteLength(value.path) > 4096 ||
    !['/workspace/work/', '/workspace/outputs/'].some(
      (root) => value.path.startsWith(root) && value.path.length > root.length,
    ) ||
    posix.normalize(value.path) !== value.path ||
    value.path.endsWith('/') ||
    /[\\\p{Cc}]/u.test(value.path) ||
    value.path.split('/').some((part) => Buffer.byteLength(part) > 255)
  )
    throw new Error('Native capture requires an operation key and a canonical work or outputs file path.')
}

export function assertSandboxFileRequest(value: SandboxFileCaptureRequestDto): void {
  exact(value, ['operationId', 'path'])
  requestFields(value)
}

export function assertSandboxFileObserveRequest(value: SandboxFileCaptureObserveRequestDto): void {
  if (value?.path !== undefined) assertSandboxFileRequest(value as SandboxFileCaptureRequestDto)
  else {
    exact(value, ['operationId'])
    if (typeof value.operationId !== 'string' || !SANDBOX_FILE_OPERATION_PATTERN.test(value.operationId))
      throw new Error('Native capture operation key is invalid.')
  }
}

export function assertSandboxFileReceipt(
  value: SandboxFileCaptureReceiptDto,
  expected: {
    organizationId: string
    sandboxId: string
    operationId?: string
    path?: string
  },
): void {
  exact(value, [
    'contract',
    'captureId',
    'operationId',
    'organizationId',
    'sandboxId',
    'path',
    'generation',
    'component',
    'totalByteLength',
    'sha256',
    'capturedAt',
  ])
  requestFields(value)
  if (
    value.contract !== SANDBOX_FILE_CAPTURE_CONTRACT ||
    !captureId.test(value.captureId) ||
    !identity(value.organizationId) ||
    !identity(value.sandboxId) ||
    value.organizationId !== expected.organizationId ||
    value.sandboxId !== expected.sandboxId ||
    (expected.operationId !== undefined && value.operationId !== expected.operationId) ||
    (expected.path !== undefined && value.path !== expected.path) ||
    !Number.isSafeInteger(value.totalByteLength) ||
    value.totalByteLength < 0 ||
    value.totalByteLength > MAXIMUM_USER_FILE_CAPTURE_BYTES ||
    !digest.test(value.sha256) ||
    typeof value.capturedAt !== 'string' ||
    !Number.isFinite(Date.parse(value.capturedAt)) ||
    new Date(value.capturedAt).toISOString() !== value.capturedAt
  )
    throw new Error('Native capture receipt authority or bounds differ.')
  assertExpectedGeneration(value.generation)
  exact(value.component, ['roleRef', 'protocol', 'helper'])
  exact(value.component.protocol, ['ref', 'digest'])
  exact(value.component.helper, ['ref', 'digest'])
  if (
    value.component.roleRef !== 'ambit.runtime-component/working-copy-capture@2' ||
    value.component.protocol.ref !== 'ambit.runtime-interface/working-copy-capture@2' ||
    !digest.test(value.component.protocol.digest) ||
    !digest.test(value.component.helper.digest) ||
    value.component.helper.ref !== `runtime-component-artifact:${value.component.helper.digest}`
  )
    throw new Error('Native capture component measurement is invalid.')
}

export function assertSandboxFileObservation(
  value: SandboxFileCaptureObservationDto,
  expected: Parameters<typeof assertSandboxFileReceipt>[1],
): void {
  exact(value, value?.status === 'complete' ? ['status', 'receipt'] : ['status'])
  if (!['absent', 'pending', 'complete', 'retired'].includes(value.status))
    throw new Error('Native capture observation state is invalid.')
  if (value.status === 'complete') assertSandboxFileReceipt(value.receipt, expected)
}

export function assertSandboxFileReadRequest(value: SandboxFileCaptureReadRequestDto): void {
  exact(value, ['receipt', 'offset', 'maximumBytes'])
  if (
    !Number.isSafeInteger(value.offset) ||
    value.offset < 0 ||
    !Number.isSafeInteger(value.maximumBytes) ||
    value.maximumBytes < 1 ||
    value.maximumBytes > MAXIMUM_USER_FILE_READ_BYTES ||
    value.offset > value.receipt?.totalByteLength
  )
    throw new Error('Native capture read bounds are invalid.')
}

export function assertSandboxFileReadResponse(
  value: SandboxFileCaptureReadResponseDto,
  expected: SandboxFileCaptureReadRequestDto,
): void {
  exact(value, ['captureId', 'totalByteLength', 'sha256', 'offset', 'byteLength', 'eof', 'bytesBase64'])
  const length = Math.min(expected.maximumBytes, expected.receipt.totalByteLength - expected.offset)
  if (
    value.captureId !== expected.receipt.captureId ||
    value.totalByteLength !== expected.receipt.totalByteLength ||
    value.sha256 !== expected.receipt.sha256 ||
    value.offset !== expected.offset ||
    value.byteLength !== length ||
    value.eof !== (expected.offset + length === expected.receipt.totalByteLength) ||
    typeof value.bytesBase64 !== 'string' ||
    value.bytesBase64.length !== Math.ceil(length / 3) * 4
  )
    throw new Error('Native capture range identity or bounds changed.')
  const bytes = Buffer.from(value.bytesBase64, 'base64')
  if (bytes.byteLength !== length || bytes.toString('base64') !== value.bytesBase64)
    throw new Error('Native capture range bytes are not canonical.')
}

export function assertSandboxFileDeleteRequest(value: SandboxFileCaptureDeleteRequestDto): void {
  if (value?.receipt !== undefined) {
    exact(value, ['receipt'])
    if (!value.receipt) throw new Error('Native capture deletion receipt is absent.')
  } else assertSandboxFileObserveRequest(value as SandboxFileCaptureObserveRequestDto)
}

export function assertSandboxFileDeleteReceipt(
  value: SandboxFileCaptureDeleteReceiptDto,
  expected?: SandboxFileCaptureReceiptDto,
): void {
  exact(value, ['captureId', 'outcome'])
  if (
    !['deleted', 'already_absent'].includes(value.outcome) ||
    (value.captureId !== null && !captureId.test(value.captureId)) ||
    (value.outcome === 'deleted' && value.captureId === null) ||
    (expected && value.captureId !== null && value.captureId !== expected.captureId)
  )
    throw new Error('Native capture deletion identity or outcome differs.')
}
