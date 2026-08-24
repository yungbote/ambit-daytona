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
import { PassThrough, Readable } from 'node:stream'

import { strictCanonicalJsonStringify } from '../../common/utils/strict-canonical-json'
import {
  SandboxProviderGenerationObservationRequestDto,
  SandboxSpecialistRenderObserveRequestDto,
  SandboxSpecialistRenderRequestAuthority,
} from '../dto/sandbox-specialist-render.dto'
import { SandboxState } from '../enums/sandbox-state.enum'
import { RunnerApiError } from '../errors/runner-api-error'
import {
  RunnerSpecialistRenderStreamResponse,
  RunnerSpecialistRenderTransport,
} from '../runner-adapter/runner-specialist-render.transport'
import { SandboxExecutionAuthorityService } from './sandbox-execution-authority.service'

const MAXIMUM_PROVIDER_LINE_BYTES = 70_000
const REQUEST_SCHEMA = 'ambit.runtime-provider-specialist-render-request/v1'
const FRAME_SCHEMA = 'ambit.runtime-provider-specialist-render-jsonl@1'

@Injectable()
export class SandboxSpecialistRenderService {
  constructor(
    private readonly authority: SandboxExecutionAuthorityService,
    private readonly transport: RunnerSpecialistRenderTransport,
  ) {}

  async execute(
    organizationId: string,
    sandboxIdOrName: string,
    request: Readable,
    signal: AbortSignal,
  ): Promise<RunnerSpecialistRenderStreamResponse> {
    const admitted = await readProviderStart(request)
    const authorized = await this.authority.authorizeProviderGeneration(
      organizationId,
      sandboxIdOrName,
      admitted.authority.source,
      admitted.authority.owner,
      admitted.authority.fence,
    )
    if (authorized.sandbox.pending || authorized.sandbox.state !== SandboxState.STARTED) {
      throw new ConflictException('Specialist rendering requires one stable running sandbox generation.')
    }
    try {
      return await this.transport.execute(authorized.runner, authorized.sandbox.id, admitted.replay, signal)
    } catch (error) {
      throw translateRunnerError(error, true)
    }
  }

  async observeCurrent(
    organizationId: string,
    sandboxIdOrName: string,
    request: SandboxProviderGenerationObservationRequestDto,
    signal: AbortSignal,
  ): Promise<unknown> {
    exactObservationAuthority(request)
    const authorized = await this.authority.authorizeProviderGeneration(
      organizationId,
      sandboxIdOrName,
      request.source,
      request.owner,
      request.fence,
    )
    if (
      authorized.sandbox.pending ||
      ![SandboxState.STARTED, SandboxState.STOPPED].includes(authorized.sandbox.state)
    ) {
      throw new ConflictException('Sandbox generation is not in a stable running or stopped state.')
    }
    try {
      return await this.transport.observeCurrent(authorized.runner, authorized.sandbox.id, request, signal)
    } catch (error) {
      throw translateRunnerError(error, false)
    }
  }

  async observeRender(
    organizationId: string,
    sandboxIdOrName: string,
    request: SandboxSpecialistRenderObserveRequestDto,
    signal: AbortSignal,
  ): Promise<unknown> {
    exactObserveRequest(request)
    const authorized = await this.authority.authorizeProviderGeneration(
      organizationId,
      sandboxIdOrName,
      request.source,
      request.owner,
      request.fence,
    )
    try {
      return await this.transport.observeRender(authorized.runner, authorized.sandbox.id, request, signal)
    } catch (error) {
      throw translateRunnerError(error, false)
    }
  }
}

type ProviderStart = Readonly<{
  authority: SandboxSpecialistRenderRequestAuthority
  replay: Readable
}>

async function readProviderStart(request: Readable): Promise<ProviderStart> {
  const prefix = await readThroughFirstLF(request)
  const newline = prefix.indexOf(0x0a)
  const line = prefix.subarray(0, newline)
  if (line.byteLength === 0 || line.byteLength + 1 > MAXIMUM_PROVIDER_LINE_BYTES || line.includes(0x0d)) {
    throw new BadRequestException('Specialist-render provider start frame is invalid.')
  }
  let value: unknown
  try {
    const text = line.toString('utf8')
    if (!Buffer.from(text, 'utf8').equals(line)) throw new Error('invalid UTF-8')
    value = JSON.parse(text)
    if (strictCanonicalJsonStringify(value) !== text) throw new Error('noncanonical JSON')
  } catch {
    throw new BadRequestException('Specialist-render provider start frame is not canonical JSON.')
  }
  const frame = exactRecord(value, ['chunkBytes', 'kind', 'request', 'schema'])
  if (frame.schema !== FRAME_SCHEMA || frame.kind !== 'provider_request_start' || frame.chunkBytes !== 49_152) {
    throw new BadRequestException('Specialist-render provider start identity differs.')
  }
  const authority = requestAuthority(frame.request)
  const replay = new PassThrough()
  replay.write(prefix)
  request.on('error', (error) => replay.destroy(error))
  request.pipe(replay)
  request.resume()
  return Object.freeze({ authority, replay })
}

function requestAuthority(value: unknown): SandboxSpecialistRenderRequestAuthority {
  const record = exactRecord(value, [
    'artifactRenderJobRef',
    'composition',
    'executable',
    'executor',
    'expectedParentGeneration',
    'fence',
    'image',
    'interface',
    'operationId',
    'owner',
    'providerPolicy',
    'requestBytes',
    'requestChunkCount',
    'requestFingerprint',
    'requestSha256',
    'schema',
    'source',
    'sourceBytes',
    'sourceChunkCount',
    'sourceSha256',
  ])
  if (record.schema !== REQUEST_SCHEMA) throw new BadRequestException('Specialist-render request schema differs.')
  const source = exactRecord(record.source, ['expectedProfile', 'expectedRuntimeKind', 'providerResourceId'])
  const owner = exactRecord(record.owner, ['grantId', 'runId', 'tenantId', 'userId', 'workspaceId'])
  const fence = exactRecord(record.fence, ['workspaceExecutionManifestRef'])
  exactObservationAuthority({ source, owner, fence } as unknown as SandboxProviderGenerationObservationRequestDto)
  return Object.freeze({
    source: source as unknown as SandboxSpecialistRenderRequestAuthority['source'],
    owner: owner as unknown as SandboxSpecialistRenderRequestAuthority['owner'],
    fence: fence as unknown as SandboxSpecialistRenderRequestAuthority['fence'],
  })
}

function exactObservationAuthority(request: SandboxProviderGenerationObservationRequestDto): void {
  exactKeys(request, ['fence', 'owner', 'source'])
  exactKeys(request.source, ['expectedProfile', 'expectedRuntimeKind', 'providerResourceId'])
  exactKeys(request.owner, ['grantId', 'runId', 'tenantId', 'userId', 'workspaceId'])
  exactKeys(request.fence, ['workspaceExecutionManifestRef'])
  if (
    typeof request.source.providerResourceId !== 'string' ||
    typeof request.source.expectedProfile !== 'string' ||
    !['base_profile', 'full_image_runtime_pack'].includes(request.source.expectedRuntimeKind) ||
    !Object.values(request.owner).every((value) => typeof value === 'string') ||
    typeof request.fence.workspaceExecutionManifestRef !== 'string'
  ) {
    throw new BadRequestException('Specialist-render provider authority is invalid.')
  }
}

function exactObserveRequest(request: SandboxSpecialistRenderObserveRequestDto): void {
  exactKeys(request, ['fence', 'operationId', 'owner', 'requestFingerprint', 'schema', 'source'])
  exactObservationAuthority({ source: request.source, owner: request.owner, fence: request.fence })
  if (
    request.schema !== 'ambit.runtime-provider-specialist-render-observe-request/v1' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(request.operationId) ||
    !/^[0-9a-f]{64}$/.test(request.requestFingerprint)
  ) {
    throw new BadRequestException('Specialist-render observe request is invalid.')
  }
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new BadRequestException('Specialist-render provider record is invalid.')
  }
  exactKeys(value as Record<string, unknown>, keys)
  return value as Record<string, unknown>
}

function exactKeys(value: object, keys: readonly string[]): void {
  if (Object.keys(value).sort().join('\n') !== [...keys].sort().join('\n')) {
    throw new BadRequestException('Specialist-render provider fields differ.')
  }
}

function readThroughFirstLF(request: Readable): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buffered = Buffer.alloc(0)
    const cleanup = () => {
      request.off('data', onData)
      request.off('end', onEnd)
      request.off('error', onError)
    }
    const onData = (chunk: Buffer | string) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      buffered = Buffer.concat([buffered, bytes])
      const newline = buffered.indexOf(0x0a)
      if (newline < 0 && buffered.byteLength >= MAXIMUM_PROVIDER_LINE_BYTES) {
        cleanup()
        request.pause()
        reject(new BadRequestException('Specialist-render provider start frame exceeds its bound.'))
        return
      }
      if (newline >= 0) {
        cleanup()
        request.pause()
        resolve(buffered)
      }
    }
    const onEnd = () => {
      cleanup()
      reject(new BadRequestException('Specialist-render provider stream ended before its first frame.'))
    }
    const onError = (error: Error) => {
      cleanup()
      reject(error)
    }
    request.on('data', onData)
    request.once('end', onEnd)
    request.once('error', onError)
    request.resume()
  })
}

function translateRunnerError(error: unknown, mutating: boolean): unknown {
  if (!(error instanceof RunnerApiError)) {
    return new ServiceUnavailableException({
      statusCode: 503,
      message: mutating
        ? 'Specialist-render outcome is unknown; observe the exact operation before retrying.'
        : 'The sandbox runner specialist-render provider is unavailable.',
      error: 'Service Unavailable',
      code: mutating ? 'SPECIALIST_RENDER_OUTCOME_UNKNOWN' : 'SPECIALIST_RENDER_UNAVAILABLE',
    })
  }
  switch (error.statusCode) {
    case 400:
      return new BadRequestException(error.message)
    case 404:
      return new NotFoundException(error.message)
    case 409:
      return new ConflictException(error.message)
    default:
      return new ServiceUnavailableException({
        statusCode: 503,
        message: mutating
          ? 'Specialist-render outcome is unknown; observe the exact operation before retrying.'
          : error.message,
        error: 'Service Unavailable',
        code: mutating ? 'SPECIALIST_RENDER_OUTCOME_UNKNOWN' : 'SPECIALIST_RENDER_UNAVAILABLE',
      })
  }
}
