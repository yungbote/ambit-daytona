/* Copyright 2026 Ambit. SPDX-License-Identifier: AGPL-3.0 */

import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  ServiceUnavailableException,
  ValidationPipe,
} from '@nestjs/common'
import { WorkingCopyCaptureService } from './working-copy-capture.service'
import { SandboxExecutionAuthorityService } from './sandbox-execution-authority.service'
import { SandboxService } from './sandbox.service'
import { RunnerService } from './runner.service'
import { RunnerAdapter, RunnerAdapterFactory } from '../runner-adapter/runnerAdapter'
import { SandboxClass } from '../enums/sandbox-class.enum'
import {
  SandboxFileCaptureReceiptDto,
  SandboxFileCaptureDeleteRequestDto,
  SandboxFileCaptureReadRequestDto,
  SandboxFileCaptureObserveRequestDto,
} from '../dto/sandbox-file-capture.dto'

const ORGANIZATION = '11111111-1111-4111-8111-111111111111'
const SANDBOX = '22222222-2222-4222-8222-222222222222'
const request = { operationId: 'browser.download-1', path: '/workspace/outputs/downloads/report.pdf' }

function receipt(): SandboxFileCaptureReceiptDto {
  return {
    contract: 'daytona.sandbox-file-capture/v1',
    captureId: `daytona-sandbox-file-capture:v1:sha256:${'a'.repeat(64)}`,
    ...request,
    organizationId: ORGANIZATION,
    sandboxId: SANDBOX,
    generation: {
      containerId: 'b'.repeat(64),
      containerCreatedAt: '2026-09-16T12:00:00.000Z',
      executionStartedAt: '2026-09-16T12:00:01.000Z',
      restartCount: 0,
    },
    component: {
      roleRef: 'ambit.runtime-component/working-copy-capture@2',
      protocol: { ref: 'ambit.runtime-interface/working-copy-capture@2', digest: `sha256:${'c'.repeat(64)}` },
      helper: { ref: `runtime-component-artifact:sha256:${'d'.repeat(64)}`, digest: `sha256:${'d'.repeat(64)}` },
    },
    totalByteLength: 5,
    sha256: `sha256:${'e'.repeat(64)}`,
    capturedAt: '2026-09-16T12:01:00.000Z',
  }
}

describe('native sandbox file capture authority', () => {
  let adapter: jest.Mocked<RunnerAdapter>
  let sandboxes: { findOneByIdOrName: jest.Mock }
  let runners: { findOneOrFail: jest.Mock }
  let service: WorkingCopyCaptureService

  beforeEach(() => {
    adapter = {
      captureSandboxFile: jest.fn(),
      observeSandboxFile: jest.fn(),
      readSandboxFile: jest.fn(),
      deleteSandboxFile: jest.fn(),
      captureWorkingCopy: jest.fn(),
    } as unknown as jest.Mocked<RunnerAdapter>
    sandboxes = {
      findOneByIdOrName: jest.fn().mockResolvedValue({
        id: SANDBOX,
        organizationId: ORGANIZATION,
        runnerId: 'assigned-runner',
        sandboxClass: SandboxClass.CONTAINER,
        labels: {},
      }),
    }
    runners = { findOneOrFail: jest.fn().mockResolvedValue({ id: 'assigned-runner', apiUrl: 'https://runner.test' }) }
    service = new WorkingCopyCaptureService(
      new SandboxExecutionAuthorityService(
        sandboxes as unknown as SandboxService,
        runners as unknown as RunnerService,
        { create: jest.fn().mockResolvedValue(adapter) } as unknown as RunnerAdapterFactory,
      ),
    )
  })

  it('derives native scope from actual sandbox ownership without a Product Run or component claim', async () => {
    const expected = receipt()
    adapter.captureSandboxFile.mockResolvedValue(expected)
    const signal = new AbortController().signal
    await expect(service.captureSandboxFile(ORGANIZATION, 'display-name', request, signal)).resolves.toEqual(expected)
    expect(sandboxes.findOneByIdOrName).toHaveBeenCalledWith('display-name', ORGANIZATION)
    expect(runners.findOneOrFail).toHaveBeenCalledWith('assigned-runner')
    expect(adapter.captureSandboxFile).toHaveBeenCalledWith(
      SANDBOX,
      { ...request, organizationId: ORGANIZATION },
      signal,
    )
    expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
  })

  it.each(['organizationId', 'source', 'owner', 'generation', 'component', 'grantId', 'authority'])(
    'rejects caller-supplied %s authority before dispatch',
    async (field) => {
      await expect(
        service.captureSandboxFile(ORGANIZATION, SANDBOX, { ...request, [field]: 'invented' }),
      ).rejects.toBeInstanceOf(BadRequestException)
      expect(adapter.captureSandboxFile).not.toHaveBeenCalled()
    },
  )

  it.each([
    '/etc/shadow',
    '/workspace/work',
    '/workspace/outputs/../work/x',
    '/workspace/outputs/x/',
    '/workspace/outputs//x',
    '/workspace/outputs/x\\y',
    '/workspace/outputs/x\u0000',
  ])('rejects inadmissible native path %s', async (path) => {
    await expect(service.captureSandboxFile(ORGANIZATION, SANDBOX, { ...request, path })).rejects.toBeInstanceOf(
      BadRequestException,
    )
    expect(adapter.captureSandboxFile).not.toHaveBeenCalled()
  })

  it('cannot recover denied native organization ownership by using a Product adapter', async () => {
    sandboxes.findOneByIdOrName.mockRejectedValue(new ForbiddenException())
    await expect(service.captureSandboxFile(ORGANIZATION, SANDBOX, request)).rejects.toBeInstanceOf(ForbiddenException)
    expect(adapter.captureSandboxFile).not.toHaveBeenCalled()
    expect(adapter.captureWorkingCopy).not.toHaveBeenCalled()
  })

  it.each(['organizationId', 'sandboxId', 'operationId', 'path'])(
    'rejects a Runner receipt for another %s',
    async (field) => {
      adapter.captureSandboxFile.mockResolvedValue({ ...receipt(), [field]: 'other' })
      const outcome = await service.captureSandboxFile(ORGANIZATION, SANDBOX, request).catch((error) => error)
      expect(outcome).toBeInstanceOf(ServiceUnavailableException)
      expect(outcome.getResponse()).toMatchObject({ code: 'WORKING_COPY_CAPTURE_OUTCOME_UNKNOWN' })
    },
  )

  it('forwards bounded immutable reads only for the current native sandbox owner', async () => {
    const read = { receipt: receipt(), offset: 0, maximumBytes: 3 }
    const result = {
      captureId: read.receipt.captureId,
      totalByteLength: 5,
      sha256: read.receipt.sha256,
      offset: 0,
      byteLength: 3,
      eof: false,
      bytesBase64: Buffer.from('abc').toString('base64'),
    }
    adapter.readSandboxFile.mockResolvedValue(result)
    await expect(service.readSandboxFile(ORGANIZATION, SANDBOX, read)).resolves.toEqual(result)
    expect(adapter.readSandboxFile).toHaveBeenCalledWith(SANDBOX, read, undefined)
    adapter.readSandboxFile.mockClear()
    await expect(
      service.readSandboxFile(ORGANIZATION, SANDBOX, {
        ...read,
        receipt: { ...read.receipt, organizationId: SANDBOX },
      }),
    ).rejects.toBeInstanceOf(BadRequestException)
    expect(adapter.readSandboxFile).not.toHaveBeenCalled()
  })

  it('rejects malformed or overlong range responses', async () => {
    const read = { receipt: receipt(), offset: 0, maximumBytes: 3 }
    adapter.readSandboxFile.mockResolvedValue({
      captureId: read.receipt.captureId,
      totalByteLength: 5,
      sha256: read.receipt.sha256,
      offset: 0,
      byteLength: 3,
      eof: false,
      bytesBase64: 'YWJj====',
    })
    await expect(service.readSandboxFile(ORGANIZATION, SANDBOX, read)).rejects.toBeInstanceOf(ConflictException)
  })

  it('observes pending state without inventing a receipt', async () => {
    adapter.observeSandboxFile.mockResolvedValue({ status: 'pending' })
    await expect(service.observeSandboxFile(ORGANIZATION, SANDBOX, request)).resolves.toEqual({ status: 'pending' })
    adapter.observeSandboxFile.mockResolvedValue({ status: 'pending', receipt: receipt() })
    await expect(service.observeSandboxFile(ORGANIZATION, SANDBOX, request)).rejects.toBeInstanceOf(ConflictException)
  })

  it('recovers retained capture by operation without requiring the browser source path', async () => {
    const pipe = new ValidationPipe({ transform: true })
    const lookup = await pipe.transform(
      { operationId: request.operationId },
      { type: 'body', metatype: SandboxFileCaptureObserveRequestDto },
    )
    adapter.observeSandboxFile.mockResolvedValue({ status: 'complete', receipt: receipt() })
    await expect(service.observeSandboxFile(ORGANIZATION, SANDBOX, lookup)).resolves.toMatchObject({
      status: 'complete',
      receipt: receipt(),
    })
    expect(adapter.observeSandboxFile).toHaveBeenCalledWith(
      SANDBOX,
      { ...lookup, organizationId: ORGANIZATION },
      undefined,
    )
    await expect(
      service.observeSandboxFile(ORGANIZATION, SANDBOX, {
        operationId: request.operationId,
        path: '/workspace/outputs/other.pdf',
      }),
    ).rejects.toBeInstanceOf(ConflictException)
  })

  it('retires a pending operation with native scope and no fabricated receipt', async () => {
    adapter.deleteSandboxFile.mockResolvedValue({ captureId: null, outcome: 'already_absent' })
    await expect(service.deleteSandboxFile(ORGANIZATION, SANDBOX, request)).resolves.toEqual({
      captureId: null,
      outcome: 'already_absent',
    })
    expect(adapter.deleteSandboxFile).toHaveBeenCalledWith(
      SANDBOX,
      { ...request, organizationId: ORGANIZATION },
      undefined,
    )
  })

  it('retries retired cleanup by operation without resolving a source path', async () => {
    const operation = { operationId: request.operationId }
    adapter.deleteSandboxFile.mockResolvedValue({ captureId: receipt().captureId, outcome: 'deleted' })
    await expect(service.deleteSandboxFile(ORGANIZATION, SANDBOX, operation)).resolves.toEqual({
      captureId: receipt().captureId,
      outcome: 'deleted',
    })
    expect(adapter.deleteSandboxFile).toHaveBeenCalledWith(
      SANDBOX,
      { ...operation, organizationId: ORGANIZATION },
      undefined,
    )
    expect(adapter.observeSandboxFile).not.toHaveBeenCalled()
    expect(adapter.captureSandboxFile).not.toHaveBeenCalled()
  })

  it('accepts the actual production DTO transformation for pending and completed work', async () => {
    const pipe = new ValidationPipe({ transform: true })
    const pending = await pipe.transform(request, { type: 'body', metatype: SandboxFileCaptureDeleteRequestDto })
    adapter.deleteSandboxFile.mockResolvedValue({ captureId: null, outcome: 'already_absent' })
    await expect(service.deleteSandboxFile(ORGANIZATION, SANDBOX, pending)).resolves.toEqual({
      captureId: null,
      outcome: 'already_absent',
    })
    const completed = await pipe.transform(
      { receipt: receipt() },
      { type: 'body', metatype: SandboxFileCaptureDeleteRequestDto },
    )
    await expect(service.deleteSandboxFile(ORGANIZATION, SANDBOX, completed)).resolves.toEqual({
      captureId: null,
      outcome: 'already_absent',
    })
    const read = await pipe.transform(
      { receipt: receipt(), offset: 5, maximumBytes: 1 },
      { type: 'body', metatype: SandboxFileCaptureReadRequestDto },
    )
    adapter.readSandboxFile.mockResolvedValue({
      captureId: read.receipt.captureId,
      totalByteLength: 5,
      sha256: read.receipt.sha256,
      offset: 5,
      byteLength: 0,
      eof: true,
      bytesBase64: '',
    })
    await expect(service.readSandboxFile(ORGANIZATION, SANDBOX, read)).resolves.toMatchObject({
      eof: true,
      byteLength: 0,
    })
  })

  it('requires reconciliation when a mutating cleanup reply is malformed', async () => {
    adapter.deleteSandboxFile.mockResolvedValue({ captureId: null, outcome: 'deleted' })
    const outcome = await service
      .deleteSandboxFile(ORGANIZATION, SANDBOX, { operationId: request.operationId })
      .catch((error) => error)
    expect(outcome).toBeInstanceOf(ServiceUnavailableException)
    expect(outcome.getResponse()).toMatchObject({ code: 'WORKING_COPY_CAPTURE_OUTCOME_UNKNOWN' })
  })

  it('refuses ambiguous deletion and honors already-aborted requests', async () => {
    await expect(
      service.deleteSandboxFile(ORGANIZATION, SANDBOX, { ...request, receipt: receipt() }),
    ).rejects.toBeInstanceOf(BadRequestException)
    const cancellation = new AbortController()
    cancellation.abort(new Error('canceled'))
    await expect(service.captureSandboxFile(ORGANIZATION, SANDBOX, request, cancellation.signal)).rejects.toThrow(
      'canceled',
    )
    expect(adapter.captureSandboxFile).not.toHaveBeenCalled()
    expect(adapter.deleteSandboxFile).not.toHaveBeenCalled()
  })
})
