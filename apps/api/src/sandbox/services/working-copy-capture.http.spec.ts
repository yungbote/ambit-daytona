/*
 * Copyright 2026 Ambit
 * SPDX-License-Identifier: AGPL-3.0
 */

import { readFileSync } from 'node:fs'
import { BadRequestException, ForbiddenException } from '@nestjs/common'
import { Sandbox } from '../entities/sandbox.entity'
import { Runner } from '../entities/runner.entity'
import { SandboxClass } from '../enums/sandbox-class.enum'
import { SandboxState } from '../enums/sandbox-state.enum'
import { RunnerAdapterFactory } from '../runner-adapter/runnerAdapter'
import { RunnerAdapterV0 } from '../runner-adapter/runnerAdapter.v0'
import { RunnerAdapterV2 } from '../runner-adapter/runnerAdapter.v2'
import {
  WorkingCopyCaptureBindingDto,
  WorkingCopyCaptureCapabilitiesRequestDto,
  WorkingCopyCaptureComponentDto,
  MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES,
} from '../dto/working-copy-capture.dto'
import { SandboxExecutionAuthorityService } from './sandbox-execution-authority.service'
import { RunnerService } from './runner.service'
import { SandboxService } from './sandbox.service'
import { WorkingCopyCaptureService } from './working-copy-capture.service'

jest.mock('./sandbox.service', () => ({ SandboxService: jest.fn() }))
jest.mock('./runner.service', () => ({ RunnerService: jest.fn() }))

const fixturePath = process.env.AMBIT_CAPTURE_HTTP_FIXTURE
const realBoundary = fixturePath ? describe : describe.skip

realBoundary('working copy capture through real Runner HTTP, Docker and MinIO', () => {
  let fixture: {
    url: string
    sandbox: Pick<Sandbox, 'id' | 'organizationId' | 'runnerId' | 'labels'>
    request: WorkingCopyCaptureCapabilitiesRequestDto
    binding: WorkingCopyCaptureBindingDto
    component: WorkingCopyCaptureComponentDto
  }

  beforeAll(() => {
    if (!fixturePath) throw new Error('Real Runner fixture is required.')
    fixture = JSON.parse(readFileSync(fixturePath, 'utf8'))
  })

  it.each(['v0', 'v2'])('uses %s generated clients and retains exact custody across replay', async (version) => {
    const unusedLifecycleDependency = {} as never
    const adapter =
      version === 'v0'
        ? new RunnerAdapterV0()
        : new RunnerAdapterV2(unusedLifecycleDependency, unusedLifecycleDependency, unusedLifecycleDependency)
    const runner = { id: 'runner-1', apiUrl: fixture.url, apiKey: 'nosecret-local-test' } as Runner
    await adapter.init(runner)
    const sandbox = {
      ...fixture.sandbox,
      sandboxClass: SandboxClass.CONTAINER,
      state: SandboxState.STOPPED,
    } as Sandbox
    const sandboxes = { findOneByIdOrName: jest.fn().mockResolvedValue(sandbox) }
    const runners = { findOneOrFail: jest.fn().mockResolvedValue(runner) }
    const adapters = { create: jest.fn().mockResolvedValue(adapter) }
    const authority = new SandboxExecutionAuthorityService(
      sandboxes as unknown as SandboxService,
      runners as unknown as RunnerService,
      adapters as unknown as RunnerAdapterFactory,
    )
    const service = new WorkingCopyCaptureService(authority)
    const discovered = await service.capabilities(sandbox.organizationId, sandbox.id, fixture.request)
    expect(discovered.component).toEqual(fixture.component)
    expect(discovered).not.toHaveProperty('authority')
    const noExpected = structuredClone(fixture.request)
    delete noExpected.authority
    expect((await service.capabilities(sandbox.organizationId, sandbox.id, noExpected)).component).toEqual(
      fixture.component,
    )
    const matching = { ...fixture.request, authority: fixture.binding.authority }
    expect((await service.capabilities(sandbox.organizationId, sandbox.id, matching)).authority).toEqual(
      fixture.binding.authority,
    )
    const forged = structuredClone(fixture.request)
    forged.owner.tenantId = '99999999-9999-4999-8999-999999999999'
    await expect(service.capabilities(sandbox.organizationId, sandbox.id, forged)).rejects.toBeInstanceOf(
      ForbiddenException,
    )
    // Bypass the host's authorization once to challenge the Runner's own
    // physical-label proof, rather than proving only the host guard.
    await expect(adapter.workingCopyCaptureCapabilities(sandbox.id, forged)).rejects.toThrow()
    const receipt = await service.capture(sandbox.organizationId, sandbox.id, fixture.binding)
    expect(receipt.authority).toEqual(fixture.binding.authority)
    expect(await service.capture(sandbox.organizationId, sandbox.id, fixture.binding)).toEqual(receipt)
    expect(await service.observe(sandbox.organizationId, sandbox.id, fixture.binding)).toEqual({
      status: 'complete',
      receipt,
    })
    const identity = { ...fixture.binding, providerResourceId: receipt.providerResourceId }
    await expect(
      service.read(sandbox.organizationId, sandbox.id, {
        ...identity,
        expectedTotalByteLength: receipt.totalByteLength,
        expectedProviderSha256Digest: receipt.providerSha256Digest,
        offset: 0,
        maximumBytes: MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES + 1,
      }),
    ).rejects.toBeInstanceOf(BadRequestException)
    const read = await service.read(sandbox.organizationId, sandbox.id, {
      ...identity,
      expectedTotalByteLength: receipt.totalByteLength,
      expectedProviderSha256Digest: receipt.providerSha256Digest,
      offset: 0,
      maximumBytes: MAXIMUM_WORKING_COPY_CAPTURE_READ_BYTES,
    })
    expect(Buffer.from(read.bytesBase64, 'base64').toString()).toBe('immutable HTTP custody')
    const stale = structuredClone(fixture.binding)
    stale.requestFingerprint = 'b'.repeat(64)
    if (!fixture.request.authority) throw new Error('Expected legacy component is required.')
    stale.authority = fixture.request.authority
    await expect(service.capture(sandbox.organizationId, sandbox.id, stale)).rejects.toThrow()
  })
})
