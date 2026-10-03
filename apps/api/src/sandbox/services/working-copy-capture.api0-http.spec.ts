import { readFileSync } from 'node:fs'
import { ConflictException } from '@nestjs/common'
import { Sandbox } from '../entities/sandbox.entity'
import { Runner } from '../entities/runner.entity'
import { SandboxClass } from '../enums/sandbox-class.enum'
import { SandboxState } from '../enums/sandbox-state.enum'
import { RunnerAdapterFactory } from '../runner-adapter/runnerAdapter'
import { RunnerAdapterV0 } from '../runner-adapter/runnerAdapter.v0'
import { RunnerAdapterV2 } from '../runner-adapter/runnerAdapter.v2'
import { SandboxExecutionAuthorityService } from './sandbox-execution-authority.service'
import { RunnerService } from './runner.service'
import { SandboxService } from './sandbox.service'
import { WorkingCopyCaptureService } from './working-copy-capture.service'
import { WorkingCopyCaptureCapabilitiesRequestDto } from '../dto/working-copy-capture.dto'

jest.mock('./sandbox.service', () => ({ SandboxService: jest.fn() }))
jest.mock('./runner.service', () => ({ RunnerService: jest.fn() }))

describe('declared API0 refuses actual R1 component replies', () => {
  it.each(['v0', 'v2'])('rejects R1 through the %s generated adapter', async (version) => {
    const path = process.env.AMBIT_CAPTURE_HTTP_FIXTURE
    if (!path) throw new Error('Actual Runner fixture is required.')
    const fixture = JSON.parse(readFileSync(path, 'utf8')) as {
      url: string
      sandbox: Pick<Sandbox, 'id' | 'organizationId' | 'runnerId' | 'labels'>
      request: WorkingCopyCaptureCapabilitiesRequestDto
    }
    const unused = {} as never
    const adapter = version === 'v0' ? new RunnerAdapterV0() : new RunnerAdapterV2(unused, unused, unused)
    const runner = { id: 'runner-1', apiUrl: fixture.url, apiKey: 'nosecret-local-test' } as Runner
    await adapter.init(runner)
    const sandbox = { ...fixture.sandbox, sandboxClass: SandboxClass.CONTAINER, state: SandboxState.STOPPED } as Sandbox
    const authority = new SandboxExecutionAuthorityService(
      { findOneByIdOrName: jest.fn().mockResolvedValue(sandbox) } as unknown as SandboxService,
      { findOneOrFail: jest.fn().mockResolvedValue(runner) } as unknown as RunnerService,
      { create: jest.fn().mockResolvedValue(adapter) } as unknown as RunnerAdapterFactory,
    )
    const service = new WorkingCopyCaptureService(authority)
    await expect(service.capabilities(sandbox.organizationId, sandbox.id, fixture.request)).rejects.toBeInstanceOf(
      ConflictException,
    )
  })
})
