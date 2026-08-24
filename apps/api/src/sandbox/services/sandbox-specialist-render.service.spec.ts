/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { readFileSync } from 'node:fs'
import { Readable } from 'node:stream'

import { strictCanonicalJsonStringify } from '../../common/utils/strict-canonical-json'
import { SandboxState } from '../enums/sandbox-state.enum'
import { SPECIALIST_RENDER_CONTENT_TYPE } from '../runner-adapter/runner-specialist-render.transport'
import { SandboxSpecialistRenderService } from './sandbox-specialist-render.service'

jest.mock('./sandbox-execution-authority.service', () => ({
  SandboxExecutionAuthorityService: class {},
}))

describe('SandboxSpecialistRenderService', () => {
  it('authorizes the first canonical frame and forwards every original byte once', async () => {
    const receipt = JSON.parse(
      readFileSync('apps/runner/pkg/specialistrender/testdata/provider-contract-golden.json', 'utf8'),
    ) as { request: Record<string, unknown> }
    const start = strictCanonicalJsonStringify({
      schema: 'ambit.runtime-provider-specialist-render-jsonl@1',
      kind: 'provider_request_start',
      chunkBytes: 49_152,
      request: receipt.request,
    })
    const wire = Buffer.from(`${start}\nremaining-frame\n`)
    const authorizeProviderGeneration = jest.fn().mockResolvedValue({
      sandbox: { id: 'sandbox', state: SandboxState.STARTED, pending: false },
      runner: { id: 'runner', apiUrl: 'http://runner', apiKey: 'secret' },
    })
    const execute = jest.fn().mockImplementation(async (_runner, sandboxId, body: Readable) => {
      const chunks: Buffer[] = []
      for await (const chunk of body) chunks.push(Buffer.from(chunk))
      expect(sandboxId).toBe('sandbox')
      expect(Buffer.concat(chunks)).toEqual(wire)
      return {
        status: 200,
        contentType: SPECIALIST_RENDER_CONTENT_TYPE,
        body: Readable.from(['response']),
      }
    })
    const service = new SandboxSpecialistRenderService({ authorizeProviderGeneration } as never, { execute } as never)

    const result = await service.execute(
      'organization',
      'sandbox',
      Readable.from([wire.subarray(0, 17), wire.subarray(17)]),
      new AbortController().signal,
    )

    expect(result.status).toBe(200)
    expect(authorizeProviderGeneration).toHaveBeenCalledWith(
      'organization',
      'sandbox',
      receipt.request.source,
      receipt.request.owner,
      receipt.request.fence,
    )
    expect(execute).toHaveBeenCalledTimes(1)
  })

  it('rejects a noncanonical or oversized first frame before provider authority', async () => {
    const authorizeProviderGeneration = jest.fn()
    const service = new SandboxSpecialistRenderService(
      { authorizeProviderGeneration } as never,
      { execute: jest.fn() } as never,
    )
    await expect(
      service.execute(
        'organization',
        'sandbox',
        Readable.from([Buffer.from('{ "schema": "wrong" }\n')]),
        new AbortController().signal,
      ),
    ).rejects.toThrow('canonical JSON')
    await expect(
      service.execute(
        'organization',
        'sandbox',
        Readable.from([Buffer.alloc(70_000, 0x78)]),
        new AbortController().signal,
      ),
    ).rejects.toThrow('exceeds its bound')
    expect(authorizeProviderGeneration).not.toHaveBeenCalled()
  })
})
