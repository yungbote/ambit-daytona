/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { EventEmitter } from 'node:events'
import { IncomingMessage, ServerResponse } from 'node:http'

import type { OrganizationAuthContext } from '../../common/interfaces/organization-auth-context.interface'
import type { StoppedWorkingCopyDirectoryRosterRequestDto } from '../dto/working-copy-capture.dto'
import type { WorkingCopyCaptureService } from '../services/working-copy-capture.service'
import { WorkingCopyCaptureController } from './working-copy-capture.controller'

describe(`${WorkingCopyCaptureController.name} cancellation`, () => {
  it('does not abort a capture only because the request body was fully consumed', async () => {
    let forwardedSignal: AbortSignal | undefined
    const captures = {
      stoppedDirectoryRoster: jest.fn(
        async (_organizationId: string, _sandboxId: string, _request: unknown, signal?: AbortSignal) => {
          forwardedSignal = signal
          return { ok: true }
        },
      ),
    }
    const controller = new WorkingCopyCaptureController(captures as unknown as WorkingCopyCaptureService)
    const incoming = new EventEmitter() as IncomingMessage
    // Node marks a POST's IncomingMessage destroyed after autoDestroy consumed its body.
    Object.defineProperties(incoming, {
      aborted: { configurable: true, value: false },
      destroyed: { configurable: true, value: true },
    })
    const outgoing = new EventEmitter() as ServerResponse<IncomingMessage>
    Object.defineProperty(outgoing, 'writableEnded', { configurable: true, value: false })
    await controller.stoppedDirectoryRoster(
      { organizationId: 'org' } as OrganizationAuthContext,
      'sandbox',
      {} as StoppedWorkingCopyDirectoryRosterRequestDto,
      incoming,
      outgoing,
    )
    expect(forwardedSignal?.aborted).toBe(false)
  })

  it('cancels the stopped runner traversal when a fully received caller disconnects from the response', async () => {
    let forwardedSignal: AbortSignal | undefined
    const aborted = new Error('runner traversal aborted')
    const captures = {
      stoppedDirectoryRoster: jest.fn(
        (_organizationId: string, _sandboxId: string, _request: unknown, signal?: AbortSignal) => {
          forwardedSignal = signal
          return new Promise((_resolve, reject) => {
            signal?.addEventListener('abort', () => reject(aborted), { once: true })
          })
        },
      ),
    }
    const controller = new WorkingCopyCaptureController(captures as unknown as WorkingCopyCaptureService)
    const incoming = new EventEmitter() as IncomingMessage
    Object.defineProperties(incoming, {
      aborted: { configurable: true, value: false },
      destroyed: { configurable: true, value: false },
    })
    const outgoing = new EventEmitter() as ServerResponse<IncomingMessage>
    Object.defineProperty(outgoing, 'writableEnded', {
      configurable: true,
      value: false,
    })

    const pending = controller.stoppedDirectoryRoster(
      { organizationId: 'daytona-org-1' } as OrganizationAuthContext,
      'sandbox-1',
      {} as StoppedWorkingCopyDirectoryRosterRequestDto,
      incoming,
      outgoing,
    )
    outgoing.emit('close')

    await expect(pending).rejects.toBe(aborted)
    expect(forwardedSignal?.aborted).toBe(true)
    expect(captures.stoppedDirectoryRoster).toHaveBeenCalledTimes(1)
  })
})
