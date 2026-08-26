/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { EventEmitter } from 'node:events'
import { IncomingMessage } from 'node:http'

import type { OrganizationAuthContext } from '../../common/interfaces/organization-auth-context.interface'
import type { StoppedWorkingCopyDirectoryRosterRequestDto } from '../dto/working-copy-capture.dto'
import type { WorkingCopyCaptureService } from '../services/working-copy-capture.service'
import { WorkingCopyCaptureController } from './working-copy-capture.controller'

describe(`${WorkingCopyCaptureController.name} cancellation`, () => {
  it('propagates an aborted inbound request to the stopped runner traversal', async () => {
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

    const pending = controller.stoppedDirectoryRoster(
      { organizationId: 'daytona-org-1' } as OrganizationAuthContext,
      'sandbox-1',
      {} as StoppedWorkingCopyDirectoryRosterRequestDto,
      incoming,
    )
    incoming.emit('aborted')

    await expect(pending).rejects.toBe(aborted)
    expect(forwardedSignal?.aborted).toBe(true)
    expect(captures.stoppedDirectoryRoster).toHaveBeenCalledTimes(1)
  })
})
