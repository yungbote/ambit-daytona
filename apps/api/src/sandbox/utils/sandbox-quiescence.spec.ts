/*
 * Copyright 2026 Ambit Platforms
 * SPDX-License-Identifier: AGPL-3.0
 */

import { SandboxState } from '../enums/sandbox-state.enum'
import { SandboxDesiredState } from '../enums/sandbox-desired-state.enum'
import { isSandboxQuiescent } from './sandbox-quiescence'

describe('sandbox quiescence', () => {
  it.each([
    [SandboxState.STOPPED, SandboxDesiredState.STOPPED],
    [SandboxState.ARCHIVED, SandboxDesiredState.ARCHIVED],
    [SandboxState.DESTROYED, SandboxDesiredState.DESTROYED],
  ] as const)('only accepts settled %s', (state, desiredState) => {
    expect(isSandboxQuiescent({ state, desiredState, pending: false })).toBe(true)
    expect(isSandboxQuiescent({ state, desiredState, pending: true })).toBe(false)
    expect(isSandboxQuiescent({ state, desiredState, pending: undefined })).toBe(false)
    expect(isSandboxQuiescent({ state, desiredState: SandboxDesiredState.STARTED, pending: false })).toBe(false)
  })

  it.each(Object.values(SandboxState).filter((state) => !['stopped', 'archived', 'destroyed'].includes(state)))(
    'treats %s as busy even without a pending marker',
    (state) => {
      for (const desiredState of Object.values(SandboxDesiredState)) {
        expect(isSandboxQuiescent({ state, desiredState, pending: false })).toBe(false)
      }
    },
  )
})
