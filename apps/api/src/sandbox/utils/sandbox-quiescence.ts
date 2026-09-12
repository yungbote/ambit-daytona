/*
 * Copyright 2026 Ambit Platforms
 * SPDX-License-Identifier: AGPL-3.0
 */

import { SandboxState } from '../enums/sandbox-state.enum'
import { SandboxDesiredState } from '../enums/sandbox-desired-state.enum'

export const QUIESCENT_SANDBOX_STATES: SandboxState[] = [
  SandboxState.STOPPED,
  SandboxState.ARCHIVED,
  SandboxState.DESTROYED,
]

export function isSandboxQuiescent(sandbox: {
  state: SandboxState
  desiredState: SandboxDesiredState
  pending: boolean | undefined
}): boolean {
  return (
    sandbox.pending === false &&
    String(sandbox.state) === String(sandbox.desiredState) &&
    QUIESCENT_SANDBOX_STATES.includes(sandbox.state)
  )
}
