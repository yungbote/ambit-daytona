/* Copyright 2026 Ambit. SPDX-License-Identifier: AGPL-3.0 */

import type { WorkingCopyCaptureComponentDto } from './working-copy-capture.dto'

/** The measured capture component, shared by discovery and native receipts. */
export function assertWorkingCopyCaptureComponent(value: unknown): asserts value is WorkingCopyCaptureComponentDto {
  exact(value, ['roleRef', 'protocol', 'helper'])
  const component = value as WorkingCopyCaptureComponentDto
  exact(component.protocol, ['ref', 'digest'])
  exact(component.helper, ['ref', 'digest'])
  if (
    component.roleRef !== 'ambit.runtime-component/working-copy-capture@2' ||
    component.protocol.ref !== 'ambit.runtime-interface/working-copy-capture@2' ||
    typeof component.protocol.digest !== 'string' ||
    !/^sha256:[0-9a-f]{64}$/.test(component.protocol.digest) ||
    typeof component.helper.digest !== 'string' ||
    !/^sha256:[0-9a-f]{64}$/.test(component.helper.digest) ||
    component.helper.ref !== `runtime-component-artifact:${component.helper.digest}`
  )
    throw new Error('Native capture component measurement is invalid.')
}

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
    throw new Error('Native capture component fields are invalid.')
}
