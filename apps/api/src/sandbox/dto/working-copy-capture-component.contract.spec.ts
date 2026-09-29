/* Copyright 2026 Ambit. SPDX-License-Identifier: AGPL-3.0 */

import { assertWorkingCopyCaptureComponent } from './working-copy-capture-component.contract'

const component = () => ({
  roleRef: 'ambit.runtime-component/working-copy-capture@2',
  protocol: { ref: 'ambit.runtime-interface/working-copy-capture@2', digest: `sha256:${'a'.repeat(64)}` },
  helper: { ref: `runtime-component-artifact:sha256:${'b'.repeat(64)}`, digest: `sha256:${'b'.repeat(64)}` },
})

describe('measured capture component', () => {
  it('admits the same measured shape for discovery and stored file receipts', () => {
    expect(() => assertWorkingCopyCaptureComponent(component())).not.toThrow()
  })

  it.each([
    ['null', () => null],
    ['array', () => [component()]],
    ['extra field', () => ({ ...component(), extra: true })],
    ['missing helper', () => ({ roleRef: component().roleRef, protocol: component().protocol })],
    ['helper extra field', () => ({ ...component(), helper: { ...component().helper, extra: true } })],
    ['protocol extra field', () => ({ ...component(), protocol: { ...component().protocol, extra: true } })],
    [
      'protocol digest array',
      () => ({ ...component(), protocol: { ...component().protocol, digest: [component().protocol.digest] } }),
    ],
    [
      'helper digest array',
      () => ({ ...component(), helper: { ...component().helper, digest: [component().helper.digest] } }),
    ],
    ['wrong protocol', () => ({ ...component(), protocol: { ...component().protocol, ref: 'other' } })],
    ['wrong helper reference', () => ({ ...component(), helper: { ...component().helper, ref: 'other' } })],
  ])('refuses %s', (_, value) => {
    expect(() => assertWorkingCopyCaptureComponent(value())).toThrow()
  })
})
