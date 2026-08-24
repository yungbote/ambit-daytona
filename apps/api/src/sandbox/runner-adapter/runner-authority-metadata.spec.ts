/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { runnerProviderAuthorityMetadata } from './runnerAdapter'

describe('runnerProviderAuthorityMetadata', () => {
  it('projects the complete bounded Ambit namespace without leaking ordinary labels', () => {
    const metadata = runnerProviderAuthorityMetadata(
      {
        labels: {
          ambitWorkspaceId: '00000000-0000-4000-8000-000000000003',
          ambitRuntimeKind: 'full_image_runtime_pack_provider_observation',
          customerLabel: 'not provider authority',
        },
      },
      { organizationName: 'Ambit' },
    )

    expect(metadata).toEqual({
      organizationName: 'Ambit',
      'daytona.authority-label.ambitWorkspaceId': '00000000-0000-4000-8000-000000000003',
      'daytona.authority-label.ambitRuntimeKind': 'full_image_runtime_pack_provider_observation',
    })
  })

  it('rejects reserved-prefix injection from ordinary metadata', () => {
    expect(() =>
      runnerProviderAuthorityMetadata({ labels: {} }, { 'daytona.authority-label.ambitWorkspaceId': 'substituted' }),
    ).toThrow('reserved provider-authority namespace')
  })

  it.each([
    ['empty', ''],
    ['padded', ' padded '],
    ['control', 'line\nbreak'],
    ['oversize', 'a'.repeat(2049)],
  ])('rejects an invalid Ambit authority label value: %s', (_name, value) => {
    expect(() => runnerProviderAuthorityMetadata({ labels: { ambitWorkspaceId: value } })).toThrow(
      'is not a bounded canonical string',
    )
  })
})
