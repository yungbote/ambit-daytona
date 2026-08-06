/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { parseDockerImage } from './docker-image.util'

const DIGEST = `sha256:${'a'.repeat(64)}`

describe('parseDockerImage', () => {
  it('round-trips a tagged image', () => {
    const image = parseDockerImage('docker.io/library/node:24')

    expect(image).toMatchObject({
      registry: 'docker.io',
      project: 'library',
      repository: 'node',
      tag: '24',
      digest: undefined,
    })
    expect(image.getFullName()).toBe('docker.io/library/node:24')
  })

  it('round-trips a digest-only image without treating its digest as a tag', () => {
    const reference = `docker.io/library/node@${DIGEST}`
    const image = parseDockerImage(reference)

    expect(image).toMatchObject({
      registry: 'docker.io',
      project: 'library',
      repository: 'node',
      tag: undefined,
      digest: DIGEST,
    })
    expect(image.getFullName()).toBe(reference)
  })

  it('preserves both a tag and an immutable digest', () => {
    const reference = `docker.io/library/node:24@${DIGEST}`
    const image = parseDockerImage(reference)

    expect(image).toMatchObject({
      registry: 'docker.io',
      project: 'library',
      repository: 'node',
      tag: '24',
      digest: DIGEST,
    })
    expect(image.getFullName()).toBe(reference)
  })

  it('distinguishes a registry port from a tag in a tagged digest reference', () => {
    const reference = `registry.example.com:5000/team/node:24@${DIGEST}`
    const image = parseDockerImage(reference)

    expect(image).toMatchObject({
      registry: 'registry.example.com:5000',
      project: 'team',
      repository: 'node',
      tag: '24',
      digest: DIGEST,
    })
    expect(image.getFullName()).toBe(reference)
  })

  it.each(['node:', `node@@${DIGEST}`, 'node@', 'node@sha256:abc'])('rejects malformed reference %s', (reference) => {
    expect(() => parseDockerImage(reference)).toThrow()
  })
})
