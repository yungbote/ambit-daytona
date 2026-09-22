/*
 * Copyright 2026 Ambit
 * SPDX-License-Identifier: AGPL-3.0
 */

import { IsNull, Repository } from 'typeorm'
import { RegionService } from '../../region/services/region.service'
import { DockerRegistry } from '../entities/docker-registry.entity'
import { RegistryType } from '../enums/registry-type.enum'
import { IDockerRegistryProvider } from '../providers/docker-registry.provider.interface'
import { DockerRegistryService } from './docker-registry.service'
import { EcrCredentialsService } from './ecr-credentials.service'

const REGION_ID = 'region-1'
const REGISTRY_HOST = 'harbor.example.test'
const DIGEST = `sha256:${'a'.repeat(64)}`

function registry(overrides: Partial<DockerRegistry> = {}): DockerRegistry {
  return Object.assign(new DockerRegistry(), {
    id: 'registry-1',
    url: REGISTRY_HOST,
    project: 'daytona',
    username: 'fixture-user',
    password: 'fixture-password',
    registryType: RegistryType.INTERNAL,
    ...overrides,
  })
}

describe('DockerRegistryService registry ownership', () => {
  let service: DockerRegistryService
  let findRegistries: jest.Mock
  let findRegion: jest.Mock

  beforeEach(() => {
    findRegistries = jest.fn()
    findRegion = jest.fn().mockResolvedValue({ id: REGION_ID, snapshotManagerUrl: 'https://snapshots.example.test' })
    service = new DockerRegistryService(
      { find: findRegistries } as unknown as Repository<DockerRegistry>,
      undefined as unknown as IDockerRegistryProvider,
      { findOne: findRegion } as unknown as RegionService,
      undefined as unknown as EcrCredentialsService,
    )
  })

  describe.each([
    { method: 'findSourceRegistryBySnapshotImageName' as const, registryType: RegistryType.INTERNAL },
    { method: 'findInternalRegistryBySnapshotRef' as const, registryType: RegistryType.INTERNAL },
    { method: 'findTransientRegistryBySnapshotImageName' as const, registryType: RegistryType.TRANSIENT },
  ])('$method', ({ method, registryType }) => {
    it.each([
      ['tagged image', `${REGISTRY_HOST}/daytona/workspace:latest`],
      ['digest reference', `${REGISTRY_HOST}/daytona/workspace@${DIGEST}`],
      ['tag and digest reference', `${REGISTRY_HOST}/daytona/workspace:latest@${DIGEST}`],
      ['nested repository', `${REGISTRY_HOST}/daytona/team/workspace:latest`],
    ])('selects the owning project for a %s', async (_name, imageName) => {
      const owner = registry({ registryType })
      findRegistries.mockResolvedValue([owner])

      await expect(service[method](imageName, REGION_ID)).resolves.toBe(owner)
    })

    it.each([
      ['sibling project', `${REGISTRY_HOST}/ambit-runtime/workspace:latest`],
      ['project name prefix', `${REGISTRY_HOST}/daytona-other/workspace:latest`],
      ['project name suffix', `${REGISTRY_HOST}/other-daytona/workspace:latest`],
      ['project segment in another namespace', `${REGISTRY_HOST}/other/daytona/workspace:latest`],
      ['repository named like the project', `${REGISTRY_HOST}/daytona:latest`],
      ['repository digest named like the project', `${REGISTRY_HOST}/daytona@${DIGEST}`],
      ['project without a repository', `${REGISTRY_HOST}/daytona`],
      ['hostname prefix', `${REGISTRY_HOST}-other/daytona/workspace:latest`],
      ['hostname suffix', `other.${REGISTRY_HOST}/daytona/workspace:latest`],
      ['unconfigured port', `${REGISTRY_HOST}:5000/daytona/workspace:latest`],
    ])('rejects %s', async (_name, imageName) => {
      findRegistries.mockResolvedValue([registry({ registryType })])

      await expect(service[method](imageName, REGION_ID)).resolves.toBeNull()
    })

    it.each([
      ['https://harbor.example.test/', 'daytona'],
      ['http://harbor.example.test///', 'daytona/'],
      [REGISTRY_HOST, '/daytona/'],
    ])('handles URL %s and project %s separators', async (url, project) => {
      const owner = registry({ registryType, url, project })
      findRegistries.mockResolvedValue([owner])

      await expect(service[method](`${REGISTRY_HOST}/daytona/workspace:latest`, REGION_ID)).resolves.toBe(owner)
      await expect(service[method](`${REGISTRY_HOST}/daytona-other/workspace:latest`, REGION_ID)).resolves.toBeNull()
    })

    it.each([
      ['mwcc-infrastructure/ambit/workspace:latest', true],
      ['mwcc-infrastructure/ambit/team/workspace:latest', true],
      ['mwcc-infrastructure/ambit-other/workspace:latest', false],
      ['mwcc-infrastructure/other/workspace:latest', false],
      ['mwcc-infrastructure/ambit:latest', false],
    ])('matches nested project ownership for %s', async (path, matches) => {
      const owner = registry({ registryType, url: 'us-east1-docker.pkg.dev', project: 'mwcc-infrastructure/ambit' })
      findRegistries.mockResolvedValue([owner])

      await expect(service[method](`us-east1-docker.pkg.dev/${path}`, REGION_ID)).resolves.toBe(matches ? owner : null)
    })

    it.each(['', undefined])('retains host-wide credentials for project %s', async (project) => {
      const owner = registry({ registryType, project, url: `https://${REGISTRY_HOST}/` })
      findRegistries.mockResolvedValue([owner])

      for (const path of ['daytona/workspace:latest', 'ambit-runtime/workspace:latest', 'workspace:latest']) {
        await expect(service[method](`${REGISTRY_HOST}/${path}`, REGION_ID)).resolves.toBe(owner)
      }
      await expect(service[method](REGISTRY_HOST, REGION_ID)).resolves.toBe(owner)
      await expect(service[method](`${REGISTRY_HOST}-other/workspace:latest`, REGION_ID)).resolves.toBeNull()
      await expect(service[method](`${REGISTRY_HOST}:5000/workspace:latest`, REGION_ID)).resolves.toBeNull()
    })

    it.each(['', 'daytona'])('matches the complete configured port with project %s', async (project) => {
      const owner = registry({ registryType, url: `${REGISTRY_HOST}:5000`, project })
      findRegistries.mockResolvedValue([owner])

      await expect(service[method](`${REGISTRY_HOST}:5000/daytona/workspace:latest`, REGION_ID)).resolves.toBe(owner)
      await expect(service[method](`${REGISTRY_HOST}:5001/daytona/workspace:latest`, REGION_ID)).resolves.toBeNull()
      await expect(service[method](`${REGISTRY_HOST}:50000/daytona/workspace:latest`, REGION_ID)).resolves.toBeNull()
      await expect(service[method](`${REGISTRY_HOST}/daytona/workspace:latest`, REGION_ID)).resolves.toBeNull()
    })

    it('continues to the matching namespace on the same host', async () => {
      const otherProject = registry({ registryType, id: 'other-registry', project: 'ambit-runtime' })
      const owner = registry({ registryType })
      findRegistries.mockResolvedValue([otherProject, owner])

      await expect(service[method](`${REGISTRY_HOST}/daytona/workspace:latest`, REGION_ID)).resolves.toBe(owner)
    })

    it('returns null when the region does not exist', async () => {
      findRegion.mockResolvedValue(null)

      await expect(service[method](`${REGISTRY_HOST}/daytona/workspace:latest`, REGION_ID)).resolves.toBeNull()
      expect(findRegistries).not.toHaveBeenCalled()
    })

    it('returns null when no registries are configured', async () => {
      findRegistries.mockResolvedValue([])

      await expect(service[method](`${REGISTRY_HOST}/daytona/workspace:latest`, REGION_ID)).resolves.toBeNull()
    })
  })

  it.each(['', 'daytona'])('preserves organization credential priority with project %s', async (project) => {
    const shared = registry()
    const organization = registry({
      id: 'organization-registry',
      project,
      organizationId: 'organization-1',
      registryType: RegistryType.ORGANIZATION,
    })
    findRegistries.mockResolvedValue([shared, organization])

    await expect(
      service.findSourceRegistryBySnapshotImageName(
        `${REGISTRY_HOST}/daytona/workspace:latest`,
        REGION_ID,
        'organization-1',
      ),
    ).resolves.toBe(organization)
  })

  it('skips organization credentials scoped to a different project', async () => {
    const shared = registry()
    const organization = registry({ project: 'ambit-runtime', registryType: RegistryType.ORGANIZATION })
    findRegistries.mockResolvedValue([shared, organization])

    await expect(
      service.findSourceRegistryBySnapshotImageName(
        `${REGISTRY_HOST}/daytona/workspace:latest`,
        REGION_ID,
        'organization-1',
      ),
    ).resolves.toBe(shared)
  })

  it.each(['https://snapshots.example.test', undefined])(
    'excludes stable platform images from transient cleanup with snapshot manager %s',
    async (snapshotManagerUrl) => {
      findRegion.mockResolvedValue({ id: REGION_ID, snapshotManagerUrl })
      const transient = registry({ registryType: RegistryType.TRANSIENT })
      findRegistries.mockResolvedValue([transient])

      await expect(
        service.findTransientRegistryBySnapshotImageName(
          `${REGISTRY_HOST}/ambit-runtime/ambit-agent-workspace@${DIGEST}`,
          REGION_ID,
        ),
      ).resolves.toBeNull()
      await expect(
        service.findTransientRegistryBySnapshotImageName(`${REGISTRY_HOST}/daytona/upload:latest`, REGION_ID),
      ).resolves.toBe(transient)
      expect(findRegistries).toHaveBeenCalledWith({
        where: {
          ...(snapshotManagerUrl ? { region: REGION_ID } : { organizationId: IsNull() }),
          registryType: RegistryType.TRANSIENT,
        },
      })
    },
  )
})
