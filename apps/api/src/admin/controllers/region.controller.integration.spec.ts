/*
 * Copyright 2026 Ambit
 * SPDX-License-Identifier: AGPL-3.0
 */

import { randomUUID } from 'node:crypto'
import { join } from 'node:path'
import { INestApplication, ValidationPipe } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { EventEmitter2 } from '@nestjs/event-emitter'
import { Test } from '@nestjs/testing'
import { DataSource } from 'typeorm'
import { AdminRegionController } from './region.controller'
import { AuthenticatedRateLimitGuard } from '../../common/guards/authenticated-rate-limit.guard'
import { Region } from '../../region/entities/region.entity'
import { RegionType } from '../../region/enums/region-type.enum'
import { RegionService } from '../../region/services/region.service'
import { Runner } from '../../sandbox/entities/runner.entity'
import { SnapshotRepository } from '../../sandbox/repositories/snapshot.repository'
import { SystemActionGuard } from '../../user/guards/system-action.guard'
import { SystemRole } from '../../user/enums/system-role.enum'

// Explicit disposable database only. Never boot AppModule, cron, provider
// workers, shared defaults or production connections to exercise this surface.
const databaseUrl = process.env.REGION_MANAGEMENT_TEST_DATABASE_URL
const integration = databaseUrl ? describe : describe.skip

integration('operator region HTTP authorization and integrity (PostgreSQL)', () => {
  let dataSource: DataSource
  let app: INestApplication
  let apiUrl: string
  const schema = `operator_regions_${randomUUID().replaceAll('-', '')}`
  const identities = {
    admin: { role: SystemRole.ADMIN, userId: 'operator' },
    user: { role: SystemRole.USER, userId: 'ordinary' },
    scoped: {
      role: SystemRole.USER,
      userId: 'ordinary',
      apiKey: { permissions: ['write:regions', 'delete:regions'] },
    },
    runner: { role: 'runner', runnerId: 'provider-runner' },
  }

  beforeAll(async () => {
    dataSource = new DataSource({
      type: 'postgres',
      url: databaseUrl,
      schema,
      entities: [join(__dirname, '../../**/*.entity.ts')],
      extra: { options: `-c search_path=${schema},public`, application_name: schema, max: 6 },
    })
    await dataSource.initialize()
    await dataSource.query(`CREATE SCHEMA "${schema}"`)
    await dataSource.synchronize()
    const events = new EventEmitter2()
    const service = new RegionService(
      dataSource.getRepository(Region),
      dataSource.getRepository(Runner),
      dataSource,
      events,
      new SnapshotRepository(dataSource, events),
      { del: jest.fn().mockResolvedValue(0) } as never,
    )
    const module = await Test.createTestingModule({
      controllers: [AdminRegionController],
      providers: [{ provide: RegionService, useValue: service }],
    })
      .overrideGuard(AuthenticatedRateLimitGuard)
      .useValue({ canActivate: () => true })
      .compile()
    app = module.createNestApplication({ logger: false })
    // Supply authenticated principals at the transport seam; exercise the real
    // system-role guard and controller. Credential exchange is not mocked as a
    // successful production login or included in this test's acceptance claim.
    app.use((request, _response, next) => {
      request.user = identities[request.headers['x-test-principal'] as keyof typeof identities]
      next()
    })
    app.useGlobalGuards(new SystemActionGuard(new Reflector()))
    app.useGlobalPipes(new ValidationPipe({ transform: true }))
    await app.listen(0, '127.0.0.1')
    apiUrl = await app.getUrl()
  }, 60000)

  afterAll(async () => {
    await app?.close()
    if (dataSource?.isInitialized) {
      await dataSource.query(`DROP SCHEMA "${schema}" CASCADE`)
      await dataSource.destroy()
    }
  })

  beforeEach(async () => {
    await dataSource.getRepository(Region).createQueryBuilder().delete().execute()
    await dataSource.getRepository(Region).save(
      new Region({
        id: 'default-region',
        name: 'default-region',
        regionType: RegionType.SHARED,
        enforceQuotas: false,
      }),
    )
  })

  const request = (method: string, path = '', body?: unknown, principal = 'admin') =>
    fetch(`${apiUrl}/admin/regions${path}`, {
      method,
      headers: { 'content-type': 'application/json', 'x-test-principal': principal },
      body: body === undefined ? undefined : JSON.stringify(body),
    })

  it('creates a separate quota-enforced dedicated region without changing the default', async () => {
    const before = await dataSource.getRepository(Region).findOneByOrFail({ id: 'default-region' })
    const response = await request('POST', '', { name: 'qualified' })
    expect(response.status).toBe(201)
    const created = await response.json()
    expect(Object.keys(created)).toEqual(['id'])
    expect(created.id).not.toBe('qualified')
    const persisted = await dataSource.getRepository(Region).findOneByOrFail({ id: created.id })
    expect(persisted).toMatchObject({
      name: 'qualified',
      regionType: RegionType.DEDICATED,
      organizationId: null,
      enforceQuotas: true,
    })
    expect(await dataSource.getRepository(Region).findOneByOrFail({ id: 'default-region' })).toEqual(before)
    const read = await request('GET', `/${created.id}`)
    expect(read.status).toBe(200)
    expect(await read.json()).toMatchObject({ id: created.id, regionType: RegionType.DEDICATED, enforceQuotas: true })
    expect((await request('GET', '/qualified')).status).toBe(404)
  })

  it.each(['user', 'scoped', 'runner', 'missing'])('%s cannot create or read operator regions', async (principal) => {
    expect((await request('POST', '', { name: 'unauthorized' }, principal)).status).toBe(403)
    expect((await request('GET', '/default-region', undefined, principal)).status).toBe(403)
    expect(await dataSource.getRepository(Region).count()).toBe(1)
  })

  it.each([
    { id: 'default-region' },
    { regionType: RegionType.CUSTOM },
    { enforceQuotas: false },
    { organizationId: randomUUID() },
    { defaultRegionId: 'default-region' },
    { proxyUrl: 'https://not-authorized.invalid' },
  ])('refuses caller-controlled internal region fields %j', async (extra) => {
    expect((await request('POST', '', { name: 'qualified', ...extra })).status).toBe(400)
    expect(await dataSource.getRepository(Region).count()).toBe(1)
  })

  it.each([null, {}, { name: '' }, { name: 1 }, { name: 'bad/name' }, { name: 'a' }, { name: 'a'.repeat(256) }])(
    'refuses invalid region input %j without a row',
    async (body) => {
      expect((await request('POST', '', body)).status).toBe(400)
      expect(await dataSource.getRepository(Region).count()).toBe(1)
    },
  )

  it('does not overwrite an existing region when its name is reused', async () => {
    const before = await dataSource.getRepository(Region).findOneByOrFail({ id: 'default-region' })
    expect((await request('POST', '', { name: 'default-region' })).status).toBe(409)
    expect(await dataSource.getRepository(Region).findOneByOrFail({ id: 'default-region' })).toEqual(before)
  })

  it('database uniqueness settles concurrent creation without duplicate regions', async () => {
    const responses = await Promise.all(Array.from({ length: 3 }, () => request('POST', '', { name: 'qualified' })))
    expect(responses.map((response) => response.status).sort()).toEqual([201, 409, 409])
    expect(await dataSource.getRepository(Region).countBy({ name: 'qualified' })).toBe(1)
  })

  it('returns not found for an absent exact identity', async () => {
    expect((await request('GET', '/missing')).status).toBe(404)
  })

  it('does not expose deletion before the existing domain invariant is closed', async () => {
    expect((await request('DELETE', '/default-region')).status).toBe(404)
    expect(await dataSource.getRepository(Region).count()).toBe(1)
  })
})
