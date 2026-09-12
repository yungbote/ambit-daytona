/*
 * Copyright 2026 Ambit Platforms
 * SPDX-License-Identifier: AGPL-3.0
 */

import { randomUUID } from 'node:crypto'
import { join } from 'node:path'
import { DataSource, QueryRunner } from 'typeorm'
import { EventEmitter2 } from '@nestjs/event-emitter'
import { ConflictException, INestApplication, ValidationPipe } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import { RunnerService, RESERVING_SANDBOX_STATES } from './runner.service'
import { Runner } from '../entities/runner.entity'
import { RunnerState } from '../enums/runner-state.enum'
import { Sandbox } from '../entities/sandbox.entity'
import { SandboxState } from '../enums/sandbox-state.enum'
import { SandboxDesiredState } from '../enums/sandbox-desired-state.enum'
import { SandboxRepository } from '../repositories/sandbox.repository'
import { SandboxConflictError } from '../errors/sandbox-conflict.error'
import { SandboxLookupCacheInvalidationService } from './sandbox-lookup-cache-invalidation.service'
import { isSandboxQuiescent } from '../utils/sandbox-quiescence'
import { Migration1789257600000 } from '../../migrations/pre-deploy/1789257600000-migration'
import { AdminRunnerController } from '../../admin/controllers/runner.controller'
import { RegionService } from '../../region/services/region.service'
import { AuthenticatedRateLimitGuard } from '../../common/guards/authenticated-rate-limit.guard'

// Run against an explicitly supplied disposable PostgreSQL database. No runtime
// environment/production database settings are read by this suite.
const databaseUrl = process.env.RUNNER_SCHEDULING_TEST_DATABASE_URL
const integration = databaseUrl ? describe : describe.skip

integration('runner scheduling ownership and placement (PostgreSQL)', () => {
  let dataSource: DataSource
  let service: RunnerService
  let sandboxes: SandboxRepository
  let runner: Runner
  let app: INestApplication
  let apiUrl: string
  const owner = 'daytona-runner-scaler'
  const schema = `runner_scheduling_${randomUUID().replaceAll('-', '')}`

  beforeAll(async () => {
    dataSource = new DataSource({
      type: 'postgres',
      url: databaseUrl,
      schema,
      entities: [join(__dirname, '../../**/*.entity.ts')],
      extra: { options: `-c search_path=${schema},public`, application_name: schema, max: 12 },
    })
    await dataSource.initialize()
    await dataSource.query(`CREATE SCHEMA "${schema}"`)
    await dataSource.synchronize()
    const events = new EventEmitter2()
    sandboxes = new SandboxRepository(dataSource, events, {
      invalidate: jest.fn(),
      invalidateOrgId: jest.fn(),
    } as unknown as SandboxLookupCacheInvalidationService)
    // Scheduling uses the actual service, repositories and database. Unrelated
    // cloud adapters, Redis, cron workers and external services are not started.
    service = Object.assign(Object.create(RunnerService.prototype), {
      dataSource,
      runnerRepository: dataSource.getRepository(Runner),
      sandboxRepository: sandboxes,
    })
    const module = await Test.createTestingModule({
      controllers: [AdminRunnerController],
      providers: [
        { provide: RunnerService, useValue: service },
        { provide: RegionService, useValue: {} },
      ],
    })
      .overrideGuard(AuthenticatedRateLimitGuard)
      .useValue({ canActivate: () => true })
      .compile()
    app = module.createNestApplication({ logger: false })
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true, forbidNonWhitelisted: true }))
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
    await dataSource.query(`TRUNCATE "${schema}"."sandbox" CASCADE`)
    await dataSource.getRepository(Runner).clear()
    runner = await dataSource.getRepository(Runner).save(
      Object.assign(new Runner({ region: 'test', name: 'runner', apiKey: 'test', apiVersion: '2' }), {
        state: RunnerState.READY,
        domain: 'daytona-runner-0.daytona-runner.daytona-runners.svc.cluster.local',
        cpu: 8,
        memoryGiB: 32,
      }),
    )
  })

  const readRunner = () => dataSource.getRepository(Runner).findOneByOrFail({ id: runner.id })
  const capacity = async () => {
    const row = (await service.getRunnerCapacity()).find((row) => row.id === runner.id)
    if (!row) throw new Error('Runner is missing from capacity')
    return row
  }
  const sandbox = (overrides: Partial<Sandbox> = {}) =>
    Object.assign(new Sandbox({ region: 'test' }), {
      organizationId: randomUUID(),
      runnerId: runner.id,
      osUser: 'daytona',
      cpu: 2,
      mem: 4,
      disk: 8,
      state: SandboxState.STOPPED,
      desiredState: SandboxDesiredState.STOPPED,
      ...overrides,
    })

  // Hold a real row lock to put concurrent transactions in a known order. The
  // test waits for PostgreSQL to report actual blocking, never an assumed delay.
  const lockRunner = async () => {
    const query = dataSource.createQueryRunner()
    await query.connect()
    await query.startTransaction()
    await query.manager.findOne(Runner, { where: { id: runner.id }, lock: { mode: 'pessimistic_write' } })
    return query
  }
  const waitForBlocked = async (count = 1) => {
    const deadline = Date.now() + 5000
    while (Date.now() < deadline) {
      const [{ blocked }] = await dataSource.query(
        `SELECT count(*)::int AS blocked FROM pg_stat_activity
          WHERE datname = current_database() AND wait_event_type = 'Lock'
            AND application_name = $1`,
        [schema],
      )
      if (blocked >= count) return
      await new Promise((resolve) => setTimeout(resolve, 10))
    }
    throw new Error(`Expected ${count} transactions blocked on the scheduling row`)
  }
  const unlock = async (query: QueryRunner) => {
    await query.commitTransaction()
    await query.release()
  }

  it('serves acquire, capacity, admin takeover and conditional release over the actual HTTP routes', async () => {
    const acquire = await fetch(`${apiUrl}/admin/runners/${runner.id}/scheduling/fences`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ owner }),
    })
    expect(acquire.status).toBe(201)
    const fence = (await acquire.json()) as { owner: string; token: string }
    const view = await fetch(`${apiUrl}/admin/runners/capacity`)
    expect(((await view.json()) as { schedulingFence: unknown }[])[0].schedulingFence).toEqual(fence)
    const takeover = await fetch(`${apiUrl}/admin/runners/${runner.id}/scheduling`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ unschedulable: true }),
    })
    expect(takeover.status).toBe(200)
    const stale = await fetch(`${apiUrl}/admin/runners/${runner.id}/scheduling/fences/${fence.token}`, {
      method: 'DELETE',
    })
    expect(stale.status).toBe(409)
    expect((await readRunner()).unschedulable).toBe(true)
  })

  it('rejects invalid HTTP ownership, tokens and non-Boolean admin writes before mutation', async () => {
    for (const body of [{}, { owner: '' }, { owner: 42 }, { owner: 'x'.repeat(129) }]) {
      const response = await fetch(`${apiUrl}/admin/runners/${runner.id}/scheduling/fences`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      expect(response.status).toBe(400)
    }
    const invalidToken = await fetch(`${apiUrl}/admin/runners/${runner.id}/scheduling/fences/not-a-token`, {
      method: 'DELETE',
    })
    expect(invalidToken.status).toBe(400)
    const invalidAdmin = await fetch(`${apiUrl}/admin/runners/${runner.id}/scheduling`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ unschedulable: 'true' }),
    })
    expect(invalidAdmin.status).toBe(400)
    expect((await readRunner()).unschedulable).toBe(false)
  })

  it('releases its own persisted token and issues a new token for the next fence', async () => {
    const first = await service.acquireSchedulingFence(runner.id, owner)
    expect((await capacity()).schedulingFence).toEqual(first)
    await service.releaseSchedulingFence(runner.id, first.token)
    expect((await readRunner()).unschedulable).toBe(false)
    const second = await service.acquireSchedulingFence(runner.id, owner)
    expect(second.token).not.toBe(first.token)
    await expect(service.releaseSchedulingFence(runner.id, first.token)).rejects.toBeInstanceOf(ConflictException)
    expect((await capacity()).schedulingFence).toEqual(second)
  })

  it.each([true, false])('an explicit admin write (%s) supersedes a controller token', async (unschedulable) => {
    const fence = await service.acquireSchedulingFence(runner.id, owner)
    await service.updateSchedulingStatus(runner.id, unschedulable)
    await expect(service.releaseSchedulingFence(runner.id, fence.token)).rejects.toBeInstanceOf(ConflictException)
    expect(await readRunner()).toMatchObject({ unschedulable, schedulingFenceOwner: null, schedulingFenceToken: null })
  })

  it('cannot acquire an existing manual or controller fence, including for the same owner', async () => {
    await service.updateSchedulingStatus(runner.id, true)
    await expect(service.acquireSchedulingFence(runner.id, owner)).rejects.toBeInstanceOf(ConflictException)
    await service.updateSchedulingStatus(runner.id, false)
    await service.acquireSchedulingFence(runner.id, owner)
    await expect(service.acquireSchedulingFence(runner.id, owner)).rejects.toBeInstanceOf(ConflictException)
    await expect(service.acquireSchedulingFence(runner.id, 'another-controller')).rejects.toBeInstanceOf(
      ConflictException,
    )
  })

  it('serializes a stale release behind an admin takeover', async () => {
    const fence = await service.acquireSchedulingFence(runner.id, owner)
    const lock = await lockRunner()
    try {
      const takeover = service.updateSchedulingStatus(runner.id, true)
      await waitForBlocked()
      const release = service.releaseSchedulingFence(runner.id, fence.token).catch((error) => error)
      await waitForBlocked(2)
      await unlock(lock)
      await takeover
      expect(await release).toBeInstanceOf(ConflictException)
      expect(await readRunner()).toMatchObject({ unschedulable: true, schedulingFenceToken: null })
    } finally {
      if (!lock.isReleased) {
        await lock.rollbackTransaction()
        await lock.release()
      }
    }
  })

  it('an admin fence also wins when the release commits first', async () => {
    const fence = await service.acquireSchedulingFence(runner.id, owner)
    const lock = await lockRunner()
    try {
      const release = service.releaseSchedulingFence(runner.id, fence.token)
      await waitForBlocked()
      const takeover = service.updateSchedulingStatus(runner.id, true)
      await waitForBlocked(2)
      await unlock(lock)
      await Promise.all([release, takeover])
      expect(await readRunner()).toMatchObject({ unschedulable: true, schedulingFenceToken: null })
    } finally {
      if (!lock.isReleased) {
        await lock.rollbackTransaction()
        await lock.release()
      }
    }
  })

  it('does not acquire or release automation fences while draining', async () => {
    await service.updateDrainingStatus(runner.id, true)
    await expect(service.acquireSchedulingFence(runner.id, owner)).rejects.toBeInstanceOf(ConflictException)
    await service.updateDrainingStatus(runner.id, false)
    const fence = await service.acquireSchedulingFence(runner.id, owner)
    await service.updateDrainingStatus(runner.id, true)
    await expect(service.releaseSchedulingFence(runner.id, fence.token)).rejects.toBeInstanceOf(ConflictException)
  })

  it('does not admit an insert selected before the fence committed', async () => {
    const selected = sandbox({ state: SandboxState.UNKNOWN, desiredState: SandboxDesiredState.STARTED })
    await service.acquireSchedulingFence(runner.id, owner)
    await expect(sandboxes.insert(selected)).rejects.toBeInstanceOf(SandboxConflictError)
    expect(await sandboxes.count()).toBe(0)
    expect((await capacity()).busySandboxes).toBe(0)
  })

  it.each(['update', 'updateWhere', 'raw'] as const)('fences wake requests through %s', async (method) => {
    const stopped = await sandboxes.insert(sandbox())
    await service.acquireSchedulingFence(runner.id, owner)
    const updateData = { desiredState: SandboxDesiredState.STARTED }
    const operation =
      method === 'updateWhere'
        ? sandboxes.updateWhere(stopped.id, { updateData, whereCondition: {} })
        : method === 'raw'
          ? sandboxes.update(stopped.id, { updateData }, true)
          : sandboxes.update(stopped.id, { updateData, entity: stopped })
    await expect(operation).rejects.toBeInstanceOf(SandboxConflictError)
    expect(await sandboxes.findOneBy({ id: stopped.id })).toMatchObject({
      desiredState: SandboxDesiredState.STOPPED,
      pending: false,
    })
  })

  it.each(['update', 'updateWhere', 'raw'] as const)(
    'rejects delayed restore/reassignment through %s',
    async (method) => {
      const unassigned = await sandboxes.insert(
        sandbox({
          runnerId: undefined,
          state: SandboxState.UNKNOWN,
          desiredState: SandboxDesiredState.STARTED,
        }),
      )
      await service.acquireSchedulingFence(runner.id, owner)
      const updateData = { runnerId: runner.id, state: SandboxState.RESTORING }
      const operation =
        method === 'updateWhere'
          ? sandboxes.updateWhere(unassigned.id, { updateData, whereCondition: {} })
          : method === 'raw'
            ? sandboxes.update(unassigned.id, { updateData }, true)
            : sandboxes.update(unassigned.id, { updateData, entity: unassigned })
      await expect(operation).rejects.toBeInstanceOf(SandboxConflictError)
      expect(await sandboxes.findOneBy({ id: unassigned.id })).toMatchObject({
        runnerId: null,
        state: SandboxState.UNKNOWN,
      })
    },
  )

  it('retains unrelated updates and raw housekeeping while fenced', async () => {
    const stopped = await sandboxes.insert(sandbox({ prevRunnerId: randomUUID() }))
    await service.acquireSchedulingFence(runner.id, owner)
    await sandboxes.update(stopped.id, { updateData: { name: 'retained-workspace' } })
    await sandboxes.update(stopped.id, { updateData: { prevRunnerId: null } }, true)
    expect(await sandboxes.findOneBy({ id: stopped.id })).toMatchObject({
      name: 'retained-workspace',
      prevRunnerId: null,
      runnerId: runner.id,
    })
    expect((await capacity()).busySandboxes).toBe(0)
  })

  it('does not reuse a prefetched runner assignment after that assignment changed', async () => {
    const stopped = await sandboxes.insert(sandbox())
    const stale = await sandboxes.findOneByOrFail({ id: stopped.id })
    await sandboxes.updateWhere(stopped.id, { updateData: { runnerId: null }, whereCondition: {} })
    await expect(
      sandboxes.update(stopped.id, { updateData: { desiredState: SandboxDesiredState.STARTED }, entity: stale }),
    ).rejects.toBeInstanceOf(SandboxConflictError)
    expect(await sandboxes.findOneBy({ id: stopped.id })).toMatchObject({
      runnerId: null,
      desiredState: SandboxDesiredState.STOPPED,
    })
  })

  it('fences warm-pool ownership transfers without stopping the existing sandbox', async () => {
    const warm = await sandboxes.insert(
      sandbox({
        organizationId: '00000000-0000-0000-0000-000000000000',
        state: SandboxState.STARTED,
        desiredState: SandboxDesiredState.STARTED,
      }),
    )
    await service.acquireSchedulingFence(runner.id, owner)
    await expect(sandboxes.update(warm.id, { updateData: { organizationId: randomUUID() } })).rejects.toBeInstanceOf(
      SandboxConflictError,
    )
    expect(await sandboxes.findOneBy({ id: warm.id })).toMatchObject({
      organizationId: warm.organizationId,
      state: SandboxState.STARTED,
    })
    expect((await capacity()).busySandboxes).toBe(1)
  })

  it('lets existing work finish naturally under the fence', async () => {
    const started = await sandboxes.insert(
      sandbox({ state: SandboxState.STARTED, desiredState: SandboxDesiredState.STARTED }),
    )
    await service.acquireSchedulingFence(runner.id, owner)
    await sandboxes.updateWhere(started.id, {
      updateData: { desiredState: SandboxDesiredState.STOPPED },
      whereCondition: {},
    })
    expect((await capacity()).busySandboxes).toBe(1)
    await sandboxes.updateWhere(started.id, { updateData: { state: SandboxState.STOPPED }, whereCondition: {} })
    expect((await capacity()).busySandboxes).toBe(0)
    expect((await readRunner()).unschedulable).toBe(true)
  })

  it('waits for an earlier admission to commit before the fence can commit', async () => {
    const query = dataSource.createQueryRunner()
    await query.connect()
    await dataSource.query(`CREATE FUNCTION "${schema}".pause_admission() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN PERFORM pg_advisory_xact_lock(73194021); RETURN NEW; END $$`)
    await dataSource.query(`CREATE TRIGGER pause_admission BEFORE INSERT ON "${schema}".sandbox
      FOR EACH ROW EXECUTE FUNCTION "${schema}".pause_admission()`)
    try {
      await query.query('SELECT pg_advisory_lock(73194021)')
      const insert = sandboxes.insert(
        sandbox({ state: SandboxState.STARTING, desiredState: SandboxDesiredState.STARTED }),
      )
      await waitForBlocked()
      const acquire = service.acquireSchedulingFence(runner.id, owner)
      await waitForBlocked(2)
      await query.query('SELECT pg_advisory_unlock(73194021)')
      await Promise.all([insert, acquire])
      expect((await capacity()).busySandboxes).toBe(1)
    } finally {
      await query.query('SELECT pg_advisory_unlock(73194021)')
      await query.release()
      await dataSource.query(`DROP TRIGGER pause_admission ON "${schema}".sandbox`)
      await dataSource.query(`DROP FUNCTION "${schema}".pause_admission()`)
    }
  })

  it('rejects an admission queued behind the fence, using the actual repository path', async () => {
    const stopped = await sandboxes.insert(sandbox())
    const lock = await lockRunner()
    try {
      const acquire = service.acquireSchedulingFence(runner.id, owner)
      await waitForBlocked()
      const wake = sandboxes
        .updateWhere(stopped.id, { updateData: { desiredState: SandboxDesiredState.STARTED }, whereCondition: {} })
        .catch((error) => error)
      await waitForBlocked(2)
      await unlock(lock)
      await acquire
      expect(await wake).toBeInstanceOf(SandboxConflictError)
      expect((await capacity()).busySandboxes).toBe(0)
    } finally {
      if (!lock.isReleased) {
        await lock.rollbackTransaction()
        await lock.release()
      }
    }
  })

  it('the capacity query agrees with the complete state/desired/pending quiescence table', async () => {
    for (const state of Object.values(SandboxState)) {
      for (const desiredState of Object.values(SandboxDesiredState)) {
        for (const pending of [false, true]) {
          const row = sandbox({ state, desiredState, pending })
          // Intentionally exercise every stored tuple, including interrupted or
          // inconsistent states that the normal entity writer would normalize.
          await dataSource.getRepository(Sandbox).insert(row)
          const view = await capacity()
          expect(view.busySandboxes).toBe(isSandboxQuiescent(row) ? 0 : 1)
          expect(view.activeSandboxes).toBe(RESERVING_SANDBOX_STATES.includes(state) ? 1 : 0)
          expect(view.reservedCpu).toBe(RESERVING_SANDBOX_STATES.includes(state) ? 2 : 0)
          await dataSource.getRepository(Sandbox).delete({ id: row.id })
        }
      }
    }
  }, 30000)

  it('the additive migration preserves existing manual fences and rolls back cleanly', async () => {
    await service.updateSchedulingStatus(runner.id, true)
    const query = dataSource.createQueryRunner()
    await query.connect()
    const migration = new Migration1789257600000()
    try {
      await migration.down(query)
      const [old] = await query.query('SELECT unschedulable FROM runner WHERE id = $1', [runner.id])
      expect(old.unschedulable).toBe(true)
      await migration.up(query)
      expect(await readRunner()).toMatchObject({
        unschedulable: true,
        schedulingFenceToken: null,
        schedulingFenceOwner: null,
      })
    } finally {
      await query.release()
    }
  })
})
