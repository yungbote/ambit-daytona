/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { DataSource, EntityManager, FindOptionsWhere, IsNull } from 'typeorm'
import { Sandbox } from '../entities/sandbox.entity'
import { SandboxLastActivity } from '../entities/sandbox-last-activity.entity'
import { Injectable, Logger, NotFoundException } from '@nestjs/common'
import { SandboxConflictError } from '../errors/sandbox-conflict.error'
import { InjectDataSource } from '@nestjs/typeorm'
import { EventEmitter2 } from '@nestjs/event-emitter'
import { BaseRepository } from '../../common/repositories/base.repository'
import { SandboxEvents } from '../constants/sandbox-events.constants'
import { SandboxStateUpdatedEvent } from '../events/sandbox-state-updated.event'
import { SandboxDesiredStateUpdatedEvent } from '../events/sandbox-desired-state-updated.event'
import { SandboxPublicStatusUpdatedEvent } from '../events/sandbox-public-status-updated.event'
import { SandboxAuthTokenRotatedEvent } from '../events/sandbox-auth-token-rotated.event'
import { SandboxOrganizationUpdatedEvent } from '../events/sandbox-organization-updated.event'
import { SandboxLookupCacheInvalidationService } from '../services/sandbox-lookup-cache-invalidation.service'
import { SandboxFork } from '../entities/sandbox-fork.entity'
import { SandboxSecret } from '../entities/sandbox-secret.entity'
import { SandboxState } from '../enums/sandbox-state.enum'
import { Runner } from '../entities/runner.entity'
import { RunnerState } from '../enums/runner-state.enum'
import { isSandboxQuiescent } from '../utils/sandbox-quiescence'

@Injectable()
export class SandboxRepository extends BaseRepository<Sandbox> {
  private readonly logger = new Logger(SandboxRepository.name)

  constructor(
    @InjectDataSource() dataSource: DataSource,
    eventEmitter: EventEmitter2,
    private readonly sandboxLookupCacheInvalidationService: SandboxLookupCacheInvalidationService,
  ) {
    super(dataSource, eventEmitter, Sandbox)
  }

  async insert(sandbox: Sandbox, parentId?: string): Promise<Sandbox> {
    const now = new Date()
    if (!sandbox.createdAt) {
      sandbox.createdAt = now
    }
    if (!sandbox.updatedAt) {
      sandbox.updatedAt = now
    }

    sandbox.assertValid()
    sandbox.enforceInvariants()

    await this.dataSource.transaction(async (entityManager) => {
      await this.assertRunnerAdmission(entityManager, sandbox)
      await entityManager.insert(Sandbox, sandbox)
      await this.upsertLastActivity(entityManager, sandbox.id, sandbox.createdAt)
      sandbox.lastActivityAt = { sandboxId: sandbox.id, lastActivityAt: sandbox.createdAt }

      // entityManager.insert does not cascade the sandboxSecrets relation, so persist the
      // join rows explicitly within the same transaction as the sandbox.
      if (sandbox.sandboxSecrets?.length) {
        await entityManager.insert(
          SandboxSecret,
          sandbox.sandboxSecrets.map((sandboxSecret) => ({
            sandboxId: sandbox.id,
            envVar: sandboxSecret.envVar,
            secretId: sandboxSecret.secretId,
          })),
        )
      }

      if (parentId) {
        await entityManager.insert(SandboxFork, {
          parentId,
          childId: sandbox.id,
        })
      }
    })

    this.invalidateLookupCacheOnInsert(sandbox)

    return sandbox
  }

  /**
   * @param id - The ID of the sandbox to update.
   * @param params.updateData - The partial data to update.
   *
   * @returns `void` because a raw update is performed.
   */
  async update(id: string, params: { updateData: Partial<Sandbox> }, raw: true): Promise<void>
  /**
   * @param id - The ID of the sandbox to update.
   * @param params.updateData - The partial data to update.
   * @param params.entity - Optional pre-fetched sandbox to use instead of fetching from the database.
   *
   * @returns The updated sandbox.
   */
  async update(id: string, params: { updateData: Partial<Sandbox>; entity?: Sandbox }, raw?: false): Promise<Sandbox>
  async update(
    id: string,
    params: { updateData: Partial<Sandbox>; entity?: Sandbox },
    raw = false,
  ): Promise<Sandbox | void> {
    const { updateData, entity } = params

    if (raw) {
      // Raw housekeeping may skip entity invariants, but it must not create a
      // second route for assigning, waking, or transferring a sandbox.
      if (['runnerId', 'state', 'desiredState', 'pending', 'organizationId'].some((key) => key in updateData)) {
        await this.updateWhere(id, { updateData, whereCondition: {} })
        return
      }
      await this.repository.update(id, updateData)
      return
    }

    const sandbox = entity ?? (await this.findOneBy({ id }))
    if (!sandbox) {
      throw new NotFoundException('Sandbox not found')
    }

    const previousSandbox = { ...sandbox }

    Object.assign(sandbox, updateData)
    sandbox.assertValid()
    const invariantChanges = sandbox.enforceInvariants()

    await this.dataSource.transaction(async (entityManager) => {
      // Match updateWhere's lock order: sandbox first, runner second. Revalidate
      // prefetched state before a runner selected earlier can admit new work.
      const current = await entityManager.findOne(Sandbox, {
        where: {
          id: previousSandbox.id,
          state: previousSandbox.state,
          desiredState: previousSandbox.desiredState,
          pending: previousSandbox.pending,
          organizationId: previousSandbox.organizationId,
          runnerId: previousSandbox.runnerId ?? IsNull(),
        },
        lock: { mode: 'pessimistic_write' },
        relations: [],
        loadEagerRelations: false,
      })
      if (!current) {
        throw new SandboxConflictError()
      }
      await this.assertRunnerAdmission(entityManager, sandbox, current)
      const result = await entityManager.update(
        Sandbox,
        {
          id: previousSandbox.id,
          state: previousSandbox.state,
          desiredState: previousSandbox.desiredState,
          pending: previousSandbox.pending,
          organizationId: previousSandbox.organizationId,
        },
        { ...updateData, ...invariantChanges },
      )
      if (!result.affected) {
        throw new SandboxConflictError()
      }
      sandbox.updatedAt = new Date()

      if (previousSandbox.state !== sandbox.state || previousSandbox.organizationId !== sandbox.organizationId) {
        await this.upsertLastActivity(entityManager, id, sandbox.updatedAt)
        sandbox.lastActivityAt = { sandboxId: id, lastActivityAt: sandbox.updatedAt }
      }
    })

    this.emitUpdateEvents(sandbox, previousSandbox)
    this.invalidateLookupCacheOnUpdate(sandbox, previousSandbox)

    return sandbox
  }

  /**
   * Partially updates a sandbox in the database and optionally emits a corresponding event based on the changes.
   *
   * Performs the update in a transaction with a pessimistic write lock to ensure consistency.
   *
   * @param id - The ID of the sandbox to update.
   * @param params.updateData - The partial data to update.
   * @param params.whereCondition - The where condition to use for the update.
   * @param afterUpdate - A callback to be executed after the update is performed.
   *   It receives the entity manager as an argument and can be used to perform additional operations after the update.
   *
   * @throws {SandboxConflictError} if the sandbox was modified by another operation
   */
  async updateWhere(
    id: string,
    params: {
      updateData: Partial<Sandbox>
      whereCondition: FindOptionsWhere<Sandbox>
    },
    afterUpdate?: (em: EntityManager) => Promise<void>,
  ): Promise<Sandbox> {
    const { updateData, whereCondition } = params

    return this.manager.transaction(async (entityManager) => {
      const whereClause = {
        ...whereCondition,
        id,
      }

      const sandbox = await entityManager.findOne(Sandbox, {
        where: whereClause,
        lock: { mode: 'pessimistic_write' },
        relations: [],
        loadEagerRelations: false,
      })

      if (!sandbox) {
        throw new SandboxConflictError()
      }

      const previousSandbox = { ...sandbox }

      Object.assign(sandbox, updateData)
      sandbox.assertValid()
      const invariantChanges = sandbox.enforceInvariants()

      await this.assertRunnerAdmission(entityManager, sandbox, previousSandbox)
      await entityManager.update(Sandbox, id, { ...updateData, ...invariantChanges })
      sandbox.updatedAt = new Date()

      if (previousSandbox.state !== sandbox.state || previousSandbox.organizationId !== sandbox.organizationId) {
        await this.upsertLastActivity(entityManager, id, sandbox.updatedAt)
        sandbox.lastActivityAt = { sandboxId: id, lastActivityAt: sandbox.updatedAt }
      }

      if (afterUpdate) {
        await afterUpdate(entityManager)
      }

      this.emitUpdateEvents(sandbox, previousSandbox)
      this.invalidateLookupCacheOnUpdate(sandbox, previousSandbox)

      return sandbox
    })
  }

  private async assertRunnerAdmission(
    manager: EntityManager,
    sandbox: Sandbox,
    previous?: Pick<Sandbox, 'runnerId' | 'organizationId' | 'state' | 'desiredState' | 'pending'>,
  ): Promise<void> {
    if (!sandbox.runnerId) return
    const requiresAdmission =
      !previous ||
      previous.runnerId !== sandbox.runnerId ||
      previous.organizationId !== sandbox.organizationId ||
      (isSandboxQuiescent(previous) && !isSandboxQuiescent(sandbox))
    if (!requiresAdmission) return

    // Serialize admission with RunnerService's exclusive scheduling lock.
    // In-flight work may finish, stop, archive, or detach under a fence. Once
    // every assigned sandbox is quiescent, new work cannot cross the fence.
    const runner = await manager.findOne(Runner, {
      where: { id: sandbox.runnerId },
      lock: { mode: 'pessimistic_read' },
    })
    if (!runner || runner.unschedulable || runner.draining || runner.state !== RunnerState.READY) {
      throw new SandboxConflictError('Runner is not accepting new sandbox work; retry when it is schedulable')
    }
  }

  /**
   * Upserts the last activity for a sandbox.
   */
  private async upsertLastActivity(
    entityManager: EntityManager,
    sandboxId: string,
    lastActivityAt: Date,
  ): Promise<void> {
    await entityManager.upsert(SandboxLastActivity, { sandboxId, lastActivityAt }, ['sandboxId'])
  }

  /**
   * Invalidates the sandbox lookup cache for the inserted sandbox.
   */
  private invalidateLookupCacheOnInsert(sandbox: Sandbox): void {
    try {
      this.sandboxLookupCacheInvalidationService.invalidateOrgId({
        sandboxId: sandbox.id,
        organizationId: sandbox.organizationId,
        name: sandbox.name,
      })
    } catch (error) {
      this.logger.warn(
        `Failed to enqueue sandbox lookup cache invalidation on insert (id, organizationId, name) for ${sandbox.id}: ${error instanceof Error ? error.message : String(error)}`,
      )
    }
  }

  /**
   * Invalidates the sandbox lookup cache for the updated sandbox.
   */
  private invalidateLookupCacheOnUpdate(
    updatedSandbox: Sandbox,
    previousSandbox: Pick<Sandbox, 'organizationId' | 'name' | 'authToken' | 'state'>,
  ): void {
    try {
      this.sandboxLookupCacheInvalidationService.invalidate({
        sandboxId: updatedSandbox.id,
        organizationId: updatedSandbox.organizationId,
        previousOrganizationId: previousSandbox.organizationId,
        name: updatedSandbox.name,
        previousName: previousSandbox.name,
      })
    } catch (error) {
      this.logger.warn(
        `Failed to enqueue sandbox lookup cache invalidation on update (id, organizationId, name) for ${updatedSandbox.id}: ${error instanceof Error ? error.message : String(error)}`,
      )
    }

    try {
      // The auth-token lookup cache backs findByAuthToken / findBySandboxAuthToken, which
      // resolve to null once a sandbox is destroyed/archived. Bust it both when the token
      // itself rotates and when that destroyed/archived gate flips in either direction, so
      // the cached row never serves a stale state past those transitions.
      const authTokensToInvalidate = new Set<string>()
      if (updatedSandbox.authToken !== previousSandbox.authToken) {
        authTokensToInvalidate.add(previousSandbox.authToken)
      }
      if (this.isInactiveState(previousSandbox.state) !== this.isInactiveState(updatedSandbox.state)) {
        authTokensToInvalidate.add(updatedSandbox.authToken)
      }
      for (const authToken of authTokensToInvalidate) {
        if (authToken) {
          this.sandboxLookupCacheInvalidationService.invalidate({ authToken })
        }
      }
    } catch (error) {
      this.logger.warn(
        `Failed to enqueue sandbox lookup cache invalidation on update (authToken) for ${updatedSandbox.id}: ${error instanceof Error ? error.message : String(error)}`,
      )
    }
  }

  private isInactiveState(state: SandboxState): boolean {
    return state === SandboxState.DESTROYED || state === SandboxState.ARCHIVED
  }

  /**
   * Emits events based on the changes made to a sandbox.
   */
  private emitUpdateEvents(
    updatedSandbox: Sandbox,
    previousSandbox: Pick<Sandbox, 'state' | 'desiredState' | 'public' | 'organizationId' | 'authToken'>,
  ): void {
    if (previousSandbox.state !== updatedSandbox.state) {
      this.eventEmitter.emit(
        SandboxEvents.STATE_UPDATED,
        new SandboxStateUpdatedEvent(updatedSandbox, previousSandbox.state, updatedSandbox.state),
      )
    }

    if (previousSandbox.desiredState !== updatedSandbox.desiredState) {
      this.eventEmitter.emit(
        SandboxEvents.DESIRED_STATE_UPDATED,
        new SandboxDesiredStateUpdatedEvent(updatedSandbox, previousSandbox.desiredState, updatedSandbox.desiredState),
      )
    }

    if (previousSandbox.public !== updatedSandbox.public) {
      this.eventEmitter.emit(
        SandboxEvents.PUBLIC_STATUS_UPDATED,
        new SandboxPublicStatusUpdatedEvent(updatedSandbox, previousSandbox.public, updatedSandbox.public),
      )
    }

    if (previousSandbox.authToken !== updatedSandbox.authToken) {
      this.eventEmitter.emit(
        SandboxEvents.AUTH_TOKEN_ROTATED,
        new SandboxAuthTokenRotatedEvent(updatedSandbox, previousSandbox.authToken, updatedSandbox.authToken),
      )
    }

    if (previousSandbox.organizationId !== updatedSandbox.organizationId) {
      this.eventEmitter.emit(
        SandboxEvents.ORGANIZATION_UPDATED,
        new SandboxOrganizationUpdatedEvent(
          updatedSandbox,
          previousSandbox.organizationId,
          updatedSandbox.organizationId,
        ),
      )
    }
  }
}
