/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { Injectable, Logger, NotFoundException, OnApplicationShutdown } from '@nestjs/common'
import { InjectRepository } from '@nestjs/typeorm'
import { Cron, CronExpression } from '@nestjs/schedule'
import { SnapshotRepository } from '../repositories/snapshot.repository'
import { Equal, FindOptionsWhere, In, IsNull, LessThan, MoreThanOrEqual, Not, Or, Repository } from 'typeorm'
import { DockerRegistryService } from '../../docker-registry/services/docker-registry.service'
import { Snapshot } from '../entities/snapshot.entity'
import { SnapshotState } from '../enums/snapshot-state.enum'
import { SnapshotRunner } from '../entities/snapshot-runner.entity'
import { Runner } from '../entities/runner.entity'
import { DockerRegistry } from '../../docker-registry/entities/docker-registry.entity'
import { RunnerState } from '../enums/runner-state.enum'
import { SnapshotRunnerState } from '../enums/snapshot-runner-state.enum'
import { v4 as uuidv4 } from 'uuid'
import { RunnerNotReadyError } from '../errors/runner-not-ready.error'
import { RedisLockProvider } from '../common/redis-lock.provider'
import { OrganizationService } from '../../organization/services/organization.service'
import { BuildInfo } from '../entities/build-info.entity'
import { fromAxiosError } from '../../common/utils/from-axios-error'
import { InjectRedis } from '@nestjs-modules/ioredis'
import { Redis } from 'ioredis'
import { RunnerService } from '../services/runner.service'
import { TrackableJobExecutions } from '../../common/interfaces/trackable-job-executions'
import { TrackJobExecution } from '../../common/decorators/track-job-execution.decorator'
import { setTimeout as sleep } from 'timers/promises'
import {
  DEDICATED_REGIONS_PER_ORGANIZATION,
  resolveEffectiveRegion,
  LARGE_SANDBOX_ORGS,
  LARGE_SANDBOX_SHARED_REGION,
  WRITER_ORGS,
  RL_REGION,
  ELEMENTOR_DEDICATED_REGION,
  META_DEDICATED_REGION,
  DEEPTUNE_AND_MILLION_DEDICATED_REGION,
  getFallbackRegion,
} from '../constants/dedicated-regions.constant'
import { areResourcesLargerThanDefault } from '../utils/resources'
import { LogExecution } from '../../common/decorators/log-execution.decorator'
import { WithInstrumentation } from '../../common/decorators/otel.decorator'
import { RunnerAdapterFactory, SnapshotDigestResponse } from '../runner-adapter/runnerAdapter'
import { SnapshotStateError } from '../errors/snapshot-state-error'
import { SnapshotEvents } from '../constants/snapshot-events'
import { SnapshotCreatedEvent } from '../events/snapshot-created.event'
import { SnapshotService } from '../services/snapshot.service'
import { OnAsyncEvent } from '../../common/decorators/on-async-event.decorator'
import { parseDockerImage } from '../../common/utils/docker-image.util'
import { getRunnerSandboxClass, isRegistryBasedSandboxClass } from '../utils/sandbox-class.util'
import { SandboxClass } from '../enums/sandbox-class.enum'
import { SandboxState } from '../enums/sandbox-state.enum'
import { SandboxDesiredState } from '../enums/sandbox-desired-state.enum'
import { BackupState } from '../enums/backup-state.enum'
import { BadRequestError } from '../../exceptions/bad-request.exception'
import { SandboxRepository } from '../repositories/sandbox.repository'
import { SnapshotInfoResponse } from '@daytona/runner-api-client'
import { SnapshotActivatedEvent } from '../events/snapshot-activated.event'
import { SnapshotInitialRunnerReadyEvent } from '../events/snapshot-initial-runner-ready.event'
import { TypedConfigService } from '../../config/typed-config.service'
import {
  getSnapshotPropagationFactor,
  DEDICATED_REGION_PROPAGATION_OVERRIDES,
} from '../constants/propagation-tiers.constant'
import { RegionType } from '../../region/enums/region-type.enum'
import { GpuType } from '../enums/gpu-type.enum'

/** Fisher-Yates shuffle — uniform random permutation in O(n). */
function shuffleArray<T>(array: T[]): T[] {
  const shuffled = [...array]
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]]
  }
  return shuffled
}

const SYNC_AGAIN = 'sync-again'
const DONT_SYNC_AGAIN = 'dont-sync-again'
const DEFAULT_SNAPSHOT_DEACTIVATION_TIMEOUT_MINUTES = 14 * 24 * 60 // 14 days
type SyncState = typeof SYNC_AGAIN | typeof DONT_SYNC_AGAIN
const BASE_PROPAGATION_FACTOR = 1 / 3

@Injectable()
export class SnapshotManager implements TrackableJobExecutions, OnApplicationShutdown {
  activeJobs = new Set<string>()

  private readonly logger = new Logger(SnapshotManager.name)
  //  generate a unique instance id used to ensure only one instance of the worker is handing the
  //  snapshot activation
  private readonly instanceId = uuidv4()

  constructor(
    @InjectRedis() private readonly redis: Redis,
    private readonly snapshotRepository: SnapshotRepository,
    @InjectRepository(SnapshotRunner)
    private readonly snapshotRunnerRepository: Repository<SnapshotRunner>,
    @InjectRepository(Runner)
    private readonly runnerRepository: Repository<Runner>,
    private readonly sandboxRepository: SandboxRepository,
    @InjectRepository(BuildInfo)
    private readonly buildInfoRepository: Repository<BuildInfo>,
    private readonly runnerService: RunnerService,
    private readonly dockerRegistryService: DockerRegistryService,
    private readonly runnerAdapterFactory: RunnerAdapterFactory,
    private readonly redisLockProvider: RedisLockProvider,
    private readonly organizationService: OrganizationService,
    private readonly snapshotService: SnapshotService,
    private readonly configService: TypedConfigService,
  ) {}

  async onApplicationShutdown() {
    //  wait for all active jobs to finish
    while (this.activeJobs.size > 0) {
      this.logger.log(`Waiting for ${this.activeJobs.size} active jobs to finish`)
      await sleep(1000)
    }
  }

  @Cron(CronExpression.EVERY_MINUTE, { name: 'scale-down-runner-snapshots', waitForCompletion: true })
  @TrackJobExecution()
  @LogExecution('scale-down-runner-snapshots')
  @WithInstrumentation()
  async scaleDownRunnerSnapshots() {
    const lockKey = 'scale-down-runner-snapshots-lock'
    const lockTtl = 3 * 60 // seconds (3 min)
    if (!(await this.redisLockProvider.lock(lockKey, lockTtl))) {
      return
    }

    const skip = (await this.redis.get('scale-down-runner-snapshots-skip')) || 0

    const defaultOrganizationQuota = this.configService.getOrThrow('defaultOrganizationQuota')

    const snapshots = await this.snapshotRepository
      .createQueryBuilder('snapshot')
      .innerJoin('organization', 'org', 'org.id = snapshot.organizationId')
      .innerJoin('region_quota', 'rq', 'rq."organizationId" = org.id AND rq."regionId" = org."defaultRegionId"')
      .select(['snapshot.*', 'rq.total_cpu_quota'])
      .where('snapshot.state = :snapshotState', { snapshotState: SnapshotState.ACTIVE })
      .andWhere('org.suspended = false')
      .andWhere(
        `
        NOT (
          org.id = ANY(:largeSbxSharedOrgs)
          AND (
            snapshot.cpu > :defaultMaxCpuPerSandbox OR
            snapshot.mem > :defaultMaxMemoryPerSandbox OR
            snapshot.disk > :defaultMaxDiskPerSandbox
          )
        )
      `,
      )
      // Don't scale down freshly-created snapshots; give propagation time to settle first.
      .andWhere('snapshot."createdAt" < :scaleDownSnapshotCutoff', {
        scaleDownSnapshotCutoff: new Date(Date.now() - 60 * 60 * 1000),
      })
      .orderBy('snapshot.createdAt', 'ASC')
      .limit(100)
      .offset(Number(skip))
      .setParameters({
        largeSbxSharedOrgs: [...LARGE_SANDBOX_ORGS],
        defaultMaxCpuPerSandbox: defaultOrganizationQuota.maxCpuPerSandbox,
        defaultMaxMemoryPerSandbox: defaultOrganizationQuota.maxMemoryPerSandbox,
        defaultMaxDiskPerSandbox: defaultOrganizationQuota.maxDiskPerSandbox,
      })
      .getRawMany()

    if (snapshots.length === 0) {
      await this.redisLockProvider.unlock(lockKey)
      await this.redis.set('scale-down-runner-snapshots-skip', 0)
      return
    }

    await this.redis.set('scale-down-runner-snapshots-skip', Number(skip) + snapshots.length)

    // snapshot_runner rows are keyed by (runnerId, snapshotRef), so every snapshot that resolves to the same
    // ref (e.g. the same image used by multiple orgs, or under multiple names) shares one pool of copies.
    // Propagation naturally tops the pool up to the highest-demand org's target, but scale-down runs per
    // snapshot row — so a low-quota org would otherwise trim copies that a high-quota org keeps refilling,
    // causing the ref to flap. Compute the scale-down ceiling per ref as the MAX demand across all active
    // snapshots that share it.
    const refDemandMap = await this.getRefPropagationDemand(
      snapshots.map((snapshot) => snapshot.ref).filter((ref): ref is string => !!ref),
    )

    const results = await Promise.allSettled(
      snapshots.map(async (snapshot) => {
        const { factor: propagationFactor, minimum: minimumRunners } =
          (snapshot.ref && refDemandMap.get(snapshot.ref)) ||
          getSnapshotPropagationFactor(snapshot.total_cpu_quota, snapshot)

        const regions = await this.snapshotService.getSnapshotRegions(snapshot.id)

        const sharedRegionIds = regions
          .filter((r) => r.organizationId === null && r.regionType === RegionType.SHARED)
          .map((r) => r.id)

        return this.scaleDownSnapshotFromRunners(snapshot, sharedRegionIds, propagationFactor, minimumRunners)
      }),
    )

    results.forEach((result) => {
      if (result.status === 'rejected') {
        this.logger.error(`Error scaling down snapshot from runners: ${fromAxiosError(result.reason)}`)
      }
    })

    await this.redisLockProvider.unlock(lockKey)
  }

  // @Cron(CronExpression.EVERY_MINUTE, { name: 'scale-down-runner-snapshots-rl', waitForCompletion: true })
  @TrackJobExecution()
  @LogExecution('scale-down-runner-snapshots-rl')
  @WithInstrumentation()
  async scaleDownRunnerSnapshotsRL() {
    const lockKey = 'scale-down-runner-snapshots-rl-lock'
    const lockTtl = 3 * 60 // seconds (3 min)
    if (!(await this.redisLockProvider.lock(lockKey, lockTtl))) {
      return
    }

    const skip = (await this.redis.get('scale-down-runner-snapshots-rl-skip')) || 0

    const snapshots = await this.snapshotRepository
      .createQueryBuilder('snapshot')
      .innerJoin('organization', 'org', 'org.id = snapshot.organizationId')
      .innerJoin('region_quota', 'rq', 'rq."organizationId" = org.id AND rq."regionId" = org."defaultRegionId"')
      .innerJoin('snapshot_region', 'sr', 'sr."snapshotId" = snapshot.id AND sr."regionId" = :rlRegion', {
        rlRegion: RL_REGION,
      })
      .select(['snapshot.*', 'rq.total_cpu_quota'])
      .where('snapshot.state = :snapshotState', { snapshotState: SnapshotState.ACTIVE })
      .andWhere('org.suspended = false')
      .andWhere('snapshot."createdAt" BETWEEN :rlScaleDownStart AND :rlScaleDownEnd', {
        rlScaleDownStart: '2026-04-24',
        rlScaleDownEnd: '2026-04-28',
      })
      .orderBy('snapshot.createdAt', 'ASC')
      .limit(50)
      .offset(Number(skip))
      .getRawMany()

    if (snapshots.length === 0) {
      await this.redisLockProvider.unlock(lockKey)
      await this.redis.set('scale-down-runner-snapshots-rl-skip', 0)
      return
    }

    await this.redis.set('scale-down-runner-snapshots-rl-skip', Number(skip) + snapshots.length)

    const results = await Promise.allSettled(
      snapshots.map(async (snapshot) => {
        const { factor: propagationFactor, minimum: minimumRunners } = getSnapshotPropagationFactor(
          snapshot.total_cpu_quota,
          snapshot,
          RL_REGION,
        )

        return this.scaleDownSnapshotFromRunners(snapshot, [RL_REGION], propagationFactor, minimumRunners)
      }),
    )

    results.forEach((result) => {
      if (result.status === 'rejected') {
        this.logger.error(`Error scaling down RL snapshot from runners: ${fromAxiosError(result.reason)}`)
      }
    })

    await this.redisLockProvider.unlock(lockKey)
  }

  @Cron(CronExpression.EVERY_5_SECONDS, { name: 'sync-runner-snapshots', waitForCompletion: true })
  @TrackJobExecution()
  @LogExecution('sync-runner-snapshots')
  @WithInstrumentation()
  async syncRunnerSnapshots() {
    const lockKey = 'sync-runner-snapshots-lock'
    const lockTtl = 10 * 60 // seconds (10 min)
    if (!(await this.redisLockProvider.lock(lockKey, lockTtl))) {
      return
    }

    const skip = (await this.redis.get('sync-runner-snapshots-skip')) || 0

    const defaultOrganizationQuota = this.configService.getOrThrow('defaultOrganizationQuota')

    const snapshots = await this.snapshotRepository
      .createQueryBuilder('snapshot')
      .innerJoin('organization', 'org', 'org.id = snapshot.organizationId')
      .innerJoin('region_quota', 'rq', 'rq."organizationId" = org.id AND rq."regionId" = org."defaultRegionId"')
      .select(['snapshot.*', 'rq.total_cpu_quota'])
      .where('snapshot.state = :snapshotState', { snapshotState: SnapshotState.ACTIVE })
      .andWhere('org.suspended = false')
      .andWhere("org.id != '8c0f7497-8037-4515-89a3-992bb9230cbc'")
      .andWhere(
        `
        NOT (
          org.id = ANY(:largeSbxSharedOrgs)
          AND (
            snapshot.cpu > :defaultMaxCpuPerSandbox OR
            snapshot.mem > :defaultMaxMemoryPerSandbox OR
            snapshot.disk > :defaultMaxDiskPerSandbox
          )
        )
      `,
      )
      // Skip freshly-created snapshots; waitForInitialPropagation already does the initial push for them.
      .andWhere('snapshot."createdAt" < :syncSnapshotCutoff', {
        syncSnapshotCutoff: new Date(Date.now() - 10 * 60 * 1000),
      })
      .orderBy('snapshot.createdAt', 'ASC')
      .limit(150)
      .offset(Number(skip))
      .setParameters({
        largeSbxSharedOrgs: [...LARGE_SANDBOX_ORGS],
        defaultMaxCpuPerSandbox: defaultOrganizationQuota.maxCpuPerSandbox,
        defaultMaxMemoryPerSandbox: defaultOrganizationQuota.maxMemoryPerSandbox,
        defaultMaxDiskPerSandbox: defaultOrganizationQuota.maxDiskPerSandbox,
      })
      .getRawMany()

    if (snapshots.length === 0) {
      await this.redisLockProvider.unlock(lockKey)
      await this.redis.set('sync-runner-snapshots-skip', 0)
      return
    }

    await this.redis.set('sync-runner-snapshots-skip', Number(skip) + snapshots.length)

    const results = await Promise.allSettled(
      snapshots.map(async (snapshot) => {
        const { factor: propagationFactor, minimum: minimumRunners } = getSnapshotPropagationFactor(
          snapshot.total_cpu_quota,
          snapshot,
        )

        const regions = await this.snapshotService.getSnapshotRegions(snapshot.id)

        const sharedRegionIds = regions.filter((r) => r.organizationId === null && r.id !== RL_REGION).map((r) => r.id)
        const organizationRegionIds = regions
          .filter((r) => r.organizationId === snapshot.organizationId && r.id !== RL_REGION)
          .map((r) => r.id)

        return this.propagateSnapshotToRunners(
          snapshot,
          sharedRegionIds,
          organizationRegionIds,
          propagationFactor,
          minimumRunners,
        )
      }),
    )

    // Log all promise errors
    results.forEach((result) => {
      if (result.status === 'rejected') {
        this.logger.error(`Error propagating snapshot to runners: ${fromAxiosError(result.reason)}`)
      }
    })

    await this.redisLockProvider.unlock(lockKey)
  }

  @Cron(CronExpression.EVERY_5_SECONDS, { name: 'sync-runner-snapshots-rl', waitForCompletion: true })
  @TrackJobExecution()
  @LogExecution('sync-runner-snapshots-rl')
  @WithInstrumentation()
  async syncRunnerSnapshotsRL() {
    const lockKey = 'sync-runner-snapshots-rl-lock'
    const lockTtl = 10 * 60 // seconds (10 min)
    if (!(await this.redisLockProvider.lock(lockKey, lockTtl))) {
      return
    }

    const skip = (await this.redis.get('sync-runner-snapshots-rl-skip')) || 0

    const snapshots = await this.snapshotRepository
      .createQueryBuilder('snapshot')
      .innerJoin('organization', 'org', 'org.id = snapshot.organizationId')
      .innerJoin('region_quota', 'rq', 'rq."organizationId" = org.id AND rq."regionId" = org."defaultRegionId"')
      .innerJoin('snapshot_region', 'sr', 'sr."snapshotId" = snapshot.id AND sr."regionId" = :rlRegion', {
        rlRegion: RL_REGION,
      })
      .select(['snapshot.*', 'rq.total_cpu_quota'])
      .where('snapshot.state = :snapshotState', { snapshotState: SnapshotState.ACTIVE })
      .andWhere('org.suspended = false')
      .orderBy('snapshot.createdAt', 'ASC')
      .limit(250)
      .offset(Number(skip))
      .getRawMany()

    if (snapshots.length === 0) {
      await this.redisLockProvider.unlock(lockKey)
      await this.redis.set('sync-runner-snapshots-rl-skip', 0)
      return
    }

    await this.redis.set('sync-runner-snapshots-rl-skip', Number(skip) + snapshots.length)

    const results = await Promise.allSettled(
      snapshots.map(async (snapshot) => {
        const { factor: propagationFactor, minimum: minimumRunners } = getSnapshotPropagationFactor(
          snapshot.total_cpu_quota,
          snapshot,
          RL_REGION,
        )

        const regions = await this.snapshotService.getSnapshotRegions(snapshot.id)

        const sharedRegionIds = regions.filter((r) => r.organizationId === null && r.id === RL_REGION).map((r) => r.id)
        const organizationRegionIds = regions
          .filter((r) => r.organizationId === snapshot.organizationId && r.id === RL_REGION)
          .map((r) => r.id)

        return this.propagateSnapshotToRunners(
          snapshot,
          sharedRegionIds,
          organizationRegionIds,
          propagationFactor,
          minimumRunners,
          10,
        )
      }),
    )

    // Log all promise errors
    results.forEach((result) => {
      if (result.status === 'rejected') {
        this.logger.error(`Error propagating snapshot to runners: ${fromAxiosError(result.reason)}`)
      }
    })

    await this.redisLockProvider.unlock(lockKey)
  }

  @Cron(CronExpression.EVERY_30_SECONDS, { name: 'sync-dedicated-runner-snapshots', waitForCompletion: true })
  @TrackJobExecution()
  @LogExecution('sync-dedicated-runner-snapshots')
  async syncDedicatedRunnerSnapshots() {
    const lockKey = 'sync-dedicated-runner-snapshots-lock'
    if (!(await this.redisLockProvider.lock(lockKey, 30))) {
      return
    }

    const orgIds = [...new Set(Object.keys(DEDICATED_REGIONS_PER_ORGANIZATION))]

    const snapshots = await this.snapshotRepository
      .createQueryBuilder('snapshot')
      .innerJoin('organization', 'org', 'org.id = snapshot.organizationId')
      .select(['snapshot.*'])
      .where('snapshot.state = :snapshotState', { snapshotState: SnapshotState.ACTIVE })
      .andWhere('org.suspended = false')
      .andWhere('org.id IN (:...orgIds)', { orgIds })
      .orderBy('RANDOM()')
      .limit(100)
      .getRawMany()

    if (snapshots.length === 0) {
      return
    }

    const response = await Promise.allSettled(
      snapshots.map((snapshot) => {
        let regions = []
        if (WRITER_ORGS.includes(snapshot.organizationId)) {
          ;['us', 'eu'].forEach((region) => {
            const dedicatedRegion = resolveEffectiveRegion(snapshot.organizationId, region, this.configService, {
              cpu: snapshot.cpu,
              memory: snapshot.mem,
              disk: snapshot.disk,
              gpu: snapshot.gpu,
            })
            if (dedicatedRegion !== region) {
              regions.push(dedicatedRegion)
            }
          })
        } else {
          regions = DEDICATED_REGIONS_PER_ORGANIZATION[snapshot.organizationId] || []
        }

        if (
          LARGE_SANDBOX_ORGS.has(snapshot.organizationId) &&
          !areResourcesLargerThanDefault(this.configService, {
            cpu: snapshot.cpu,
            memory: snapshot.mem,
            disk: snapshot.disk,
            gpu: snapshot.gpu,
          })
        ) {
          regions = regions.filter((region) => region !== LARGE_SANDBOX_SHARED_REGION)
        }

        return Promise.allSettled(
          regions.map(async (region) => {
            if (!snapshot.ref) {
              return
            }

            const runners = await this.runnerRepository.find({
              where: this.eligibleRunnerWhere(snapshot, [region]),
            })
            if (!runners.length) {
              return
            }

            // Runners that already have (or are pulling) this snapshot are skipped.
            const existingSnapshotRunners = await this.snapshotRunnerRepository.find({
              where: {
                snapshotRef: snapshot.ref,
                runnerId: In(runners.map((runner) => runner.id)),
              },
            })
            const allocatedRunnerIds = new Set(existingSnapshotRunners.map((sr) => sr.runnerId))

            let runnersToPropagateTo = runners.filter((runner) => !allocatedRunnerIds.has(runner.id))

            // By default dedicated regions receive the snapshot on every runner (100%). Some orgs are
            // capped to a percentage of the dedicated fleet instead.
            const override = DEDICATED_REGION_PROPAGATION_OVERRIDES[snapshot.organizationId]
            if (override) {
              const target = Math.max(override.minimum, Math.ceil((override.percentage / 100) * runners.length))
              const remaining = Math.max(0, target - allocatedRunnerIds.size)
              runnersToPropagateTo = shuffleArray(runnersToPropagateTo).slice(0, remaining)
            }

            return Promise.allSettled(
              runnersToPropagateTo.map(async (runner) => {
                await this.runnerService.createSnapshotRunnerEntry(
                  runner.id,
                  snapshot.ref,
                  SnapshotRunnerState.PULLING_SNAPSHOT,
                )
                // Use base region for registry lookup (dedicated regions may not have registry configs)
                const regionForRegistry = getFallbackRegion(runner.region) ?? runner.region
                const dockerRegistry = await this.dockerRegistryService.findInternalRegistryBySnapshotRef(
                  snapshot.ref,
                  regionForRegistry,
                )
                return this.pullSnapshotRunner(
                  runner,
                  snapshot.ref,
                  dockerRegistry,
                  undefined,
                  undefined,
                  undefined,
                  snapshot.disk,
                )
              }),
            )
          }),
        )
      }),
    )

    response.forEach((res) => {
      if (res.status === 'rejected') {
        this.logger.error(`Error propagating snapshot to dedicated runner: ${res.reason}`)
      }
    })

    await this.redisLockProvider.unlock(lockKey)
  }

  @Cron(CronExpression.EVERY_5_SECONDS, { name: 'sync-pulling-runner-snapshot-states', waitForCompletion: true })
  @TrackJobExecution()
  @LogExecution('sync-pulling-runner-snapshot-states')
  @WithInstrumentation()
  async syncPullingRunnerSnapshotStates() {
    const lockKey = 'sync-pulling-runner-snapshot-states-lock'
    if (!(await this.redisLockProvider.lock(lockKey, 30))) {
      return
    }

    const runnerSnapshots = await this.snapshotRunnerRepository
      .createQueryBuilder('snapshotRunner')
      .where({
        state: SnapshotRunnerState.PULLING_SNAPSHOT,
      })
      .orderBy('RANDOM()')
      .take(100)
      .getMany()

    await Promise.allSettled(
      runnerSnapshots.map((snapshotRunner) => {
        return this.syncRunnerSnapshotState(snapshotRunner).catch((err) => {
          if (err.code !== 'ECONNRESET') {
            if (err instanceof RunnerNotReadyError) {
              this.logger.debug(
                `Runner ${snapshotRunner.runnerId} is not ready while trying to sync snapshot runner ${snapshotRunner.id}: ${err}`,
              )
              return
            }
            this.logger.error(`Error syncing runner snapshot state ${snapshotRunner.id}: ${fromAxiosError(err)}`)
            this.snapshotRunnerRepository.update(snapshotRunner.id, {
              state: SnapshotRunnerState.ERROR,
              errorReason: fromAxiosError(err).message,
            })
          }
        })
      }),
    )

    await this.redisLockProvider.unlock(lockKey)
  }

  @Cron(CronExpression.EVERY_5_SECONDS, { name: 'sync-building-runner-snapshot-states', waitForCompletion: true })
  @TrackJobExecution()
  @LogExecution('sync-building-runner-snapshot-states')
  @WithInstrumentation()
  async syncBuildingRunnerSnapshotStates() {
    const lockKey = 'sync-building-runner-snapshot-states-lock'
    if (!(await this.redisLockProvider.lock(lockKey, 30))) {
      return
    }

    const runnerSnapshots = await this.snapshotRunnerRepository
      .createQueryBuilder('snapshotRunner')
      .where({
        state: SnapshotRunnerState.BUILDING_SNAPSHOT,
      })
      .orderBy('RANDOM()')
      .take(100)
      .getMany()

    await Promise.allSettled(
      runnerSnapshots.map((snapshotRunner) => {
        return this.syncRunnerSnapshotState(snapshotRunner).catch((err) => {
          if (err.code !== 'ECONNRESET') {
            if (err instanceof RunnerNotReadyError) {
              this.logger.debug(
                `Runner ${snapshotRunner.runnerId} is not ready while trying to sync snapshot runner ${snapshotRunner.id}: ${err}`,
              )
              return
            }
            this.logger.error(`Error syncing runner snapshot state ${snapshotRunner.id}: ${fromAxiosError(err)}`)
            this.snapshotRunnerRepository.update(snapshotRunner.id, {
              state: SnapshotRunnerState.ERROR,
              errorReason: fromAxiosError(err).message,
            })
          }
        })
      }),
    )

    await this.redisLockProvider.unlock(lockKey)
  }

  // REMOVING is split out to its own cron with its own lock so it doesn't compete with
  // the higher-priority PULLING/BUILDING states. We additionally wait at least 3 minutes
  // since the last update to give in-flight removals a chance to settle on the runner.
  @Cron(CronExpression.EVERY_5_SECONDS, { name: 'sync-removing-runner-snapshot-states' })
  @TrackJobExecution()
  @LogExecution('sync-removing-runner-snapshot-states')
  @WithInstrumentation()
  async syncRemovingRunnerSnapshotStates() {
    const lockKey = 'sync-removing-runner-snapshot-states-lock'
    if (!(await this.redisLockProvider.lock(lockKey, 30))) {
      return
    }

    const threeMinutesAgo = new Date(Date.now() - 3 * 60 * 1000)
    const runnerSnapshots = await this.snapshotRunnerRepository
      .createQueryBuilder('snapshotRunner')
      .where({
        state: SnapshotRunnerState.REMOVING,
        updatedAt: LessThan(threeMinutesAgo),
      })
      .orderBy('RANDOM()')
      .take(200)
      .getMany()

    await Promise.allSettled(
      runnerSnapshots.map((snapshotRunner) => {
        return this.syncRunnerSnapshotState(snapshotRunner).catch((err) => {
          if (err.code !== 'ECONNRESET') {
            if (err instanceof RunnerNotReadyError) {
              this.logger.debug(
                `Runner ${snapshotRunner.runnerId} is not ready while trying to sync snapshot runner ${snapshotRunner.id}: ${err}`,
              )
              return
            }
            this.logger.error(`Error syncing runner snapshot state ${snapshotRunner.id}: ${fromAxiosError(err)}`)
            this.snapshotRunnerRepository.update(snapshotRunner.id, {
              state: SnapshotRunnerState.ERROR,
              errorReason: fromAxiosError(err).message,
            })
          }
        })
      }),
    )

    await this.redisLockProvider.unlock(lockKey)
  }

  async syncRunnerSnapshotState(snapshotRunner: SnapshotRunner): Promise<void> {
    const runner = await this.runnerService.findOne(snapshotRunner.runnerId)
    if (!runner) {
      //  cleanup the snapshot runner record if the runner is not found
      //  this can happen if the runner is deleted from the database without cleaning up the snapshot runners
      await this.snapshotRunnerRepository.delete(snapshotRunner.id)
      this.logger.warn(
        `Runner ${snapshotRunner.runnerId} not found while trying to process snapshot runner ${snapshotRunner.id}. Snapshot runner has been removed.`,
      )
      return
    }

    if (runner.state !== RunnerState.READY) {
      const unresponsiveRetentionMs =
        this.configService.getOrThrow('unresponsiveRunnerSnapshotRetentionHours') * 60 * 60 * 1000
      const recentlySignaled =
        runner.state !== RunnerState.DECOMMISSIONED &&
        runner.lastChecked != null &&
        Date.now() - runner.lastChecked.getTime() < unresponsiveRetentionMs

      if (recentlySignaled) {
        // Keep the row and back off; the runner is likely to recover and resume the pull.
        throw new RunnerNotReadyError(
          `Runner ${runner.id} is not ready (state=${runner.state}); retaining snapshot runner ${snapshotRunner.id}`,
        )
      }

      await this.snapshotRunnerRepository.delete(snapshotRunner.id)

      throw new RunnerNotReadyError(`Runner ${runner.id} is not ready`)
    }

    switch (snapshotRunner.state) {
      case SnapshotRunnerState.PULLING_SNAPSHOT:
        await this.handleSnapshotRunnerStatePullingSnapshot(snapshotRunner, runner)
        break
      case SnapshotRunnerState.BUILDING_SNAPSHOT:
        await this.handleSnapshotRunnerStateBuildingSnapshot(snapshotRunner, runner)
        break
      case SnapshotRunnerState.REMOVING:
        await this.handleSnapshotRunnerStateRemoving(snapshotRunner, runner)
        break
    }
  }

  /**
   * Build the WHERE clause that selects the runners eligible to hold a given snapshot.
   *
   * This is shared by propagateSnapshotToRunners and scaleDownSnapshotFromRunners so both operate on the
   * exact same eligible-runner set. The eligible-runner count is the denominator of the propagation target
   * (`ceil(factor * eligibleRunners)`); if the two paths used different filters they would compute different
   * targets and fight each other (propagation re-pulling what scale-down removes, and vice versa).
   */
  private eligibleRunnerWhere(snapshot: Snapshot, regionIds: string[]): FindOptionsWhere<Runner> {
    return {
      state: RunnerState.READY,
      unschedulable: Not(true),
      draining: Not(true),
      region: In(regionIds),
      gpu: snapshot.gpu > 0 ? MoreThanOrEqual(snapshot.gpu) : Or(IsNull(), Equal(0)),
      gpuType: snapshot.gpuType ? snapshot.gpuType : Or(IsNull(), Not(In(Object.values(GpuType)))),
      // Temporary: Android snapshots can go to container runners
      sandboxClass: getRunnerSandboxClass(snapshot.sandboxClass),
    }
  }

  /**
   * For each of the given snapshot refs, compute the maximum propagation demand (factor and minimum) across
   * all ACTIVE snapshots that resolve to that ref.
   *
   * Because snapshot_runner copies are shared per ref, the scale-down ceiling for a ref must reflect the
   * highest-demand snapshot sharing it; otherwise a lower-demand snapshot's scale-down would remove copies a
   * higher-demand snapshot's propagation keeps recreating. Using the max is intentionally conservative (it may
   * retain slightly more than any single org strictly needs) which is the safe direction — it prevents flapping.
   */
  private async getRefPropagationDemand(refs: string[]): Promise<Map<string, { factor: number; minimum: number }>> {
    const demandMap = new Map<string, { factor: number; minimum: number }>()

    const distinctRefs = [...new Set(refs)]
    if (distinctRefs.length === 0) {
      return demandMap
    }

    // Mirror the quota join used by propagation/scale-down so the factor is computed from the org's real quota.
    const sharingSnapshots = await this.snapshotRepository
      .createQueryBuilder('snapshot')
      .innerJoin('organization', 'org', 'org.id = snapshot.organizationId')
      .innerJoin('region_quota', 'rq', 'rq."organizationId" = org.id AND rq."regionId" = org."defaultRegionId"')
      .select(['snapshot.*', 'rq.total_cpu_quota'])
      .where('snapshot.state = :snapshotState', { snapshotState: SnapshotState.ACTIVE })
      .andWhere('org.suspended = false')
      .andWhere('snapshot.ref IN (:...refs)', { refs: distinctRefs })
      .getRawMany()

    for (const sharing of sharingSnapshots) {
      const { factor, minimum } = getSnapshotPropagationFactor(sharing.total_cpu_quota, sharing)
      const current = demandMap.get(sharing.ref)
      if (current) {
        current.factor = Math.max(current.factor, factor)
        current.minimum = Math.max(current.minimum, minimum)
      } else {
        demandMap.set(sharing.ref, { factor, minimum })
      }
    }

    return demandMap
  }

  /**
   * The number of shared runners a snapshot should be propagated to.
   *
   * Shared by propagateSnapshotToRunners (as the propagation goal) and scaleDownSnapshotFromRunners (as the
   * ceiling above which copies are removed) so the two are always computed identically from the same inputs.
   */
  private getTargetSharedRunnerCount(
    eligibleSharedRunnerCount: number,
    propagationFactor: number,
    minimumRunners: number,
  ): number {
    return Math.max(minimumRunners, Math.ceil(propagationFactor * eligibleSharedRunnerCount))
  }

  async propagateSnapshotToRunners(
    snapshot: Snapshot,
    sharedRegionIds: string[],
    organizationRegionIds: string[],
    propagationFactor: number,
    minimumRunners = 0,
    excludeTopDiskUsagePercent = 5,
  ) {
    //  todo: remove try catch block and implement error handling
    try {
      //  get all runners in the regions to propagate to
      const runners = await this.runnerRepository.find({
        where: this.eligibleRunnerWhere(snapshot, [...sharedRegionIds, ...organizationRegionIds]),
      })

      // Identify the top N% of runners by disk usage so we don't push NEW snapshot copies onto runners that are nearly full.
      // Existing snapshot_runner entries on these runners still count toward the propagation goal — we just don't add more.
      const ineligibleRunnerIds = new Set<string>()
      if (excludeTopDiskUsagePercent > 0 && runners.length > 0) {
        const sortedByDiskUsageDesc = [...runners].sort(
          (a, b) => b.currentDiskUsagePercentage - a.currentDiskUsagePercentage,
        )
        const excludeCount = Math.floor((sortedByDiskUsageDesc.length * excludeTopDiskUsagePercent) / 100)
        for (let i = 0; i < excludeCount; i++) {
          ineligibleRunnerIds.add(sortedByDiskUsageDesc[i].id)
        }
      }

      const sharedRunners = runners.filter((runner) => sharedRegionIds.includes(runner.region))
      const sharedRunnerIds = sharedRunners.map((runner) => runner.id)

      const organizationRunners = runners.filter((runner) => organizationRegionIds.includes(runner.region))
      const organizationRunnerIds = organizationRunners.map((runner) => runner.id)

      //  get all runners where the snapshot is already propagated to (or in progress)
      const sharedSnapshotRunners = sharedRunnerIds.length
        ? await this.snapshotRunnerRepository.find({
            where: {
              snapshotRef: snapshot.ref,
              state: In([SnapshotRunnerState.READY, SnapshotRunnerState.PULLING_SNAPSHOT]),
              runnerId: In(sharedRunnerIds),
            },
          })
        : []
      const sharedSnapshotRunnersDistinctRunnersIds = new Set(
        sharedSnapshotRunners.map((snapshotRunner) => snapshotRunner.runnerId),
      )

      const organizationSnapshotRunners = organizationRunnerIds.length
        ? await this.snapshotRunnerRepository.find({
            where: {
              snapshotRef: snapshot.ref,
              state: In([SnapshotRunnerState.READY, SnapshotRunnerState.PULLING_SNAPSHOT]),
              runnerId: In(organizationRunnerIds),
            },
          })
        : []
      const organizationSnapshotRunnersDistinctRunnersIds = new Set(
        organizationSnapshotRunners.map((snapshotRunner) => snapshotRunner.runnerId),
      )

      //  get all runners where the snapshot is not propagated to and that are eligible to receive new copies
      const unallocatedSharedRunners = sharedRunners.filter(
        (runner) => !sharedSnapshotRunnersDistinctRunnersIds.has(runner.id) && !ineligibleRunnerIds.has(runner.id),
      )
      const unallocatedOrganizationRunners = organizationRunners.filter(
        (runner) =>
          !organizationSnapshotRunnersDistinctRunnersIds.has(runner.id) && !ineligibleRunnerIds.has(runner.id),
      )

      const runnersToPropagateTo: Runner[] = []

      // propagate the snapshot to all organization runners
      runnersToPropagateTo.push(...unallocatedOrganizationRunners)

      // respect the propagation limit for shared runners, enforcing a minimum
      const targetSharedRunnerCount = this.getTargetSharedRunnerCount(
        sharedRunners.length,
        propagationFactor,
        minimumRunners,
      )
      const sharedRunnersPropagateLimit = Math.max(
        0,
        targetSharedRunnerCount - sharedSnapshotRunnersDistinctRunnersIds.size,
      )
      runnersToPropagateTo.push(...shuffleArray(unallocatedSharedRunners).slice(0, sharedRunnersPropagateLimit))

      if (runnersToPropagateTo.length === 0) {
        return
      }

      // regionId -> registry
      const internalRegistriesMap = new Map<string, DockerRegistry>()
      const registryBased = isRegistryBasedSandboxClass(snapshot.sandboxClass)

      if (registryBased) {
        for (const regionId of [...sharedRegionIds, ...organizationRegionIds]) {
          const registry = await this.dockerRegistryService.findInternalRegistryBySnapshotRef(snapshot.ref, regionId)
          if (registry) {
            internalRegistriesMap.set(regionId, registry)
          }
        }
      }

      const results = await Promise.allSettled(
        runnersToPropagateTo.map(async (runner) => {
          const internalRegistry = internalRegistriesMap.get(runner.region)
          if (registryBased && !internalRegistry) {
            throw new Error(`No internal registry found for snapshot ${snapshot.ref} in region ${runner.region}`)
          }

          let snapshotRunner = await this.runnerService.getSnapshotRunner(runner.id, snapshot.ref)

          try {
            if (!snapshotRunner) {
              await this.runnerService.createSnapshotRunnerEntry(
                runner.id,
                snapshot.ref,
                SnapshotRunnerState.PULLING_SNAPSHOT,
              )
              await this.pullSnapshotRunner(
                runner,
                snapshot.ref,
                internalRegistry,
                undefined,
                undefined,
                snapshot.sandboxClass,
                snapshot.disk,
              )
            } else if (snapshotRunner.state === SnapshotRunnerState.PULLING_SNAPSHOT) {
              await this.handleSnapshotRunnerStatePullingSnapshot(snapshotRunner, runner)
            }
          } catch (err) {
            this.logger.error(`Error propagating snapshot to runner ${runner.id}: ${fromAxiosError(err)}`)
            // The entry may have just been created above (snapshotRunner was null), so re-fetch it to update.
            if (!snapshotRunner) {
              snapshotRunner = await this.runnerService.getSnapshotRunner(runner.id, snapshot.ref)
            }
            if (snapshotRunner) {
              snapshotRunner.state = SnapshotRunnerState.ERROR
              snapshotRunner.errorReason = err.message
              await this.snapshotRunnerRepository.update(snapshotRunner.id, snapshotRunner)
            }
          }
        }),
      )

      results.forEach((result) => {
        if (result.status === 'rejected') {
          this.logger.error(result.reason)
        }
      })
    } catch (err) {
      this.logger.error(err)
    }
  }

  async scaleDownSnapshotFromRunners(
    snapshot: Snapshot,
    sharedRegionIds: string[],
    propagationFactor: number = BASE_PROPAGATION_FACTOR,
    minimumRunners = 0,
  ): Promise<number> {
    try {
      if (sharedRegionIds.length === 0) {
        return 0
      }

      // Use the same eligible-runner set as propagation so the scale-down ceiling is computed over the exact
      // same denominator. If these diverge, scale-down can target fewer copies than propagation maintains,
      // causing a remove -> re-propagate flapping loop.
      const sharedRunners = await this.runnerRepository.find({
        where: this.eligibleRunnerWhere(snapshot, sharedRegionIds),
      })

      const sharedRunnerIds = sharedRunners.map((runner) => runner.id)

      if (sharedRunnerIds.length === 0) {
        return 0
      }

      // Get all snapshot runners in READY state for shared runners (excluding those created in the last hour)
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000)
      const sharedSnapshotRunners = await this.snapshotRunnerRepository.find({
        where: {
          snapshotRef: snapshot.ref,
          state: SnapshotRunnerState.READY,
          runnerId: In(sharedRunnerIds),
          createdAt: LessThan(oneHourAgo),
        },
      })

      // Must match propagateSnapshotToRunners: respect both the factor and the minimum floor
      const maxSharedSnapshotRunners = this.getTargetSharedRunnerCount(
        sharedRunners.length,
        propagationFactor,
        minimumRunners,
      )

      // Only scale down if the propagated amount exceeds the limit by more than 15%
      const scaleDownThreshold = Math.ceil(maxSharedSnapshotRunners * 1.15)
      const excessCount = sharedSnapshotRunners.length - maxSharedSnapshotRunners

      if (sharedSnapshotRunners.length > scaleDownThreshold) {
        // Sort by createdAt ascending (oldest first) to remove oldest ones
        const sortedSnapshotRunners = sharedSnapshotRunners.sort(
          (a, b) => a.createdAt.getTime() - b.createdAt.getTime(),
        )

        // Take the excess ones to remove
        const snapshotRunnersToRemove = sortedSnapshotRunners.slice(0, excessCount)

        await Promise.allSettled(
          snapshotRunnersToRemove.map(async (snapshotRunner) => {
            await this.snapshotRunnerRepository.update(snapshotRunner.id, {
              state: SnapshotRunnerState.REMOVING,
            })
          }),
        )

        this.logger.log(
          `Marked ${snapshotRunnersToRemove.length} snapshot runners for removal for snapshot ${snapshot.ref}`,
        )

        return snapshotRunnersToRemove.length
      }

      return 0
    } catch (err) {
      this.logger.error(`Error scaling down snapshot ${snapshot.ref}: ${fromAxiosError(err)}`)
      return 0
    }
  }

  async pullSnapshotRunner(
    runner: Runner,
    snapshotRef: string,
    registry?: DockerRegistry,
    destinationRegistry?: DockerRegistry,
    destinationRef?: string,
    sandboxClass?: SandboxClass,
    diskGiB?: number,
  ) {
    const runnerAdapter = await this.runnerAdapterFactory.create(runner)
    // Runner returns immediately; polling for completion is handled by syncRunnerSnapshotStates cron
    await runnerAdapter.pullSnapshot(
      snapshotRef,
      registry,
      destinationRegistry,
      destinationRef,
      undefined,
      sandboxClass,
      diskGiB,
    )
  }

  async handleSnapshotRunnerStatePullingSnapshot(snapshotRunner: SnapshotRunner, runner: Runner) {
    const runnerAdapter = await this.runnerAdapterFactory.create(runner)
    try {
      await runnerAdapter.getSnapshotInfo(snapshotRunner.snapshotRef)
      snapshotRunner.state = SnapshotRunnerState.READY
      await this.snapshotRunnerRepository.save(snapshotRunner)
      return
    } catch (err) {
      if (err instanceof SnapshotStateError) {
        snapshotRunner.state = SnapshotRunnerState.ERROR
        snapshotRunner.errorReason = err.errorReason
        await this.snapshotRunnerRepository.save(snapshotRunner)
        return
      }
    }

    const timeoutMinutes = 60
    const timeoutMs = timeoutMinutes * 60 * 1000
    if (Date.now() - snapshotRunner.updatedAt.getTime() > timeoutMs) {
      snapshotRunner.state = SnapshotRunnerState.ERROR
      snapshotRunner.errorReason = 'Timeout while pulling snapshot to runner'
      await this.snapshotRunnerRepository.save(snapshotRunner)
      return
    }

    const retryTimeoutMinutes = 10
    const retryTimeoutMs = retryTimeoutMinutes * 60 * 1000
    if (Date.now() - snapshotRunner.createdAt.getTime() > retryTimeoutMs) {
      // Use base region for registry lookup (dedicated regions may not have registry configs)
      const regionForRegistry = getFallbackRegion(runner.region) ?? runner.region
      const snapshot = await this.snapshotRepository.findOne({ where: { ref: snapshotRunner.snapshotRef } })
      let sandboxClass = snapshot?.sandboxClass
      if (!sandboxClass) {
        // Backup-snapshot refs do not have a Snapshot row; fall back to the owning sandbox's class.
        const sandbox = await this.sandboxRepository.findOne({
          where: { backupSnapshot: snapshotRunner.snapshotRef },
        })
        sandboxClass = sandbox?.sandboxClass
      }
      let internalRegistry: DockerRegistry | undefined
      if (!sandboxClass || isRegistryBasedSandboxClass(sandboxClass)) {
        const found = await this.dockerRegistryService.findInternalRegistryBySnapshotRef(
          snapshotRunner.snapshotRef,
          regionForRegistry,
        )
        if (!found) {
          throw new Error(
            `No internal registry found for snapshot ${snapshotRunner.snapshotRef} in region ${regionForRegistry}`,
          )
        }
        internalRegistry = found
      }
      await this.pullSnapshotRunner(
        runner,
        snapshotRunner.snapshotRef,
        internalRegistry,
        undefined,
        undefined,
        sandboxClass,
        snapshot?.disk,
      )
      return
    }
  }

  async handleSnapshotRunnerStateBuildingSnapshot(snapshotRunner: SnapshotRunner, runner: Runner) {
    const runnerAdapter = await this.runnerAdapterFactory.create(runner)
    try {
      await runnerAdapter.getSnapshotInfo(snapshotRunner.snapshotRef)
      snapshotRunner.state = SnapshotRunnerState.READY
      await this.snapshotRunnerRepository.save(snapshotRunner)
      return
    } catch (err) {
      if (err instanceof SnapshotStateError) {
        snapshotRunner.state = SnapshotRunnerState.ERROR
        snapshotRunner.errorReason = err.errorReason
        await this.snapshotRunnerRepository.save(snapshotRunner)
        return
      }
    }

    const timeoutMinutes = 120
    const timeoutMs = timeoutMinutes * 60 * 1000
    if (Date.now() - snapshotRunner.updatedAt.getTime() > timeoutMs) {
      snapshotRunner.state = SnapshotRunnerState.ERROR
      snapshotRunner.errorReason = 'Timeout while building snapshot on runner'
      await this.snapshotRunnerRepository.save(snapshotRunner)
    }
  }

  // Pre-pulls backup snapshots to other runners to speed migration during draining.
  // No-op when DRAINING_MODE != migrate (nothing to migrate to).
  @Cron(CronExpression.EVERY_10_SECONDS, { name: 'migrate-draining-runner-snapshots', waitForCompletion: true })
  @TrackJobExecution()
  @LogExecution('migrate-draining-runner-snapshots')
  @WithInstrumentation()
  private async handleMigrateDrainingRunnerSnapshots() {
    if (this.configService.get('draining.mode') !== 'migrate') {
      return
    }

    const lockKey = 'migrate-draining-runner-snapshots'
    const hasLock = await this.redisLockProvider.lock(lockKey, 60)
    if (!hasLock) {
      return
    }

    try {
      const drainingRunners = await this.runnerRepository.find({
        where: {
          draining: true,
          state: RunnerState.READY,
        },
      })

      this.logger.debug(`Checking ${drainingRunners.length} draining runners for snapshot migration`)

      await Promise.allSettled(
        drainingRunners.map(async (runner) => {
          try {
            const sandboxes = await this.sandboxRepository.find({
              where: {
                runnerId: runner.id,
                state: SandboxState.STOPPED,
                desiredState: SandboxDesiredState.STOPPED,
                backupState: BackupState.COMPLETED,
                backupSnapshot: Not(IsNull()),
              },
              take: 100,
            })

            this.logger.debug(
              `Found ${sandboxes.length} eligible sandboxes on draining runner ${runner.id} for snapshot migration`,
            )

            await Promise.allSettled(
              sandboxes.map(async (sandbox) => {
                const sandboxLockKey = `draining-runner-snapshot-migration:${sandbox.id}`
                const hasSandboxLock = await this.redisLockProvider.lock(sandboxLockKey, 3600)
                if (!hasSandboxLock) {
                  return
                }

                try {
                  // Get an available runner in the same region with the same class
                  const targetRunner = await this.runnerService.getRandomAvailableRunner({
                    regions: [sandbox.region],
                    sandboxClass: sandbox.sandboxClass,
                    excludedRunnerIds: [runner.id],
                    gpu: sandbox.gpu,
                    gpuType: sandbox.gpuType ?? null,
                  })

                  // Check if snapshot runner entry already exists
                  const existingEntry = await this.runnerService.getSnapshotRunner(
                    targetRunner.id,
                    sandbox.backupSnapshot,
                  )
                  if (existingEntry) {
                    if (existingEntry.state === SnapshotRunnerState.ERROR) {
                      // Clean up the failed entry so we can retry
                      this.logger.warn(
                        `Removing ERROR snapshot runner entry ${existingEntry.id} for runner ${targetRunner.id} and snapshot ${sandbox.backupSnapshot} to allow retry`,
                      )
                      await this.snapshotRunnerRepository.delete(existingEntry.id)
                    } else {
                      this.logger.debug(
                        `Snapshot runner entry already exists for runner ${targetRunner.id} and snapshot ${sandbox.backupSnapshot} (state: ${existingEntry.state})`,
                      )
                      // Do not unlock to avoid duplicates
                      return
                    }
                  }

                  // Find the backup registry to use as source for the pull.
                  // Non-registry-based classes (e.g. Windows) reference an S3 key rather than a
                  // Docker registry, so skip the registry lookup for them.
                  const registry = sandbox.backupRegistryId
                    ? await this.dockerRegistryService.findOne(sandbox.backupRegistryId)
                    : isRegistryBasedSandboxClass(sandbox.sandboxClass)
                      ? await this.dockerRegistryService.findInternalRegistryBySnapshotRef(
                          sandbox.backupSnapshot,
                          targetRunner.region,
                        )
                      : undefined

                  if (isRegistryBasedSandboxClass(sandbox.sandboxClass) && !registry) {
                    this.logger.warn(
                      `No registry found for backup snapshot ${sandbox.backupSnapshot} of sandbox ${sandbox.id}`,
                    )
                    await this.redisLockProvider.unlock(sandboxLockKey)
                    return
                  }

                  // Create snapshot runner entry on the target runner
                  await this.runnerService.createSnapshotRunnerEntry(
                    targetRunner.id,
                    sandbox.backupSnapshot,
                    SnapshotRunnerState.PULLING_SNAPSHOT,
                  )
                  await this.pullSnapshotRunner(
                    targetRunner,
                    sandbox.backupSnapshot,
                    registry,
                    undefined,
                    undefined,
                    sandbox.sandboxClass,
                    sandbox.disk,
                  )

                  this.logger.log(
                    `Created snapshot runner entry for sandbox ${sandbox.id} backup ${sandbox.backupSnapshot} on runner ${targetRunner.id} (migrating from draining runner ${runner.id})`,
                  )
                  await this.redisLockProvider.unlock(sandboxLockKey)
                } catch (e) {
                  if (e instanceof BadRequestError && e.message.startsWith('No available runners')) {
                    this.logger.warn(
                      `No available runners found in region ${sandbox.region} for sandbox ${sandbox.id} snapshot migration`,
                    )
                  } else {
                    this.logger.error(`Error migrating snapshot for sandbox ${sandbox.id}`, e)
                  }
                  await this.redisLockProvider.unlock(sandboxLockKey)
                }
              }),
            )
          } catch (e) {
            this.logger.error(`Error processing draining runner ${runner.id} for snapshot migration`, e)
          }
        }),
      )
    } finally {
      await this.redisLockProvider.unlock(lockKey)
    }
  }

  @Cron(CronExpression.EVERY_10_SECONDS, { name: 'check-snapshot-cleanup' })
  @TrackJobExecution()
  @LogExecution('check-snapshot-cleanup')
  @WithInstrumentation()
  async checkSnapshotCleanup() {
    const lockKey = 'check-snapshot-cleanup-lock'
    if (!(await this.redisLockProvider.lock(lockKey, 30))) {
      return
    }

    try {
      const snapshots = await this.snapshotRepository.find({
        where: {
          state: SnapshotState.REMOVING,
        },
      })

      const results = await Promise.allSettled(
        snapshots.map(async (snapshot) => {
          const countActiveSnapshots = await this.snapshotRepository.count({
            where: {
              state: SnapshotState.ACTIVE,
              ref: snapshot.ref,
            },
          })

          // Only remove snapshot runners if no other snapshots depend on them
          if (countActiveSnapshots === 0) {
            await this.snapshotRunnerRepository.update(
              {
                snapshotRef: snapshot.ref,
              },
              {
                state: SnapshotRunnerState.REMOVING,
              },
            )
          }

          await this.snapshotRepository.remove(snapshot)
        }),
      )

      results.forEach((result) => {
        if (result.status === 'rejected') {
          this.logger.error(`Error cleaning up snapshot: ${fromAxiosError(result.reason)}`)
        }
      })
    } finally {
      await this.redisLockProvider.unlock(lockKey)
    }
  }

  @Cron(CronExpression.EVERY_10_SECONDS, { name: 'check-snapshot-state' })
  @TrackJobExecution()
  @LogExecution('check-snapshot-state')
  @WithInstrumentation()
  async checkSnapshotState() {
    //  the first time the snapshot is created it needs to be pushed to the internal registry
    //  before propagating to the runners
    //  this cron job will process the snapshot states until the snapshot is active (or error)

    //  get all snapshots
    const snapshots = await this.snapshotRepository.find({
      where: {
        state: Not(In([SnapshotState.ACTIVE, SnapshotState.ERROR, SnapshotState.BUILD_FAILED, SnapshotState.INACTIVE])),
      },
    })

    const results = await Promise.allSettled(
      snapshots.map(async (snapshot) => {
        await this.syncSnapshotState(snapshot.id)
      }),
    )

    results.forEach((result, index) => {
      if (result.status === 'rejected') {
        this.logger.error(
          `Error syncing snapshot state for snapshot ${snapshots[index].id}: ${fromAxiosError(result.reason)}`,
        )
      }
    })
  }

  async syncSnapshotState(snapshotId: string): Promise<void> {
    const lockKey = `sync-snapshot-state-${snapshotId}`
    if (!(await this.redisLockProvider.lock(lockKey, 720))) {
      return
    }

    const snapshot = await this.snapshotRepository.findOne({
      where: { id: snapshotId },
    })

    if (
      !snapshot ||
      [SnapshotState.ACTIVE, SnapshotState.ERROR, SnapshotState.BUILD_FAILED, SnapshotState.INACTIVE].includes(
        snapshot.state,
      )
    ) {
      await this.redisLockProvider.unlock(lockKey)
      return
    }

    let syncState = DONT_SYNC_AGAIN

    try {
      switch (snapshot.state) {
        case SnapshotState.PENDING:
          syncState = await this.handleSnapshotStatePending(snapshot)
          break
        case SnapshotState.PULLING:
        case SnapshotState.BUILDING:
          syncState = await this.handleCheckInitialRunnerSnapshot(snapshot)
          break
        case SnapshotState.REMOVING:
          syncState = await this.handleSnapshotStateRemoving(snapshot)
          break
      }
    } catch (error) {
      if (error.code === 'ECONNRESET') {
        syncState = SYNC_AGAIN
      } else {
        const message = error.message || String(error)
        await this.updateSnapshotState(snapshot, SnapshotState.ERROR, message)
      }
    }

    await this.redisLockProvider.unlock(lockKey)
    if (syncState === SYNC_AGAIN) {
      void this.syncSnapshotState(snapshotId).catch((err) =>
        this.logger.error(`Error syncing snapshot state for snapshot ${snapshotId}: ${fromAxiosError(err)}`),
      )
    }
  }

  async handleSnapshotRunnerStateRemoving(snapshotRunner: SnapshotRunner, runner: Runner) {
    if (!runner) {
      //  generally this should not happen
      //  in case the runner has been deleted from the database, delete the snapshot runner record
      const errorMessage = `Runner not found while trying to remove snapshot ${snapshotRunner.snapshotRef} from runner ${snapshotRunner.runnerId}`
      this.logger.warn(errorMessage)

      this.snapshotRunnerRepository.delete(snapshotRunner.id).catch((err) => {
        this.logger.error(fromAxiosError(err))
      })
      return
    }
    if (!snapshotRunner.snapshotRef) {
      //  this should never happen
      //  remove the snapshot runner record (it will be recreated again by the snapshot propagation job)
      this.logger.warn(`Internal snapshot name not found for snapshot runner ${snapshotRunner.id}`)
      this.snapshotRunnerRepository.delete(snapshotRunner.id).catch((err) => {
        this.logger.error(fromAxiosError(err))
      })
      return
    }

    const runnerAdapter = await this.runnerAdapterFactory.create(runner)
    const exists = await runnerAdapter.snapshotExists(snapshotRunner.snapshotRef)
    if (!exists) {
      await this.snapshotRunnerRepository.delete(snapshotRunner.id)
    } else {
      //  just in case the snapshot is still there
      runnerAdapter.removeSnapshot(snapshotRunner.snapshotRef).catch((err) => {
        //  this should not happen, and is not critical
        //  if the runner can not remove the snapshot, just delete the snapshot runner record
        this.snapshotRunnerRepository.delete(snapshotRunner.id).catch((err) => {
          this.logger.error(fromAxiosError(err))
        })
        //  and log the error for tracking
        const errorMessage = `Failed to do just in case remove snapshot ${snapshotRunner.snapshotRef} from runner ${runner.id}: ${fromAxiosError(err)}`
        this.logger.warn(errorMessage)
      })
    }
  }

  async handleSnapshotStateRemoving(snapshot: Snapshot): Promise<SyncState> {
    const snapshotRunnerItems = await this.snapshotRunnerRepository.find({
      where: {
        snapshotRef: snapshot.ref,
      },
    })

    if (snapshotRunnerItems.length === 0) {
      await this.snapshotRepository.remove(snapshot)
    }

    return DONT_SYNC_AGAIN
  }

  async handleCheckInitialRunnerSnapshot(snapshot: Snapshot): Promise<SyncState> {
    // Check for timeout - allow up to 60 minutes
    const timeoutMinutes = 60
    const timeoutMs = timeoutMinutes * 60 * 1000
    if (Date.now() - snapshot.updatedAt.getTime() > timeoutMs) {
      await this.updateSnapshotState(snapshot, SnapshotState.ERROR, 'Timeout processing snapshot on initial runner')
      return DONT_SYNC_AGAIN
    }

    // Check if the snapshot ref is already set and it is already on the runner
    const snapshotRunner = await this.snapshotRunnerRepository.findOne({
      where: {
        snapshotRef: snapshot.ref,
        runnerId: snapshot.initialRunnerId,
      },
    })

    const runner = await this.runnerService.findOneOrFail(snapshot.initialRunnerId)

    if (snapshot.ref && snapshotRunner) {
      const readyForActive = isRegistryBasedSandboxClass(snapshot.sandboxClass) ? snapshot.size != null : true
      if (snapshotRunner.state === SnapshotRunnerState.READY && readyForActive) {
        await this.waitForInitialPropagation(snapshot)
        await this.updateSnapshotState(snapshot, SnapshotState.ACTIVE)
        return DONT_SYNC_AGAIN
      } else if (snapshotRunner.state === SnapshotRunnerState.ERROR) {
        await this.snapshotRunnerRepository.delete(snapshotRunner.id)
      }
    }

    if (!isRegistryBasedSandboxClass(snapshot.sandboxClass)) {
      return DONT_SYNC_AGAIN
    }

    const runnerAdapter = await this.runnerAdapterFactory.create(runner)

    const initialImageRefOnRunner = snapshot.buildInfo ? snapshot.buildInfo.snapshotRef : snapshot.ref

    let snapshotInfoResponse: SnapshotInfoResponse
    try {
      snapshotInfoResponse = await runnerAdapter.getSnapshotInfo(initialImageRefOnRunner)
    } catch (error) {
      if (error instanceof SnapshotStateError) {
        throw error
      } else {
        return DONT_SYNC_AGAIN
      }
    }

    // Use base region for registry lookup (dedicated regions may not have registry configs)
    const regionForRegistry = getFallbackRegion(runner.region) ?? runner.region
    const internalRegistry = await this.dockerRegistryService.getAvailableInternalRegistry(regionForRegistry)
    if (!internalRegistry) {
      throw new Error('No internal registry found for snapshot')
    }

    const digestSyncState = await this.processSnapshotDigest(
      snapshot,
      internalRegistry,
      snapshotInfoResponse.hash,
      snapshotInfoResponse.sizeGB,
      snapshotInfoResponse.entrypoint,
    )

    if (digestSyncState === DONT_SYNC_AGAIN) {
      return DONT_SYNC_AGAIN
    }

    let inspectedSnapshotDigest: SnapshotDigestResponse | undefined
    try {
      inspectedSnapshotDigest = await runnerAdapter.inspectSnapshotInRegistry(snapshot.ref, internalRegistry)
    } catch (error) {
      this.logger.error(`Failed to inspect snapshot ${snapshot.ref} in registry: ${error}`)
      return DONT_SYNC_AGAIN
    }

    if (snapshot.size == null && typeof inspectedSnapshotDigest?.sizeGB === 'number') {
      await this.processSnapshotDigest(
        snapshot,
        internalRegistry,
        snapshotInfoResponse.hash,
        inspectedSnapshotDigest.sizeGB,
        snapshotInfoResponse.entrypoint,
      )
    }

    // Build snapshots use a temporary runner-local reference before their
    // canonical registry reference is known. Pull snapshots do not: once the
    // digest is resolved, initialImageRefOnRunner is snapshot.ref itself.
    // Removing that canonical reference races the asynchronous v2 runner job
    // against the READY snapshot_runner row below; when the remove completes,
    // it deletes the row and leaves an ACTIVE snapshot with no schedulable
    // runner. Only staging references may be cleaned during activation.
    if (snapshot.buildInfo && initialImageRefOnRunner !== snapshot.ref) {
      try {
        await runnerAdapter.removeSnapshot(initialImageRefOnRunner)
      } catch (error) {
        this.logger.error(
          `Failed to remove snapshot staging ref ${initialImageRefOnRunner}: ${fromAxiosError(error)}`,
        )
      }
    }

    // For pull snapshots, best effort cleanup the original image now that we've computed the ref from it
    // Only cleanup if there's no other snapshot in processing state using the same image
    if (!snapshot.buildInfo && snapshot.imageName && snapshot.imageName !== snapshot.ref) {
      try {
        const anotherSnapshot = await this.snapshotRepository.findOne({
          where: {
            imageName: snapshot.imageName,
            id: Not(snapshot.id),
            state: Not(In([SnapshotState.ACTIVE, SnapshotState.INACTIVE])),
          },
        })
        if (!anotherSnapshot) {
          await runnerAdapter.removeSnapshot(snapshot.imageName)
        }
      } catch (err) {
        this.logger.error(`Failed to cleanup original image ${snapshot.imageName}: ${fromAxiosError(err)}`)
      }
    }

    if (snapshotRunner) {
      snapshotRunner.state = SnapshotRunnerState.READY
      await this.snapshotRunnerRepository.save(snapshotRunner)
    } else {
      await this.runnerService.createSnapshotRunnerEntry(runner.id, snapshot.ref, SnapshotRunnerState.READY)
    }

    if (snapshot.size == null) {
      this.logger.warn(`Snapshot ${snapshot.id} has no resolved size yet; deferring activation`)
      return DONT_SYNC_AGAIN
    }

    await this.waitForInitialPropagation(snapshot)

    await this.updateSnapshotState(snapshot, SnapshotState.ACTIVE)

    // Best effort removal of old snapshot from transient registry
    // Use base region for registry lookup (dedicated regions may not have registry configs)
    const regionForTransientRegistry = getFallbackRegion(runner.region) ?? runner.region
    const transientRegistry = await this.dockerRegistryService.findTransientRegistryBySnapshotImageName(
      snapshot.imageName,
      regionForTransientRegistry,
    )
    if (transientRegistry) {
      try {
        await this.dockerRegistryService.removeImage(snapshot.imageName, transientRegistry.id)
      } catch (error) {
        if (error.statusCode === 404) {
          //  image not found, just return
          return DONT_SYNC_AGAIN
        }
        this.logger.error('Failed to remove transient image:', fromAxiosError(error))
      }
    }

    return DONT_SYNC_AGAIN
  }

  /**
   * Resolve the org's CPU quota for its default region, mirroring the quota join used by the
   * sync-runner-snapshots[-rl] crons (region_quota on org.defaultRegionId). The propagation factor is
   * derived from this so the initial run targets the same number of runners the crons maintain.
   */
  private async getOrganizationDefaultRegionCpuQuota(snapshot: Snapshot): Promise<number> {
    const organization = await this.organizationService.findOne(snapshot.organizationId)
    if (!organization?.defaultRegionId) {
      return 0
    }
    const regionQuota = await this.organizationService.getRegionQuota(
      snapshot.organizationId,
      organization.defaultRegionId,
      snapshot.sandboxClass,
    )
    return regionQuota?.totalCpuQuota ?? 0
  }

  /**
   * Kick off an initial propagation run for a freshly-built snapshot across all of its regions so copies
   * start landing on shared runners immediately, instead of waiting for the next sync-runner-snapshots cron
   * cycle. Then block (best effort) until a couple of runners are READY so the first sandboxes created from the
   * snapshot start fast.
   *
   * The propagation tiers mirror the steady-state cron so the initial target matches it and they don't fight.
   * If propagation doesn't reach the target in time, the caller still activates the snapshot with partial
   * propagation — the crons finish the job afterwards.
   */
  private async waitForInitialPropagation(snapshot: Snapshot): Promise<void> {
    const regions = await this.snapshotService.getSnapshotRegions(snapshot.id)

    const sharedRegionIds = regions.filter((r) => r.organizationId === null).map((r) => r.id)
    const organizationRegionIds = regions.filter((r) => r.organizationId === snapshot.organizationId).map((r) => r.id)

    if (sharedRegionIds.length === 0 && organizationRegionIds.length === 0) {
      return
    }

    const cpuQuota = await this.getOrganizationDefaultRegionCpuQuota(snapshot)
    const { factor, minimum } = getSnapshotPropagationFactor(cpuQuota, snapshot)

    // Determine how many runners we expect to end up holding the snapshot (org runners always get a copy;
    // shared runners are limited by the propagation factor), and collect their ids so we can poll readiness.
    const eligibleRunners = await this.runnerRepository.find({
      where: this.eligibleRunnerWhere(snapshot, [...sharedRegionIds, ...organizationRegionIds]),
    })
    const targetRunnerIds = new Set(eligibleRunners.map((runner) => runner.id))

    const sharedRunnerCount = eligibleRunners.filter((runner) => sharedRegionIds.includes(runner.region)).length
    const organizationRunnerCount = eligibleRunners.filter((runner) =>
      organizationRegionIds.includes(runner.region),
    ).length

    const targetRunnerCount = Math.min(
      targetRunnerIds.size,
      organizationRunnerCount + this.getTargetSharedRunnerCount(sharedRunnerCount, factor, minimum),
    )

    // Fire-and-forget: this creates the snapshot_runner rows and dispatches the pulls; the readiness poll
    // below (and the crons) take over from there. propagateSnapshotToRunners never throws.
    this.propagateSnapshotToRunners(snapshot, sharedRegionIds, organizationRegionIds, factor, minimum)

    if (targetRunnerIds.size === 0) {
      return
    }

    // Activate once at least 2 runners (or a configurable fraction of the desired propagation target, whichever is
    // greater) are READY so the first sandboxes start fast while the crons finish topping up the rest. Never require
    // more than the target itself.
    const readyFactor = this.configService.getOrThrow('initialSnapshotPropagationReadyFactor')
    const targetReadyCount = Math.min(targetRunnerCount, Math.max(2, Math.ceil(targetRunnerCount * readyFactor)))
    if (targetReadyCount === 0) {
      return
    }

    const runnerIds = [...targetRunnerIds]
    const startedAt = Date.now()
    const waitTimeMs = 10 * 60 * 1000 // 10 minutes

    while (Date.now() - startedAt < waitTimeMs) {
      const currentReadyCount = await this.snapshotRunnerRepository.count({
        where: {
          snapshotRef: snapshot.ref,
          state: SnapshotRunnerState.READY,
          runnerId: In(runnerIds),
        },
      })

      if (currentReadyCount >= targetReadyCount) {
        return
      }

      await sleep(10_000)
    }

    this.logger.warn(`Snapshot ${snapshot.id} initial propagation timed out, activating with partial propagation`)
  }

  async processPullOnInitialRunner(snapshot: Snapshot, runner: Runner) {
    // Check for timeout - allow up to 60 minutes
    const timeoutMinutes = 60
    const timeoutMs = timeoutMinutes * 60 * 1000
    if (Date.now() - snapshot.updatedAt.getTime() > timeoutMs) {
      await this.updateSnapshotState(
        snapshot,
        SnapshotState.ERROR,
        'Timeout processing snapshot pull on initial runner',
      )
      return DONT_SYNC_AGAIN
    }

    try {
      if (isRegistryBasedSandboxClass(snapshot.sandboxClass)) {
        // Use base region for registry lookups (dedicated regions may not have registry configs)
        const regionForRegistry = getFallbackRegion(runner.region) ?? runner.region

        // Snapshots created from a sandbox have no external `imageName` - their canonical
        // reference is `ref`, which already lives in the internal registry. Pull directly
        // from `ref` (mirroring propagateSnapshotToRunners) instead of trying to pull an
        // empty `imageName` from an external source registry, which caused flaky activation.
        const fromSandbox = !snapshot.imageName && !snapshot.buildInfo
        if (fromSandbox) {
          if (!snapshot.ref) {
            throw new Error(`Snapshot ${snapshot.id} has no imageName or ref to pull from`)
          }
          const internalRegistry =
            (await this.dockerRegistryService.findInternalRegistryBySnapshotRef(snapshot.ref, regionForRegistry)) ??
            undefined
          await this.pullSnapshotRunner(
            runner,
            snapshot.ref,
            internalRegistry,
            undefined,
            undefined,
            snapshot.sandboxClass,
            snapshot.disk,
          )
        } else {
          let sourceRegistry =
            (await this.dockerRegistryService.findSourceRegistryBySnapshotImageName(
              snapshot.imageName,
              regionForRegistry,
              snapshot.organizationId,
            )) ?? undefined
          if (!sourceRegistry) {
            sourceRegistry =
              (await this.dockerRegistryService.getDefaultSourceRegistryForImage(snapshot.imageName)) ?? undefined
          }
          const destinationRegistry =
            (await this.dockerRegistryService.getAvailableInternalRegistry(regionForRegistry)) ?? undefined

          await this.pullSnapshotRunner(
            runner,
            snapshot.imageName,
            sourceRegistry,
            destinationRegistry,
            snapshot.ref ? snapshot.ref : undefined,
            snapshot.sandboxClass,
            snapshot.disk,
          )
        }
      } else {
        await this.pullSnapshotRunner(
          runner,
          snapshot.ref,
          undefined,
          undefined,
          undefined,
          snapshot.sandboxClass,
          snapshot.disk,
        )
      }
    } catch (err) {
      // Validation errors are still returned synchronously
      await this.updateSnapshotState(snapshot, SnapshotState.ERROR, err.message)
      throw err
    }
  }

  async processBuildOnRunner(snapshot: Snapshot, runner: Runner) {
    try {
      // Use base region for registry lookup (dedicated regions may not have registry configs)
      const regionForRegistry = getFallbackRegion(runner.region) ?? runner.region
      const registry = await this.dockerRegistryService.getAvailableInternalRegistry(regionForRegistry)

      const sourceRegistries = await this.dockerRegistryService.getSourceRegistriesForDockerfile(
        snapshot.buildInfo.dockerfileContent,
        snapshot.organizationId,
      )

      const runnerAdapter = await this.runnerAdapterFactory.create(runner)

      registry.url = registry.url.replace(/^(https?:\/\/)/, '')
      // Runner returns immediately; polling for completion is handled by handleCheckInitialRunnerSnapshot
      await runnerAdapter.buildSnapshot(
        snapshot.buildInfo,
        snapshot.organizationId,
        sourceRegistries.length > 0 ? sourceRegistries : undefined,
        registry ?? undefined,
        true,
      )
    } catch (err) {
      this.logger.error(`Error building snapshot ${snapshot.name}: ${fromAxiosError(err)}`)
      await this.updateSnapshotState(snapshot, SnapshotState.BUILD_FAILED, fromAxiosError(err).message)
    }
  }

  async handleSnapshotStatePending(snapshot: Snapshot): Promise<SyncState> {
    let initialRunner: Runner | undefined = undefined

    if (!snapshot.initialRunnerId) {
      // Per-org concurrency gate ("queue") to cap how many snapshots an org can be processing concurrently.
      // Snapshots over the limit stay in PENDING and are retried on the next cron tick, so creations are still
      // admitted but their eager propagation work (other runners pulling the ref from the registry) is spread out
      // instead of bursting (e.g. an org churning hundreds of snapshots). Both build and pull snapshots propagate
      // at activation and sit in BUILDING/PULLING while waitForInitialPropagation runs, so both count toward the
      // cap. A value of <= 0 means unlimited. Admission is serialized per org with a short lock so concurrent cron
      // ticks can't overshoot.
      const organization = await this.organizationService.findOne(snapshot.organizationId)
      const maxConcurrentProcessing =
        organization?.maxConcurrentSnapshotProcessing ??
        this.configService.getOrThrow('defaultOrganizationQuota.maxConcurrentSnapshotProcessing')

      let admissionLockKey: string | undefined
      if (maxConcurrentProcessing > 0) {
        admissionLockKey = `snapshot-processing-admission-${snapshot.organizationId}`
        if (!(await this.redisLockProvider.lock(admissionLockKey, 30))) {
          // Another admission for this org is in progress; retry on the next cron tick.
          return DONT_SYNC_AGAIN
        }

        // Snapshots already holding a processing slot: actively building/pulling, plus ones just admitted (they
        // have claimed an initial runner) that haven't transitioned out of PENDING yet.
        const inProgressCount = await this.snapshotRepository.count({
          where: [
            {
              organizationId: snapshot.organizationId,
              id: Not(snapshot.id),
              state: In([SnapshotState.BUILDING, SnapshotState.PULLING]),
            },
            {
              organizationId: snapshot.organizationId,
              id: Not(snapshot.id),
              state: SnapshotState.PENDING,
              initialRunnerId: Not(IsNull()),
            },
          ],
        })

        if (inProgressCount >= maxConcurrentProcessing) {
          // At capacity — leave this snapshot queued in PENDING; it will be retried on the next cron tick.
          await this.redisLockProvider.unlock(admissionLockKey)
          return DONT_SYNC_AGAIN
        }
      }

      // TODO: get only runners where the base snapshot is available (extract from buildInfo)
      const excludedRunnerIds = snapshot.buildInfo
        ? await this.runnerService.getRunnersWithMultipleSnapshotsBuilding()
        : await this.runnerService.getRunnersWithMultipleSnapshotsPulling()

      try {
        const regions = await this.snapshotService.getSnapshotRegions(snapshot.id)
        if (!regions.length) {
          throw new Error('No regions found for snapshot')
        }

        let dedicatedRegions = DEDICATED_REGIONS_PER_ORGANIZATION[snapshot.organizationId]

        // If the organization is in LARGE_SANDBOX_ORGS and the resources are not larger than the default, remove the LARGE_SANDBOX_SHARED_REGION
        if (
          LARGE_SANDBOX_ORGS.has(snapshot.organizationId) &&
          !areResourcesLargerThanDefault(this.configService, {
            cpu: snapshot.cpu,
            memory: snapshot.mem,
            disk: snapshot.disk,
            gpu: snapshot.gpu,
          })
        ) {
          dedicatedRegions = dedicatedRegions.filter((region) => region !== LARGE_SANDBOX_SHARED_REGION)
        }
        // =================
        this.logger.warn('dedicatedRegions', dedicatedRegions, 'organizationId', snapshot.organizationId)
        // =================

        // deduce regions for selecting the initial runner
        let regionIdsForInitialRunner: string[] = []

        const customSnapshotManagerRegions = regions.filter(
          (region) => region.regionType === RegionType.CUSTOM && region.snapshotManagerUrl,
        )

        if (customSnapshotManagerRegions.length) {
          // must use runner with access to the custom snapshot manager
          regionIdsForInitialRunner = customSnapshotManagerRegions.map((region) => region.id)
        } else if (dedicatedRegions?.length) {
          regionIdsForInitialRunner = dedicatedRegions
        } else {
          regionIdsForInitialRunner = regions.map((region) => region.id)
        }

        const availabilityThreshold =
          this.configService.getOrThrow('runnerScore.thresholds.availability') +
          this.configService.getOrThrow('runnerScore.thresholds.initialRunnerScoreAddon')

        initialRunner = await this.runnerService.getRandomAvailableRunner({
          regions: regionIdsForInitialRunner,
          // Temporary: Android snapshots can go to container runners
          sandboxClass: getRunnerSandboxClass(snapshot.sandboxClass),
          excludedRunnerIds: excludedRunnerIds,
          availabilityScoreThreshold: availabilityThreshold,
          gpu: snapshot.gpu,
          gpuType: snapshot.gpuType ?? null,
        })
        // =================
        this.logger.warn('runnerId', initialRunner?.id)
        // =================
      } catch (error) {
        this.logger.warn(`Failed to get initial runner: ${fromAxiosError(error)}`)
      }

      if (!initialRunner) {
        // No runners available, retry later
        if (admissionLockKey) {
          await this.redisLockProvider.unlock(admissionLockKey)
        }
        return DONT_SYNC_AGAIN
      }

      const updateData: Partial<Snapshot> = {
        initialRunnerId: initialRunner.id,
      }

      await this.snapshotRepository.update(snapshot.id, { updateData, entity: snapshot })

      // Slot is now claimed (initialRunnerId set, counted by the next admission); release the admission lock so the
      // slow build/pull below runs without holding it.
      if (admissionLockKey) {
        await this.redisLockProvider.unlock(admissionLockKey)
      }
    } else {
      initialRunner = await this.runnerService.findOneOrFail(snapshot.initialRunnerId)
    }

    // Use base region for registry lookups (dedicated regions may not have registry configs)
    const regionForRegistryLookup = getFallbackRegion(initialRunner.region) ?? initialRunner.region

    if (snapshot.buildInfo) {
      await this.updateSnapshotState(snapshot, SnapshotState.BUILDING)
      await this.runnerService.createSnapshotRunnerEntry(
        initialRunner.id,
        snapshot.buildInfo.snapshotRef,
        SnapshotRunnerState.BUILDING_SNAPSHOT,
      )
      await this.processBuildOnRunner(snapshot, initialRunner)
    } else {
      if (!snapshot.ref) {
        const runnerAdapter = await this.runnerAdapterFactory.create(initialRunner)
        const registry = await this.dockerRegistryService.findRegistryByImageName(
          snapshot.imageName,
          regionForRegistryLookup,
          snapshot.organizationId,
        )

        const image = parseDockerImage(snapshot.imageName)
        if (registry && !image.registry) {
          image.registry = registry.url.replace(/^(https?:\/\/)/, '')
        }
        const imageName = image.getFullName()

        const internalRegistry = await this.dockerRegistryService.getAvailableInternalRegistry(regionForRegistryLookup)
        if (!internalRegistry) {
          throw new Error('No internal registry found for snapshot')
        }

        const snapshotDigestResponse = await runnerAdapter.inspectSnapshotInRegistry(imageName, registry)
        const digestSyncState = await this.processSnapshotDigest(
          snapshot,
          internalRegistry,
          snapshotDigestResponse.hash,
          snapshotDigestResponse.sizeGB,
        )

        if (digestSyncState === DONT_SYNC_AGAIN) {
          return DONT_SYNC_AGAIN
        }
      }

      await this.updateSnapshotState(snapshot, SnapshotState.PULLING)
      await this.runnerService.createSnapshotRunnerEntry(
        initialRunner.id,
        snapshot.ref,
        SnapshotRunnerState.PULLING_SNAPSHOT,
      )
      await this.processPullOnInitialRunner(snapshot, initialRunner)
    }

    return SYNC_AGAIN
  }

  private async updateSnapshotState(snapshot: Snapshot, state: SnapshotState, errorReason?: string, size?: number) {
    const updateData: Partial<Snapshot> = {
      state,
    }

    if (state === SnapshotState.ACTIVE) {
      updateData.lastUsedAt = new Date()
    }

    if (errorReason !== undefined) {
      updateData.errorReason = errorReason
    }

    if (size !== undefined) {
      updateData.size = size
    }

    await this.snapshotRepository.update(snapshot.id, { updateData, entity: snapshot })
  }

  @Cron(CronExpression.EVERY_MINUTE, { name: 'cleanup-old-buildinfo-snapshot-runners' })
  @TrackJobExecution()
  @LogExecution('cleanup-old-buildinfo-snapshot-runners')
  @WithInstrumentation()
  async cleanupOldBuildInfoSnapshotRunners() {
    const lockKey = 'cleanup-old-buildinfo-snapshots-lock'
    if (!(await this.redisLockProvider.lock(lockKey, 300))) {
      return
    }

    try {
      // Dedicated regions get a much shorter staleness window so we don't pin disk space
      // on small fleets when an org stops using a snapshot.
      const stalenessDays = this.configService.getOrThrow('buildInfoSnapshotRunnerStalenessDays')
      const stalenessInterval = `(CASE WHEN r.region IN (:dedicatedMeta) THEN interval '3 hours' WHEN r.region IN (:dedicatedElementor, :dedicatedRL, :dedicatedDeeptuneAndMillion) THEN interval '10 hours' ELSE interval '${stalenessDays} days' END)`

      const staleEntries = await this.snapshotRunnerRepository
        .createQueryBuilder('sr')
        .select('sr.id')
        .innerJoin(BuildInfo, 'bi', 'sr."snapshotRef" = bi."snapshotRef"')
        .innerJoin('runner', 'r', 'r.id = sr."runnerId"::uuid')
        .where('sr.state = :readyState', { readyState: SnapshotRunnerState.READY })
        .andWhere(`bi.lastUsedAt < now() - ${stalenessInterval}`)
        .andWhere(`sr.updatedAt < now() - ${stalenessInterval}`)
        .andWhere("sr.snapshotRef LIKE 'daytona-%'")
        .setParameters({
          dedicatedElementor: ELEMENTOR_DEDICATED_REGION,
          dedicatedRL: RL_REGION,
          dedicatedMeta: META_DEDICATED_REGION,
          dedicatedDeeptuneAndMillion: DEEPTUNE_AND_MILLION_DEDICATED_REGION,
        })
        .limit(500)
        .getMany()

      if (staleEntries.length === 0) {
        return
      }

      const ids = staleEntries.map((sr) => sr.id)
      const result = await this.snapshotRunnerRepository.update(
        { id: In(ids) },
        { state: SnapshotRunnerState.REMOVING },
      )

      if (result.affected > 0) {
        this.logger.debug(`Marked ${result.affected} SnapshotRunners for removal due to unused BuildInfo`)
      }
    } catch (error) {
      this.logger.error(`Failed to mark old BuildInfo SnapshotRunners for removal: ${fromAxiosError(error)}`)
    } finally {
      await this.redisLockProvider.unlock(lockKey)
    }
  }

  @Cron(CronExpression.EVERY_10_MINUTES, { name: 'deactivate-old-snapshots' })
  @TrackJobExecution()
  @LogExecution('deactivate-old-snapshots')
  @WithInstrumentation()
  async deactivateOldSnapshots() {
    const lockKey = 'deactivate-old-snapshots-lock'
    if (!(await this.redisLockProvider.lock(lockKey, 300))) {
      return
    }

    try {
      const cutoff = `NOW() - INTERVAL '1 minute' * COALESCE(org."snapshot_deactivation_timeout_minutes", ${DEFAULT_SNAPSHOT_DEACTIVATION_TIMEOUT_MINUTES})`

      const oldSnapshots = await this.snapshotRepository
        .createQueryBuilder('snapshot')
        .leftJoin('organization', 'org', `org."id" = snapshot."organizationId"`)
        .where('snapshot.general = false')
        .andWhere('snapshot.state = :snapshotState', { snapshotState: SnapshotState.ACTIVE })
        .andWhere(`(snapshot."lastUsedAt" IS NULL OR snapshot."lastUsedAt" < ${cutoff})`)
        .andWhere(`snapshot."createdAt" < ${cutoff}`)
        .andWhere('snapshot."organizationId" NOT IN (:...writerOrgs)', { writerOrgs: WRITER_ORGS })
        .andWhere(
          `NOT EXISTS (
            SELECT 1 FROM snapshot s
            WHERE s."ref" = snapshot."ref"
            AND s.state = :activeState
            AND (s."lastUsedAt" >= ${cutoff} OR s."createdAt" >= ${cutoff})
          )`,
          {
            activeState: SnapshotState.ACTIVE,
          },
        )
        .take(100)
        .getMany()

      if (oldSnapshots.length === 0) {
        return
      }

      // Deactivate the snapshots
      const settledResults = await Promise.allSettled(
        oldSnapshots.map((snapshot) =>
          this.snapshotRepository.update(snapshot.id, {
            updateData: { state: SnapshotState.INACTIVE },
            entity: snapshot,
          }),
        ),
      )

      const deactivatedSnapshots: Snapshot[] = []
      for (const [i, result] of settledResults.entries()) {
        if (result.status === 'fulfilled') {
          deactivatedSnapshots.push(oldSnapshots[i])
        } else {
          this.logger.warn(`Failed to deactivate snapshot ${oldSnapshots[i].id}: ${result.reason}`)
        }
      }

      // Get internal names of deactivated snapshots
      const refs = deactivatedSnapshots.map((snapshot) => snapshot.ref).filter((name) => name) // Filter out null/undefined values

      if (refs.length > 0) {
        // Set associated SnapshotRunner records to REMOVING state
        const result = await this.snapshotRunnerRepository.update(
          { snapshotRef: In(refs) },
          { state: SnapshotRunnerState.REMOVING },
        )

        this.logger.debug(
          `Deactivated ${deactivatedSnapshots.length} snapshots and marked ${result.affected} SnapshotRunners for removal`,
        )
      }
    } catch (error) {
      this.logger.error(`Failed to deactivate old snapshots: ${fromAxiosError(error)}`)
    } finally {
      await this.redisLockProvider.unlock(lockKey)
    }
  }

  @Cron(CronExpression.EVERY_MINUTE, { name: 'cleanup-inactive-snapshots-from-runners' })
  @TrackJobExecution()
  @LogExecution('cleanup-inactive-snapshots-from-runners')
  @WithInstrumentation()
  async cleanupInactiveSnapshotsFromRunners() {
    const lockKey = 'cleanup-inactive-snapshots-from-runners-lock'
    if (!(await this.redisLockProvider.lock(lockKey, 300))) {
      return
    }

    try {
      // Only fetch inactive snapshots that have associated snapshot runner entries
      const queryResult = await this.snapshotRepository
        .createQueryBuilder('snapshot')
        .select('snapshot."ref"')
        .where('snapshot.state = :inactiveState', { inactiveState: SnapshotState.INACTIVE })
        .andWhere('snapshot."ref" IS NOT NULL')
        .andWhereExists(
          this.snapshotRunnerRepository
            .createQueryBuilder('snapshot_runner')
            .select('1')
            .where('snapshot_runner."snapshotRef" = snapshot."ref"')
            .andWhere('snapshot_runner.state != :snapshotRunnerState', {
              snapshotRunnerState: SnapshotRunnerState.REMOVING,
            }),
        )
        .andWhere(
          () => {
            const query = this.snapshotRepository
              .createQueryBuilder('s')
              .select('1')
              .where('s."ref" = snapshot."ref"')
              .andWhere('s.state = :activeState')
            return `NOT EXISTS (${query.getQuery()})`
          },
          {
            activeState: SnapshotState.ACTIVE,
          },
        )
        .orderBy('snapshot."updatedAt"', 'DESC')
        .take(100)
        .getRawMany()

      const inactiveSnapshotRefs = queryResult.map((result) => result.ref)

      if (inactiveSnapshotRefs.length > 0) {
        // Set associated SnapshotRunner records to REMOVING state
        const result = await this.snapshotRunnerRepository.update(
          { snapshotRef: In(inactiveSnapshotRefs) },
          { state: SnapshotRunnerState.REMOVING },
        )

        this.logger.debug(`Marked ${result.affected} SnapshotRunners for removal`)
      }
    } catch (error) {
      this.logger.error(`Failed to cleanup inactive snapshots from runners: ${fromAxiosError(error)}`)
    } finally {
      await this.redisLockProvider.unlock(lockKey)
    }
  }

  private async processSnapshotDigest(
    snapshot: Snapshot,
    internalRegistry: DockerRegistry,
    hash: string,
    sizeGB?: number,
    entrypoint?: string[] | string,
  ) {
    const updateData: Partial<Snapshot> = {}

    if (!snapshot.ref) {
      const sanitizedUrl = internalRegistry.url.replace(/^https?:\/\//, '')
      updateData.ref = `${sanitizedUrl}/${internalRegistry.project || 'daytona'}/daytona-${hash}:daytona`
    }

    if (snapshot.size == null && typeof sizeGB === 'number') {
      const organization = await this.organizationService.findOne(snapshot.organizationId)
      if (!organization) {
        throw new NotFoundException(`Organization with ID ${snapshot.organizationId} not found`)
      }

      const MAX_SIZE_GB = organization.maxSnapshotSize

      updateData.size = sizeGB

      if (sizeGB > MAX_SIZE_GB) {
        await this.updateSnapshotState(
          snapshot,
          SnapshotState.ERROR,
          `Snapshot size (${sizeGB.toFixed(2)}GB) exceeds maximum allowed size of ${MAX_SIZE_GB}GB`,
          sizeGB,
        )
        return DONT_SYNC_AGAIN
      }
    }

    // If entrypoint is not explicitly set, set it from snapshotInfoResponse
    if (!snapshot.entrypoint) {
      if (entrypoint && entrypoint.length > 0) {
        updateData.entrypoint = Array.isArray(entrypoint) ? entrypoint : [entrypoint]
      }
    }

    if (Object.keys(updateData).length > 0) {
      await this.snapshotRepository.update(snapshot.id, { updateData, entity: snapshot })
    }
  }

  @OnAsyncEvent({
    event: SnapshotEvents.CREATED,
  })
  private async handleSnapshotCreatedEvent(event: SnapshotCreatedEvent) {
    await this.syncSnapshotState(event.snapshot.id)
  }

  @OnAsyncEvent({
    event: SnapshotEvents.ACTIVATED,
  })
  private async handleSnapshotActivatedEvent(event: SnapshotActivatedEvent) {
    await this.syncSnapshotState(event.snapshot.id)
  }

  // Fired by the v2 job handler when the initial pull/build lands, so activation goes through
  // handleCheckInitialRunnerSnapshot -> waitForInitialPropagation instead of activating without propagation.
  @OnAsyncEvent({
    event: SnapshotEvents.INITIAL_RUNNER_READY,
  })
  private async handleSnapshotInitialRunnerReadyEvent(event: SnapshotInitialRunnerReadyEvent) {
    await this.syncSnapshotState(event.snapshotId)
  }
}
