/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { BadRequestException, ConflictException, Inject, Injectable, Logger, NotFoundException } from '@nestjs/common'
import { InjectRepository } from '@nestjs/typeorm'
import { Cron, CronExpression } from '@nestjs/schedule'
import {
  DataSource,
  Equal,
  FindOptionsWhere,
  In,
  IsNull,
  MoreThanOrEqual,
  Not,
  Or,
  Repository,
  UpdateResult,
} from 'typeorm'
import { Runner } from '../entities/runner.entity'
import { CreateRunnerInternalDto } from '../dto/create-runner-internal.dto'
import { SandboxClass } from '../enums/sandbox-class.enum'
import { GpuType } from '../enums/gpu-type.enum'
import { RunnerState } from '../enums/runner-state.enum'
import { BadRequestError } from '../../exceptions/bad-request.exception'
import { EventEmitter2 } from '@nestjs/event-emitter'
import { SandboxState } from '../enums/sandbox-state.enum'
import { SnapshotRunner } from '../entities/snapshot-runner.entity'
import { SnapshotRunnerState } from '../enums/snapshot-runner-state.enum'
import { RunnerSnapshotDto } from '../dto/runner-snapshot.dto'
import { RunnerAdapterFactory, RunnerInfo } from '../runner-adapter/runnerAdapter'
import { RedisLockProvider } from '../common/redis-lock.provider'
import { TypedConfigService } from '../../config/typed-config.service'
import { LogExecution } from '../../common/decorators/log-execution.decorator'
import { getFallbackRegions, hasFallbackRegion, isHighReliabilityRegion } from '../constants/dedicated-regions.constant'
import { WithInstrumentation } from '../../common/decorators/otel.decorator'
import { RegionService } from '../../region/services/region.service'
import { RUNNER_NAME_REGEX } from '../constants/runner-name-regex.constant'
import { RegionType } from '../../region/enums/region-type.enum'
import { RunnerDto } from '../dto/runner.dto'
import { RunnerEvents } from '../constants/runner-events'
import { RunnerStateUpdatedEvent } from '../events/runner-state-updated.event'
import { RunnerDeletedEvent } from '../events/runner-deleted.event'
import { generateApiKeyValue } from '../../common/utils/api-key'
import { RunnerFullDto } from '../dto/runner-full.dto'
import { InjectRedis } from '@nestjs-modules/ioredis'
import Redis from 'ioredis'
import { SandboxDesiredState } from '../enums/sandbox-desired-state.enum'
import { runnerLookupCacheKeyById, RUNNER_LOOKUP_CACHE_TTL_MS } from '../utils/runner-lookup-cache.util'
import { normalizeGpuType } from '../utils/gpu-type-normalizer.util'
import { SandboxRepository } from '../repositories/sandbox.repository'
import { SnapshotRepository } from '../repositories/snapshot.repository'
import { RunnerServiceInfo } from '../common/runner-service-info'

const SYSBOX_SERVICE_NAMES = ['sysbox-mgr', 'sysbox-fs']

@Injectable()
export class RunnerService {
  private readonly logger = new Logger(RunnerService.name)
  private readonly serviceStartTime = new Date()
  private readonly scoreConfig: AvailabilityScoreConfig

  constructor(
    @InjectRepository(Runner)
    private readonly runnerRepository: Repository<Runner>,
    private readonly runnerAdapterFactory: RunnerAdapterFactory,
    private readonly sandboxRepository: SandboxRepository,
    @InjectRepository(SnapshotRunner)
    private readonly snapshotRunnerRepository: Repository<SnapshotRunner>,
    private readonly redisLockProvider: RedisLockProvider,
    private readonly configService: TypedConfigService,
    private readonly regionService: RegionService,
    private readonly snapshotRepository: SnapshotRepository,
    @Inject(EventEmitter2)
    private eventEmitter: EventEmitter2,
    private readonly dataSource: DataSource,
    @InjectRedis()
    private readonly redis: Redis,
  ) {
    this.scoreConfig = this.getAvailabilityScoreConfig()
  }

  /**
   * @throws {BadRequestException} If the runner name or class is invalid.
   * @throws {NotFoundException} If the region is not found.
   * @throws {ConflictException} If a runner with the same values already exists.
   */
  async create(createRunnerDto: CreateRunnerInternalDto): Promise<{
    runner: Runner
    apiKey: string
  }> {
    if (!RUNNER_NAME_REGEX.test(createRunnerDto.name)) {
      throw new BadRequestException('Runner name must contain only letters, numbers, underscores, periods, and hyphens')
    }
    if (createRunnerDto.name.length < 2 || createRunnerDto.name.length > 255) {
      throw new BadRequestException('Runner name must be between 3 and 255 characters')
    }

    const apiKey = createRunnerDto.apiKey ?? generateApiKeyValue()

    let runner: Runner

    switch (createRunnerDto.apiVersion) {
      case '0':
        runner = new Runner({
          region: createRunnerDto.regionId,
          name: createRunnerDto.name,
          apiVersion: createRunnerDto.apiVersion,
          apiKey: apiKey,
          cpu: createRunnerDto.cpu,
          memoryGiB: createRunnerDto.memoryGiB,
          diskGiB: createRunnerDto.diskGiB,
          domain: createRunnerDto.domain,
          apiUrl: createRunnerDto.apiUrl,
          proxyUrl: createRunnerDto.proxyUrl,
          appVersion: createRunnerDto.appVersion,
          tags: createRunnerDto.tags,
          sandboxClass: createRunnerDto.sandboxClass,
        })
        break
      case '2':
        runner = new Runner({
          region: createRunnerDto.regionId,
          name: createRunnerDto.name,
          apiVersion: createRunnerDto.apiVersion,
          apiKey: apiKey,
          appVersion: createRunnerDto.appVersion,
          tags: createRunnerDto.tags,
          sandboxClass: createRunnerDto.sandboxClass,
        })
        break
      default:
        throw new BadRequestException('Invalid runner version')
    }

    try {
      const savedRunner = await this.runnerRepository.save(runner)
      this.invalidateRunnerCache(savedRunner.id)
      return { runner: savedRunner, apiKey }
    } catch (error) {
      if (error.code === '23505') {
        if (error.detail.includes('domain')) {
          throw new ConflictException('This domain is already in use')
        }
        if (error.detail.includes('name')) {
          throw new ConflictException(`Runner with name ${createRunnerDto.name} already exists in this region`)
        }
        throw new ConflictException('A runner with these values already exists')
      }
      throw error
    }
  }

  async findAllFull(): Promise<RunnerFullDto[]> {
    const runners = await this.runnerRepository.find()

    const regionIds = new Set(runners.map((runner) => runner.region))
    const regions = await this.regionService.findByIds(Array.from(regionIds))

    const regionTypeMap = new Map<string, RegionType>()
    regions.forEach((region) => {
      regionTypeMap.set(region.id, region.regionType)
    })

    return runners.map((runner) => RunnerFullDto.fromRunner(runner, regionTypeMap.get(runner.region)))
  }

  async findAllByRegion(regionId: string): Promise<RunnerDto[]> {
    const runners = await this.runnerRepository.find({
      where: {
        region: regionId,
      },
    })

    return runners.map(RunnerDto.fromRunner)
  }

  async findAllByRegionFull(regionId: string): Promise<RunnerFullDto[]> {
    const runners = await this.runnerRepository.find({
      where: {
        region: regionId,
      },
    })

    const region = await this.regionService.findOne(regionId)

    return runners.map((runner) => RunnerFullDto.fromRunner(runner, region?.regionType))
  }

  async findAllByOrganization(organizationId: string, regionType?: RegionType): Promise<RunnerDto[]> {
    const regions = await this.regionService.findAllByOrganization(organizationId, regionType)
    const regionIds = regions.map((region) => region.id)

    const runners = await this.runnerRepository.find({
      where: {
        region: In(regionIds),
      },
    })

    return runners.map(RunnerDto.fromRunner)
  }

  async findDrainingPaginated(skip: number, take: number): Promise<Runner[]> {
    return this.runnerRepository.find({
      where: {
        draining: true,
        state: Not(RunnerState.DECOMMISSIONED),
      },
      order: {
        id: 'ASC',
      },
      skip,
      take,
    })
  }

  async findAllReady(): Promise<Runner[]> {
    return this.runnerRepository.find({
      where: {
        state: RunnerState.READY,
      },
    })
  }

  async findOne(id: string): Promise<Runner | null> {
    return this.runnerRepository.findOne({
      where: { id },
      cache: {
        id: runnerLookupCacheKeyById(id),
        milliseconds: RUNNER_LOOKUP_CACHE_TTL_MS,
      },
    })
  }

  async findOneOrFail(id: string): Promise<Runner> {
    const runner = await this.findOne(id)
    if (!runner) {
      throw new NotFoundException(`Runner with ID ${id} not found`)
    }
    return runner
  }

  async findOneFullOrFail(id: string): Promise<RunnerFullDto> {
    const runner = await this.findOneOrFail(id)
    const region = await this.regionService.findOne(runner.region)

    return RunnerFullDto.fromRunner(runner, region?.regionType)
  }

  async findOneByDomain(domain: string): Promise<Runner | null> {
    return this.runnerRepository.findOneBy({ domain })
  }

  async findByIds(runnerIds: string[]): Promise<Runner[]> {
    if (runnerIds.length === 0) {
      return []
    }

    return this.runnerRepository.find({
      where: { id: In(runnerIds) },
    })
  }

  async findByApiKey(apiKey: string): Promise<Runner | null> {
    return this.runnerRepository.findOneBy({ apiKey })
  }

  async findBySandboxId(sandboxId: string): Promise<Runner | null> {
    const sandbox = await this.sandboxRepository.findOne({
      where: { id: sandboxId, state: Not(SandboxState.DESTROYED) },
      select: ['runnerId'],
    })
    if (!sandbox) {
      throw new NotFoundException(`Sandbox with ID ${sandboxId} not found`)
    }
    if (!sandbox.runnerId) {
      throw new NotFoundException(`Sandbox with ID ${sandboxId} does not have a runner`)
    }

    return this.findOne(sandbox.runnerId)
  }

  async getRegionId(runnerId: string): Promise<string> {
    const runner = await this.runnerRepository.findOne({
      where: {
        id: runnerId,
      },
      select: ['region'],
      loadEagerRelations: false,
    })

    if (!runner || !runner.region) {
      throw new NotFoundException('Runner not found')
    }

    return runner.region
  }

  async findAvailableRunners(params: GetRunnerParams): Promise<Runner[]> {
    const runnerFilter: FindOptionsWhere<Runner> = {
      state: RunnerState.READY,
      unschedulable: Not(true),
      draining: Not(true),
      availabilityScore: params.availabilityScoreThreshold
        ? MoreThanOrEqual(params.availabilityScoreThreshold)
        : MoreThanOrEqual(this.configService.getOrThrow('runnerScore.thresholds.availability')),
    }

    if (params.gpu > 0) {
      // runner.gpu = -1 means infinite GPU capacity, so it satisfies any positive GPU requirement.
      runnerFilter.gpu = Or(Equal(-1), MoreThanOrEqual(params.gpu))
      if (typeof params.gpuType === 'string') {
        runnerFilter.gpuType = params.gpuType
      }
    } else {
      // GPU runners are exclusively reserved for GPU sandboxes.
      runnerFilter.gpu = Or(IsNull(), Equal(0))
    }

    const excludedRunnerIds = new Set((params.excludedRunnerIds ?? []).filter((id): id is string => !!id))

    // A runner with runner.gpu = N can host up to N concurrent GPU sandboxes.
    // Skip runners that have already reached their GPU sandbox capacity.
    if (params.gpu > 0) {
      const fullRunnerIds = await this.getRunnersAtGpuCapacity()
      for (const id of fullRunnerIds) {
        excludedRunnerIds.add(id)
      }
    }

    // Reservation: a runner is not a candidate when its active sandboxes plus
    // this request would exceed the configured fraction of its registered
    // CPU or memory. The health score stays a tie-breaker; it is not a
    // capacity model. Disabled while the limits are 0.
    const reservation = {
      maxCpuUtilization: Number(this.configService.get('runnerReservation.maxCpuUtilization') ?? 0),
      maxMemUtilization: Number(this.configService.get('runnerReservation.maxMemUtilization') ?? 0),
    }
    if (
      (reservation.maxCpuUtilization > 0 || reservation.maxMemUtilization > 0) &&
      ((params.cpu ?? 0) > 0 || (params.mem ?? 0) > 0)
    ) {
      const overLimits = await this.getRunnersOverReservationLimits(reservation, {
        cpu: params.cpu,
        mem: params.mem,
      })
      for (const id of overLimits) {
        excludedRunnerIds.add(id)
      }
    }

    if (params.snapshotRef !== undefined) {
      const snapshotRunners = await this.snapshotRunnerRepository.find({
        where: {
          state: SnapshotRunnerState.READY,
          snapshotRef: params.snapshotRef,
        },
      })

      const runnerIds = snapshotRunners
        .map((snapshotRunner) => snapshotRunner.runnerId)
        .filter((id) => !excludedRunnerIds.has(id))

      if (!runnerIds.length) {
        return []
      }

      runnerFilter.id = In(runnerIds)
    } else if (excludedRunnerIds.size) {
      runnerFilter.id = Not(In(Array.from(excludedRunnerIds)))
    }

    if (params.regions?.length) {
      runnerFilter.region = In(params.regions)
    }

    if (params.sandboxClass !== undefined) {
      runnerFilter.sandboxClass = params.sandboxClass
    }

    const runners = await this.runnerRepository.find({
      where: runnerFilter,
    })

    if (runners.length === 0 && params.regions && params.regions.some(hasFallbackRegion)) {
      return this.findAvailableRunners({ ...params, regions: getFallbackRegions(params.regions) })
    }

    const selectionPercentage = params.regions?.includes('RL') ? 0.75 : 0.33

    return runners
      .sort((a, b) => b.availabilityScore - a.availabilityScore)
      .slice(0, Math.max(10, Math.ceil(runners.length * selectionPercentage)))
  }

  /**
   * Returns true if at least one runner is registered for the given (region, sandboxClass)
   * and is currently schedulable.
   *
   * Callers must apply `getRunnerSandboxClass(snapshot.sandboxClass)` before calling, matching the
   * convention used by `findAvailableRunners` / `getRandomAvailableRunner`. Otherwise classes
   * that re-target to a different runner pool (currently `ANDROID → CONTAINER`) will be
   * falsely reported as having no schedulable runners.
   *
   * Intentionally ignores transient signals like `state` (e.g. UNRESPONSIVE) and
   * `availabilityScore`, so this returns true even if every matching runner is temporarily
   * unhealthy. The purpose is to detect a *structural* misconfiguration where no runner could
   * ever host a snapshot of that (region, sandboxClass) combination, and to fail snapshot
   * creation fast with a 400 instead of letting it sit in PENDING indefinitely.
   */
  async hasSchedulableRunner(regionId: string, sandboxClass: SandboxClass): Promise<boolean> {
    return this.runnerRepository.exists({
      where: {
        region: regionId,
        sandboxClass,
        unschedulable: Not(true),
        draining: Not(true),
      },
    })
  }

  /**
   * @throws {NotFoundException} If the runner is not found.
   * @throws {HttpException} If the runner is not unschedulable.
   * @throws {HttpException} If the runner has sandboxes associated with it.
   */
  async remove(id: string): Promise<void> {
    const runner = await this.findOne(id)
    if (!runner) {
      throw new NotFoundException('Runner not found')
    }

    if (!runner.unschedulable) {
      throw new BadRequestError('Cannot delete runner which is available for scheduling sandboxes')
    }

    const sandboxCount = await this.sandboxRepository.count({
      where: { runnerId: id, state: Not(In([SandboxState.ARCHIVED, SandboxState.DESTROYED])) },
    })
    if (sandboxCount > 0) {
      throw new BadRequestError('Cannot delete runner which has sandboxes associated with it')
    }

    await this.dataSource.transaction(async (em) => {
      await em.delete(Runner, id)
      await this.eventEmitter.emitAsync(RunnerEvents.DELETED, new RunnerDeletedEvent(em, id))
    })
    this.invalidateRunnerCache(id)
  }

  async updateRunnerHealth(
    runnerId: string,
    domain?: string,
    apiUrl?: string,
    proxyUrl?: string,
    serviceHealth?: RunnerServiceInfo[],
    metrics?: {
      currentCpuLoadAverage?: number
      currentCpuUsagePercentage?: number
      currentMemoryUsagePercentage?: number
      currentDiskUsagePercentage?: number
      currentAllocatedCpu?: number
      currentAllocatedMemoryGiB?: number
      currentAllocatedDiskGiB?: number
      currentSnapshotCount?: number
      currentStartedSandboxes?: number
      cpu?: number
      memoryGiB?: number
      diskGiB?: number
      gpu?: number
      gpuType?: string
    },
    appVersion?: string,
  ): Promise<void> {
    const runner = await this.findOne(runnerId)
    if (!runner) {
      this.logger.error(`Runner ${runnerId} not found when trying to update health`)
      return
    }

    if (runner.state === RunnerState.DECOMMISSIONED) {
      this.logger.debug(`Runner ${runnerId} is decommissioned, not updating health`)
      return
    }

    const updateData: Partial<Runner> = {
      state: RunnerState.READY,
      lastChecked: new Date(),
    }

    if (domain) {
      updateData.domain = domain
    }

    if (apiUrl) {
      updateData.apiUrl = apiUrl
    }

    if (proxyUrl) {
      updateData.proxyUrl = proxyUrl
    }

    if (appVersion) {
      updateData.appVersion = appVersion
    }

    if (serviceHealth !== undefined) {
      updateData.serviceHealth = serviceHealth
    } else {
      // Clear any previously stored service health when no new health data is provided
      updateData.serviceHealth = null
    }

    const unhealthyServices = serviceHealth?.filter((s) => !s.healthy) ?? []
    if (unhealthyServices.length > 0) {
      const unhealthySummary = unhealthyServices
        .map((s) => `"${s.serviceName}"${s.errorReason ? ` (${s.errorReason})` : ''}`)
        .join(', ')
      this.logger.warn(`Runner ${runnerId} services reported unhealthy: ${unhealthySummary}`)

      // Sysbox outages don't affect running sandboxes in most ways, so by default they don't make the runner unresponsive
      const relevantServices = this.configService.get('runnerUnresponsiveOnUnhealthySysbox')
        ? unhealthyServices
        : unhealthyServices.filter((s) => !SYSBOX_SERVICE_NAMES.includes(s.serviceName))

      if (relevantServices.length > 0 && process.env.RUNNER_UNHEALTHY_ON_SERVICE_UNHEALTHY === 'true') {
        updateData.state = RunnerState.UNRESPONSIVE
      }
    }

    if (metrics) {
      updateData.currentCpuLoadAverage = metrics.currentCpuLoadAverage || 0
      updateData.currentCpuUsagePercentage = metrics.currentCpuUsagePercentage || 0
      updateData.currentMemoryUsagePercentage = metrics.currentMemoryUsagePercentage || 0
      updateData.currentDiskUsagePercentage = metrics.currentDiskUsagePercentage || 0
      updateData.currentAllocatedCpu = metrics.currentAllocatedCpu || 0
      updateData.currentAllocatedMemoryGiB = metrics.currentAllocatedMemoryGiB || 0
      updateData.currentAllocatedDiskGiB = metrics.currentAllocatedDiskGiB || 0
      updateData.currentSnapshotCount = metrics.currentSnapshotCount || 0
      updateData.currentStartedSandboxes = metrics.currentStartedSandboxes || 0
      updateData.cpu = metrics.cpu
      updateData.memoryGiB = metrics.memoryGiB
      updateData.diskGiB = metrics.diskGiB

      if (metrics.gpu !== undefined) {
        updateData.gpu = metrics.gpu
      }
      if (metrics.gpuType !== undefined) {
        const normalized = normalizeGpuType(metrics.gpuType)
        if (metrics.gpuType && !normalized) {
          this.logger.warn(`Runner ${runnerId} reported unrecognized GPU type: "${metrics.gpuType}"`)
        }
        updateData.gpuType = normalized
      }

      updateData.availabilityScore = this.calculateAvailabilityScore(runnerId, {
        cpuLoadAverage: updateData.currentCpuLoadAverage,
        cpuUsage: updateData.currentCpuUsagePercentage,
        memoryUsage: updateData.currentMemoryUsagePercentage,
        diskUsage: updateData.currentDiskUsagePercentage,
        allocatedCpu: updateData.currentAllocatedCpu,
        allocatedMemoryGiB: updateData.currentAllocatedMemoryGiB,
        allocatedDiskGiB: updateData.currentAllocatedDiskGiB,
        runnerCpu: updateData.cpu || runner.cpu,
        runnerMemoryGiB: updateData.memoryGiB || runner.memoryGiB,
        runnerDiskGiB: updateData.diskGiB || runner.diskGiB,
        startedSandboxes: updateData.currentStartedSandboxes || 0,
      })

      if (isHighReliabilityRegion(runner.region)) {
        updateData.availabilityScore = Math.max(0, updateData.availabilityScore - 20) // More conservative scoring for dedicated runners
      }
    } else {
      this.logger.warn(`Runner ${runnerId} reported null metrics`)
    }

    await this.updateRunner(runnerId, updateData)
    this.logger.debug(`Updated health for runner ${runnerId}`)

    this.eventEmitter.emit(
      RunnerEvents.STATE_UPDATED,
      new RunnerStateUpdatedEvent(runner, runner.state, updateData.state),
    )
  }

  private async updateRunnerState(runnerId: string, newState: RunnerState): Promise<void> {
    const runner = await this.findOne(runnerId)
    if (!runner) {
      this.logger.error(`Runner ${runnerId} not found when trying to update state`)
      return
    }

    // Don't change state if runner is decommissioned
    if (runner.state === RunnerState.DECOMMISSIONED) {
      this.logger.debug(`Runner ${runnerId} is decommissioned, not updating state`)
      return
    }

    await this.updateRunner(runnerId, {
      state: newState,
      lastChecked: new Date(),
    })

    this.eventEmitter.emit(RunnerEvents.STATE_UPDATED, new RunnerStateUpdatedEvent(runner, runner.state, newState))
  }

  @Cron(CronExpression.EVERY_10_SECONDS, { name: 'check-runners', waitForCompletion: true })
  @LogExecution('check-runners')
  @WithInstrumentation()
  private async handleCheckRunners() {
    const lockKey = 'check-runners'
    const hasLock = await this.redisLockProvider.lock(lockKey, 60)
    if (!hasLock) {
      return
    }

    try {
      const runners = await this.runnerRepository.find({
        where: [
          {
            apiVersion: '0',
            state: Not(RunnerState.DECOMMISSIONED),
          },
          {
            // v2 runners report health via healthcheck endpoint, so we only check if the health is stale (lastChecked timestamp)
            apiVersion: '2',
            state: RunnerState.READY,
          },
        ],
        order: {
          lastChecked: {
            direction: 'ASC',
            nulls: 'FIRST',
          },
        },
        take: 100,
      })

      await Promise.allSettled(
        runners.map(async (runner) => {
          // v2 runners report health via healthcheck endpoint, check based on lastChecked timestamp
          if (runner.apiVersion === '2') {
            await this.checkRunnerV2Health(runner)
            return
          }

          // v0 runners: imperative health check via adapter
          const shouldRetry = runner.state === RunnerState.READY
          const retryDelays = shouldRetry ? [500, 1000] : []

          for (let attempt = 0; attempt <= retryDelays.length; attempt++) {
            if (attempt > 0) {
              await new Promise((resolve) => setTimeout(resolve, retryDelays[attempt - 1]))
            }

            const abortController = new AbortController()
            let timeoutId: NodeJS.Timeout | null = null

            const runnerHealthTimeoutSeconds = this.configService.get('runnerHealthTimeout')

            try {
              await Promise.race([
                (async () => {
                  this.logger.debug(`Checking runner ${runner.id}`)
                  const runnerAdapter = await this.runnerAdapterFactory.create(runner)

                  await runnerAdapter.healthCheck(abortController.signal)

                  let runnerInfo: RunnerInfo | undefined
                  try {
                    runnerInfo = await runnerAdapter.runnerInfo(abortController.signal)
                  } catch (e) {
                    this.logger.warn(`Failed to get runner info for runner ${runner.id}: ${e.message}`)
                  }

                  await this.updateRunnerHealth(
                    runner.id,
                    undefined,
                    undefined,
                    undefined,
                    runnerInfo?.serviceHealth,
                    runnerInfo?.metrics,
                    runnerInfo?.appVersion,
                  )
                })(),
                new Promise((_, reject) => {
                  timeoutId = setTimeout(() => {
                    abortController.abort()
                    reject(new Error('Health check timeout'))
                  }, runnerHealthTimeoutSeconds * 1000)
                }),
              ])

              if (timeoutId) {
                clearTimeout(timeoutId)
              }
              return // Success, exit retry loop
            } catch (e) {
              if (timeoutId) {
                clearTimeout(timeoutId)
              }

              if (e.message === 'Health check timeout') {
                this.logger.error(
                  `Runner ${runner.id} health check timed out after ${runnerHealthTimeoutSeconds} seconds`,
                )
              } else if (e.code === 'ECONNREFUSED') {
                this.logger.error(`Runner ${runner.id} not reachable`)
              } else if (e.name === 'AbortError') {
                this.logger.error(`Runner ${runner.id} health check was aborted due to timeout`)
              } else {
                this.logger.error(`Error checking runner ${runner.id}`, e)
              }

              // If last attempt, mark as unresponsive
              if (attempt === retryDelays.length) {
                await this.updateRunnerState(runner.id, RunnerState.UNRESPONSIVE)
              }
            }
          }
        }),
      )
    } finally {
      await this.redisLockProvider.unlock(lockKey)
    }
  }

  /**
   * Check v2 runner health based on lastChecked timestamp.
   * v2 runners report health via the healthcheck endpoint, so we check if lastChecked is within threshold.
   */
  private async checkRunnerV2Health(runner: Runner): Promise<void> {
    const markAsUnresponsive = async () => {
      this.logger.warn(
        `v2 Runner ${runner.id} health check stale (last: ${Math.round((Date.now() - runner.lastChecked.getTime()) / 1000)}s ago), marking as UNRESPONSIVE`,
      )
      await this.updateRunnerState(runner.id, RunnerState.UNRESPONSIVE)
    }

    if (!runner.lastChecked) {
      return
    }

    // v2 runners report health every ~10 seconds via the healthcheck endpoint
    // Allow 60 seconds (6 missed healthchecks) before marking as UNRESPONSIVE
    const healthCheckThresholdMs = 60 * 1000

    if (runner.lastChecked < this.serviceStartTime) {
      // Allow the runner a grace period to re-establish health checks
      const timeSinceServiceStart = Date.now() - this.serviceStartTime.getTime()

      if (timeSinceServiceStart > healthCheckThresholdMs) {
        // Grace period expired and runner still hasn't checked in
        await markAsUnresponsive()
      }
    } else {
      // Runner has checked in since API started - use normal threshold
      const timeSinceLastCheck = Date.now() - runner.lastChecked.getTime()

      if (timeSinceLastCheck > healthCheckThresholdMs) {
        // Runner hasn't reported health recently
        await markAsUnresponsive()
      }
    }
  }

  // @Cron(CronExpression.EVERY_10_SECONDS, { name: 'check-decommission-runners', waitForCompletion: true })
  @LogExecution('check-decommission-runners')
  @WithInstrumentation()
  private async handleCheckDecommissionRunners() {
    const lockKey = 'check-decommission-runners'
    const hasLock = await this.redisLockProvider.lock(lockKey, 60)
    if (!hasLock) {
      return
    }

    try {
      const drainingRunners = await this.runnerRepository.find({
        where: {
          draining: true,
          state: Not(RunnerState.DECOMMISSIONED),
        },
      })

      this.logger.debug(`Checking ${drainingRunners.length} draining runners`)

      await Promise.allSettled(
        drainingRunners.map(async (runner) => {
          try {
            // Check if runner has any sandboxes with desiredState != DESTROYED
            const nonDestroyedSandboxCount = await this.sandboxRepository.count({
              where: {
                runnerId: runner.id,
                desiredState: Not(SandboxDesiredState.DESTROYED),
              },
            })

            const redisKey = `runner:draining-check:${runner.id}`

            if (nonDestroyedSandboxCount > 0) {
              // Reset counter if there are non-destroyed sandboxes
              await this.redis.set(redisKey, '0', 'EX', 600) // 10 minute TTL
              this.logger.debug(
                `Runner ${runner.id} has ${nonDestroyedSandboxCount} sandboxes with desiredState != DESTROYED, reset counter`,
              )
            } else {
              // Increment counter
              const currentCount = await this.redis.get(redisKey)
              const count = currentCount ? parseInt(currentCount, 10) + 1 : 1

              if (count >= 3) {
                // Decommission the runner
                await this.updateRunner(runner.id, {
                  state: RunnerState.DECOMMISSIONED,
                })
                await this.redis.del(redisKey)
                this.logger.log(`Runner ${runner.id} has been decommissioned after 3 successful draining checks`)
              } else {
                await this.redis.set(redisKey, count.toString(), 'EX', 600) // 10 minute TTL
                this.logger.debug(
                  `Runner ${runner.id} draining check passed (${count}/3), all sandboxes have desiredState = DESTROYED`,
                )
              }
            }
          } catch (e) {
            this.logger.error(`Error checking draining runner ${runner.id}`, e)
          }
        }),
      )
    } finally {
      await this.redisLockProvider.unlock(lockKey)
    }
  }

  /** Operator record of the node behind a runner; heartbeats report CPU only. */
  async updateRegisteredCapacity(
    id: string,
    capacity: { cpu?: number; memoryGiB?: number; diskGiB?: number },
  ): Promise<void> {
    const runner = await this.findOne(id)
    if (!runner) {
      throw new NotFoundException(`Runner with ID ${id} not found`)
    }
    const update: Partial<Runner> = {}
    for (const key of ['cpu', 'memoryGiB', 'diskGiB'] as const) {
      const value = capacity[key]
      if (value === undefined) continue
      if (!Number.isFinite(value) || value <= 0) {
        throw new BadRequestError(`Runner ${key} must be a positive number`)
      }
      update[key] = value
    }
    if (Object.keys(update).length === 0) return
    await this.runnerRepository.update(id, update)
  }

  async updateSchedulingStatus(id: string, unschedulable: boolean): Promise<Runner> {
    const runner = await this.findOneOrFail(id)
    runner.unschedulable = unschedulable
    await this.runnerRepository.save(runner)
    return runner
  }

  async updateDrainingStatus(id: string, draining: boolean): Promise<Runner> {
    const runner = await this.findOneOrFail(id)
    runner.draining = draining
    await this.runnerRepository.save(runner)
    return runner
  }

  async getRandomAvailableRunner(params: GetRunnerParams): Promise<Runner> {
    const pickRandom = (runners: Runner[]) => runners[Math.floor(Math.random() * runners.length)]

    if (params.gpu > 0 && Array.isArray(params.gpuType) && params.gpuType.length > 0) {
      for (const gpuType of params.gpuType) {
        const candidates = await this.findAvailableRunners({ ...params, gpuType })
        if (candidates.length > 0) {
          return pickRandom(candidates)
        }
      }
      throw new BadRequestError(`No available runners with GPU type: ${params.gpuType.join(', ')}.`)
    }

    const availableRunners = await this.findAvailableRunners(params)
    if (availableRunners.length === 0) {
      throw new BadRequestError('No available runners')
    }
    return pickRandom(availableRunners)
  }

  /**
   * Asserts that the given runner can host a new sandbox with the requested resources and sandboxClass.
   * Combines the schedulability checks applied by findAvailableRunners (state/flags/availabilityScore)
   * with an explicit resource-fit check against the runner's currently reported allocations.
   *
   * Used when a specific runner is required (e.g. linking a new sandbox to an existing sandbox on a runner).
   *
   * @throws {BadRequestError} If any precondition is not met.
   */
  assertRunnerCanHost(runner: Runner): void {
    if (runner.state !== RunnerState.READY) {
      throw new BadRequestError(`Runner ${runner.id} is not READY (current: ${runner.state})`)
    }
    if (runner.unschedulable) {
      throw new BadRequestError(`Runner ${runner.id} is unschedulable`)
    }
    if (runner.draining) {
      throw new BadRequestError(`Runner ${runner.id} is draining`)
    }

    const minScore = this.configService.getOrThrow('runnerScore.thresholds.availability')
    if (runner.availabilityScore < minScore) {
      throw new BadRequestError(
        `Runner ${runner.id} does not meet availability score threshold (${runner.availabilityScore} < ${minScore})`,
      )
    }
  }

  async getSnapshotRunner(runnerId: string, snapshotRef: string): Promise<SnapshotRunner> {
    return this.snapshotRunnerRepository.findOne({
      where: {
        runnerId: runnerId,
        snapshotRef: snapshotRef,
      },
    })
  }

  async getSnapshotRunners(snapshotRef: string): Promise<SnapshotRunner[]> {
    return this.snapshotRunnerRepository.find({
      where: {
        snapshotRef,
      },
      order: {
        state: 'ASC', // Sorts state BUILDING_SNAPSHOT before ERROR
        createdAt: 'ASC', // Sorts first runner to start building snapshot on top
      },
    })
  }

  async createSnapshotRunnerEntry(
    runnerId: string,
    snapshotRef: string,
    state?: SnapshotRunnerState,
    errorReason?: string,
  ): Promise<void> {
    try {
      const snapshotRunner = new SnapshotRunner()
      snapshotRunner.runnerId = runnerId
      snapshotRunner.snapshotRef = snapshotRef
      if (state) {
        snapshotRunner.state = state
      }
      if (errorReason) {
        snapshotRunner.errorReason = errorReason
      }
      await this.snapshotRunnerRepository.save(snapshotRunner)
    } catch (error) {
      if (error.code === '23505') {
        // PostgreSQL unique violation error code - entry already exists, allow it
        this.logger.debug(
          `SnapshotRunner entry already exists for runnerId: ${runnerId}, snapshotRef: ${snapshotRef}. Continuing...`,
        )
        return
      }
      throw error // Re-throw any other errors
    }
  }

  // TODO: combine getRunnersWithMultipleSnapshotsBuilding and getRunnersWithMultipleSnapshotsPulling?

  async getRunnersWithMultipleSnapshotsBuilding(maxSnapshotCount = 6): Promise<string[]> {
    const runners = await this.sandboxRepository
      .createQueryBuilder('sandbox')
      .select('sandbox.runnerId', 'runnerId')
      .where('sandbox.state = :state', { state: SandboxState.BUILDING_SNAPSHOT })
      .andWhere('sandbox.buildInfoSnapshotRef IS NOT NULL')
      .groupBy('sandbox.runnerId')
      .having('COUNT(DISTINCT sandbox.buildInfoSnapshotRef) > :maxSnapshotCount', { maxSnapshotCount })
      .getRawMany()

    return runners.map((item) => item.runnerId)
  }

  async getRunnersWithMultipleSnapshotsPulling(maxSnapshotCount = 6): Promise<string[]> {
    const runners = await this.snapshotRunnerRepository
      .createQueryBuilder('snapshot_runner')
      .select('snapshot_runner.runnerId')
      .where('snapshot_runner.state = :state', { state: SnapshotRunnerState.PULLING_SNAPSHOT })
      .groupBy('snapshot_runner.runnerId')
      .having('COUNT(*) > :maxSnapshotCount', { maxSnapshotCount })
      .getRawMany()

    return runners.map((item) => item.runnerId)
  }

  /**
   * Returns the IDs of runners where placing one more sandbox (with the
   * `requested` resources) for `buildInfoSnapshotRef` would exceed any of the
   * configured per-runner limits for that build:
   *
   *  - `maxCpuUtilization`: fraction (0-1) of the runner's *actual* CPU
   *    capacity (`runner.cpu`) the build's sandboxes may occupy.
   *  - `maxMemUtilization`: fraction (0-1) of the runner's *actual* memory
   *    (`runner.memoryGiB`) the build's sandboxes may occupy.
   *  - `maxSandboxCount`: absolute cap on the number of the build's sandboxes
   *    on a single runner.
   *
   * Scaling CPU/memory to each runner's real capacity (instead of a fixed
   * value) lets larger runners host more of the same build. A runner is
   * returned if it violates ANY enabled limit; limits <= 0 are skipped.
   */
  async getRunnersOverBuildInfoSnapshotRefLimits(
    buildInfoSnapshotRef: string,
    limits: { maxCpuUtilization?: number; maxMemUtilization?: number; maxSandboxCount?: number },
    requested: { cpu?: number; mem?: number } = {},
  ): Promise<string[]> {
    if (!buildInfoSnapshotRef) {
      return []
    }
    return this.getRunnersOverLimits({ buildInfoSnapshotRef }, limits, requested)
  }

  /**
   * Runners where placing one more sandbox with `requested` resources would
   * exceed the configured fraction of the runner's registered CPU or memory,
   * counting every active sandbox on the runner regardless of snapshot. The
   * build-info limit above is this same query scoped to one snapshot.
   */
  async getRunnersOverReservationLimits(
    limits: { maxCpuUtilization?: number; maxMemUtilization?: number },
    requested: { cpu?: number; mem?: number } = {},
  ): Promise<string[]> {
    return this.getRunnersOverLimits({}, limits, requested)
  }

  /**
   * Per-runner reservation view for operators and the runner scaler: the
   * registered capacity next to what active sandboxes currently reserve.
   */
  async getRunnerCapacity(): Promise<RunnerCapacity[]> {
    const runners = await this.runnerRepository.find({ order: { domain: 'ASC' } })
    const rows: { runnerId: string; cpu: string; mem: string; count: string }[] = await this.sandboxRepository
      .createQueryBuilder('sandbox')
      .select('sandbox.runnerId', 'runnerId')
      .addSelect('COALESCE(SUM(sandbox.cpu), 0)', 'cpu')
      .addSelect('COALESCE(SUM(sandbox.mem), 0)', 'mem')
      .addSelect('COUNT(*)', 'count')
      .where('sandbox.runnerId IS NOT NULL')
      .andWhere('sandbox.state IN (:...states)', { states: RESERVING_SANDBOX_STATES })
      .groupBy('sandbox.runnerId')
      .getRawMany()
    const reserved = new Map(rows.map((row) => [row.runnerId, row]))
    return runners.map((runner) => {
      const row = reserved.get(runner.id)
      return {
        id: runner.id,
        domain: runner.domain,
        region: runner.region,
        sandboxClass: runner.sandboxClass,
        state: runner.state,
        unschedulable: runner.unschedulable === true,
        draining: runner.draining === true,
        availabilityScore: runner.availabilityScore,
        cpu: runner.cpu,
        memoryGiB: runner.memoryGiB,
        diskGiB: runner.diskGiB,
        reservedCpu: Number(row?.cpu ?? 0),
        reservedMemoryGiB: Number(row?.mem ?? 0),
        activeSandboxes: Number(row?.count ?? 0),
      }
    })
  }

  private async getRunnersOverLimits(
    scope: { buildInfoSnapshotRef?: string },
    limits: { maxCpuUtilization?: number; maxMemUtilization?: number; maxSandboxCount?: number },
    requested: { cpu?: number; mem?: number } = {},
  ): Promise<string[]> {
    const buildInfoSnapshotRef = scope.buildInfoSnapshotRef

    const havingClauses: string[] = []
    const params: Record<string, number> = {}
    const groupByColumns: string[] = []

    if (limits.maxCpuUtilization && limits.maxCpuUtilization > 0) {
      havingClauses.push('(runner.cpu > 0 AND SUM(sandbox.cpu) + :requestedCpu > runner.cpu * :maxCpuUtilization)')
      params.requestedCpu = Math.max(0, requested.cpu ?? 0)
      params.maxCpuUtilization = limits.maxCpuUtilization
      groupByColumns.push('runner.cpu')
    }

    if (limits.maxMemUtilization && limits.maxMemUtilization > 0) {
      havingClauses.push(
        '(runner.memoryGiB > 0 AND SUM(sandbox.mem) + :requestedMem > runner.memoryGiB * :maxMemUtilization)',
      )
      params.requestedMem = Math.max(0, requested.mem ?? 0)
      params.maxMemUtilization = limits.maxMemUtilization
      groupByColumns.push('runner.memoryGiB')
    }

    if (limits.maxSandboxCount && limits.maxSandboxCount > 0) {
      // +1 accounts for the sandbox about to be placed.
      havingClauses.push('COUNT(*) + 1 > :maxSandboxCount')
      params.maxSandboxCount = limits.maxSandboxCount
    }

    if (havingClauses.length === 0) {
      return []
    }

    const activeStates: SandboxState[] = RESERVING_SANDBOX_STATES

    const query = this.sandboxRepository
      .createQueryBuilder('sandbox')
      .select('sandbox.runnerId', 'runnerId')
      .where('sandbox.runnerId IS NOT NULL')
      .andWhere('sandbox.state IN (:...states)', { states: activeStates })
    if (buildInfoSnapshotRef) {
      query.andWhere('sandbox.buildInfoSnapshotRef = :ref', { ref: buildInfoSnapshotRef })
    }
    query.groupBy('sandbox.runnerId').having(havingClauses.join(' OR '), params)

    // The Runner join is only needed to read the runner's real CPU/memory
    // capacity; a count-only check never touches it.
    if (groupByColumns.length > 0) {
      query.innerJoin(Runner, 'runner', 'runner.id = sandbox.runnerId')
      for (const column of groupByColumns) {
        query.addGroupBy(column)
      }
    }

    const runners = await query.getRawMany()

    return runners.map((item) => item.runnerId).filter((id): id is string => !!id)
  }

  /**
   * Returns runner IDs that have reached their GPU sandbox capacity. A runner
   * with `runner.gpu = N` can host up to N concurrent GPU sandboxes; this
   * method returns runners where the count of GPU sandboxes is `>= N`.
   *
   * Every GPU sandbox in any state other than DESTROYED / ARCHIVED /
   * BUILD_FAILED counts toward capacity - including STOPPED, ERROR, RESIZING,
   * SNAPSHOTTING, etc. - because the GPU index is pinned into the container's
   * HostConfig.DeviceRequests at create time and survives any subsequent
   * restart, so the physical card stays reserved for that sandbox until it
   * is fully destroyed.
   *
   * ARCHIVED is excluded together with DESTROYED: GPU sandboxes are forced
   * ephemeral (see SandboxService) so they cannot legitimately reach the
   * archived state, but if one ever does (legacy data, manual bypass) the
   * container is no longer on the runner and the card is effectively free.
   *
   * BUILD_FAILED is excluded because the build failed before a GPU container
   * was created on the runner, so no physical card is reserved.
   *
   * Runners with `runner.gpu = -1` are treated as having infinite GPU capacity
   * and are never considered at capacity. The `runner.gpu > 0` predicate below
   * already excludes them, so they can host unlimited GPU sandboxes.
   */
  async getRunnersAtGpuCapacity(): Promise<string[]> {
    const rows = await this.sandboxRepository
      .createQueryBuilder('sandbox')
      .innerJoin(Runner, 'runner', 'runner.id = sandbox.runnerId')
      .select('sandbox.runnerId', 'runnerId')
      .where('sandbox.runnerId IS NOT NULL')
      .andWhere('sandbox.gpu > 0')
      .andWhere('runner.gpu IS NOT NULL AND runner.gpu > 0')
      .andWhere('sandbox.state NOT IN (:...freeStates)', {
        freeStates: [SandboxState.DESTROYED, SandboxState.ARCHIVED, SandboxState.BUILD_FAILED],
      })
      .groupBy('sandbox.runnerId')
      .addGroupBy('runner.gpu')
      .having('COUNT(*) >= runner.gpu')
      .getRawMany()

    return rows.map((r) => r.runnerId).filter((id): id is string => !!id)
  }

  async getRunnersBySnapshotRef(ref: string): Promise<RunnerSnapshotDto[]> {
    const snapshotRunners = await this.snapshotRunnerRepository.find({
      where: {
        snapshotRef: ref,
        state: Not(SnapshotRunnerState.ERROR),
      },
      select: ['runnerId', 'id'],
    })

    // Extract distinct runnerIds from snapshot runners
    const runnerIds = [...new Set(snapshotRunners.map((sr) => sr.runnerId))]

    // Find all runners with these IDs
    const runners = await this.runnerRepository.find({
      where: { id: In(runnerIds) },
      select: ['id', 'domain'],
    })

    this.logger.debug(`Found ${runners.length} runners with IDs: ${runners.map((r) => r.id).join(', ')}`)

    // Map to DTO format, including the snapshot runner ID
    return runners.map((runner) => {
      const snapshotRunner = snapshotRunners.find((sr) => sr.runnerId === runner.id)
      return new RunnerSnapshotDto(snapshotRunner.id, runner.id, runner.domain)
    })
  }

  async getInitialRunnerBySnapshotId(snapshotId: string): Promise<Runner> {
    const snapshot = await this.snapshotRepository.findOne({ where: { id: snapshotId } })
    if (!snapshot) {
      throw new NotFoundException('Snapshot runner not found')
    }
    if (!snapshot.initialRunnerId) {
      throw new BadRequestException('Initial runner not found')
    }

    return await this.findOneOrFail(snapshot.initialRunnerId)
  }

  async getRunnerApiVersion(runnerId: string): Promise<string> {
    const result = await this.runnerRepository.findOneOrFail({
      select: ['apiVersion'],
      where: { id: runnerId },
      cache: {
        id: `runner:apiVersion:${runnerId}`,
        milliseconds: 60 * 60 * 1000, // Cache for 1 hour
      },
    })

    return result.apiVersion
  }

  private async updateRunner(
    id: string,
    data: Partial<Omit<Runner, 'id' | 'createdAt' | 'updatedAt'>>,
  ): Promise<UpdateResult> {
    const result = await this.runnerRepository.update(id, data)
    this.invalidateRunnerCache(id)
    return result
  }

  private invalidateRunnerCache(runnerId: string): void {
    const cache = this.dataSource.queryResultCache
    if (!cache) {
      return
    }

    cache
      .remove([runnerLookupCacheKeyById(runnerId)])
      .then(() => this.logger.debug(`Invalidated runner lookup cache for ${runnerId}`))
      .catch((error) =>
        this.logger.warn(
          `Failed to invalidate runner lookup cache for ${runnerId}: ${error instanceof Error ? error.message : String(error)}`,
        ),
      )
  }

  private calculateAvailabilityScore(runnerId: string, params: AvailabilityScoreParams): number {
    if (
      params.cpuLoadAverage < 0 ||
      params.cpuUsage < 0 ||
      params.memoryUsage < 0 ||
      params.diskUsage < 0 ||
      params.allocatedCpu < 0 ||
      params.allocatedMemoryGiB < 0 ||
      params.allocatedDiskGiB < 0 ||
      params.startedSandboxes < 0
    ) {
      this.logger.warn(
        `Runner ${runnerId} has negative values for load, CPU, memory, disk, allocated CPU, allocated memory, allocated disk, or started sandboxes`,
      )
      return 0
    }

    return this.calculateTOPSISScore(params)
  }

  private calculateTOPSISScore(params: AvailabilityScoreParams): number {
    const current = [
      params.cpuUsage,
      params.memoryUsage,
      params.diskUsage,
      // Allocation ratios percentage
      (params.allocatedCpu / params.runnerCpu) * 100,
      (params.allocatedMemoryGiB / params.runnerMemoryGiB) * 100,
      (params.allocatedDiskGiB / params.runnerDiskGiB) * 100,
      params.startedSandboxes, // Raw count, will be normalized against its critical target value
    ]

    // Calculate weighted Euclidean distances
    let distanceToOptimal = 0
    let distanceToCritical = 0

    for (let i = 0; i < current.length; i++) {
      // Normalize to 0-1 scale
      const normalizedCurrent = current[i] / 100
      const normalizedOptimal = this.scoreConfig.targetValues.optimal[i] / 100
      const normalizedCritical = this.scoreConfig.targetValues.critical[i] / 100

      distanceToOptimal += this.scoreConfig.weights[i] * Math.pow(normalizedCurrent - normalizedOptimal, 2)
      distanceToCritical += this.scoreConfig.weights[i] * Math.pow(normalizedCurrent - normalizedCritical, 2)
    }

    distanceToOptimal = Math.sqrt(distanceToOptimal)
    distanceToCritical = Math.sqrt(distanceToCritical)

    // TOPSIS relative closeness score (0 to 1)
    let topsisScore = distanceToCritical / (distanceToOptimal + distanceToCritical)

    // Apply exponential penalties for critical thresholds
    let penaltyMultiplier = 1

    if (params.cpuUsage >= this.scoreConfig.penalty.thresholds.cpu) {
      penaltyMultiplier *= Math.exp(
        -this.scoreConfig.penalty.exponents.cpu * (params.cpuUsage - this.scoreConfig.penalty.thresholds.cpu),
      )
    }

    if (params.cpuLoadAverage >= this.scoreConfig.penalty.thresholds.cpuLoadAvg) {
      penaltyMultiplier *= Math.exp(
        -this.scoreConfig.penalty.exponents.cpuLoadAvg *
          (params.cpuLoadAverage - this.scoreConfig.penalty.thresholds.cpuLoadAvg),
      )
    }

    if (params.memoryUsage >= this.scoreConfig.penalty.thresholds.memory) {
      penaltyMultiplier *= Math.exp(
        -this.scoreConfig.penalty.exponents.memory * (params.memoryUsage - this.scoreConfig.penalty.thresholds.memory),
      )
    }

    if (params.diskUsage >= this.scoreConfig.penalty.thresholds.disk) {
      penaltyMultiplier *= Math.exp(
        -this.scoreConfig.penalty.exponents.disk * (params.diskUsage - this.scoreConfig.penalty.thresholds.disk),
      )
    }

    // Apply penalty
    topsisScore *= penaltyMultiplier

    return Math.round(topsisScore * 100)
  }

  private getAvailabilityScoreConfig(): AvailabilityScoreConfig {
    return {
      availabilityThreshold: this.configService.getOrThrow('runnerScore.thresholds.availability'),
      weights: [
        this.configService.getOrThrow('runnerScore.weights.cpuUsage'),
        this.configService.getOrThrow('runnerScore.weights.memoryUsage'),
        this.configService.getOrThrow('runnerScore.weights.diskUsage'),
        this.configService.getOrThrow('runnerScore.weights.allocatedCpu'),
        this.configService.getOrThrow('runnerScore.weights.allocatedMemory'),
        this.configService.getOrThrow('runnerScore.weights.allocatedDisk'),
        this.configService.getOrThrow('runnerScore.weights.startedSandboxes'),
      ],
      penalty: {
        exponents: {
          cpu: this.configService.getOrThrow('runnerScore.penalty.exponents.cpu'),
          cpuLoadAvg: this.configService.getOrThrow('runnerScore.penalty.exponents.cpuLoadAvg'),
          memory: this.configService.getOrThrow('runnerScore.penalty.exponents.memory'),
          disk: this.configService.getOrThrow('runnerScore.penalty.exponents.disk'),
        },
        thresholds: {
          cpu: this.configService.getOrThrow('runnerScore.penalty.thresholds.cpu'),
          cpuLoadAvg: this.configService.getOrThrow('runnerScore.penalty.thresholds.cpuLoadAvg'),
          memory: this.configService.getOrThrow('runnerScore.penalty.thresholds.memory'),
          disk: this.configService.getOrThrow('runnerScore.penalty.thresholds.disk'),
        },
      },
      targetValues: {
        optimal: [
          this.configService.getOrThrow('runnerScore.targetValues.optimal.cpu'),
          this.configService.getOrThrow('runnerScore.targetValues.optimal.memory'),
          this.configService.getOrThrow('runnerScore.targetValues.optimal.disk'),
          this.configService.getOrThrow('runnerScore.targetValues.optimal.allocCpu'),
          this.configService.getOrThrow('runnerScore.targetValues.optimal.allocMem'),
          this.configService.getOrThrow('runnerScore.targetValues.optimal.allocDisk'),
          this.configService.getOrThrow('runnerScore.targetValues.optimal.startedSandboxes'),
        ],
        critical: [
          this.configService.getOrThrow('runnerScore.targetValues.critical.cpu'),
          this.configService.getOrThrow('runnerScore.targetValues.critical.memory'),
          this.configService.getOrThrow('runnerScore.targetValues.critical.disk'),
          this.configService.getOrThrow('runnerScore.targetValues.critical.allocCpu'),
          this.configService.getOrThrow('runnerScore.targetValues.critical.allocMem'),
          this.configService.getOrThrow('runnerScore.targetValues.critical.allocDisk'),
          this.configService.getOrThrow('runnerScore.targetValues.critical.startedSandboxes'),
        ],
      },
    }
  }
}

/** Sandbox states that hold runner CPU/memory, for reservation accounting. */
export const RESERVING_SANDBOX_STATES: SandboxState[] = [
  SandboxState.CREATING,
  SandboxState.RESTORING,
  SandboxState.STARTED,
  SandboxState.STARTING,
  SandboxState.STOPPING,
  SandboxState.BUILDING_SNAPSHOT,
  SandboxState.PULLING_SNAPSHOT,
  SandboxState.UNKNOWN,
  SandboxState.RESIZING,
  SandboxState.SNAPSHOTTING,
  SandboxState.FORKING,
]

export type RunnerCapacity = {
  id: string
  domain: string
  region: string
  sandboxClass: SandboxClass
  state: RunnerState
  unschedulable: boolean
  draining: boolean
  availabilityScore: number
  cpu: number
  memoryGiB: number | null
  diskGiB: number | null
  reservedCpu: number
  reservedMemoryGiB: number
  activeSandboxes: number
}

export class GetRunnerParams {
  regions: string[]
  sandboxClass: SandboxClass
  snapshotRef?: string
  excludedRunnerIds?: string[]
  availabilityScoreThreshold?: number
  /**
   * Resources the sandbox about to be placed will reserve. When the
   * runnerReservation limits are configured, runners whose active sandboxes
   * plus this request would exceed their registered capacity are excluded.
   */
  cpu?: number
  mem?: number
  // When > 0, only consider runners that have at least this much GPU capacity
  // and have not yet reached their GPU sandbox capacity (a runner with
  // runner.gpu = N can host up to N concurrent GPU sandboxes).
  gpu: number
  /**
   * GPU type filter. Three forms accepted:
   *  - `null` → no GPU type filter
   *  - single `GpuType` → exact match (honored by `findAvailableRunners`)
   *  - `GpuType[]` ordered preference list → only honored by `getRandomAvailableRunner`,
   *    which iterates and returns a runner matching the first type with capacity.
   */
  gpuType: GpuType | GpuType[] | null
}

interface AvailabilityScoreParams {
  cpuLoadAverage: number
  cpuUsage: number
  memoryUsage: number
  diskUsage: number
  allocatedCpu: number
  allocatedMemoryGiB: number
  allocatedDiskGiB: number
  startedSandboxes: number
  runnerCpu: number
  runnerMemoryGiB: number
  runnerDiskGiB: number
}

interface AvailabilityScoreConfig {
  availabilityThreshold: number
  weights: number[]
  penalty: {
    exponents: {
      cpu: number
      cpuLoadAvg: number
      memory: number
      disk: number
    }
    thresholds: {
      cpu: number
      cpuLoadAvg: number
      memory: number
      disk: number
    }
  }
  targetValues: {
    optimal: number[]
    critical: number[]
  }
}
