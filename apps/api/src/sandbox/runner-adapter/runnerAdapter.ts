/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { Injectable, Logger } from '@nestjs/common'
import { Runner } from '../entities/runner.entity'
import { ModuleRef } from '@nestjs/core'
import { RunnerAdapterV0 } from './runnerAdapter.v0'
import { RunnerAdapterV2 } from './runnerAdapter.v2'
import { BuildInfo } from '../entities/build-info.entity'
import { DockerRegistry } from '../../docker-registry/entities/docker-registry.entity'
import { Sandbox } from '../entities/sandbox.entity'
import { SandboxState } from '../enums/sandbox-state.enum'
import { SandboxClass } from '../enums/sandbox-class.enum'
import { BackupState } from '../enums/backup-state.enum'
import { RunnerServiceInfo } from '../common/runner-service-info'
import {
  WorkingCopyCaptureBindingDto,
  WorkingCopyCaptureDeleteReceiptDto,
  WorkingCopyCaptureExistsResponseDto,
  WorkingCopyCaptureIdentityDto,
  WorkingCopyCaptureObservationDto,
  WorkingCopyCaptureReadDto,
  WorkingCopyCaptureReadResponseDto,
  WorkingCopyCaptureReceiptDto,
  StoppedWorkingCopyDirectoryRosterRequestDto,
  StoppedWorkingCopyDirectoryRosterReceiptDto,
} from '../dto/working-copy-capture.dto'
import {
  SandboxGenerationObservationDto,
  SandboxGenerationObservationRequestDto,
  SandboxGenerationStopObservationDto,
  StopSandboxGenerationRequestDto,
  StoppedSandboxGenerationReceiptDto,
} from '../dto/sandbox-generation-stop.dto'

export interface RunnerSandboxInfo {
  state: SandboxState
  daemonVersion?: string
  backupState?: BackupState
  backupSnapshot?: string
  backupErrorReason?: string
  recoverable?: boolean
}

export interface RunnerSnapshotInfo {
  name: string
  sizeGB: number
  entrypoint: string[]
  cmd: string[]
  hash: string
}

export interface SnapshotDigestResponse {
  hash: string
  sizeGB: number
}

const RUNNER_AUTHORITY_METADATA_PREFIX = 'daytona.authority-label.'

/**
 * Projects the provider-neutral `ambit*` authority namespace into immutable
 * container labels at creation. The runner later observes those labels rather
 * than trusting a stop/capture request echo. Organization metadata cannot
 * inject this reserved transport prefix, while future Ambit authority fields
 * do not require another provider-specific DTO change.
 */
export function runnerProviderAuthorityMetadata(
  sandbox: Pick<Sandbox, 'labels'>,
  metadata?: Readonly<Record<string, string>>,
): Record<string, string> {
  const projected: Record<string, string> = {}
  for (const [key, value] of Object.entries(metadata ?? {})) {
    if (key.startsWith(RUNNER_AUTHORITY_METADATA_PREFIX)) {
      throw new Error('Sandbox metadata uses the reserved provider-authority namespace.')
    }
    projected[key] = value
  }
  for (const [key, value] of Object.entries(sandbox.labels ?? {})) {
    if (!/^ambit[A-Z][A-Za-z0-9]{0,127}$/.test(key)) continue
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      Buffer.byteLength(value, 'utf8') > 2048 ||
      value !== value.trim() ||
      [...value].some((character) => {
        const code = character.codePointAt(0) as number
        return code === 0 || code < 32 || code === 127
      })
    ) {
      throw new Error(`Sandbox authority label ${key} is not a bounded canonical string.`)
    }
    projected[`${RUNNER_AUTHORITY_METADATA_PREFIX}${key}`] = value
  }
  return projected
}

// Result returned when the runner finished a snapshot-from-sandbox operation
// synchronously (v0 path). v2 dispatches the work as an async job and returns
// `undefined`; the API job-state handler picks up the result later.
export interface CreateSandboxSnapshotResult {
  ref: string
  hash: string
  sizeGB?: number
  entrypoint?: string[]
  cmd?: string[]
}

export interface RunnerMetrics {
  currentAllocatedCpu?: number
  currentAllocatedDiskGiB?: number
  currentAllocatedMemoryGiB?: number
  currentCpuUsagePercentage?: number
  currentDiskUsagePercentage?: number
  currentMemoryUsagePercentage?: number
  currentSnapshotCount?: number
  currentStartedSandboxes?: number
}

export interface RunnerInfo {
  serviceHealth?: RunnerServiceInfo[]
  metrics?: RunnerMetrics
  appVersion?: string
}

export interface StartSandboxResponse {
  daemonVersion: string
}

export interface RunnerAdapter {
  init(runner: Runner): Promise<void>

  healthCheck(signal?: AbortSignal): Promise<void>

  runnerInfo(signal?: AbortSignal): Promise<RunnerInfo>

  sandboxInfo(sandboxId: string): Promise<RunnerSandboxInfo>
  createSandbox(
    sandbox: Sandbox,
    snapshotRef: string,
    registry?: DockerRegistry,
    entrypoint?: string[],
    metadata?: { [key: string]: string },
    otelEndpoint?: string,
    skipStart?: boolean,
  ): Promise<StartSandboxResponse | undefined>
  startSandbox(
    sandboxId: string,
    authToken: string,
    secretsToken: string | null,
    metadata?: { [key: string]: string },
    skipStart?: boolean,
  ): Promise<StartSandboxResponse | undefined>
  stopSandbox(sandboxId: string, force?: boolean): Promise<void>
  destroySandbox(sandboxId: string): Promise<void>
  createBackup(sandbox: Sandbox, backupSnapshotName: string, registry?: DockerRegistry): Promise<void>

  removeSnapshot(snapshotName: string): Promise<void>
  buildSnapshot(
    buildInfo: BuildInfo,
    organizationId?: string,
    sourceRegistries?: DockerRegistry[],
    registry?: DockerRegistry,
    pushToInternalRegistry?: boolean,
  ): Promise<void>
  pullSnapshot(
    snapshotName: string,
    registry?: DockerRegistry,
    destinationRegistry?: DockerRegistry,
    destinationRef?: string,
    newTag?: string,
    sandboxClass?: SandboxClass,
    diskGiB?: number,
  ): Promise<void>
  snapshotExists(snapshotRef: string): Promise<boolean>
  getSnapshotInfo(snapshotName: string): Promise<RunnerSnapshotInfo>
  inspectSnapshotInRegistry(snapshotName: string, registry?: DockerRegistry): Promise<SnapshotDigestResponse>

  updateNetworkSettings(
    sandboxId: string,
    networkBlockAll?: boolean,
    networkAllowList?: string,
    networkLimitEgress?: boolean,
    domainAllowList?: string,
  ): Promise<void>

  /**
   * Pushes the sandbox's full desired secret env (env var name -> placeholder) to the
   * runner so a running sandbox's daemon can expose it to newly spawned processes.
   * Placeholders absent from the map are unset. Replace semantics, idempotent.
   */
  updateSandboxSecrets(sandboxId: string, secretEnvs: { [key: string]: string }): Promise<void>

  forkSandbox(sourceSandboxId: string, newSandboxId: string): Promise<void>

  pauseSandbox(sandboxId: string): Promise<void>

  createSnapshotFromSandbox(
    sandboxId: string,
    snapshotName: string,
    organizationId: string,
    registry?: DockerRegistry,
    includeMemory?: boolean,
  ): Promise<CreateSandboxSnapshotResult | undefined>

  recoverSandbox(sandbox: Sandbox, registry?: DockerRegistry, skipStart?: boolean): Promise<void>

  resizeSandbox(
    sandboxId: string,
    cpu?: number,
    memory?: number,
    disk?: number,
    registry?: DockerRegistry,
  ): Promise<void>

  captureWorkingCopy(sandboxId: string, binding: WorkingCopyCaptureBindingDto): Promise<WorkingCopyCaptureReceiptDto>
  observeWorkingCopyCapture(
    sandboxId: string,
    binding: WorkingCopyCaptureBindingDto,
  ): Promise<WorkingCopyCaptureObservationDto>
  readWorkingCopyCapture(
    sandboxId: string,
    request: WorkingCopyCaptureReadDto,
  ): Promise<WorkingCopyCaptureReadResponseDto>
  deleteWorkingCopyCapture(
    sandboxId: string,
    identity: WorkingCopyCaptureIdentityDto,
  ): Promise<WorkingCopyCaptureDeleteReceiptDto>
  workingCopyCaptureExists(
    sandboxId: string,
    identity: WorkingCopyCaptureIdentityDto,
  ): Promise<WorkingCopyCaptureExistsResponseDto>
  stoppedWorkingCopyDirectoryRoster(
    sandboxId: string,
    request: StoppedWorkingCopyDirectoryRosterRequestDto,
  ): Promise<StoppedWorkingCopyDirectoryRosterReceiptDto>

  observeSandboxGeneration(
    sandboxId: string,
    request: SandboxGenerationObservationRequestDto,
  ): Promise<SandboxGenerationObservationDto>
  stopSandboxGenerationOnce(
    sandboxId: string,
    request: StopSandboxGenerationRequestDto,
  ): Promise<StoppedSandboxGenerationReceiptDto>
  observeSandboxGenerationStop(
    sandboxId: string,
    request: StopSandboxGenerationRequestDto,
  ): Promise<SandboxGenerationStopObservationDto>
}

@Injectable()
export class RunnerAdapterFactory {
  private readonly logger = new Logger(RunnerAdapterFactory.name)

  constructor(private moduleRef: ModuleRef) {}

  async create(runner: Runner): Promise<RunnerAdapter> {
    switch (runner.apiVersion) {
      case '0': {
        const adapter = await this.moduleRef.create(RunnerAdapterV0)
        await adapter.init(runner)
        return adapter
      }
      case '2': {
        const adapter = await this.moduleRef.create(RunnerAdapterV2)
        await adapter.init(runner)
        return adapter
      }
      default:
        throw new Error(`Unsupported runner version: ${runner.apiVersion}`)
    }
  }
}
