/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { Injectable, Logger } from '@nestjs/common'
import {
  CreateSandboxSnapshotResult,
  RunnerAdapter,
  RunnerInfo,
  RunnerSandboxInfo,
  RunnerSnapshotInfo,
  runnerProviderAuthorityMetadata,
  StartSandboxResponse,
  SnapshotDigestResponse,
} from './runnerAdapter'
import { SnapshotStateError } from '../errors/snapshot-state-error'
import { Runner } from '../entities/runner.entity'
import {
  Configuration,
  SandboxApi,
  EnumsSandboxState,
  SnapshotsApi,
  EnumsBackupState,
  DefaultApi,
  CreateSandboxDTO,
  BuildSnapshotRequestDTO,
  CreateBackupDTO,
  PullSnapshotRequestDTO,
  ToolboxApi,
  UpdateNetworkSettingsDTO,
  UpdateSandboxSecretsDTO,
  RecoverSandboxDTO,
} from '@daytona/runner-api-client'
import { Sandbox } from '../entities/sandbox.entity'
import { BuildInfo } from '../entities/build-info.entity'
import { DockerRegistry } from '../../docker-registry/entities/docker-registry.entity'
import { stripRegistryScheme } from '../../common/utils/registry-url.util'
import { SandboxState } from '../enums/sandbox-state.enum'
import { SandboxClass } from '../enums/sandbox-class.enum'
import { BackupState } from '../enums/backup-state.enum'
import { RunnerApiError } from '../errors/runner-api-error'
import { createRunnerHttpClient } from './runner-http-client'
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

@Injectable()
export class RunnerAdapterV0 implements RunnerAdapter {
  private readonly logger = new Logger(RunnerAdapterV0.name)
  private sandboxApiClient: SandboxApi
  private snapshotApiClient: SnapshotsApi
  private runnerApiClient: DefaultApi
  private toolboxApiClient: ToolboxApi

  private convertSandboxState(state: EnumsSandboxState): SandboxState {
    switch (state) {
      case EnumsSandboxState.SandboxStateCreating:
        return SandboxState.CREATING
      case EnumsSandboxState.SandboxStateRestoring:
        return SandboxState.RESTORING
      case EnumsSandboxState.SandboxStateDestroyed:
        return SandboxState.DESTROYED
      case EnumsSandboxState.SandboxStateDestroying:
        return SandboxState.DESTROYING
      case EnumsSandboxState.SandboxStateStarted:
        return SandboxState.STARTED
      case EnumsSandboxState.SandboxStateStopped:
        return SandboxState.STOPPED
      case EnumsSandboxState.SandboxStateStarting:
        return SandboxState.STARTING
      case EnumsSandboxState.SandboxStateStopping:
        return SandboxState.STOPPING
      case EnumsSandboxState.SandboxStateError:
        return SandboxState.ERROR
      case EnumsSandboxState.SandboxStatePullingSnapshot:
        return SandboxState.PULLING_SNAPSHOT
      default:
        return SandboxState.UNKNOWN
    }
  }

  private convertBackupState(state: EnumsBackupState): BackupState {
    switch (state) {
      case EnumsBackupState.BackupStatePending:
        return BackupState.PENDING
      case EnumsBackupState.BackupStateInProgress:
        return BackupState.IN_PROGRESS
      case EnumsBackupState.BackupStateCompleted:
        return BackupState.COMPLETED
      case EnumsBackupState.BackupStateFailed:
        return BackupState.ERROR
      default:
        return BackupState.NONE
    }
  }

  public async init(runner: Runner): Promise<void> {
    if (!runner.apiUrl) {
      throw new Error('Runner API URL is required')
    }

    const axiosInstance = createRunnerHttpClient(runner, this.logger)

    this.sandboxApiClient = new SandboxApi(new Configuration(), '', axiosInstance)
    this.snapshotApiClient = new SnapshotsApi(new Configuration(), '', axiosInstance)
    this.runnerApiClient = new DefaultApi(new Configuration(), '', axiosInstance)
    this.toolboxApiClient = new ToolboxApi(new Configuration(), '', axiosInstance)
  }

  async healthCheck(signal?: AbortSignal): Promise<void> {
    const response = await this.runnerApiClient.healthCheck({ signal })
    if (response.data.status !== 'ok') {
      throw new Error('Runner is not healthy')
    }
  }

  async runnerInfo(signal?: AbortSignal): Promise<RunnerInfo> {
    const response = await this.runnerApiClient.runnerInfo({ signal })
    return {
      serviceHealth: response.data.serviceHealth,
      metrics: response.data.metrics,
      appVersion: response.data.appVersion,
    }
  }

  async captureWorkingCopy(
    sandboxId: string,
    binding: WorkingCopyCaptureBindingDto,
  ): Promise<WorkingCopyCaptureReceiptDto> {
    const response = await this.sandboxApiClient.captureWorkingCopy(sandboxId, binding)
    return response.data as WorkingCopyCaptureReceiptDto
  }

  async observeWorkingCopyCapture(
    sandboxId: string,
    binding: WorkingCopyCaptureBindingDto,
  ): Promise<WorkingCopyCaptureObservationDto> {
    const response = await this.sandboxApiClient.observeWorkingCopyCapture(sandboxId, binding)
    return response.data as WorkingCopyCaptureObservationDto
  }

  async readWorkingCopyCapture(
    sandboxId: string,
    request: WorkingCopyCaptureReadDto,
  ): Promise<WorkingCopyCaptureReadResponseDto> {
    const response = await this.sandboxApiClient.readWorkingCopyCapture(sandboxId, request)
    return response.data as WorkingCopyCaptureReadResponseDto
  }

  async deleteWorkingCopyCapture(
    sandboxId: string,
    identity: WorkingCopyCaptureIdentityDto,
  ): Promise<WorkingCopyCaptureDeleteReceiptDto> {
    const response = await this.sandboxApiClient.deleteWorkingCopyCapture(sandboxId, identity)
    return response.data as WorkingCopyCaptureDeleteReceiptDto
  }

  async workingCopyCaptureExists(
    sandboxId: string,
    identity: WorkingCopyCaptureIdentityDto,
  ): Promise<WorkingCopyCaptureExistsResponseDto> {
    const response = await this.sandboxApiClient.workingCopyCaptureExists(sandboxId, identity)
    return response.data as WorkingCopyCaptureExistsResponseDto
  }

  async stoppedWorkingCopyDirectoryRoster(
    sandboxId: string,
    request: StoppedWorkingCopyDirectoryRosterRequestDto,
    signal?: AbortSignal,
  ): Promise<StoppedWorkingCopyDirectoryRosterReceiptDto> {
    const response = await this.sandboxApiClient.stoppedWorkingCopyDirectoryRoster(sandboxId, request, { signal })
    return response.data as StoppedWorkingCopyDirectoryRosterReceiptDto
  }

  async observeSandboxGeneration(
    sandboxId: string,
    request: SandboxGenerationObservationRequestDto,
  ): Promise<SandboxGenerationObservationDto> {
    const response = await this.sandboxApiClient.observeSandboxGeneration(sandboxId, request)
    return response.data as SandboxGenerationObservationDto
  }

  async stopSandboxGenerationOnce(
    sandboxId: string,
    request: StopSandboxGenerationRequestDto,
  ): Promise<StoppedSandboxGenerationReceiptDto> {
    const response = await this.sandboxApiClient.stopSandboxGenerationOnce(sandboxId, request)
    return response.data as StoppedSandboxGenerationReceiptDto
  }

  async observeSandboxGenerationStop(
    sandboxId: string,
    request: StopSandboxGenerationRequestDto,
  ): Promise<SandboxGenerationStopObservationDto> {
    const response = await this.sandboxApiClient.observeSandboxGenerationStop(sandboxId, request)
    return response.data as SandboxGenerationStopObservationDto
  }

  async sandboxInfo(sandboxId: string): Promise<RunnerSandboxInfo> {
    const sandboxInfo = await this.sandboxApiClient.info(sandboxId)
    return {
      state: this.convertSandboxState(sandboxInfo.data.state),
      backupState: this.convertBackupState(sandboxInfo.data.backupState),
      backupSnapshot: sandboxInfo.data.backupSnapshot,
      backupErrorReason: sandboxInfo.data.backupError,
      recoverable: sandboxInfo.data.recoverable,
      daemonVersion: sandboxInfo.data.daemonVersion,
    }
  }

  async createSandbox(
    sandbox: Sandbox,
    snapshotRef: string,
    registry?: DockerRegistry,
    entrypoint?: string[],
    metadata?: { [key: string]: string },
    otelEndpoint?: string,
    skipStart?: boolean,
  ): Promise<StartSandboxResponse | undefined> {
    const createSandboxDto: CreateSandboxDTO = {
      id: sandbox.id,
      name: sandbox.name,
      userId: sandbox.organizationId,
      snapshot: snapshotRef,
      osUser: sandbox.osUser,
      cpuQuota: sandbox.cpu,
      gpuQuota: sandbox.gpu,
      memoryQuota: sandbox.mem,
      storageQuota: sandbox.disk,
      env: sandbox.env,
      registry: registry
        ? {
            project: registry.project,
            url: stripRegistryScheme(registry.url),
            username: registry.username,
            password: registry.password,
          }
        : undefined,
      entrypoint: entrypoint,
      volumes: sandbox.volumes?.map((volume) => ({
        volumeId: volume.volumeId,
        mountPath: volume.mountPath,
        subpath: volume.subpath,
      })),
      networkBlockAll: sandbox.networkBlockAll,
      networkAllowList: sandbox.networkAllowList,
      domainAllowList: sandbox.domainAllowList,
      metadata: runnerProviderAuthorityMetadata(sandbox, metadata),
      authToken: sandbox.authToken,
      secretsToken: sandbox.secretsToken ?? undefined,
      otelEndpoint,
      skipStart: skipStart,
      organizationId: sandbox.organizationId,
      regionId: sandbox.region,
      linkedSandboxId: sandbox.linkedSandboxId ?? undefined,
      sandboxClass: sandbox.sandboxClass,
    }

    const response = await this.sandboxApiClient.create(createSandboxDto)

    if (!response?.data?.daemonVersion) {
      return undefined
    }

    return {
      daemonVersion: response.data.daemonVersion,
    }
  }

  async startSandbox(
    sandboxId: string,
    authToken: string,
    secretsToken: string,
    metadata?: { [key: string]: string },
  ): Promise<StartSandboxResponse | undefined> {
    const response = await this.sandboxApiClient.start(sandboxId, authToken, secretsToken, metadata)

    if (!response?.data?.daemonVersion) {
      return undefined
    }

    return {
      daemonVersion: response.data.daemonVersion,
    }
  }

  async stopSandbox(sandboxId: string, force?: boolean): Promise<void> {
    await this.sandboxApiClient.stop(sandboxId, { force })
  }

  async destroySandbox(sandboxId: string): Promise<void> {
    await this.sandboxApiClient.destroy(sandboxId)
  }

  async createBackup(sandbox: Sandbox, backupSnapshotName: string, registry?: DockerRegistry): Promise<void> {
    const request: CreateBackupDTO = {
      snapshot: backupSnapshotName,
      registry: undefined,
    }

    if (registry) {
      request.registry = {
        project: registry.project,
        url: stripRegistryScheme(registry.url),
        username: registry.username,
        password: registry.password,
      }
    }

    await this.sandboxApiClient.createBackup(sandbox.id, request)
  }

  async buildSnapshot(
    buildInfo: BuildInfo,
    organizationId?: string,
    sourceRegistries?: DockerRegistry[],
    registry?: DockerRegistry,
    pushToInternalRegistry?: boolean,
  ): Promise<void> {
    const request: BuildSnapshotRequestDTO = {
      snapshot: buildInfo.snapshotRef,
      dockerfile: buildInfo.dockerfileContent,
      organizationId: organizationId,
      context: buildInfo.contextHashes,
      pushToInternalRegistry: pushToInternalRegistry,
    }

    if (sourceRegistries) {
      request.sourceRegistries = sourceRegistries.map((sourceRegistry) => ({
        project: sourceRegistry.project,
        url: stripRegistryScheme(sourceRegistry.url),
        username: sourceRegistry.username,
        password: sourceRegistry.password,
      }))
    }

    if (registry) {
      request.registry = {
        project: registry.project,
        url: stripRegistryScheme(registry.url),
        username: registry.username,
        password: registry.password,
      }
    }

    await this.snapshotApiClient.buildSnapshot(request)
  }

  async removeSnapshot(snapshotName: string): Promise<void> {
    await this.snapshotApiClient.removeSnapshot(snapshotName)
  }

  async pullSnapshot(
    snapshotName: string,
    registry?: DockerRegistry,
    destinationRegistry?: DockerRegistry,
    destinationRef?: string,
    newTag?: string,
    sandboxClass?: SandboxClass,
    diskGiB?: number,
  ): Promise<void> {
    const request: PullSnapshotRequestDTO = {
      snapshot: snapshotName,
      newTag,
      sandboxClass,
      diskGiB,
    }

    if (registry) {
      request.registry = {
        project: registry.project,
        url: stripRegistryScheme(registry.url),
        username: registry.username,
        password: registry.password,
      }
    }

    if (destinationRegistry) {
      request.destinationRegistry = {
        project: destinationRegistry.project,
        url: stripRegistryScheme(destinationRegistry.url),
        username: destinationRegistry.username,
        password: destinationRegistry.password,
      }
    }

    if (destinationRef) {
      request.destinationRef = destinationRef
    }

    await this.snapshotApiClient.pullSnapshot(request)
  }

  async snapshotExists(snapshotName: string): Promise<boolean> {
    const response = await this.snapshotApiClient.snapshotExists(snapshotName)
    return response.data.exists
  }

  async getSnapshotInfo(snapshotName: string): Promise<RunnerSnapshotInfo> {
    try {
      const response = await this.snapshotApiClient.getSnapshotInfo(snapshotName)

      return {
        name: response.data.name || '',
        sizeGB: response.data.sizeGB,
        entrypoint: response.data.entrypoint,
        cmd: response.data.cmd,
        hash: response.data.hash,
      }
    } catch (err) {
      if (err instanceof RunnerApiError && err.statusCode === 422) {
        throw new SnapshotStateError(err.message)
      }
      throw err
    }
  }

  async inspectSnapshotInRegistry(snapshotName: string, registry?: DockerRegistry): Promise<SnapshotDigestResponse> {
    const response = await this.snapshotApiClient.inspectSnapshotInRegistry({
      snapshot: snapshotName,
      registry: registry
        ? {
            project: registry.project,
            url: stripRegistryScheme(registry.url),
            username: registry.username,
            password: registry.password,
          }
        : undefined,
    })

    return {
      hash: response.data.hash,
      sizeGB: response.data.sizeGB,
    }
  }

  async updateNetworkSettings(
    sandboxId: string,
    networkBlockAll?: boolean,
    networkAllowList?: string,
    networkLimitEgress?: boolean,
    domainAllowList?: string,
  ): Promise<void> {
    const updateNetworkSettingsDto: UpdateNetworkSettingsDTO = {
      networkBlockAll: networkBlockAll,
      networkAllowList: networkAllowList,
      networkLimitEgress: networkLimitEgress,
      domainAllowList: domainAllowList,
    }

    await this.sandboxApiClient.updateNetworkSettings(sandboxId, updateNetworkSettingsDto)
  }

  async updateSandboxSecrets(sandboxId: string, secretEnvs: { [key: string]: string }): Promise<void> {
    const updateSandboxSecretsDto: UpdateSandboxSecretsDTO = {
      env: secretEnvs,
    }

    await this.sandboxApiClient.updateSandboxSecrets(sandboxId, updateSandboxSecretsDto)
  }

  async forkSandbox(_sourceSandboxId: string, _newSandboxId: string): Promise<void> {
    throw new Error('forkSandbox is not supported for V0 runners')
  }

  async pauseSandbox(_sandboxId: string): Promise<void> {
    throw new Error('pauseSandbox is not supported for V0 runners')
  }

  async createSnapshotFromSandbox(
    sandboxId: string,
    snapshotName: string,
    organizationId: string,
    registry?: DockerRegistry,
    _includeMemory?: boolean,
  ): Promise<CreateSandboxSnapshotResult> {
    if (!registry) {
      throw new Error('registry is required to snapshot a Docker sandbox')
    }

    const response = await this.sandboxApiClient.snapshotFromSandbox(sandboxId, {
      name: snapshotName,
      organizationId,
      registry: {
        project: registry.project,
        url: stripRegistryScheme(registry.url),
        username: registry.username,
        password: registry.password,
      },
    })

    const data = response.data
    if (!data?.name || !data?.hash) {
      throw new Error('runner returned invalid snapshot-from-sandbox response')
    }

    return {
      ref: data.name,
      hash: data.hash,
      sizeGB: data.sizeGB,
      entrypoint: data.entrypoint,
      cmd: data.cmd,
    }
  }

  // skipStart is a v2-only signal (carried in the job payload); v0's sync API has no equivalent.
  async recoverSandbox(sandbox: Sandbox, registry?: DockerRegistry, _skipStart?: boolean): Promise<void> {
    const recoverSandboxDTO: RecoverSandboxDTO = {
      userId: sandbox.organizationId,
      snapshot: sandbox.snapshot,
      osUser: sandbox.osUser,
      cpuQuota: sandbox.cpu,
      gpuQuota: sandbox.gpu,
      memoryQuota: sandbox.mem,
      storageQuota: sandbox.disk,
      env: sandbox.env,
      volumes: sandbox.volumes?.map((volume) => ({
        volumeId: volume.volumeId,
        mountPath: volume.mountPath,
        subpath: volume.subpath,
      })),
      networkBlockAll: sandbox.networkBlockAll,
      networkAllowList: sandbox.networkAllowList,
      domainAllowList: sandbox.domainAllowList,
      errorReason: sandbox.errorReason,
      backupErrorReason: sandbox.backupErrorReason,
      registry: registry
        ? {
            project: registry.project,
            url: stripRegistryScheme(registry.url),
            username: registry.username,
            password: registry.password,
          }
        : undefined,
    }
    await this.sandboxApiClient.recover(sandbox.id, recoverSandboxDTO)
  }

  async resizeSandbox(
    sandboxId: string,
    cpu?: number,
    memory?: number,
    disk?: number,
    registry?: DockerRegistry,
  ): Promise<void> {
    await this.sandboxApiClient.resize(sandboxId, {
      cpu,
      memory,
      disk,
      registry: registry
        ? {
            project: registry.project,
            url: stripRegistryScheme(registry.url),
            username: registry.username,
            password: registry.password,
          }
        : undefined,
    })
  }
}
