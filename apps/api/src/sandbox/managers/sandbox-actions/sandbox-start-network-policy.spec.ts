import { SandboxStartAction } from './sandbox-start.action'
import { Sandbox } from '../../entities/sandbox.entity'
import { SandboxState } from '../../enums/sandbox-state.enum'
import { BackupState } from '../../enums/backup-state.enum'
import { RunnerState } from '../../enums/runner-state.enum'
import { LockCode } from '../../common/redis-lock.provider'

describe('sandbox restart network policy', () => {
  it.each([SandboxState.STOPPED, SandboxState.ARCHIVED, SandboxState.PAUSED])(
    'reconstructs every saved network restriction for %s',
    async (state) => {
      for (const policy of [
        { blockAll: true, allowList: null },
        { blockAll: false, allowList: '192.0.2.0/24' },
        { blockAll: false, allowList: null },
      ]) {
        const startSandbox = jest.fn().mockResolvedValue(undefined)
        const lock = { getCode: () => 'same-lock' } as LockCode
        const save = jest.fn().mockResolvedValue(undefined)
        const action = new SandboxStartAction(
          { findOneOrFail: jest.fn().mockResolvedValue({ state: RunnerState.READY }) } as never,
          { create: jest.fn().mockResolvedValue({ startSandbox }) } as never,
          { save, update: save } as never,
          {} as never,
          {} as never,
          {
            findOne: jest.fn().mockResolvedValue({
              sandboxMetadata: { organizationId: 'org', limitNetworkEgress: 'true' },
            }),
          } as never,
          { get: () => 0 } as never,
          { getCode: jest.fn().mockResolvedValue(lock) } as never,
          {} as never,
          {} as never,
        )
        const sandbox = {
          id: 'sandbox',
          organizationId: 'org',
          runnerId: 'runner',
          state,
          pending: true,
          snapshot: 'retained-image',
          backupState: BackupState.NONE,
          authToken: 'task-token',
          secretsToken: null,
          networkBlockAll: policy.blockAll,
          networkAllowList: policy.allowList,
          domainAllowList: null,
          volumes: [],
          env: {},
        } as Sandbox
        await action.run(sandbox, lock)
        expect(startSandbox).toHaveBeenCalledTimes(1)
        expect(startSandbox).toHaveBeenCalledWith(
          'sandbox',
          'task-token',
          null,
          expect.objectContaining({
            networkBlockAll: String(policy.blockAll),
            networkAllowList: policy.allowList ?? '',
            domainAllowList: '',
            limitNetworkEgress: 'true',
          }),
        )
      }
    },
  )
})
