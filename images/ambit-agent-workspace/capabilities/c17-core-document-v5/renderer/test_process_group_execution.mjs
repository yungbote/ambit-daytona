import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { executeBoundedProcessGroup } from './process-group-execution.mjs'

const SUBREAPER = fileURLToPath(
  new URL('./libreoffice-subreaper.py', import.meta.url),
)

test('returns bounded output only after a naturally empty process group', async () => {
  const result = await executeBoundedProcessGroup({
    executable: '/bin/sh',
    arguments: ['-c', 'printf exact-output'],
    cwd: '/tmp',
    env: { LANG: 'C' },
    maximumWallMilliseconds: 2_000,
    maximumOutputBytes: 1024,
  })
  assert.equal(result.stdout.toString(), 'exact-output')
  assert.equal(result.stderr.byteLength, 0)
})

test('kills and reaps the whole process group on timeout', async () => {
  await assert.rejects(
    executeBoundedProcessGroup({
      executable: '/bin/sh',
      arguments: ['-c', 'sleep 30 & wait'],
      cwd: '/tmp',
      env: { PATH: '/usr/bin:/bin' },
      maximumWallMilliseconds: 50,
      maximumOutputBytes: 1024,
    }),
    /wall-time policy/,
  )
})

test('kills and reaps the whole process group on cancellation', async () => {
  const controller = new AbortController()
  const running = executeBoundedProcessGroup({
    executable: '/bin/sh',
    arguments: ['-c', 'sleep 30 & wait'],
    cwd: '/tmp',
    env: { PATH: '/usr/bin:/bin' },
    maximumWallMilliseconds: 5_000,
    maximumOutputBytes: 1024,
    signal: controller.signal,
  })
  controller.abort(new Error('test cancellation'))
  await assert.rejects(running, /test cancellation/)
})

test('kills and reaps the whole process group on output overflow', async () => {
  await assert.rejects(
    executeBoundedProcessGroup({
      executable: '/bin/sh',
      arguments: ['-c', 'while :; do printf 0123456789; done'],
      cwd: '/tmp',
      env: { PATH: '/usr/bin:/bin' },
      maximumWallMilliseconds: 5_000,
      maximumOutputBytes: 128,
    }),
    /output exceeded/,
  )
})

test('subreaper retains and reaps descendants after their leader exits', async () => {
  const result = await executeBoundedProcessGroup({
    executable: '/usr/bin/python3',
    arguments: [
      SUBREAPER,
      '/bin/sh',
      '-c',
      'sleep 0.05 & printf leader-exited',
    ],
    cwd: '/tmp',
    env: { PATH: '/usr/bin:/bin' },
    maximumWallMilliseconds: 2_000,
    maximumOutputBytes: 1024,
  })
  assert.equal(result.stdout.toString(), 'leader-exited')
})
