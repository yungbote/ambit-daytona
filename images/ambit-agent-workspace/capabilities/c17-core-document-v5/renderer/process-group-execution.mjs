import { spawn } from 'node:child_process'
import { setTimeout as delay } from 'node:timers/promises'

const NATURAL_QUIESCENCE_MILLISECONDS = 500
const FORCED_QUIESCENCE_MILLISECONDS = 2_000

function positiveSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer.`)
  }
  return value
}

function processGroupExists(processGroupId) {
  try {
    process.kill(-processGroupId, 0)
    return true
  } catch (error) {
    if (error?.code === 'ESRCH') return false
    if (error?.code === 'EPERM') return true
    throw error
  }
}

function signalProcessGroup(processGroupId, signal) {
  try {
    process.kill(-processGroupId, signal)
  } catch (error) {
    if (error?.code !== 'ESRCH') throw error
  }
}

async function waitForProcessGroupExit(processGroupId, milliseconds) {
  const deadline = Date.now() + milliseconds
  while (processGroupExists(processGroupId)) {
    if (Date.now() >= deadline) return false
    await delay(10)
  }
  return true
}

function appendBounded(chunks, chunk, state) {
  const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
  state.bytes += bytes.byteLength
  if (state.bytes > state.maximumBytes) {
    return false
  }
  chunks.push(bytes)
  return true
}

function safeFailureSummary(bytes) {
  return bytes
    .subarray(0, 1024)
    .toString('utf8')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu, '?')
    .trim()
}

export async function executeBoundedProcessGroup({
  executable,
  arguments: arguments_,
  cwd,
  env,
  maximumWallMilliseconds,
  maximumStdoutBytes,
  maximumStderrBytes,
  signal,
  spawnProcess = spawn,
}) {
  if (
    typeof executable !== 'string' ||
    !executable.startsWith('/') ||
    !Array.isArray(arguments_) ||
    arguments_.some((value) => typeof value !== 'string') ||
    typeof cwd !== 'string' ||
    !cwd.startsWith('/') ||
    env === null ||
    typeof env !== 'object' ||
    Array.isArray(env) ||
    typeof spawnProcess !== 'function'
  ) {
    throw new TypeError('Bounded process-group execution input is invalid.')
  }
  const wallMilliseconds = positiveSafeInteger(
    maximumWallMilliseconds,
    'Process maximum wall milliseconds',
  )
  const stdoutLimit = positiveSafeInteger(
    maximumStdoutBytes,
    'Process maximum stdout bytes',
  )
  const stderrLimit = positiveSafeInteger(
    maximumStderrBytes,
    'Process maximum stderr bytes',
  )
  if (signal?.aborted) throw signal.reason

  const child = spawnProcess(executable, arguments_, {
    cwd,
    env,
    detached: true,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  })
  if (!Number.isSafeInteger(child.pid) || child.pid <= 0) {
    throw new TypeError('Bounded child process has no exact process-group ID.')
  }
  const processGroupId = child.pid
  const stdout = []
  const stderr = []
  const stdoutState = { bytes: 0, maximumBytes: stdoutLimit }
  const stderrState = { bytes: 0, maximumBytes: stderrLimit }
  let terminalReason = null
  let spawnError = null
  let forcedKillTimer = null

  const terminate = (reason) => {
    if (terminalReason === null) terminalReason = reason
    signalProcessGroup(processGroupId, 'SIGTERM')
    if (forcedKillTimer === null) {
      forcedKillTimer = setTimeout(
        () => signalProcessGroup(processGroupId, 'SIGKILL'),
        500,
      )
      forcedKillTimer.unref?.()
    }
  }
  const onAbort = () =>
    terminate(signal.reason ?? new Error('Process execution was aborted.'))
  signal?.addEventListener('abort', onAbort, { once: true })
  const timer = setTimeout(
    () => terminate(new Error('Process execution exceeded its wall-time policy.')),
    wallMilliseconds,
  )
  timer.unref?.()

  child.stdout?.on('data', (chunk) => {
    if (!appendBounded(stdout, chunk, stdoutState)) {
      terminate(new Error('Process stdout exceeded its byte policy.'))
    }
  })
  child.stderr?.on('data', (chunk) => {
    if (!appendBounded(stderr, chunk, stderrState)) {
      terminate(new Error('Process stderr exceeded its byte policy.'))
    }
  })
  child.once('error', (error) => {
    spawnError = error
    terminate(error)
  })

  let close
  try {
    close = await new Promise((resolve) => {
      child.once('close', (code, childSignal) =>
        resolve({ code, signal: childSignal }),
      )
    })
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', onAbort)
  }

  let naturallyQuiescent = await waitForProcessGroupExit(
    processGroupId,
    NATURAL_QUIESCENCE_MILLISECONDS,
  )
  if (!naturallyQuiescent) {
    signalProcessGroup(processGroupId, 'SIGKILL')
    const forced = await waitForProcessGroupExit(
      processGroupId,
      FORCED_QUIESCENCE_MILLISECONDS,
    )
    if (!forced) {
      throw new Error('Child process group remained populated after SIGKILL.')
    }
  }
  if (forcedKillTimer !== null) clearTimeout(forcedKillTimer)
  if (terminalReason) throw terminalReason
  if (spawnError) throw spawnError
  if (!naturallyQuiescent) {
    throw new Error('Child process group outlived its successful leader.')
  }
  const stdoutBytes = Buffer.concat(stdout)
  const stderrBytes = Buffer.concat(stderr)
  if (close.code !== 0 || close.signal !== null) {
    const summary = safeFailureSummary(Buffer.concat([stderrBytes, stdoutBytes]))
    throw new Error(
      `Child process failed with code=${close.code} signal=${close.signal}` +
        (summary ? `: ${summary}` : '.'),
    )
  }
  return Object.freeze({ stdout: stdoutBytes, stderr: stderrBytes })
}
