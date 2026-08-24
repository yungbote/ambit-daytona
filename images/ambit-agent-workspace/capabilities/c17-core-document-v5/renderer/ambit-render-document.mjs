#!/opt/ambit/runtime-pack/core-document-v5/bin/node

import { createHash } from 'node:crypto'
import {
  constants as fsConstants,
  readFileSync,
  realpathSync,
} from 'node:fs'
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rm,
  unlink,
} from 'node:fs/promises'
import { isAbsolute, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import {
  admitEmptyOutputDirectory,
  loadRenderPolicy,
  readRegularNoFollow,
  reproveOutputDirectory,
} from './ambit-render-pages.mjs'
import { admitDocxPackage } from './docx-package-admission.mjs'
import {
  canonicalFrameLine,
  createPayloadChunkFrame,
  digestBytes,
  FramedJsonlLineReader,
  FRAMED_JSONL_SCHEMA,
  payloadChunkCount,
  RAW_CHUNK_BYTES,
  readRenderRequest,
  RenderControlAdmissionClosed,
  RenderProtocolCancellation,
  watchRenderCancellation,
} from './framed-jsonl-protocol.mjs'
import { executeBoundedProcessGroup } from './process-group-execution.mjs'
import { inspectRenderOutput } from './render-output-verification.mjs'
import { canonicalJson } from './render-contracts.mjs'
import { CORE_DOCUMENT_V5_PACK_ROOT } from './pdfjs-page-renderer.mjs'
import { RenderTerminalArbiter } from './render-terminal-arbiter.mjs'

const STRUCTURAL_PYTHON_PATH = join(
  CORE_DOCUMENT_V5_PACK_ROOT,
  'bin/ambit-structural-python',
)
const LIBREOFFICE_SUBREAPER_PATH = join(
  CORE_DOCUMENT_V5_PACK_ROOT,
  'renderer/process-group-subreaper.py',
)
const LIBREOFFICE_PATH = '/usr/bin/libreoffice'
const NODE_PATH = join(CORE_DOCUMENT_V5_PACK_ROOT, 'bin/node')
const PAGE_RENDERER_PATH = join(
  CORE_DOCUMENT_V5_PACK_ROOT,
  'renderer/ambit-render-pages.mjs',
)
const INTERFACE_LOCK_PATH = join(
  CORE_DOCUMENT_V5_PACK_ROOT,
  'locks/document-render-interface.lock.json',
)
const DEFAULT_WORKSPACE_ROOT = '/workspace'
const DEFAULT_CACHE_ROOT = '/tmp'
const MAXIMUM_INTERFACE_LOCK_BYTES = 1024 * 1024
const CANCELLATION_EXIT_CODE = 130
const NONCE = /^[0-9a-f]{32}$/

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

function sameFileIdentity(left, right) {
  return [
    'ctimeNs',
    'dev',
    'gid',
    'ino',
    'mode',
    'mtimeNs',
    'nlink',
    'size',
    'uid',
  ].every((key) => left[key] === right[key])
}

function sameDirectoryAuthority(left, right) {
  return ['dev', 'gid', 'ino', 'mode', 'uid'].every(
    (key) => left[key] === right[key],
  )
}

async function writePrivateImmutable(path, bytes) {
  const handle = await open(
    path,
    fsConstants.O_WRONLY |
      fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      fsConstants.O_NOFOLLOW |
      fsConstants.O_CLOEXEC,
    0o444,
  )
  try {
    await handle.writeFile(bytes)
    await handle.sync()
    const metadata = await handle.stat({ bigint: true })
    if (
      !metadata.isFile() ||
      metadata.nlink !== 1n ||
      metadata.size !== BigInt(bytes.byteLength) ||
      (metadata.mode & 0o777n) !== 0o444n
    ) {
      throw new TypeError('Private document staging identity is invalid.')
    }
  } finally {
    await handle.close()
  }
}

async function sealAndReadConvertedPdf(output, filename, maximumBytes) {
  if (filename !== 'document.pdf') {
    throw new TypeError('Converted PDF filename is not canonical.')
  }
  const heldPath = join(`/proc/self/fd/${output.handle.fd}`, filename)
  const handle = await open(
    heldPath,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC,
  )
  try {
    const before = await handle.stat({ bigint: true })
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.dev !== output.identity.dev ||
      before.uid !== BigInt(process.getuid()) ||
      before.size <= 0n ||
      before.size > BigInt(maximumBytes)
    ) {
      throw new TypeError('Converted PDF is not one bounded owned regular file.')
    }
    await handle.chmod(0o444)
    await handle.sync()
    const sealed = await handle.stat({ bigint: true })
    if (
      !sealed.isFile() ||
      sealed.nlink !== 1n ||
      sealed.dev !== before.dev ||
      sealed.ino !== before.ino ||
      sealed.uid !== before.uid ||
      sealed.gid !== before.gid ||
      sealed.size !== before.size ||
      (sealed.mode & 0o777n) !== 0o444n
    ) {
      throw new TypeError('Converted PDF could not be sealed on its exact inode.')
    }
    const bytes = await handle.readFile()
    const after = await handle.stat({ bigint: true })
    const linked = await lstat(heldPath, { bigint: true })
    if (
      bytes.byteLength !== Number(sealed.size) ||
      !sameFileIdentity(sealed, after) ||
      !linked.isFile() ||
      linked.isSymbolicLink() ||
      linked.dev !== sealed.dev ||
      linked.ino !== sealed.ino ||
      (linked.mode & 0o777n) !== 0o444n
    ) {
      throw new TypeError('Converted PDF identity changed while it was sealed.')
    }
    return bytes
  } finally {
    await handle.close()
  }
}

async function admitPrivateMountRoot(path, label) {
  if (!isAbsolute(path)) {
    throw new TypeError(`${label} must be one absolute real path.`)
  }
  const handle = await open(
    path,
    fsConstants.O_RDONLY |
      fsConstants.O_DIRECTORY |
      fsConstants.O_NOFOLLOW |
      fsConstants.O_CLOEXEC,
  )
  try {
    const identity = await handle.stat({ bigint: true })
    const linked = await lstat(path, { bigint: true })
    if (
      !identity.isDirectory() ||
      !linked.isDirectory() ||
      linked.isSymbolicLink() ||
      !sameDirectoryAuthority(identity, linked) ||
      identity.uid !== BigInt(process.getuid()) ||
      (identity.mode & 0o777n) !== 0o700n ||
      (await realpath(path)) !== path ||
      (await readdir(`/proc/self/fd/${handle.fd}`)).length !== 0
    ) {
      throw new TypeError(
        `${label} is not one empty task-private mode-0700 directory.`,
      )
    }
    return Object.freeze({ handle, identity, label, path })
  } catch (error) {
    await handle.close()
    throw error
  }
}

async function reprovePrivateMount(mount) {
  const linked = await lstat(mount.path, { bigint: true })
  const held = await mount.handle.stat({ bigint: true })
  if (
    !linked.isDirectory() ||
    linked.isSymbolicLink() ||
    !sameDirectoryAuthority(mount.identity, linked) ||
    !sameDirectoryAuthority(mount.identity, held)
  ) {
    throw new TypeError(`${mount.label} identity changed during rendering.`)
  }
}

async function removePrivateMountContents(mount) {
  await reprovePrivateMount(mount)
  const heldPath = `/proc/self/fd/${mount.handle.fd}`
  for (const name of await readdir(heldPath)) {
    await rm(join(heldPath, name), {
      recursive: true,
      force: false,
      maxRetries: 2,
    })
  }
  await mount.handle.sync()
  if ((await readdir(heldPath)).length !== 0) {
    throw new TypeError(`${mount.label} retained private render residue.`)
  }
  await reprovePrivateMount(mount)
}

async function disposePrivateMount(mount) {
  try {
    await removePrivateMountContents(mount)
  } finally {
    await mount.handle.close()
  }
}

export async function convertDocxToPdf({
  documentBytes,
  policy,
  workspaceRoot = DEFAULT_WORKSPACE_ROOT,
  cacheRoot = DEFAULT_CACHE_ROOT,
  execute = executeBoundedProcessGroup,
  signal,
}) {
  if (
    !Buffer.isBuffer(documentBytes) ||
    documentBytes.byteLength > policy.input.maximumBytes
  ) {
    throw new TypeError('Input is not one bounded DOCX package.')
  }
  admitDocxPackage(documentBytes, policy.input)
  if (typeof execute !== 'function') {
    throw new TypeError('LibreOffice execution authority is invalid.')
  }

  let workspace
  let cache
  try {
    workspace = await admitPrivateMountRoot(
      workspaceRoot,
      'Document workspace root',
    )
    cache = await admitPrivateMountRoot(cacheRoot, 'Document cache root')
    if (sameDirectoryAuthority(workspace.identity, cache.identity)) {
      throw new TypeError('Document workspace and cache mounts must be distinct.')
    }
  } catch (error) {
    const opened = [workspace, cache].filter(Boolean)
    await Promise.allSettled(opened.map((mount) => mount.handle.close()))
    throw error
  }
  let operationRoot
  let privateCacheRoot
  try {
    operationRoot = await mkdtemp(join(workspace.path, '.ambit-document-render-'))
    await chmod(operationRoot, 0o700)
    privateCacheRoot = await mkdtemp(join(cache.path, '.ambit-document-render-'))
    await chmod(privateCacheRoot, 0o700)
  } catch (error) {
    const cleanup = await Promise.allSettled([
      disposePrivateMount(workspace),
      disposePrivateMount(cache),
    ])
    const failure = cleanup.find((result) => result.status === 'rejected')
    if (failure) {
      throw new AggregateError(
        [error, failure.reason],
        'Private render root creation and cleanup both failed.',
        { cause: error },
      )
    }
    throw error
  }
  let disposePromise
  const dispose = () => {
    if (disposePromise) return disposePromise
    disposePromise = (async () => {
      const settled = await Promise.allSettled([
        disposePrivateMount(workspace),
        disposePrivateMount(cache),
      ])
      const failures = settled
        .filter((result) => result.status === 'rejected')
        .map((result) => result.reason)
      if (failures.length === 1) throw failures[0]
      if (failures.length > 1) {
        throw new AggregateError(failures, 'Both private render mounts failed cleanup.')
      }
    })()
    return disposePromise
  }
  try {
    const input = join(operationRoot, 'document.docx')
    const convertedOutput = join(operationRoot, 'converted')
    const profile = join(privateCacheRoot, 'libreoffice-profile')
    await mkdir(convertedOutput, { mode: 0o700 })
    await mkdir(profile, { mode: 0o700 })
    await writePrivateImmutable(input, documentBytes)
    const outputDirectory = await admitEmptyOutputDirectory(convertedOutput)
    let pdfBytes
    try {
      await execute({
        executable: STRUCTURAL_PYTHON_PATH,
        arguments: [
          LIBREOFFICE_SUBREAPER_PATH,
          LIBREOFFICE_PATH,
          '--headless',
          '--nologo',
          '--nodefault',
          '--norestore',
          '--nolockcheck',
          `-env:UserInstallation=${pathToFileURL(profile).href}`,
          '--convert-to',
          'pdf:writer_pdf_Export',
          '--outdir',
          convertedOutput,
          input,
        ],
        cwd: operationRoot,
        env: {
          HOME: privateCacheRoot,
          LANG: 'C.UTF-8',
          LC_ALL: 'C.UTF-8',
          PATH: '/usr/bin:/bin',
          SAL_USE_VCLPLUGIN: 'svp',
          TMPDIR: privateCacheRoot,
          TZ: 'UTC',
          XDG_CACHE_HOME: join(privateCacheRoot, 'cache'),
          XDG_CONFIG_HOME: join(privateCacheRoot, 'config'),
        },
        maximumWallMilliseconds: policy.libreOffice.maximumWallMilliseconds,
        maximumStdoutBytes: policy.execution.maximumChildStdoutBytes,
        maximumStderrBytes: policy.execution.maximumChildStderrBytes,
        signal,
      })
      const heldOutput = `/proc/self/fd/${outputDirectory.handle.fd}`
      const names = await readdir(heldOutput)
      if (names.length !== 1 || names[0] !== 'document.pdf') {
        throw new TypeError('LibreOffice did not produce one exact PDF output.')
      }
      pdfBytes = await sealAndReadConvertedPdf(
        outputDirectory,
        'document.pdf',
        policy.libreOffice.maximumPdfBytes,
      )
      await reproveOutputDirectory(convertedOutput, outputDirectory.identity)
    } finally {
      await outputDirectory.handle.close()
    }
    if (
      pdfBytes.byteLength < 8 ||
      !pdfBytes.subarray(0, 5).equals(Buffer.from('%PDF-')) ||
      !pdfBytes
        .subarray(-Math.min(1024, pdfBytes.byteLength))
        .toString('latin1')
        .includes('%%EOF')
    ) {
      throw new TypeError('LibreOffice output is not one bounded PDF document.')
    }
    await unlink(input)
    const pdfPath = join(convertedOutput, 'document.pdf')
    return Object.freeze({
      pdfBytes,
      pdfPath,
      operationRoot,
      privateCacheRoot,
      dispose,
    })
  } catch (error) {
    try {
      await dispose()
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        'Document conversion and private-mount cleanup both failed.',
        { cause: error },
      )
    }
    throw error
  }
}

export async function renderDocumentRequest(request, options = {}) {
  const loaded = options.loadedPolicy ?? (await loadRenderPolicy())
  const converted = await convertDocxToPdf({
    documentBytes: request.document,
    policy: loaded.policy,
    workspaceRoot: options.workspaceRoot,
    cacheRoot: options.cacheRoot,
    execute: options.execute,
    signal: options.signal,
  })
  try {
    const outputPath = join(converted.operationRoot, 'rendered')
    await mkdir(outputPath, { mode: 0o700 })
    const sourceDocument = Object.freeze({
      format: 'docx',
      sha256: request.documentSha256,
      bytes: request.document.byteLength,
    })
    const childRequest = Buffer.from(
      `${canonicalJson({
        schema: 'ambit.runtime-pack-internal-page-render/v1',
        backendLineage: request.backendLineage,
        sourceDocument,
      })}\n`,
    )
    await writePrivateImmutable(
      join(converted.operationRoot, 'render-request.json'),
      childRequest,
    )
    const executeRenderer =
      options.executeRenderer ?? options.execute ?? executeBoundedProcessGroup
    const child = await executeRenderer({
      executable: STRUCTURAL_PYTHON_PATH,
      arguments: [
        LIBREOFFICE_SUBREAPER_PATH,
        NODE_PATH,
        PAGE_RENDERER_PATH,
        '--internal-render-child',
      ],
      cwd: converted.operationRoot,
      env: {
        HOME: converted.privateCacheRoot,
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
        PATH: `${join(CORE_DOCUMENT_V5_PACK_ROOT, 'bin')}:/usr/bin:/bin`,
        TMPDIR: converted.privateCacheRoot,
        TZ: 'UTC',
        XDG_CACHE_HOME: join(converted.privateCacheRoot, 'page-cache'),
        XDG_CONFIG_HOME: join(converted.privateCacheRoot, 'page-config'),
      },
      maximumWallMilliseconds:
        loaded.policy.execution.maximumPipelineWallMilliseconds,
      maximumStdoutBytes: loaded.policy.execution.maximumChildStdoutBytes,
      maximumStderrBytes: loaded.policy.execution.maximumChildStderrBytes,
      signal: options.signal,
    })
    if (!Buffer.isBuffer(child.stdout) || !Buffer.isBuffer(child.stderr)) {
      throw new TypeError('Internal page-render process receipt is unavailable.')
    }
    if (child.stderr.byteLength !== 0) {
      throw new TypeError('Internal page-render process emitted stderr on success.')
    }
    let childReceipt
    try {
      childReceipt = JSON.parse(child.stdout.toString('utf8'))
    } catch (error) {
      throw new TypeError('Internal page-render process receipt is not JSON.', {
        cause: error,
      })
    }
    if (
      child.stdout.byteLength === 0 ||
      !child.stdout.equals(Buffer.from(`${canonicalJson(childReceipt)}\n`)) ||
      childReceipt?.schema !== 'ambit.runtime-pack-internal-page-render/v1' ||
      childReceipt?.outcome !== 'passed' ||
      !Number.isSafeInteger(childReceipt?.manifestBytes) ||
      childReceipt.manifestBytes <= 0 ||
      typeof childReceipt?.manifestSha256 !== 'string' ||
      !/^sha256:[0-9a-f]{64}$/.test(childReceipt.manifestSha256) ||
      Object.keys(childReceipt).sort().join('\n') !==
        ['manifestBytes', 'manifestSha256', 'outcome', 'schema']
          .sort()
          .join('\n')
    ) {
      throw new TypeError('Internal page-render process receipt is invalid.')
    }
    const inspection = await inspectRenderOutput({
      packRoot: CORE_DOCUMENT_V5_PACK_ROOT,
      output: outputPath,
    })
    if (
      childReceipt.manifestBytes !== inspection.manifestBytes.byteLength ||
      childReceipt.manifestSha256 !== sha256(inspection.manifestBytes)
    ) {
      throw new TypeError('Internal page-render receipt differs from sealed output.')
    }
    return Object.freeze({
      ...inspection,
      outputPath,
      dispose: converted.dispose,
    })
  } catch (error) {
    await converted.dispose()
    throw error
  }
}

async function writeLine(writable, line, signal) {
  if (signal?.aborted) throw signal.reason
  await new Promise((resolve, reject) => {
    let settled = false
    const finish = (error) => {
      if (settled) return
      settled = true
      signal?.removeEventListener('abort', abort)
      if (error) reject(error)
      else resolve()
    }
    const abort = () => {
      writable.destroy?.()
      finish(signal.reason ?? new Error('Render transport write was aborted.'))
    }
    signal?.addEventListener('abort', abort, { once: true })
    try {
      writable.write(line, (error) => finish(error))
    } catch (error) {
      finish(error)
    }
  })
}

async function emitImmutablePageChunks({ path, page, emit, nonce, signal }) {
  const handle = await open(
    path,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC,
  )
  const digest = createHash('sha256')
  try {
    const before = await handle.stat({ bigint: true })
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.size !== BigInt(page.bytes) ||
      (before.mode & 0o777n) !== 0o444n
    ) {
      throw new TypeError('Sealed render page identity is invalid.')
    }
    const chunkCount = payloadChunkCount(page.bytes)
    await emit({
      schema: FRAMED_JSONL_SCHEMA,
      kind: 'page_start',
      nonce,
      page,
      chunkBytes: RAW_CHUNK_BYTES,
      chunkCount,
    })
    let position = 0
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
      if (signal?.aborted) throw signal.reason
      const size = Math.min(RAW_CHUNK_BYTES, page.bytes - position)
      const buffer = Buffer.allocUnsafe(size)
      const result = await handle.read(buffer, 0, size, position)
      if (result.bytesRead !== size) {
        throw new TypeError('Sealed render page ended before its claimed size.')
      }
      position += size
      digest.update(buffer)
      await emit(
        createPayloadChunkFrame({
          kind: 'page_chunk',
          index: chunkIndex,
          bytes: buffer,
          extra: { nonce, pageIndex: page.index },
        }),
      )
    }
    const after = await handle.stat({ bigint: true })
    if (
      position !== page.bytes ||
      !sameFileIdentity(before, after) ||
      `sha256:${digest.digest('hex')}` !== page.sha256
    ) {
      throw new TypeError('Sealed render page changed while framing.')
    }
  } finally {
    await handle.close()
  }
}

export async function streamSealedResponseBody({
  sealed,
  nonce,
  writable,
  signal,
}) {
  const streamDigest = createHash('sha256')
  let frameCount = 0
  const emit = async (value) => {
    if (signal?.aborted) throw signal.reason
    const line = canonicalFrameLine(value)
    streamDigest.update(line)
    frameCount += 1
    await writeLine(writable, line, signal)
  }
  for (const page of sealed.manifest.pages) {
    await emitImmutablePageChunks({
      path: join(sealed.outputPath, page.filename),
      page,
      emit,
      nonce,
      signal,
    })
  }

  const manifestBytes = sealed.manifestBytes
  const manifestSha256 = digestBytes(manifestBytes)
  const manifestChunkCount = payloadChunkCount(manifestBytes.byteLength)
  await emit({
    schema: FRAMED_JSONL_SCHEMA,
    kind: 'manifest_start',
    nonce,
    bytes: manifestBytes.byteLength,
    sha256: manifestSha256,
    manifestDigest: sealed.manifest.manifestDigest,
    pageCount: sealed.manifest.pageCount,
    chunkBytes: RAW_CHUNK_BYTES,
    chunkCount: manifestChunkCount,
  })
  for (let chunkIndex = 0; chunkIndex < manifestChunkCount; chunkIndex += 1) {
    const bytes = manifestBytes.subarray(
      chunkIndex * RAW_CHUNK_BYTES,
      Math.min((chunkIndex + 1) * RAW_CHUNK_BYTES, manifestBytes.byteLength),
    )
    await emit(
      createPayloadChunkFrame({
        kind: 'manifest_chunk',
        index: chunkIndex,
        bytes,
        extra: { nonce },
      }),
    )
  }
  const terminal = Object.freeze({
    schema: FRAMED_JSONL_SCHEMA,
    kind: 'response_end',
    nonce,
    outcome: 'passed',
    exitCode: 0,
    frameCount,
    pageCount: sealed.manifest.pageCount,
    totalOutputBytes: sealed.manifest.totalOutputBytes,
    manifestBytes: manifestBytes.byteLength,
    manifestSha256,
    manifestDigest: sealed.manifest.manifestDigest,
    policy: sealed.manifest.policy,
    streamSha256: `sha256:${streamDigest.digest('hex')}`,
  })
  return terminal
}

export async function streamSealedResponse(args) {
  const terminal = await streamSealedResponseBody(args)
  await writeLine(args.writable, canonicalFrameLine(terminal), args.signal)
  return terminal
}

function parseArguments(argv) {
  if (
    argv.length !== 3 ||
    argv[0] !== '--framed-jsonl' ||
    argv[1] !== '--nonce' ||
    typeof argv[2] !== 'string' ||
    !NONCE.test(argv[2])
  ) {
    throw new TypeError(
      'Expected --framed-jsonl --nonce LOWERCASE_128_BIT_HEX.',
    )
  }
  return Object.freeze({ nonce: argv[2] })
}

async function loadInterfaceIdentity() {
  const bytes = await readRegularNoFollow(
    INTERFACE_LOCK_PATH,
    MAXIMUM_INTERFACE_LOCK_BYTES,
  )
  const value = JSON.parse(bytes.toString('utf8'))
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    value.schema !== 'ambit.runtime-interface-lock/v1' ||
    value.state !== 'candidate-ready' ||
    typeof value.contract !== 'object' ||
    sha256(Buffer.from(canonicalJson(value.contract))) !== value.digest ||
    value.contract.interfaceRef !==
      'ambit.runtime-interface/docx-paginated-render@1'
  ) {
    throw new TypeError('Installed document-render interface lock is invalid.')
  }
  return Object.freeze({
    ref: value.contract.interfaceRef,
    digest: value.digest,
  })
}

function processIdentity() {
  const statText = readFileSync('/proc/self/stat', 'utf8')
  const close = statText.lastIndexOf(')')
  const fields = statText.slice(close + 2).trim().split(' ')
  const startTicks = fields[19]
  if (!/^[1-9][0-9]*$/.test(startTicks)) {
    throw new TypeError('Helper process start-tick identity is invalid.')
  }
  return Object.freeze({ pid: process.pid, startTicks })
}

function signalAbortController() {
  const controller = new AbortController()
  const abort = (name) => {
    if (!controller.signal.aborted) {
      controller.abort(new Error(`Helper received ${name}.`))
    }
  }
  const onTerm = () => abort('SIGTERM')
  const onInt = () => abort('SIGINT')
  process.once('SIGTERM', onTerm)
  process.once('SIGINT', onInt)
  return Object.freeze({
    controller,
    dispose() {
      process.removeListener('SIGTERM', onTerm)
      process.removeListener('SIGINT', onInt)
    },
  })
}

function deadlineController(milliseconds, message) {
  if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0) {
    throw new TypeError('Render deadline must be a positive safe integer.')
  }
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new Error(message)), milliseconds)
  timer.unref?.()
  return Object.freeze({
    controller,
    dispose() {
      clearTimeout(timer)
    },
  })
}

function combineAbortSignals(signals) {
  const controller = new AbortController()
  const admitted = signals.filter((signal) => signal !== undefined)
  const listeners = admitted.map((signal) => {
    const abort = () => {
      if (!controller.signal.aborted) {
        controller.abort(signal.reason ?? new Error('Render execution was aborted.'))
      }
    }
    if (signal.aborted) abort()
    else signal.addEventListener('abort', abort, { once: true })
    return { signal, abort }
  })
  return Object.freeze({
    signal: controller.signal,
    dispose() {
      for (const listener of listeners) {
        listener.signal.removeEventListener('abort', listener.abort)
      }
    },
  })
}

async function awaitWithAbort(operation, signal) {
  if (signal.aborted) throw signal.reason
  let abort
  const rejected = new Promise((resolve, reject) => {
    abort = () => reject(signal.reason ?? new Error('Render operation was aborted.'))
    signal.addEventListener('abort', abort, { once: true })
  })
  try {
    return await Promise.race([Promise.resolve().then(operation), rejected])
  } finally {
    signal.removeEventListener('abort', abort)
  }
}

async function disposeWithDeadline(dispose, milliseconds) {
  const deadline = deadlineController(
    milliseconds,
    'Private render cleanup exceeded its deadline.',
  )
  try {
    await awaitWithAbort(dispose, deadline.controller.signal)
  } finally {
    deadline.dispose()
  }
}

async function writeTerminalWithDeadline({
  writable,
  frame,
  milliseconds,
  signals = [],
}) {
  const deadline = deadlineController(
    milliseconds,
    'Render terminal write exceeded its deadline.',
  )
  const combined = combineAbortSignals([deadline.controller.signal, ...signals])
  try {
    await writeLine(writable, canonicalFrameLine(frame), combined.signal)
  } finally {
    combined.dispose()
    deadline.dispose()
  }
}

async function main() {
  const { nonce } = parseArguments(process.argv.slice(2))
  const loadedPolicy = await loadRenderPolicy()
  const interfaceIdentity = await loadInterfaceIdentity()
  const signals = signalAbortController()
  const pipelineDeadline = deadlineController(
    loadedPolicy.policy.execution.maximumPipelineWallMilliseconds,
    'Document render exceeded its whole-pipeline deadline.',
  )
  const arbiter = new RenderTerminalArbiter()
  const external = combineAbortSignals([
    signals.controller.signal,
    pipelineDeadline.controller.signal,
  ])
  const onExternalAbort = () => {
    arbiter.fail(
      external.signal.reason ?? new Error('Document render was externally aborted.'),
    )
  }
  if (external.signal.aborted) onExternalAbort()
  else external.signal.addEventListener('abort', onExternalAbort, { once: true })
  const lineReader = new FramedJsonlLineReader(process.stdin)
  let sealed
  let controlWatcher
  let failure = null
  let cleanupFailure = null
  let successTerminal = null
  try {
    await writeLine(
      process.stdout,
      canonicalFrameLine({
        schema: FRAMED_JSONL_SCHEMA,
        kind: 'ready',
        nonce,
        cancellationExitCode: CANCELLATION_EXIT_CODE,
        chunkBytes: RAW_CHUNK_BYTES,
        interface: interfaceIdentity,
        policy: {
          ref: loadedPolicy.policy.policyRef,
          digest: sha256(loadedPolicy.policyBytes),
        },
        processIdentity: processIdentity(),
      }),
      arbiter.signal,
    )
    const request = await readRenderRequest(
      lineReader,
      loadedPolicy.policy.input.maximumBytes,
      nonce,
      arbiter.signal,
    )
    controlWatcher = watchRenderCancellation(lineReader, nonce).catch((error) => {
      if (
        error instanceof RenderControlAdmissionClosed &&
        ['success-committed', 'succeeded'].includes(arbiter.state)
      ) {
        return
      }
      if (error instanceof RenderProtocolCancellation) arbiter.cancel(error)
      else arbiter.fail(error)
    })
    sealed = await renderDocumentRequest(request, {
      loadedPolicy,
      signal: arbiter.signal,
    })
    successTerminal = await streamSealedResponseBody({
      sealed,
      nonce,
      writable: process.stdout,
      signal: arbiter.signal,
    })
    await disposeWithDeadline(
      sealed.dispose,
      loadedPolicy.policy.execution.maximumCleanupMilliseconds,
    )
    sealed = null
    if (!arbiter.commitSuccess()) {
      throw arbiter.reason ?? new Error('Render success lost terminal arbitration.')
    }
    lineReader.close(new RenderControlAdmissionClosed())
    await controlWatcher
    await writeTerminalWithDeadline({
      writable: process.stdout,
      frame: successTerminal,
      milliseconds:
        loadedPolicy.policy.execution.maximumTerminalWriteMilliseconds,
      signals: [arbiter.signal],
    })
    arbiter.completeSuccess()
  } catch (error) {
    failure = error
    if (error instanceof RenderProtocolCancellation) arbiter.cancel(error)
    else arbiter.fail(error)
  } finally {
    try {
      if (sealed) {
        await disposeWithDeadline(
          sealed.dispose,
          loadedPolicy.policy.execution.maximumCleanupMilliseconds,
        )
      }
    } catch (cleanupError) {
      cleanupFailure = cleanupError
      arbiter.fail(cleanupError)
      failure = failure
        ? new AggregateError(
            [failure, cleanupError],
            'Render failed and private-root cleanup also failed.',
            { cause: failure },
          )
        : cleanupError
    }
    lineReader.close()
    await controlWatcher
    external.signal.removeEventListener('abort', onExternalAbort)
    external.dispose()
    pipelineDeadline.dispose()
    signals.dispose()
  }
  const protocolCancellation =
    cleanupFailure === null &&
    arbiter.state === 'cancelled' &&
    arbiter.reason instanceof RenderProtocolCancellation
  if (protocolCancellation) {
    try {
      await writeTerminalWithDeadline({
        writable: process.stdout,
        frame: {
        schema: FRAMED_JSONL_SCHEMA,
        kind: 'cancelled',
        nonce,
        outcome: 'cancelled',
        exitCode: CANCELLATION_EXIT_CODE,
        quiescence:
          'all-render-process-groups-settled-and-private-roots-removed',
        },
        milliseconds:
          loadedPolicy.policy.execution.maximumTerminalWriteMilliseconds,
        signals: [signals.controller.signal],
      })
    } catch (terminalError) {
      arbiter.fail(terminalError)
      throw terminalError
    }
    process.exitCode = CANCELLATION_EXIT_CODE
    return
  }
  if (arbiter.state === 'succeeded') return
  throw failure ?? arbiter.reason ?? new Error('Document render failed closed.')
}

function invokedAsProgram() {
  try {
    return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
  } catch {
    return false
  }
}

if (invokedAsProgram()) {
  main().catch(() => {
    process.exitCode = 1
  })
}
