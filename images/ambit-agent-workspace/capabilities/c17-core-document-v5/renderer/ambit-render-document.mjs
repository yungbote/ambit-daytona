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
  stat,
} from 'node:fs/promises'
import { isAbsolute, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import {
  loadRenderPolicy,
  readRegularNoFollow,
  renderPagesToDirectory,
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
  RenderProtocolCancellation,
  watchRenderCancellation,
} from './framed-jsonl-protocol.mjs'
import { executeBoundedProcessGroup } from './process-group-execution.mjs'
import { inspectRenderOutput } from './render-output-verification.mjs'
import { canonicalJson } from './render-contracts.mjs'
import { CORE_DOCUMENT_V5_PACK_ROOT } from './pdfjs-page-renderer.mjs'

const STRUCTURAL_PYTHON_PATH = join(
  CORE_DOCUMENT_V5_PACK_ROOT,
  'bin/ambit-structural-python',
)
const LIBREOFFICE_SUBREAPER_PATH = join(
  CORE_DOCUMENT_V5_PACK_ROOT,
  'renderer/libreoffice-subreaper.py',
)
const LIBREOFFICE_PATH = '/usr/bin/libreoffice'
const INTERFACE_LOCK_PATH = join(
  CORE_DOCUMENT_V5_PACK_ROOT,
  'locks/document-render-interface.lock.json',
)
const DEFAULT_WORKSPACE_ROOT = '/workspace'
const DEFAULT_CACHE_ROOT = '/tmp'
const MAXIMUM_PROCESS_OUTPUT_BYTES = 64 * 1024
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

async function admitPrivateMountRoot(path, label) {
  if (!isAbsolute(path) || (await realpath(path)) !== path) {
    throw new TypeError(`${label} must be one absolute real path.`)
  }
  const metadata = await stat(path, { bigint: true })
  if (
    !metadata.isDirectory() ||
    metadata.uid !== BigInt(process.getuid()) ||
    (metadata.mode & 0o777n) !== 0o700n
  ) {
    throw new TypeError(`${label} is not one task-private mode-0700 directory.`)
  }
  return path
}

async function removePrivateRoot(path) {
  await rm(path, { recursive: true, force: true, maxRetries: 2 })
  try {
    await lstat(path)
  } catch (error) {
    if (error?.code === 'ENOENT') return
    throw error
  }
  throw new TypeError('Private render root remained after cleanup.')
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

  const workspace = await admitPrivateMountRoot(
    workspaceRoot,
    'Document workspace root',
  )
  const cache = await admitPrivateMountRoot(cacheRoot, 'Document cache root')
  const operationRoot = await mkdtemp(join(workspace, '.ambit-document-render-'))
  await chmod(operationRoot, 0o700)
  let privateCacheRoot
  try {
    privateCacheRoot = await mkdtemp(join(cache, '.ambit-document-render-'))
    await chmod(privateCacheRoot, 0o700)
  } catch (error) {
    await removePrivateRoot(operationRoot)
    throw error
  }
  let disposed = false
  const dispose = async () => {
    if (disposed) return
    disposed = true
    const settled = await Promise.allSettled([
      removePrivateRoot(operationRoot),
      removePrivateRoot(privateCacheRoot),
    ])
    const failure = settled.find((result) => result.status === 'rejected')
    if (failure) throw failure.reason
  }
  try {
    const input = join(operationRoot, 'document.docx')
    const convertedOutput = join(operationRoot, 'converted')
    const profile = join(privateCacheRoot, 'libreoffice-profile')
    await mkdir(convertedOutput, { mode: 0o700 })
    await mkdir(profile, { mode: 0o700 })
    await writePrivateImmutable(input, documentBytes)
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
      maximumOutputBytes: MAXIMUM_PROCESS_OUTPUT_BYTES,
      signal,
    })
    const names = await readdir(convertedOutput)
    if (names.length !== 1 || names[0] !== 'document.pdf') {
      throw new TypeError('LibreOffice did not produce one exact PDF output.')
    }
    const pdfPath = join(convertedOutput, names[0])
    await chmod(pdfPath, 0o444)
    const pdfBytes = await readRegularNoFollow(
      pdfPath,
      policy.libreOffice.maximumPdfBytes,
    )
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
    return Object.freeze({ pdfBytes, operationRoot, dispose })
  } catch (error) {
    await dispose()
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
    await renderPagesToDirectory({
      pdfBytes: converted.pdfBytes,
      outputPath,
      backendLineage: request.backendLineage,
      sourceDocument: {
        format: 'docx',
        sha256: request.documentSha256,
        bytes: request.document.byteLength,
      },
    })
    const inspection = await inspectRenderOutput({
      packRoot: CORE_DOCUMENT_V5_PACK_ROOT,
      output: outputPath,
    })
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

async function writeLine(writable, line) {
  await new Promise((resolve, reject) => {
    writable.write(line, (error) => (error ? reject(error) : resolve()))
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

export async function streamSealedResponse({
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
    await writeLine(writable, line)
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
  await writeLine(writable, canonicalFrameLine(terminal))
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

async function main() {
  const { nonce } = parseArguments(process.argv.slice(2))
  const loadedPolicy = await loadRenderPolicy()
  const interfaceIdentity = await loadInterfaceIdentity()
  const signals = signalAbortController()
  const lineReader = new FramedJsonlLineReader(process.stdin)
  let sealed
  let controlWatcher
  let finished = false
  let failure = null
  let cleanupFailure = null
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
    )
    const request = await readRenderRequest(
      lineReader,
      loadedPolicy.policy.input.maximumBytes,
      nonce,
      signals.controller.signal,
    )
    controlWatcher = watchRenderCancellation(lineReader, nonce).catch(
      (error) => {
        if (!finished && !signals.controller.signal.aborted) {
          signals.controller.abort(error)
        }
      },
    )
    sealed = await renderDocumentRequest(request, {
      loadedPolicy,
      signal: signals.controller.signal,
    })
    await streamSealedResponse({
      sealed,
      nonce,
      writable: process.stdout,
      signal: signals.controller.signal,
    })
    finished = true
  } catch (error) {
    failure = error
  } finally {
    signals.dispose()
    try {
      if (sealed) await sealed.dispose()
    } catch (cleanupError) {
      cleanupFailure = cleanupError
      failure = failure
        ? new AggregateError(
            [failure, cleanupError],
            'Render failed and private-root cleanup also failed.',
            { cause: failure },
          )
        : cleanupError
    }
    finished = true
    lineReader.close()
    await controlWatcher
  }
  const protocolCancellation =
    cleanupFailure === null &&
    (failure instanceof RenderProtocolCancellation ||
      signals.controller.signal.reason instanceof RenderProtocolCancellation)
  if (protocolCancellation) {
    await writeLine(
      process.stdout,
      canonicalFrameLine({
        schema: FRAMED_JSONL_SCHEMA,
        kind: 'cancelled',
        nonce,
        outcome: 'cancelled',
        exitCode: CANCELLATION_EXIT_CODE,
        quiescence: 'libreoffice-process-group-settled-and-private-roots-removed',
      }),
    )
    process.exitCode = CANCELLATION_EXIT_CODE
    return
  }
  if (failure) throw failure
}

function invokedAsProgram() {
  try {
    return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
  } catch {
    return false
  }
}

if (invokedAsProgram()) {
  main().catch((error) => {
    process.stderr.write(`core-document@5 framed render failed: ${error.message}\n`)
    process.exitCode = 1
  })
}
