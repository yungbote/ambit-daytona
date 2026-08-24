import { createHash } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import {
  lstat,
  open,
  readdir,
  realpath,
} from 'node:fs/promises'
import { createRequire } from 'node:module'
import { isAbsolute, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import {
  admitBackendComponentLineageEnvelope,
  admitInstalledEngineLineage,
  admitRenderPolicy,
  canonicalJson,
  composeRenderExecutionLineage,
  createRenderManifest,
} from './render-contracts.mjs'
import {
  admitCanvasModule,
  admitPdfjsModule,
  CORE_DOCUMENT_V5_PACK_ROOT,
  renderPdfBytes,
} from './pdfjs-page-renderer.mjs'

const POLICY_PATH = join(
  CORE_DOCUMENT_V5_PACK_ROOT,
  'policy/render-policy.json',
)
const PDFJS_MODULE_PATH = join(
  CORE_DOCUMENT_V5_PACK_ROOT,
  'renderer/pdfjs/legacy/build/pdf.mjs',
)
const CANVAS_MODULE_PATH = join(
  CORE_DOCUMENT_V5_PACK_ROOT,
  'renderer/node_modules/@napi-rs/canvas',
)
const CANVAS_PACKAGE_PATH = join(CANVAS_MODULE_PATH, 'package.json')
const ENGINE_LINEAGE_PATH = join(
  CORE_DOCUMENT_V5_PACK_ROOT,
  'lineage/installed-render-engine-lineage.json',
)
const EXPECTED_NODE_VERSION = 'v24.19.0'
const OUTPUT_MANIFEST_NAME = 'render-manifest.json'
const INTERNAL_RENDER_REQUEST_NAME = 'render-request.json'
const INTERNAL_PDF_NAME = 'converted/document.pdf'
const INTERNAL_OUTPUT_NAME = 'rendered'
const INTERNAL_RENDER_SCHEMA = 'ambit.runtime-pack-internal-page-render/v1'
const MAXIMUM_INTERNAL_REQUEST_BYTES = 64 * 1024

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

export async function readRegularNoFollow(path, maximumBytes) {
  if (!isAbsolute(path)) {
    throw new TypeError('Input path must be absolute.')
  }
  const handle = await open(
    path,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC,
  )
  try {
    const before = await handle.stat({ bigint: true })
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      (before.mode & 0o222n) !== 0n ||
      before.size <= 0n ||
      before.size > BigInt(maximumBytes)
    ) {
      throw new TypeError('Input must be one bounded immutable regular file.')
    }
    const bytes = await handle.readFile()
    const after = await handle.stat({ bigint: true })
    if (
      bytes.byteLength !== Number(before.size) ||
      !sameFileIdentity(before, after)
    ) {
      throw new TypeError('Input identity changed while it was being read.')
    }
    return bytes
  } finally {
    await handle.close()
  }
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

function sameDirectoryIdentity(left, right) {
  return ['dev', 'gid', 'ino', 'mode', 'uid'].every(
    (key) => left[key] === right[key],
  )
}

export async function holdTaskPrivateDirectory(path, requireEmpty = false) {
  if (!isAbsolute(path) || typeof requireEmpty !== 'boolean') {
    throw new TypeError('Task-private directory input is invalid.')
  }
  const handle = await open(
    path,
    fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
  )
  try {
    const identity = await handle.stat({ bigint: true })
    if (
      !identity.isDirectory() ||
      identity.uid !== BigInt(process.getuid()) ||
      (identity.mode & 0o777n) !== 0o700n ||
      (await realpath(path)) !== path ||
      (requireEmpty && (await readdir(`/proc/self/fd/${handle.fd}`)).length !== 0)
    ) {
      throw new TypeError(
        'Directory must be one canonical task-private directory.',
      )
    }
    await reproveOutputDirectory(path, identity)
    return Object.freeze({ path, handle, identity })
  } catch (error) {
    await handle.close()
    throw error
  }
}

export async function admitEmptyOutputDirectory(path) {
  return holdTaskPrivateDirectory(path, true)
}

export async function reproveOutputDirectory(path, expected) {
  const observed = await lstat(path, { bigint: true })
  if (
    !observed.isDirectory() ||
    observed.isSymbolicLink() ||
    !sameDirectoryIdentity(expected, observed)
  ) {
    throw new TypeError('Output directory identity changed during rendering.')
  }
}

export async function writeDurableOutput(output, filename, bytes) {
  if (!/^(?:page-[0-9]{4}\.png|render-manifest\.json)$/.test(filename)) {
    throw new TypeError('Output filename is not canonical.')
  }
  await reproveOutputDirectory(output.path, output.identity)
  const heldDirectoryPath = `/proc/self/fd/${output.handle.fd}`
  const path = join(heldDirectoryPath, filename)
  const handle = await open(
    path,
    fsConstants.O_WRONLY |
      fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      fsConstants.O_NOFOLLOW |
      fsConstants.O_CLOEXEC,
    0o444,
  )
  let writtenIdentity
  try {
    await handle.writeFile(bytes)
    await handle.sync()
    const metadata = await handle.stat({ bigint: true })
    if (
      !metadata.isFile() ||
      metadata.nlink !== 1n ||
      metadata.dev !== output.identity.dev ||
      metadata.size !== BigInt(Buffer.byteLength(bytes)) ||
      (metadata.mode & 0o777n) !== 0o444n
    ) {
      throw new TypeError('Durable output file identity is invalid.')
    }
    writtenIdentity = metadata
  } finally {
    await handle.close()
  }
  await reproveOutputDirectory(output.path, output.identity)
  const linked = await lstat(join(output.path, filename), { bigint: true })
  if (
    !linked.isFile() ||
    linked.isSymbolicLink() ||
    linked.dev !== output.identity.dev ||
    linked.ino !== writtenIdentity.ino ||
    (linked.mode & 0o777n) !== 0o444n
  ) {
    throw new TypeError('Durable output is not linked at the admitted path.')
  }
  await output.handle.sync()
}

function readCanonicalInput(bytes, admit, label) {
  const text = bytes.toString('utf8')
  const value = JSON.parse(text)
  if (`${canonicalJson(value)}\n` !== text) {
    throw new TypeError(`${label} bytes are not canonical JSON.`)
  }
  return admit(value)
}

async function loadExactEngine() {
  if (process.version !== EXPECTED_NODE_VERSION) {
    throw new TypeError('The exact Node runtime is unavailable.')
  }
  const require = createRequire(import.meta.url)
  const canvasPackage = require(CANVAS_PACKAGE_PATH)
  const admittedCanvas = admitCanvasModule(
    require(CANVAS_MODULE_PATH),
    canvasPackage,
  )
  const canvas = admittedCanvas.module
  globalThis.DOMMatrix = canvas.DOMMatrix
  globalThis.ImageData = canvas.ImageData
  globalThis.Path2D = canvas.Path2D
  const pdfjs = admitPdfjsModule(await import(pathToFileURL(PDFJS_MODULE_PATH)))
  return { pdfjs, canvas, canvasPackage }
}

export async function loadRenderPolicy() {
  const policyBytes = await readRegularNoFollow(POLICY_PATH, 1048576)
  const policy = admitRenderPolicy(JSON.parse(policyBytes.toString('utf8')))
  return Object.freeze({ policyBytes, policy })
}

export async function renderPagesToDirectory({
  pdfBytes,
  outputPath,
  backendLineage,
  sourceDocument,
}) {
  const { policyBytes, policy } = await loadRenderPolicy()
  if (policy.pdfjs.executionState !== 'available') {
    throw new TypeError('The exact PDF.js execution evidence remains unavailable.')
  }
  if (
    !Buffer.isBuffer(pdfBytes) ||
    pdfBytes.byteLength === 0 ||
    pdfBytes.byteLength > policy.libreOffice.maximumPdfBytes
  ) {
    throw new TypeError('Intermediate PDF bytes are unavailable or exceed policy.')
  }
  const backendComponentLineage = admitBackendComponentLineageEnvelope(
    backendLineage,
  )
  const installedEngineBytes = await readRegularNoFollow(
    ENGINE_LINEAGE_PATH,
    1048576,
  )
  const installedEngineLineage = readCanonicalInput(
    installedEngineBytes,
    admitInstalledEngineLineage,
    'Installed render engine lineage',
  )
  const executionLineage = composeRenderExecutionLineage({
    backendComponentLineage,
    installedEngineLineage,
  })
  const output = await admitEmptyOutputDirectory(outputPath)
  try {
    const { pdfjs, canvas, canvasPackage } = await loadExactEngine()
    const pages = await renderPdfBytes({
      pdfBytes,
      policy,
      pdfjs,
      canvas,
      canvasPackage,
      sink: async (page) =>
        writeDurableOutput(output, page.evidence.filename, page.bytes),
    })
    const manifest = createRenderManifest({
      sourceDocument,
      intermediatePdfBytes: pdfBytes.byteLength,
      policySha256: sha256(policyBytes),
      pages,
      policy,
      executionLineage,
    })
    const manifestBytes = `${canonicalJson(manifest)}\n`
    await writeDurableOutput(output, OUTPUT_MANIFEST_NAME, manifestBytes)
    await reproveOutputDirectory(output.path, output.identity)
    return manifestBytes
  } finally {
    await output.handle.close()
  }
}

function exactInternalRenderRequest(value) {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).sort().join('\n') !==
      ['backendLineage', 'schema', 'sourceDocument'].sort().join('\n') ||
    value.schema !== INTERNAL_RENDER_SCHEMA
  ) {
    throw new TypeError('Internal page-render request identity is invalid.')
  }
  return Object.freeze({
    schema: value.schema,
    backendLineage: admitBackendComponentLineageEnvelope(value.backendLineage),
    sourceDocument: value.sourceDocument,
  })
}

export async function runInternalPageRenderChild(cwd = process.cwd()) {
  if (!isAbsolute(cwd) || (await realpath(cwd)) !== cwd) {
    throw new TypeError('Internal page-render working root is invalid.')
  }
  const loaded = await loadRenderPolicy()
  const requestBytes = await readRegularNoFollow(
    join(cwd, INTERNAL_RENDER_REQUEST_NAME),
    MAXIMUM_INTERNAL_REQUEST_BYTES,
  )
  const request = readCanonicalInput(
    requestBytes,
    exactInternalRenderRequest,
    'Internal page-render request',
  )
  const pdfBytes = await readRegularNoFollow(
    join(cwd, INTERNAL_PDF_NAME),
    loaded.policy.libreOffice.maximumPdfBytes,
  )
  const manifestBytes = await renderPagesToDirectory({
    pdfBytes,
    outputPath: join(cwd, INTERNAL_OUTPUT_NAME),
    backendLineage: request.backendLineage,
    sourceDocument: request.sourceDocument,
  })
  return Object.freeze({
    schema: INTERNAL_RENDER_SCHEMA,
    outcome: 'passed',
    manifestBytes: manifestBytes.byteLength,
    manifestSha256: sha256(manifestBytes),
  })
}

function invokedAsProgram() {
  return process.argv[1] === fileURLToPath(import.meta.url)
}

if (invokedAsProgram()) {
  const arguments_ = process.argv.slice(2)
  if (arguments_.length !== 1 || arguments_[0] !== '--internal-render-child') {
    process.exitCode = 64
  } else {
    runInternalPageRenderChild()
      .then((receipt) => {
        process.stdout.write(`${canonicalJson(receipt)}\n`)
      })
      .catch(() => {
        process.exitCode = 1
      })
  }
}
