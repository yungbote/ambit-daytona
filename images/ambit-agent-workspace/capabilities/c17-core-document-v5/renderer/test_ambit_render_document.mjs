import assert from 'node:assert/strict'
import { execFile as execFileCallback } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import test from 'node:test'
import { promisify } from 'node:util'

import {
  convertDocxToPdf,
  streamSealedResponse,
} from './ambit-render-document.mjs'
import { makeDocx } from './test-support/docx-fixture.mjs'

const POLICY = {
  schema: 'ambit.runtime-pack-document-render-policy/v1',
  policyRef: 'ambit.render-policy/core-document-paginated@1',
  input: {
    formats: ['docx'],
    localImmutableBytesOnly: true,
    remoteUrls: 'forbidden',
    maximumBytes: 67108864,
    maximumEntryBytes: 67108864,
    maximumPackageEntries: 2048,
    maximumRelationshipBytes: 4194304,
    maximumUncompressedBytes: 268435456,
    maximumXmlAttributeBytes: 1048576,
    maximumXmlAttributesPerElement: 64,
    maximumXmlBytes: 4194304,
    maximumXmlDecodedTextBytes: 4194304,
    maximumXmlDepth: 64,
    maximumXmlEntityReferences: 65536,
    maximumXmlNodes: 65536,
    macros: 'disabled',
    externalLinks: 'disabled',
    passwordProtected: 'unsupported',
  },
  execution: {
    maximumChildStderrBytes: 65536,
    maximumChildStdoutBytes: 16384,
    maximumCleanupMilliseconds: 10000,
    maximumPipelineWallMilliseconds: 180000,
    maximumTerminalWriteMilliseconds: 5000,
  },
  libreOffice: {
    processModel: 'one-process-per-render',
    privateUserProfile: 'required',
    profileReuse: 'forbidden',
    headless: true,
    nologo: true,
    nodefault: true,
    norestore: true,
    nolockcheck: true,
    maximumPdfBytes: 268435456,
    maximumWallMilliseconds: 120000,
  },
  pages: {
    maximumCount: 512,
    maximumBytesPerPage: 67108864,
    maximumWidthPixels: 20000,
    maximumHeightPixels: 20000,
    maximumPixelsPerPage: 100000000,
    maximumTotalPixels: 536870912,
    maximumTotalOutputBytes: 536870912,
    rasterScale: 2,
    background: '#ffffff',
    pngEncoding: 'napi-rs-canvas-png-default-v1',
    orderedZeroBasedRosterRequired: true,
    exactPngSha256Required: true,
  },
  pdfjs: {
    bytesInputOnly: true,
    localStaticResourcesOnly: true,
    workerVersionMustEqualApiVersion: true,
    standardFonts: 'unsupported-until-license-corrected-and-frozen',
    popplerFallback: 'forbidden',
    requiredGlobals: ['DOMMatrix', 'ImageData', 'Path2D'],
    canvasFactory: 'ambit.pdfjs-canvas-factory/napi-rs@1',
    executionState: 'available',
  },
  scratch: {
    cacheRequiredBytes: 67108864,
    derivation:
      'max(input-docx+intermediate-pdf,intermediate-pdf+page-output)+bounded-overhead',
    workspaceOverheadBytes: 33554432,
    workspaceRequiredBytes: 838860800,
  },
  canonicalArtifactBoundary: 'external-commit-only',
  renderOutputGrantsCanonicalAuthority: false,
}

const DOCX = makeDocx()
const PDF = Buffer.from('%PDF-1.7\n%%EOF\n')
const execFile = promisify(execFileCallback)

test('converts through one bounded private LibreOffice invocation', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'ambit-document-wrapper-'))
  const cache = await mkdtemp(join(tmpdir(), 'ambit-document-cache-'))
  try {
    let invocation
    const converted = await convertDocxToPdf({
      documentBytes: DOCX,
      policy: POLICY,
      workspaceRoot: workspace,
      cacheRoot: cache,
      execute: async (options) => {
        invocation = options
        const output = options.arguments[options.arguments.indexOf('--outdir') + 1]
        await writeFile(join(output, 'document.pdf'), PDF)
        return { stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
      },
    })
    assert.equal(
      invocation.executable,
      '/opt/ambit/runtime-pack/core-document-v5/bin/ambit-structural-python',
    )
    assert.deepEqual(invocation.arguments.slice(0, 7), [
      '/opt/ambit/runtime-pack/core-document-v5/renderer/process-group-subreaper.py',
      '/usr/bin/libreoffice',
      '--headless',
      '--nologo',
      '--nodefault',
      '--norestore',
      '--nolockcheck',
    ])
    assert.equal(invocation.maximumWallMilliseconds, 120000)
    assert.equal(invocation.env.SAL_USE_VCLPLUGIN, 'svp')
    assert.equal(invocation.env.PATH, '/usr/bin:/bin')
    assert.deepEqual(converted.pdfBytes, PDF)
    await converted.dispose()
    assert.deepEqual(await readdir(workspace), [])
    assert.deepEqual(await readdir(cache), [])
  } finally {
    await rm(workspace, { recursive: true, force: true })
    await rm(cache, { recursive: true, force: true })
  }
})

test('rejects non-DOCX input before granting process authority', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'ambit-document-wrapper-'))
  const cache = await mkdtemp(join(tmpdir(), 'ambit-document-cache-'))
  try {
    let invoked = false
    await assert.rejects(
      convertDocxToPdf({
        documentBytes: Buffer.from('not a docx'),
        policy: POLICY,
        workspaceRoot: workspace,
        cacheRoot: cache,
        execute: async () => {
          invoked = true
        },
      }),
      /not one bounded DOCX/,
    )
    assert.equal(invoked, false)
    assert.deepEqual(await readdir(workspace), [])
    assert.deepEqual(await readdir(cache), [])
  } finally {
    await rm(workspace, { recursive: true, force: true })
    await rm(cache, { recursive: true, force: true })
  }
})

test('removes private staging when conversion output is noncanonical', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'ambit-document-wrapper-'))
  const cache = await mkdtemp(join(tmpdir(), 'ambit-document-cache-'))
  try {
    await assert.rejects(
      convertDocxToPdf({
        documentBytes: DOCX,
        policy: POLICY,
        workspaceRoot: workspace,
        cacheRoot: cache,
        execute: async (options) => {
          const output =
            options.arguments[options.arguments.indexOf('--outdir') + 1]
          await writeFile(join(output, 'unexpected.pdf'), PDF)
        },
      }),
      /one exact PDF output/,
    )
    assert.deepEqual(await readdir(workspace), [])
    assert.deepEqual(await readdir(cache), [])
  } finally {
    await rm(workspace, { recursive: true, force: true })
    await rm(cache, { recursive: true, force: true })
  }
})

test('cleans the held mount rosters after hostile root renames', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'ambit-document-wrapper-'))
  const cache = await mkdtemp(join(tmpdir(), 'ambit-document-cache-'))
  try {
    await assert.rejects(
      convertDocxToPdf({
        documentBytes: DOCX,
        policy: POLICY,
        workspaceRoot: workspace,
        cacheRoot: cache,
        execute: async (options) => {
          await rename(options.cwd, join(workspace, 'renamed-operation-root'))
          await rename(options.env.HOME, join(cache, 'renamed-cache-root'))
          throw new Error('hostile child renamed both private roots')
        },
      }),
      /hostile child renamed both private roots/,
    )
    assert.deepEqual(await readdir(workspace), [])
    assert.deepEqual(await readdir(cache), [])
  } finally {
    await rm(workspace, { recursive: true, force: true })
    await rm(cache, { recursive: true, force: true })
  }
})

test('admits the exact PDF limit and rejects its first excess byte', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'ambit-document-wrapper-'))
  const cache = await mkdtemp(join(tmpdir(), 'ambit-document-cache-'))
  const policy = {
    ...POLICY,
    libreOffice: {
      ...POLICY.libreOffice,
      maximumPdfBytes: PDF.byteLength,
    },
  }
  try {
    const convert = (outputBytes) =>
      convertDocxToPdf({
        documentBytes: DOCX,
        policy,
        workspaceRoot: workspace,
        cacheRoot: cache,
        execute: async (options) => {
          const output =
            options.arguments[options.arguments.indexOf('--outdir') + 1]
          await writeFile(join(output, 'document.pdf'), outputBytes)
          return { stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
        },
      })
    const exact = await convert(PDF)
    await exact.dispose()
    await assert.rejects(
      convert(Buffer.concat([PDF, Buffer.from('x')])),
      /bounded immutable regular file/,
    )
    assert.deepEqual(await readdir(workspace), [])
    assert.deepEqual(await readdir(cache), [])
  } finally {
    await rm(workspace, { recursive: true, force: true })
    await rm(cache, { recursive: true, force: true })
  }
})

test('the installed-style CLI fails closed without plaintext PTY diagnostics', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ambit-document-launcher-'))
  try {
    const launcher = join(directory, 'ambit-render-document.mjs')
    await symlink(new URL('./ambit-render-document.mjs', import.meta.url), launcher)
    await assert.rejects(
      execFile(process.execPath, [launcher], { encoding: 'utf8' }),
      (error) => {
        assert.equal(error.code, 1)
        assert.equal(error.stdout, '')
        assert.equal(error.stderr, '')
        return true
      },
    )
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

test('streams only nonce-bound bounded frames and a digest-bound terminal', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ambit-document-response-'))
  const output = join(root, 'output')
  await mkdir(output, { mode: 0o700 })
  const pageBytes = Buffer.alloc(50_000, 0x5a)
  const page = Object.freeze({
    index: 0,
    number: 1,
    filename: 'page-0001.png',
    width: 10,
    height: 20,
    pixels: 200,
    bytes: pageBytes.byteLength,
    sha256: `sha256:${createHash('sha256').update(pageBytes).digest('hex')}`,
  })
  const manifestBytes = Buffer.from('{"sealed":true}\n')
  const nonce = 'a'.repeat(32)
  const chunks = []
  const writable = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(Buffer.from(chunk))
      callback()
    },
  })
  try {
    await writeFile(join(output, page.filename), pageBytes)
    await chmod(join(output, page.filename), 0o444)
    const terminal = await streamSealedResponse({
      sealed: {
        outputPath: output,
        manifestBytes,
        manifest: {
          pages: [page],
          pageCount: 1,
          totalOutputBytes: pageBytes.byteLength,
          manifestDigest: `sha256:${'1'.repeat(64)}`,
          policy: {
            ref: 'ambit.render-policy/core-document-paginated@1',
            digest: `sha256:${'2'.repeat(64)}`,
          },
        },
      },
      nonce,
      writable,
    })
    const lines = Buffer.concat(chunks).toString('utf8').trimEnd().split('\n')
    const frames = lines.map((line) => JSON.parse(line))
    assert.deepEqual(
      frames.map((frame) => frame.kind),
      [
        'page_start',
        'page_chunk',
        'page_chunk',
        'manifest_start',
        'manifest_chunk',
        'response_end',
      ],
    )
    assert.ok(frames.every((frame) => frame.nonce === nonce))
    assert.equal(terminal.outcome, 'passed')
    assert.equal(terminal.exitCode, 0)
    const preceding = Buffer.from(`${lines.slice(0, -1).join('\n')}\n`)
    assert.equal(
      terminal.streamSha256,
      `sha256:${createHash('sha256').update(preceding).digest('hex')}`,
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
