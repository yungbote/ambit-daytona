import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { deflateSync } from 'node:zlib'

import { verifyRenderOutput } from './verify_render_output.mjs'
import {
  admitPngPageEvidence,
  canonicalJson,
  composeRenderExecutionLineage,
  createRenderManifest,
} from '../renderer/render-contracts.mjs'

const PACK_ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const policyBytes = await readFile(join(PACK_ROOT, 'policy/render-policy.json'))
const policy = JSON.parse(policyBytes)

function crc32(bytes) {
  let crc = 0xffffffff
  for (const byte of bytes) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1
    }
  }
  return (crc ^ 0xffffffff) >>> 0
}

function chunk(type, data) {
  const typeBytes = Buffer.from(type)
  const output = Buffer.alloc(12 + data.length)
  output.writeUInt32BE(data.length, 0)
  typeBytes.copy(output, 4)
  data.copy(output, 8)
  output.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])), 8 + data.length)
  return output
}

function png() {
  const header = Buffer.alloc(13)
  header.writeUInt32BE(1, 0)
  header.writeUInt32BE(1, 4)
  header[8] = 8
  header[9] = 6
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(Buffer.alloc(5))),
    chunk('IEND', Buffer.alloc(0)),
  ])
}

function pin(ref, digit) {
  return { ref, digest: `sha256:${digit.repeat(64)}` }
}

function lineage() {
  return composeRenderExecutionLineage({
    backendComponentLineage: {
      schemaRef: 'fixture-schema',
      ref: 'fixture-lineage',
      digest: `sha256:${'1'.repeat(64)}`,
      canonicalBytesSha256: `sha256:${'2'.repeat(64)}`,
    },
    installedEngineLineage: {
      schema: 'ambit.runtime-pack-installed-render-engine-lineage/v1',
      nodeBinary: pin('node', '3'),
      pdfjsRoster: pin('pdfjs', '4'),
      canvasSource: pin('canvas-source', '5'),
      canvasNative: pin('canvas-native', '6'),
      libreOfficeClosure: pin('libreoffice', '7'),
      fontManifest: pin('fonts', '8'),
    },
  })
}

async function fixture() {
  const output = await mkdtemp(join(tmpdir(), 'ambit-render-output-'))
  const pageBytes = png()
  const page = admitPngPageEvidence(
    { index: 0, number: 1, width: 1, height: 1, pixels: 1 },
    pageBytes,
  )
  const manifest = createRenderManifest({
    sourceDocument: {
      format: 'docx',
      sha256: `sha256:${'9'.repeat(64)}`,
      bytes: 100,
    },
    intermediatePdfBytes: 200,
    policySha256: `sha256:${createHash('sha256').update(policyBytes).digest('hex')}`,
    pages: [page],
    policy,
    executionLineage: lineage(),
  })
  await writeFile(join(output, page.filename), pageBytes)
  await writeFile(join(output, 'render-manifest.json'), `${canonicalJson(manifest)}\n`)
  await chmod(join(output, page.filename), 0o444)
  await chmod(join(output, 'render-manifest.json'), 0o444)
  return output
}

test('recomputes the closed page and manifest evidence', async () => {
  const output = await fixture()
  try {
    const result = await verifyRenderOutput({ packRoot: PACK_ROOT, output })
    assert.equal(result.outcome, 'passed')
    assert.equal(result.pageCount, 1)
  } finally {
    await rm(output, { recursive: true, force: true })
  }
})

test('rejects substituted page bytes and extra output files', async () => {
  const output = await fixture()
  try {
    const page = join(output, 'page-0001.png')
    await chmod(page, 0o644)
    await writeFile(page, Buffer.from('substituted'))
    await chmod(page, 0o444)
    await assert.rejects(
      verifyRenderOutput({ packRoot: PACK_ROOT, output }),
      /Rendered page bytes/,
    )
  } finally {
    await rm(output, { recursive: true, force: true })
  }

  const extraOutput = await fixture()
  try {
    await writeFile(join(extraOutput, 'extra'), 'unexpected')
    await chmod(join(extraOutput, 'extra'), 0o444)
    await assert.rejects(
      verifyRenderOutput({ packRoot: PACK_ROOT, output: extraOutput }),
      /file roster is not closed/,
    )
  } finally {
    await rm(extraOutput, { recursive: true, force: true })
  }
})
