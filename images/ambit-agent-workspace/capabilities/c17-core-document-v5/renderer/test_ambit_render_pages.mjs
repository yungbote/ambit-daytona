import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { deflateSync } from 'node:zlib'

import {
  admitExactRenderEvidence,
  admitRenderExecutionLineage,
  admitPngPageEvidence,
  admitRenderPolicy,
  canonicalJson,
  composeRenderExecutionLineage,
  createRenderManifest,
  planPageDimensions,
} from './render-contracts.mjs'

const policy = admitRenderPolicy(
  JSON.parse(
    await readFile(new URL('../policy/render-policy.json', import.meta.url)),
  ),
)

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

function pngChunk(type, data) {
  const typeBytes = Buffer.from(type, 'ascii')
  const output = Buffer.alloc(12 + data.byteLength)
  output.writeUInt32BE(data.byteLength, 0)
  typeBytes.copy(output, 4)
  data.copy(output, 8)
  output.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])), 8 + data.length)
  return output
}

function testPng(width, height, marker = 0) {
  const header = Buffer.alloc(13)
  header.writeUInt32BE(width, 0)
  header.writeUInt32BE(height, 4)
  header[8] = 8
  header[9] = 6
  const rows = Buffer.alloc(height * (1 + width * 4))
  rows[1] = marker
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk('IHDR', header),
    pngChunk('IDAT', deflateSync(rows)),
    pngChunk('IEND', Buffer.alloc(0)),
  ])
}

function pin(name, digit) {
  return { ref: name, digest: `sha256:${digit.repeat(64)}` }
}

function executionLineage(backendDigest = '5') {
  return composeRenderExecutionLineage({
    backendComponentLineage: {
      schemaRef: 'ambit.backend-contract/runtime-component-lineage@pending',
      ref: 'backend-runtime-component-lineage:fixture',
      digest: `sha256:${backendDigest.repeat(64)}`,
      canonicalBytesSha256: `sha256:${'6'.repeat(64)}`,
    },
    installedEngineLineage: {
      schema: 'ambit.runtime-pack-installed-render-engine-lineage/v1',
      nodeBinary: pin('runtime-component-input:node-v24.19.0', 'b'),
      pdfjsRoster: pin('runtime-component-input:pdfjs-6.2.108', 'c'),
      canvasSource: pin(
        'runtime-component-input:napi-canvas-source-1.0.7',
        'd',
      ),
      canvasNative: pin(
        'runtime-component-input:napi-canvas-linux-x64-1.0.7',
        'e',
      ),
      libreOfficeClosure: pin(
        'runtime-component-input:libreoffice-writer',
        'f',
      ),
      fontManifest: pin('runtime-component-input:noto-fonts', '0'),
    },
  })
}

test('plans an exact zero-based page roster', () => {
  assert.deepEqual(
    planPageDimensions(
      [
        { width: 1224, height: 1584 },
        { width: 100.1, height: 200.1 },
      ],
      policy,
    ),
    [
      { index: 0, number: 1, width: 1224, height: 1584, pixels: 1938816 },
      { index: 1, number: 2, width: 101, height: 201, pixels: 20301 },
    ],
  )
})

test('rejects page count, per-page dimensions, and aggregate pixels', () => {
  assert.throws(
    () =>
      planPageDimensions(
        Array.from({ length: policy.pages.maximumCount + 1 }, () => ({
          width: 1,
          height: 1,
        })),
        policy,
      ),
    /page-count policy/,
  )
  assert.throws(
    () =>
      planPageDimensions(
        [{ width: policy.pages.maximumWidthPixels + 1, height: 1 }],
        policy,
      ),
    /raster dimension policy/,
  )
  const smallAggregatePolicy = structuredClone(policy)
  smallAggregatePolicy.pages.maximumTotalPixels = 100
  assert.throws(
    () =>
      planPageDimensions(
        [
          { width: 10, height: 10 },
          { width: 1, height: 1 },
        ],
        smallAggregatePolicy,
      ),
    /total pixel policy/,
  )
})

test('binds exact PNG bytes and rejects non-PNG output', () => {
  const [plan] = planPageDimensions([{ width: 10, height: 20 }], policy)
  const png = testPng(10, 20, 7)
  const evidence = admitPngPageEvidence(plan, png)
  assert.deepEqual(evidence, {
    index: 0,
    number: 1,
    filename: 'page-0001.png',
    width: 10,
    height: 20,
    pixels: 200,
    bytes: png.byteLength,
    sha256: `sha256:${createHash('sha256').update(png).digest('hex')}`,
  })
  assert.throws(
    () =>
      admitPngPageEvidence(
        plan,
        Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
      ),
    /not a complete PNG/,
  )
  assert.throws(
    () => admitPngPageEvidence(plan, testPng(11, 20)),
    /dimensions differ/,
  )
})

test('creates deterministic byte-free candidate lineage with no authority', () => {
  const plans = planPageDimensions(
    [
      { width: 10, height: 20 },
      { width: 30, height: 40 },
    ],
    policy,
  )
  const pages = plans.map((plan, index) =>
    admitPngPageEvidence(plan, testPng(plan.width, plan.height, index)),
  )
  const input = {
    sourceDocument: {
      format: 'docx',
      sha256: `sha256:${'1'.repeat(64)}`,
      bytes: 2048,
    },
    intermediatePdfBytes: 1024,
    policySha256: `sha256:${'2'.repeat(64)}`,
    pages,
    policy,
    executionLineage: executionLineage(),
  }
  const first = createRenderManifest(input)
  const second = createRenderManifest(input)
  assert.equal(canonicalJson(first), canonicalJson(second))
  assert.equal(first.canonicalAuthority, 'none')
  assert.equal(first.canonicalBoundary, 'external_artifact_commit')
  assert.equal(first.executionLineage.backendComponentLineage.digest, `sha256:${'5'.repeat(64)}`)
  assert.match(
    first.manifestRef,
    /^runtime-paginated-render-manifest:sha256:[0-9a-f]{64}$/,
  )
  const changed = createRenderManifest({
    ...input,
    sourceDocument: {
      ...input.sourceDocument,
      sha256: `sha256:${'3'.repeat(64)}`,
    },
  })
  assert.notEqual(first.manifestDigest, changed.manifestDigest)
})

test('rejects reordered pages and substituted engine lineage', () => {
  const plans = planPageDimensions(
    [
      { width: 10, height: 20 },
      { width: 30, height: 40 },
    ],
    policy,
  )
  const pages = plans.map((plan, index) =>
    admitPngPageEvidence(plan, testPng(plan.width, plan.height, index)),
  )
  const base = {
    sourceDocument: {
      format: 'docx',
      sha256: `sha256:${'1'.repeat(64)}`,
      bytes: 2048,
    },
    intermediatePdfBytes: 1024,
    policySha256: `sha256:${'2'.repeat(64)}`,
    pages,
    policy,
    executionLineage: executionLineage(),
  }
  assert.throws(
    () => createRenderManifest({ ...base, pages: [...pages].reverse() }),
    /page order or identity/,
  )
  assert.throws(
    () =>
      createRenderManifest({
        ...base,
        executionLineage: {
          ...base.executionLineage,
          canvasNative: pin('runtime-component-input:substituted', '1'),
        },
      }),
    /not canonical or exact/,
  )
})

test('shares exact source, PDF, page, and aggregate evidence bounds', () => {
  const page = admitPngPageEvidence(
    { index: 0, number: 1, width: 10, height: 20, pixels: 200 },
    testPng(10, 20),
  )
  const base = {
    sourceDocument: {
      format: 'docx',
      sha256: `sha256:${'1'.repeat(64)}`,
      bytes: policy.input.maximumBytes,
    },
    intermediatePdfBytes: policy.libreOffice.maximumPdfBytes,
    pages: [page],
    policy,
  }
  const admitted = admitExactRenderEvidence(base)
  assert.equal(admitted.pages[0].pixels, 200)
  assert.equal(admitted.pageCount, 1)

  assert.throws(
    () =>
      admitExactRenderEvidence({
        ...base,
        sourceDocument: {
          ...base.sourceDocument,
          bytes: policy.input.maximumBytes + 1,
        },
      }),
    /source or intermediate PDF exceeds/,
  )
  assert.throws(
    () =>
      admitExactRenderEvidence({
        ...base,
        intermediatePdfBytes: policy.libreOffice.maximumPdfBytes + 1,
      }),
    /source or intermediate PDF exceeds/,
  )
  for (const mutation of [
    { ...page, pixels: page.pixels + 1 },
    { ...page, number: 2 },
    { ...page, filename: '../page-0001.png' },
    { ...page, width: policy.pages.maximumWidthPixels + 1 },
    { ...page, height: policy.pages.maximumHeightPixels + 1 },
    { ...page, bytes: policy.pages.maximumBytesPerPage + 1 },
  ]) {
    assert.throws(
      () => admitExactRenderEvidence({ ...base, pages: [mutation] }),
      /page order or identity, dimensions, or bounds/,
    )
  }
})

test('binds opaque backend-lineage substitutions into execution identity', () => {
  const first = executionLineage('5')
  const changed = executionLineage('6')
  assert.notEqual(first.lineageDigest, changed.lineageDigest)
  assert.equal(
    canonicalJson(admitRenderExecutionLineage(first)),
    canonicalJson(first),
  )
})

test('external backend envelopes cannot supply or substitute engine pins', () => {
  assert.throws(
    () =>
      composeRenderExecutionLineage({
        backendComponentLineage: {
          schemaRef: 'ambit.backend-contract/runtime-component-lineage@pending',
          ref: 'backend-runtime-component-lineage:fixture',
          digest: `sha256:${'5'.repeat(64)}`,
          canonicalBytesSha256: `sha256:${'6'.repeat(64)}`,
          nodeBinary: pin('caller-controlled-node', '7'),
        },
        installedEngineLineage: {
          schema: 'ambit.runtime-pack-installed-render-engine-lineage/v1',
          nodeBinary: pin('runtime-component-input:node-v24.19.0', 'b'),
          pdfjsRoster: pin('runtime-component-input:pdfjs-6.2.108', 'c'),
          canvasSource: pin('runtime-component-input:canvas-source', 'd'),
          canvasNative: pin('runtime-component-input:canvas-native', 'e'),
          libreOfficeClosure: pin('runtime-component-input:libreoffice', 'f'),
          fontManifest: pin('runtime-component-input:fonts', '0'),
        },
      }),
    /External backend component lineage fields are invalid/,
  )
})

test('rejects proxy, accessor, symbol, and sparse canonical inputs', () => {
  assert.throws(() => canonicalJson(new Proxy({}, {})), /plain data record/)
  const accessor = {}
  Object.defineProperty(accessor, 'value', {
    enumerable: true,
    get() {
      throw new Error('getter must never run')
    },
  })
  assert.throws(() => canonicalJson(accessor), /own data/)
  assert.throws(() => canonicalJson({ [Symbol('field')]: 1 }), /symbol fields/)
  const sparse = []
  sparse.length = 1
  assert.throws(() => canonicalJson(sparse), /dense and field-free/)
})
