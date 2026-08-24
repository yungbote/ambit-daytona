import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { deflateSync } from 'node:zlib'

import { admitRenderPolicy } from './render-contracts.mjs'
import {
  admitCanvasModule,
  renderPdfBytes,
} from './pdfjs-page-renderer.mjs'

const policy = admitRenderPolicy(
  JSON.parse(
    await readFile(new URL('../policy/render-policy.json', import.meta.url)),
  ),
)
const canvasPackage = { name: '@napi-rs/canvas', version: '1.0.7' }

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

function png(width, height, marker = 0) {
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

function fakeCanvas(overrides = {}) {
  return {
    createCanvas(width, height) {
      return {
        width,
        height,
        getContext() {
          return {}
        },
        async encode() {
          return png(width, height)
        },
      }
    },
    DOMMatrix: class DOMMatrix {},
    ImageData: class ImageData {},
    Path2D: class Path2D {},
    ...overrides,
  }
}

function fakePdfjs({ pageCount = 2, onGetPage, onDestroy } = {}) {
  return {
    version: '6.2.108',
    getDocument() {
      return {
        promise: Promise.resolve({
          numPages: pageCount,
          async getPage(number) {
            onGetPage?.(number)
            return {
              getViewport() {
                return { width: number, height: number + 1 }
              },
              render() {
                return { promise: Promise.resolve() }
              },
              cleanup() {},
            }
          },
          async cleanup() {},
        }),
        async destroy() {
          onDestroy?.()
        },
      }
    },
  }
}

test('admits package identity separately from the versionless Canvas module', () => {
  const admitted = admitCanvasModule(fakeCanvas(), canvasPackage)
  assert.equal(admitted.identity.version, '1.0.7')
  assert.equal(typeof admitted.module.Path2D, 'function')
  for (const missing of ['createCanvas', 'DOMMatrix', 'ImageData', 'Path2D']) {
    assert.throws(
      () =>
        admitCanvasModule(
          fakeCanvas({ [missing]: undefined }),
          canvasPackage,
        ),
      /exact PDF\.js Canvas implementation is unavailable/,
    )
  }
  assert.throws(
    () =>
      admitCanvasModule(fakeCanvas(), {
        name: '@napi-rs/canvas',
        version: '1.0.8',
      }),
    /exact PDF\.js Canvas identity is unavailable/,
  )
})

test('rejects an excessive document before fetching any page', async () => {
  let fetched = 0
  let destroyed = 0
  await assert.rejects(
    renderPdfBytes({
      pdfBytes: Buffer.from('%PDF-test'),
      policy,
      pdfjs: fakePdfjs({
        pageCount: policy.pages.maximumCount + 1,
        onGetPage: () => {
          fetched += 1
        },
        onDestroy: () => {
          destroyed += 1
        },
      }),
      canvas: fakeCanvas(),
      canvasPackage,
      sink: async () => {},
    }),
    /page count or document contract is invalid/,
  )
  assert.equal(fetched, 0)
  assert.equal(destroyed, 1)
})

test('uses the PDF bound rather than the smaller DOCX transport bound', async () => {
  let admittedBytes = 0
  let getDocumentCalls = 0
  const pdfjs = fakePdfjs({ pageCount: 1 })
  const getDocument = pdfjs.getDocument
  pdfjs.getDocument = (input) => {
    getDocumentCalls += 1
    admittedBytes = input.data.byteLength
    return getDocument(input)
  }
  const aboveDocxBound = Buffer.allocUnsafe(policy.input.maximumBytes + 1)
  const pages = await renderPdfBytes({
    pdfBytes: aboveDocxBound,
    policy,
    pdfjs,
    canvas: fakeCanvas(),
    canvasPackage,
    sink: async () => {},
  })
  assert.equal(pages.length, 1)
  assert.equal(admittedBytes, policy.input.maximumBytes + 1)
  assert.equal(getDocumentCalls, 1)

  await assert.rejects(
    renderPdfBytes({
      pdfBytes: Buffer.allocUnsafe(policy.libreOffice.maximumPdfBytes + 1),
      policy,
      pdfjs,
      canvas: fakeCanvas(),
      canvasPackage,
      sink: async () => {},
    }),
    /intermediate PDF policy/,
  )
  assert.equal(getDocumentCalls, 1)
})

test('streams pages sequentially and retains only immutable evidence', async () => {
  const cleanupCounts = new Map()
  let destroyed = 0
  let activeSinks = 0
  let maximumActiveSinks = 0
  const pdfjs = fakePdfjs({ onDestroy: () => (destroyed += 1) })
  const originalGetDocument = pdfjs.getDocument
  pdfjs.getDocument = function getDocument(input) {
    const task = originalGetDocument(input)
    return {
      ...task,
      promise: task.promise.then((document) => ({
        ...document,
        async getPage(number) {
          const page = await document.getPage(number)
          return {
            ...page,
            cleanup() {
              cleanupCounts.set(number, (cleanupCounts.get(number) ?? 0) + 1)
            },
          }
        },
      })),
    }
  }
  const sinkPages = []
  const evidence = await renderPdfBytes({
    pdfBytes: Buffer.from('%PDF-test'),
    policy,
    pdfjs,
    canvas: fakeCanvas(),
    canvasPackage,
    sink: async (page) => {
      activeSinks += 1
      maximumActiveSinks = Math.max(maximumActiveSinks, activeSinks)
      await Promise.resolve()
      sinkPages.push(page)
      activeSinks -= 1
    },
  })
  assert.equal(maximumActiveSinks, 1)
  assert.deepEqual([...cleanupCounts.values()], [2, 2])
  assert.equal(destroyed, 1)
  assert.equal(sinkPages.length, 2)
  assert.equal(evidence.length, 2)
  assert.equal(Object.hasOwn(evidence[0], 'bytes'), true)
  assert.equal(Object.hasOwn(evidence[0], 'body'), false)
  assert.equal(Buffer.isBuffer(evidence[0]), false)
})

test('cleans the page, surface, and document when the sink rejects', async () => {
  let cleanup = 0
  let destroyed = 0
  let surface
  const canvas = fakeCanvas({
    createCanvas(width, height) {
      surface = fakeCanvas().createCanvas(width, height)
      return surface
    },
  })
  const pdfjs = fakePdfjs({ pageCount: 1, onDestroy: () => (destroyed += 1) })
  const originalGetDocument = pdfjs.getDocument
  pdfjs.getDocument = function getDocument(input) {
    const task = originalGetDocument(input)
    return {
      ...task,
      promise: task.promise.then((document) => ({
        ...document,
        async getPage(number) {
          const page = await document.getPage(number)
          return { ...page, cleanup: () => (cleanup += 1) }
        },
      })),
    }
  }
  await assert.rejects(
    renderPdfBytes({
      pdfBytes: Buffer.from('%PDF-test'),
      policy,
      pdfjs,
      canvas,
      canvasPackage,
      sink: async () => {
        throw new Error('sink unavailable')
      },
    }),
    /sink unavailable/,
  )
  assert.equal(cleanup, 2)
  assert.equal(destroyed, 1)
  assert.equal(surface.width, 0)
  assert.equal(surface.height, 0)
})
