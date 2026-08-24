import assert from 'node:assert/strict'
import { Readable } from 'node:stream'
import test from 'node:test'

import {
  encodeRenderRequestLines,
  FramedJsonlLineReader,
  FRAMED_JSONL_SCHEMA,
  RAW_CHUNK_BYTES,
  readRenderRequest,
  RenderRequestCollector,
  RenderProtocolCancellation,
} from './framed-jsonl-protocol.mjs'

const LINEAGE = Object.freeze({
  schemaRef: 'ambit.runtime-component-lineage/v1',
  ref: 'runtime-component-lineage:fixture',
  digest: `sha256:${'1'.repeat(64)}`,
  canonicalBytesSha256: `sha256:${'2'.repeat(64)}`,
})
const NONCE = 'a'.repeat(32)

test('round-trips canonical ordered string-safe request chunks', async () => {
  const document = Buffer.alloc(RAW_CHUNK_BYTES + 17, 0xa5)
  const lines = encodeRenderRequestLines({
    backendLineage: LINEAGE,
    document,
    nonce: NONCE,
  })
  assert.equal(lines.length, 4)
  assert.ok(lines.every((line) => line.at(-1) === 0x0a))
  const request = await readRenderRequest(
    new FramedJsonlLineReader(Readable.from(lines)),
    2 * RAW_CHUNK_BYTES,
    NONCE,
  )
  assert.deepEqual(request.backendLineage, LINEAGE)
  assert.deepEqual(request.document, document)
})

test('rejects reordered, substituted, and noncanonical request lines', () => {
  const document = Buffer.from('exact document bytes')
  const lines = encodeRenderRequestLines({
    backendLineage: LINEAGE,
    document,
    nonce: NONCE,
  }).map((line) => line.subarray(0, -1))

  const reordered = new RenderRequestCollector(1024, NONCE)
  reordered.accept(lines[0])
  assert.throws(() => reordered.accept(lines[2]), /order|request_end/)

  const substituted = new RenderRequestCollector(1024, NONCE)
  substituted.accept(lines[0])
  const chunk = JSON.parse(lines[1])
  chunk.sha256 = `sha256:${'0'.repeat(64)}`
  assert.throws(
    () => substituted.accept(Buffer.from(JSON.stringify(chunk))),
    /digest differs/,
  )

  const pretty = Buffer.from(
    JSON.stringify(
      {
        schema: FRAMED_JSONL_SCHEMA,
        kind: 'request_start',
      },
      null,
      2,
    ),
  )
  assert.throws(
    () => new RenderRequestCollector(1024, NONCE).accept(pretty),
    /delimiter|canonical/,
  )
})

test('rejects oversized aggregate claims before retaining payload bytes', () => {
  const lines = encodeRenderRequestLines({
    backendLineage: LINEAGE,
    document: Buffer.alloc(1025),
    nonce: NONCE,
  })
  assert.throws(
    () =>
      new RenderRequestCollector(1024, NONCE).accept(
        lines[0].subarray(0, -1),
      ),
    /bounds are invalid/,
  )
})

test('admits cancellation only from the exact nonce-bound protocol peer', () => {
  const collector = new RenderRequestCollector(1024, NONCE)
  assert.throws(
    () =>
      collector.accept(
        Buffer.from(
          `{"kind":"cancel","nonce":"${NONCE}","schema":"${FRAMED_JSONL_SCHEMA}"}`,
        ),
      ),
    RenderProtocolCancellation,
  )
  assert.throws(
    () =>
      new RenderRequestCollector(1024, NONCE).accept(
        Buffer.from(
          `{"kind":"cancel","nonce":"${'b'.repeat(32)}","schema":"${FRAMED_JSONL_SCHEMA}"}`,
        ),
      ),
    /cancel identity is invalid/,
  )
})
