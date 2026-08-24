import assert from 'node:assert/strict'
import { PassThrough, Readable } from 'node:stream'
import test from 'node:test'

import {
  canonicalFrameLine,
  encodeRenderRequestLines,
  FramedJsonlLineReader,
  FRAMED_JSONL_SCHEMA,
  RAW_CHUNK_BYTES,
  readRenderRequest,
  RenderControlAdmissionClosed,
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

test('rejects normalized-but-nonidentical UTF-8 bytes for every inbound kind', () => {
  const request = encodeRenderRequestLines({
    backendLineage: LINEAGE,
    document: Buffer.from('exact document bytes'),
    nonce: NONCE,
  }).map((line) => line.subarray(0, -1))
  const cancel = canonicalFrameLine({
    schema: FRAMED_JSONL_SCHEMA,
    kind: 'cancel',
    nonce: NONCE,
  }).subarray(0, -1)
  const cases = [
    { name: 'request_start', line: request[0], prefix: [] },
    { name: 'document_chunk', line: request[1], prefix: [request[0]] },
    {
      name: 'request_end',
      line: request[2],
      prefix: [request[0], request[1]],
    },
    { name: 'cancel', line: cancel, prefix: [] },
  ]
  for (const { name, line, prefix } of cases) {
    const parsed = JSON.parse(line)
    const reversed = Buffer.from(
      JSON.stringify(Object.fromEntries(Object.entries(parsed).reverse())),
    )
    const escapedSlash = Buffer.from(line.toString('utf8').replace('/', '\\/'))
    const mutants = [
      Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), line]),
      Buffer.concat([Buffer.from(' '), line]),
      Buffer.concat([line, Buffer.from(' ')]),
      reversed,
      escapedSlash,
    ]
    for (const [index, mutant] of mutants.entries()) {
      const collector = new RenderRequestCollector(1024, NONCE)
      for (const admitted of prefix) collector.accept(admitted)
      assert.throws(
        () => collector.accept(mutant),
        /canonical JSON|not JSON/,
        `${name} mutant ${index}`,
      )
    }
  }
})

test('preserves the success-commit close reason across iterator rejection', async () => {
  const input = new PassThrough()
  const reader = new FramedJsonlLineReader(input)
  const pending = reader.readLine()
  await new Promise((resolve) => setImmediate(resolve))
  const reason = new RenderControlAdmissionClosed()
  reader.close(reason)
  await assert.rejects(pending, (error) => error === reason)
})
