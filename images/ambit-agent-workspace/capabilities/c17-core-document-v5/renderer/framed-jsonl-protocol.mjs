import { createHash } from 'node:crypto'

import {
  admitBackendComponentLineageEnvelope,
  canonicalJson,
} from './render-contracts.mjs'

export const FRAMED_JSONL_SCHEMA =
  'ambit.runtime-interface/docx-paginated-render-jsonl@1'
export const RAW_CHUNK_BYTES = 49_152
export const MAXIMUM_FRAME_LINE_BYTES = 70_000
const MAXIMUM_START_LINE_BYTES = 16_384
const NONCE = /^[0-9a-f]{32}$/

export class RenderProtocolCancellation extends Error {
  constructor() {
    super('Render request was cancelled by its exact protocol peer.')
    this.name = 'RenderProtocolCancellation'
  }
}

export class RenderTransportClosed extends Error {
  constructor() {
    super('Render PTY transport closed before helper completion.')
    this.name = 'RenderTransportClosed'
  }
}

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

function exactKeys(value, expected, label) {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).sort().join('\n') !== [...expected].sort().join('\n')
  ) {
    throw new TypeError(`${label} fields are invalid.`)
  }
  return value
}

function exactSha256(value, label) {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new TypeError(`${label} must be an exact SHA-256.`)
  }
  return value
}

function positiveSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer.`)
  }
  return value
}

function nonnegativeSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a nonnegative safe integer.`)
  }
  return value
}

function expectedChunkCount(bytes) {
  return Math.ceil(bytes / RAW_CHUNK_BYTES)
}

function exactNonce(value) {
  if (typeof value !== 'string' || !NONCE.test(value)) {
    throw new TypeError('Framed render nonce is invalid.')
  }
  return value
}

function decodeCanonicalLine(lineBytes, maximumBytes = MAXIMUM_FRAME_LINE_BYTES) {
  if (
    !Buffer.isBuffer(lineBytes) ||
    lineBytes.byteLength === 0 ||
    lineBytes.byteLength > maximumBytes ||
    lineBytes.includes(0x0d) ||
    lineBytes.includes(0x0a)
  ) {
    throw new TypeError('Framed JSONL line size or delimiter is invalid.')
  }
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(lineBytes)
  } catch (error) {
    throw new TypeError('Framed JSONL line is not exact UTF-8.', { cause: error })
  }
  let value
  try {
    value = JSON.parse(text)
  } catch (error) {
    throw new TypeError('Framed JSONL line is not JSON.', { cause: error })
  }
  if (canonicalJson(value) !== text) {
    throw new TypeError('Framed JSONL line is not canonical JSON.')
  }
  return value
}

function decodeBase64(value, expectedBytes) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > Math.ceil(RAW_CHUNK_BYTES / 3) * 4 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    throw new TypeError('Framed JSONL payload is not canonical base64.')
  }
  const bytes = Buffer.from(value, 'base64')
  if (
    bytes.byteLength !== expectedBytes ||
    bytes.toString('base64') !== value
  ) {
    throw new TypeError('Framed JSONL base64 bytes differ from their claim.')
  }
  return bytes
}

export class RenderRequestCollector {
  #aggregate = createHash('sha256')
  #backendLineage
  #buffers = []
  #chunkCount
  #documentBytes
  #documentSha256
  #nextIndex = 0
  #state = 'start'
  #maximumDocumentBytes
  #nonce

  constructor(maximumDocumentBytes, nonce) {
    this.#maximumDocumentBytes = positiveSafeInteger(
      maximumDocumentBytes,
      'Maximum request document bytes',
    )
    this.#nonce = exactNonce(nonce)
  }

  accept(lineBytes) {
    if (this.#state === 'complete') {
      throw new TypeError('Framed request contains data after request_end.')
    }
    const value = decodeCanonicalLine(
      lineBytes,
      this.#state === 'start'
        ? MAXIMUM_START_LINE_BYTES
        : MAXIMUM_FRAME_LINE_BYTES,
    )
    if (value.kind === 'cancel') {
      admitCancelFrame(value, this.#nonce)
      throw new RenderProtocolCancellation()
    }
    if (this.#state === 'start') {
      this.#acceptStart(value)
      return null
    }
    if (value.kind === 'document_chunk') {
      this.#acceptChunk(value)
      return null
    }
    if (value.kind === 'request_end') {
      return this.#acceptEnd(value)
    }
    throw new TypeError('Framed request kind or order is invalid.')
  }

  #acceptStart(value) {
    const frame = exactKeys(
      value,
      [
        'backendLineage',
        'chunkBytes',
        'chunkCount',
        'documentBytes',
        'documentSha256',
        'kind',
        'nonce',
        'schema',
      ],
      'Render request_start',
    )
    const documentBytes = positiveSafeInteger(
      frame.documentBytes,
      'Render request document bytes',
    )
    const chunkCount = positiveSafeInteger(
      frame.chunkCount,
      'Render request chunk count',
    )
    if (
      frame.schema !== FRAMED_JSONL_SCHEMA ||
      frame.kind !== 'request_start' ||
      frame.nonce !== this.#nonce ||
      frame.chunkBytes !== RAW_CHUNK_BYTES ||
      documentBytes > this.#maximumDocumentBytes ||
      chunkCount !== expectedChunkCount(documentBytes)
    ) {
      throw new TypeError('Render request_start identity or bounds are invalid.')
    }
    this.#backendLineage = admitBackendComponentLineageEnvelope(
      frame.backendLineage,
    )
    this.#documentBytes = documentBytes
    this.#documentSha256 = exactSha256(
      frame.documentSha256,
      'Render request document digest',
    )
    this.#chunkCount = chunkCount
    this.#state = 'chunks'
  }

  #acceptChunk(value) {
    const frame = exactKeys(
      value,
      ['base64', 'bytes', 'index', 'kind', 'nonce', 'schema', 'sha256'],
      'Render document_chunk',
    )
    const index = nonnegativeSafeInteger(
      frame.index,
      'Render document chunk index',
    )
    const bytes = positiveSafeInteger(
      frame.bytes,
      'Render document chunk bytes',
    )
    const remaining = this.#documentBytes - this.#nextIndex * RAW_CHUNK_BYTES
    const expectedBytes = Math.min(RAW_CHUNK_BYTES, remaining)
    if (
      frame.schema !== FRAMED_JSONL_SCHEMA ||
      frame.kind !== 'document_chunk' ||
      frame.nonce !== this.#nonce ||
      index !== this.#nextIndex ||
      index >= this.#chunkCount ||
      bytes !== expectedBytes
    ) {
      throw new TypeError('Render document_chunk order or bounds are invalid.')
    }
    const decoded = decodeBase64(frame.base64, bytes)
    if (sha256(decoded) !== exactSha256(frame.sha256, 'Document chunk digest')) {
      throw new TypeError('Render document_chunk digest differs.')
    }
    this.#aggregate.update(decoded)
    this.#buffers.push(decoded)
    this.#nextIndex += 1
  }

  #acceptEnd(value) {
    const frame = exactKeys(
      value,
      [
        'chunkCount',
        'documentBytes',
        'documentSha256',
        'kind',
        'nonce',
        'schema',
      ],
      'Render request_end',
    )
    if (
      frame.schema !== FRAMED_JSONL_SCHEMA ||
      frame.kind !== 'request_end' ||
      frame.nonce !== this.#nonce ||
      frame.chunkCount !== this.#chunkCount ||
      frame.documentBytes !== this.#documentBytes ||
      frame.documentSha256 !== this.#documentSha256 ||
      this.#nextIndex !== this.#chunkCount
    ) {
      throw new TypeError('Render request_end aggregate or order is invalid.')
    }
    const observedDigest = `sha256:${this.#aggregate.digest('hex')}`
    const document = Buffer.concat(this.#buffers, this.#documentBytes)
    if (
      document.byteLength !== this.#documentBytes ||
      observedDigest !== this.#documentSha256
    ) {
      throw new TypeError('Render request document aggregate differs.')
    }
    this.#state = 'complete'
    this.#buffers = []
    return Object.freeze({
      backendLineage: this.#backendLineage,
      document,
      documentSha256: observedDigest,
    })
  }
}

export class FramedJsonlLineReader {
  #iterator
  #pending = Buffer.alloc(0)
  #readable

  constructor(readable) {
    if (
      readable === null ||
      typeof readable !== 'object' ||
      typeof readable[Symbol.asyncIterator] !== 'function'
    ) {
      throw new TypeError('Framed JSONL input stream is invalid.')
    }
    this.#readable = readable
    this.#iterator = readable[Symbol.asyncIterator]()
  }

  async readLine(signal) {
    while (true) {
      const newline = this.#pending.indexOf(0x0a)
      if (newline >= 0) {
        const line = Buffer.from(this.#pending.subarray(0, newline))
        this.#pending = this.#pending.subarray(newline + 1)
        return line
      }
      if (this.#pending.byteLength > MAXIMUM_FRAME_LINE_BYTES) {
        throw new RangeError('Framed JSONL input line exceeds policy.')
      }
      if (signal?.aborted) throw signal.reason
      const abort = () => this.close(signal.reason)
      signal?.addEventListener('abort', abort, { once: true })
      let next
      try {
        next = await this.#iterator.next()
      } finally {
        signal?.removeEventListener('abort', abort)
      }
      if (next.done) {
        if (this.#pending.byteLength !== 0) {
          throw new TypeError('Framed JSONL input ended without a newline.')
        }
        return null
      }
      const chunk = Buffer.isBuffer(next.value)
        ? next.value
        : Buffer.from(next.value)
      this.#pending = Buffer.concat([this.#pending, chunk])
      if (this.#pending.byteLength > MAXIMUM_FRAME_LINE_BYTES * 2) {
        throw new RangeError('Framed JSONL input buffer exceeds policy.')
      }
    }
  }

  close(error) {
    if (!this.#readable.destroyed) this.#readable.destroy(error)
  }
}

export async function readRenderRequest(
  lineReader,
  maximumDocumentBytes,
  nonce,
  signal,
) {
  if (!(lineReader instanceof FramedJsonlLineReader)) {
    throw new TypeError('Render request requires one framed line reader.')
  }
  const collector = new RenderRequestCollector(maximumDocumentBytes, nonce)
  while (true) {
    const line = await lineReader.readLine(signal)
    if (line === null) {
      throw new TypeError('Framed request ended before request_end.')
    }
    const completed = collector.accept(line)
    if (completed) return completed
  }
}

function admitCancelFrame(value, nonce) {
  const frame = exactKeys(
    value,
    ['kind', 'nonce', 'schema'],
    'Render cancel',
  )
  if (
    frame.schema !== FRAMED_JSONL_SCHEMA ||
    frame.kind !== 'cancel' ||
    frame.nonce !== nonce
  ) {
    throw new TypeError('Render cancel identity is invalid.')
  }
  return frame
}

export async function watchRenderCancellation(lineReader, nonce) {
  exactNonce(nonce)
  if (!(lineReader instanceof FramedJsonlLineReader)) {
    throw new TypeError('Render cancellation requires one framed line reader.')
  }
  const line = await lineReader.readLine()
  if (line === null) {
    throw new RenderTransportClosed()
  }
  admitCancelFrame(decodeCanonicalLine(line, MAXIMUM_START_LINE_BYTES), nonce)
  throw new RenderProtocolCancellation()
}

export function encodeRenderRequestLines({ backendLineage, document, nonce }) {
  const admittedLineage = admitBackendComponentLineageEnvelope(backendLineage)
  const admittedNonce = exactNonce(nonce)
  if (!Buffer.isBuffer(document) || document.byteLength === 0) {
    throw new TypeError('Render request document is unavailable.')
  }
  const documentSha256 = sha256(document)
  const chunkCount = expectedChunkCount(document.byteLength)
  const lines = [
    canonicalFrameLine({
      schema: FRAMED_JSONL_SCHEMA,
      kind: 'request_start',
      nonce: admittedNonce,
      backendLineage: admittedLineage,
      documentBytes: document.byteLength,
      documentSha256,
      chunkBytes: RAW_CHUNK_BYTES,
      chunkCount,
    }),
  ]
  for (let index = 0; index < chunkCount; index += 1) {
    const bytes = document.subarray(
      index * RAW_CHUNK_BYTES,
      Math.min((index + 1) * RAW_CHUNK_BYTES, document.byteLength),
    )
    lines.push(
      canonicalFrameLine({
        schema: FRAMED_JSONL_SCHEMA,
        kind: 'document_chunk',
        nonce: admittedNonce,
        index,
        bytes: bytes.byteLength,
        sha256: sha256(bytes),
        base64: bytes.toString('base64'),
      }),
    )
  }
  lines.push(
    canonicalFrameLine({
      schema: FRAMED_JSONL_SCHEMA,
      kind: 'request_end',
      nonce: admittedNonce,
      documentBytes: document.byteLength,
      documentSha256,
      chunkCount,
    }),
  )
  return Object.freeze(lines)
}

export function canonicalFrameLine(value) {
  const line = Buffer.from(`${canonicalJson(value)}\n`)
  if (line.byteLength > MAXIMUM_FRAME_LINE_BYTES) {
    throw new RangeError('Framed JSONL output line exceeds policy.')
  }
  return line
}

export function createPayloadChunkFrame({ kind, index, bytes, extra = {} }) {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength === 0) {
    throw new TypeError('Response payload chunk is unavailable.')
  }
  return Object.freeze({
    ...extra,
    schema: FRAMED_JSONL_SCHEMA,
    kind,
    chunkIndex: index,
    bytes: bytes.byteLength,
    sha256: sha256(bytes),
    base64: bytes.toString('base64'),
  })
}

export function payloadChunkCount(bytes) {
  return expectedChunkCount(positiveSafeInteger(bytes, 'Payload bytes'))
}

export function digestBytes(bytes) {
  if (!Buffer.isBuffer(bytes)) {
    throw new TypeError('Digest input must be bytes.')
  }
  return sha256(bytes)
}
