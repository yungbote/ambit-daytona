import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import test from 'node:test'

import {
  convertOfficePdfRequest,
  convertOfficeToPdf,
  streamOfficePdfResponseBody,
} from './ambit-render-document.mjs'
import {
  admitOfficePackage,
  OFFICE_FORMATS,
} from './docx-package-admission.mjs'
import {
  encodeRenderRequestLines,
  RenderRequestCollector,
  OFFICE_PDF_JSONL_SCHEMA,
} from './framed-jsonl-protocol.mjs'
import { canonicalJson } from './render-contracts.mjs'
import { makeDocx, DOCX_LIMITS } from './test-support/docx-fixture.mjs'

const policy = JSON.parse(
  await readFile(new URL('../policy/office-pdf-policy.json', import.meta.url)),
)
const nonce = 'a'.repeat(32)
const digest = (bytes) =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`
const backendLineage = Object.freeze({
  schemaRef: 'ambit.backend-contract/runtime-component-lineage@1',
  ref: `runtime-component-lineage:sha256:${'b'.repeat(64)}`,
  digest: `sha256:${'b'.repeat(64)}`,
  canonicalBytesSha256: `sha256:${'c'.repeat(64)}`,
})
const pdfBytes = Buffer.concat([
  Buffer.from('%PDF-1.7\n'),
  Buffer.alloc(50_000, 32),
  Buffer.from('\n%%EOF\n'),
])

function officeEntries(format) {
  const profile = OFFICE_FORMATS[format]
  return [
    {
      name: '[Content_Types].xml',
      bytes: Buffer.from(
        `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/${profile.mainPart}" ContentType="${profile.mainContentType}"/></Types>`,
      ),
    },
    {
      name: '_rels/.rels',
      bytes: Buffer.from(
        `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="${profile.mainPart}"/></Relationships>`,
      ),
    },
    { name: profile.mainPart, bytes: Buffer.from('<document/>') },
  ]
}

function officeBytes(format) {
  return makeDocx(officeEntries(format))
}

for (const format of Object.keys(OFFICE_FORMATS)) {
  test(`${format} uses its actual package identity and the shared bounded conversion`, async () => {
    const document = officeBytes(format)
    admitOfficePackage(document, DOCX_LIMITS, format)
    for (const mismatch of Object.keys(OFFICE_FORMATS).filter(
      (value) => value !== format,
    )) {
      assert.throws(() => admitOfficePackage(document, DOCX_LIMITS, mismatch))
    }
    const workspaceRoot = await mkdtemp(
      join(tmpdir(), 'ambit-office-workspace-'),
    )
    const cacheRoot = await mkdtemp(join(tmpdir(), 'ambit-office-cache-'))
    let sealed
    try {
      const signal = new AbortController().signal
      let calls = 0
      sealed = await convertOfficePdfRequest(
        {
          document,
          documentMediaType: OFFICE_FORMATS[format].mediaType,
          documentSha256: digest(document),
          backendLineage,
        },
        {
          loadedPolicy: { policy },
          workspaceRoot,
          cacheRoot,
          signal,
          execute: async (input) => {
            calls += 1
            assert.equal(input.signal, signal)
            assert.equal(
              input.maximumWallMilliseconds,
              policy.libreOffice.maximumWallMilliseconds,
            )
            assert.ok(input.arguments.at(-1).endsWith(`document.${format}`))
            assert.deepEqual(await readFile(input.arguments.at(-1)), document)
            const output =
              input.arguments[input.arguments.indexOf('--outdir') + 1]
            await writeFile(join(output, 'document.pdf'), pdfBytes)
            return { stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
          },
        },
      )
      assert.equal(calls, 1)
      assert.deepEqual(sealed.pdfBytes, pdfBytes)
      assert.deepEqual(sealed.source, {
        mediaType: OFFICE_FORMATS[format].mediaType,
        sha256: digest(document),
        bytes: document.byteLength,
      })
      await sealed.dispose()
      sealed = null
      assert.deepEqual(await readdir(workspaceRoot), [])
      assert.deepEqual(await readdir(cacheRoot), [])
    } finally {
      await sealed?.dispose()
      await rm(workspaceRoot, { recursive: true, force: true })
      await rm(cacheRoot, { recursive: true, force: true })
    }
  })
}

test('binds the root Office relationship to the declared media kind', () => {
  for (const format of Object.keys(OFFICE_FORMATS)) {
    const profile = OFFICE_FORMATS[format]
    const wrong = officeEntries(format)
    wrong[1].bytes = Buffer.from(
      wrong[1].bytes
        .toString()
        .replace(
          `Target="${profile.mainPart}"`,
          'Target="different/document.xml"',
        ),
    )
    wrong.push({
      name: 'different/document.xml',
      bytes: Buffer.from('<document/>'),
    })
    assert.throws(
      () => admitOfficePackage(makeDocx(wrong), DOCX_LIMITS, format),
      /root relationship/,
    )
    for (const target of [`./${profile.mainPart}`, `/${profile.mainPart}`]) {
      const equivalent = officeEntries(format)
      equivalent[1].bytes = Buffer.from(
        equivalent[1].bytes
          .toString()
          .replace(`Target="${profile.mainPart}"`, `Target="${target}"`),
      )
      admitOfficePackage(makeDocx(equivalent), DOCX_LIMITS, format)
    }
    const duplicate = officeEntries(format)
    duplicate[1].bytes = Buffer.from(
      duplicate[1].bytes
        .toString()
        .replace(
          '</Relationships>',
          `<Relationship Id="another" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="${profile.mainPart}"/></Relationships>`,
        ),
    )
    assert.throws(
      () => admitOfficePackage(makeDocx(duplicate), DOCX_LIMITS, format),
      /exactly one main/,
    )
  }
})

test('Office frames bind exact MIME, source, lineage, ordered bytes and conversion output', async () => {
  const document = officeBytes('pptx')
  const documentMediaType = OFFICE_FORMATS.pptx.mediaType
  const lines = encodeRenderRequestLines({
    backendLineage,
    document,
    nonce,
    documentMediaType,
  })
  const collector = new RenderRequestCollector(
    policy.input.maximumBytes,
    nonce,
    OFFICE_PDF_JSONL_SCHEMA,
  )
  let request
  for (const line of lines) request = collector.accept(line.subarray(0, -1))
  assert.equal(request.documentMediaType, documentMediaType)
  assert.deepEqual(request.document, document)
  const legacy = new RenderRequestCollector(policy.input.maximumBytes, nonce)
  assert.throws(() => legacy.accept(lines[0].subarray(0, -1)))
  const chunks = []
  const writable = new Writable({
    write(chunk, encoding, callback) {
      chunks.push(Buffer.from(chunk))
      callback()
    },
  })
  const source = {
    mediaType: documentMediaType,
    sha256: digest(document),
    bytes: document.byteLength,
  }
  const terminal = await streamOfficePdfResponseBody({
    sealed: { pdfBytes, source, backendLineage },
    nonce,
    writable,
  })
  const response = Buffer.concat(chunks)
  const frames = response.toString('utf8').trim().split('\n').map(JSON.parse)
  assert.deepEqual(
    frames.map((frame) => frame.kind),
    ['pdf_start', 'pdf_chunk', 'pdf_chunk'],
  )
  assert.deepEqual(frames[0].source, source)
  assert.deepEqual(frames[0].backendLineage, backendLineage)
  assert.deepEqual(
    Buffer.concat(
      frames.slice(1).map((frame) => Buffer.from(frame.base64, 'base64')),
    ),
    pdfBytes,
  )
  assert.equal(terminal.streamSha256, digest(response))
  assert.equal(terminal.pdfSha256, digest(pdfBytes))
  assert.equal(terminal.frameCount, frames.length)
  assert.equal(
    Buffer.from(`${canonicalJson(terminal)}\n`).includes(
      Buffer.from('response_end'),
    ),
    true,
  )
})

test('cancellation reaches the single converter and removes its private roots', async () => {
  const workspaceRoot = await mkdtemp(
    join(tmpdir(), 'ambit-office-stop-workspace-'),
  )
  const cacheRoot = await mkdtemp(join(tmpdir(), 'ambit-office-stop-cache-'))
  const controller = new AbortController()
  try {
    await assert.rejects(
      convertOfficeToPdf({
        documentBytes: officeBytes('xlsx'),
        mediaType: OFFICE_FORMATS.xlsx.mediaType,
        policy,
        workspaceRoot,
        cacheRoot,
        signal: controller.signal,
        execute: async ({ signal }) => {
          assert.equal(signal, controller.signal)
          controller.abort(new Error('stopped'))
          signal.throwIfAborted()
        },
      }),
      /stopped/,
    )
    assert.deepEqual(await readdir(workspaceRoot), [])
    assert.deepEqual(await readdir(cacheRoot), [])
  } finally {
    await rm(workspaceRoot, { recursive: true, force: true })
    await rm(cacheRoot, { recursive: true, force: true })
  }
})
