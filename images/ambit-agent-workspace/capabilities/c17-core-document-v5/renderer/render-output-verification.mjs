import { createHash } from 'node:crypto'
import { lstat, readFile, readdir, realpath } from 'node:fs/promises'
import { isAbsolute, join } from 'node:path'

import { readRegularNoFollow } from './ambit-render-pages.mjs'
import {
  admitPngPageEvidence,
  canonicalJson,
  createRenderManifest,
} from './render-contracts.mjs'

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

export async function inspectRenderOutput({ packRoot, output }) {
  if (
    !isAbsolute(packRoot) ||
    !isAbsolute(output) ||
    (await realpath(packRoot)) !== packRoot ||
    (await realpath(output)) !== output
  ) {
    throw new TypeError('Render verification paths must be absolute and real.')
  }
  const directory = await lstat(output, { bigint: true })
  if (
    !directory.isDirectory() ||
    directory.isSymbolicLink() ||
    directory.uid !== BigInt(process.getuid()) ||
    (directory.mode & 0o777n) !== 0o700n
  ) {
    throw new TypeError('Render output directory identity is invalid.')
  }
  const policyPath = join(packRoot, 'policy/render-policy.json')
  const policyMetadata = await lstat(policyPath)
  if (!policyMetadata.isFile() || policyMetadata.isSymbolicLink()) {
    throw new TypeError('Installed render policy is not one regular file.')
  }
  const policyBytes = await readFile(policyPath)
  const policy = JSON.parse(policyBytes.toString('utf8'))
  const manifestBytes = await readRegularNoFollow(
    join(output, 'render-manifest.json'),
    1024 * 1024,
  )
  const manifest = JSON.parse(manifestBytes.toString('utf8'))
  if (`${canonicalJson(manifest)}\n` !== manifestBytes.toString('utf8')) {
    throw new TypeError('Render manifest is not canonical JSON.')
  }
  exactKeys(
    manifest,
    [
      'canonicalAuthority',
      'canonicalBoundary',
      'executionLineage',
      'intermediatePdf',
      'kind',
      'manifestDigest',
      'manifestRef',
      'pageCount',
      'pages',
      'policy',
      'schema',
      'sourceDocument',
      'totalOutputBytes',
      'totalPixels',
    ],
    'Render manifest',
  )
  exactKeys(
    manifest.intermediatePdf,
    ['bytes', 'digestDisposition'],
    'Intermediate PDF evidence',
  )
  if (
    manifest.intermediatePdf.digestDisposition !==
    'excluded_volatile_converter_metadata'
  ) {
    throw new TypeError('Intermediate PDF disposition is invalid.')
  }
  if (!Array.isArray(manifest.pages)) {
    throw new TypeError('Render page roster is invalid.')
  }
  const expectedFiles = ['render-manifest.json']
  const pages = []
  for (const page of manifest.pages) {
    exactKeys(
      page,
      [
        'bytes',
        'filename',
        'height',
        'index',
        'number',
        'pixels',
        'sha256',
        'width',
      ],
      'Render page',
    )
    const bytes = await readRegularNoFollow(
      join(output, page.filename),
      policy.pages.maximumBytesPerPage,
    )
    const admitted = admitPngPageEvidence(
      {
        index: page.index,
        number: page.number,
        width: page.width,
        height: page.height,
        pixels: page.pixels,
      },
      bytes,
    )
    if (canonicalJson(admitted) !== canonicalJson(page)) {
      throw new TypeError('Rendered page bytes differ from their evidence.')
    }
    expectedFiles.push(page.filename)
    pages.push(admitted)
  }
  const observedFiles = (await readdir(output)).sort()
  if (expectedFiles.sort().join('\n') !== observedFiles.join('\n')) {
    throw new TypeError('Render output file roster is not closed.')
  }
  const recreated = createRenderManifest({
    sourceDocument: manifest.sourceDocument,
    intermediatePdfBytes: manifest.intermediatePdf.bytes,
    policySha256: sha256(policyBytes),
    pages,
    policy,
    executionLineage: manifest.executionLineage,
  })
  if (`${canonicalJson(recreated)}\n` !== manifestBytes.toString('utf8')) {
    throw new TypeError('Render manifest identity or aggregate evidence differs.')
  }
  const verification = Object.freeze({
    schema: 'ambit.runtime-pack-render-output-verification/v1',
    outcome: 'passed',
    sourceDocument: recreated.sourceDocument,
    pageCount: recreated.pageCount,
    totalOutputBytes: recreated.totalOutputBytes,
    manifestDigest: recreated.manifestDigest,
  })
  return Object.freeze({
    manifest: recreated,
    manifestBytes,
    verification,
  })
}

export async function verifyRenderOutput(args) {
  return (await inspectRenderOutput(args)).verification
}
