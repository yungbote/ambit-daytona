import { createHash } from 'node:crypto'
import { lstat, readFile, readdir, realpath } from 'node:fs/promises'
import { isAbsolute, join } from 'node:path'

import {
  holdTaskPrivateDirectory,
  readRegularNoFollow,
  reproveOutputDirectory,
} from './ambit-render-pages.mjs'
import {
  admitExactRenderEvidence,
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
  const directory = await holdTaskPrivateDirectory(output)
  try {
    const policyPath = join(packRoot, 'policy/render-policy.json')
    const policyMetadata = await lstat(policyPath)
    if (!policyMetadata.isFile() || policyMetadata.isSymbolicLink()) {
      throw new TypeError('Installed render policy is not one regular file.')
    }
    const policyBytes = await readFile(policyPath)
    const policy = JSON.parse(policyBytes.toString('utf8'))
    const heldDirectoryPath = `/proc/self/fd/${directory.handle.fd}`
    const manifestBytes = await readRegularNoFollow(
      join(heldDirectoryPath, 'render-manifest.json'),
      1024 * 1024,
    )
    const manifestText = manifestBytes.toString('utf8')
    const manifest = JSON.parse(manifestText)
    if (`${canonicalJson(manifest)}\n` !== manifestText) {
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
    const exactEvidence = admitExactRenderEvidence({
      sourceDocument: manifest.sourceDocument,
      intermediatePdfBytes: manifest.intermediatePdf.bytes,
      pages: manifest.pages,
      policy,
    })
    const expectedFiles = ['render-manifest.json']
    const pages = []
    for (const page of exactEvidence.pages) {
      const bytes = await readRegularNoFollow(
        join(heldDirectoryPath, page.filename),
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
    const observedFiles = (await readdir(heldDirectoryPath)).sort()
    if (expectedFiles.sort().join('\n') !== observedFiles.join('\n')) {
      throw new TypeError('Render output file roster is not closed.')
    }
    const recreated = createRenderManifest({
      sourceDocument: exactEvidence.sourceDocument,
      intermediatePdfBytes: exactEvidence.intermediatePdf.bytes,
      policySha256: sha256(policyBytes),
      pages,
      policy,
      executionLineage: manifest.executionLineage,
    })
    if (`${canonicalJson(recreated)}\n` !== manifestText) {
      throw new TypeError('Render manifest identity or aggregate evidence differs.')
    }
    await reproveOutputDirectory(output, directory.identity)
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
  } finally {
    await directory.handle.close()
  }
}

export async function verifyRenderOutput(args) {
  return (await inspectRenderOutput(args)).verification
}
