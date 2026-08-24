#!/usr/bin/env node

import { isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalJson } from '../renderer/render-contracts.mjs'
import { verifyRenderOutput } from '../renderer/render-output-verification.mjs'

function parseArguments(argv) {
  if (
    argv.length !== 4 ||
    argv[0] !== '--pack-root' ||
    argv[2] !== '--output' ||
    !isAbsolute(argv[1]) ||
    !isAbsolute(argv[3])
  ) {
    throw new TypeError(
      'Expected --pack-root ABSOLUTE_PATH --output ABSOLUTE_DIRECTORY.',
    )
  }
  return { packRoot: argv[1], output: argv[3] }
}

async function main() {
  process.stdout.write(
    `${canonicalJson(await verifyRenderOutput(parseArguments(process.argv.slice(2))))}\n`,
  )
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`render output verification failed: ${error.message}\n`)
    process.exitCode = 1
  })
}

export { verifyRenderOutput }
