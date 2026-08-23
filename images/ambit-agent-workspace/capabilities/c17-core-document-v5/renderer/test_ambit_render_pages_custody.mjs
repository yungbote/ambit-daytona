import assert from 'node:assert/strict'
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import {
  admitEmptyOutputDirectory,
  parseArguments,
  readRegularNoFollow,
  reproveOutputDirectory,
  writeDurableOutput,
} from './ambit-render-pages.mjs'

async function temporaryRoot(run) {
  const root = await mkdtemp(join(tmpdir(), 'ambit-render-custody-'))
  try {
    return await run(root)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

test('parses only the authority-explicit CLI argument roster', () => {
  assert.deepEqual(
    parseArguments([
      '--input',
      '/input.pdf',
      '--output',
      '/output',
      '--backend-lineage',
      '/lineage.json',
    ]),
    {
      input: '/input.pdf',
      output: '/output',
      backendLineage: '/lineage.json',
    },
  )
  assert.throws(
    () =>
      parseArguments([
        '--input',
        '/input.pdf',
        '--output',
        '/output',
        '--lineage',
        '/lineage.json',
      ]),
    /--backend-lineage/,
  )
})

test('reads one no-follow immutable file and rejects writable or linked inputs', async () => {
  await temporaryRoot(async (root) => {
    const input = join(root, 'input.pdf')
    await writeFile(input, 'exact bytes', { mode: 0o444 })
    assert.equal((await readRegularNoFollow(input, 1024)).toString(), 'exact bytes')

    await chmod(input, 0o644)
    await assert.rejects(
      readRegularNoFollow(input, 1024),
      /bounded immutable regular file/,
    )
    await chmod(input, 0o444)

    const alias = join(root, 'alias.pdf')
    await symlink(input, alias)
    await assert.rejects(readRegularNoFollow(alias, 1024))
  })
})

test('writes exclusive fsynced files and rejects directory replacement', async () => {
  await temporaryRoot(async (root) => {
    const outputPath = join(root, 'output')
    await mkdir(outputPath, { mode: 0o700 })
    const output = await admitEmptyOutputDirectory(outputPath)
    try {
      const body = Buffer.from('candidate bytes')
      await writeDurableOutput(output, 'page-0001.png', body)
      assert.equal(
        await readFile(join(outputPath, 'page-0001.png'), 'utf8'),
        body.toString(),
      )
      assert.equal((await lstat(join(outputPath, 'page-0001.png'))).mode & 0o777, 0o444)
      await assert.rejects(
        writeDurableOutput(output, 'page-0001.png', body),
      )
      await assert.rejects(
        writeDurableOutput(output, '../escape', body),
        /filename is not canonical/,
      )

      const moved = join(root, 'moved-output')
      await rename(outputPath, moved)
      await mkdir(outputPath, { mode: 0o700 })
      await assert.rejects(
        reproveOutputDirectory(outputPath, output.identity),
        /identity changed/,
      )
      await assert.rejects(
        writeDurableOutput(output, 'render-manifest.json', body),
        /identity changed/,
      )
    } finally {
      await output.handle.close()
    }
  })
})
