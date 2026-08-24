import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { Writable } from 'node:stream'

import { streamSealedResponseBody } from './ambit-render-document.mjs'
import { RenderTerminalArbiter } from './render-terminal-arbiter.mjs'

test('linearizes cancellation and success at one synchronous commit point', async () => {
  for (const first of ['cancel', 'success']) {
    const arbiter = new RenderTerminalArbiter()
    const cancellation = new Error('exact peer cancel')
    if (first === 'cancel') {
      assert.equal(arbiter.cancel(cancellation), true)
      assert.equal(arbiter.commitSuccess(), false)
      assert.equal(arbiter.state, 'cancelled')
      assert.equal(arbiter.reason, cancellation)
    } else {
      assert.equal(arbiter.commitSuccess(), true)
      assert.equal(arbiter.cancel(cancellation), false)
      assert.equal(arbiter.state, 'success-committed')
      arbiter.completeSuccess()
      assert.equal(arbiter.state, 'succeeded')
    }
  }
})

test('turns cleanup or terminal failure into failure even after a prior claim', () => {
  for (const initial of ['cancelled', 'success-committed']) {
    const arbiter = new RenderTerminalArbiter()
    if (initial === 'cancelled') arbiter.cancel(new Error('cancel'))
    else arbiter.commitSuccess()
    const failure = new Error('cleanup failed')
    assert.equal(arbiter.fail(failure), true)
    assert.equal(arbiter.state, 'failed')
    assert.equal(arbiter.reason, failure)
    assert.equal(arbiter.cancel(new Error('late cancel')), false)
  }
})

test('aborts a backpressured response write without emitting a terminal', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ambit-terminal-backpressure-'))
  const outputPath = join(root, 'output')
  await mkdir(outputPath, { mode: 0o700 })
  const pageBytes = Buffer.alloc(128, 0x5a)
  const page = {
    index: 0,
    number: 1,
    filename: 'page-0001.png',
    width: 8,
    height: 4,
    pixels: 32,
    bytes: pageBytes.byteLength,
    sha256: `sha256:${createHash('sha256').update(pageBytes).digest('hex')}`,
  }
  await writeFile(join(outputPath, page.filename), pageBytes)
  await chmod(join(outputPath, page.filename), 0o444)
  let destroyed = false
  let writes = 0
  let resolveStarted
  const started = new Promise((resolve) => {
    resolveStarted = resolve
  })
  const writable = new Writable({
    write(_chunk, _encoding, _callback) {
      writes += 1
      resolveStarted()
    },
    destroy(_error, callback) {
      destroyed = true
      callback()
    },
  })
  const controller = new AbortController()
  const running = streamSealedResponseBody({
    sealed: {
      outputPath,
      manifestBytes: Buffer.from('{"exact":true}\n'),
      manifest: {
        pages: [page],
        pageCount: 1,
        totalOutputBytes: pageBytes.byteLength,
        manifestDigest: `sha256:${'1'.repeat(64)}`,
        policy: {
          ref: 'ambit.render-policy/core-document-paginated@1',
          digest: `sha256:${'2'.repeat(64)}`,
        },
      },
    },
    nonce: 'a'.repeat(32),
    writable,
    signal: controller.signal,
  })
  await started
  controller.abort(new Error('hostile cancel during backpressure'))
  try {
    await assert.rejects(running, /hostile cancel during backpressure/)
    assert.equal(writes, 1)
    assert.equal(destroyed, true)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
