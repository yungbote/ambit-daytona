import assert from 'node:assert/strict'
import test from 'node:test'

import { admitDocxPackage } from './docx-package-admission.mjs'
import {
  DOCX_LIMITS,
  makeDocx,
  minimalDocxEntries,
} from './test-support/docx-fixture.mjs'

test('admits one bounded macro-free internal OOXML package', () => {
  const admitted = admitDocxPackage(makeDocx(), DOCX_LIMITS)
  assert.equal(admitted.entryCount, 3)
  assert.ok(admitted.totalUncompressedBytes > admitted.relationshipBytes)
})

test('rejects external relationships and active embedded parts', () => {
  const external = minimalDocxEntries()
  external[1] = {
    ...external[1],
    bytes: Buffer.from(
      '<Relationships><Relationship Target="https://example.invalid" TargetMode="External"/></Relationships>',
    ),
  }
  assert.throws(
    () => admitDocxPackage(makeDocx(external), DOCX_LIMITS),
    /external relationship/,
  )

  const macro = [
    ...minimalDocxEntries(),
    { name: 'word/vbaProject.bin', bytes: Buffer.from('not admitted') },
  ]
  assert.throws(
    () => admitDocxPackage(makeDocx(macro), DOCX_LIMITS),
    /active or externally loaded part/,
  )
})

test('rejects encryption, duplicate names, and missing required parts', () => {
  const encrypted = minimalDocxEntries()
  encrypted[0] = { ...encrypted[0], flags: 1 }
  assert.throws(
    () => admitDocxPackage(makeDocx(encrypted), DOCX_LIMITS),
    /metadata is unsupported/,
  )
  assert.throws(
    () =>
      admitDocxPackage(
        makeDocx([...minimalDocxEntries(), minimalDocxEntries()[0]]),
        DOCX_LIMITS,
      ),
    /duplicated/,
  )
  assert.throws(
    () => admitDocxPackage(makeDocx(minimalDocxEntries().slice(0, 2)), DOCX_LIMITS),
    /omits required part/,
  )
})

test('rejects malformed directory data, checksum drift, and expansion limits', () => {
  const malformed = makeDocx()
  malformed.writeUInt32LE(0, malformed.byteLength - 22)
  assert.throws(
    () => admitDocxPackage(malformed, DOCX_LIMITS),
    /no exact terminal ZIP directory/,
  )

  const checksum = makeDocx()
  checksum[30 + checksum.readUInt16LE(26)] ^= 0xff
  assert.throws(
    () => admitDocxPackage(checksum, DOCX_LIMITS),
    /invalid|checksum differs/,
  )

  assert.throws(
    () =>
      admitDocxPackage(makeDocx(), {
        ...DOCX_LIMITS,
        maximumUncompressedBytes: 32,
      }),
    /uncompressed bytes exceeds/,
  )
  assert.throws(
    () =>
      admitDocxPackage(makeDocx(), {
        ...DOCX_LIMITS,
        maximumPackageEntries: 2,
      }),
    /topology is unsupported or exceeds policy/,
  )
})
