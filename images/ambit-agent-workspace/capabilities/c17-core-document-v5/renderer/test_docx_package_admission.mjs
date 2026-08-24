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
      '<r:Relationships xmlns:r="http://schemas.openxmlformats.org/package/2006/relationships"><r:Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="h&#x74;tps://example.invalid" TargetMode="Ext&#101;rnal"/></r:Relationships>',
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

test('decodes XML entities before macro, ActiveX, OLE, and external decisions', () => {
  const contentTypes = minimalDocxEntries()
  contentTypes[0] = {
    ...contentTypes[0],
    bytes: Buffer.from(
      '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabl&#101;d.main+xml"/></Types>',
    ),
  }
  assert.throws(
    () => admitDocxPackage(makeDocx(contentTypes), DOCX_LIMITS),
    /active or invalid|main document content type/,
  )

  for (const escapedType of ['act&#x69;veX', 'oleObj&#101;ct']) {
    const relationships = minimalDocxEntries()
    relationships[1] = {
      ...relationships[1],
      bytes: Buffer.from(
        `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/${escapedType}" Target="word/document.xml"/></Relationships>`,
      ),
    }
    assert.throws(
      () => admitDocxPackage(makeDocx(relationships), DOCX_LIMITS),
      /relationship identity or target is unsafe/,
    )
  }

  const disguisedExternal = minimalDocxEntries()
  disguisedExternal[1] = {
    ...disguisedExternal[1],
    bytes: Buffer.from(
      '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="h&#x74;tp://example.invalid"/></Relationships>',
    ),
  }
  assert.throws(
    () => admitDocxPackage(makeDocx(disguisedExternal), DOCX_LIMITS),
    /relationship identity or target is unsafe/,
  )
})

test('rejects DTD authority and bounded XML expansion classes', () => {
  const dtd = minimalDocxEntries()
  dtd[0] = {
    ...dtd[0],
    bytes: Buffer.from(
      '<!DOCTYPE Types [<!ENTITY x "macroEnabled">]><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="&x;"/></Types>',
    ),
  }
  assert.throws(
    () => admitDocxPackage(makeDocx(dtd), DOCX_LIMITS),
    /DTD, CDATA, or processing authority/,
  )

  for (const [field, value, message] of [
    ['maximumXmlNodes', 1, /nodes exceed/],
    ['maximumXmlDepth', 1, /depth exceeds/],
    ['maximumXmlAttributesPerElement', 1, /attributes per element exceed/],
    ['maximumXmlAttributeBytes', 8, /attribute bytes exceed/],
    ['maximumXmlDecodedTextBytes', 8, /decoded text bytes exceed/],
    ['maximumXmlBytes', 64, /bytes are unavailable, oversized/],
  ]) {
    assert.throws(
      () =>
        admitDocxPackage(makeDocx(), {
          ...DOCX_LIMITS,
          [field]: value,
        }),
      message,
      field,
    )
  }

  const entities = minimalDocxEntries()
  entities[0] = {
    ...entities[0],
    bytes: Buffer.from(
      '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/docum&#101;nt.xm&#108;" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
    ),
  }
  assert.throws(
    () =>
      admitDocxPackage(makeDocx(entities), {
        ...DOCX_LIMITS,
        maximumXmlEntityReferences: 1,
      }),
    /entity references exceed/,
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
