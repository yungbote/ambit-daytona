import { inflateRawSync } from 'node:zlib'

const CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50
const END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50
const LOCAL_FILE_SIGNATURE = 0x04034b50
const MAXIMUM_ZIP_COMMENT_BYTES = 0xffff
const ALLOWED_GENERAL_PURPOSE_FLAGS = 0x080e
const REQUIRED_PARTS = Object.freeze([
  '[Content_Types].xml',
  '_rels/.rels',
  'word/document.xml',
])
const FORBIDDEN_PART = /(?:^|\/)(?:activeX|embeddings|externalLinks)(?:\/|$)|(?:^|\/)vbaProject(?:Signature)?\.bin$|\.(?:html?|mht|mhtml)$/iu
const DOCUMENT_CONTENT_TYPE =
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'
const FORBIDDEN_CONTENT_TYPE =
  /macroEnabled|vbaProject|activeX|oleObject|xhtml|html/iu
const EXTERNAL_RELATIONSHIP = /\bTargetMode\s*=/u

function exactPositiveSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer.`)
  }
  return value
}

function admitLimits(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('DOCX package limits are invalid.')
  }
  return Object.freeze({
    maximumEntryBytes: exactPositiveSafeInteger(
      value.maximumEntryBytes,
      'DOCX maximum entry bytes',
    ),
    maximumPackageEntries: exactPositiveSafeInteger(
      value.maximumPackageEntries,
      'DOCX maximum package entries',
    ),
    maximumRelationshipBytes: exactPositiveSafeInteger(
      value.maximumRelationshipBytes,
      'DOCX maximum relationship bytes',
    ),
    maximumUncompressedBytes: exactPositiveSafeInteger(
      value.maximumUncompressedBytes,
      'DOCX maximum uncompressed bytes',
    ),
  })
}

function findEndOfCentralDirectory(bytes) {
  const minimum = Math.max(0, bytes.byteLength - 22 - MAXIMUM_ZIP_COMMENT_BYTES)
  for (let offset = bytes.byteLength - 22; offset >= minimum; offset -= 1) {
    if (
      bytes.readUInt32LE(offset) === END_OF_CENTRAL_DIRECTORY_SIGNATURE &&
      offset + 22 + bytes.readUInt16LE(offset + 20) === bytes.byteLength
    ) {
      return offset
    }
  }
  throw new TypeError('DOCX package has no exact terminal ZIP directory.')
}

function addBounded(left, right, maximum, label) {
  const total = left + right
  if (!Number.isSafeInteger(total) || total > maximum) {
    throw new RangeError(`${label} exceeds its package policy.`)
  }
  return total
}

function decodePartName(bytes, flags) {
  if (
    bytes.byteLength === 0 ||
    ((flags & 0x0800) === 0 && bytes.some((byte) => byte > 0x7f))
  ) {
    throw new TypeError('DOCX package part name encoding is unsupported.')
  }
  const name = bytes.toString('utf8')
  if (!Buffer.from(name, 'utf8').equals(bytes)) {
    throw new TypeError('DOCX package part name is not exact UTF-8.')
  }
  const parts = name.split('/')
  const directory = name.endsWith('/')
  const pathParts = directory ? parts.slice(0, -1) : parts
  if (
    name.includes('\\') ||
    name.includes('\0') ||
    name.startsWith('/') ||
    pathParts.length === 0 ||
    pathParts.some((part) => part === '' || part === '.' || part === '..')
  ) {
    throw new TypeError('DOCX package part name is unsafe or noncanonical.')
  }
  return name
}

function exactSlice(bytes, start, length, label) {
  const end = start + length
  if (
    !Number.isSafeInteger(start) ||
    !Number.isSafeInteger(length) ||
    !Number.isSafeInteger(end) ||
    start < 0 ||
    length < 0 ||
    end > bytes.byteLength
  ) {
    throw new TypeError(`${label} exceeds the DOCX package.`)
  }
  return bytes.subarray(start, end)
}

function readEntry(bytes, entry, limits) {
  const local = entry.localOffset
  if (
    local + 30 > entry.centralOffset ||
    bytes.readUInt32LE(local) !== LOCAL_FILE_SIGNATURE
  ) {
    throw new TypeError('DOCX local file header is missing or overlaps metadata.')
  }
  const localFlags = bytes.readUInt16LE(local + 6)
  const localMethod = bytes.readUInt16LE(local + 8)
  const localNameLength = bytes.readUInt16LE(local + 26)
  const localExtraLength = bytes.readUInt16LE(local + 28)
  const localName = exactSlice(
    bytes,
    local + 30,
    localNameLength,
    'DOCX local part name',
  )
  if (
    localFlags !== entry.flags ||
    localMethod !== entry.method ||
    !localName.equals(entry.nameBytes)
  ) {
    throw new TypeError('DOCX local and central file identities differ.')
  }
  const dataStart = local + 30 + localNameLength + localExtraLength
  const compressed = exactSlice(
    bytes,
    dataStart,
    entry.compressedBytes,
    'DOCX compressed part',
  )
  if (dataStart + compressed.byteLength > entry.centralDirectoryStart) {
    throw new TypeError('DOCX part data overlaps the central directory.')
  }
  let output
  if (entry.method === 0) {
    output = Buffer.from(compressed)
  } else {
    try {
      output = inflateRawSync(compressed, {
        maxOutputLength: limits.maximumEntryBytes,
      })
    } catch (error) {
      throw new TypeError('DOCX compressed part is invalid or exceeds policy.', {
        cause: error,
      })
    }
  }
  if (
    output.byteLength !== entry.uncompressedBytes ||
    crc32(output) !== entry.crc32
  ) {
    throw new TypeError('DOCX part size or checksum differs from its directory.')
  }
  return output
}

function xmlText(bytes, label) {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    if (text.includes('\0')) {
      throw new TypeError(`${label} contains a NUL byte.`)
    }
    return text
  } catch (error) {
    if (error instanceof TypeError && error.message.includes(label)) throw error
    throw new TypeError(`${label} is not exact UTF-8 XML.`, { cause: error })
  }
}

export function admitDocxPackage(bytes, limitValue) {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength < 22) {
    throw new TypeError('Input is not one bounded DOCX package.')
  }
  const limits = admitLimits(limitValue)
  const eocd = findEndOfCentralDirectory(bytes)
  const disk = bytes.readUInt16LE(eocd + 4)
  const centralDisk = bytes.readUInt16LE(eocd + 6)
  const diskEntries = bytes.readUInt16LE(eocd + 8)
  const entryCount = bytes.readUInt16LE(eocd + 10)
  const centralBytes = bytes.readUInt32LE(eocd + 12)
  const centralOffset = bytes.readUInt32LE(eocd + 16)
  if (
    disk !== 0 ||
    centralDisk !== 0 ||
    diskEntries !== entryCount ||
    entryCount === 0 ||
    entryCount === 0xffff ||
    entryCount > limits.maximumPackageEntries ||
    centralBytes === 0xffffffff ||
    centralOffset === 0xffffffff ||
    centralOffset + centralBytes !== eocd
  ) {
    throw new TypeError(
      'DOCX ZIP directory topology is unsupported or exceeds policy.',
    )
  }

  const entries = new Map()
  let cursor = centralOffset
  let totalUncompressedBytes = 0
  for (let index = 0; index < entryCount; index += 1) {
    if (
      cursor + 46 > eocd ||
      bytes.readUInt32LE(cursor) !== CENTRAL_DIRECTORY_SIGNATURE
    ) {
      throw new TypeError('DOCX central directory is truncated or reordered.')
    }
    const flags = bytes.readUInt16LE(cursor + 8)
    const method = bytes.readUInt16LE(cursor + 10)
    const checksum = bytes.readUInt32LE(cursor + 16)
    const compressedBytes = bytes.readUInt32LE(cursor + 20)
    const uncompressedBytes = bytes.readUInt32LE(cursor + 24)
    const nameLength = bytes.readUInt16LE(cursor + 28)
    const extraLength = bytes.readUInt16LE(cursor + 30)
    const commentLength = bytes.readUInt16LE(cursor + 32)
    const startDisk = bytes.readUInt16LE(cursor + 34)
    const localOffset = bytes.readUInt32LE(cursor + 42)
    const recordBytes = 46 + nameLength + extraLength + commentLength
    const nameBytes = exactSlice(
      bytes,
      cursor + 46,
      nameLength,
      'DOCX central part name',
    )
    const name = decodePartName(nameBytes, flags)
    if (
      cursor + recordBytes > eocd ||
      startDisk !== 0 ||
      localOffset === 0xffffffff ||
      compressedBytes === 0xffffffff ||
      uncompressedBytes === 0xffffffff ||
      (flags & ~ALLOWED_GENERAL_PURPOSE_FLAGS) !== 0 ||
      ![0, 8].includes(method) ||
      uncompressedBytes > limits.maximumEntryBytes ||
      entries.has(name)
    ) {
      throw new TypeError(
        'DOCX part metadata is unsupported, duplicated, or exceeds policy.',
      )
    }
    if (method === 0 && compressedBytes !== uncompressedBytes) {
      throw new TypeError('Stored DOCX part sizes differ.')
    }
    totalUncompressedBytes = addBounded(
      totalUncompressedBytes,
      uncompressedBytes,
      limits.maximumUncompressedBytes,
      'DOCX uncompressed bytes',
    )
    entries.set(
      name,
      Object.freeze({
        name,
        nameBytes: Buffer.from(nameBytes),
        flags,
        method,
        crc32: checksum,
        compressedBytes,
        uncompressedBytes,
        localOffset,
        centralOffset: cursor,
        centralDirectoryStart: centralOffset,
      }),
    )
    cursor += recordBytes
  }
  const firstLocalOffset = Math.min(
    ...[...entries.values()].map((entry) => entry.localOffset),
  )
  if (cursor !== eocd || firstLocalOffset !== 0) {
    throw new TypeError('DOCX central directory has unbound bytes or a preamble.')
  }
  for (const required of REQUIRED_PARTS) {
    if (!entries.has(required)) {
      throw new TypeError(`DOCX package omits required part: ${required}.`)
    }
  }
  if ([...entries.keys()].some((name) => FORBIDDEN_PART.test(name))) {
    throw new TypeError('DOCX package contains an active or externally loaded part.')
  }

  const admittedParts = new Map()
  for (const [name, entry] of entries) {
    const part = readEntry(bytes, entry, limits)
    if (REQUIRED_PARTS.includes(name) || name.endsWith('.rels')) {
      admittedParts.set(name, part)
    }
  }

  const contentTypes = xmlText(
    admittedParts.get('[Content_Types].xml'),
    'DOCX content types',
  )
  if (
    !contentTypes.includes(DOCUMENT_CONTENT_TYPE) ||
    FORBIDDEN_CONTENT_TYPE.test(contentTypes)
  ) {
    throw new TypeError('DOCX content types are not one macro-free Word document.')
  }
  let relationshipBytes = 0
  for (const [name, entry] of entries) {
    if (!name.endsWith('.rels')) continue
    relationshipBytes = addBounded(
      relationshipBytes,
      entry.uncompressedBytes,
      limits.maximumRelationshipBytes,
      'DOCX relationship bytes',
    )
    const relationships = xmlText(
      admittedParts.get(name),
      `DOCX relationships ${name}`,
    )
    if (EXTERNAL_RELATIONSHIP.test(relationships)) {
      throw new TypeError('DOCX package contains an external relationship.')
    }
  }
  return Object.freeze({ entryCount, totalUncompressedBytes, relationshipBytes })
}

const CRC_TABLE = Object.freeze(
  Array.from({ length: 256 }, (_, value) => {
    let crc = value
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1
    }
    return crc >>> 0
  }),
)

function crc32(bytes) {
  let crc = 0xffffffff
  for (const byte of bytes) {
    crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}
