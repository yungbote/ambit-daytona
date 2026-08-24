import { deflateRawSync } from 'node:zlib'

const CONTENT_TYPE =
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'

export const DOCX_LIMITS = Object.freeze({
  maximumEntryBytes: 1024 * 1024,
  maximumPackageEntries: 128,
  maximumRelationshipBytes: 1024 * 1024,
  maximumUncompressedBytes: 4 * 1024 * 1024,
})

export function minimalDocxEntries() {
  return [
    {
      name: '[Content_Types].xml',
      bytes: Buffer.from(
        `<Types><Override PartName="/word/document.xml" ContentType="${CONTENT_TYPE}"/></Types>`,
      ),
    },
    {
      name: '_rels/.rels',
      bytes: Buffer.from(
        '<Relationships><Relationship Target="word/document.xml"/></Relationships>',
      ),
    },
    { name: 'word/document.xml', bytes: Buffer.from('<w:document/>') },
  ]
}

export function makeDocx(entries = minimalDocxEntries()) {
  const localRecords = []
  const centralRecords = []
  let localOffset = 0
  for (const entry of entries) {
    const name = Buffer.from(entry.name)
    const bytes = Buffer.from(entry.bytes)
    const flags = entry.flags ?? 0
    const method = entry.method ?? 8
    const compressed = method === 8 ? deflateRawSync(bytes) : bytes
    const checksum = crc32(bytes)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(flags, 6)
    local.writeUInt16LE(method, 8)
    local.writeUInt32LE(checksum, 14)
    local.writeUInt32LE(compressed.byteLength, 18)
    local.writeUInt32LE(bytes.byteLength, 22)
    local.writeUInt16LE(name.byteLength, 26)
    const localRecord = Buffer.concat([local, name, compressed])
    localRecords.push(localRecord)

    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE(20, 4)
    central.writeUInt16LE(20, 6)
    central.writeUInt16LE(flags, 8)
    central.writeUInt16LE(method, 10)
    central.writeUInt32LE(checksum, 16)
    central.writeUInt32LE(compressed.byteLength, 20)
    central.writeUInt32LE(bytes.byteLength, 24)
    central.writeUInt16LE(name.byteLength, 28)
    central.writeUInt32LE(localOffset, 42)
    centralRecords.push(Buffer.concat([central, name]))
    localOffset += localRecord.byteLength
  }
  const central = Buffer.concat(centralRecords)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(entries.length, 8)
  end.writeUInt16LE(entries.length, 10)
  end.writeUInt32LE(central.byteLength, 12)
  end.writeUInt32LE(localOffset, 16)
  return Buffer.concat([...localRecords, central, end])
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
