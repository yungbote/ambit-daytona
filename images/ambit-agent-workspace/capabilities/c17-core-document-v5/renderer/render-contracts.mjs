import { createHash } from 'node:crypto'
import { types as nodeTypes } from 'node:util'

const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value))
}

function canonicalValue(value) {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean'
  ) {
    return value
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError('Canonical JSON numbers must be finite and positive-zero.')
    }
    return value
  }
  if (Array.isArray(value)) {
    return exactArrayValues(value, 'Canonical JSON array').map((child) =>
      canonicalValue(child),
    )
  }
  const record = exactDataRecord(value, 'Canonical JSON object')
  return Object.fromEntries(
    Object.keys(record)
      .sort()
      .map((key) => [key, canonicalValue(record[key])]),
  )
}

function exactKeys(value, expected, label) {
  const record = exactDataRecord(value, label)
  if (Object.keys(record).sort().join('\n') !== [...expected].sort().join('\n')) {
    throw new TypeError(`${label} fields are invalid.`)
  }
  return record
}

function exactDataRecord(value, label) {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError(`${label} must be a plain data record.`)
  }
  const keys = Reflect.ownKeys(value)
  if (keys.some((key) => typeof key !== 'string')) {
    throw new TypeError(`${label} must not contain symbol fields.`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const detached = {}
  for (const key of keys) {
    const descriptor = descriptors[key]
    if (
      !descriptor ||
      !Object.hasOwn(descriptor, 'value') ||
      descriptor.enumerable !== true
    ) {
      throw new TypeError(`${label} fields must be enumerable own data.`)
    }
    detached[key] = descriptor.value
  }
  return detached
}

function exactArrayValues(value, label) {
  if (
    !Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype
  ) {
    throw new TypeError(`${label} must be an ordinary array.`)
  }
  const expected = [
    ...Array.from({ length: value.length }, (_, index) => String(index)),
    'length',
  ]
  const keys = Reflect.ownKeys(value)
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index])
  ) {
    throw new TypeError(`${label} must be dense and field-free.`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  return expected.slice(0, -1).map((key) => {
    const descriptor = descriptors[key]
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`${label} entries must be own data.`)
    }
    return descriptor.value
  })
}

function positiveSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer.`)
  }
  return value
}

export function admitRenderPolicy(value) {
  const policy = exactKeys(
    value,
    [
      'canonicalArtifactBoundary',
      'execution',
      'input',
      'libreOffice',
      'pages',
      'pdfjs',
      'policyRef',
      'renderOutputGrantsCanonicalAuthority',
      'schema',
      'scratch',
    ],
    'Render policy',
  )
  if (
    policy.schema !== 'ambit.runtime-pack-document-render-policy/v1' ||
    policy.policyRef !== 'ambit.render-policy/core-document-paginated@1' ||
    policy.canonicalArtifactBoundary !== 'external-commit-only' ||
    policy.renderOutputGrantsCanonicalAuthority !== false
  ) {
    throw new TypeError('Render policy identity is invalid.')
  }
  const input = exactKeys(
    policy.input,
    [
      'externalLinks',
      'formats',
      'localImmutableBytesOnly',
      'macros',
      'maximumBytes',
      'maximumEntryBytes',
      'maximumPackageEntries',
      'maximumRelationshipBytes',
      'maximumUncompressedBytes',
      'maximumXmlAttributeBytes',
      'maximumXmlAttributesPerElement',
      'maximumXmlBytes',
      'maximumXmlDecodedTextBytes',
      'maximumXmlDepth',
      'maximumXmlEntityReferences',
      'maximumXmlNodes',
      'passwordProtected',
      'remoteUrls',
    ],
    'Render input policy',
  )
  positiveSafeInteger(input.maximumBytes, 'Render input maximum bytes')
  positiveSafeInteger(input.maximumEntryBytes, 'Render input maximum entry bytes')
  positiveSafeInteger(
    input.maximumPackageEntries,
    'Render input maximum package entries',
  )
  positiveSafeInteger(
    input.maximumRelationshipBytes,
    'Render input maximum relationship bytes',
  )
  positiveSafeInteger(
    input.maximumUncompressedBytes,
    'Render input maximum uncompressed bytes',
  )
  for (const key of [
    'maximumXmlAttributeBytes',
    'maximumXmlAttributesPerElement',
    'maximumXmlBytes',
    'maximumXmlDecodedTextBytes',
    'maximumXmlDepth',
    'maximumXmlEntityReferences',
    'maximumXmlNodes',
  ]) {
    positiveSafeInteger(input[key], `Render input policy ${key}`)
  }
  if (
    input.localImmutableBytesOnly !== true ||
    canonicalJson(input.formats) !== canonicalJson(['docx']) ||
    input.remoteUrls !== 'forbidden' ||
    input.macros !== 'disabled' ||
    input.externalLinks !== 'disabled' ||
    input.passwordProtected !== 'unsupported' ||
    input.maximumEntryBytes > input.maximumUncompressedBytes ||
    input.maximumRelationshipBytes > input.maximumUncompressedBytes ||
    input.maximumXmlBytes > input.maximumRelationshipBytes ||
    input.maximumXmlDecodedTextBytes > input.maximumXmlBytes ||
    input.maximumXmlAttributeBytes > input.maximumXmlDecodedTextBytes
  ) {
    throw new TypeError('Render input policy is invalid.')
  }
  const execution = exactKeys(
    policy.execution,
    [
      'maximumChildStderrBytes',
      'maximumChildStdoutBytes',
      'maximumCleanupMilliseconds',
      'maximumPipelineWallMilliseconds',
      'maximumTerminalWriteMilliseconds',
    ],
    'Render execution policy',
  )
  for (const key of Object.keys(execution)) {
    positiveSafeInteger(execution[key], `Render execution policy ${key}`)
  }
  const libreOffice = exactKeys(
    policy.libreOffice,
    [
      'headless',
      'maximumPdfBytes',
      'maximumWallMilliseconds',
      'nodefault',
      'nolockcheck',
      'nologo',
      'norestore',
      'privateUserProfile',
      'processModel',
      'profileReuse',
    ],
    'LibreOffice render policy',
  )
  positiveSafeInteger(
    libreOffice.maximumWallMilliseconds,
    'LibreOffice maximum wall milliseconds',
  )
  positiveSafeInteger(
    libreOffice.maximumPdfBytes,
    'LibreOffice maximum PDF bytes',
  )
  if (
    libreOffice.processModel !== 'one-process-per-render' ||
    libreOffice.privateUserProfile !== 'required' ||
    libreOffice.profileReuse !== 'forbidden' ||
    libreOffice.headless !== true ||
    libreOffice.nologo !== true ||
    libreOffice.nodefault !== true ||
    libreOffice.norestore !== true ||
    libreOffice.nolockcheck !== true
  ) {
    throw new TypeError('LibreOffice render policy is invalid.')
  }
  const pages = exactKeys(
    policy.pages,
    [
      'background',
      'exactPngSha256Required',
      'maximumBytesPerPage',
      'maximumCount',
      'maximumHeightPixels',
      'maximumPixelsPerPage',
      'maximumTotalOutputBytes',
      'maximumTotalPixels',
      'maximumWidthPixels',
      'orderedZeroBasedRosterRequired',
      'pngEncoding',
      'rasterScale',
    ],
    'Render page policy',
  )
  for (const key of [
    'maximumCount',
    'maximumBytesPerPage',
    'maximumHeightPixels',
    'maximumPixelsPerPage',
    'maximumTotalOutputBytes',
    'maximumTotalPixels',
    'maximumWidthPixels',
    'rasterScale',
  ]) {
    positiveSafeInteger(pages[key], `Render page policy ${key}`)
  }
  if (
    pages.background !== '#ffffff' ||
    pages.pngEncoding !== 'napi-rs-canvas-png-default-v1' ||
    pages.orderedZeroBasedRosterRequired !== true ||
    pages.exactPngSha256Required !== true
  ) {
    throw new TypeError('Render page encoding policy is invalid.')
  }
  if (
    execution.maximumPipelineWallMilliseconds <=
      libreOffice.maximumWallMilliseconds ||
    execution.maximumCleanupMilliseconds >=
      execution.maximumPipelineWallMilliseconds ||
    execution.maximumTerminalWriteMilliseconds >=
      execution.maximumPipelineWallMilliseconds
  ) {
    throw new TypeError('Render execution deadline policy is invalid.')
  }
  const pdfjs = exactKeys(
    policy.pdfjs,
    [
      'bytesInputOnly',
      'canvasFactory',
      'executionState',
      'localStaticResourcesOnly',
      'popplerFallback',
      'requiredGlobals',
      'standardFonts',
      'workerVersionMustEqualApiVersion',
    ],
    'PDF.js policy',
  )
  if (
    pdfjs.bytesInputOnly !== true ||
    pdfjs.canvasFactory !== 'ambit.pdfjs-canvas-factory/napi-rs@1' ||
    pdfjs.localStaticResourcesOnly !== true ||
    pdfjs.popplerFallback !== 'forbidden' ||
    !['available', 'unavailable'].includes(pdfjs.executionState) ||
    pdfjs.standardFonts !==
      'unsupported-until-license-corrected-and-frozen' ||
    pdfjs.workerVersionMustEqualApiVersion !== true ||
    canonicalJson(pdfjs.requiredGlobals) !==
      canonicalJson(['DOMMatrix', 'ImageData', 'Path2D'])
  ) {
    throw new TypeError('PDF.js execution policy is invalid.')
  }
  const scratch = exactKeys(
    policy.scratch,
    [
      'cacheRequiredBytes',
      'derivation',
      'workspaceOverheadBytes',
      'workspaceRequiredBytes',
    ],
    'Render scratch policy',
  )
  for (const key of [
    'cacheRequiredBytes',
    'workspaceOverheadBytes',
    'workspaceRequiredBytes',
  ]) {
    positiveSafeInteger(scratch[key], `Render scratch policy ${key}`)
  }
  const derivedWorkspaceBytes =
    Math.max(
      input.maximumBytes + libreOffice.maximumPdfBytes,
      libreOffice.maximumPdfBytes + pages.maximumTotalOutputBytes,
    ) + scratch.workspaceOverheadBytes
  if (
    scratch.derivation !==
      'max(input-docx+intermediate-pdf,intermediate-pdf+page-output)+bounded-overhead' ||
    !Number.isSafeInteger(derivedWorkspaceBytes) ||
    scratch.workspaceRequiredBytes !== derivedWorkspaceBytes
  ) {
    throw new TypeError('Render scratch derivation is invalid.')
  }
  return Object.freeze({
    ...policy,
    execution: Object.freeze(execution),
    input: Object.freeze(input),
    libreOffice: Object.freeze(libreOffice),
    pages: Object.freeze(pages),
    pdfjs: Object.freeze(pdfjs),
    scratch: Object.freeze(scratch),
  })
}

export function planPageDimensions(dimensions, policyValue) {
  const policy = admitRenderPolicy(policyValue)
  const dimensionValues = exactArrayValues(dimensions, 'Page dimension roster')
  if (dimensionValues.length === 0) {
    throw new TypeError('A rendered document must contain at least one page.')
  }
  if (dimensionValues.length > policy.pages.maximumCount) {
    throw new RangeError('The rendered document exceeds the page-count policy.')
  }
  let totalPixels = 0
  const pages = dimensionValues.map((value, index) => {
    const dimension = exactKeys(value, ['height', 'width'], 'Page dimension')
    if (
      typeof dimension.width !== 'number' ||
      typeof dimension.height !== 'number' ||
      !Number.isFinite(dimension.width) ||
      !Number.isFinite(dimension.height) ||
      dimension.width <= 0 ||
      dimension.height <= 0
    ) {
      throw new TypeError('Page dimensions must be finite and positive.')
    }
    const width = Math.ceil(dimension.width)
    const height = Math.ceil(dimension.height)
    const pixels = width * height
    if (
      !Number.isSafeInteger(pixels) ||
      width > policy.pages.maximumWidthPixels ||
      height > policy.pages.maximumHeightPixels ||
      pixels > policy.pages.maximumPixelsPerPage
    ) {
      throw new RangeError('A page exceeds the raster dimension policy.')
    }
    totalPixels += pixels
    if (
      !Number.isSafeInteger(totalPixels) ||
      totalPixels > policy.pages.maximumTotalPixels
    ) {
      throw new RangeError('The rendered document exceeds total pixel policy.')
    }
    return Object.freeze({ index, number: index + 1, width, height, pixels })
  })
  return Object.freeze(pages)
}

function exactSha256(value, label) {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new TypeError(`${label} must be an exact SHA-256.`)
  }
  return value
}

function exactRef(value, label) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 512 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new TypeError(`${label} must be one bounded canonical ref.`)
  }
  return value
}

function pinnedRef(value, label) {
  const pin = exactKeys(value, ['digest', 'ref'], label)
  return Object.freeze({
    ref: exactRef(pin.ref, `${label} ref`),
    digest: exactSha256(pin.digest, `${label} digest`),
  })
}

function backendLineagePin(value) {
  const pin = exactKeys(
    value,
    ['canonicalBytesSha256', 'digest', 'ref', 'schemaRef'],
    'External backend component lineage',
  )
  return Object.freeze({
    schemaRef: exactRef(pin.schemaRef, 'Backend lineage schema'),
    ref: exactRef(pin.ref, 'Backend lineage ref'),
    digest: exactSha256(pin.digest, 'Backend lineage digest'),
    canonicalBytesSha256: exactSha256(
      pin.canonicalBytesSha256,
      'Backend lineage canonical bytes',
    ),
  })
}

export function admitBackendComponentLineageEnvelope(value) {
  return backendLineagePin(value)
}

export function admitInstalledEngineLineage(value) {
  const input = exactKeys(
    value,
    [
      'canvasNative',
      'canvasSource',
      'fontManifest',
      'libreOfficeClosure',
      'nodeBinary',
      'pdfjsRoster',
      'schema',
    ],
    'Installed render engine lineage',
  )
  if (input.schema !== 'ambit.runtime-pack-installed-render-engine-lineage/v1') {
    throw new TypeError('Installed render engine lineage schema is invalid.')
  }
  return Object.freeze({
    schema: input.schema,
    nodeBinary: pinnedRef(input.nodeBinary, 'Installed Node binary'),
    pdfjsRoster: pinnedRef(input.pdfjsRoster, 'Installed PDF.js roster'),
    canvasSource: pinnedRef(input.canvasSource, 'Installed Canvas source'),
    canvasNative: pinnedRef(
      input.canvasNative,
      'Installed Canvas native binary',
    ),
    libreOfficeClosure: pinnedRef(
      input.libreOfficeClosure,
      'Installed LibreOffice closure',
    ),
    fontManifest: pinnedRef(input.fontManifest, 'Installed font manifest'),
  })
}

export function createRenderExecutionLineage(value) {
  const input = exactKeys(
    value,
    [
      'backendComponentLineage',
      'canvasNative',
      'canvasSource',
      'fontManifest',
      'libreOfficeClosure',
      'nodeBinary',
      'pdfjsRoster',
    ],
    'Render execution lineage input',
  )
  const body = Object.freeze({
    schema: 'ambit.runtime-pack-render-execution-lineage/v1',
    kind: 'stable_render_execution_lineage',
    operationalAuthority: 'none',
    currentness: 'requires_backend_runtime_currentness_reproof',
    backendComponentLineage: backendLineagePin(
      input.backendComponentLineage,
    ),
    nodeBinary: pinnedRef(input.nodeBinary, 'Node binary'),
    pdfjsRoster: pinnedRef(input.pdfjsRoster, 'PDF.js roster'),
    canvasSource: pinnedRef(input.canvasSource, 'Canvas source'),
    canvasNative: pinnedRef(input.canvasNative, 'Canvas native binary'),
    libreOfficeClosure: pinnedRef(
      input.libreOfficeClosure,
      'LibreOffice closure',
    ),
    fontManifest: pinnedRef(input.fontManifest, 'Font manifest'),
  })
  const digest = sha256(Buffer.from(canonicalJson(body)))
  return Object.freeze({
    ...body,
    lineageRef: 'runtime-render-execution-lineage:' + digest,
    lineageDigest: digest,
  })
}

export function composeRenderExecutionLineage(value) {
  const input = exactKeys(
    value,
    ['backendComponentLineage', 'installedEngineLineage'],
    'Render execution lineage composition',
  )
  const backend = admitBackendComponentLineageEnvelope(
    input.backendComponentLineage,
  )
  const installed = admitInstalledEngineLineage(input.installedEngineLineage)
  return createRenderExecutionLineage({
    backendComponentLineage: backend,
    nodeBinary: installed.nodeBinary,
    pdfjsRoster: installed.pdfjsRoster,
    canvasSource: installed.canvasSource,
    canvasNative: installed.canvasNative,
    libreOfficeClosure: installed.libreOfficeClosure,
    fontManifest: installed.fontManifest,
  })
}

export function admitRenderExecutionLineage(value) {
  const lineage = exactKeys(
    value,
    [
      'backendComponentLineage',
      'canvasNative',
      'canvasSource',
      'currentness',
      'fontManifest',
      'kind',
      'libreOfficeClosure',
      'lineageDigest',
      'lineageRef',
      'nodeBinary',
      'operationalAuthority',
      'pdfjsRoster',
      'schema',
    ],
    'Render execution lineage',
  )
  const recreated = createRenderExecutionLineage({
    backendComponentLineage: lineage.backendComponentLineage,
    nodeBinary: lineage.nodeBinary,
    pdfjsRoster: lineage.pdfjsRoster,
    canvasSource: lineage.canvasSource,
    canvasNative: lineage.canvasNative,
    libreOfficeClosure: lineage.libreOfficeClosure,
    fontManifest: lineage.fontManifest,
  })
  if (canonicalJson(recreated) !== canonicalJson(lineage)) {
    throw new TypeError('Render execution lineage is not canonical or exact.')
  }
  return recreated
}

export function admitPngPageEvidence(plan, bytes) {
  const page = exactKeys(
    plan,
    ['height', 'index', 'number', 'pixels', 'width'],
    'Planned page',
  )
  if (!Buffer.isBuffer(bytes)) {
    throw new TypeError('Rendered page bytes are not a PNG.')
  }
  const png = parsePng(bytes)
  if (
    !Number.isSafeInteger(page.index) ||
    page.index < 0 ||
    page.number !== page.index + 1 ||
    !Number.isSafeInteger(page.width) ||
    page.width <= 0 ||
    !Number.isSafeInteger(page.height) ||
    page.height <= 0 ||
    !Number.isSafeInteger(page.pixels) ||
    page.pixels !== page.width * page.height ||
    png.width !== page.width ||
    png.height !== page.height
  ) {
    throw new TypeError('Rendered PNG dimensions differ from the page plan.')
  }
  return Object.freeze({
    index: page.index,
    number: page.number,
    filename: `page-${String(page.number).padStart(4, '0')}.png`,
    width: page.width,
    height: page.height,
    pixels: page.pixels,
    bytes: bytes.byteLength,
    sha256: sha256(bytes),
  })
}

function parsePng(bytes) {
  if (bytes.byteLength < 57 || !bytes.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new TypeError('Rendered page bytes are not a complete PNG.')
  }
  let offset = 8
  let width = null
  let height = null
  let sawImageData = false
  let sawEnd = false
  let chunkIndex = 0
  while (offset < bytes.byteLength) {
    if (bytes.byteLength - offset < 12) {
      throw new TypeError('Rendered PNG contains a truncated chunk.')
    }
    const length = bytes.readUInt32BE(offset)
    const chunkEnd = offset + 12 + length
    if (!Number.isSafeInteger(chunkEnd) || chunkEnd > bytes.byteLength) {
      throw new TypeError('Rendered PNG chunk length is invalid.')
    }
    const typeBytes = bytes.subarray(offset + 4, offset + 8)
    const type = typeBytes.toString('ascii')
    if (!/^[A-Za-z]{4}$/.test(type)) {
      throw new TypeError('Rendered PNG chunk type is invalid.')
    }
    const data = bytes.subarray(offset + 8, offset + 8 + length)
    const expectedCrc = bytes.readUInt32BE(offset + 8 + length)
    if (crc32(typeBytes, data) !== expectedCrc) {
      throw new TypeError('Rendered PNG chunk checksum is invalid.')
    }
    if (chunkIndex === 0) {
      if (type !== 'IHDR' || length !== 13) {
        throw new TypeError('Rendered PNG does not begin with an exact IHDR.')
      }
      width = data.readUInt32BE(0)
      height = data.readUInt32BE(4)
      if (
        width === 0 ||
        height === 0 ||
        data[8] !== 8 ||
        ![0, 2, 3, 4, 6].includes(data[9]) ||
        data[10] !== 0 ||
        data[11] !== 0 ||
        data[12] > 1
      ) {
        throw new TypeError('Rendered PNG IHDR is unsupported.')
      }
    } else if (type === 'IHDR') {
      throw new TypeError('Rendered PNG contains a duplicate IHDR.')
    }
    if (type === 'IDAT') sawImageData = true
    if (type === 'IEND') {
      if (length !== 0 || chunkEnd !== bytes.byteLength) {
        throw new TypeError('Rendered PNG terminal chunk is invalid.')
      }
      sawEnd = true
    } else if (sawEnd) {
      throw new TypeError('Rendered PNG contains data after IEND.')
    }
    offset = chunkEnd
    chunkIndex += 1
  }
  if (!sawImageData || !sawEnd || width === null || height === null) {
    throw new TypeError('Rendered PNG structure is incomplete.')
  }
  return { width, height }
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

function crc32(...chunks) {
  let crc = 0xffffffff
  for (const bytes of chunks) {
    for (const byte of bytes) {
      crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8)
    }
  }
  return (crc ^ 0xffffffff) >>> 0
}

export function admitExactRenderEvidence({
  sourceDocument,
  intermediatePdfBytes,
  pages,
  policy,
}) {
  const source = exactKeys(
    sourceDocument,
    ['bytes', 'format', 'sha256'],
    'Render evidence source document',
  )
  if (!['docx', 'pdf'].includes(source.format)) {
    throw new TypeError('Render evidence source format is invalid.')
  }
  exactSha256(source.sha256, 'Render evidence source document')
  positiveSafeInteger(source.bytes, 'Render evidence source document bytes')
  positiveSafeInteger(intermediatePdfBytes, 'Render evidence intermediate PDF bytes')
  const admittedPolicy = admitRenderPolicy(policy)
  if (
    source.bytes >
      (source.format === 'docx'
        ? admittedPolicy.input.maximumBytes
        : admittedPolicy.libreOffice.maximumPdfBytes) ||
    intermediatePdfBytes > admittedPolicy.libreOffice.maximumPdfBytes
  ) {
    throw new RangeError('Render source or intermediate PDF exceeds policy.')
  }
  const pageValues = exactArrayValues(pages, 'Render evidence page roster')
  if (
    pageValues.length === 0 ||
    pageValues.length > admittedPolicy.pages.maximumCount
  ) {
    throw new TypeError('Render evidence page roster is invalid.')
  }
  let totalOutputBytes = 0
  let totalPixels = 0
  const admittedPages = pageValues.map((value, index) => {
    const page = exactKeys(
      value,
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
      'Render evidence page',
    )
    const width = positiveSafeInteger(page.width, 'Rendered page width')
    const height = positiveSafeInteger(page.height, 'Rendered page height')
    const pixels = positiveSafeInteger(page.pixels, 'Rendered page pixels')
    const bytes = positiveSafeInteger(page.bytes, 'Rendered page bytes')
    if (
      page.index !== index ||
      page.number !== index + 1 ||
      page.filename !== `page-${String(index + 1).padStart(4, '0')}.png` ||
      !/^sha256:[0-9a-f]{64}$/.test(page.sha256) ||
      width > admittedPolicy.pages.maximumWidthPixels ||
      height > admittedPolicy.pages.maximumHeightPixels ||
      !Number.isSafeInteger(width * height) ||
      pixels !== width * height ||
      pixels > admittedPolicy.pages.maximumPixelsPerPage ||
      bytes > admittedPolicy.pages.maximumBytesPerPage
    ) {
      throw new TypeError(
        'Render manifest page order or identity, dimensions, or bounds are invalid.',
      )
    }
    totalOutputBytes += bytes
    totalPixels += pixels
    if (
      !Number.isSafeInteger(totalOutputBytes) ||
      !Number.isSafeInteger(totalPixels) ||
      totalOutputBytes > admittedPolicy.pages.maximumTotalOutputBytes ||
      totalPixels > admittedPolicy.pages.maximumTotalPixels
    ) {
      throw new RangeError('Render evidence aggregate bounds are invalid.')
    }
    return Object.freeze({
      index,
      number: index + 1,
      filename: page.filename,
      width,
      height,
      pixels,
      bytes,
      sha256: page.sha256,
    })
  })
  return Object.freeze({
    sourceDocument: Object.freeze({
      format: source.format,
      sha256: source.sha256,
      bytes: source.bytes,
    }),
    intermediatePdf: Object.freeze({
      bytes: intermediatePdfBytes,
      digestDisposition: 'excluded_volatile_converter_metadata',
    }),
    pageCount: admittedPages.length,
    totalPixels,
    totalOutputBytes,
    pages: Object.freeze(admittedPages),
  })
}

export function createRenderManifest({
  sourceDocument,
  intermediatePdfBytes,
  policySha256,
  pages,
  policy,
  executionLineage,
}) {
  exactSha256(policySha256, 'Render manifest policy')
  const evidence = admitExactRenderEvidence({
    sourceDocument,
    intermediatePdfBytes,
    pages,
    policy,
  })
  const admittedLineage = admitRenderExecutionLineage(executionLineage)
  const body = Object.freeze({
    schema: 'ambit.runtime-pack-paginated-render-manifest/v1',
    kind: 'paginated_render_candidate',
    canonicalAuthority: 'none',
    canonicalBoundary: 'external_artifact_commit',
    sourceDocument: evidence.sourceDocument,
    intermediatePdf: evidence.intermediatePdf,
    policy: Object.freeze({
      ref: 'ambit.render-policy/core-document-paginated@1',
      digest: policySha256,
    }),
    executionLineage: admittedLineage,
    pageCount: evidence.pageCount,
    totalPixels: evidence.totalPixels,
    totalOutputBytes: evidence.totalOutputBytes,
    pages: evidence.pages,
  })
  const digest = sha256(Buffer.from(canonicalJson(body)))
  return Object.freeze({
    ...body,
    manifestRef: `runtime-paginated-render-manifest:${digest}`,
    manifestDigest: digest,
  })
}

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}
