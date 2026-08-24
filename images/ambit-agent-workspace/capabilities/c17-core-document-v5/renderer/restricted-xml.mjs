const XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace'
const XMLNS_NAMESPACE = 'http://www.w3.org/2000/xmlns/'
const NAME = /^[A-Za-z_][A-Za-z0-9_.-]*$/u
const XML_DECLARATION =
  /^<\?xml[\t\n\r ]+version=(?:"1\.0"|'1\.0')(?:[\t\n\r ]+encoding=(?:"UTF-8"|'UTF-8'|"utf-8"|'utf-8'))?(?:[\t\n\r ]+standalone=(?:"yes"|'yes'|"no"|'no'))?[\t\n\r ]*\?>/u

function positiveSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer.`)
  }
  return value
}

function admitLimits(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Restricted XML limits are invalid.')
  }
  return Object.freeze({
    maximumBytes: positiveSafeInteger(
      value.maximumXmlBytes,
      'Restricted XML maximum bytes',
    ),
    maximumNodes: positiveSafeInteger(
      value.maximumXmlNodes,
      'Restricted XML maximum nodes',
    ),
    maximumDepth: positiveSafeInteger(
      value.maximumXmlDepth,
      'Restricted XML maximum depth',
    ),
    maximumAttributesPerElement: positiveSafeInteger(
      value.maximumXmlAttributesPerElement,
      'Restricted XML maximum attributes per element',
    ),
    maximumAttributeBytes: positiveSafeInteger(
      value.maximumXmlAttributeBytes,
      'Restricted XML maximum attribute bytes',
    ),
    maximumEntityReferences: positiveSafeInteger(
      value.maximumXmlEntityReferences,
      'Restricted XML maximum entity references',
    ),
    maximumDecodedTextBytes: positiveSafeInteger(
      value.maximumXmlDecodedTextBytes,
      'Restricted XML maximum decoded text bytes',
    ),
  })
}

function qname(value, label) {
  const pieces = value.split(':')
  if (
    pieces.length > 2 ||
    pieces.some((piece) => !NAME.test(piece)) ||
    value.toLowerCase().startsWith('xml') &&
      !['xml', 'xmlns'].includes(pieces[0])
  ) {
    throw new TypeError(`${label} is not one supported XML qualified name.`)
  }
  return Object.freeze({
    prefix: pieces.length === 2 ? pieces[0] : null,
    localName: pieces.at(-1),
  })
}

function validXmlCodePoint(codePoint) {
  return (
    codePoint === 0x09 ||
    codePoint === 0x0a ||
    codePoint === 0x0d ||
    (codePoint >= 0x20 && codePoint <= 0xd7ff) ||
    (codePoint >= 0xe000 && codePoint <= 0xfffd) ||
    (codePoint >= 0x10000 && codePoint <= 0x10ffff)
  )
}

function requireXmlCharacters(value, label) {
  for (const character of value) {
    if (!validXmlCodePoint(character.codePointAt(0))) {
      throw new TypeError(`${label} contains a character forbidden by XML 1.0.`)
    }
  }
}

function increment(state, key, maximum, label, amount = 1) {
  state[key] += amount
  if (!Number.isSafeInteger(state[key]) || state[key] > maximum) {
    throw new RangeError(`${label} exceeds its restricted XML policy.`)
  }
}

function decodeEntities(value, state, limits, label) {
  requireXmlCharacters(value, label)
  let output = ''
  let cursor = 0
  while (cursor < value.length) {
    const ampersand = value.indexOf('&', cursor)
    if (ampersand < 0) {
      output += value.slice(cursor)
      break
    }
    output += value.slice(cursor, ampersand)
    const semicolon = value.indexOf(';', ampersand + 1)
    if (semicolon < 0 || semicolon - ampersand > 16) {
      throw new TypeError(`${label} contains an unterminated or oversized entity.`)
    }
    increment(
      state,
      'entityReferences',
      limits.maximumEntityReferences,
      'Restricted XML entity references',
    )
    const entity = value.slice(ampersand + 1, semicolon)
    const named = Object.freeze({
      amp: '&',
      apos: "'",
      gt: '>',
      lt: '<',
      quot: '"',
    })
    let decoded = named[entity]
    if (decoded === undefined) {
      let codePoint
      if (/^#[0-9]+$/u.test(entity)) {
        codePoint = Number.parseInt(entity.slice(1), 10)
      } else if (/^#x[0-9A-Fa-f]+$/u.test(entity)) {
        codePoint = Number.parseInt(entity.slice(2), 16)
      } else {
        throw new TypeError(`${label} contains a forbidden named entity.`)
      }
      if (!Number.isSafeInteger(codePoint) || !validXmlCodePoint(codePoint)) {
        throw new TypeError(`${label} contains an invalid numeric entity.`)
      }
      decoded = String.fromCodePoint(codePoint)
    }
    output += decoded
    cursor = semicolon + 1
  }
  requireXmlCharacters(output, label)
  increment(
    state,
    'decodedTextBytes',
    limits.maximumDecodedTextBytes,
    'Restricted XML decoded text bytes',
    Buffer.byteLength(output),
  )
  return output
}

function skipWhitespace(text, cursor) {
  while (cursor < text.length && /[\t\n\r ]/u.test(text[cursor])) cursor += 1
  return cursor
}

function scanName(text, cursor, label) {
  const start = cursor
  while (cursor < text.length && /[A-Za-z0-9_.:-]/u.test(text[cursor])) {
    cursor += 1
  }
  if (cursor === start) throw new TypeError(`${label} is missing.`)
  const raw = text.slice(start, cursor)
  return Object.freeze({ raw, parsed: qname(raw, label), cursor })
}

function resolveElementName(parsed, namespaces) {
  const namespaceUri = parsed.prefix
    ? namespaces.get(parsed.prefix)
    : namespaces.get('') ?? null
  if (parsed.prefix && namespaceUri === undefined) {
    throw new TypeError('Restricted XML element uses an unbound namespace prefix.')
  }
  return Object.freeze({ ...parsed, namespaceUri })
}

function resolveAttributeName(parsed, namespaces) {
  if (parsed.prefix === null) return Object.freeze({ ...parsed, namespaceUri: null })
  const namespaceUri = namespaces.get(parsed.prefix)
  if (namespaceUri === undefined) {
    throw new TypeError('Restricted XML attribute uses an unbound namespace prefix.')
  }
  return Object.freeze({ ...parsed, namespaceUri })
}

function freezeNode(node) {
  return Object.freeze({
    namespaceUri: node.namespaceUri,
    localName: node.localName,
    prefix: node.prefix,
    attributes: Object.freeze(node.attributes.map((attribute) => Object.freeze(attribute))),
    children: Object.freeze(node.children.map(freezeNode)),
    text: node.text,
  })
}

export function parseRestrictedXml(bytes, limitValue, label = 'Restricted XML') {
  const limits = admitLimits(limitValue)
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.byteLength === 0 ||
    bytes.byteLength > limits.maximumBytes ||
    bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))
  ) {
    throw new TypeError(`${label} bytes are unavailable, oversized, or BOM-prefixed.`)
  }
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch (error) {
    throw new TypeError(`${label} is not exact UTF-8.`, { cause: error })
  }
  if (!Buffer.from(text, 'utf8').equals(bytes)) {
    throw new TypeError(`${label} is not exact UTF-8.`)
  }
  requireXmlCharacters(text, label)

  const state = {
    attributeBytes: 0,
    decodedTextBytes: 0,
    entityReferences: 0,
    nodes: 0,
  }
  const baseNamespaces = new Map([
    ['xml', XML_NAMESPACE],
    ['xmlns', XMLNS_NAMESPACE],
  ])
  const stack = []
  let root = null
  let cursor = 0
  if (text.startsWith('<?xml')) {
    const declaration = text.match(XML_DECLARATION)
    if (!declaration) throw new TypeError(`${label} XML declaration is unsupported.`)
    cursor = declaration[0].length
  }

  while (cursor < text.length) {
    if (text.startsWith('<!--', cursor)) {
      const close = text.indexOf('-->', cursor + 4)
      if (close < 0 || text.slice(cursor + 4, close).includes('--')) {
        throw new TypeError(`${label} contains a malformed comment.`)
      }
      increment(state, 'nodes', limits.maximumNodes, 'Restricted XML nodes')
      cursor = close + 3
      continue
    }
    if (text[cursor] !== '<') {
      const close = text.indexOf('<', cursor)
      const end = close < 0 ? text.length : close
      const decoded = decodeEntities(
        text.slice(cursor, end),
        state,
        limits,
        `${label} text`,
      )
      if (decoded.length > 0) {
        increment(state, 'nodes', limits.maximumNodes, 'Restricted XML nodes')
        if (stack.length === 0) {
          if (decoded.trim() !== '') {
            throw new TypeError(`${label} contains text outside its root element.`)
          }
        } else {
          stack.at(-1).node.text += decoded
        }
      }
      cursor = end
      continue
    }
    if (text.startsWith('<!', cursor) || text.startsWith('<?', cursor)) {
      throw new TypeError(`${label} contains DTD, CDATA, or processing authority.`)
    }
    if (text.startsWith('</', cursor)) {
      const closing = scanName(text, cursor + 2, `${label} closing element name`)
      cursor = skipWhitespace(text, closing.cursor)
      if (text[cursor] !== '>' || stack.length === 0) {
        throw new TypeError(`${label} contains a malformed closing element.`)
      }
      const opened = stack.pop()
      if (opened.rawName !== closing.raw) {
        throw new TypeError(`${label} element nesting is not exact.`)
      }
      cursor += 1
      continue
    }

    const opening = scanName(text, cursor + 1, `${label} element name`)
    cursor = opening.cursor
    const parentNamespaces = stack.at(-1)?.namespaces ?? baseNamespaces
    const namespaces = new Map(parentNamespaces)
    const rawAttributes = []
    let selfClosing = false
    while (true) {
      cursor = skipWhitespace(text, cursor)
      if (text.startsWith('/>', cursor)) {
        selfClosing = true
        cursor += 2
        break
      }
      if (text[cursor] === '>') {
        cursor += 1
        break
      }
      const attributeName = scanName(
        text,
        cursor,
        `${label} attribute name`,
      )
      cursor = skipWhitespace(text, attributeName.cursor)
      if (text[cursor] !== '=') {
        throw new TypeError(`${label} attribute assignment is malformed.`)
      }
      cursor = skipWhitespace(text, cursor + 1)
      const quote = text[cursor]
      if (quote !== '"' && quote !== "'") {
        throw new TypeError(`${label} attribute value is not quoted.`)
      }
      const close = text.indexOf(quote, cursor + 1)
      if (close < 0) throw new TypeError(`${label} attribute value is unterminated.`)
      const rawValue = text.slice(cursor + 1, close)
      if (rawValue.includes('<')) {
        throw new TypeError(`${label} attribute contains a forbidden delimiter.`)
      }
      const value = decodeEntities(
        rawValue,
        state,
        limits,
        `${label} attribute`,
      )
      increment(
        state,
        'attributeBytes',
        limits.maximumAttributeBytes,
        'Restricted XML attribute bytes',
        Buffer.byteLength(value),
      )
      rawAttributes.push({ name: attributeName.parsed, rawName: attributeName.raw, value })
      if (rawAttributes.length > limits.maximumAttributesPerElement) {
        throw new RangeError(
          'Restricted XML attributes per element exceed their policy.',
        )
      }
      cursor = close + 1
    }

    const rawNames = rawAttributes.map((attribute) => attribute.rawName)
    if (new Set(rawNames).size !== rawNames.length) {
      throw new TypeError(`${label} contains duplicate lexical attributes.`)
    }
    for (const attribute of rawAttributes) {
      const declaration =
        attribute.rawName === 'xmlns'
          ? ''
          : attribute.name.prefix === 'xmlns'
            ? attribute.name.localName
            : null
      if (declaration === null) continue
      if (
        declaration === 'xmlns' ||
        attribute.value === XMLNS_NAMESPACE ||
        (declaration === 'xml' && attribute.value !== XML_NAMESPACE) ||
        (declaration !== 'xml' && attribute.value === XML_NAMESPACE) ||
        (declaration !== '' && attribute.value === '')
      ) {
        throw new TypeError(`${label} namespace declaration is invalid.`)
      }
      if (declaration === '') {
        if (attribute.value === '') namespaces.delete('')
        else namespaces.set('', attribute.value)
      } else {
        namespaces.set(declaration, attribute.value)
      }
    }

    const resolvedName = resolveElementName(opening.parsed, namespaces)
    const attributes = rawAttributes
      .filter(
        (attribute) =>
          attribute.rawName !== 'xmlns' && attribute.name.prefix !== 'xmlns',
      )
      .map((attribute) => ({
        ...resolveAttributeName(attribute.name, namespaces),
        value: attribute.value,
      }))
    const expandedNames = attributes.map(
      (attribute) => `${attribute.namespaceUri ?? ''}\u0000${attribute.localName}`,
    )
    if (new Set(expandedNames).size !== expandedNames.length) {
      throw new TypeError(`${label} contains duplicate expanded attributes.`)
    }
    increment(state, 'nodes', limits.maximumNodes, 'Restricted XML nodes')
    const depth = stack.length + 1
    if (depth > limits.maximumDepth) {
      throw new RangeError('Restricted XML depth exceeds its policy.')
    }
    const node = {
      namespaceUri: resolvedName.namespaceUri,
      localName: resolvedName.localName,
      prefix: resolvedName.prefix,
      attributes,
      children: [],
      text: '',
    }
    if (stack.length === 0) {
      if (root !== null) throw new TypeError(`${label} contains multiple root elements.`)
      root = node
    } else {
      stack.at(-1).node.children.push(node)
    }
    if (!selfClosing) stack.push({ node, namespaces, rawName: opening.raw })
  }

  if (root === null || stack.length !== 0) {
    throw new TypeError(`${label} root element is missing or unterminated.`)
  }
  return freezeNode(root)
}

export function exactUnqualifiedAttributes(node, expected, label) {
  if (
    node === null ||
    typeof node !== 'object' ||
    !Array.isArray(node.attributes) ||
    node.attributes.some((attribute) => attribute.namespaceUri !== null)
  ) {
    throw new TypeError(`${label} attributes are not unqualified.`)
  }
  const record = Object.fromEntries(
    node.attributes.map((attribute) => [attribute.localName, attribute.value]),
  )
  if (Object.keys(record).sort().join('\n') !== [...expected].sort().join('\n')) {
    throw new TypeError(`${label} attribute fields are invalid.`)
  }
  return Object.freeze(record)
}
