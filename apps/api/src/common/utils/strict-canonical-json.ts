/*
 * Copyright 2025 Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

/** Canonical JSON for bounded provider authority wires. */
export function strictCanonicalJsonStringify(value: unknown): string {
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false'
    case 'number':
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error('Canonical JSON number is invalid.')
      return String(value)
    case 'string':
      return canonicalString(value)
    case 'object':
      if (value === null) return 'null'
      if (Array.isArray(value)) return `[${value.map(strictCanonicalJsonStringify).join(',')}]`
      if (Object.getPrototypeOf(value) !== Object.prototype) throw new Error('Canonical JSON object is not plain.')
      return `{${Object.keys(value)
        .sort()
        .map(
          (key) => `${canonicalString(key)}:${strictCanonicalJsonStringify((value as Record<string, unknown>)[key])}`,
        )
        .join(',')}}`
    default:
      throw new Error('Canonical JSON value is invalid.')
  }
}

function canonicalString(value: string): string {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = value.charCodeAt(index + 1)
      if (!(low >= 0xdc00 && low <= 0xdfff)) throw new Error('Canonical JSON string has an unpaired surrogate.')
      index += 1
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error('Canonical JSON string has an unpaired surrogate.')
    }
  }
  return JSON.stringify(value)
}
