import assert from 'node:assert/strict'
import test from 'node:test'

import { normalizeTypeScriptDiffWhitespace } from './normalize-generated.mjs'

test('normalizes generated comment and EOF trivia deterministically', () => {
  const source = ['/**', ' * ', ' */', 'export const value = 1;   ', '', ''].join('\n')
  const normalized = normalizeTypeScriptDiffWhitespace(source, [
    { kind: 'trailing_whitespace', line: 2 },
    { kind: 'trailing_whitespace', line: 4 },
    { kind: 'blank_line_at_eof', line: 6 },
  ])

  assert.equal(normalized, ['/**', ' *', ' */', 'export const value = 1;', ''].join('\n'))
  assert.equal(normalizeTypeScriptDiffWhitespace(normalized, []), normalized)
})

test('preserves semantic trailing spaces inside multiline template literals', () => {
  const source = ['export const value = `first  ', 'second`;', '', ''].join('\n')

  assert.throws(
    () => normalizeTypeScriptDiffWhitespace(source, [{ kind: 'trailing_whitespace', line: 1 }]),
    /semantic TypeScript token bytes/u,
  )
  const eofNormalized = normalizeTypeScriptDiffWhitespace(source, [{ kind: 'blank_line_at_eof', line: 4 }])
  assert.equal(eofNormalized, ['export const value = `first  ', 'second`;', ''].join('\n'))
  assert.match(eofNormalized, /first {2}\n/u)
})
