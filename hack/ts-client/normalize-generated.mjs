#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import {
  closeSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { dirname, relative, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'
import { randomUUID } from 'node:crypto'

import ts from 'typescript'

export function normalizeTypeScriptDiffWhitespace(source, issues) {
  if (typeof source !== 'string' || !Array.isArray(issues)) {
    throw new TypeError('Generated TypeScript normalization input is invalid.')
  }
  const protectedRanges = protectedTokenRanges(source)
  const lineStarts = [0]
  for (let index = 0; index < source.length; index += 1) {
    if (source.charCodeAt(index) === 0x0a) lineStarts.push(index + 1)
  }
  const edits = []
  let eofEdit = null
  for (const issue of issues) {
    if (!issue || !Number.isSafeInteger(issue.line) || issue.line < 1) {
      throw new TypeError('Generated TypeScript whitespace diagnostic is invalid.')
    }
    if (issue.kind === 'trailing_whitespace') {
      const start = lineStarts[issue.line - 1]
      if (start === undefined) throw new Error('Whitespace diagnostic line is absent.')
      const newline = source.indexOf('\n', start)
      const physicalEnd = newline === -1 ? source.length : newline
      const logicalEnd = source.charCodeAt(physicalEnd - 1) === 0x0d ? physicalEnd - 1 : physicalEnd
      const line = source.slice(start, logicalEnd)
      const trailing = /[ \t]+$/u.exec(line)
      if (!trailing) throw new Error('Trailing-whitespace diagnostic no longer matches source.')
      const editStart = start + trailing.index
      assertOutsideProtectedTokens(editStart, logicalEnd, protectedRanges)
      edits.push({ start: editStart, end: logicalEnd, replacement: '' })
      continue
    }
    if (issue.kind === 'blank_line_at_eof') {
      if (eofEdit) continue
      const trailing = /[ \t\r\n]+$/u.exec(source)
      if (!trailing || trailing.index === 0 || !trailing[0].includes('\n')) {
        throw new Error('EOF-whitespace diagnostic no longer matches source.')
      }
      assertOutsideProtectedTokens(trailing.index, source.length, protectedRanges)
      eofEdit = { start: trailing.index, end: source.length, replacement: '\n' }
      continue
    }
    throw new TypeError('Generated TypeScript whitespace diagnostic kind is invalid.')
  }
  if (eofEdit) edits.push(eofEdit)
  edits.sort((left, right) => right.start - left.start || right.end - left.end)
  let normalized = source
  let previousStart = source.length + 1
  for (const edit of edits) {
    if (edit.end > previousStart) {
      if (eofEdit && edit.start >= eofEdit.start && edit.end <= eofEdit.end) continue
      throw new Error('Generated TypeScript whitespace edits overlap.')
    }
    normalized = `${normalized.slice(0, edit.start)}${edit.replacement}${normalized.slice(edit.end)}`
    previousStart = edit.start
  }
  return normalized
}

function protectedTokenRanges(source) {
  const sourceFile = ts.createSourceFile('generated-client.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  if (sourceFile.parseDiagnostics.length > 0) {
    throw new Error('Generated TypeScript is not syntactically valid.')
  }
  const ranges = []
  const protect = (node) => {
    ranges.push({ start: node.getStart(sourceFile, false), end: node.end })
  }
  const visit = (node) => {
    if (
      ts.isStringLiteralLike(node) ||
      node.kind === ts.SyntaxKind.RegularExpressionLiteral ||
      node.kind === ts.SyntaxKind.JsxText
    ) {
      protect(node)
    }
    if (ts.isTemplateExpression(node)) {
      protect(node.head)
      for (const span of node.templateSpans) protect(span.literal)
    }
    ts.forEachChild(node, visit)
  }
  visit(sourceFile)
  return ranges
}

function assertOutsideProtectedTokens(start, end, protectedRanges) {
  if (protectedRanges.some((range) => start < range.end && end > range.start)) {
    throw new Error('Refusing to normalize semantic TypeScript token bytes.')
  }
}

function parseDiffCheck(output, roots) {
  const admittedRoots = roots.map((root) => `${root.replaceAll('\\', '/')}/`)
  const issues = new Map()
  for (const line of output.split('\n')) {
    const match = /^(.+):(\d+): (trailing whitespace|new blank line at EOF)\.$/u.exec(line)
    if (!match) continue
    const path = match[1].replaceAll('\\', '/')
    if (!path.endsWith('.ts') || !admittedRoots.some((root) => path.startsWith(root))) {
      throw new Error(`Refusing to normalize non-TypeScript or out-of-scope path: ${path}`)
    }
    const current = issues.get(path) ?? []
    current.push({
      line: Number(match[2]),
      kind: match[3] === 'trailing whitespace' ? 'trailing_whitespace' : 'blank_line_at_eof',
    })
    issues.set(path, current)
  }
  const diagnostics = output
    .split('\n')
    .filter((line) => /:\d+: (?:trailing whitespace|new blank line at EOF)\.$/u.test(line))
  if (diagnostics.length !== [...issues.values()].reduce((count, rows) => count + rows.length, 0)) {
    throw new Error('Generated whitespace diagnostics were not parsed exactly.')
  }
  return issues
}

function diffCheck(roots) {
  const result = spawnSync('git', ['diff', '--check', 'HEAD', '--', ...roots], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  })
  if (result.error || ![0, 2].includes(result.status)) {
    throw result.error ?? new Error(result.stderr || 'git diff --check failed unexpectedly.')
  }
  return result.stdout
}

function writeAtomic(path, bytes, mode) {
  const temporary = `${path}.normalize-${process.pid}-${randomUUID()}`
  let descriptor = null
  try {
    descriptor = openSync(temporary, 'wx', mode)
    writeFileSync(descriptor, bytes, { encoding: 'utf8' })
    fsyncSync(descriptor)
    closeSync(descriptor)
    descriptor = null
    renameSync(temporary, path)
  } catch (error) {
    if (descriptor !== null) closeSync(descriptor)
    try {
      unlinkSync(temporary)
    } catch {
      // The original normalization failure remains authoritative.
    }
    throw error
  }
}

function normalizeGeneratedTrees(rootArguments) {
  if (rootArguments.length !== 1) {
    throw new Error('Usage: normalize-generated.mjs <generated-src-dir>')
  }
  const repositoryRoot = realpathSync(process.cwd())
  const supplied = rootArguments[0].replaceAll('\\', '/')
  if (!/^libs\/[a-z0-9._-]*api-client\/src$/u.test(supplied)) {
    throw new Error('Generated client root is outside the admitted library path.')
  }
  const root = resolve(repositoryRoot, supplied)
  const rootStat = lstatSync(root)
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || realpathSync(root) !== root) {
    throw new Error('Generated client root is absent or unsafe.')
  }
  const parsed = parseDiffCheck(diffCheck([supplied]), [supplied])
  let changed = 0
  for (const [relativePath, issues] of [...parsed.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const path = resolve(repositoryRoot, relativePath)
    const relativeToRoot = relative(root, path)
    if (relativeToRoot.startsWith(`..${sep}`) || relativeToRoot === '..' || dirname(path) === path) {
      throw new Error('Generated TypeScript path escaped its admitted root.')
    }
    const stat = lstatSync(path)
    if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(path) !== path) {
      throw new Error('Generated TypeScript file is absent or unsafe.')
    }
    const source = readFileSync(path, 'utf8')
    const normalized = normalizeTypeScriptDiffWhitespace(source, issues)
    if (normalized !== source) {
      writeAtomic(path, normalized, stat.mode & 0o777)
      changed += 1
    }
  }
  const remaining = diffCheck([supplied])
  if (remaining) throw new Error(`Generated whitespace remains:\n${remaining}`)
  process.stdout.write(`${JSON.stringify({ changed, root: supplied, status: 'normalized' })}\n`)
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    normalizeGeneratedTrees(process.argv.slice(2))
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`)
    process.exitCode = 1
  }
}
