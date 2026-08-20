#!/usr/bin/env bash
set -u

for installer in apk pip pip3 uv npm npx; do
  if command -v "${installer}" >/dev/null 2>&1; then
    printf 'runtime installer unexpectedly available: %s\n' "${installer}" >&2
    exit 94
  fi
done
exit 93
