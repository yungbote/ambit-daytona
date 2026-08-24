#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: normalize-generated.sh <generated-src-dir>" >&2
  exit 64
fi

generated_root="$1"
case "$generated_root" in
  libs/*api-client/src) ;;
  *)
    echo "Generated client root is outside the admitted library path." >&2
    exit 65
    ;;
esac

if [ ! -d "$generated_root" ] || [ -L "$generated_root" ]; then
  echo "Generated client root is absent or unsafe." >&2
  exit 66
fi
if find "$generated_root" -type l -print -quit | grep -q .; then
  echo "Generated client output contains a symlink." >&2
  exit 67
fi

find "$generated_root" -type f \
  \( -name '*.ts' -o -name '*.md' -o -name '*.json' \
     -o -name '*.yaml' -o -name '*.yml' -o -name '*.txt' \
     -o -name 'FILES' -o -name 'VERSION' \
     -o -name '.openapi-generator-ignore' \) \
  -print0 \
  | LC_ALL=C sort -z \
  | while IFS= read -r -d '' generated_file; do
      # OpenAPI templates retain padding in empty JSDoc rows and emit one or
      # more blank rows after their final declaration. Normalize only those
      # byte classes; token spelling, order, and generator-owned semantics are
      # untouched.
      perl -0pi -e \
        's/[ \t]+(?=\r?\n)//g; s/(?:\r?\n)+\z/\n/; $_ .= "\n" unless /\n\z/' \
        "$generated_file"
    done
