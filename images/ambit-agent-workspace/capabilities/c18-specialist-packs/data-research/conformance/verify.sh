#!/usr/bin/env bash
set -euo pipefail

output_root=${1:?empty output directory is required}
pack_root=/opt/ambit/runtime-pack/data-research
mkdir -p "${output_root}"
"${pack_root}/conformance/runtime-guard.sh" data-research "${output_root}"
export HOME=${output_root}/home
export XDG_CACHE_HOME=${output_root}/cache
export XDG_CONFIG_HOME=${output_root}/config
export XDG_RUNTIME_DIR=${output_root}/run
export MPLCONFIGDIR=${output_root}/matplotlib
mkdir -p "${HOME}" "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}" \
  "${MPLCONFIGDIR}"
chmod 0700 "${XDG_RUNTIME_DIR}"

python3 "${pack_root}/conformance/verify.py" generate "${output_root}/run-a"
rm -rf "${MPLCONFIGDIR}"/*
python3 "${pack_root}/conformance/verify.py" generate "${output_root}/run-b"

for run in a b; do
  source=${output_root}/run-${run}
  native=${output_root}/native-${run}
  mkdir -p "${native}"
  sqlite3 "${native}/analysis.sqlite" <<SQL
CREATE TABLE revenue(region TEXT NOT NULL, q1 INTEGER NOT NULL, q2 INTEGER NOT NULL, sample REAL NOT NULL, total INTEGER NOT NULL);
.mode csv
.import --skip 1 '${source}/revenue.csv' revenue
SELECT SUM(total) FROM revenue;
SQL
  sqlite3 "${native}/analysis.sqlite" 'SELECT SUM(total) FROM revenue;' \
    > "${native}/sqlite-total.txt"
  pandoc --from=gfm --to=html5 --standalone \
    --metadata title='Reproducible revenue analysis' \
    "${source}/research.md" -o "${native}/research.html"
  dot -Tsvg "${source}/lineage.dot" -o "${native}/lineage.svg"
done

rm -rf "${HOME}" "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}" \
  "${MPLCONFIGDIR}"
python3 "${pack_root}/conformance/verify.py" finalize "${output_root}"
test -s "${output_root}/conformance-receipt.json"
