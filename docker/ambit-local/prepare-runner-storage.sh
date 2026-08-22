#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE

if [[ $# -ne 1 ]]; then
  echo 'Usage: prepare-runner-storage.sh STATE_ROOT' >&2
  exit 64
fi

echo 'runner storage activation is owned by start-isolated-docker.sh inside its reviewed private mount namespace' >&2
echo 'do not mount runner storage from the caller or host namespace' >&2
exit 64
