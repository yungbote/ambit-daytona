#!/bin/sh
# Helm 4 removed the legacy `version -c` flag that the kubectl-bundled
# Kustomize 5.7 Helm inflator still probes. Translate only that capability
# check; every chart operation is delegated unchanged to the installed Helm.
if [ "$1" = version ] && [ "${2:-}" = -c ]; then
  # Kustomize rejects any major other than 3 before invoking Helm, although
  # the template/pull commands it uses are unchanged in Helm 4.
  printf '%s\n' 'v3.18.6+helm4-cli-compatible'
  exit 0
fi
exec /usr/bin/helm "$@"
