#!/usr/bin/env bash
# Copyright 2026 Ambit
# SPDX-License-Identifier: AGPL-3.0

set -euo pipefail

plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$plugin_dir/../../harbor-post-renderer.sh"

