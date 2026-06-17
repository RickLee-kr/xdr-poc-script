#!/usr/bin/env bash
# Backward-compatible entry — canonical menu lives at repository root.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "${ROOT}/dsp-menu.sh" "$@"
