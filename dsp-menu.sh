#!/usr/bin/env bash
# Wrapper — run the DSP operator menu from the repository root.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${ROOT}/scripts/dsp-menu.sh" "$@"
