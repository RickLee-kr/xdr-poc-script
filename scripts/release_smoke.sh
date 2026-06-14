#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/dsp ]]; then
  python3 -m venv .venv
  .venv/bin/pip install -e ".[dev]" -q
fi

export PATH="$ROOT/.venv/bin:$PATH"

echo "== dsp --version =="
dsp --version

echo "== dsp run local dry-run =="
dsp run --profile normal --dry-run --quiet

echo "== dsp run webshell dry-run =="
dsp run \
  --profile normal \
  --execution-provider webshell \
  --webshell-family jsp \
  --webshell-url http://dummy/shell.jsp \
  --dry-run \
  --quiet

echo "== pytest --collect-only =="
python -m pytest --collect-only -q

echo "release smoke: OK"
