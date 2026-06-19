#!/usr/bin/env bash
# Smoke checks for install-dsp.sh (syntax, Python gate, local clean install).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_SCRIPT="${ROOT}/install-dsp.sh"

log() {
  printf '[install-dsp-smoke] %s\n' "$*"
}

die() {
  printf '[install-dsp-smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

find_real_python311_plus() {
  local candidate bin
  for candidate in python3.13 python3.12 python3.11 python3; do
    bin="$(command -v "${candidate}" 2>/dev/null || true)"
    if [[ -z "${bin}" ]]; then
      continue
    fi
    if "${bin}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null \
      && "${bin}" -c 'import venv' 2>/dev/null; then
      printf '%s\n' "${bin}"
      return 0
    fi
  done
  return 1
}

write_fake_python310() {
  local dest="$1"
  cat >"${dest}" <<'PY'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
  echo "Python 3.10.12"
  exit 0
fi
if [[ "${1:-}" == "-c" ]]; then
  case "${2:-}" in
    *sys.version_info*) exit 1 ;;
    *import\ venv*) exit 0 ;;
  esac
fi
if [[ "${1:-}" == "-m" && "${2:-}" == "venv" ]]; then
  echo "fake python3.10 must not create venv" >&2
  exit 1
fi
exit 1
PY
  chmod +x "${dest}"
}

write_python_wrapper() {
  local dest="$1"
  local real_py="$2"
  cat >"${dest}" <<EOF
#!/usr/bin/env bash
exec "${real_py}" "\$@"
EOF
  chmod +x "${dest}"
}

check_syntax() {
  log "bash -n install-dsp.sh"
  bash -n "${INSTALL_SCRIPT}"
}

check_python310_rejection() {
  log "Python 3.10-only environment should fail before venv creation"
  local tmpdir fake_bin stderr_log py
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/install-dsp-smoke-310.XXXXXX")"
  fake_bin="${tmpdir}/bin"
  stderr_log="${tmpdir}/stderr.log"
  mkdir -p "${fake_bin}"

  for py in python3 python3.11 python3.12 python3.13; do
    write_fake_python310 "${fake_bin}/${py}"
  done

  set +e
  PATH="${fake_bin}:${PATH}" \
    DSP_NO_LAUNCH=1 \
    bash "${INSTALL_SCRIPT}" 2>"${stderr_log}"
  local rc=$?
  set -e

  if [[ "${rc}" -eq 0 ]]; then
    cat "${stderr_log}" >&2 || true
    rm -rf "${tmpdir}"
    die "expected non-zero exit when only Python 3.10 is available"
  fi
  if ! grep -q 'requires Python 3.11 or newer' "${stderr_log}"; then
    cat "${stderr_log}" >&2 || true
    rm -rf "${tmpdir}"
    die "expected friendly Python 3.11 requirement message on stderr"
  fi
  if ! grep -q 'python3.11-venv' "${stderr_log}"; then
    cat "${stderr_log}" >&2 || true
    rm -rf "${tmpdir}"
    die "expected Ubuntu python3.11 install guidance on stderr"
  fi

  rm -rf "${tmpdir}"
  log "Python 3.10 rejection: OK"
}

check_default_python310_uses_python311() {
  log "default python3=3.10 with python3.11 available should create Python 3.11+ venv"
  local tmpdir fake_bin repo_dir real_py stderr_log combined_log
  real_py="$(find_real_python311_plus)" || die "need a real Python >= 3.11 on PATH for smoke test"

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/install-dsp-smoke-pref.XXXXXX")"
  fake_bin="${tmpdir}/bin"
  repo_dir="${tmpdir}/xdr-poc-script"
  stderr_log="${tmpdir}/stderr.log"
  combined_log="${tmpdir}/combined.log"
  mkdir -p "${fake_bin}"

  write_fake_python310 "${fake_bin}/python3"
  write_fake_python310 "${fake_bin}/python3.12"
  write_fake_python310 "${fake_bin}/python3.13"
  write_python_wrapper "${fake_bin}/python3.11" "${real_py}"

  set +e
  PATH="${fake_bin}:/usr/bin:/bin" \
    DSP_NO_LAUNCH=1 \
    DSP_REPO_DIR="${repo_dir}" \
    DSP_REPO_URL="file://${ROOT}" \
    RELEASE_BRANCH="$(git -C "${ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo HEAD)" \
    bash "${INSTALL_SCRIPT}" >"${combined_log}" 2>&1
  local rc=$?
  set -e
  cp "${combined_log}" "${stderr_log}"

  if [[ "${rc}" -ne 0 ]]; then
    cat "${combined_log}" >&2 || true
    rm -rf "${tmpdir}"
    die "install failed when python3.11 wrapper was available"
  fi
  if ! grep -q 'selected python:' "${combined_log}"; then
    cat "${combined_log}" >&2 || true
    rm -rf "${tmpdir}"
    die "expected selected python log line"
  fi
  if ! grep -Fq "selected python: ${fake_bin}/python3.11" "${combined_log}"; then
    cat "${combined_log}" >&2 || true
    rm -rf "${tmpdir}"
    die "expected installer to select python3.11 wrapper, not default python3"
  fi

  local venv_py_version
  venv_py_version="$("${repo_dir}/.venv/bin/python" -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')"
  if [[ "${venv_py_version%%.*}" -lt 3 ]] || [[ "${venv_py_version#*.}" -lt 11 ]]; then
    rm -rf "${tmpdir}"
    die "venv Python must be >= 3.11 (got ${venv_py_version})"
  fi
  if [[ -d "${repo_dir}/.venv/lib/python3.10" ]]; then
    rm -rf "${tmpdir}"
    die "expected no python3.10 site-packages directory in venv"
  fi

  rm -rf "${tmpdir}"
  log "python3.11 preference over default python3: OK"
}

check_stale_python310_venv_recreated() {
  log "stale Python 3.10 .venv should be removed and recreated with Python 3.11+"
  local tmpdir fake_bin repo_dir real_py combined_log
  real_py="$(find_real_python311_plus)" || die "need a real Python >= 3.11 on PATH for smoke test"

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/install-dsp-smoke-stale.XXXXXX")"
  fake_bin="${tmpdir}/bin"
  repo_dir="${tmpdir}/xdr-poc-script"
  combined_log="${tmpdir}/combined.log"
  mkdir -p "${fake_bin}"

  write_fake_python310 "${fake_bin}/python3"
  write_fake_python310 "${fake_bin}/python3.12"
  write_fake_python310 "${fake_bin}/python3.13"
  write_python_wrapper "${fake_bin}/python3.11" "${real_py}"

  git clone -q "file://${ROOT}" "${repo_dir}"
  mkdir -p "${repo_dir}/.venv/bin" "${repo_dir}/.venv/lib/python3.10/site-packages"
  write_fake_python310 "${repo_dir}/.venv/bin/python"
  ln -sf python "${repo_dir}/.venv/bin/pip"

  set +e
  PATH="${fake_bin}:/usr/bin:/bin" \
    DSP_NO_LAUNCH=1 \
    DSP_REPO_DIR="${repo_dir}" \
    DSP_REPO_URL="file://${ROOT}" \
    RELEASE_BRANCH="$(git -C "${ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo HEAD)" \
    bash "${INSTALL_SCRIPT}" >"${combined_log}" 2>&1
  local rc=$?
  set -e

  if [[ "${rc}" -ne 0 ]]; then
    cat "${combined_log}" >&2 || true
    rm -rf "${tmpdir}"
    die "install failed when replacing stale Python 3.10 venv"
  fi
  if ! grep -q 'removing existing virtual environment (Python < 3.11)' "${combined_log}"; then
    cat "${combined_log}" >&2 || true
    rm -rf "${tmpdir}"
    die "expected stale venv removal log line"
  fi

  local venv_py_version
  venv_py_version="$("${repo_dir}/.venv/bin/python" -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')"
  if [[ "${venv_py_version%%.*}" -lt 3 ]] || [[ "${venv_py_version#*.}" -lt 11 ]]; then
    rm -rf "${tmpdir}"
    die "recreated venv Python must be >= 3.11 (got ${venv_py_version})"
  fi
  if [[ ! -x "${repo_dir}/.venv/bin/dsp" ]]; then
    rm -rf "${tmpdir}"
    die "expected dsp console script after stale venv recreation"
  fi

  rm -rf "${tmpdir}"
  log "stale venv recreation: OK"
}

check_clean_install() {
  log "clean install with available Python >= 3.11"
  local tmpdir repo_dir
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/install-dsp-smoke-install.XXXXXX")"
  repo_dir="${tmpdir}/xdr-poc-script"

  DSP_NO_LAUNCH=1 \
    DSP_REPO_DIR="${repo_dir}" \
    DSP_REPO_URL="file://${ROOT}" \
    RELEASE_BRANCH="$(git -C "${ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo HEAD)" \
    bash "${INSTALL_SCRIPT}"

  if [[ ! -x "${repo_dir}/.venv/bin/dsp" ]]; then
    rm -rf "${tmpdir}"
    die "expected ${repo_dir}/.venv/bin/dsp after install"
  fi

  local venv_py_version
  venv_py_version="$("${repo_dir}/.venv/bin/python" -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')"
  if [[ "${venv_py_version%%.*}" -lt 3 ]] || [[ "${venv_py_version#*.}" -lt 11 ]]; then
    rm -rf "${tmpdir}"
    die "venv Python must be >= 3.11 (got ${venv_py_version})"
  fi

  rm -rf "${tmpdir}"
  log "clean install: OK"
}

main() {
  check_syntax
  check_python310_rejection
  check_default_python310_uses_python311
  check_stale_python310_venv_recreated
  check_clean_install
  log "install-dsp smoke: OK"
}

main "$@"
