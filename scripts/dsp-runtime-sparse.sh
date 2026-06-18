#!/usr/bin/env bash
# Shared git sparse-checkout paths for DSP runtime install/update.
# Keep in sync with install-dsp.sh (bootstrap may run before this file exists).

# Runtime + operator docs cone (excludes tests/, lab/, dev specs, docs/validation/, etc.)
DSP_RUNTIME_SPARSE_PATHS=(
  /dsp
  /scenarios
  /scripts
  /pyproject.toml
  /README.md
  /install-dsp.sh
  /dsp-menu.sh
  /docs/DSP_MENU.md
  /docs/DSP_BOOTSTRAP_INSTALL.md
  /RELEASE_NOTES.md
  /RELEASE_1_0_LAB_GUIDE.md
  /.gitignore
)

dsp_sparse_checkout_available() {
  git sparse-checkout --help >/dev/null 2>&1
}

dsp_repo_is_sparse() {
  local dir="${1:?repo dir required}"
  [[ -d "${dir}/.git" ]] || return 1
  local list
  list="$(git -C "${dir}" sparse-checkout list 2>/dev/null || true)"
  [[ -n "${list}" ]]
}

dsp_repo_install_type() {
  local dir="${1:?repo dir required}"
  if dsp_repo_is_sparse "${dir}"; then
    printf 'sparse'
  else
    printf 'full'
  fi
}

dsp_apply_sparse_checkout() {
  local dir="${1:?repo dir required}"
  if ! dsp_sparse_checkout_available; then
    return 1
  fi
  git -C "${dir}" sparse-checkout init --no-cone 2>/dev/null || true
  git -C "${dir}" sparse-checkout set "${DSP_RUNTIME_SPARSE_PATHS[@]}"
}

dsp_sparse_clone() {
  local repo_url="${1:?repo url required}"
  local branch="${2:?branch required}"
  local dest="${3:?dest required}"
  git clone --filter=blob:none --sparse -b "${branch}" "${repo_url}" "${dest}"
  dsp_apply_sparse_checkout "${dest}"
}

dsp_full_clone_notice() {
  local dir="${1:?repo dir required}"
  cat <<EOF
[install-dsp] NOTE: ${dir} is a full git clone (not sparse runtime install).
[install-dsp] Extra dev files (tests/, specs, validation docs) remain on disk — not removed automatically.
[install-dsp] For a minimal runtime tree, clean reinstall:
[install-dsp]   rm -rf "${dir}"
[install-dsp]   DSP_NO_LAUNCH=1 bash install-dsp.sh
[install-dsp] Developers who need the full repo: DSP_FULL_CLONE=1 bash install-dsp.sh
EOF
}
