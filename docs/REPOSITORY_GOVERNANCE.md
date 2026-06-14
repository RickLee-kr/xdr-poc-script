# Repository Governance

## Official Source of Truth

**`git@github.com:RickLee-kr/xdr-poc-script.git`** is the only writable source repository for DSP and PoC code.

All DSP feature work, releases, and documentation updates must land in this repository.

## Deprecated Repositories

**`detection-scenario-platform`** (`git@github.com:RickLee-kr/detection-scenario-platform.git`) is deprecated.

Do not push new commits, open new feature branches, or treat it as the active development target.

## xdr-lab-appliance Boundary

**`xdr-lab-appliance`** is an appliance/lab integration repository. It must not contain editable DSP source.

- Do not commit DSP code changes under `xdr-lab-appliance`.
- Do not push DSP refactors, fixes, or releases from the appliance repo.
- If DSP source appears under `xdr-lab-appliance/detection-scenario-platform/`, treat it as a read-only mirror or stale copy—not a commit target.

## Pre-Commit Checklist

Before every commit, verify:

1. **Working directory** — `pwd` must be the standalone DSP repo (for example `/home/aella/xdr-poc-script`), not `xdr-lab-appliance`.
2. **Remote** — `git remote -v` must show `git@github.com:RickLee-kr/xdr-poc-script.git` as `origin`.
3. **Scope** — changes are limited to the intended repository and branch; no accidental edits in deprecated or appliance paths.

When in doubt, stop and confirm repository and remote before committing.
