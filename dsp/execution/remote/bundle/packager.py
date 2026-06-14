"""Package local scenario bundles for webshell upload."""

from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ASSETS_DIR = Path(__file__).resolve().parent / "assets"
_RUNNER_ASSET = _ASSETS_DIR / "run_scenario.py"


@dataclass(frozen=True)
class ScenarioBundlePackage:
    local_dir: Path
    remote_run_dir: str
    remote_files: tuple[tuple[str, Path], ...]


def pack_scenario_bundle(manifest: dict[str, Any]) -> ScenarioBundlePackage:
    """Write manifest.json and run_scenario.py into a local staging directory."""
    paths = manifest.get("paths") or {}
    remote_run_dir = str(paths.get("work_dir"))
    if not remote_run_dir:
        raise ValueError("manifest.paths.work_dir is required")

    local_dir = Path(tempfile.mkdtemp(prefix="dsp-bundle-"))
    manifest_path = local_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    runner_path = local_dir / "run_scenario.py"
    if not _RUNNER_ASSET.is_file():
        raise FileNotFoundError(f"bundle runner asset not found: {_RUNNER_ASSET}")
    shutil.copyfile(_RUNNER_ASSET, runner_path)
    runner_path.chmod(0o755)

    remote_files = (
        (f"{remote_run_dir}/manifest.json", manifest_path),
        (f"{remote_run_dir}/run_scenario.py", runner_path),
    )
    return ScenarioBundlePackage(
        local_dir=local_dir,
        remote_run_dir=remote_run_dir,
        remote_files=remote_files,
    )
