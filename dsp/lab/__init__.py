"""DSP lab operational harness — traffic execution without detection validation."""

from dsp.lab.operational_runner import (
    BatchLabRunResult,
    LabRunResult,
    build_parser,
    resolve_active_scenario_ids,
    run_from_args,
    run_local_lab,
    run_local_lab_batch,
    run_webshell_lab,
    run_webshell_lab_batch,
)

__all__ = [
    "BatchLabRunResult",
    "LabRunResult",
    "build_parser",
    "resolve_active_scenario_ids",
    "run_from_args",
    "run_local_lab",
    "run_local_lab_batch",
    "run_webshell_lab",
    "run_webshell_lab_batch",
]
