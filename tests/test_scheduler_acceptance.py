from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "scheduler_acceptance",
    Path(__file__).resolve().parents[1] / "scripts" / "scheduler_acceptance.py",
)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)
run_benchmark = HARNESS.run_benchmark


def test_offline_scheduler_contract() -> None:
    # Shared-runner wall time is not a stable CI assertion. The deliberate CLI
    # benchmark retains the measured <=0.70 gate; CI verifies its deterministic
    # topology, outcomes, cleanup, and state-integrity contracts.
    result = run_benchmark(max_elapsed_ratio=None)
    assert result["gate"] == {"passed": True, "failures": []}
    assert result["arms"]["A"]["outcomes"] == result["arms"]["C"]["outcomes"]
    assert result["arms"]["A"]["attempts"] == result["arms"]["C"]["attempts"] == 30
    assert result["arms"]["A"]["max_active_distinct_challenges"] == 1
    assert result["arms"]["C"]["max_active_distinct_challenges"] == 2
    assert result["arms"]["A"]["max_turns"] == 2
    assert result["arms"]["C"]["max_turns"] == 4
    assert HARNESS._gate(result["arms"], 99.0, None) == []
    assert HARNESS._gate(result["arms"], 0.71, 0.70) == ["arm C elapsed ratio exceeded 0.70"]
