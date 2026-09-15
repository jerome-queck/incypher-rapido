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


def test_offline_scheduler_acceptance_gate() -> None:
    result = run_benchmark()
    assert result["gate"] == {"passed": True, "failures": []}
    assert result["arms"]["A"]["outcomes"] == result["arms"]["C"]["outcomes"]
    assert result["arms"]["A"]["attempts"] == result["arms"]["C"]["attempts"] == 30
    assert result["ratio"] <= 0.70
