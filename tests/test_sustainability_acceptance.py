from __future__ import annotations

import asyncio
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS_PATH = ROOT / "scripts" / "sustainability_acceptance.py"
SPEC = importlib.util.spec_from_file_location("sustainability_acceptance", HARNESS_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)
assess, cycle, run = HARNESS.assess, HARNESS.cycle, HARNESS.run


def samples():
    return [
        {
            "cycle": index,
            "seconds": float(index),
            "heap_bytes": 100_000,
            "rss_high_water_bytes": 10_000_000,
            "storage_bytes": 50_000 + index * 4096,
            "cpu_seconds": index * 0.1,
            "fds": 8,
            "tasks": 1,
            "threads": 1,
        }
        for index in range(13)
    ]


def test_synthetic_reopen_faults_and_queue_finish(tmp_path):
    async def exercise():
        first = await cycle(tmp_path, 0, 2, 8)
        second = await cycle(tmp_path, 1, 2, 8)
        assert first == second
        assert first == {
            "unsolved": 2,
            "failed": 2,
            "timeout": 2,
            "cancelled": 2,
            "recovered": 1,
            "peak_active": 2,
            "peak_queue": 2,
        }

    asyncio.run(exercise())


def test_unsolved_outcome_is_not_scheduler_timing_dependent(tmp_path, monkeypatch):
    original = HARNESS._operation

    async def delayed_operation(kind):
        if kind == "unsolved":
            await asyncio.sleep(0.01)
        await original(kind)

    monkeypatch.setattr(HARNESS, "_operation", delayed_operation)
    result = asyncio.run(cycle(tmp_path, 0, 2, 8))
    assert result["unsolved"] == 2
    assert result["timeout"] == 2


def test_projection_uses_twice_rate_plus_growth_slack():
    report = assess(samples(), 100)
    assert report["status"] == "passed"
    assert report["projection_cycles_at_twice_observed_rate"] == 200
    storage = report["growth"]["storage_bytes"]
    assert storage["projected_bytes"] == 50_000 + 12 * 4096 + (4096 + 8192) * 200


@pytest.mark.parametrize("resource", ["fds", "tasks", "threads"])
def test_retained_resource_is_failure(resource):
    rows = samples()
    rows[-1][resource] += 1
    report = assess(rows, 100)
    assert report["status"] == "failed"
    assert any(resource in error for error in report["failures"])


def test_linear_heap_leak_and_nonlinear_storage_growth_fail():
    rows = samples()
    for index, row in enumerate(rows):
        row["heap_bytes"] += index * 4096
        if index > 6:
            row["storage_bytes"] += (index - 6) ** 2 * 4096
    report = assess(rows, 100)
    assert any("heap_bytes: growth" in error for error in report["failures"])
    assert any("storage_bytes: late growth" in error for error in report["failures"])


def test_missing_sampler_cannot_pass():
    rows = samples()
    rows[3]["fds"] = None
    assert "fds: sampler unavailable" in assess(rows, 100)["failures"]


def test_cancelled_cycle_drains_workers_and_releases_state(tmp_path):
    async def exercise():
        baseline = set(asyncio.all_tasks())
        task = asyncio.create_task(cycle(tmp_path, 0, 1, 256))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert set(asyncio.all_tasks()) == baseline
        # A later cycle can acquire the state lease and drain all interrupted rows.
        from rapido.state import StateStore

        store = StateStore(tmp_path / "state.sqlite3")
        try:
            store.acquire_supervisor()
            assert store.recover_interrupted() >= 1
            assert store.active_attempts() == []
        finally:
            store.close()

    asyncio.run(exercise())


def test_short_real_measurement_reports_scope_and_samples():
    completed = subprocess.run(
        [sys.executable, str(HARNESS_PATH), "--cycles", "48"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    report = json.loads(completed.stdout)
    assert completed.returncode == 0, report.get("failures")
    assert report["status"] == "passed", report["failures"]
    assert report["outcomes"]["recovered"] == 48
    assert len(report["samples"]) == 49
    assert report["peak_active"] <= report["workers"]
    assert report["peak_queue"] <= report["workers"]
    assert "synthetic" in report["scope"]
    assert report["limitations"]


@pytest.mark.parametrize("kwargs", [{"cycles": 1}, {"workers": 0}, {"jobs": 1000}])
def test_unbounded_or_insufficient_configuration_rejected(kwargs):
    with pytest.raises(ValueError):
        asyncio.run(run(**kwargs))
