from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
from pathlib import Path

import pytest

import rapido.board_contract as BOARD_CONTRACT
from rapido.board_contract import run_contract
from rapido.clock import ManualClock

SPEC = importlib.util.spec_from_file_location(
    "board_contract_soak",
    Path(__file__).resolve().parents[1] / "scripts" / "board_contract_soak.py",
)
assert SPEC is not None and SPEC.loader is not None
SOAK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SOAK
SPEC.loader.exec_module(SOAK)


@pytest.fixture(autouse=True)
def _checkout_offline_pilot(monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = "_rapido_board_contract_offline_pilot"
    monkeypatch.setattr(
        BOARD_CONTRACT,
        "_PACKAGED_OFFLINE_PILOT_DIRECTORY",
        Path(__file__).resolve().parents[1] / "scripts",
    )
    sys.modules.pop(module_name, None)
    yield
    sys.modules.pop(module_name, None)


def test_start_barrier_waits_only_for_bounded_future_window() -> None:
    sleeps: list[float] = []
    wall_milliseconds = 1_000_000

    def sleep(seconds: float) -> None:
        nonlocal wall_milliseconds
        sleeps.append(seconds)
        wall_milliseconds += round(seconds * 1_000)

    deadline = SOAK._wait_for_start(
        1_015_000,
        wall_time_ns=lambda: wall_milliseconds * 1_000_000,
        sleep=sleep,
    )
    assert sleeps == [15.0]
    assert deadline == 20_815_000


def test_start_barrier_accepts_small_scheduling_lag_without_sleep() -> None:
    sleeps: list[float] = []
    deadline = SOAK._wait_for_start(
        999_500,
        wall_time_ns=lambda: 1_000_000_000_000,
        sleep=sleeps.append,
    )
    assert sleeps == []
    assert deadline == 20_799_500


@pytest.mark.parametrize("start", (0, -1, 998_999, 1_300_001))
def test_start_barrier_rejects_invalid_stale_or_unbounded_values(start: int) -> None:
    with pytest.raises(ValueError, match="start barrier"):
        SOAK._wait_for_start(start, wall_time_ns=lambda: 1_000_000_000_000)


def test_barrier_window_rejects_wall_rollback_and_staleness() -> None:
    deadline = 1_000_000 + 19_800_000
    with pytest.raises(ValueError, match="has not been reached"):
        SOAK._absolute_window_from_barrier(
            deadline,
            monotonic=lambda: 100.0,
            wall_time_ns=lambda: 999_999 * 1_000_000,
        )
    with pytest.raises(ValueError, match="already stale"):
        SOAK._absolute_window_from_barrier(
            deadline,
            monotonic=lambda: 100.0,
            wall_time_ns=lambda: 1_001_001 * 1_000_000,
        )


def test_barrier_oversleep_and_setup_reduce_watch_without_deadline_extension(
    tmp_path: Path,
) -> None:
    start_wall_milliseconds = 1_000_000
    wall_milliseconds = start_wall_milliseconds - 1_000
    clock = ManualClock(100.0)

    def oversleep(seconds: float) -> None:
        nonlocal wall_milliseconds
        actual = seconds + 0.5
        wall_milliseconds += round(actual * 1_000)
        clock.advance(actual)

    registered_wall_deadline = SOAK._wait_for_start(
        start_wall_milliseconds,
        wall_time_ns=lambda: wall_milliseconds * 1_000_000,
        sleep=oversleep,
    )
    origin, deadline = SOAK._absolute_window_from_barrier(
        registered_wall_deadline,
        monotonic=clock.monotonic,
        wall_time_ns=lambda: wall_milliseconds * 1_000_000,
    )
    assert origin == 101.0
    assert deadline == 19_901.0

    clock.advance(7.0)
    entered_at = clock.monotonic()
    receipt = asyncio.run(
        run_contract(
            tmp_path,
            private_seed=os.urandom(32),
            clock=clock,
            soak_seconds=SOAK.H24_SOAK_SECONDS,
            absolute_origin=origin,
            absolute_deadline=deadline,
        )
    ).public()

    assert receipt["requested_seconds"] == SOAK.H24_SOAK_SECONDS
    assert receipt["correctness_denominator_included"] is False
    assert receipt["scenario_count"] == receipt["passed_count"] == 10
    assert clock.monotonic() == deadline
    assert sum(clock.sleeps) == pytest.approx(deadline - entered_at)
    scenario = next(
        row
        for row in receipt["scenarios"]
        if row["scenario_id"] == "watch_change_original_deadline"
    )
    assert scenario["facts"]["deadline_seconds"] == SOAK.H24_SOAK_SECONDS
    assert scenario["facts"]["deadline_unchanged"] is True
    assert 7.5 < scenario["facts"]["transient_offset_seconds"] <= SOAK.H24_SOAK_SECONDS
    assert 7.5 < scenario["facts"]["change_offset_seconds"] <= SOAK.H24_SOAK_SECONDS


def test_output_is_exclusive_and_mode_0600(tmp_path: Path) -> None:
    output = tmp_path / "soak.json"
    SOAK._write_private_output(output, '{"schema":"test"}\n')

    assert output.read_text() == '{"schema":"test"}\n'
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        SOAK._write_private_output(output, "replacement")
