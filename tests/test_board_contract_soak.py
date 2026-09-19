from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "board_contract_soak",
    Path(__file__).resolve().parents[1] / "scripts" / "board_contract_soak.py",
)
assert SPEC is not None and SPEC.loader is not None
SOAK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SOAK
SPEC.loader.exec_module(SOAK)


def test_start_barrier_waits_only_for_bounded_future_window() -> None:
    sleeps: list[float] = []
    SOAK._wait_for_start(
        1_015_000,
        wall_time_ns=lambda: 1_000_000_000_000,
        sleep=sleeps.append,
    )
    assert sleeps == [15.0]


def test_start_barrier_accepts_small_scheduling_lag_without_sleep() -> None:
    sleeps: list[float] = []
    SOAK._wait_for_start(
        999_500,
        wall_time_ns=lambda: 1_000_000_000_000,
        sleep=sleeps.append,
    )
    assert sleeps == []


@pytest.mark.parametrize("start", (0, -1, 998_999, 1_300_001))
def test_start_barrier_rejects_invalid_stale_or_unbounded_values(start: int) -> None:
    with pytest.raises(ValueError, match="start barrier"):
        SOAK._wait_for_start(start, wall_time_ns=lambda: 1_000_000_000_000)


def test_output_is_exclusive_and_mode_0600(tmp_path: Path) -> None:
    output = tmp_path / "soak.json"
    SOAK._write_private_output(output, '{"schema":"test"}\n')

    assert output.read_text() == '{"schema":"test"}\n'
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        SOAK._write_private_output(output, "replacement")
