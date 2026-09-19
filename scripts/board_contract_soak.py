#!/usr/bin/env python3
"""Run the benign Board-contract smoke or preregistered real-clock soak."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import stat
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

import rapido.board_contract as BOARD_CONTRACT
from rapido.board_contract import run_contract
from rapido.clock import ManualClock, SystemClock

H24_SOAK_SECONDS = 19_800.0
MAX_BARRIER_LATENESS_MILLISECONDS = 1_000


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration-seconds", type=float, default=2.0)
    parser.add_argument("--accelerated", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--start-at-unix-ms", type=int)
    return parser.parse_args()


def _wait_for_start(
    start_at_unix_ms: int | None,
    *,
    wall_time_ns: Callable[[], int] = time.time_ns,
    sleep: Callable[[float], None] = time.sleep,
) -> int | None:
    if start_at_unix_ms is None:
        return None
    if isinstance(start_at_unix_ms, bool) or start_at_unix_ms <= 0:
        raise ValueError("start barrier must be a positive Unix millisecond")
    while True:
        remaining_ms = start_at_unix_ms - wall_time_ns() // 1_000_000
        if remaining_ms < -MAX_BARRIER_LATENESS_MILLISECONDS:
            raise ValueError("start barrier is already stale")
        if remaining_ms > 300_000:
            raise ValueError("start barrier is too far in the future")
        if remaining_ms <= 0:
            break
        sleep(remaining_ms / 1_000)
    return start_at_unix_ms + int(H24_SOAK_SECONDS * 1_000)


def _absolute_window_from_barrier(
    registered_deadline_wall_milliseconds: int | None,
    *,
    monotonic: Callable[[], float],
    wall_time_ns: Callable[[], int] = time.time_ns,
) -> tuple[float | None, float | None]:
    if registered_deadline_wall_milliseconds is None:
        return None, None
    registered_start = registered_deadline_wall_milliseconds - int(H24_SOAK_SECONDS * 1_000)
    current_wall_milliseconds = wall_time_ns() // 1_000_000
    if current_wall_milliseconds < registered_start:
        raise ValueError("start barrier has not been reached")
    lateness_milliseconds = current_wall_milliseconds - registered_start
    if lateness_milliseconds > MAX_BARRIER_LATENESS_MILLISECONDS:
        raise ValueError("start barrier is already stale")
    current_monotonic = monotonic()
    origin = current_monotonic - lateness_milliseconds / 1_000
    if origin < 0:
        raise ValueError("start barrier monotonic origin is invalid")
    return origin, origin + H24_SOAK_SECONDS


def _write_private_output(path: Path, encoded: str) -> None:
    if not path.is_absolute():
        raise ValueError("output path must be absolute")
    try:
        parent = path.parent.lstat()
    except OSError as exc:
        raise ValueError("output directory is unavailable") from exc
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise ValueError("output directory is invalid")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def main() -> int:
    BOARD_CONTRACT._PACKAGED_OFFLINE_PILOT_DIRECTORY = Path(__file__).resolve().parent
    arguments = _arguments()
    if not 0 < arguments.duration_seconds <= 19_800:
        raise SystemExit("--duration-seconds must be within 0..19800")
    if arguments.start_at_unix_ms is not None and arguments.duration_seconds != H24_SOAK_SECONDS:
        raise SystemExit("--start-at-unix-ms requires the frozen 19800-second H24 soak")
    try:
        registered_wall_deadline = _wait_for_start(arguments.start_at_unix_ms)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    clock = ManualClock() if arguments.accelerated else SystemClock()
    try:
        absolute_origin, absolute_deadline = _absolute_window_from_barrier(
            registered_wall_deadline,
            monotonic=clock.monotonic,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    with tempfile.TemporaryDirectory(prefix="rapido-board-contract-") as directory:
        receipt = asyncio.run(
            run_contract(
                Path(directory),
                private_seed=os.urandom(32),
                clock=clock,
                soak_seconds=arguments.duration_seconds,
                absolute_origin=absolute_origin,
                absolute_deadline=absolute_deadline,
            )
        ).public()
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
    if arguments.output is None:
        print(encoded, end="")
    else:
        try:
            _write_private_output(arguments.output, encoded)
        except (OSError, ValueError) as exc:
            raise SystemExit(str(exc)) from exc
    return 0 if receipt["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
