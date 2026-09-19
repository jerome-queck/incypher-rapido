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

from rapido.board_contract import run_contract
from rapido.clock import ManualClock, SystemClock


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
) -> None:
    if start_at_unix_ms is None:
        return
    if isinstance(start_at_unix_ms, bool) or start_at_unix_ms <= 0:
        raise ValueError("start barrier must be a positive Unix millisecond")
    remaining_ms = start_at_unix_ms - wall_time_ns() // 1_000_000
    if remaining_ms < -1_000:
        raise ValueError("start barrier is already stale")
    if remaining_ms > 300_000:
        raise ValueError("start barrier is too far in the future")
    if remaining_ms > 0:
        sleep(remaining_ms / 1_000)


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
    arguments = _arguments()
    if not 0 < arguments.duration_seconds <= 19_800:
        raise SystemExit("--duration-seconds must be within 0..19800")
    try:
        _wait_for_start(arguments.start_at_unix_ms)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    clock = ManualClock() if arguments.accelerated else SystemClock()
    with tempfile.TemporaryDirectory(prefix="rapido-board-contract-") as directory:
        receipt = asyncio.run(
            run_contract(
                Path(directory),
                private_seed=os.urandom(32),
                clock=clock,
                soak_seconds=arguments.duration_seconds,
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
