#!/usr/bin/env python3
"""Run the benign Board-contract smoke or preregistered real-clock soak."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
from pathlib import Path

from rapido.board_contract import run_contract
from rapido.clock import ManualClock, SystemClock


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration-seconds", type=float, default=2.0)
    parser.add_argument("--accelerated", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    if not 0 < arguments.duration_seconds <= 19_800:
        raise SystemExit("--duration-seconds must be within 0..19800")
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
        arguments.output.write_text(encoded)
    return 0 if receipt["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
