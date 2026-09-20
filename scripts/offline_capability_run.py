#!/usr/bin/env python3
"""Run one explicitly constructed private offline capability plan."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import io
import json
import os
import sys
from collections.abc import Callable
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from typing import Any

from rapido.offline_profile import assert_offline_environment
from rapido.offline_run import (
    OfflineRunRegistration,
    build_native_offline_plan,
    execute_offline_plan,
)


def _factory(value: str) -> Callable[[], OfflineRunRegistration]:
    module_name, separator, attribute = value.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("factory must use module:attribute")
    module = importlib.import_module(module_name)
    factory: Any = getattr(module, attribute)
    if not callable(factory):
        raise TypeError("offline plan factory is not callable")
    return factory


class _ClosedSink(io.TextIOBase):
    """Discard private setup output without retaining it in memory."""

    def __init__(self) -> None:
        self.wrote = False

    def write(self, value: str) -> int:
        self.wrote = self.wrote or bool(value)
        return len(value)


@contextmanager
def _discard_private_output():
    """Discard Python, fd, and inherited child output for the private execution scope."""
    private_stdout = _ClosedSink()
    private_stderr = _ClosedSink()
    sys.stdout.flush()
    sys.stderr.flush()
    saved_stdout = os.dup(1)
    saved_stderr = os.dup(2)
    discard = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(discard, 1)
        os.dup2(discard, 2)
        with redirect_stdout(private_stdout), redirect_stderr(private_stderr):
            yield private_stdout, private_stderr
    finally:
        os.dup2(saved_stdout, 1)
        os.dup2(saved_stderr, 2)
        os.close(saved_stdout)
        os.close(saved_stderr)
        os.close(discard)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--factory", required=True, help="private module:factory returning a plan")
    args = parser.parse_args(argv)
    try:
        assert_offline_environment()
        with _discard_private_output() as (private_stdout, private_stderr):
            registration = _factory(args.factory)()
            if type(registration) is not OfflineRunRegistration:
                raise TypeError("private factory did not return OfflineRunRegistration")
            plan = build_native_offline_plan(registration)
            receipt = asyncio.run(execute_offline_plan(plan))
        if private_stdout.wrote or private_stderr.wrote:
            raise RuntimeError("private setup emitted output")
    except (Exception, KeyboardInterrupt):  # noqa: BLE001 - closed public CLI boundary
        print(
            json.dumps(
                {
                    "schema": "rapido-offline-board-acceptance-v1",
                    "status": "failed",
                    "error": "offline_setup_failed",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    completed = receipt["status"] == "completed" and receipt["cleanup"]["exact_cleanup"] is True
    print(
        json.dumps(
            {
                "schema": receipt["schema"],
                "status": receipt["status"],
                "exact_cleanup": receipt["cleanup"]["exact_cleanup"],
                "run_completed": completed,
            },
            sort_keys=True,
        )
    )
    return 0 if completed else 1


if __name__ == "__main__":
    raise SystemExit(main())
