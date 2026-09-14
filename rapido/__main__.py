"""CLI: `python -m rapido demo` or `python -m rapido preflight`."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
import tempfile
from pathlib import Path

from .board import ContractError, ReadOnlyBoard
from .offline import Ledger, fixtures, run_jobs


def save_report(path: str, report: dict) -> None:
    """Atomic owner-only report file. Never serialize credentials or HTTP bodies."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".rapido-", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


async def demo(args: argparse.Namespace) -> dict:
    loop = asyncio.get_running_loop()
    current = asyncio.current_task()
    assert current is not None
    loop.add_signal_handler(signal.SIGTERM, current.cancel)
    try:
        with Ledger(args.db) as ledger:
            return await run_jobs(
                fixtures(), ledger, lanes=args.lanes,
                deadline_seconds=args.deadline, simulated_io_seconds=0.05,
            )
    finally:
        loop.remove_signal_handler(signal.SIGTERM)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    offline = sub.add_parser("demo", help="only bundled, benign offline fixtures")
    offline.add_argument("--db", default="/tmp/rapido/demo.sqlite3")
    offline.add_argument("--lanes", type=int, default=2)
    offline.add_argument("--deadline", type=float, default=10.0)
    offline.add_argument("--output")
    preflight = sub.add_parser("preflight", help="GET-only official Board metadata")
    preflight.add_argument("--output")
    args = parser.parse_args()
    try:
        if args.command == "demo":
            report = asyncio.run(demo(args))
        else:
            report = ReadOnlyBoard(os.environ.get("CTFD_API_TOKEN", "")).snapshot()
        if args.output:
            save_report(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
        if args.command == "demo":
            return 0 if all(
                r["status"] in ("verified", "cached") for r in report["results"]
            ) else 2
        return 0 if report["team_membership_observed"] else 2
    except (ContractError, ValueError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, asyncio.CancelledError):
        print('{"status":"cancelled"}', file=sys.stderr)
        return 130
    except Exception:
        # Transport/SQLite/OS errors can contain sensitive paths or response data.
        print('{"status":"failed","reason":"local I/O or internal error"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
