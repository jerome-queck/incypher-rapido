"""Command-line entrypoint."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
import time
from collections.abc import Awaitable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .board import BoardClient, BoardError
from .codex_app import CodexAppClient, CodexAppError
from .config import ConfigError, RuntimeConfig, validate_codex_home
from .control import DurableJobControl
from .monitor import append_private_jsonl, monitor_payload, render_text
from .orchestrator import _challenge_coherence_key
from .state import StateStore


async def _run_with_shutdown(operation: Awaitable[Any]):
    """Translate SIGTERM into structured task cancellation and durable cleanup."""
    loop = asyncio.get_running_loop()
    task = asyncio.create_task(operation)
    installed = False
    try:
        loop.add_signal_handler(signal.SIGTERM, task.cancel)
        installed = True
    except (NotImplementedError, RuntimeError):
        pass
    try:
        return await task
    finally:
        if installed:
            loop.remove_signal_handler(signal.SIGTERM)


def _codex_child_env(config: RuntimeConfig) -> dict[str, str]:
    """A deliberate allowlist; Board credentials never enter the model process."""
    return {
        "CODEX_HOME": str(config.codex_home),
        "HOME": str(config.codex_home),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TERM": "dumb",
        "NO_COLOR": "1",
    }


def _qualified_challenge_ids(
    rows: list[dict[str, Any]], confirmation: list[dict[str, Any]]
) -> list[int]:
    first = [row.get("id") for row in rows]
    second = [row.get("id") for row in confirmation]
    if (
        not first
        or any(type(value) is not int or value <= 0 for value in first + second)
        or len(first) != len(set(first))
        or len(second) != len(set(second))
        or sorted(first) != sorted(second)
    ):
        raise BoardError("consecutive challenge lists were empty or incoherent")
    return first  # type: ignore[return-value]


def _preflight() -> int:
    config = RuntimeConfig.from_env(require_board_auth=True)
    board = BoardClient(
        config.board_url,
        config.board_token,
        timeout=config.board_timeout_seconds,
        artifact_limit=config.max_artifact_bytes,
    )
    if not board.anonymous_identity_is_rejected():
        raise BoardError("anonymous Board identity negative control failed")
    identity = board.identity()
    identity_confirmation = board.identity()
    if type(identity.get("team_id")) is not int or identity["team_id"] <= 0:
        raise BoardError("authenticated Board identity has no qualified team")
    if identity_confirmation.get("id") != identity.get("id") or identity_confirmation.get(
        "team_id"
    ) != identity.get("team_id"):
        raise BoardError("consecutive Board identities were incoherent")
    rows = board.list_challenges()
    confirmation = board.list_challenges()
    _qualified_challenge_ids(rows, confirmation)
    ids = []
    categories: dict[str, int] = {}
    types: dict[str, int] = {}
    for row in rows:
        challenge_id = row.get("id")
        if type(challenge_id) is not int or challenge_id <= 0:
            raise BoardError("challenge list contains an invalid id")
        detail = board.challenge(challenge_id)
        if _challenge_coherence_key(board.challenge(challenge_id)) != _challenge_coherence_key(
            detail
        ):
            raise BoardError("consecutive challenge details were incoherent")
        ids.append(detail.id)
        categories[detail.category] = categories.get(detail.category, 0) + 1
        types[detail.type] = types.get(detail.type, 0) + 1
    final_ids = [row.get("id") for row in board.list_challenges()]
    if (
        any(type(value) is not int or value <= 0 for value in final_ids)
        or len(final_ids) != len(set(final_ids))
        or sorted(final_ids) != sorted(ids)
    ):
        raise BoardError("challenge list changed during qualification")
    final_identity = board.identity()
    if (
        final_identity.get("id") != identity["id"]
        or final_identity.get("team_id") != identity["team_id"]
    ):
        raise BoardError("Board identity changed during qualification")
    report = {
        "status": "ok",
        "authenticated": True,
        "identity_id": identity["id"],
        "team_id_present": type(identity.get("team_id")) is int,
        "challenge_count": len(ids),
        "challenge_ids": sorted(ids),
        "categories": dict(sorted(categories.items())),
        "types": dict(sorted(types.items())),
        "writes": 0,
        "effective_config": config.public_record(),
    }
    print(json.dumps(report, sort_keys=True))
    return 0


def _run() -> int:
    config = RuntimeConfig.from_env(require_board_auth=True)
    validate_codex_home(config.codex_home)
    board = BoardClient(
        config.board_url,
        config.board_token,
        timeout=config.board_timeout_seconds,
        artifact_limit=config.max_artifact_bytes,
    )
    runtime = CodexAppClient(
        env=_codex_child_env(config),
        binary=config.codex_binary,
        model=config.model,
        reasoning_effort=config.reasoning_effort,
        cwd=config.work_root,
        max_workspace_bytes=config.max_lane_workspace_bytes,
    )
    try:
        report = asyncio.run(
            _run_with_shutdown(DurableJobControl.drive(config, board=board, runtime=runtime))
        )
    except asyncio.CancelledError:
        print(json.dumps({"status": "interrupted"}), file=sys.stderr)
        return 130
    print(json.dumps(asdict(report), sort_keys=True))
    return 0 if report.status in {"completed", "deadline"} else 1


def _pending() -> int:
    config = RuntimeConfig.from_env()
    state = StateStore(config.state_path)
    try:
        print(json.dumps({"pending": state.pending_submission_intents()}, sort_keys=True))
    finally:
        state.close()
    return 0


def _reconcile(challenge_id: int, candidate_sha256: str, outcome: str) -> int:
    config = RuntimeConfig.from_env()
    state = StateStore(config.state_path)
    try:
        state.acquire_supervisor()
        state.reconcile_submission_intent(
            challenge_id,
            candidate_sha256,
            outcome.replace("-", "_"),
        )
    finally:
        state.close()
    print(json.dumps({"status": "reconciled", "outcome": outcome}, sort_keys=True))
    return 0


def _monitor(
    *, run_id: str | None, output_format: str, follow: bool, interval: int, record_jsonl: bool
) -> int:
    state_path = Path(os.environ.get("RAPIDO_STATE_PATH", "/state/rapido.sqlite3"))
    if not state_path.is_absolute():
        raise ConfigError("RAPIDO_STATE_PATH must be absolute")
    record_path = state_path.with_name("rapido-monitor.jsonl")
    if record_jsonl and record_path == state_path:
        raise ValueError("monitor record path must differ from the state database")
    previous: tuple[float, int] | None = None
    while True:
        view = DurableJobControl.monitor_snapshot(state_path, run_id=run_id)
        payload, previous = monitor_payload(view, previous)
        print(
            json.dumps(payload, sort_keys=True)
            if output_format == "json"
            else render_text(payload),
            flush=True,
        )
        if record_jsonl:
            append_private_jsonl(record_path, payload)
        if not follow or view.status != "running":
            return 0
        time.sleep(interval)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rapido")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("preflight", help="authenticated read-only Board contract check")
    subcommands.add_parser("config", help="print effective non-secret configuration")
    subcommands.add_parser("pending", help="list ambiguous submission fingerprints")
    reconcile = subcommands.add_parser(
        "reconcile", help="record an explicit operator finding for an ambiguous submission"
    )
    reconcile.add_argument("--challenge-id", type=int, required=True)
    reconcile.add_argument("--candidate-sha256", required=True)
    reconcile.add_argument(
        "--outcome", choices=("correct", "incorrect", "not-delivered"), required=True
    )
    monitor = subcommands.add_parser("monitor", help="show sanitized live queue and resource stats")
    monitor.add_argument("--run-id")
    monitor.add_argument("--format", choices=("text", "json"), default="text")
    monitor.add_argument("--follow", action="store_true")
    monitor.add_argument("--interval", type=int, choices=range(5, 301), default=10)
    monitor.add_argument("--record-jsonl", action="store_true")
    subcommands.add_parser("run", help="run the autonomous native-Codex queue")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "preflight":
            return _preflight()
        if arguments.command == "config":
            print(json.dumps(RuntimeConfig.from_env().public_record(), sort_keys=True))
            return 0
        if arguments.command == "pending":
            return _pending()
        if arguments.command == "reconcile":
            return _reconcile(
                arguments.challenge_id,
                arguments.candidate_sha256,
                arguments.outcome,
            )
        if arguments.command == "monitor":
            return _monitor(
                run_id=arguments.run_id,
                output_format=arguments.format,
                follow=arguments.follow,
                interval=arguments.interval,
                record_jsonl=arguments.record_jsonl,
            )
        if arguments.command == "run":
            return _run()
    except (BoardError, CodexAppError, ConfigError, OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"status": "interrupted"}), file=sys.stderr)
        return 130
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
