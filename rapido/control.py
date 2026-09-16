"""Public durable-control interface with sanitized read-only inspection."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import RuntimeConfig
from .orchestrator import NativeRuntime, Orchestrator, RunReport
from .routing import DISPOSITIONS, FAILURE_KINDS, ROUTE_AXES
from .state import StateStore


class _AdaptiveOrchestrator(Orchestrator):
    """Private adaptive entry point owned by DurableJobControl."""

    _adaptive_control = True


@dataclass(frozen=True)
class JobView:
    job_id: str
    challenge_id: int
    catalogue_rank: int
    episode: int
    phase: str
    role: str
    lane: int
    state: str
    route_fingerprint: str
    admitted_sequence: int
    started_sequence: int | None
    closed_sequence: int | None


@dataclass(frozen=True)
class RouteDecisionView:
    decision_sequence: int
    challenge_id: int
    source_episode: int
    failure_kind: str
    failure_subreason: str
    disposition: str
    rule_id: str
    source_route_fingerprint: str
    successor_route_fingerprint: str | None
    changed_axes: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class ControlView:
    run_id: str
    status: str
    catalogue_count: int
    initial_coverage_count: int
    pending_submission_count: int
    owned_instance_count: int
    jobs: tuple[JobView, ...]
    route_decisions: tuple[RouteDecisionView, ...]


def _public_fingerprint(value: object | None) -> str | None:
    if value is None:
        return None
    raw = str(value)
    if len(raw) != 64 or any(character not in "0123456789abcdef" for character in raw):
        raise ValueError("durable route fingerprint is invalid")
    return "sha256:" + base64.urlsafe_b64encode(bytes.fromhex(raw)).decode("ascii").rstrip("=")


def _read_only_connection(path: Path) -> sqlite3.Connection:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("state database must be a regular file, never a symlink")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    os.close(descriptor)
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _changed_axes(value: object) -> tuple[str, ...]:
    try:
        decoded = json.loads(str(value))
    except json.JSONDecodeError as exc:
        raise ValueError("durable changed axes are invalid") from exc
    if (
        not isinstance(decoded, list)
        or any(not isinstance(item, str) or item not in ROUTE_AXES for item in decoded)
        or len(set(decoded)) != len(decoded)
    ):
        raise ValueError("durable changed axes are invalid")
    return tuple(decoded)


class DurableJobControl:
    """Own one production run and expose only sanitized durable facts."""

    @staticmethod
    async def drive(config: RuntimeConfig, *, board: Any, runtime: NativeRuntime) -> RunReport:
        state = StateStore(config.state_path)
        try:
            return await _AdaptiveOrchestrator(config, board, state, runtime).run()
        finally:
            state.close()

    @staticmethod
    def inspect(state_path: Path, run_id: str | None = None) -> ControlView:
        connection = _read_only_connection(state_path)
        try:
            connection.execute("BEGIN")
            if run_id is None:
                row = connection.execute(
                    "SELECT id, status FROM runs ORDER BY started_at DESC, id DESC LIMIT 1"
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT id, status FROM runs WHERE id=?", (run_id,)
                ).fetchone()
            if row is None:
                raise ValueError("run is absent")
            selected_run_id = str(row["id"])
            catalogue_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM control_catalogue WHERE run_id=?",
                    (selected_run_id,),
                ).fetchone()[0]
            )
            initial_coverage_count = int(
                connection.execute(
                    "SELECT COUNT(DISTINCT challenge_id) FROM control_jobs "
                    "WHERE run_id=? AND phase='initial' AND started_sequence IS NOT NULL",
                    (selected_run_id,),
                ).fetchone()[0]
            )
            pending_submission_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM submission_intents WHERE status='pending'"
                ).fetchone()[0]
            )
            owned_instance_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM instances "
                    "WHERE status IN ('creating', 'owned', 'cleanup_pending')"
                ).fetchone()[0]
            )
            job_rows = connection.execute(
                """
                SELECT job_id, challenge_id, catalogue_rank, episode, phase, role, lane, state,
                       route_fingerprint, admitted_sequence, started_sequence, closed_sequence
                FROM control_jobs WHERE run_id=?
                ORDER BY admitted_sequence, lane
                """,
                (selected_run_id,),
            ).fetchall()
            has_decisions = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='control_route_decisions'"
            ).fetchone()
            decision_rows = (
                []
                if has_decisions is None
                else connection.execute(
                    """
                    SELECT decision_sequence, challenge_id, source_episode,
                           failure_kind, failure_subreason, disposition, rule_id,
                           source_route_fingerprint, successor_route_fingerprint,
                           changed_axes_json, reason
                    FROM control_route_decisions WHERE run_id=?
                    ORDER BY decision_sequence
                    """,
                    (selected_run_id,),
                ).fetchall()
            )
            for decision in decision_rows:
                if (
                    str(decision["failure_kind"]) not in FAILURE_KINDS
                    or str(decision["disposition"]) not in DISPOSITIONS
                ):
                    raise ValueError("durable route decision is invalid")
            return ControlView(
                run_id=selected_run_id,
                status=str(row["status"]),
                catalogue_count=catalogue_count,
                initial_coverage_count=initial_coverage_count,
                pending_submission_count=pending_submission_count,
                owned_instance_count=owned_instance_count,
                jobs=tuple(
                    JobView(
                        job_id=str(job["job_id"]),
                        challenge_id=int(job["challenge_id"]),
                        catalogue_rank=int(job["catalogue_rank"]),
                        episode=int(job["episode"]),
                        phase=str(job["phase"]),
                        role=str(job["role"]),
                        lane=int(job["lane"]),
                        state=str(job["state"]),
                        route_fingerprint=str(_public_fingerprint(job["route_fingerprint"])),
                        admitted_sequence=int(job["admitted_sequence"]),
                        started_sequence=(
                            None
                            if job["started_sequence"] is None
                            else int(job["started_sequence"])
                        ),
                        closed_sequence=(
                            None if job["closed_sequence"] is None else int(job["closed_sequence"])
                        ),
                    )
                    for job in job_rows
                ),
                route_decisions=tuple(
                    RouteDecisionView(
                        decision_sequence=int(decision["decision_sequence"]),
                        challenge_id=int(decision["challenge_id"]),
                        source_episode=int(decision["source_episode"]),
                        failure_kind=str(decision["failure_kind"]),
                        failure_subreason=str(decision["failure_subreason"]),
                        disposition=str(decision["disposition"]),
                        rule_id=str(decision["rule_id"]),
                        source_route_fingerprint=str(
                            _public_fingerprint(decision["source_route_fingerprint"])
                        ),
                        successor_route_fingerprint=_public_fingerprint(
                            decision["successor_route_fingerprint"]
                        ),
                        changed_axes=_changed_axes(decision["changed_axes_json"]),
                        reason=str(decision["reason"]),
                    )
                    for decision in decision_rows
                ),
            )
        finally:
            connection.close()


__all__ = ["ControlView", "DurableJobControl", "JobView", "RouteDecisionView"]
