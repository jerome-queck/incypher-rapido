"""Public durable-control interface with sanitized read-only inspection."""

from __future__ import annotations

import base64
import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import RuntimeConfig
from .orchestrator import NativeRuntime, Orchestrator, RunReport
from .state import StateStore


@dataclass(frozen=True)
class JobView:
    job_id: str
    challenge_id: int
    catalogue_rank: int
    phase: str
    role: str
    lane: int
    state: str
    route_fingerprint: str
    admitted_sequence: int
    started_sequence: int | None
    closed_sequence: int | None


@dataclass(frozen=True)
class ControlView:
    run_id: str
    status: str
    catalogue_count: int
    initial_coverage_count: int
    pending_submission_count: int
    owned_instance_count: int
    jobs: tuple[JobView, ...]


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


class DurableJobControl:
    """Own one production run and expose only sanitized durable facts."""

    @staticmethod
    async def drive(config: RuntimeConfig, *, board: Any, runtime: NativeRuntime) -> RunReport:
        state = StateStore(config.state_path)
        try:
            return await Orchestrator(config, board, state, runtime).run()
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
                SELECT job_id, challenge_id, catalogue_rank, phase, role, lane, state,
                       route_fingerprint, admitted_sequence, started_sequence, closed_sequence
                FROM control_jobs WHERE run_id=?
                ORDER BY admitted_sequence, lane
                """,
                (selected_run_id,),
            ).fetchall()
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
                        phase=str(job["phase"]),
                        role=str(job["role"]),
                        lane=int(job["lane"]),
                        state=str(job["state"]),
                        route_fingerprint=(
                            "sha256:"
                            + base64.urlsafe_b64encode(bytes.fromhex(str(job["route_fingerprint"])))
                            .decode("ascii")
                            .rstrip("=")
                        ),
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
            )
        finally:
            connection.close()


__all__ = ["ControlView", "DurableJobControl", "JobView"]
