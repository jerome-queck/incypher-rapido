"""Public durable-control interface with sanitized read-only inspection."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
    agent_role: str
    model: str
    effort: str
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
    pending_candidate_count: int
    verified_candidate_count: int
    jobs: tuple[JobView, ...]
    route_decisions: tuple[RouteDecisionView, ...]


@dataclass(frozen=True)
class RunningLaneView:
    challenge_id: int
    episode: int
    lane: int
    role: str
    agent_role: str
    model: str
    effort: str
    tool_calls: int


@dataclass(frozen=True)
class MonitorView:
    schema: str
    sampled_at: str
    run_id: str
    status: str
    started_at: str
    deadline_at: str
    remaining_seconds: int
    watching: bool
    catalogue_count: int
    initial_coverage_count: int
    active_challenge_ids: tuple[int, ...]
    queued_challenge_ids: tuple[int, ...]
    instance_waiting_challenge_ids: tuple[int, ...]
    terminal_challenge_ids: tuple[int, ...]
    lane_states: tuple[tuple[str, int], ...]
    reserved_lane_count: int
    completed_waiting_lane_count: int
    running_lanes: tuple[RunningLaneView, ...]
    attempt_count: int
    tool_call_count: int
    continuation_count: int
    pending_submission_count: int
    submission_outcomes: tuple[tuple[str, int], ...]
    pending_candidate_count: int
    verified_candidate_count: int
    instance_states: tuple[tuple[str, int], ...]


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


def _current_candidate_counts(connection: sqlite3.Connection, run_id: str) -> tuple[int, int]:
    has_candidate_vault = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='candidate_proposals'"
    ).fetchone()
    if has_candidate_vault is None:
        return 0, 0
    pending = int(
        connection.execute(
            """
            SELECT COUNT(*) FROM (
              SELECT proposal.challenge_id, proposal.candidate_key
              FROM candidate_proposals AS proposal
              JOIN control_catalogue AS catalogue
                ON catalogue.run_id=proposal.run_id
               AND catalogue.challenge_id=proposal.challenge_id
              WHERE proposal.run_id=?
                AND proposal.episode>=catalogue.context_episode
                AND proposal.role IN ('specialist', 'recovery')
                AND NOT EXISTS (
                  SELECT 1 FROM submission_intents AS settled
                  WHERE settled.challenge_id=proposal.challenge_id
                    AND settled.candidate_sha256=lower(hex(proposal.candidate_key))
                    AND settled.status IN ('correct', 'incorrect', 'already_solved')
                )
                AND NOT EXISTS (
                  SELECT 1 FROM candidate_verifications AS verification
                  JOIN candidate_evidence_proofs AS producer_proof
                    ON producer_proof.source_attempt_id=verification.producer_attempt_id
                   AND producer_proof.run_id=verification.run_id
                   AND producer_proof.challenge_id=verification.challenge_id
                   AND producer_proof.candidate_key=verification.candidate_key
                  JOIN candidate_evidence_proofs AS verifier_proof
                    ON verifier_proof.source_attempt_id=verification.verifier_attempt_id
                   AND verifier_proof.run_id=verification.run_id
                   AND verifier_proof.challenge_id=verification.challenge_id
                   AND verifier_proof.candidate_key=verification.candidate_key
                  WHERE verification.run_id=proposal.run_id
                    AND verification.challenge_id=proposal.challenge_id
                    AND verification.candidate_key=proposal.candidate_key
                )
              GROUP BY proposal.challenge_id, proposal.candidate_key
            )
            """,
            (run_id,),
        ).fetchone()[0]
    )
    verified = int(
        connection.execute(
            """
            SELECT COUNT(*)
            FROM candidate_verifications AS verification
            JOIN candidate_proposals AS proposal
              ON proposal.source_attempt_id=verification.producer_attempt_id
            JOIN control_catalogue AS catalogue
              ON catalogue.run_id=proposal.run_id
             AND catalogue.challenge_id=proposal.challenge_id
            JOIN candidate_evidence_proofs AS producer_proof
              ON producer_proof.source_attempt_id=verification.producer_attempt_id
             AND producer_proof.run_id=verification.run_id
             AND producer_proof.challenge_id=verification.challenge_id
             AND producer_proof.candidate_key=verification.candidate_key
            JOIN candidate_evidence_proofs AS verifier_proof
              ON verifier_proof.source_attempt_id=verification.verifier_attempt_id
             AND verifier_proof.run_id=verification.run_id
             AND verifier_proof.challenge_id=verification.challenge_id
             AND verifier_proof.candidate_key=verification.candidate_key
            WHERE verification.run_id=?
              AND proposal.episode>=catalogue.context_episode
            """,
            (run_id,),
        ).fetchone()[0]
    )
    return pending, verified


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
            pending_candidate_count, verified_candidate_count = _current_candidate_counts(
                connection, selected_run_id
            )
            job_rows = connection.execute(
                """
                SELECT job_id, challenge_id, catalogue_rank, episode, phase, role,
                       agent_role, model, effort, lane, state, route_fingerprint,
                       admitted_sequence, started_sequence, closed_sequence
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
                pending_candidate_count=pending_candidate_count,
                verified_candidate_count=verified_candidate_count,
                jobs=tuple(
                    JobView(
                        job_id=str(job["job_id"]),
                        challenge_id=int(job["challenge_id"]),
                        catalogue_rank=int(job["catalogue_rank"]),
                        episode=int(job["episode"]),
                        phase=str(job["phase"]),
                        role=str(job["role"]),
                        agent_role=str(job["agent_role"]),
                        model=str(job["model"]),
                        effort=str(job["effort"]),
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

    @staticmethod
    def monitor_snapshot(state_path: Path, run_id: str | None = None) -> MonitorView:
        """Return bounded operational counters without reading private solver payloads."""
        connection = _read_only_connection(state_path)
        try:
            connection.execute("BEGIN")
            if run_id is None:
                run = connection.execute(
                    "SELECT id, status, started_at, config_json FROM runs "
                    "ORDER BY started_at DESC, id DESC LIMIT 1"
                ).fetchone()
            else:
                run = connection.execute(
                    "SELECT id, status, started_at, config_json FROM runs WHERE id=?", (run_id,)
                ).fetchone()
            if run is None:
                raise ValueError("run is absent")
            selected_run_id = str(run["id"])
            try:
                started = datetime.fromisoformat(str(run["started_at"]))
                config = json.loads(str(run["config_json"]))
                run_seconds = int(config["run_seconds"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError("run timing is invalid") from exc
            if started.tzinfo is None or run_seconds < 0:
                raise ValueError("run timing is invalid")
            deadline = started.astimezone(UTC) + timedelta(seconds=run_seconds)
            sampled = datetime.now(UTC)
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
            pending_candidate_count, verified_candidate_count = _current_candidate_counts(
                connection, selected_run_id
            )

            catalogue_ids = {
                int(row[0])
                for row in connection.execute(
                    "SELECT challenge_id FROM control_catalogue WHERE run_id=?",
                    (selected_run_id,),
                ).fetchall()
            }
            active_ids = {
                int(row[0])
                for row in connection.execute(
                    "SELECT DISTINCT jobs.challenge_id FROM control_jobs AS jobs "
                    "JOIN attempts AS attempt "
                    "ON attempt.run_id=jobs.run_id "
                    "AND attempt.challenge_id=jobs.challenge_id "
                    "AND attempt.episode=jobs.episode AND attempt.lane=jobs.lane "
                    "WHERE jobs.run_id=? AND jobs.state='running' "
                    "AND attempt.status='running' AND attempt.finished_at IS NULL",
                    (selected_run_id,),
                ).fetchall()
            }
            queued_ids = {
                int(row[0])
                for row in connection.execute(
                    "SELECT DISTINCT challenge_id FROM control_jobs "
                    "WHERE run_id=? AND state='queued'",
                    (selected_run_id,),
                ).fetchall()
            }
            lease_rows = connection.execute(
                """
                SELECT kind, data_json FROM events
                WHERE run_id=? AND kind IN (
                  'instance_lease_waiting', 'instance_lease_granted',
                  'instance_lease_active', 'instance_lease_releasable',
                  'instance_lease_released', 'instance_lease_poisoned',
                  'instance_lease_deferred', 'instance_lease_admission_expired'
                ) ORDER BY sequence
                """,
                (selected_run_id,),
            ).fetchall()
            lease_phase: dict[int, str] = {}
            for row in lease_rows:
                try:
                    data = json.loads(str(row["data_json"]))
                except json.JSONDecodeError as exc:
                    raise ValueError("instance lease event is invalid") from exc
                if isinstance(data, dict) and type(data.get("challenge_id")) is int:
                    lease_phase[int(data["challenge_id"])] = str(row["kind"])
            waiting_ids = {
                challenge_id
                for challenge_id, phase in lease_phase.items()
                if phase == "instance_lease_waiting"
            }
            queued_ids -= waiting_ids
            control_waiting_ids = {
                int(row[0])
                for row in connection.execute(
                    "SELECT DISTINCT jobs.challenge_id FROM control_jobs AS jobs "
                    "LEFT JOIN attempts AS attempt "
                    "ON attempt.run_id=jobs.run_id "
                    "AND attempt.challenge_id=jobs.challenge_id "
                    "AND attempt.episode=jobs.episode AND attempt.lane=jobs.lane "
                    "WHERE jobs.run_id=? AND jobs.state='running' "
                    "AND (attempt.id IS NULL OR attempt.finished_at IS NOT NULL)",
                    (selected_run_id,),
                ).fetchall()
            }
            terminal_ids = (
                catalogue_ids - active_ids - queued_ids - waiting_ids - control_waiting_ids
            )

            running_rows = connection.execute(
                """
                SELECT jobs.challenge_id, jobs.episode, jobs.lane, jobs.role,
                       jobs.agent_role, jobs.model, jobs.effort,
                       COALESCE(attempt.tool_count, 0) AS tool_count
                FROM control_jobs AS jobs
                JOIN attempts AS attempt
                  ON attempt.run_id=jobs.run_id
                 AND attempt.challenge_id=jobs.challenge_id
                 AND attempt.episode=jobs.episode
                 AND attempt.lane=jobs.lane
                WHERE jobs.run_id=? AND jobs.state='running'
                  AND attempt.status='running' AND attempt.finished_at IS NULL
                ORDER BY jobs.catalogue_rank, jobs.episode, jobs.lane
                """,
                (selected_run_id,),
            ).fetchall()
            lane_states = tuple(
                (str(row["state"]), int(row["count"]))
                for row in connection.execute(
                    "SELECT state, COUNT(*) AS count FROM control_jobs "
                    "WHERE run_id=? GROUP BY state ORDER BY state",
                    (selected_run_id,),
                ).fetchall()
            )
            reserved_lane_count, completed_waiting_lane_count = (
                int(value)
                for value in connection.execute(
                    "SELECT "
                    "COALESCE(SUM(CASE WHEN attempt.id IS NULL THEN 1 ELSE 0 END), 0), "
                    "COALESCE(SUM(CASE WHEN attempt.finished_at IS NOT NULL THEN 1 ELSE 0 END), 0) "
                    "FROM control_jobs AS jobs LEFT JOIN attempts AS attempt "
                    "ON attempt.run_id=jobs.run_id "
                    "AND attempt.challenge_id=jobs.challenge_id "
                    "AND attempt.episode=jobs.episode AND attempt.lane=jobs.lane "
                    "WHERE jobs.run_id=? AND jobs.state='running'",
                    (selected_run_id,),
                ).fetchone()
            )
            attempt_row = connection.execute(
                "SELECT COUNT(*) AS count, COALESCE(SUM(tool_count), 0) AS tools "
                "FROM attempts WHERE run_id=?",
                (selected_run_id,),
            ).fetchone()
            continuation_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM events WHERE run_id=? "
                    "AND kind='primary_solver_continued'",
                    (selected_run_id,),
                ).fetchone()[0]
            )
            submission_outcomes = tuple(
                (str(row["outcome"]), int(row["count"]))
                for row in connection.execute(
                    "SELECT outcome, COUNT(*) AS count FROM submissions "
                    "WHERE run_id=? GROUP BY outcome ORDER BY outcome",
                    (selected_run_id,),
                ).fetchall()
            )
            instance_states = tuple(
                (str(row["status"]), int(row["count"]))
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM instances "
                    "WHERE run_id=? GROUP BY status ORDER BY status",
                    (selected_run_id,),
                ).fetchall()
            )
            watching = (
                bool(config.get("watch_board"))
                and not (active_ids or queued_ids or waiting_ids or control_waiting_ids)
                and str(run["status"]) == "running"
            )
            return MonitorView(
                schema="rapido.monitor.v2",
                sampled_at=sampled.isoformat(),
                run_id=selected_run_id,
                status=str(run["status"]),
                started_at=started.astimezone(UTC).isoformat(),
                deadline_at=deadline.isoformat(),
                remaining_seconds=max(0, int((deadline - sampled).total_seconds())),
                watching=watching,
                catalogue_count=catalogue_count,
                initial_coverage_count=initial_coverage_count,
                active_challenge_ids=tuple(sorted(active_ids)),
                queued_challenge_ids=tuple(sorted(queued_ids)),
                instance_waiting_challenge_ids=tuple(sorted(waiting_ids)),
                terminal_challenge_ids=tuple(sorted(terminal_ids)),
                lane_states=lane_states,
                reserved_lane_count=reserved_lane_count,
                completed_waiting_lane_count=completed_waiting_lane_count,
                running_lanes=tuple(
                    RunningLaneView(
                        challenge_id=int(row["challenge_id"]),
                        episode=int(row["episode"]),
                        lane=int(row["lane"]),
                        role=str(row["role"]),
                        agent_role=str(row["agent_role"]),
                        model=str(row["model"]),
                        effort=str(row["effort"]),
                        tool_calls=int(row["tool_count"]),
                    )
                    for row in running_rows
                ),
                attempt_count=int(attempt_row["count"]),
                tool_call_count=int(attempt_row["tools"]),
                continuation_count=continuation_count,
                pending_submission_count=pending_submission_count,
                submission_outcomes=submission_outcomes,
                pending_candidate_count=pending_candidate_count,
                verified_candidate_count=verified_candidate_count,
                instance_states=instance_states,
            )
        finally:
            connection.close()


__all__ = [
    "ControlView",
    "DurableJobControl",
    "JobView",
    "MonitorView",
    "RouteDecisionView",
    "RunningLaneView",
]
