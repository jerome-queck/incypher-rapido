"""Versioned, candidate-free reconciliation for finalized Rapido state archives."""

from __future__ import annotations

import hashlib
import sqlite3
import stat
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

REPORT_SCHEMA = "rapido-reconciled-report-v1"
REPORT_POLICY = "rapido-accounting-policy-v1"
BOARD_POLICY = "rapido-board-outcomes-v1"
RUNTIME_VERIFICATION_POLICY = "rapido-runtime-current-verification-v1"
USAGE_POLICY = "policy.native_attempt_usage.v1"

POSTRUN_POLICIES = frozenset({"policy.accepted_postrun.v1", "policy.synthetic_accepted_grade.v1"})
STRICT_POLICIES = frozenset(
    {"policy.strict_current_verification.v1", "policy.synthetic_strict_evaluator.v1"}
)
STRICT_EXCLUSION_RULES = frozenset({"rule.synthetic_policy_scope_excluded.v1"})
CORRECTNESS_VALUES = frozenset({"correct", "incorrect", "unverifiable"})
QUALIFICATION_VALUES = frozenset({"qualified", "not_qualified", "unknown"})
STRICT_OUTCOMES = frozenset({"validated", "excluded"})
USAGE_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cached_input_tokens",
    "reasoning_tokens",
)

_CURRENT_VERIFICATION_VIEW_POLICIES = {
    "1ae3ba7af455f6ea5dc5546ecd50597955c59ce3dfd382ab44bec1728907c9c4": (
        "rapido-current-verification-view-a46526e-v1"
    ),
    "a29c28d8c5d2d7a4370943fc5141877057c1e8eaa98ef29c9f8313a7d823805d": (
        "rapido-current-verification-view-5d17fab-v1"
    ),
}


def _exact_keys(source: Mapping[str, object], expected: set[str], name: str) -> None:
    actual = set(source)
    if actual != expected:
        raise ValueError(
            f"{name} fields differ: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _integer(value: object, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise TypeError(f"{name} must be an integer >= {minimum}")
    return value


@dataclass(frozen=True)
class EvaluationRow:
    task_id: int
    correctness: str
    qualification: str

    @classmethod
    def from_mapping(cls, source: Mapping[str, object]) -> EvaluationRow:
        _exact_keys(source, {"task_id", "correctness", "qualification"}, "evaluation row")
        return cls(
            task_id=_integer(source["task_id"], "task_id", minimum=1),
            correctness=str(source["correctness"]),
            qualification=str(source["qualification"]),
        )

    def validated(self) -> EvaluationRow:
        _integer(self.task_id, "task_id", minimum=1)
        if self.correctness not in CORRECTNESS_VALUES:
            raise ValueError("unknown correctness value")
        if self.qualification not in QUALIFICATION_VALUES:
            raise ValueError("unknown qualification value")
        return self


@dataclass(frozen=True)
class PostrunEvaluation:
    policy_version: str
    rows: Sequence[EvaluationRow]

    @classmethod
    def from_mapping(cls, source: Mapping[str, object]) -> PostrunEvaluation:
        _exact_keys(source, {"policy_version", "rows"}, "postrun evaluation")
        rows = source["rows"]
        if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
            raise TypeError("postrun rows must be a list of objects")
        return cls(
            policy_version=str(source["policy_version"]),
            rows=tuple(EvaluationRow.from_mapping(row) for row in rows),
        )

    def validated(self) -> PostrunEvaluation:
        if self.policy_version not in POSTRUN_POLICIES:
            raise ValueError("unknown postrun policy version")
        if not self.rows:
            raise ValueError("postrun evaluation must contain tasks")
        if not all(isinstance(row, EvaluationRow) for row in self.rows):
            raise TypeError("postrun rows must be EvaluationRow values")
        task_ids = [row.validated().task_id for row in self.rows]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError("postrun evaluation contains duplicate task identities")
        return self


@dataclass(frozen=True)
class StrictDecision:
    task_id: int
    outcome: str
    exclusion_rule: str | None

    @classmethod
    def from_mapping(cls, source: Mapping[str, object]) -> StrictDecision:
        _exact_keys(source, {"task_id", "outcome", "exclusion_rule"}, "strict decision")
        rule = source["exclusion_rule"]
        if rule is not None and not isinstance(rule, str):
            raise TypeError("exclusion_rule must be null or a string")
        return cls(
            task_id=_integer(source["task_id"], "task_id", minimum=1),
            outcome=str(source["outcome"]),
            exclusion_rule=rule,
        )

    def validated(self) -> StrictDecision:
        _integer(self.task_id, "task_id", minimum=1)
        if self.outcome not in STRICT_OUTCOMES:
            raise ValueError("unknown strict decision outcome")
        if self.outcome == "validated" and self.exclusion_rule is not None:
            raise ValueError("validated strict decision cannot have an exclusion rule")
        if self.outcome == "excluded" and self.exclusion_rule not in STRICT_EXCLUSION_RULES:
            raise ValueError("excluded strict decision requires a registered rule")
        return self


@dataclass(frozen=True)
class StrictEvaluation:
    policy_version: str
    decisions: Sequence[StrictDecision]

    @classmethod
    def from_mapping(cls, source: Mapping[str, object]) -> StrictEvaluation:
        _exact_keys(source, {"policy_version", "decisions"}, "strict evaluation")
        decisions = source["decisions"]
        if not isinstance(decisions, list) or not all(
            isinstance(decision, Mapping) for decision in decisions
        ):
            raise TypeError("strict decisions must be a list of objects")
        return cls(
            policy_version=str(source["policy_version"]),
            decisions=tuple(StrictDecision.from_mapping(decision) for decision in decisions),
        )

    def validated(self) -> StrictEvaluation:
        if self.policy_version not in STRICT_POLICIES:
            raise ValueError("unknown strict evaluator policy version")
        if not all(isinstance(decision, StrictDecision) for decision in self.decisions):
            raise TypeError("strict decisions must be StrictDecision values")
        task_ids = [decision.validated().task_id for decision in self.decisions]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError("strict evaluation contains duplicate task identities")
        return self


@dataclass(frozen=True)
class UsageRow:
    attempt_id: str
    values: Mapping[str, int | None]

    @classmethod
    def from_mapping(cls, source: Mapping[str, object]) -> UsageRow:
        expected = {"attempt_id", *USAGE_FIELDS}
        _exact_keys(source, expected, "usage row")
        attempt_id = source["attempt_id"]
        if not isinstance(attempt_id, str) or not attempt_id:
            raise TypeError("attempt_id must be a non-empty string")
        values: dict[str, int | None] = {}
        for name in USAGE_FIELDS:
            value = source[name]
            values[name] = None if value is None else _integer(value, name)
        return cls(attempt_id=attempt_id, values=values)

    def validated(self) -> UsageRow:
        if not isinstance(self.attempt_id, str) or not self.attempt_id:
            raise TypeError("attempt_id must be a non-empty string")
        if set(self.values) != set(USAGE_FIELDS):
            raise ValueError("usage row fields differ from the fixed registry")
        for name in USAGE_FIELDS:
            value = self.values[name]
            if value is not None:
                _integer(value, name)
        return self


@dataclass(frozen=True)
class UsageEvidence:
    policy_version: str
    rows: Sequence[UsageRow]

    @classmethod
    def from_mapping(cls, source: Mapping[str, object]) -> UsageEvidence:
        _exact_keys(source, {"policy_version", "rows"}, "usage evidence")
        rows = source["rows"]
        if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
            raise TypeError("usage rows must be a list of objects")
        return cls(
            policy_version=str(source["policy_version"]),
            rows=tuple(UsageRow.from_mapping(row) for row in rows),
        )

    def validated(self) -> UsageEvidence:
        if self.policy_version != USAGE_POLICY:
            raise ValueError("unknown usage policy version")
        if not all(isinstance(row, UsageRow) for row in self.rows):
            raise TypeError("usage rows must be UsageRow values")
        attempt_ids = [row.validated().attempt_id for row in self.rows]
        if len(attempt_ids) != len(set(attempt_ids)):
            raise ValueError("usage evidence contains duplicate attempt identities")
        return self


@dataclass(frozen=True)
class ReconciliationInputs:
    """Private row-level authorities; identifiers are joined but never emitted."""

    postrun_evaluation: PostrunEvaluation
    strict_evaluator: StrictEvaluation
    native_usage: UsageEvidence | None = None

    @classmethod
    def from_mapping(cls, source: Mapping[str, object]) -> ReconciliationInputs:
        _exact_keys(
            source,
            {"postrun_evaluation", "strict_evaluator", "native_usage"},
            "reconciliation inputs",
        )
        postrun = source["postrun_evaluation"]
        strict = source["strict_evaluator"]
        usage = source["native_usage"]
        if not isinstance(postrun, Mapping) or not isinstance(strict, Mapping):
            raise TypeError("postrun_evaluation and strict_evaluator must be objects")
        if usage is not None and not isinstance(usage, Mapping):
            raise TypeError("native_usage must be null or an object")
        return cls(
            postrun_evaluation=PostrunEvaluation.from_mapping(postrun),
            strict_evaluator=StrictEvaluation.from_mapping(strict),
            native_usage=None if usage is None else UsageEvidence.from_mapping(usage),
        )

    def validated(self) -> ReconciliationInputs:
        self.postrun_evaluation.validated()
        self.strict_evaluator.validated()
        if self.native_usage is not None:
            self.native_usage.validated()
        return self


def parse_timestamp(value: str) -> datetime:
    timestamp = datetime.fromisoformat(value)
    if timestamp.tzinfo is None:
        raise ValueError("timestamps must include a UTC offset")
    return timestamp


def clipped_seconds(start: datetime, end: datetime, lower: datetime, upper: datetime) -> float:
    """Return interval overlap; lane overlaps intentionally remain additive."""

    if end < start or upper < lower:
        raise ValueError("invalid time interval")
    return max(0.0, (min(end, upper) - max(start, lower)).total_seconds())


def _open_archive(path: Path) -> sqlite3.Connection:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("archive database must be a regular file, never a symlink")
    sidecars = [path.with_name(path.name + suffix) for suffix in ("-wal", "-shm", "-journal")]
    if any(sidecar.exists() for sidecar in sidecars):
        raise ValueError("archive must be finalized and checkpointed without SQLite sidecars")
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    if int(connection.execute("PRAGMA query_only").fetchone()[0]) != 1:
        connection.close()
        raise RuntimeError("archive connection is not query-only")
    return connection


_REQUIRED_COLUMNS = {
    "runs": {"id", "started_at", "finished_at"},
    "submissions": {
        "sequence",
        "run_id",
        "challenge_id",
        "at",
        "candidate_sha256",
        "context_episode",
        "outcome",
    },
    "submission_intents": {
        "challenge_id",
        "candidate_sha256",
        "first_run_id",
        "context_episode",
        "status",
        "updated_at",
    },
    "attempts": {
        "id",
        "run_id",
        "challenge_id",
        "episode",
        "lane",
        "started_at",
        "finished_at",
    },
    "control_jobs": {
        "job_id",
        "run_id",
        "challenge_id",
        "episode",
        "lane",
        "started_sequence",
    },
    "control_catalogue": {"run_id", "challenge_id"},
    "candidate_proposals": {"source_attempt_id", "run_id", "challenge_id", "candidate_key"},
    "candidate_evidence_proofs": {
        "source_attempt_id",
        "run_id",
        "challenge_id",
        "candidate_key",
    },
    "current_candidate_verifications": {"run_id", "challenge_id"},
    "evidence_objects": {"run_id"},
    "evidence_items": {"run_id"},
}


def _require_schema(connection: sqlite3.Connection) -> str:
    for table, required in _REQUIRED_COLUMNS.items():
        present = {
            str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        missing = required - present
        if missing:
            raise ValueError(f"archive schema missing {table} columns: {sorted(missing)}")
    view = connection.execute(
        "SELECT type, sql FROM sqlite_master WHERE name='current_candidate_verifications'"
    ).fetchall()
    if len(view) != 1 or str(view[0]["type"]) != "view" or view[0]["sql"] is None:
        raise ValueError("current_candidate_verifications must be the production view")
    normalized = " ".join(str(view[0]["sql"]).split()).encode()
    view_policy = _CURRENT_VERIFICATION_VIEW_POLICIES.get(hashlib.sha256(normalized).hexdigest())
    if view_policy is None:
        raise ValueError("current_candidate_verifications view policy is incompatible")
    return view_policy


def _one_to_one_attempt_job_count(connection: sqlite3.Connection, run_id: str) -> int:
    join = """
        ON job.run_id=attempt.run_id
       AND job.challenge_id=attempt.challenge_id
       AND job.episode=attempt.episode
       AND job.lane=attempt.lane
       AND job.started_sequence IS NOT NULL
    """
    bad_attempts = connection.execute(
        f"""
        SELECT attempt.id, COUNT(job.job_id) AS matches
        FROM attempts AS attempt LEFT JOIN control_jobs AS job {join}
        WHERE attempt.run_id=?
        GROUP BY attempt.id HAVING COUNT(job.job_id)!=1
        """,
        (run_id,),
    ).fetchall()
    bad_started_jobs = connection.execute(
        """
        SELECT job.job_id, COUNT(attempt.id) AS matches
        FROM control_jobs AS job LEFT JOIN attempts AS attempt
          ON attempt.run_id=job.run_id
         AND attempt.challenge_id=job.challenge_id
         AND attempt.episode=job.episode
         AND attempt.lane=job.lane
        WHERE job.run_id=? AND job.started_sequence IS NOT NULL
        GROUP BY job.job_id HAVING COUNT(attempt.id)!=1
        """,
        (run_id,),
    ).fetchall()
    if bad_attempts or bad_started_jobs:
        raise ValueError("attempt and started-job identities are not one-to-one")
    return int(
        connection.execute(
            f"""
            SELECT COUNT(*) FROM attempts AS attempt
            JOIN control_jobs AS job {join}
            WHERE attempt.run_id=?
            """,
            (run_id,),
        ).fetchone()[0]
    )


def _one_to_one_submission_intent_count(connection: sqlite3.Connection, run_id: str) -> int:
    identity = """
        intent.first_run_id=submission.run_id
        AND intent.challenge_id=submission.challenge_id
        AND intent.candidate_sha256=submission.candidate_sha256
        AND intent.context_episode=submission.context_episode
    """
    submissions = connection.execute(
        f"""
        SELECT submission.sequence, COUNT(intent.challenge_id) AS matches
        FROM submissions AS submission LEFT JOIN submission_intents AS intent ON {identity}
        WHERE submission.run_id=? GROUP BY submission.sequence ORDER BY submission.sequence
        """,
        (run_id,),
    ).fetchall()
    intents = connection.execute(
        f"""
        SELECT intent.challenge_id, intent.candidate_sha256, intent.context_episode, intent.status,
               intent.updated_at,
               COUNT(submission.sequence) AS matches,
               SUM(CASE WHEN submission.outcome=intent.status THEN 1 ELSE 0 END) AS final_matches,
               SUM(CASE WHEN submission.outcome='unread' THEN 1 ELSE 0 END) AS unread_matches,
               MAX(CASE WHEN submission.outcome=intent.status
                        THEN submission.sequence END) AS final_sequence,
               MAX(CASE WHEN submission.outcome='unread'
                        THEN submission.sequence END) AS unread_sequence
        FROM submission_intents AS intent LEFT JOIN submissions AS submission ON {identity}
        WHERE intent.first_run_id=?
        GROUP BY intent.challenge_id, intent.candidate_sha256, intent.context_episode,
                 intent.status, intent.updated_at
        """,
        (run_id,),
    ).fetchall()

    def intent_is_consistent(row: sqlite3.Row) -> bool:
        status = str(row["status"])
        matches = int(row["matches"])
        final_matches = int(row["final_matches"])
        unread_matches = int(row["unread_matches"])
        if status == "pending":
            return matches == 0
        if status == "not_delivered":
            return unread_matches == matches
        if status in {"correct", "incorrect"}:
            unread_sequence = row["unread_sequence"]
            final_sequence = row["final_sequence"]
            return (
                final_matches == 1
                and matches == final_matches + unread_matches
                and final_sequence is not None
                and (unread_sequence is None or int(unread_sequence) < int(final_sequence))
            )
        return matches == 1 and final_matches == 1

    late_unread = any(
        parse_timestamp(str(row["submission_at"])) > parse_timestamp(str(row["intent_updated_at"]))
        for row in connection.execute(
            f"""
            SELECT submission.at AS submission_at, intent.updated_at AS intent_updated_at
            FROM submission_intents AS intent JOIN submissions AS submission ON {identity}
            WHERE intent.first_run_id=? AND intent.status='not_delivered'
              AND submission.outcome='unread'
            """,
            (run_id,),
        )
    )
    if (
        late_unread
        or any(int(row["matches"]) != 1 for row in submissions)
        or any(not intent_is_consistent(row) for row in intents)
    ):
        raise ValueError("submission and intent identities are not bidirectionally one-to-one")
    return sum(int(row["matches"]) > 0 for row in intents)


def _timing(
    connection: sqlite3.Connection, run_id: str, started: str, finished: str
) -> dict[str, Any]:
    lower = parse_timestamp(started)
    upper = parse_timestamp(finished)
    elapsed = clipped_seconds(lower, upper, lower, upper)
    lane_seconds = 0.0
    clipped_attempts = 0
    intervals: list[tuple[datetime, datetime]] = []
    for row in connection.execute(
        "SELECT started_at, finished_at FROM attempts WHERE run_id=? ORDER BY id", (run_id,)
    ):
        if row["finished_at"] is None:
            raise ValueError("finalized archive contains an unfinished attempt")
        attempt_start = parse_timestamp(str(row["started_at"]))
        attempt_end = parse_timestamp(str(row["finished_at"]))
        duration = clipped_seconds(attempt_start, attempt_end, lower, upper)
        lane_seconds += duration
        clipped_attempts += int(attempt_start < lower or attempt_end > upper)
        clipped_start, clipped_end = max(attempt_start, lower), min(attempt_end, upper)
        if clipped_end > clipped_start:
            intervals.append((clipped_start, clipped_end))
    intervals.sort()
    merged: list[tuple[datetime, datetime]] = []
    for start, end in intervals:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    wall_active_seconds = sum((end - start).total_seconds() for start, end in merged)
    return {
        "elapsed_seconds": round(elapsed, 6),
        "lane_seconds": round(lane_seconds, 6),
        "wall_active_seconds": round(wall_active_seconds, 6),
        "concurrent_lane_seconds": round(lane_seconds - wall_active_seconds, 6),
        "average_active_lanes": round(lane_seconds / elapsed, 6) if elapsed else None,
        "clipped_attempt_count": clipped_attempts,
        "semantics": "lane intervals clipped to one run t0/tf; overlaps remain additive",
    }


def _postrun_metrics(evaluation: PostrunEvaluation) -> tuple[dict[str, object], dict[str, object]]:
    correctness = Counter(row.correctness for row in evaluation.rows)
    matrix = {
        correct: {
            qualification: sum(
                row.correctness == correct and row.qualification == qualification
                for row in evaluation.rows
            )
            for qualification in sorted(QUALIFICATION_VALUES)
        }
        for correct in sorted(CORRECTNESS_VALUES)
    }
    score = {
        "value": correctness["correct"],
        "denominator": len(evaluation.rows),
        "unit": "task",
        "policy_version": evaluation.policy_version,
        "axis": "retrospective_correctness",
        "source": "external_row_level_evaluation",
    }
    return score, matrix


def _strict_metrics(evaluation: StrictEvaluation, runtime_task_ids: set[int]) -> dict[str, object]:
    decisions = {decision.task_id: decision for decision in evaluation.decisions}
    if set(decisions) != runtime_task_ids:
        missing = len(runtime_task_ids - set(decisions))
        unexpected = len(set(decisions) - runtime_task_ids)
        raise ValueError(
            f"strict decisions do not match runtime-current identities: missing={missing}, "
            f"unexpected={unexpected}"
        )
    exclusions = Counter(
        decision.exclusion_rule for decision in decisions.values() if decision.outcome == "excluded"
    )
    return {
        "value": sum(decision.outcome == "validated" for decision in decisions.values()),
        "denominator": len(runtime_task_ids),
        "unit": "task",
        "policy_version": evaluation.policy_version,
        "axis": "external_evaluator_validation",
        "source": "external_per_runtime_identity_decisions",
        "exclusion_reasons": {
            str(rule): count for rule, count in sorted(exclusions.items()) if rule is not None
        },
    }


def _usage_metrics(usage: UsageEvidence | None, attempt_ids: set[str]) -> dict[str, object] | None:
    if usage is None:
        return None
    rows = {row.attempt_id: row for row in usage.rows}
    if set(rows) != attempt_ids:
        missing = len(attempt_ids - set(rows))
        unexpected = len(set(rows) - attempt_ids)
        raise ValueError(
            f"usage rows do not match attempt identities: missing={missing}, unexpected={unexpected}"
        )
    metrics: dict[str, object] = {}
    for name in USAGE_FIELDS:
        values = [row.values[name] for row in rows.values()]
        observed = [value for value in values if value is not None]
        metrics[name] = {
            "observed_total": sum(observed),
            "observed_attempt_count": len(observed),
            "missing_attempt_count": len(values) - len(observed),
            "total": sum(observed) if len(observed) == len(values) else None,
        }
    return {
        "policy_version": usage.policy_version,
        "attempt_count": len(rows),
        "metrics": metrics,
    }


def reconcile_archive(
    database: Path,
    run_id: str,
    inputs: ReconciliationInputs,
) -> dict[str, object]:
    """Build a deterministic sanitized report without migrating or writing the source database."""

    inputs.validated()
    connection = _open_archive(database)
    try:
        connection.execute("BEGIN")
        verification_view_policy = _require_schema(connection)
        run_rows = connection.execute(
            "SELECT started_at, finished_at FROM runs WHERE id=?", (run_id,)
        ).fetchall()
        if len(run_rows) != 1 or run_rows[0]["finished_at"] is None:
            raise ValueError("run_id must identify one finalized run")
        run = run_rows[0]
        joined = _one_to_one_attempt_job_count(connection, run_id)
        submission_intents_joined = _one_to_one_submission_intent_count(connection, run_id)

        board_new_correct = int(
            connection.execute(
                "SELECT COUNT(DISTINCT challenge_id) FROM submissions "
                "WHERE run_id=? AND outcome='correct'",
                (run_id,),
            ).fetchone()[0]
        )
        already_solved = int(
            connection.execute(
                "SELECT COUNT(*) FROM submissions WHERE run_id=? AND outcome='already_solved'",
                (run_id,),
            ).fetchone()[0]
        )
        runtime_task_ids = {
            int(row["challenge_id"])
            for row in connection.execute(
                "SELECT DISTINCT challenge_id FROM current_candidate_verifications WHERE run_id=?",
                (run_id,),
            ).fetchall()
        }
        catalogue_task_ids = {
            int(row["challenge_id"])
            for row in connection.execute(
                "SELECT challenge_id FROM control_catalogue WHERE run_id=?", (run_id,)
            ).fetchall()
        }
        postrun_task_ids = {row.task_id for row in inputs.postrun_evaluation.rows}
        if postrun_task_ids != catalogue_task_ids:
            missing = len(catalogue_task_ids - postrun_task_ids)
            unexpected = len(postrun_task_ids - catalogue_task_ids)
            raise ValueError(
                f"postrun rows do not match catalogue identities: missing={missing}, "
                f"unexpected={unexpected}"
            )
        proof_backed = int(
            connection.execute(
                """
                SELECT COUNT(DISTINCT proposal.source_attempt_id)
                FROM candidate_proposals AS proposal
                JOIN attempts AS attempt
                  ON attempt.id=proposal.source_attempt_id
                 AND attempt.run_id=proposal.run_id
                 AND attempt.challenge_id=proposal.challenge_id
                JOIN candidate_evidence_proofs AS proof
                  ON proof.source_attempt_id=proposal.source_attempt_id
                 AND proof.run_id=proposal.run_id
                 AND proof.challenge_id=proposal.challenge_id
                 AND proof.candidate_key=proposal.candidate_key
                WHERE proposal.run_id=?
                """,
                (run_id,),
            ).fetchone()[0]
        )
        attempt_ids = {
            str(row["id"])
            for row in connection.execute(
                "SELECT id FROM attempts WHERE run_id=?", (run_id,)
            ).fetchall()
        }
        evidence_items = int(
            connection.execute(
                "SELECT COUNT(*) FROM evidence_items WHERE run_id=?", (run_id,)
            ).fetchone()[0]
        )
        evidence_objects = int(
            connection.execute(
                "SELECT COUNT(*) FROM evidence_objects WHERE run_id=?", (run_id,)
            ).fetchone()[0]
        )
        postrun, qualification_matrix = _postrun_metrics(inputs.postrun_evaluation)

        return {
            "schema": REPORT_SCHEMA,
            "policy_version": REPORT_POLICY,
            "metrics": {
                "postrun_correctness": postrun,
                "postrun_correctness_qualification_matrix": qualification_matrix,
                "board_new_correct": {
                    "value": board_new_correct,
                    "unit": "task",
                    "policy_version": BOARD_POLICY,
                    "axis": "board_current_run_correctness",
                    "source": "submission_outcome_correct",
                },
                "already_solved_history": {
                    "value": already_solved,
                    "unit": "submission_identity",
                    "policy_version": BOARD_POLICY,
                    "axis": "account_history",
                    "source": "submission_outcome_already_solved",
                },
                "runtime_current_verification": {
                    "value": len(runtime_task_ids),
                    "unit": "task",
                    "policy_version": RUNTIME_VERIFICATION_POLICY,
                    "axis": "runtime_qualification",
                    "source": "current_candidate_verifications",
                },
                "strict_evaluator": _strict_metrics(inputs.strict_evaluator, runtime_task_ids),
            },
            "archive": {
                "attempt_count": len(attempt_ids),
                "attempt_job_join_count": joined,
                "submission_intent_join_count": submission_intents_joined,
                "proof_backed_proposal_attempt_count": proof_backed,
                "evidence_item_count": evidence_items,
                "evidence_object_count": evidence_objects,
                "current_verification_view_policy": verification_view_policy,
                "timing": _timing(
                    connection, run_id, str(run["started_at"]), str(run["finished_at"])
                ),
                "native_usage": _usage_metrics(inputs.native_usage, attempt_ids),
            },
            "interpretation": {
                "axes_are_independent": True,
                "already_solved_upgrades_correctness": False,
                "runtime_qualification_equals_external_validation": False,
                "proof_backed_proposals_depend_on_attempt_candidate_column": False,
                "evidence_items_equal_distinct_objects": evidence_items == evidence_objects,
            },
        }
    finally:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        connection.close()
