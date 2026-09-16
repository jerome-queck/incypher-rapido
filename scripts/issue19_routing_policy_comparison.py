#!/usr/bin/env python3
"""Run the frozen, effect-free issue #19 routing-policy comparison."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import platform
import resource
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Self

from rapido.routing_policy import (
    OPERATION_PROTOCOL_SHA256,
    PARENT_PROTOCOL_SHA256,
    ComparisonContract,
    PolicyInput,
    authorize_comparison_evaluation,
    evaluate_comparison_policy,
)
from rapido.state import StateStore

ROOT = Path(__file__).resolve().parents[1]
PARENT_PATH = ROOT / "notes/research/issue-19-routing-comparison-protocol-v1.json"
OPERATION_PATH = ROOT / "notes/research/issue-19-routing-operation-count-protocol-v1.json"
if hashlib.sha256(PARENT_PATH.read_bytes()).hexdigest() != PARENT_PROTOCOL_SHA256:
    raise RuntimeError("parent comparison protocol file digest changed")
if hashlib.sha256(OPERATION_PATH.read_bytes()).hexdigest() != OPERATION_PROTOCOL_SHA256:
    raise RuntimeError("operation comparison protocol file digest changed")
PARENT = json.loads(PARENT_PATH.read_text(encoding="utf-8"))
OPERATION = json.loads(OPERATION_PATH.read_text(encoding="utf-8"))
CONTRACT = ComparisonContract.from_documents(PARENT, OPERATION)

_SURFACE_MODULE_PREFIXES = {
    "containers": ("subprocess", "rapido.artifact_worker_main"),
    "external_board": ("rapido.board",),
    "instances": (),
    "model_inference": ("rapido.codex_app", "rapido.solver"),
    "network": (
        "http",
        "socket",
        "ssl",
        "urllib.request",
        "rapido.board",
        "rapido.solver",
        "rapido.target",
    ),
    "submissions": (),
}
_SURFACE_FUNCTIONS = {
    "instances": {
        "_cleanup_instance_record",
        "_cleanup_owned_instances",
        "_delete_instance",
        "_recover_created_instance_receipt",
        "_start_instance",
        "instance",
        "mark_instance",
        "owned_instances",
    },
    "submissions": {
        "_submit_candidate",
        "finalize_submission",
        "pending_submission_intents",
        "reconcile_submission_intent",
        "record_submission",
        "reserve_submission",
        "submit",
    },
}


class DisabledSurfaceMonitor:
    """Count actual calls into every surface forbidden by the E3 protocol."""

    def __init__(self) -> None:
        self.counts = {name: 0 for name in PARENT["disabled_surfaces"]}
        self._previous: object = None
        self._previous_thread: object = None

    def _profile(self, frame: FrameType, event: str, argument: object) -> None:
        del argument
        if event != "call":
            return
        module = str(frame.f_globals.get("__name__", ""))
        function = frame.f_code.co_name
        for surface, prefixes in _SURFACE_MODULE_PREFIXES.items():
            if any(module == prefix or module.startswith(f"{prefix}.") for prefix in prefixes):
                self.counts[surface] += 1
        for surface, functions in _SURFACE_FUNCTIONS.items():
            if function in functions and module.startswith("rapido."):
                self.counts[surface] += 1

    def __enter__(self) -> Self:
        global _ACTIVE_SURFACE_MONITOR
        self._previous = sys.getprofile()
        self._previous_thread = threading.getprofile()
        if (
            self._previous is not None
            or self._previous_thread is not None
            or _ACTIVE_SURFACE_MONITOR is not None
        ):
            raise RuntimeError("comparison requires exclusive disabled-surface profiling")
        _ACTIVE_SURFACE_MONITOR = self
        sys.setprofile(self._profile)
        threading.setprofile(self._profile)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        global _ACTIVE_SURFACE_MONITOR
        del exc_type, exc, traceback
        _ACTIVE_SURFACE_MONITOR = None
        sys.setprofile(None)
        threading.setprofile(None)


_ACTIVE_SURFACE_MONITOR: DisabledSurfaceMonitor | None = None


def _disabled_surface_audit(event: str, arguments: tuple[object, ...]) -> None:
    del arguments
    monitor = _ACTIVE_SURFACE_MONITOR
    if monitor is None:
        return
    if event.startswith("socket."):
        monitor.counts["network"] += 1
        raise RuntimeError("comparison blocked a disabled network surface")
    if event in {"subprocess.Popen", "os.fork", "os.system"} or event.startswith(
        ("os.posix_spawn", "os.spawn")
    ):
        monitor.counts["containers"] += 1
        raise RuntimeError("comparison blocked a disabled process surface")


sys.addaudithook(_disabled_surface_audit)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _public_fingerprint(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("comparison route fingerprint is invalid")
    return "sha256:" + base64.urlsafe_b64encode(bytes.fromhex(value)).decode("ascii").rstrip("=")


def _case_payload(case: dict[str, object]) -> PolicyInput:
    value = json.loads(_canonical(PARENT["fixture_payload_defaults"]))
    if case["fact_profile"] != "none":
        value.update(
            json.loads(_canonical(PARENT["fixture_payload_overrides"][case["fact_profile"]]))
        )
    value["failure_kind"] = case["failure_kind"]
    value["failure_subreason"] = PARENT["failure_subreason_by_case"][case["id"]]
    return PolicyInput.from_dict(value)


def private_canaries(repetition: int) -> tuple[str, ...]:
    return tuple(
        [f"INCYPHER{{e3-private-{repetition}-{case['id']}}}" for case in PARENT["cases"]]
        + [f"credential-e3-private-{repetition}", f"board-authority-e3-private-{repetition}"]
    )


def _private_encodings(repetition: int) -> tuple[str, ...]:
    encoded: list[str] = []
    for canary in private_canaries(repetition):
        raw = canary.encode("utf-8")
        encoded.extend(
            (
                canary,
                hashlib.sha256(raw).hexdigest(),
                raw.hex(),
                base64.b64encode(raw).decode("ascii"),
                base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
                urllib.parse.quote(canary, safe=""),
            )
        )
    return tuple(encoded)


def _source_files() -> tuple[Path, ...]:
    files = [Path(__file__).resolve(), PARENT_PATH, OPERATION_PATH]
    files.extend(sorted((ROOT / "rapido").rglob("*.py")))
    return tuple(dict.fromkeys(files))


def git_source_identity() -> dict[str, object]:
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    files = {str(path.relative_to(ROOT)): _file_digest(path) for path in _source_files()}
    production = {path: digest for path, digest in files.items() if path.startswith("rapido/")}
    tree_payload = "".join(f"{path}\0{digest}\n" for path, digest in sorted(production.items()))
    return {
        "clean": not status,
        "commit": commit,
        "files": files,
        "production_tree_sha256": hashlib.sha256(tree_payload.encode("utf-8")).hexdigest(),
    }


def _environment(path: Path) -> dict[str, object]:
    page_size = os.sysconf("SC_PAGE_SIZE")
    page_count = os.sysconf("SC_PHYS_PAGES")
    pid_limit = resource.getrlimit(resource.RLIMIT_NPROC)[0]
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "sqlite_version": sqlite3.sqlite_version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "memory_bytes": page_size * page_count,
        "pid_limit": None if pid_limit == resource.RLIM_INFINITY else pid_limit,
        "filesystem_block_size": os.statvfs(path).f_bsize,
    }


def _run_id(arm: str, case_id: str, repetition: int) -> str:
    return hashlib.sha256(f"e3:{arm}:{case_id}:{repetition}".encode("ascii")).hexdigest()[:32]


def _event_bytes(connection: sqlite3.Connection, run_id: str) -> int:
    rows = connection.execute(
        "SELECT kind, COALESCE(job_id, ''), data_json FROM control_events "
        "WHERE run_id=? ORDER BY sequence",
        (run_id,),
    ).fetchall()
    return sum(
        len(str(kind).encode("utf-8"))
        + 1
        + len(str(job_id).encode("utf-8"))
        + 1
        + len(str(data_json).encode("utf-8"))
        for kind, job_id, data_json in rows
    )


def _encoded_event_bytes(kind: str, job_id: str | None, data: dict[str, object]) -> int:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return sum(len(value.encode("utf-8")) for value in (kind, "\0", job_id or "", "\0", encoded))


def _expected_event_bytes(
    arm: str,
    case: dict[str, object],
    repetition: int,
    value: PolicyInput,
    disposition: str,
    recipe_id: str | None,
    changed_axes: tuple[str, ...],
) -> int:
    """Independently serialize the frozen event plan for raw-cost tamper checks."""
    run_id = _run_id(arm, str(case["id"]), repetition)
    events: list[tuple[str, str | None, dict[str, object]]] = []

    def job_id(episode: int, role: str, lane: int) -> str:
        return f"{run_id}:1:{episode}:{role}:{lane}"

    for lane in range(2):
        events.append(
            (
                "job_admitted",
                job_id(0, "specialist", lane),
                {
                    "catalogue_rank": 1,
                    "challenge_id": 1,
                    "episode": 0,
                    "lane": lane,
                    "phase": "initial",
                    "role": "specialist",
                },
            )
        )
    for used_id in sorted(value.used_successor_recipe_ids):
        events.append(
            (
                "comparison_used_route_recorded",
                None,
                {
                    "challenge_id": 1,
                    "route_fingerprint": CONTRACT.route_templates[used_id].fingerprint,
                    "route_recorded": True,
                },
            )
        )
    for lane in range(2):
        events.append(
            (
                "job_started",
                job_id(0, "specialist", lane),
                {"challenge_id": 1, "episode": 0, "lane": lane},
            )
        )
    events.extend(
        (
            "comparison_route_fact_recorded",
            None,
            {"challenge_id": 1, "episode": 0, **fact.as_dict()},
        )
        for fact in value.facts
    )
    for lane in (1, 0) if repetition % 2 else (0, 1):
        events.append(
            (
                "comparison_lane_completed",
                job_id(0, "specialist", lane),
                {"challenge_id": 1, "episode": 0, "lane": lane},
            )
        )
    terminal = "completed" if disposition == "no_route" else "error"
    lane_state = "unsolved" if disposition == "no_route" else "failed"
    for lane in range(2):
        events.append(
            (
                "job_closed",
                job_id(0, "specialist", lane),
                {
                    "challenge_id": 1,
                    "episode": 0,
                    "lane": lane,
                    "lane_state": lane_state,
                    "terminal": terminal,
                },
            )
        )
    if disposition != "no_route":
        source = CONTRACT.route_templates[value.current_route_id]
        successor = (
            source
            if recipe_id == "repeat_source_route_comparator_v1"
            else CONTRACT.route_templates[recipe_id]
            if disposition == "dispatch" and recipe_id is not None
            else None
        )
        events.append(
            (
                "comparison_failure_route_decision",
                None,
                {
                    "challenge_id": 1,
                    "changed_axes": list(changed_axes),
                    "disposition": disposition,
                    "failure_kind": value.failure_kind,
                    "failure_subreason": value.failure_subreason,
                    "recipe_id": recipe_id,
                    "source_episode": 0,
                    "source_route_fingerprint": source.fingerprint,
                    "successor_route_fingerprint": (
                        None if successor is None else successor.fingerprint
                    ),
                },
            )
        )
        if disposition == "dispatch":
            if successor is None:
                raise AssertionError("dispatch event plan has no successor")
            for lane in range(2):
                events.append(
                    (
                        "job_admitted",
                        job_id(1, successor.role, lane),
                        {
                            "catalogue_rank": 1,
                            "challenge_id": 1,
                            "episode": 1,
                            "lane": lane,
                            "phase": "retry",
                            "role": successor.role,
                        },
                    )
                )
    return sum(_encoded_event_bytes(*event) for event in events)


def _terminal_and_conversion(
    case: dict[str, object], arm: str, repetition: int, disposition: str, recipe_id: str | None
) -> tuple[str, int, int]:
    expected = case["expected"]
    expected_recipe = PARENT["evaluator_contract"]["expected_recipe_by_case"].get(case["id"])
    if expected == "no_route":
        return "completed_without_successor", 0, int(disposition == "dispatch")
    if expected == "contain":
        terminal = (
            "safely_contained" if disposition == "contain" else "closed_without_qualification"
        )
        return terminal, 0, int(disposition == "dispatch")
    correct_route = disposition == "dispatch" and (
        (arm == "fifo_unchanged" and recipe_id == "repeat_source_route_comparator_v1")
        or (arm != "fifo_unchanged" and recipe_id == expected_recipe)
    )
    schedule = (
        PARENT["evaluator_contract"]["fifo_comparator_success_repetitions"]
        if arm == "fifo_unchanged"
        else PARENT["evaluator_contract"]["correct_recipe_success_repetitions"]
    )
    converted = int(correct_route and repetition in schedule)
    false_dispatch = int(
        disposition == "dispatch" and arm != "fifo_unchanged" and recipe_id != expected_recipe
    )
    return (
        "qualified_local_admission" if converted else "closed_without_qualification",
        converted,
        false_dispatch,
    )


def _expected_row_values(case: dict[str, object], arm: str, repetition: int) -> dict[str, object]:
    value = _case_payload(case)
    evaluation = evaluate_comparison_policy(arm, value, CONTRACT)
    decision = authorize_comparison_evaluation(value, evaluation, CONTRACT)
    terminal, conversion, false_dispatch = _terminal_and_conversion(
        case, arm, repetition, decision.disposition, decision.recipe_id
    )
    source = CONTRACT.route_templates[value.current_route_id]
    preused = {source.fingerprint} | {
        CONTRACT.route_templates[recipe_id].fingerprint
        for recipe_id in value.used_successor_recipe_ids
    }
    selected_fingerprint = (
        source.fingerprint
        if evaluation.recipe_id == "repeat_source_route_comparator_v1"
        else (
            CONTRACT.route_templates[evaluation.recipe_id].fingerprint
            if evaluation.recipe_id in CONTRACT.route_templates
            else None
        )
    )
    used_count = len(value.used_successor_recipe_ids)
    fact_start = 5 + used_count
    fact_sequences = list(range(fact_start, fact_start + len(value.facts)))
    decision_sequence = (
        None if decision.disposition == "no_route" else 9 + used_count + len(value.facts)
    )
    expected = {
        "policy_input_digest": value.digest,
        "policy_config_digest": evaluation.policy_config_digest,
        "disposition": decision.disposition,
        "recipe_id": decision.recipe_id,
        "failure_kind": value.failure_kind,
        "source_fact_count": len(value.facts),
        "source_fact_public_metadata_digest": value.source_fact_public_metadata_digest,
        "source_route_fingerprint": _public_fingerprint(decision.source_fingerprint),
        "successor_route_fingerprint": _public_fingerprint(decision.successor_fingerprint),
        "changed_axes": list(decision.changed_axes),
        "terminal_outcome": terminal,
        "positive_conversion": conversion,
        "false_dispatch": false_dispatch,
        "unchanged_dispatch": int(
            decision.disposition == "dispatch"
            and decision.source_fingerprint == decision.successor_fingerprint
        ),
        "duplicate_route": int(
            arm != "fifo_unchanged"
            and selected_fingerprint is not None
            and selected_fingerprint in preused
        ),
        "policy_operation_count": evaluation.operation_count,
        "policy_config_bytes": evaluation.policy_config_bytes,
        "context_bytes": 2 * len(_canonical(value.as_dict())),
        "decision_sequence": decision_sequence,
        "fact_event_sequences": fact_sequences,
        "model_effort_mismatch": 0,
        "effect_authority_mismatch": 0,
        "scope_mismatch": 0,
        "replay_divergence": 0,
        "coverage_failure": 0,
        "pending_effects": 0,
        "owned_instances": 0,
        "workspace_residue": 0,
        "candidate_leak": 0,
        "tool_call_count": 0,
    }
    expected["durable_event_bytes"] = _expected_event_bytes(
        arm,
        case,
        repetition,
        value,
        decision.disposition,
        decision.recipe_id,
        decision.changed_axes,
    )
    return expected


def _replay_digest(row: dict[str, object]) -> str:
    fields = OPERATION["measurement_accounting"]["replay_digest"]["fields"]
    return _digest({field: row[field] for field in fields})


def _run_row(
    output_root: Path,
    arm: str,
    case: dict[str, object],
    repetition: int,
) -> dict[str, object]:
    started = time.monotonic()
    value = _case_payload(case)
    run_id = _run_id(arm, str(case["id"]), repetition)
    with tempfile.TemporaryDirectory(prefix="row-", dir=output_root) as temporary:
        row_root = Path(temporary)
        row_root.chmod(0o700)
        workspace = row_root / "workspace"
        workspace.mkdir(mode=0o700)
        payload = _canonical(value.as_dict())
        artifact_paths = []
        for lane in range(2):
            path = workspace / f"lane-{lane}.json"
            path.write_bytes(payload)
            path.chmod(0o600)
            artifact_paths.append(path)
        context_bytes = sum(path.stat().st_size for path in artifact_paths)
        state = StateStore(row_root / "state" / "state.sqlite3")
        try:
            state.start_run(run_id, {"comparison": True})
            state.upsert_challenge(1, "E3 fixture", "routing", "standard", 100)
            state.record_control_catalogue(run_id, [(1, 1, True)])
            state.admit_control_wave(
                run_id,
                1,
                0,
                1,
                2,
                CONTRACT.route_templates[value.current_route_id],
            )
            for used_id in sorted(value.used_successor_recipe_ids):
                state.record_comparison_used_route(run_id, 1, CONTRACT.route_templates[used_id])
            state.start_control_wave(run_id, 1, 0)
            fact_sequences = state.record_comparison_route_facts(
                run_id,
                1,
                0,
                value.facts,
                protocol_digest=PARENT_PROTOCOL_SHA256,
            )
            for lane in range(2):
                state.start_attempt(
                    f"{run_id}:1:0:{lane}",
                    run_id,
                    1,
                    0,
                    lane,
                    "gpt-daybreak-blue-latest",
                    "xhigh",
                )
            lane_order = (1, 0) if repetition % 2 else (0, 1)
            for lane in lane_order:
                state.finish_attempt(
                    f"{run_id}:1:0:{lane}",
                    "unsolved" if case["id"] == "completed" else "failed",
                )
                state.record_comparison_lane_completion(run_id, 1, 0, lane)
            trace = state.finish_and_compare_control_wave(
                run_id=run_id,
                challenge_id=1,
                source_episode=0,
                next_episode=1,
                catalogue_rank=1,
                lanes=2,
                policy_input=value,
                arm=arm,
                contract=CONTRACT,
            )
            replay_divergence = 0
            if trace.decision_sequence is not None:
                replay = state.replay_comparison_route_decision(trace.decision_sequence, CONTRACT)
                replay_divergence = int(replay.decision_digest != trace.decision_digest)
            with sqlite3.connect(state.path) as connection:
                event_bytes = _event_bytes(connection, run_id)
                pending_effects = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM submission_intents WHERE status='pending'"
                    ).fetchone()[0]
                )
                owned_instances = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM instances "
                        "WHERE status IN ('creating', 'owned', 'cleanup_pending')"
                    ).fetchone()[0]
                )
                integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
                foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
                successor_jobs = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM control_jobs WHERE run_id=? AND episode=1",
                        (run_id,),
                    ).fetchone()[0]
                )
        finally:
            state.close()
        for artifact in artifact_paths:
            artifact.unlink()
        workspace.rmdir()
        workspace_residue = int(workspace.exists())

        expected = _expected_row_values(case, arm, repetition)
        coverage_failure = int(
            (trace.decision.disposition == "dispatch" and successor_jobs != 2)
            or (trace.decision.disposition != "dispatch" and successor_jobs != 0)
            or integrity != "ok"
            or bool(foreign_keys)
        )
        row: dict[str, object] = {
            "arm": arm,
            "case": case["id"],
            "repetition": repetition,
            "policy_input_digest": value.digest,
            "policy_config_digest": trace.evaluation.policy_config_digest,
            "decision_sequence": trace.decision_sequence,
            "fact_event_sequences": list(fact_sequences),
            "disposition": trace.decision.disposition,
            "recipe_id": trace.decision.recipe_id,
            "failure_kind": value.failure_kind,
            "source_fact_count": len(value.facts),
            "source_fact_public_metadata_digest": value.source_fact_public_metadata_digest,
            "source_route_fingerprint": _public_fingerprint(trace.decision.source_fingerprint),
            "successor_route_fingerprint": _public_fingerprint(
                trace.decision.successor_fingerprint
            ),
            "changed_axes": list(trace.decision.changed_axes),
            "terminal_outcome": expected["terminal_outcome"],
            "positive_conversion": expected["positive_conversion"],
            "false_dispatch": expected["false_dispatch"],
            "unchanged_dispatch": expected["unchanged_dispatch"],
            "duplicate_route": expected["duplicate_route"],
            "model_effort_mismatch": int(
                trace.decision.successor is not None
                and (
                    trace.decision.successor.model != "gpt-daybreak-blue-latest"
                    or trace.decision.successor.effort != "xhigh"
                )
            ),
            "effect_authority_mismatch": int(
                trace.decision.successor is not None
                and trace.decision.successor.effect_policy != "controller_only"
            ),
            "scope_mismatch": int(
                trace.decision.disposition == "dispatch"
                and any(fact.scope != "same_run_challenge_episode" for fact in value.facts)
            ),
            "replay_divergence": replay_divergence,
            "coverage_failure": coverage_failure,
            "pending_effects": pending_effects,
            "owned_instances": owned_instances,
            "workspace_residue": workspace_residue,
            "candidate_leak": 0,
            "tool_call_count": 0,
            "context_bytes": context_bytes,
            "durable_event_bytes": event_bytes,
            "policy_operation_count": trace.evaluation.operation_count,
            "policy_config_bytes": trace.evaluation.policy_config_bytes,
            "replay_digest": "",
            "elapsed_seconds": 0.0,
        }
        row["replay_digest"] = _replay_digest(row)
        row["candidate_leak"] = int(
            any(
                canary in json.dumps(row, sort_keys=True)
                for canary in _private_encodings(repetition)
            )
        )
        row["elapsed_seconds"] = time.monotonic() - started
        return row


def select_arm(summaries: dict[str, dict[str, object]], *, fifo_total: int) -> str | None:
    candidates = []
    for arm in PARENT["selection_gate"]["eligible_policy_arms"]:
        summary = summaries[arm]
        if not summary["eligible"] or int(summary["positive_conversion"]) <= fifo_total:
            continue
        key = (
            -int(summary["minimum_kind_conversion"]),
            -int(summary["positive_conversion"]),
            int(summary["unproductive_dispatch"]),
            int(summary["tool_call_count"]),
            int(summary["context_bytes"]),
            int(summary["durable_event_bytes"]),
            int(summary["policy_operation_count"]),
            int(summary["policy_config_bytes"]),
        )
        candidates.append((key, arm))
    if not candidates:
        return None
    candidates.sort()
    if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
        return None
    return candidates[0][1]


def _failed_gate(failures: list[str]) -> dict[str, object]:
    return {
        "passed": False,
        "failures": failures,
        "selected": None,
        "arm_summaries": {},
    }


def summarize_observations(
    observations: list[dict[str, object]],
) -> tuple[dict[str, dict[str, object]], int]:
    """Derive selection inputs only from raw rows; validation stays separate."""
    positive_cases = {
        case["id"]: case["failure_kind"]
        for case in PARENT["cases"]
        if case["expected"] == "dispatch"
    }
    summaries: dict[str, dict[str, object]] = {}
    by_arm = {arm: [row for row in observations if row["arm"] == arm] for arm in PARENT["arms"]}
    fifo_kind_conversion: dict[str, int] = {}
    for arm, rows in by_arm.items():
        kind_conversion = {
            kind: sum(
                int(row["positive_conversion"])
                for row in rows
                if positive_cases.get(row["case"]) == kind
            )
            for kind in sorted({str(value) for value in positive_cases.values()})
        }
        violations = sum(
            int(row[field])
            for row in rows
            for field in (
                "false_dispatch",
                "unchanged_dispatch",
                "model_effort_mismatch",
                "effect_authority_mismatch",
                "scope_mismatch",
                "replay_divergence",
                "coverage_failure",
                "pending_effects",
                "owned_instances",
                "workspace_residue",
                "candidate_leak",
            )
        ) + sum(int(row["duplicate_route"] and row["disposition"] == "dispatch") for row in rows)
        summaries[arm] = {
            "eligible": arm != "fifo_unchanged" and violations == 0,
            "minimum_kind_conversion": min(kind_conversion.values()),
            "positive_conversion": sum(int(row["positive_conversion"]) for row in rows),
            "unproductive_dispatch": sum(
                int(
                    row["disposition"] == "dispatch"
                    and row["terminal_outcome"] != "qualified_local_admission"
                )
                for row in rows
            ),
            "tool_call_count": sum(int(row["tool_call_count"]) for row in rows),
            "context_bytes": sum(int(row["context_bytes"]) for row in rows),
            "durable_event_bytes": sum(int(row["durable_event_bytes"]) for row in rows),
            "policy_operation_count": sum(int(row["policy_operation_count"]) for row in rows),
            "policy_config_bytes": sum(int(row["policy_config_bytes"]) for row in rows),
            "elapsed_seconds": sum(float(row["elapsed_seconds"]) for row in rows),
            "kind_conversion": kind_conversion,
            "violation_count": violations,
        }
        if arm == "fifo_unchanged":
            fifo_kind_conversion = kind_conversion
    for arm in PARENT["selection_gate"]["eligible_policy_arms"]:
        if any(
            summaries[arm]["kind_conversion"][kind] < fifo_kind_conversion[kind]
            for kind in fifo_kind_conversion
        ):
            summaries[arm]["eligible"] = False
    return summaries, int(summaries["fifo_unchanged"]["positive_conversion"])


def recompute_gate(
    observations: object,
    *,
    repetitions: int,
) -> dict[str, object]:
    if not isinstance(observations, list):
        return _failed_gate(["observations_not_list"])
    expected_identity = [
        (repetition, arm, case["id"])
        for repetition in range(repetitions)
        for arm in PARENT["arms"]
        for case in PARENT["cases"]
    ]
    if len(observations) != len(expected_identity):
        return _failed_gate(["row_cardinality"])
    fields = set(PARENT["observation_fields"])
    failures: list[str] = []
    for index, (row, identity) in enumerate(zip(observations, expected_identity, strict=True)):
        if not isinstance(row, dict) or set(row) != fields:
            return _failed_gate([f"row_schema:{index}"])
        if (row["repetition"], row["arm"], row["case"]) != identity:
            return _failed_gate([f"row_order:{index}"])
        case = next(case for case in PARENT["cases"] if case["id"] == row["case"])
        expected = _expected_row_values(case, str(row["arm"]), int(row["repetition"]))
        for field, value in expected.items():
            if row[field] != value:
                failures.append(f"row_value:{index}:{field}")
        value = _case_payload(case)
        if (
            row["fact_event_sequences"]
            != [
                *range(
                    int(row["fact_event_sequences"][0]),
                    int(row["fact_event_sequences"][0]) + len(value.facts),
                )
            ]
            if value.facts
            else row["fact_event_sequences"] != []
        ):
            failures.append(f"fact_sequences:{index}")
        completed = case["id"] == "completed"
        if (row["decision_sequence"] is None) != completed:
            failures.append(f"decision_sequence:{index}")
        flag_fields = OPERATION["raw_row_semantics"].get("integer_flag_domain")
        del flag_fields
        for field in PARENT["observation_schema"]["boolean_integer_fields"]:
            if type(row[field]) is not int or row[field] not in {0, 1}:
                failures.append(f"flag_domain:{index}:{field}")
        for field in (
            "tool_call_count",
            "context_bytes",
            "durable_event_bytes",
            "policy_operation_count",
            "policy_config_bytes",
        ):
            if type(row[field]) is not int or row[field] < 0:
                failures.append(f"cost_domain:{index}:{field}")
        if (
            not isinstance(row["elapsed_seconds"], (int, float))
            or not math.isfinite(row["elapsed_seconds"])
            or row["elapsed_seconds"] < 0
        ):
            failures.append(f"elapsed:{index}")
        if row["replay_digest"] != _replay_digest(row):
            failures.append(f"replay_digest:{index}")
    if failures:
        return _failed_gate(sorted(set(failures)))

    summaries, fifo_total = summarize_observations(observations)
    selected = select_arm(summaries, fifo_total=fifo_total)
    selection_failures: list[str] = []
    if repetitions == PARENT["common_config"]["repetitions"]:
        expected_totals = OPERATION["expected_twenty_repetition_operation_totals"]
        for arm, expected_total in expected_totals.items():
            if summaries[arm]["policy_operation_count"] != expected_total:
                selection_failures.append(f"operation_total:{arm}")
    if selected is None:
        selection_failures.append("no_unique_eligible_improvement")
    return {
        "passed": not selection_failures,
        "failures": selection_failures,
        "selected": selected if not selection_failures else None,
        "arm_summaries": summaries,
    }


def _fixture_record(repetitions: int, execution_orders: list[list[str]]) -> dict[str, object]:
    arms = list(PARENT["arms"])
    templates = PARENT["route_templates"]
    return {
        "arms": arms,
        "cases": [case["id"] for case in PARENT["cases"]],
        "repetitions": repetitions,
        "common_config": PARENT["common_config"],
        "fixture_manifest": PARENT["fixture_manifest"],
        "fixture_payload_digest": PARENT["frozen_digests"]["fixture_payload"],
        "policy_configs": PARENT["policy_configs"],
        "policy_config_digests": {arm: _digest(PARENT["policy_configs"][arm]) for arm in arms},
        "route_schema_fields": sorted(templates["baseline_v1"]),
        "route_recipes": PARENT["route_recipes"],
        "route_recipe_digests": {
            recipe_id: _digest(recipe)
            for recipe_id, recipe in sorted(PARENT["route_recipes"].items())
        },
        "route_templates": templates,
        "route_template_digests": {
            route_id: _digest(route) for route_id, route in sorted(templates.items())
        },
        "arm_execution_order": execution_orders,
        "lane_completion_order": [
            [1, 0] if repetition % 2 else [0, 1] for repetition in range(repetitions)
        ],
        "artifact_encoding": PARENT["fixture_manifest"]["case_payload_encoding"],
    }


def validate_result(
    result: object,
    *,
    repetitions: int,
    expected_source: dict[str, object] | None = None,
    require_clean_source: bool = False,
    verify_source_files: bool = False,
) -> None:
    """Reject stored aggregate, source, schema, privacy, and cost tampering."""
    top_fields = OPERATION["result_container_schema"]["exact_top_level_fields"]
    if not isinstance(result, dict) or set(result) != set(top_fields):
        raise ValueError("comparison result top-level schema changed")
    expected_protocol = {
        "parent_protocol_sha256": PARENT_PROTOCOL_SHA256,
        "operation_protocol_sha256": OPERATION_PROTOCOL_SHA256,
        "parent_frozen_digests": PARENT["frozen_digests"],
    }
    if result["schema_version"] != OPERATION["result_container_schema"]["schema_version"]:
        raise ValueError("comparison result schema version changed")
    if result["protocol"] != expected_protocol:
        raise ValueError("comparison result protocol binding changed")
    fixture = result["fixture"]
    if not isinstance(fixture, dict):
        raise TypeError("comparison result fixture is invalid")
    execution_orders = fixture.get("arm_execution_order")
    if not isinstance(execution_orders, list):
        raise TypeError("comparison execution order is invalid")
    if fixture != _fixture_record(repetitions, execution_orders):
        raise ValueError("comparison result fixture changed")
    expected_orders = []
    arms = list(PARENT["arms"])
    for repetition in range(repetitions):
        offset = repetition % len(arms)
        expected_orders.append(arms[offset:] + arms[:offset])
    if execution_orders != expected_orders:
        raise ValueError("comparison execution rotation changed")

    recomputed = recompute_gate(result["observations"], repetitions=repetitions)
    if result["gate"] != recomputed:
        raise ValueError("comparison stored gate differs from raw recomputation")
    if result["selection"] != {"arm": recomputed["selected"]}:
        raise ValueError("comparison stored selection differs from raw recomputation")

    provenance = result["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != {
        "source",
        "environment",
        "started_at",
        "finished_at",
        "elapsed_seconds",
        "canonical_command",
        "canonical_result_format",
        "disabled_surface_calls",
    }:
        raise ValueError("comparison result provenance schema changed")
    if (
        provenance["canonical_command"] != PARENT["result_provenance_contract"]["canonical_command"]
        or provenance["canonical_result_format"]
        != PARENT["result_provenance_contract"]["canonical_result_format"]
    ):
        raise ValueError("comparison result command or format changed")
    if provenance["disabled_surface_calls"] != {name: 0 for name in PARENT["disabled_surfaces"]}:
        raise ValueError("comparison disabled surface was invoked")
    environment = provenance["environment"]
    if not isinstance(environment, dict) or set(environment) != set(
        PARENT["result_provenance_contract"]["environment_fields"]
    ):
        raise ValueError("comparison environment schema changed")
    elapsed = provenance["elapsed_seconds"]
    if not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0:
        raise ValueError("comparison elapsed time is invalid")
    timestamps = []
    for field in ("started_at", "finished_at"):
        try:
            parsed = datetime.fromisoformat(str(provenance[field]))
        except ValueError as exc:
            raise ValueError("comparison provenance timestamp is invalid") from exc
        if parsed.tzinfo is None:
            raise ValueError("comparison provenance timestamp lacks timezone")
        timestamps.append(parsed)
    if timestamps[1] < timestamps[0]:
        raise ValueError("comparison provenance timestamps are reversed")

    source = provenance["source"]
    if not isinstance(source, dict) or set(source) != {
        "clean",
        "commit",
        "files",
        "production_tree_sha256",
    }:
        raise ValueError("comparison source identity schema changed")
    source_files = source["files"]
    required_paths = {str(path.relative_to(ROOT)) for path in _source_files()}
    if not isinstance(source_files, dict) or set(source_files) != required_paths:
        raise ValueError("comparison source file manifest changed")
    if (
        not isinstance(source["commit"], str)
        or len(source["commit"]) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in source["commit"])
    ):
        raise ValueError("comparison source commit is invalid")
    digests = [source["production_tree_sha256"], *source_files.values()]
    if any(
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        for digest in digests
    ):
        raise ValueError("comparison source digest is invalid")
    production = {
        path: digest for path, digest in source_files.items() if path.startswith("rapido/")
    }
    tree_payload = "".join(f"{path}\0{digest}\n" for path, digest in sorted(production.items()))
    if source["production_tree_sha256"] != hashlib.sha256(tree_payload.encode("utf-8")).hexdigest():
        raise ValueError("comparison production tree digest changed")
    if require_clean_source and source["clean"] is not True:
        raise ValueError("comparison source was not clean")
    if expected_source is not None and source != expected_source:
        raise ValueError("comparison source identity changed")
    current_files = {str(path.relative_to(ROOT)): _file_digest(path) for path in _source_files()}
    if source_files != current_files:
        raise ValueError("comparison source files differ from the recorded measurement")
    if verify_source_files:
        commit_check = subprocess.run(
            ["git", "cat-file", "-e", f"{source['commit']}^{{commit}}"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        if commit_check.returncode != 0:
            raise ValueError("comparison source commit is unavailable")
        for path, digest in source_files.items():
            committed = subprocess.run(
                ["git", "show", f"{source['commit']}:{path}"],
                cwd=ROOT,
                capture_output=True,
                check=False,
            )
            if committed.returncode != 0 or hashlib.sha256(committed.stdout).hexdigest() != digest:
                raise ValueError("comparison source file does not match its source commit")
    encoded = json.dumps(result, ensure_ascii=True, sort_keys=True)
    if any(
        canary in encoded
        for repetition in range(repetitions)
        for canary in _private_encodings(repetition)
    ):
        raise ValueError("comparison result contains private fixture material")


def run_comparison(
    output_root: Path,
    *,
    repetitions: int = 20,
    require_clean_source: bool = True,
) -> dict[str, object]:
    source_before = git_source_identity()
    if require_clean_source and not source_before.get("clean"):
        raise RuntimeError("E3 measurement requires clean merged source")
    if require_clean_source and repetitions != PARENT["common_config"]["repetitions"]:
        raise ValueError("E3 measurement requires the registered repetition count")
    if type(repetitions) is not int or not 1 <= repetitions <= 20:
        raise ValueError("comparison repetitions are invalid")
    if output_root.exists() and any(output_root.iterdir()):
        raise ValueError("comparison output root must be empty")
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_root.chmod(0o700)
    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    execution_orders: list[list[str]] = []
    rows = []
    arms = list(PARENT["arms"])
    with DisabledSurfaceMonitor() as surface_monitor:
        for repetition in range(repetitions):
            offset = repetition % len(arms)
            execution_order = arms[offset:] + arms[:offset]
            execution_orders.append(execution_order)
            for arm in execution_order:
                for case in PARENT["cases"]:
                    rows.append(_run_row(output_root, arm, case, repetition))
    if any(surface_monitor.counts.values()):
        raise RuntimeError("comparison invoked a disabled surface")
    order = {arm: index for index, arm in enumerate(arms)}
    case_order = {case["id"]: index for index, case in enumerate(PARENT["cases"])}
    rows.sort(key=lambda row: (row["repetition"], order[row["arm"]], case_order[row["case"]]))
    if any(output_root.iterdir()):
        raise RuntimeError("comparison workspace residue remains")
    gate = recompute_gate(rows, repetitions=repetitions)
    source_after = git_source_identity()
    if require_clean_source and (not source_after.get("clean") or source_after != source_before):
        raise RuntimeError("E3 source changed during measurement")
    provenance = {
        "source": source_after,
        "environment": _environment(output_root),
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat(),
        "elapsed_seconds": time.monotonic() - started,
        "canonical_command": PARENT["result_provenance_contract"]["canonical_command"],
        "canonical_result_format": PARENT["result_provenance_contract"]["canonical_result_format"],
        "disabled_surface_calls": surface_monitor.counts,
    }
    result = {
        "schema_version": OPERATION["result_container_schema"]["schema_version"],
        "protocol": {
            "parent_protocol_sha256": PARENT_PROTOCOL_SHA256,
            "operation_protocol_sha256": OPERATION_PROTOCOL_SHA256,
            "parent_frozen_digests": PARENT["frozen_digests"],
        },
        "fixture": _fixture_record(repetitions, execution_orders),
        "observations": rows,
        "gate": gate,
        "provenance": provenance,
        "selection": {"arm": gate["selected"]},
    }
    validate_result(
        result,
        repetitions=repetitions,
        expected_source=source_after,
        require_clean_source=require_clean_source,
    )
    return result


def _write_result(path: Path, result: dict[str, object]) -> None:
    if path.exists():
        raise FileExistsError("comparison result already exists")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=True, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", type=Path, default=PARENT_PATH)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=20)
    args = parser.parse_args()
    if args.protocol.resolve() != PARENT_PATH.resolve():
        raise ValueError("comparison protocol path differs from the registered command")
    if args.output.exists():
        raise FileExistsError("comparison result already exists")
    output_root = args.output.with_name(f".{args.output.name}.work")
    if output_root.exists():
        raise FileExistsError("comparison work root already exists")
    try:
        result = run_comparison(output_root, repetitions=args.repetitions)
        if not result["gate"]["passed"]:
            raise RuntimeError("comparison selection gate did not pass")
        validate_result(
            result,
            repetitions=args.repetitions,
            expected_source=git_source_identity(),
            require_clean_source=True,
        )
        _write_result(args.output, result)
        validate_result(
            json.loads(args.output.read_text(encoding="utf-8")),
            repetitions=args.repetitions,
            require_clean_source=True,
            verify_source_files=True,
        )
    finally:
        if output_root.exists() and not any(output_root.iterdir()):
            output_root.rmdir()


if __name__ == "__main__":
    main()
