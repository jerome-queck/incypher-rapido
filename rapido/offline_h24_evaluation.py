"""Frozen H24 preregistration and pure sanitized-result evaluator.

This module performs no model, Board, container, filesystem, or network work.  It freezes the
public experiment contract and validates/recomputes a later sanitized receipt.  Private fixture
answers, candidate values, digests, authorities, credentials, and host paths have no schema slot.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import statistics
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Final, Literal

from .board_contract import SCENARIO_IDS, validate_public_receipt
from .offline_h24 import CATALOGUE, validate_catalogue

PREREGISTRATION_SCHEMA: Final = "rapido-offline-h24-preregistration-v1"
REGISTRATION_SCHEMA: Final = "rapido-offline-h24-source-image-registration-v1"
RECEIPT_SCHEMA: Final = "rapido-offline-h24-evaluation-receipt-v1"
EVALUATION_SCHEMA: Final = "rapido-offline-h24-evaluation-v1"
ORDER_SEED: Final = "8a2ffd40fdeef877816275730e7bfce26eed11309b68136d2dcbbf4a4de4ede2"
GLOBAL_SCORING_SECONDS: Final = 19_800
CLEANUP_GRACE_SECONDS: Final = 190
CHECKPOINT_MINUTES: Final = (30, 60, 120, 180, 330)
MODEL: Final = "gpt-daybreak-blue-latest"
EFFORT: Final = "xhigh"
ARMS: Final = ("one_shot", "evidence_repair")

Decision = Literal[
    "capability_signal",
    "conversion_only_signal",
    "inconclusive",
    "no_justified_change",
]

_DECISIONS = frozenset(Decision.__args__)
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
_TERMINAL_OUTCOMES = frozenset(
    {
        "completed",
        "timeout",
        "provider_failure",
        "fixture_failure",
        "cancelled",
        "inconclusive",
        "not_started",
    }
)
_QUALIFICATION_REASONS = frozenset(
    {
        "qualified",
        "candidate_evidence_incomplete",
        "candidate_ineligible",
        "candidate_supplied",
        "candidate_unobserved",
        "verifier_requires_fixed_observation",
        "solver_output",
        "no_candidate",
        "wrong",
        "timeout",
        "provider_failure",
        "fixture_failure",
        "cancelled",
        "not_started",
    }
)
_REPAIR_TRIGGERS = frozenset(
    {"none", "candidate_unobserved", "verifier_requires_fixed_observation"}
)
_FALSE_ACCEPTS = frozenset(
    {"none", "incorrect_candidate", "supplied_candidate", "echoed_candidate"}
)
_FAILURE_CLASSES = frozenset(
    {
        "none",
        "timeout",
        "provider_transport",
        "provider_policy",
        "provider_quota",
        "startup",
        "model_validation",
        "fixture_setup",
        "cancelled",
        "solver_output",
        "evidence",
        "unknown",
    }
)
_SPAN_STAGES = frozenset(
    {
        "startup",
        "model_validation",
        "fixture_setup",
        "queue",
        "first_turn",
        "repair_turn",
        "evidence",
    }
)
_SPAN_STATUSES = frozenset({"completed", "failed", "cancelled"})
_USAGE_FIELDS: Final = (
    "input_tokens",
    "output_tokens",
    "cached_input_tokens",
    "reasoning_tokens",
)

_OUTCOME_FIELDS = frozenset(
    {
        "task_id",
        "arm",
        "order",
        "group",
        "terminal_outcome",
        "failure_class",
        "oracle_correct",
        "qualification_accepted",
        "qualified_correct",
        "qualification_reason",
        "false_accept",
        "repair_trigger",
        "repair_attempted",
        "first_candidate_elapsed_milliseconds",
        "correct_offset_milliseconds",
        "qualified_offset_milliseconds",
        "paired_qualified_elapsed_milliseconds",
        "terminal_offset_milliseconds",
        "usage",
        "tool_call_count",
        "spans",
        "artifact_bytes",
    }
)
_SPAN_FIELDS = frozenset(
    {"stage", "status", "start_offset_milliseconds", "end_offset_milliseconds"}
)
_RUNTIME_SPAN_FIELDS = frozenset(
    {"arm", "stage", "status", "start_offset_milliseconds", "end_offset_milliseconds"}
)
_CLEANUP_FIELDS = frozenset(
    {
        "started_offset_milliseconds",
        "elapsed_milliseconds",
        "completed",
        "orphan_process_count",
        "fake_instance_count",
        "pending_write_count",
        "workspace_residue_bytes",
        "privacy_scan_passed",
        "source_database_mutation_detected",
    }
)
_PREFLIGHT_FIELDS = frozenset(
    {
        "catalogue_valid",
        "all_24_prepared",
        "private_oracle_isolated",
        "target_network_disabled",
        "provider_transport_available",
    }
)
_RUNTIME_RESOURCE_FIELDS = frozenset(
    {
        "observation_status",
        "sample_interval_seconds",
        "peak_cpu_percent",
        "peak_rss_bytes",
        "peak_pids",
        "oom_killed",
    }
)
_BARRIER_FIELDS = frozenset(
    {
        "start_wall_epoch_milliseconds",
        "global_deadline_wall_epoch_milliseconds",
        "creation_before_barrier",
    }
)


def _exact(value: object, fields: frozenset[str] | set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ValueError(f"{label} fields are not exact")
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{label} must be boolean")
    return value


def _integer(value: object, label: str, *, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise TypeError(f"{label} must be a bounded nonnegative integer")
    return value


def _optional_integer(value: object, label: str, *, maximum: int = 2**63 - 1) -> int | None:
    if value is None:
        return None
    return _integer(value, label, maximum=maximum)


def _number(value: object, label: str, *, maximum: float = float(2**63 - 1)) -> float:
    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise TypeError(f"{label} must be a finite number")
    result = float(value)
    if not 0 <= result <= maximum:
        raise ValueError(f"{label} is outside its bounded range")
    return result


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _RFC3339_UTC.fullmatch(value) is None:
        raise ValueError(f"{label} must be an RFC3339 UTC timestamp")
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def preregistration_sha256(value: Mapping[str, object]) -> str:
    """Return the canonical external binding digest for one validated preregistration."""
    validate_preregistration(value)
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def stable_task_order(task_ids: Sequence[str] | None = None) -> tuple[str, ...]:
    """Order exact public task IDs by HMAC-SHA256(seed, ASCII task ID), then ID."""
    expected = tuple(task.id for task in CATALOGUE)
    supplied = expected if task_ids is None else tuple(task_ids)
    if len(supplied) != len(set(supplied)) or set(supplied) != set(expected):
        raise ValueError("order input must contain every frozen H24 task exactly once")
    seed = bytes.fromhex(ORDER_SEED)
    return tuple(
        sorted(
            supplied,
            key=lambda task_id: (
                hmac.new(seed, task_id.encode("ascii"), hashlib.sha256).digest(),
                task_id,
            ),
        )
    )


def _descriptor(arm: str) -> dict[str, object]:
    return {
        "arm": arm,
        "returned_model": MODEL,
        "returned_effort": EFFORT,
        "revision_status": "unavailable",
        "revision": None,
    }


def build_frozen_preregistration() -> dict[str, object]:
    """Build the exact public preregistration committed before any H24 outcome."""
    validate_catalogue()
    tasks = {task.id: task for task in CATALOGUE}
    ordered = stable_task_order()
    return {
        "schema": PREREGISTRATION_SCHEMA,
        "status": "frozen_before_outcomes",
        "order_seed": ORDER_SEED,
        "ordering": {
            "algorithm": "hmac_sha256_sort_v1",
            "message": "ascii_task_id",
            "tie_breaker": "ascii_task_id",
        },
        "global_scoring_seconds": GLOBAL_SCORING_SECONDS,
        "cleanup_grace_seconds": CLEANUP_GRACE_SECONDS,
        "checkpoints_minutes": list(CHECKPOINT_MINUTES),
        "arms": [
            {
                "id": "one_shot",
                "model": MODEL,
                "effort": EFFORT,
                "solve_call_limit": 1,
                "same_thread_repair_limit": 0,
            },
            {
                "id": "evidence_repair",
                "model": MODEL,
                "effort": EFFORT,
                "solve_call_limit": 1,
                "same_thread_repair_limit": 1,
            },
        ],
        "descriptor_preflight": [_descriptor(arm) for arm in ARMS],
        "execution": {
            "pair_concurrency": 1,
            "native_clients": 2,
            "startup": "serialized_shared_home",
            "paired_turns": "concurrent",
            "pair_deadline": "minimum_of_global_and_admission_plus_task_cap",
            "repair_same_thread": True,
            "repairable_rejections": [
                "candidate_unobserved",
                "verifier_requires_fixed_observation",
            ],
            "target_network": False,
            "provider_transport_required": True,
            "failed_and_inconclusive_retained": True,
        },
        "tasks": [
            {
                "order": index,
                "id": task_id,
                "group": tasks[task_id].group,
                "wall_seconds": tasks[task_id].wall_seconds,
                "cpu_seconds_ceiling": tasks[task_id].cpu_seconds_ceiling,
                "memory_bytes_ceiling": tasks[task_id].memory_bytes_ceiling,
                "artifact_bytes_ceiling": tasks[task_id].artifact_bytes_ceiling,
                "first_dispatched_arm": ARMS[(index - 1) % 2],
            }
            for index, task_id in enumerate(ordered, 1)
        ],
        "runtime_resource_limits": {
            "cpu_percent_ceiling": 1_200.0,
            "memory_bytes_ceiling": 24 * 1024 * 1024 * 1024,
            "pids_ceiling": 256,
            "sampling_interval_seconds_max": 10.0,
        },
        "soak": {
            "schema": "rapido-benign-board-contract-v1",
            "clock_mode": "real",
            "seconds": GLOBAL_SCORING_SECONDS,
            "scenario_ids": list(SCENARIO_IDS),
            "parallel_with_native": True,
            "correctness_denominator_included": False,
        },
        "gates": {
            "maximum_provider_pair_failures": 2,
            "easy_exact_and_qualified_each_arm": 6,
            "easy_repair_median_ratio_max": 1.2,
            "easy_repair_individual_ratio_max": 1.5,
            "capability_non_easy_raw_gain_min": 2,
            "conversion_qualified_gain_min": 3,
            "conversion_opportunity_min": 3,
            "hard_raw_diagnostic_below": 3,
            "automatic_production_promotion": False,
        },
        "privacy": {
            "field_policy": "closed_exact_keys_v1",
            "private_oracle": "controller_only_outside_repository_auth_and_workspaces",
            "forbidden": [
                "candidate_values",
                "candidate_or_answer_digests",
                "credentials",
                "oracle_keys",
                "host_paths",
                "target_authorities",
                "raw_model_output",
                "raw_tool_payloads",
            ],
        },
        "source_image_registration": {
            "schema": REGISTRATION_SCHEMA,
            "location": "external_immutable",
            "timing": "after_pr6_squash_merge_before_outcomes",
            "required": True,
        },
    }


def validate_preregistration(value: object) -> None:
    """Require byte-semantic equality with the exact frozen public contract."""
    if not isinstance(value, Mapping) or dict(value) != build_frozen_preregistration():
        raise ValueError("H24 preregistration differs from the frozen v1 contract")


def validate_source_image_registration(
    value: object, preregistration: Mapping[str, object]
) -> Mapping[str, object]:
    """Validate the immutable post-merge, pre-outcome source/image binding."""
    validate_preregistration(preregistration)
    row = _exact(
        value,
        {
            "schema",
            "preregistration_sha256",
            "registered_at_utc",
            "registration_state",
            "source",
            "image",
        },
        "source/image registration",
    )
    if row["schema"] != REGISTRATION_SCHEMA:
        raise ValueError("source/image registration schema is invalid")
    expected_digest = preregistration_sha256(preregistration)
    if row["preregistration_sha256"] != expected_digest:
        raise ValueError("source/image registration does not bind this preregistration")
    _timestamp(row["registered_at_utc"], "registration timestamp")
    if row["registration_state"] != "frozen_after_pr6_merge_before_outcomes":
        raise ValueError("source/image registration state is invalid")
    source = _exact(
        row["source"],
        {"commit_sha", "tree_sha", "worktree_status", "pr6_squash_merge_commit_sha"},
        "registered source",
    )
    commit = source["commit_sha"]
    if (
        not isinstance(commit, str)
        or _SHA40.fullmatch(commit) is None
        or not isinstance(source["tree_sha"], str)
        or _SHA40.fullmatch(source["tree_sha"]) is None
        or source["worktree_status"] != "clean"
        or source["pr6_squash_merge_commit_sha"] != commit
    ):
        raise ValueError("registered source identity is invalid")
    image = _exact(
        row["image"],
        {"id", "platform", "build_source_commit_sha", "immutable"},
        "registered image",
    )
    if (
        not isinstance(image["id"], str)
        or _IMAGE_ID.fullmatch(image["id"]) is None
        or image["platform"] not in {"linux/amd64", "linux/arm64"}
        or image["build_source_commit_sha"] != commit
        or image["immutable"] is not True
    ):
        raise ValueError("registered image identity is invalid")
    return row


def _validate_descriptor_rows(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) != len(ARMS):
        raise ValueError("runtime descriptor preflight must contain both arms")
    rows: list[dict[str, object]] = []
    fields = {"arm", "returned_model", "returned_effort", "revision_status", "revision"}
    for arm, value_row in zip(ARMS, value, strict=True):
        row = _exact(value_row, fields, "runtime descriptor")
        if row["arm"] != arm:
            raise ValueError("runtime descriptor arm order is invalid")
        if not all(
            item is None or isinstance(item, str)
            for item in (
                row["returned_model"],
                row["returned_effort"],
                row["revision_status"],
                row["revision"],
            )
        ):
            raise TypeError("runtime descriptor values must be strings or null")
        if row["revision_status"] not in {"observed", "unavailable", "invalid"}:
            raise ValueError("runtime descriptor revision status is invalid")
        if (
            row["revision_status"] in {"unavailable", "invalid"} and row["revision"] is not None
        ) or (row["revision_status"] == "observed" and row["revision"] is None):
            raise ValueError("runtime descriptor revision missingness is inconsistent")
        rows.append(dict(row))
    return rows


def _validate_preflight(value: object) -> dict[str, bool]:
    row = _exact(value, _PREFLIGHT_FIELDS, "fixture preflight")
    return {name: _boolean(row[name], f"preflight {name}") for name in sorted(_PREFLIGHT_FIELDS)}


def _validate_usage(value: object) -> dict[str, int | None]:
    row = _exact(value, set(_USAGE_FIELDS), "outcome usage")
    return {field: _optional_integer(row[field], f"usage {field}") for field in _USAGE_FIELDS}


def _optional_number(value: object, label: str) -> float | None:
    if value is None:
        return None
    return _number(value, label)


def _validate_runtime_resources(value: object) -> dict[str, object]:
    row = _exact(value, _RUNTIME_RESOURCE_FIELDS, "runtime resources")
    status = row["observation_status"]
    if status not in {"observed", "partial", "unavailable"}:
        raise ValueError("runtime resource observation status is invalid")
    sample_interval = _optional_number(row["sample_interval_seconds"], "sample interval")
    peak_cpu = _optional_number(row["peak_cpu_percent"], "peak CPU percent")
    peak_rss = _optional_integer(row["peak_rss_bytes"], "peak RSS")
    peak_pids = _optional_integer(row["peak_pids"], "peak PIDs")
    oom = row["oom_killed"]
    if oom is not None:
        oom = _boolean(oom, "OOM status")
    observed = (sample_interval, peak_cpu, peak_rss, peak_pids, oom)
    if status == "observed" and any(item is None for item in observed):
        raise ValueError("observed runtime resources contain missing values")
    if status == "unavailable" and any(item is not None for item in observed):
        raise ValueError("unavailable runtime resources contain observed values")
    return {
        "observation_status": status,
        "sample_interval_seconds": sample_interval,
        "peak_cpu_percent": peak_cpu,
        "peak_rss_bytes": peak_rss,
        "peak_pids": peak_pids,
        "oom_killed": oom,
    }


def _validate_barrier(value: object) -> dict[str, object]:
    row = _exact(value, _BARRIER_FIELDS, "execution barrier")
    start = _integer(row["start_wall_epoch_milliseconds"], "barrier start")
    deadline = _integer(row["global_deadline_wall_epoch_milliseconds"], "barrier deadline")
    before = _boolean(row["creation_before_barrier"], "barrier creation status")
    if deadline - start != GLOBAL_SCORING_SECONDS * 1_000:
        raise ValueError("execution barrier does not preserve the global scoring window")
    return {
        "start_wall_epoch_milliseconds": start,
        "global_deadline_wall_epoch_milliseconds": deadline,
        "creation_before_barrier": before,
    }


def _validate_spans(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise TypeError("outcome spans must be a list")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for value_row in value:
        row = _exact(value_row, _SPAN_FIELDS, "outcome span")
        stage = row["stage"]
        status = row["status"]
        if stage not in _SPAN_STAGES or status not in _SPAN_STATUSES:
            raise ValueError("outcome span enum is invalid")
        if stage in seen:
            raise ValueError("outcome contains a duplicate span stage")
        seen.add(str(stage))
        start = _integer(row["start_offset_milliseconds"], "span start")
        end = _integer(row["end_offset_milliseconds"], "span end")
        if end < start:
            raise ValueError("outcome span ends before it starts")
        result.append(
            {
                "stage": stage,
                "status": status,
                "start_offset_milliseconds": start,
                "end_offset_milliseconds": end,
            }
        )
    return result


def _validate_runtime_spans(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise TypeError("runtime spans must be a list")
    result: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for value_row in value:
        row = _exact(value_row, _RUNTIME_SPAN_FIELDS, "runtime span")
        arm = row["arm"]
        stage = row["stage"]
        status = row["status"]
        if arm not in ARMS or stage not in {"startup", "model_validation"}:
            raise ValueError("runtime span identity is invalid")
        if status not in _SPAN_STATUSES:
            raise ValueError("runtime span status is invalid")
        identity = (str(arm), str(stage))
        if identity in seen:
            raise ValueError("runtime spans contain a duplicate identity")
        seen.add(identity)
        start = _integer(row["start_offset_milliseconds"], "runtime span start")
        end = _integer(row["end_offset_milliseconds"], "runtime span end")
        if end < start:
            raise ValueError("runtime span ends before it starts")
        result.append(
            {
                "arm": arm,
                "stage": stage,
                "status": status,
                "start_offset_milliseconds": start,
                "end_offset_milliseconds": end,
            }
        )
    return result


def _validate_outcome(
    value: object,
    expected_task: Mapping[str, object],
    expected_arm: str,
) -> dict[str, object]:
    row = _exact(value, _OUTCOME_FIELDS, "H24 outcome")
    if (
        row["task_id"] != expected_task["id"]
        or row["arm"] != expected_arm
        or row["order"] != expected_task["order"]
        or row["group"] != expected_task["group"]
    ):
        raise ValueError("H24 outcome one-to-one identity is invalid")
    if row["terminal_outcome"] not in _TERMINAL_OUTCOMES:
        raise ValueError("H24 terminal outcome is invalid")
    if row["failure_class"] not in _FAILURE_CLASSES:
        raise ValueError("H24 failure class is invalid")
    if row["qualification_reason"] not in _QUALIFICATION_REASONS:
        raise ValueError("H24 qualification reason is invalid")
    if row["false_accept"] not in _FALSE_ACCEPTS:
        raise ValueError("H24 false-accept class is invalid")
    if row["repair_trigger"] not in _REPAIR_TRIGGERS:
        raise ValueError("H24 repair trigger is invalid")

    oracle_correct = _boolean(row["oracle_correct"], "oracle correctness")
    qualification_accepted = _boolean(row["qualification_accepted"], "qualification acceptance")
    qualified_correct = _boolean(row["qualified_correct"], "qualified correctness")
    repair_attempted = _boolean(row["repair_attempted"], "repair attempted")
    if qualified_correct is not (oracle_correct and qualification_accepted):
        raise ValueError("qualified correctness must equal correctness and qualification")
    if (row["qualification_reason"] == "qualified") is not qualification_accepted:
        raise ValueError("qualification acceptance and reason disagree")
    if expected_arm == "one_shot" and (row["repair_trigger"] != "none" or repair_attempted):
        raise ValueError("one-shot outcome cannot contain repair state")
    if repair_attempted and row["repair_trigger"] == "none":
        raise ValueError("repair attempt lacks an eligible trigger")
    if row["false_accept"] != "none" and not qualification_accepted:
        raise ValueError("false accept requires accepted qualification")
    if qualification_accepted and not oracle_correct and row["false_accept"] == "none":
        raise ValueError("accepted incorrect answer lacks a false-accept class")
    if qualification_accepted and oracle_correct and row["false_accept"] == "incorrect_candidate":
        raise ValueError("incorrect-candidate false accept contradicts the oracle")

    first_candidate = _optional_integer(
        row["first_candidate_elapsed_milliseconds"], "first candidate elapsed"
    )
    correct_offset = _optional_integer(row["correct_offset_milliseconds"], "correct offset")
    qualified_offset = _optional_integer(row["qualified_offset_milliseconds"], "qualified offset")
    paired_qualified = _optional_integer(
        row["paired_qualified_elapsed_milliseconds"], "paired qualified elapsed"
    )
    terminal_offset = _integer(row["terminal_offset_milliseconds"], "terminal offset")
    if (correct_offset is not None) is not oracle_correct:
        raise ValueError("oracle correctness and correct timestamp disagree")
    if (qualified_offset is not None) is not qualified_correct:
        raise ValueError("qualified correctness and timestamp disagree")
    if (paired_qualified is not None) is not qualified_correct:
        raise ValueError("qualified correctness and paired timing disagree")
    for name, offset in (("correct", correct_offset), ("qualified", qualified_offset)):
        if offset is not None and offset > terminal_offset:
            raise ValueError(f"{name} timestamp follows terminal timestamp")

    return {
        **dict(row),
        "oracle_correct": oracle_correct,
        "qualification_accepted": qualification_accepted,
        "qualified_correct": qualified_correct,
        "repair_attempted": repair_attempted,
        "first_candidate_elapsed_milliseconds": first_candidate,
        "correct_offset_milliseconds": correct_offset,
        "qualified_offset_milliseconds": qualified_offset,
        "paired_qualified_elapsed_milliseconds": paired_qualified,
        "terminal_offset_milliseconds": terminal_offset,
        "usage": _validate_usage(row["usage"]),
        "tool_call_count": _integer(row["tool_call_count"], "tool call count"),
        "spans": _validate_spans(row["spans"]),
        "artifact_bytes": _integer(row["artifact_bytes"], "outcome artifact bytes"),
    }


def _validate_cleanup(value: object) -> dict[str, object]:
    row = _exact(value, _CLEANUP_FIELDS, "cleanup receipt")
    return {
        "started_offset_milliseconds": _integer(
            row["started_offset_milliseconds"], "cleanup start"
        ),
        "elapsed_milliseconds": _integer(row["elapsed_milliseconds"], "cleanup elapsed"),
        "completed": _boolean(row["completed"], "cleanup completed"),
        "orphan_process_count": _integer(row["orphan_process_count"], "orphan count"),
        "fake_instance_count": _integer(row["fake_instance_count"], "fake instance count"),
        "pending_write_count": _integer(row["pending_write_count"], "pending write count"),
        "workspace_residue_bytes": _integer(row["workspace_residue_bytes"], "workspace residue"),
        "privacy_scan_passed": _boolean(row["privacy_scan_passed"], "privacy scan"),
        "source_database_mutation_detected": _boolean(
            row["source_database_mutation_detected"], "source database mutation"
        ),
    }


def _interval_union(intervals: Sequence[tuple[int, int]]) -> int:
    if not intervals:
        return 0
    ordered = sorted(intervals)
    total = 0
    start, end = ordered[0]
    for next_start, next_end in ordered[1:]:
        if next_start > end:
            total += end - start
            start, end = next_start, next_end
        else:
            end = max(end, next_end)
    return total + end - start


def _timing_summary(
    rows: Sequence[Mapping[str, object]], runtime_spans: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    intervals: list[tuple[int, int]] = []
    lane = 0
    for row in rows:
        spans = row["spans"]
        assert isinstance(spans, list)
        for span in spans:
            assert isinstance(span, Mapping)
            start = int(span["start_offset_milliseconds"])
            end = int(span["end_offset_milliseconds"])
            lane += end - start
            if end > start:
                intervals.append((start, end))
    for span in runtime_spans:
        start = int(span["start_offset_milliseconds"])
        end = int(span["end_offset_milliseconds"])
        lane += end - start
        if end > start:
            intervals.append((start, end))
    wall = _interval_union(intervals)
    return {
        "lane_milliseconds": lane,
        "wall_active_milliseconds": wall,
        "concurrent_lane_milliseconds": lane - wall,
        "semantics": "relative intervals; lane time additive; wall time interval union",
    }


def _usage_summary(rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    arms: dict[str, object] = {}
    for arm in ARMS:
        selected = [row for row in rows if row["arm"] == arm]
        fields: dict[str, object] = {}
        for field in _USAGE_FIELDS:
            values = [row["usage"][field] for row in selected]  # type: ignore[index]
            observed = [value for value in values if value is not None]
            missing = len(values) - len(observed)
            fields[field] = {
                "total": sum(observed) if missing == 0 else None,
                "observed_total": sum(observed),
                "observed_attempt_count": len(observed),
                "missing_attempt_count": missing,
            }
        arms[arm] = {"fields": fields}
    return {
        "policy": "missing_usage_remains_null; cumulative_final_snapshot_counted_once",
        "arms": arms,
    }


def _checkpoint_counts(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for minute in CHECKPOINT_MINUTES:
        boundary = minute * 60 * 1_000
        arms: dict[str, object] = {}
        for arm in ARMS:
            selected = [row for row in rows if row["arm"] == arm]
            arms[arm] = {
                "C": sum(
                    row["correct_offset_milliseconds"] is not None
                    and int(row["correct_offset_milliseconds"]) <= boundary
                    for row in selected
                ),
                "Q": sum(
                    row["qualified_offset_milliseconds"] is not None
                    and int(row["qualified_offset_milliseconds"]) <= boundary
                    for row in selected
                ),
            }
        result.append({"minutes": minute, "arms": arms})
    return result


def _counts(rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for arm in ARMS:
        selected = [row for row in rows if row["arm"] == arm]
        non_easy = [row for row in selected if row["group"] != "easy"]
        hard = [row for row in selected if row["group"] == "hard"]
        result[arm] = {
            "rows": len(selected),
            "C": sum(bool(row["oracle_correct"]) for row in selected),
            "Q": sum(bool(row["qualified_correct"]) for row in selected),
            "C_minus_Q": sum(bool(row["oracle_correct"]) for row in selected)
            - sum(bool(row["qualified_correct"]) for row in selected),
            "non_easy_C": sum(bool(row["oracle_correct"]) for row in non_easy),
            "non_easy_Q": sum(bool(row["qualified_correct"]) for row in non_easy),
            "hard_C": sum(bool(row["oracle_correct"]) for row in hard),
            "wrong_but_accepted": sum(
                bool(row["qualification_accepted"]) and not bool(row["oracle_correct"])
                for row in selected
            ),
            "false_accepts": sum(row["false_accept"] != "none" for row in selected),
        }
    return result


def _easy_gate(rows: Sequence[Mapping[str, object]]) -> tuple[bool, dict[str, object]]:
    easy = [row for row in rows if row["group"] == "easy"]
    exact = {
        arm: sum(bool(row["qualified_correct"]) for row in easy if row["arm"] == arm)
        for arm in ARMS
    }
    by_key = {(row["task_id"], row["arm"]): row for row in easy}
    ratios: list[float] = []
    for task in CATALOGUE:
        if task.group != "easy":
            continue
        one = by_key[(task.id, "one_shot")]["paired_qualified_elapsed_milliseconds"]
        repair = by_key[(task.id, "evidence_repair")]["paired_qualified_elapsed_milliseconds"]
        if one is None or repair is None:
            continue
        if one == 0:
            ratios.append(1.0 if repair == 0 else math.inf)
        else:
            ratios.append(int(repair) / int(one))
    median = statistics.median(ratios) if len(ratios) == 6 else None
    maximum = max(ratios) if len(ratios) == 6 else None
    passed = (
        exact == {"one_shot": 6, "evidence_repair": 6}
        and median is not None
        and median <= 1.2
        and maximum is not None
        and maximum <= 1.5
    )
    return passed, {
        "qualified_easy_by_arm": exact,
        "repair_to_one_shot_qualified_ratio_median": median,
        "repair_to_one_shot_qualified_ratio_max": maximum,
        "passed": passed,
    }


def _resource_gate(
    rows: Sequence[Mapping[str, object]],
    task_specs: Mapping[str, Mapping[str, object]],
    runtime: Mapping[str, object],
    limits: Mapping[str, object],
) -> bool:
    for row in rows:
        spec = task_specs[str(row["task_id"])]
        if int(row["artifact_bytes"]) > int(spec["artifact_bytes_ceiling"]):
            return False
    return (
        runtime["observation_status"] == "observed"
        and float(runtime["sample_interval_seconds"])
        <= float(limits["sampling_interval_seconds_max"])
        and float(runtime["peak_cpu_percent"]) <= float(limits["cpu_percent_ceiling"])
        and int(runtime["peak_rss_bytes"]) <= int(limits["memory_bytes_ceiling"])
        and int(runtime["peak_pids"]) <= int(limits["pids_ceiling"])
        and runtime["oom_killed"] is False
    )


def classify_h24(
    *,
    model_preflight_valid: bool,
    provider_pair_failures: int,
    safety_integrity_passed: bool,
    easy_passed: bool,
    one_raw: int,
    repair_raw: int,
    one_non_easy_raw: int,
    repair_non_easy_raw: int,
    one_qualified: int,
    repair_qualified: int,
    repair_opportunities: int,
) -> Decision:
    """Apply the preregistered decision precedence without inspecting private values."""
    if not model_preflight_valid or provider_pair_failures > 2:
        return "inconclusive"
    if not safety_integrity_passed or not easy_passed or repair_raw < one_raw:
        return "no_justified_change"
    if repair_non_easy_raw - one_non_easy_raw >= 2:
        return "capability_signal"
    if repair_raw == one_raw and repair_qualified - one_qualified >= 3:
        if repair_opportunities >= 3:
            return "conversion_only_signal"
        return "inconclusive"
    if repair_opportunities < 3:
        return "inconclusive"
    return "no_justified_change"


def _raw_object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be an object")
    return value


def _raw_list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise TypeError(f"{label} must be a list")
    return value


def _closed_failure(value: object) -> str:
    if value is None:
        return "none"
    if value in _FAILURE_CLASSES:
        return str(value)
    if value in {"interrupted", "cleanup"}:
        return "cancelled"
    if value in {"usage_limit_exceeded", "rate_limit_exceeded", "session_budget_exceeded"}:
        return "provider_quota"
    if value in {"cyber_policy", "misalignment_policy_violation"}:
        return "provider_policy"
    if value in {
        "http_connection_failed",
        "response_stream_connection_failed",
        "response_stream_disconnected",
        "response_too_many_failed_attempts",
        "server_overloaded",
        "native_runtime",
        "internal_server_error",
    }:
        return "provider_transport"
    return "unknown"


def _raw_span_projection(native: Mapping[str, object]) -> list[dict[str, object]]:
    values = _raw_list(native.get("spans"), "raw native spans")
    result: list[dict[str, object]] = []
    for value in values:
        row = _raw_object(value, "raw native span")
        if row.get("status") == "not_run":
            continue
        stage = row.get("stage")
        if stage not in _SPAN_STAGES:
            raise ValueError("raw native span stage is invalid")
        result.append(
            {
                "stage": stage,
                "status": row.get("status"),
                "start_offset_milliseconds": row.get("start_offset_milliseconds"),
                "end_offset_milliseconds": row.get("end_offset_milliseconds"),
            }
        )
    return _validate_spans(result)


def _span_end(spans: Sequence[Mapping[str, object]], stage: str) -> int | None:
    return next(
        (int(row["end_offset_milliseconds"]) for row in spans if row["stage"] == stage),
        None,
    )


def _raw_outcome_projection(raw: object, task: Mapping[str, object], arm: str) -> dict[str, object]:
    row = _raw_object(raw, "raw H24 result")
    if (
        row.get("task_id") != task["id"]
        or row.get("arm") != arm
        or row.get("family") != task["group"]
    ):
        raise ValueError("raw H24 result identity is invalid")
    if row.get("model") != MODEL or row.get("effort") != EFFORT or row.get("role") != "verifier":
        raise ValueError("raw H24 result roster is invalid")
    first = _raw_object(row.get("first"), "raw first evaluation")
    final = _raw_object(row.get("final"), "raw final evaluation")
    first_outcome = first.get("outcome")
    final_outcome = final.get("outcome")
    allowed = {
        "verified_correct",
        "verified_wrong",
        "rejected_correct",
        "rejected_wrong",
        "no_candidate",
        "solver_output",
        "timeout",
        "provider_failure",
    }
    if first_outcome not in allowed or final_outcome not in allowed:
        raise ValueError("raw H24 verifier outcome is invalid")
    repair_attempted = _boolean(row.get("repair_attempted"), "raw repair attempted")
    continuation_count = _integer(row.get("continuation_count"), "raw continuation count")
    if continuation_count != int(repair_attempted) or continuation_count > 1:
        raise ValueError("raw H24 continuation count is invalid")
    if arm == "one_shot" and repair_attempted:
        raise ValueError("raw one-shot result attempted repair")

    native = _raw_object(row.get("native_observability"), "raw native observability")
    spans = _raw_span_projection(native)
    terminal_offset = max(
        (int(span["end_offset_milliseconds"]) for span in spans),
        default=0,
    )
    first_end = _span_end(spans, "first_turn")
    repair_end = _span_end(spans, "repair_turn")
    final_end = repair_end if repair_attempted and repair_end is not None else first_end
    final_end = terminal_offset if final_end is None else final_end

    correct_outcomes = {"verified_correct", "rejected_correct"}
    oracle_correct = final_outcome in correct_outcomes
    qualification_accepted = final_outcome in {"verified_correct", "verified_wrong"}
    qualified_correct = final_outcome == "verified_correct"
    first_correct = first_outcome in correct_outcomes
    correct_offset = (
        (first_end if first_correct and first_end is not None else final_end)
        if oracle_correct
        else None
    )
    qualified_offset = final_end if qualified_correct else None
    task_origin = min(
        (int(span["start_offset_milliseconds"]) for span in spans),
        default=terminal_offset,
    )
    paired_qualified = final_end - task_origin if qualified_correct else None
    candidate_outcomes = {
        "verified_correct",
        "verified_wrong",
        "rejected_correct",
        "rejected_wrong",
    }
    first_candidate_elapsed = None
    if first_outcome in candidate_outcomes:
        first_candidate_elapsed = (
            first_end - task_origin if first_end is not None else terminal_offset - task_origin
        )
    elif final_outcome in candidate_outcomes:
        first_candidate_elapsed = final_end - task_origin

    terminal_outcome = {
        "timeout": "timeout",
        "provider_failure": "provider_failure",
        "no_candidate": "inconclusive",
        "solver_output": "inconclusive",
    }.get(str(final_outcome), "completed")
    rejection = final.get("rejection_reason")
    if qualification_accepted:
        qualification_reason = "qualified"
    elif rejection in _QUALIFICATION_REASONS:
        qualification_reason = rejection
    else:
        qualification_reason = {
            "no_candidate": "no_candidate",
            "solver_output": "solver_output",
            "timeout": "timeout",
            "provider_failure": "provider_failure",
        }.get(str(final_outcome), "wrong")
    first_rejection = first.get("rejection_reason")
    repair_trigger = (
        first_rejection
        if arm == "evidence_repair" and first_rejection in _REPAIR_TRIGGERS - {"none"}
        else "none"
    )
    usage = _raw_object(native.get("usage"), "raw native usage")
    accounted = _raw_object(usage.get("accounted"), "raw accounted usage")
    tools = _raw_object(row.get("tool_calls"), "raw tool calls")
    return {
        "task_id": task["id"],
        "arm": arm,
        "order": task["order"],
        "group": task["group"],
        "terminal_outcome": terminal_outcome,
        "failure_class": _closed_failure(row.get("failure_class")),
        "oracle_correct": oracle_correct,
        "qualification_accepted": qualification_accepted,
        "qualified_correct": qualified_correct,
        "qualification_reason": qualification_reason,
        "false_accept": "incorrect_candidate" if final_outcome == "verified_wrong" else "none",
        "repair_trigger": repair_trigger,
        "repair_attempted": repair_attempted,
        "first_candidate_elapsed_milliseconds": first_candidate_elapsed,
        "correct_offset_milliseconds": correct_offset,
        "qualified_offset_milliseconds": qualified_offset,
        "paired_qualified_elapsed_milliseconds": paired_qualified,
        "terminal_offset_milliseconds": terminal_offset,
        "usage": {field: accounted.get(field) for field in _USAGE_FIELDS},
        "tool_call_count": tools.get("cumulative"),
        "spans": spans,
        "artifact_bytes": row.get("artifact_bytes"),
    }


def _raw_runtime_projection(
    raw_runtime: object,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    runtime = _raw_object(raw_runtime, "raw H24 runtime")
    descriptors: list[dict[str, object]] = []
    spans: list[dict[str, object]] = []
    for arm in ARMS:
        arm_row = _raw_object(runtime.get(arm), "raw arm runtime")
        descriptor = arm_row.get("descriptor")
        if isinstance(descriptor, Mapping):
            returned_model = descriptor.get("returned_model")
            returned_effort = EFFORT if descriptor.get("effort_supported") is True else None
            revision_status = descriptor.get("revision_status")
            revision = descriptor.get("revision")
        else:
            returned_model = None
            returned_effort = None
            revision_status = "invalid"
            revision = None
        descriptors.append(
            {
                "arm": arm,
                "returned_model": returned_model,
                "returned_effort": returned_effort,
                "revision_status": revision_status,
                "revision": revision,
            }
        )
        raw_spans = _raw_object(arm_row.get("spans"), "raw runtime spans")
        for stage in ("startup", "model_validation"):
            span = _raw_object(raw_spans.get(stage), "raw runtime span")
            if span.get("status") == "not_run":
                continue
            spans.append(
                {
                    "arm": arm,
                    "stage": stage,
                    "status": span.get("status"),
                    "start_offset_milliseconds": span.get("start_offset_milliseconds"),
                    "end_offset_milliseconds": span.get("end_offset_milliseconds"),
                }
            )
    return _validate_descriptor_rows(descriptors), _validate_runtime_spans(spans)


def build_evaluation_receipt(
    *,
    preregistration: Mapping[str, object],
    registration: Mapping[str, object],
    raw_h24: Mapping[str, object],
    soak: Mapping[str, object],
    barrier: Mapping[str, object],
    runtime_resources: Mapping[str, object],
    cleanup: Mapping[str, object],
    run_started_at_utc: str,
    scoring_elapsed_milliseconds: int,
) -> dict[str, object]:
    """Purely adapt sanitized runner/supervisor facts into the exact final envelope."""
    validate_preregistration(preregistration)
    validate_source_image_registration(registration, preregistration)
    if (
        set(raw_h24)
        != {
            "schema",
            "source",
            "image",
            "protocol",
            "runtime",
            "results",
            "summary",
            "native_observability",
        }
        or raw_h24.get("schema") != "rapido-offline-h24-pilot-v1"
    ):
        raise ValueError("raw H24 receipt shape or schema is invalid")
    protocol = _raw_object(raw_h24.get("protocol"), "raw H24 protocol")
    tasks = preregistration["tasks"]
    assert isinstance(tasks, list)
    expected_order = [task["id"] for task in tasks]
    expected_resources = [
        {
            "task_id": task["id"],
            "wall_seconds": task["wall_seconds"],
            "artifact_bytes_ceiling": task["artifact_bytes_ceiling"],
            "cpu_seconds_ceiling": task["cpu_seconds_ceiling"],
            "memory_bytes_ceiling": task["memory_bytes_ceiling"],
        }
        for task in tasks
    ]
    expected_roster = [
        {"arm": "one_shot", "model": MODEL, "effort": EFFORT, "continuation": False},
        {
            "arm": "evidence_repair",
            "model": MODEL,
            "effort": EFFORT,
            "continuation": True,
        },
    ]
    if (
        protocol.get("task_order") != expected_order
        or protocol.get("preregistration_sha256") != preregistration_sha256(preregistration)
        or protocol.get("randomization") != "hmac_sha256_sort_v1"
        or protocol.get("task_resource_policies") != expected_resources
        or protocol.get("global_deadline_seconds") != GLOBAL_SCORING_SECONDS
        or protocol.get("pair_deadline") != "minimum_of_global_and_admission_plus_task_cap"
        or protocol.get("startup") != "serialized_shared_home"
        or protocol.get("paired_turns") != "concurrent"
        or protocol.get("repair_same_thread") is not True
        or protocol.get("repair_continuation_limit") != 1
        or protocol.get("repairable_rejections")
        != ["candidate_unobserved", "verifier_requires_fixed_observation"]
        or protocol.get("board_enabled") is not False
        or protocol.get("submissions_enabled") is not False
        or protocol.get("target_network_enabled") is not False
        or protocol.get("provider_transport_required") is not True
        or protocol.get("fallback_allowed") is not False
        or protocol.get("roster") != expected_roster
    ):
        raise ValueError("raw H24 protocol does not match the frozen preregistration")
    source = _raw_object(raw_h24.get("source"), "raw source identity")
    observed_source = _raw_object(source.get("observed"), "raw observed source")
    registered_source = _raw_object(registration.get("source"), "registered source")
    if observed_source.get("head_sha") != registered_source.get("commit_sha"):
        raise ValueError("raw H24 source does not match external registration")
    image = _raw_object(raw_h24.get("image"), "raw image identity")
    declared_image = _raw_object(image.get("declared"), "raw declared image")
    registered_image = _raw_object(registration.get("image"), "registered image")
    if declared_image.get("id") != registered_image.get("id"):
        raise ValueError("raw H24 image does not match external registration")

    raw_results = _raw_list(raw_h24.get("results"), "raw H24 results")
    if len(raw_results) != 48:
        raise ValueError("raw H24 receipt must contain exactly 48 results")
    outcomes: list[dict[str, object]] = []
    cursor = 0
    for task in tasks:
        assert isinstance(task, Mapping)
        for arm in ARMS:
            projected = _raw_outcome_projection(raw_results[cursor], task, arm)
            outcomes.append(_validate_outcome(projected, task, arm))
            cursor += 1
    descriptors, runtime_spans = _raw_runtime_projection(raw_h24.get("runtime"))
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "preregistration_sha256": preregistration_sha256(preregistration),
        "registration": dict(registration),
        "run_started_at_utc": run_started_at_utc,
        "barrier": dict(barrier),
        "scoring_elapsed_milliseconds": scoring_elapsed_milliseconds,
        "runtime_descriptor_preflight": descriptors,
        "runtime_spans": runtime_spans,
        "fixture_preflight": {
            "catalogue_valid": True,
            "all_24_prepared": True,
            "private_oracle_isolated": protocol.get("oracle_location")
            == "controller_only_outside_repository_auth_and_workspaces",
            "target_network_disabled": protocol.get("target_network_enabled") is False,
            "provider_transport_available": protocol.get("provider_transport_required") is True,
        },
        "runtime_resources": dict(runtime_resources),
        "outcomes": outcomes,
        "soak": dict(soak),
        "cleanup": dict(cleanup),
    }
    evaluate_h24_receipt(preregistration, receipt)
    return receipt


def evaluate_h24_receipt(
    preregistration: Mapping[str, object], receipt: object
) -> dict[str, object]:
    """Validate, recompute, gate, and classify one sanitized final H24 receipt."""
    validate_preregistration(preregistration)
    top = _exact(
        receipt,
        {
            "schema",
            "preregistration_sha256",
            "registration",
            "run_started_at_utc",
            "barrier",
            "scoring_elapsed_milliseconds",
            "runtime_descriptor_preflight",
            "runtime_spans",
            "fixture_preflight",
            "runtime_resources",
            "outcomes",
            "soak",
            "cleanup",
        },
        "H24 evaluation receipt",
    )
    if top["schema"] != RECEIPT_SCHEMA:
        raise ValueError("H24 evaluation receipt schema is invalid")
    digest = preregistration_sha256(preregistration)
    if top["preregistration_sha256"] != digest:
        raise ValueError("H24 evaluation receipt does not bind this preregistration")
    registration = validate_source_image_registration(top["registration"], preregistration)
    started = _timestamp(top["run_started_at_utc"], "run start")
    registered = _timestamp(registration["registered_at_utc"], "registration timestamp")
    if registered > started:
        raise ValueError("source/image registration occurred after outcome collection began")
    barrier = _validate_barrier(top["barrier"])
    scoring_elapsed = _integer(top["scoring_elapsed_milliseconds"], "scoring elapsed")
    descriptors = _validate_descriptor_rows(top["runtime_descriptor_preflight"])
    runtime_spans = _validate_runtime_spans(top["runtime_spans"])
    preflight = _validate_preflight(top["fixture_preflight"])
    runtime_resources = _validate_runtime_resources(top["runtime_resources"])

    tasks = preregistration["tasks"]
    assert isinstance(tasks, list)
    values = top["outcomes"]
    if not isinstance(values, list) or len(values) != 48:
        raise ValueError("H24 receipt must contain exactly 48 outcome rows")
    rows: list[dict[str, object]] = []
    cursor = 0
    for task in tasks:
        assert isinstance(task, Mapping)
        for arm in ARMS:
            rows.append(_validate_outcome(values[cursor], task, arm))
            cursor += 1

    soak = top["soak"]
    validate_public_receipt(soak)
    assert isinstance(soak, Mapping)
    if (
        soak["clock_mode"] != "real"
        or float(soak["requested_seconds"]) != GLOBAL_SCORING_SECONDS
        or tuple(row["scenario_id"] for row in soak["scenarios"]) != SCENARIO_IDS  # type: ignore[index]
        or soak["correctness_denominator_included"] is not False
    ):
        raise ValueError("H24 soak differs from the preregistered real-clock contract")
    cleanup = _validate_cleanup(top["cleanup"])

    counts = _counts(rows)
    one = counts["one_shot"]
    repair = counts["evidence_repair"]
    assert isinstance(one, Mapping) and isinstance(repair, Mapping)
    checkpoints = _checkpoint_counts(rows)
    if any(
        arm_counts["Q"] > arm_counts["C"]
        for checkpoint in checkpoints
        for arm_counts in checkpoint["arms"].values()  # type: ignore[union-attr]
    ):
        raise ValueError("checkpoint qualified-correct count exceeds oracle-correct count")

    expected_descriptors = preregistration["descriptor_preflight"]
    model_preflight_valid = descriptors == expected_descriptors
    fixture_preflight_valid = all(preflight.values())
    provider_pair_failures = sum(
        any(
            row["terminal_outcome"] == "provider_failure" and row["task_id"] == task["id"]
            for row in rows
        )
        for task in tasks
    )
    easy_passed, easy = _easy_gate(rows)
    task_specs = {str(task["id"]): task for task in tasks}
    limits = preregistration["runtime_resource_limits"]
    assert isinstance(limits, Mapping)
    resource_passed = _resource_gate(rows, task_specs, runtime_resources, limits)
    deadline_passed = (
        scoring_elapsed >= GLOBAL_SCORING_SECONDS * 1_000
        and barrier["creation_before_barrier"] is True
        and all(
            int(row["terminal_offset_milliseconds"]) <= GLOBAL_SCORING_SECONDS * 1_000
            for row in rows
        )
        and all(
            int(span["end_offset_milliseconds"]) <= GLOBAL_SCORING_SECONDS * 1_000
            for row in rows
            for span in row["spans"]  # type: ignore[union-attr]
        )
    )
    cleanup_passed = (
        int(cleanup["started_offset_milliseconds"]) >= GLOBAL_SCORING_SECONDS * 1_000
        and int(cleanup["elapsed_milliseconds"]) <= CLEANUP_GRACE_SECONDS * 1_000
        and cleanup["completed"] is True
        and cleanup["orphan_process_count"] == 0
        and cleanup["fake_instance_count"] == 0
        and cleanup["pending_write_count"] == 0
        and cleanup["workspace_residue_bytes"] == 0
        and cleanup["privacy_scan_passed"] is True
        and cleanup["source_database_mutation_detected"] is False
    )
    false_accept_passed = all(row["false_accept"] == "none" for row in rows)
    soak_passed = soak["passed"] is True
    safety_integrity_passed = (
        fixture_preflight_valid
        and resource_passed
        and deadline_passed
        and cleanup_passed
        and false_accept_passed
        and soak_passed
    )
    opportunities = sum(
        row["arm"] == "evidence_repair" and row["repair_trigger"] != "none" for row in rows
    )
    decision = classify_h24(
        model_preflight_valid=model_preflight_valid and fixture_preflight_valid,
        provider_pair_failures=provider_pair_failures,
        safety_integrity_passed=safety_integrity_passed,
        easy_passed=easy_passed,
        one_raw=int(one["C"]),
        repair_raw=int(repair["C"]),
        one_non_easy_raw=int(one["non_easy_C"]),
        repair_non_easy_raw=int(repair["non_easy_C"]),
        one_qualified=int(one["Q"]),
        repair_qualified=int(repair["Q"]),
        repair_opportunities=opportunities,
    )
    if decision not in _DECISIONS:
        raise AssertionError("classifier returned an invalid decision")
    return {
        "schema": EVALUATION_SCHEMA,
        "decision": decision,
        "counts": counts,
        "checkpoints": checkpoints,
        "usage": _usage_summary(rows),
        "timing": _timing_summary(rows, runtime_spans),
        "gates": {
            "model_preflight": model_preflight_valid,
            "fixture_preflight": fixture_preflight_valid,
            "provider_pair_failures": provider_pair_failures,
            "provider_pair_failure_limit_passed": provider_pair_failures <= 2,
            "resource_ceilings": resource_passed,
            "global_deadline": deadline_passed,
            "state_contract_10_of_10": soak_passed,
            "false_accept_free": false_accept_passed,
            "cleanup_and_privacy": cleanup_passed,
            "easy_non_regression": easy,
            "safety_integrity": safety_integrity_passed,
        },
        "diagnostics": {
            "repair_opportunities": opportunities,
            "hard_repair_raw_below_three": int(repair["hard_C"]) < 3,
            "hard_raw_by_arm": {
                "one_shot": int(one["hard_C"]),
                "evidence_repair": int(repair["hard_C"]),
            },
            "automatic_production_promotion": False,
        },
    }


__all__ = [
    "ARMS",
    "CHECKPOINT_MINUTES",
    "CLEANUP_GRACE_SECONDS",
    "EFFORT",
    "EVALUATION_SCHEMA",
    "GLOBAL_SCORING_SECONDS",
    "MODEL",
    "ORDER_SEED",
    "PREREGISTRATION_SCHEMA",
    "RECEIPT_SCHEMA",
    "REGISTRATION_SCHEMA",
    "build_evaluation_receipt",
    "build_frozen_preregistration",
    "classify_h24",
    "evaluate_h24_receipt",
    "preregistration_sha256",
    "stable_task_order",
    "validate_preregistration",
    "validate_source_image_registration",
]
