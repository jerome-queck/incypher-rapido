"""Pure validation for sanitized offline capability registrations and receipts.

The validators intentionally perform cross-field checks that JSON Schema cannot express. They do
no filesystem, model, Board, container, or network work and accept no private values.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any, Final

REGISTRATION_SCHEMA: Final = "rapido-capability-experiment-registry-v1"
RECEIPT_SCHEMA: Final = "rapido-capability-public-receipt-v1"
TASK_MANIFEST_SCHEMA: Final = "rapido-capability-candidate-manifest-v1"
REGISTRATION_CANONICAL_SHA256: Final = (
    "f74810e1c43c0a1cbdebd196af6f76b1d96bfb6572b344129662dd9f2657ffd1"
)
SOURCE_SHA: Final = "6aa26147c35fbc46affeeb77d93d6b88640564a8"
SOURCE_IMAGE_ID: Final = "sha256:0eef1ceb74759bf64e9a89ca0dd1cf722bd1f6967a9b53666577164ee4d71c52"
TASK_MANIFEST_SHA256: Final = "14a5dbd43fac8df0703b22a2cb258f458a7319c000f95e15b8ef5984a573981b"
SCHEDULER_CONTRACT: Final = {
    "active_challenges": 5,
    "lane_admissions": 20,
    "dynamic_leases": 1,
}
EXPERIMENT_IDS: Final = frozenset(
    {
        "STAGE1-FREEZE",
        "BOARD-ACCEPT",
        "HARD-BASELINE",
        "FIX-1",
        "FIX-2",
        "FIX-3",
        "RTE-MIXED",
        "RTE-DAYBREAK",
        "RTE-OPTIONAL-STAGE-CATEGORY",
        "HELDOUT-CONFIRM",
        "FINAL-CAPACITY",
    }
)
EXPERIMENT_NUMERICS: Final = {
    "STAGE1-FREEZE": (1, "mandatory", 2700, 0, 0, 0, 0, 0),
    "BOARD-ACCEPT": (2, "mandatory", 1800, 800, 3, 1_000_000, 50_000, 30_000),
    "HARD-BASELINE": (4, "mandatory", 3600, 800, 3, 20_000_000, 1_000_000, 600_000),
    "FIX-1": (5, "conditional", 2700, 800, 3, 12_000_000, 600_000, 360_000),
    "FIX-2": (5, "conditional", 2700, 800, 3, 12_000_000, 600_000, 360_000),
    "FIX-3": (5, "conditional", 2700, 800, 3, 12_000_000, 600_000, 360_000),
    "RTE-MIXED": (6, "mandatory", 2700, 800, 3, 15_000_000, 750_000, 450_000),
    "RTE-DAYBREAK": (6, "mandatory", 2700, 800, 3, 15_000_000, 750_000, 450_000),
    "RTE-OPTIONAL-STAGE-CATEGORY": (
        6,
        "conditional",
        2700,
        800,
        3,
        15_000_000,
        750_000,
        450_000,
    ),
    "HELDOUT-CONFIRM": (7, "mandatory", 4500, 800, 3, 25_000_000, 1_250_000, 750_000),
    "FINAL-CAPACITY": (8, "mandatory", 19_800, 800, 3, 100_000_000, 5_000_000, 3_000_000),
}
SENTINEL_IDS: Final = frozenset(f"EAS-00{index}" for index in range(1, 7))
MODEL_ALIASES: Final = frozenset({"DAYBREAK_XHIGH", "LUNA_MAX", "LUNA_XHIGH"})
MODEL_DESCRIPTOR_PAIRS: Final = {
    "DAYBREAK_XHIGH": ("gpt-daybreak-blue-latest", "xhigh"),
    "LUNA_MAX": ("gpt-5.6-luna", "max"),
    "LUNA_XHIGH": ("gpt-5.6-luna", "xhigh"),
}
MIXED_LANES: Final = (
    "DAYBREAK_XHIGH",
    "DAYBREAK_XHIGH",
    "LUNA_MAX",
    "LUNA_XHIGH",
)
DAYBREAK_LANES: Final = ("DAYBREAK_XHIGH",) * 4
ROUTING_CONTRACTS: Final = {
    "STAGE1-FREEZE": (("preflight_v1", MIXED_LANES),),
    "BOARD-ACCEPT": (("mixed_v1", MIXED_LANES),),
    "HARD-BASELINE": (("mixed_v1", MIXED_LANES),),
    "FIX-1": (("mixed_v1", MIXED_LANES),),
    "FIX-2": (("mixed_v1", MIXED_LANES),),
    "FIX-3": (("mixed_v1", MIXED_LANES),),
    "RTE-MIXED": (("rte_mixed_v1", MIXED_LANES),),
    "RTE-DAYBREAK": (("rte_daybreak_v1", DAYBREAK_LANES),),
    "RTE-OPTIONAL-STAGE-CATEGORY": (("rte_optional_stage_category_v1", MIXED_LANES),),
    "HELDOUT-CONFIRM": (
        ("selected_mixed_v1", MIXED_LANES),
        ("selected_daybreak_v1", DAYBREAK_LANES),
    ),
    "FINAL-CAPACITY": (
        ("selected_mixed_v1", MIXED_LANES),
        ("selected_daybreak_v1", DAYBREAK_LANES),
    ),
}
EXPERIMENT_DENOMINATOR_CONTRACTS: Final = {
    "STAGE1-FREEZE": (0, 0, None, 0, 0),
    "BOARD-ACCEPT": (0, 0, None, 0, 0),
    "HARD-BASELINE": (12, 18, "CAL-", 4, 4),
    "FIX-1": (1, 72, "FX-", 1, 1),
    "FIX-2": (1, 72, "FX-", 1, 1),
    "FIX-3": (1, 72, "FX-", 1, 1),
    "RTE-MIXED": (18, 18, "RTE-", 9, 4),
    "RTE-DAYBREAK": (18, 18, "RTE-", 9, 4),
    "RTE-OPTIONAL-STAGE-CATEGORY": (1, 18, "RTE-", 1, 1),
    "HELDOUT-CONFIRM": (18, 18, "HLD-", 9, 4),
    "FINAL-CAPACITY": (83, 720, "RES-", 9, 5),
}
SCORE_AXES: Final = (
    "raw_oracle_correctness",
    "fresh_family_capability",
    "qualification_projection",
    "actual_independent_verification",
    "elapsed_and_time_to_first_correct",
    "provider_usage",
    "tool_behavior",
    "resource_lifecycle",
    "ecological_lane",
    "transformation_lane",
)
ASSIGNMENT_COUNTS: Final = {
    "sentinel": 6,
    "calibration": 18,
    "focused-sibling": 72,
    "routing": 36,
    "heldout": 18,
    "capacity-reserve": 720,
}
RESOURCE_CONTRACT: Final = {
    "controller": {"cpu": 8, "ram_gib": 16, "pids": 512, "run_root_gib": 64},
    "dynamic_service": {"cpu": 1, "ram_gib": 2, "pids": 128, "network": "isolated_internal_only"},
    "hostile_worker": {
        "cpu": 2,
        "ram_gib": 6,
        "pids": 256,
        "network": "none",
        "command_seconds": 120,
    },
    "task_capsule": {"download_mib": 128, "unpacked_gib": 1},
}
FORBIDDEN_PUBLIC_FIELDS: Final = (
    "candidate_value",
    "candidate_digest",
    "answer",
    "oracle_key",
    "credential",
    "target_authority",
    "host_path",
    "raw_private_payload",
    "raw_model_output",
    "raw_tool_payload",
)
SCORED_RUNNER_EXCLUSIONS: Final = (
    "repository_history",
    "solutions",
    "writeups",
    "attempt_trees",
    "prior_candidates",
    "reference_corpus",
    "generator_seed",
    "checker_source",
    "oracle_key",
    "arbitrary_egress",
)
TERMINAL_LABELS: Final = frozenset(
    {
        "correct",
        "incorrect",
        "already_terminal",
        "unstarted_at_cap",
        "queued_at_cap",
        "attempt_timeout",
        "global_cap",
        "no_unique_candidate",
        "repeated_candidate_only",
        "no_new_durable_observation",
        "tool_absent",
        "dependency_absent",
        "unsupported_format",
        "parser_failure",
        "tool_argument_schema",
        "tool_runtime",
        "sandbox_failure",
        "policy_refusal",
        "context_loss",
        "method_replay_failure",
        "oracle_inconclusive",
        "provider_unavailable",
        "provider_failure",
        "descriptor_mismatch",
        "usage_cap",
        "service_start_failure",
        "service_unready",
        "service_lost",
        "cleanup_failure",
        "privacy_boundary",
        "source_drift",
        "fixture_invalid",
    }
)
TOOL_FAILURE_LABELS: Final = frozenset(
    {
        "tool_absent",
        "dependency_absent",
        "unsupported_format",
        "parser_failure",
        "tool_argument_schema",
        "tool_runtime",
        "sandbox_failure",
        "policy_refusal",
        "context_loss",
    }
)
PROVIDER_ATTEMPT_STATUSES: Final = frozenset(
    {
        "completed",
        "provider_failure",
        "provider_unavailable",
        "descriptor_mismatch",
        "cancelled",
    }
)

_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TASK_ID = re.compile(r"[A-Z0-9-]{3,80}\Z")
_FORBIDDEN_KEYS = frozenset(
    {
        "answer",
        "expected_answer",
        "flag",
        "candidate_value",
        "candidate_hash",
        "candidate_digest",
        "answer_digest",
        "oracle_key",
        "credential",
        "api_key",
        "access_token",
        "refresh_token",
        "secret",
        "target_authority",
        "host_path",
        "raw_private_payload",
        "raw_model_output",
        "raw_tool_payload",
    }
)
_FORBIDDEN_VALUE = re.compile(
    r"(?:INCYPHER\{|flag\{|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"(?:https?|wss?)://|\b(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?\b|"
    r"(?<![A-Za-z0-9])(?:~|\$HOME)/[^\s>`'\"]+|"
    r"(?<![<A-Za-z0-9])/(?!/)[^\s>`'\"]+|"
    r"(?:^|\s)[A-Za-z]:[\\/][^\s>`'\"]+|(?:^|\s)(?:\\\\|//)[^\s>`'\"]+|"
    r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?::[0-9]{2,5})?\b|"
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{2,5})?\b)",
    re.IGNORECASE,
)


class CapabilitySchemaError(ValueError):
    """A public registration or receipt violates the frozen contract."""


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CapabilitySchemaError(f"{label} must be an object")
    return value


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise CapabilitySchemaError(f"{label} must be an array")
    return value


def _exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    observed = set(value)
    if observed != expected:
        raise CapabilitySchemaError(
            f"{label} fields mismatch: missing={sorted(expected - observed)}, "
            f"extra={sorted(observed - expected)}"
        )


def _nonnegative_integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise CapabilitySchemaError(f"{label} must be a nonnegative integer")
    return value


def _nullable_nonnegative_integer(value: Any, label: str) -> None:
    if value is not None:
        _nonnegative_integer(value, label)


def _validate_usage(value: Any, label: str) -> None:
    usage = _mapping(value, label)
    _exact_fields(usage, {"input", "cached_input", "output", "reasoning"}, label)
    for field in usage:
        _nullable_nonnegative_integer(usage[field], f"{label}.{field}")


def _validate_resources(value: Any, label: str) -> None:
    resources = _mapping(value, label)
    _exact_fields(
        resources,
        {
            "cpu_peak_cores",
            "memory_peak_bytes",
            "pids_peak",
            "disk_peak_bytes",
            "unavailable_reason",
        },
        label,
    )
    cpu = resources["cpu_peak_cores"]
    if cpu is not None and (isinstance(cpu, bool) or not isinstance(cpu, (int, float)) or cpu < 0):
        raise CapabilitySchemaError(f"{label}.cpu_peak_cores must be nonnegative or null")
    for field in ("memory_peak_bytes", "pids_peak", "disk_peak_bytes"):
        _nullable_nonnegative_integer(resources[field], f"{label}.{field}")
    reason = resources["unavailable_reason"]
    if reason is not None and (
        not isinstance(reason, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", reason)
    ):
        raise CapabilitySchemaError(f"{label}.unavailable_reason is invalid")
    observed = (
        resources["cpu_peak_cores"],
        resources["memory_peak_bytes"],
        resources["pids_peak"],
        resources["disk_peak_bytes"],
    )
    if (any(value is None for value in observed)) is not (reason is not None):
        raise CapabilitySchemaError(f"{label} null resource sample/reason mismatch")


def _public_scan(value: Any, where: str = "root") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in _FORBIDDEN_KEYS:
                raise CapabilitySchemaError(f"forbidden public key at {where}")
            _public_scan(item, f"{where}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _public_scan(item, f"{where}[{index}]")
    elif isinstance(value, str):
        try:
            ipv6_authority = (
                ipaddress.ip_address(value.removeprefix("[").removesuffix("]")).version == 6
            )
        except ValueError:
            ipv6_authority = False
        if _FORBIDDEN_VALUE.search(value) or ipv6_authority:
            raise CapabilitySchemaError(f"forbidden public value at {where}")


def validate_registration(document: Mapping[str, Any]) -> None:
    """Validate the immutable public experiment registry."""

    root = _mapping(document, "registration")
    _exact_fields(
        root,
        {
            "schema",
            "prepared_date",
            "registration_state",
            "authority",
            "source",
            "runtime",
            "scheduler",
            "models",
            "task_manifest",
            "experiments",
            "score_axes",
            "terminal_labels",
            "resources",
            "privacy",
            "cleanup",
            "source_delta",
        },
        "registration",
    )
    if root["schema"] != REGISTRATION_SCHEMA or root["registration_state"] != "frozen_pre_outcome":
        raise CapabilitySchemaError("registration identity or state is invalid")
    if root["prepared_date"] != "2026-09-20":
        raise CapabilitySchemaError("registration prepared date is invalid")

    authority = _mapping(root["authority"], "authority")
    _exact_fields(
        authority,
        {
            "capability_handoff_sha256",
            "candidate_manifest_sha256",
            "handoff_validation",
            "locked_facts_policy",
            "urgent_handoff_sha256",
        },
        "authority",
    )
    for field in (
        "capability_handoff_sha256",
        "candidate_manifest_sha256",
        "urgent_handoff_sha256",
    ):
        if not isinstance(authority[field], str) or not _SHA256.fullmatch(authority[field]):
            raise CapabilitySchemaError(f"authority.{field} is invalid")
    if authority["handoff_validation"] != "passed":
        raise CapabilitySchemaError("handoff validation must pass")
    if authority["locked_facts_policy"] != "R7_and_H24_not_rerun_or_regraded":
        raise CapabilitySchemaError("locked facts policy changed")

    source = _mapping(root["source"], "source")
    _exact_fields(
        source,
        {
            "base_sha",
            "dirty",
            "dockerfile_sha256",
            "offline_eval_dockerfile_sha256",
            "origin_main_sha",
            "source_archive_sha256",
            "tool_acceptance_sha256",
        },
        "source",
    )
    for field in ("base_sha", "origin_main_sha"):
        if not isinstance(source.get(field), str) or not _SHA40.fullmatch(source[field]):
            raise CapabilitySchemaError(f"source.{field} is invalid")
    for field in (
        "source_archive_sha256",
        "dockerfile_sha256",
        "offline_eval_dockerfile_sha256",
        "tool_acceptance_sha256",
    ):
        if not isinstance(source.get(field), str) or not _SHA256.fullmatch(source[field]):
            raise CapabilitySchemaError(f"source.{field} is invalid")
    if source.get("base_sha") != source.get("origin_main_sha") or source.get("dirty") is not False:
        raise CapabilitySchemaError("source must bind clean refreshed main")

    runtime = _mapping(root["runtime"], "runtime")
    _exact_fields(
        runtime,
        {
            "descriptor_preflight_passed",
            "host_native_client",
            "image_id",
            "image_native_client",
            "platform",
            "tool_acceptance_identity",
        },
        "runtime",
    )
    if not isinstance(runtime.get("image_id"), str) or not _IMAGE.fullmatch(runtime["image_id"]):
        raise CapabilitySchemaError("runtime.image_id is invalid")
    if runtime.get("descriptor_preflight_passed") is not True:
        raise CapabilitySchemaError("descriptor preflight must pass")
    if runtime.get("platform") != "linux/arm64":
        raise CapabilitySchemaError("runtime platform changed")

    scheduler = _mapping(root["scheduler"], "scheduler")
    _exact_fields(scheduler, set(SCHEDULER_CONTRACT), "scheduler")
    if scheduler != SCHEDULER_CONTRACT:
        raise CapabilitySchemaError("registration scheduler contract changed")

    models = _mapping(root["models"], "models")
    if set(models) != MODEL_ALIASES:
        raise CapabilitySchemaError("model alias set is invalid")
    for alias, expected in MODEL_DESCRIPTOR_PAIRS.items():
        row = _mapping(models[alias], f"models.{alias}")
        _exact_fields(
            row,
            {
                "effective_model",
                "fallback",
                "requested_effort",
                "requested_model",
                "supported_efforts",
            },
            f"models.{alias}",
        )
        if (row.get("requested_model"), row.get("requested_effort")) != expected:
            raise CapabilitySchemaError(f"model descriptor changed for {alias}")
        if row.get("effective_model") != expected[0] or row.get("fallback") != "forbidden":
            raise CapabilitySchemaError(f"model preflight mismatch for {alias}")
        supported = _sequence(row["supported_efforts"], f"models.{alias}.supported_efforts")
        if expected[1] not in supported or len(supported) != len(set(supported)):
            raise CapabilitySchemaError(f"model effort catalogue is invalid for {alias}")

    manifest = _mapping(root["task_manifest"], "task_manifest")
    _exact_fields(
        manifest,
        {
            "assignment_counts",
            "assignment_freeze",
            "candidate_manifest_sha256",
            "family_count",
            "generator_checker_versions",
            "sentinel_ids",
            "sentinel_tier",
            "status",
            "task_count",
        },
        "task_manifest",
    )
    if manifest.get("task_count") != sum(ASSIGNMENT_COUNTS.values()):
        raise CapabilitySchemaError("task manifest count is invalid")
    if manifest.get("assignment_counts") != ASSIGNMENT_COUNTS:
        raise CapabilitySchemaError("task assignment counts are invalid")
    sentinel_ids = _sequence(manifest.get("sentinel_ids"), "sentinel_ids")
    if set(sentinel_ids) != SENTINEL_IDS or len(sentinel_ids) != len(SENTINEL_IDS):
        raise CapabilitySchemaError("sentinel ID set is invalid")
    if manifest.get("sentinel_tier") != "sentinel":
        raise CapabilitySchemaError("sentinels must not enter the difficult Tier A denominator")
    if (
        manifest.get("family_count") != 12
        or manifest.get("status") != "planned_not_admitted"
        or manifest.get("assignment_freeze")
        != "full_private_manifest_committed_before_relevant_outcome"
        or manifest.get("generator_checker_versions")
        != "private-unassigned-v1_until_family_admission"
    ):
        raise CapabilitySchemaError("task manifest freeze semantics changed")
    if not isinstance(manifest.get("candidate_manifest_sha256"), str) or not _SHA256.fullmatch(
        manifest["candidate_manifest_sha256"]
    ):
        raise CapabilitySchemaError("candidate manifest commitment is invalid")

    experiments = _sequence(root["experiments"], "experiments")
    experiment_ids: list[str] = []
    required_fields = {
        "experiment_id",
        "stage",
        "status",
        "tasks",
        "per_task_budget",
        "wall_cap_seconds",
        "usage_budget",
        "model_policy",
        "checker_policy",
        "denominator",
        "stop_rule",
        "decision_rule",
    }
    for raw in experiments:
        row = _mapping(raw, "experiment")
        _exact_fields(row, required_fields, f"experiment {row.get('experiment_id')}")
        experiment_id = row.get("experiment_id")
        if not isinstance(experiment_id, str):
            raise CapabilitySchemaError("experiment ID is invalid")
        experiment_ids.append(experiment_id)
        if type(row.get("stage")) is not int or not 1 <= row["stage"] <= 8:
            raise CapabilitySchemaError(f"experiment stage is invalid: {experiment_id}")
        wall = row.get("wall_cap_seconds")
        if type(wall) is not int or wall < 1 or wall > 19_800:
            raise CapabilitySchemaError(f"experiment wall cap is invalid: {experiment_id}")
        budget = _mapping(row.get("per_task_budget"), f"{experiment_id}.per_task_budget")
        if set(budget) != {"attempt_seconds", "scored_episodes"}:
            raise CapabilitySchemaError(f"experiment task budget is incomplete: {experiment_id}")
        for field in budget:
            _nonnegative_integer(budget[field], f"{experiment_id}.per_task_budget.{field}")
        if budget["attempt_seconds"] > 7200 or budget["scored_episodes"] > 8:
            raise CapabilitySchemaError(f"experiment task budget is out of range: {experiment_id}")
        task_names = _sequence(row.get("tasks"), f"{experiment_id}.tasks")
        if experiment_id != "STAGE1-FREEZE" and not task_names:
            raise CapabilitySchemaError(f"experiment task set is empty: {experiment_id}")
        if any(not isinstance(name, str) or not name for name in task_names):
            raise CapabilitySchemaError(f"experiment task reference is invalid: {experiment_id}")
        usage = _mapping(row.get("usage_budget"), f"{experiment_id}.usage_budget")
        _exact_fields(
            usage,
            {"cached_input", "input_cap", "null_policy", "output_cap", "reasoning_cap"},
            f"{experiment_id}.usage_budget",
        )
        for field in ("input_cap", "output_cap", "reasoning_cap"):
            _nonnegative_integer(usage[field], f"{experiment_id}.usage_budget.{field}")
        if (
            usage["cached_input"] != "reported_separately"
            or usage["null_policy"] != "preserve_null"
        ):
            raise CapabilitySchemaError(f"experiment usage semantics changed: {experiment_id}")
        expected_numeric = EXPERIMENT_NUMERICS.get(experiment_id)
        observed_numeric = (
            row["stage"],
            row["status"],
            row["wall_cap_seconds"],
            budget["attempt_seconds"],
            budget["scored_episodes"],
            usage["input_cap"],
            usage["output_cap"],
            usage["reasoning_cap"],
        )
        if observed_numeric != expected_numeric:
            raise CapabilitySchemaError(f"experiment numeric contract changed: {experiment_id}")
        for field in (
            "model_policy",
            "checker_policy",
            "denominator",
            "stop_rule",
            "decision_rule",
        ):
            if not isinstance(row.get(field), str) or not row[field]:
                raise CapabilitySchemaError(f"experiment {experiment_id} missing {field}")
    if frozenset(experiment_ids) != EXPERIMENT_IDS or len(experiment_ids) != len(EXPERIMENT_IDS):
        raise CapabilitySchemaError("experiment ID set is invalid")
    final = next(row for row in experiments if row["experiment_id"] == "FINAL-CAPACITY")
    if final["wall_cap_seconds"] != 19_800:
        raise CapabilitySchemaError("final capacity wall cap must be 19800 seconds")

    score_axes = _sequence(root["score_axes"], "score_axes")
    if tuple(score_axes) != SCORE_AXES:
        raise CapabilitySchemaError("score axes changed")
    terminal_labels = _sequence(root["terminal_labels"], "terminal_labels")
    if frozenset(terminal_labels) != TERMINAL_LABELS or len(terminal_labels) != len(
        TERMINAL_LABELS
    ):
        raise CapabilitySchemaError("terminal label set is invalid")

    resources = _mapping(root["resources"], "resources")
    _exact_fields(
        resources, {"controller", "dynamic_service", "hostile_worker", "task_capsule"}, "resources"
    )
    expected_resource_fields = {name: set(values) for name, values in RESOURCE_CONTRACT.items()}
    for name, fields in expected_resource_fields.items():
        values = _mapping(resources[name], f"resources.{name}")
        _exact_fields(values, fields, f"resources.{name}")
        for field, value in values.items():
            if field != "network":
                _nonnegative_integer(value, f"resources.{name}.{field}")
    if resources != RESOURCE_CONTRACT:
        raise CapabilitySchemaError("registration resource contract changed")

    privacy = _mapping(root["privacy"], "privacy")
    _exact_fields(
        privacy,
        {
            "candidate_public_identity",
            "forbidden_public_fields",
            "path_classes",
            "production_board_access",
            "scored_runner_exclusions",
        },
        "privacy",
    )
    if (
        privacy["candidate_public_identity"] != "ordinal_only"
        or privacy["production_board_access"] != "forbidden"
        or tuple(privacy["forbidden_public_fields"]) != FORBIDDEN_PUBLIC_FIELDS
        or tuple(privacy["scored_runner_exclusions"]) != SCORED_RUNNER_EXCLUSIONS
        or tuple(privacy["path_classes"])
        != (
            "private_curator_root",
            "private_runner_root",
            "private_oracle_root",
            "private_output_root",
        )
    ):
        raise CapabilitySchemaError("registration privacy boundary changed")

    cleanup = _mapping(root["cleanup"], "cleanup")
    _exact_fields(
        cleanup,
        {"inventory", "outer_grace_seconds", "private_parent_preflight", "settlement_seconds"},
        "cleanup",
    )
    if (
        set(_sequence(cleanup["inventory"], "cleanup.inventory"))
        != {
            "processes",
            "containers",
            "volumes",
            "networks",
            "workspaces",
            "services",
            "state_objects",
            "run_ids",
        }
        or cleanup["outer_grace_seconds"] != 190
        or cleanup["settlement_seconds"] != 180
        or cleanup["private_parent_preflight"] != "passed"
    ):
        raise CapabilitySchemaError("registration cleanup contract changed")

    source_delta = _mapping(root["source_delta"], "source_delta")
    _exact_fields(
        source_delta,
        {
            "design_local_checkout_used",
            "design_remote_main_matches_expected",
            "historical_remote_main_matches_expected",
            "rapido_main_moved",
            "runtime_delta",
        },
        "source_delta",
    )
    if (
        source_delta["design_local_checkout_used"] is not False
        or source_delta["design_remote_main_matches_expected"] is not True
        or source_delta["historical_remote_main_matches_expected"] is not True
        or source_delta["rapido_main_moved"] is not False
        or not isinstance(source_delta["runtime_delta"], str)
        or not source_delta["runtime_delta"]
    ):
        raise CapabilitySchemaError("source delta is invalid")
    _public_scan(root)
    canonical = json.dumps(root, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if hashlib.sha256(canonical).hexdigest() != REGISTRATION_CANONICAL_SHA256:
        raise CapabilitySchemaError("registration canonical commitment changed")


def validate_task_manifest(document: Mapping[str, Any]) -> None:
    """Validate the private, pre-outcome task-assignment manifest without exposing its rows."""

    root = _mapping(document, "task manifest")
    if root.get("schema") != TASK_MANIFEST_SCHEMA:
        raise CapabilitySchemaError("task manifest identity is invalid")
    tasks = [_mapping(row, "task manifest row") for row in _sequence(root.get("tasks"), "tasks")]
    if root.get("task_count") != len(tasks) or len(tasks) != sum(ASSIGNMENT_COUNTS.values()):
        raise CapabilitySchemaError("task manifest row count is invalid")

    task_ids = [row.get("task_id") for row in tasks]
    if any(not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id) for task_id in task_ids):
        raise CapabilitySchemaError("task manifest contains an invalid task ID")
    if len(task_ids) != len(set(task_ids)):
        raise CapabilitySchemaError("task manifest task IDs must be unique")

    observed_assignments = Counter(row.get("assignment") for row in tasks)
    if (
        dict(observed_assignments) != ASSIGNMENT_COUNTS
        or root.get("assignment_counts") != ASSIGNMENT_COUNTS
    ):
        raise CapabilitySchemaError("task manifest assignment counts are invalid")
    sentinel_rows = [row for row in tasks if row.get("assignment") == "sentinel"]
    if {row.get("task_id") for row in sentinel_rows} != SENTINEL_IDS:
        raise CapabilitySchemaError("task manifest sentinel assignment is invalid")

    families = [_mapping(row, "family") for row in _sequence(root.get("families"), "families")]
    family_ids = [row.get("family_id") for row in families]
    if (
        root.get("family_count") != len(families)
        or len(family_ids) != len(set(family_ids))
        or any(not isinstance(family_id, str) or not family_id for family_id in family_ids)
    ):
        raise CapabilitySchemaError("task manifest family set is invalid")
    if any(
        row.get("assignment") != "sentinel" and row.get("family_id") not in set(family_ids)
        for row in tasks
    ):
        raise CapabilitySchemaError("task manifest references an unknown family")


def validate_receipt(document: Mapping[str, Any]) -> None:
    """Validate one sanitized receipt, including exact-set and aggregate invariants."""

    root = _mapping(document, "receipt")
    _public_scan(root)
    required = {
        "schema",
        "run_id",
        "experiment_id",
        "source",
        "configuration",
        "denominator",
        "tasks",
        "time_series",
        "sentinels",
        "aggregate",
        "failure_counts",
        "capacity",
        "service_attempts",
        "classification",
        "resources",
        "cleanup",
        "privacy",
        "human_decisions",
    }
    _exact_fields(root, required, "receipt")
    if root["schema"] != RECEIPT_SCHEMA or root["experiment_id"] not in EXPERIMENT_IDS:
        raise CapabilitySchemaError("receipt identity is invalid")

    run_id = root["run_id"]
    if not isinstance(run_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", run_id):
        raise CapabilitySchemaError("receipt run ID is invalid")
    source = _mapping(root["source"], "source")
    _exact_fields(
        source,
        {"sha", "image_id", "dirty", "registration_sha256", "task_manifest_sha256"},
        "source",
    )
    if (
        source["sha"] != SOURCE_SHA
        or source["image_id"] != SOURCE_IMAGE_ID
        or source["registration_sha256"] != REGISTRATION_CANONICAL_SHA256
        or source["task_manifest_sha256"] != TASK_MANIFEST_SHA256
        or source["dirty"] is not False
    ):
        raise CapabilitySchemaError("receipt source identity contradicts the frozen registration")

    configuration = _mapping(root["configuration"], "configuration")
    _exact_fields(
        configuration,
        {
            "routing_profile",
            "requested_descriptors",
            "lane_descriptors",
            "effective_descriptors_match",
            "active_challenges",
            "lane_admissions",
            "dynamic_leases",
            "attempt_seconds",
            "episodes_per_task",
            "wall_cap_seconds",
            "usage_caps",
        },
        "configuration",
    )
    if not isinstance(configuration["routing_profile"], str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9_-]{0,79}", configuration["routing_profile"]
    ):
        raise CapabilitySchemaError("configuration routing profile is invalid")
    descriptors = _sequence(configuration["requested_descriptors"], "requested_descriptors")
    if (
        not descriptors
        or len(descriptors) > 8
        or any(item not in MODEL_ALIASES for item in descriptors)
    ):
        raise CapabilitySchemaError("configuration model descriptors are invalid")
    lane_descriptors = _sequence(configuration["lane_descriptors"], "lane_descriptors")
    if (
        not lane_descriptors
        or len(lane_descriptors) > 64
        or any(item not in MODEL_ALIASES for item in lane_descriptors)
        or set(descriptors) != set(lane_descriptors)
        or len(descriptors) != len(set(descriptors))
    ):
        raise CapabilitySchemaError("configuration lane descriptors are invalid")
    routing_contracts = ROUTING_CONTRACTS[root["experiment_id"]]
    observed_routing = (configuration["routing_profile"], tuple(lane_descriptors))
    if observed_routing not in routing_contracts:
        raise CapabilitySchemaError("configuration routing contradicts the frozen experiment")
    expected_requested = {alias for alias in lane_descriptors}
    if set(descriptors) != expected_requested:
        raise CapabilitySchemaError("configuration requested descriptors contradict its lanes")
    if type(configuration["effective_descriptors_match"]) is not bool:
        raise CapabilitySchemaError("configuration descriptor result is invalid")
    for field in (
        "active_challenges",
        "lane_admissions",
        "dynamic_leases",
        "attempt_seconds",
        "episodes_per_task",
        "wall_cap_seconds",
    ):
        _nonnegative_integer(configuration[field], f"configuration.{field}")
    usage_caps = _mapping(configuration["usage_caps"], "configuration.usage_caps")
    _exact_fields(usage_caps, {"input", "output", "reasoning"}, "configuration.usage_caps")
    for field in usage_caps:
        _nonnegative_integer(usage_caps[field], f"configuration.usage_caps.{field}")
    ranges = {
        "active_challenges": (1, 8),
        "lane_admissions": (1, 64),
        "dynamic_leases": (0, 1),
        "attempt_seconds": (1, 7200),
        "episodes_per_task": (1, 8),
        "wall_cap_seconds": (1, 19_800),
    }
    if any(
        not minimum <= configuration[field] <= maximum
        for field, (minimum, maximum) in ranges.items()
    ):
        raise CapabilitySchemaError("configuration value is outside its registered bound")
    if any(configuration[field] != value for field, value in SCHEDULER_CONTRACT.items()):
        raise CapabilitySchemaError("configuration scheduler contradicts the frozen registration")
    experiment_numeric = EXPERIMENT_NUMERICS[root["experiment_id"]]
    expected_configuration = {
        "wall_cap_seconds": experiment_numeric[2],
        "attempt_seconds": experiment_numeric[3],
        "episodes_per_task": experiment_numeric[4],
        "input": experiment_numeric[5],
        "output": experiment_numeric[6],
        "reasoning": experiment_numeric[7],
    }
    if (
        configuration["wall_cap_seconds"] != expected_configuration["wall_cap_seconds"]
        or configuration["attempt_seconds"] != expected_configuration["attempt_seconds"]
        or configuration["episodes_per_task"] != expected_configuration["episodes_per_task"]
        or usage_caps
        != {
            "input": expected_configuration["input"],
            "output": expected_configuration["output"],
            "reasoning": expected_configuration["reasoning"],
        }
    ):
        raise CapabilitySchemaError("receipt configuration contradicts the frozen experiment")

    denominator = _mapping(root["denominator"], "denominator")
    _exact_fields(
        denominator,
        {"task_count", "difficult_count", "family_count", "category_count", "task_ids"},
        "denominator",
    )
    task_ids = list(_sequence(denominator.get("task_ids"), "denominator.task_ids"))
    if not task_ids or len(task_ids) != len(set(task_ids)):
        raise CapabilitySchemaError("denominator task IDs must be nonempty and unique")
    if any(not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id) for task_id in task_ids):
        raise CapabilitySchemaError("denominator task ID is invalid")
    if denominator.get("task_count") != len(task_ids):
        raise CapabilitySchemaError("denominator task count mismatch")

    tasks = list(_sequence(root["tasks"], "tasks"))
    rows = [_mapping(row, "task") for row in tasks]
    all_provider_attempts: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    all_candidate_checks: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    all_tool_attempts: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    all_independent_verifications: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    task_fields = {
        "task_id",
        "family_id",
        "category",
        "tier",
        "started",
        "admitted_ms",
        "started_ms",
        "first_unique_candidate_ms",
        "first_correct_ms",
        "terminal_ms",
        "terminal_label",
        "raw_correct",
        "qualification",
        "qualification_ms",
        "qualification_rejection_stage",
        "independent_check",
        "independent_verification",
        "candidate_unique_count",
        "candidate_repeat_count",
        "checker_call_count",
        "provider_invocation_count",
        "provider_failure_count",
        "provider_attempts",
        "candidate_checks",
        "checker_version",
        "usage",
        "resources",
        "tool_call_count",
        "tool_attempts",
        "tool_failure_labels",
        "cleanup_passed",
    }
    for index, row in enumerate(rows):
        label = f"tasks[{index}]"
        _exact_fields(row, task_fields, label)
        for field in ("family_id", "category"):
            if not isinstance(row[field], str) or not row[field]:
                raise CapabilitySchemaError(f"{label}.{field} is invalid")
        if row["tier"] not in {"A", "B", "C", "sentinel"} or type(row["started"]) is not bool:
            raise CapabilitySchemaError(f"{label} tier or started state is invalid")
        if row["raw_correct"] is not None and type(row["raw_correct"]) is not bool:
            raise CapabilitySchemaError(f"{label}.raw_correct is invalid")
        if row["terminal_label"] is not None and row["terminal_label"] not in TERMINAL_LABELS:
            raise CapabilitySchemaError(f"{label} terminal label is invalid")
        for field in (
            "candidate_unique_count",
            "candidate_repeat_count",
            "checker_call_count",
            "provider_invocation_count",
            "provider_failure_count",
            "tool_call_count",
        ):
            _nonnegative_integer(row[field], f"{label}.{field}")
        if row["started"] is False and row["raw_correct"] is not None:
            raise CapabilitySchemaError(f"{label} cannot be correct without starting")
        for field in (
            "admitted_ms",
            "started_ms",
            "first_unique_candidate_ms",
            "first_correct_ms",
            "qualification_ms",
            "terminal_ms",
        ):
            _nullable_nonnegative_integer(row[field], f"{label}.{field}")
        observed_times = [
            row[field]
            for field in (
                "admitted_ms",
                "started_ms",
                "first_unique_candidate_ms",
                "first_correct_ms",
                "qualification_ms",
                "terminal_ms",
            )
            if row[field] is not None
        ]
        if observed_times != sorted(observed_times):
            raise CapabilitySchemaError(f"{label} lifecycle offsets are out of order")
        if row["started"] is True and (row["admitted_ms"] is None or row["started_ms"] is None):
            raise CapabilitySchemaError(f"{label} started without admission/start offsets")
        if row["terminal_label"] is None:
            raise CapabilitySchemaError(f"{label} final receipt lacks a terminal label")
        if row["candidate_unique_count"] > 0 and row["first_unique_candidate_ms"] is None:
            raise CapabilitySchemaError(f"{label} unique candidate lacks an offset")
        if row["candidate_unique_count"] == 0 and row["first_unique_candidate_ms"] is not None:
            raise CapabilitySchemaError(f"{label} candidate offset exists without a candidate")
        if (row["raw_correct"] is True) is not (row["first_correct_ms"] is not None):
            raise CapabilitySchemaError(f"{label} raw result and first-correct offset disagree")
        if row["raw_correct"] is True and row["candidate_unique_count"] == 0:
            raise CapabilitySchemaError(f"{label} correct result lacks a unique candidate")
        if (row["terminal_label"] == "correct") is not (row["raw_correct"] is True):
            raise CapabilitySchemaError(f"{label} correct terminal and raw result disagree")
        if (row["terminal_label"] is None) is not (row["terminal_ms"] is None):
            raise CapabilitySchemaError(f"{label} terminal label and offset disagree")
        for field in (
            "checker_version",
            "qualification_rejection_stage",
        ):
            if row[field] is not None and (not isinstance(row[field], str) or not row[field]):
                raise CapabilitySchemaError(f"{label}.{field} is invalid")
        if row["cleanup_passed"] is not None and type(row["cleanup_passed"]) is not bool:
            raise CapabilitySchemaError(f"{label}.cleanup_passed is invalid")
        if row["started"] is True and row["cleanup_passed"] is None:
            raise CapabilitySchemaError(f"{label} started without a cleanup result")
        if row["terminal_label"] == "cleanup_failure" and row["cleanup_passed"] is not False:
            raise CapabilitySchemaError(f"{label} cleanup terminal lacks matching evidence")
        if row["qualification"] not in {"accepted", "rejected", "not_applicable", "inconclusive"}:
            raise CapabilitySchemaError(f"{label}.qualification is invalid")
        if (row["qualification"] in {"accepted", "rejected"}) is not (
            row["qualification_ms"] is not None
        ):
            raise CapabilitySchemaError(f"{label} qualification offset is inconsistent")
        if row["independent_check"] not in {"correct", "incorrect", "inconclusive", "not_invoked"}:
            raise CapabilitySchemaError(f"{label}.independent_check is invalid")
        independent_verification = row["independent_verification"]
        if row["independent_check"] == "not_invoked":
            if independent_verification is not None:
                raise CapabilitySchemaError(f"{label} has uninvoked independent evidence")
        else:
            verification = _mapping(independent_verification, f"{label}.independent_verification")
            _exact_fields(
                verification,
                {"started_ms", "ended_ms", "result", "method_version"},
                f"{label}.independent_verification",
            )
            verification_started = _nonnegative_integer(
                verification["started_ms"], f"{label}.independent_verification.started_ms"
            )
            verification_ended = _nonnegative_integer(
                verification["ended_ms"], f"{label}.independent_verification.ended_ms"
            )
            if verification_ended < verification_started:
                raise CapabilitySchemaError(f"{label} independent offsets are out of order")
            if verification["result"] != row["independent_check"]:
                raise CapabilitySchemaError(f"{label} independent result contradicts its evidence")
            if row["started_ms"] is not None and verification_started < row["started_ms"]:
                raise CapabilitySchemaError(f"{label} independent check precedes task lifecycle")
            if row["terminal_ms"] is not None and verification_ended > row["terminal_ms"]:
                raise CapabilitySchemaError(f"{label} independent check exceeds task lifecycle")
            if not isinstance(verification["method_version"], str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,119}", verification["method_version"]
            ):
                raise CapabilitySchemaError(f"{label} independent method version is invalid")
            all_independent_verifications.append((row, verification))
        if row["checker_version"] is None:
            raise CapabilitySchemaError(f"{label} checker version is missing")
        if row["provider_failure_count"] > row["provider_invocation_count"]:
            raise CapabilitySchemaError(f"{label} provider failures exceed invocations")
        _validate_usage(row["usage"], f"{label}.usage")
        attempts = [
            _mapping(item, f"{label}.provider_attempts")
            for item in _sequence(row["provider_attempts"], f"{label}.provider_attempts")
        ]
        attempt_fields = {
            "ordinal",
            "lane",
            "requested_model",
            "requested_effort",
            "effective_model",
            "effective_effort",
            "effective_revision_build",
            "native_client_version",
            "status",
            "started_ms",
            "ended_ms",
            "usage",
        }
        for attempt_index, attempt in enumerate(attempts, start=1):
            attempt_label = f"{label}.provider_attempts[{attempt_index - 1}]"
            _exact_fields(attempt, attempt_fields, attempt_label)
            if attempt["ordinal"] != attempt_index:
                raise CapabilitySchemaError(f"{attempt_label} ordinal is invalid")
            lane = _nonnegative_integer(attempt["lane"], f"{attempt_label}.lane")
            if lane >= len(lane_descriptors):
                raise CapabilitySchemaError(f"{attempt_label}.lane is invalid")
            if attempt["requested_model"] not in {"gpt-daybreak-blue-latest", "gpt-5.6-luna"}:
                raise CapabilitySchemaError(f"{attempt_label} requested model is invalid")
            if attempt["requested_effort"] not in {"xhigh", "max"}:
                raise CapabilitySchemaError(f"{attempt_label} requested effort is invalid")
            requested_alias = next(
                (
                    alias
                    for alias, pair in MODEL_DESCRIPTOR_PAIRS.items()
                    if pair == (attempt["requested_model"], attempt["requested_effort"])
                ),
                None,
            )
            if requested_alias != lane_descriptors[lane]:
                raise CapabilitySchemaError(f"{attempt_label} descriptor does not match its lane")
            if (
                attempt["effective_model"] is not None
                and attempt["effective_model"] != attempt["requested_model"]
            ):
                raise CapabilitySchemaError(f"{attempt_label} model fallback is forbidden")
            if (
                attempt["effective_effort"] is not None
                and attempt["effective_effort"] != attempt["requested_effort"]
            ):
                raise CapabilitySchemaError(f"{attempt_label} effort fallback is forbidden")
            revision = attempt["effective_revision_build"]
            client = attempt["native_client_version"]
            for field, value in (
                ("effective_revision_build", revision),
                ("native_client_version", client),
            ):
                if value is not None and (
                    not isinstance(value, str)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:+-]{0,119}", value)
                ):
                    raise CapabilitySchemaError(f"{attempt_label}.{field} is invalid")
            if client is None:
                raise CapabilitySchemaError(f"{attempt_label} native client version is missing")
            if attempt["status"] not in PROVIDER_ATTEMPT_STATUSES:
                raise CapabilitySchemaError(f"{attempt_label} status is invalid")
            started_ms = _nonnegative_integer(attempt["started_ms"], f"{attempt_label}.started_ms")
            ended_ms = _nonnegative_integer(attempt["ended_ms"], f"{attempt_label}.ended_ms")
            if ended_ms < started_ms:
                raise CapabilitySchemaError(f"{attempt_label} offsets are out of order")
            if row["started_ms"] is not None and started_ms < row["started_ms"]:
                raise CapabilitySchemaError(f"{attempt_label} falls outside task lifecycle")
            if row["terminal_ms"] is not None and (
                started_ms > row["terminal_ms"]
                or attempt["status"] != "cancelled"
                and ended_ms > row["terminal_ms"]
            ):
                raise CapabilitySchemaError(f"{attempt_label} falls outside task lifecycle")
            if attempt["status"] == "completed" and (
                attempt["effective_model"] is None
                or attempt["effective_effort"] is None
                or revision is None
            ):
                raise CapabilitySchemaError(
                    f"{attempt_label} completed without an effective descriptor"
                )
            _validate_usage(attempt["usage"], f"{attempt_label}.usage")
            all_provider_attempts.append((row, attempt))
        provider_failures = sum(
            attempt["status"] in {"provider_failure", "provider_unavailable", "descriptor_mismatch"}
            for attempt in attempts
        )
        if row["provider_invocation_count"] != len(attempts):
            raise CapabilitySchemaError(f"{label} provider invocation count mismatch")
        if row["provider_failure_count"] != provider_failures:
            raise CapabilitySchemaError(f"{label} provider failure count mismatch")
        expected_terminal_status = {
            "provider_failure": "provider_failure",
            "provider_unavailable": "provider_unavailable",
            "descriptor_mismatch": "descriptor_mismatch",
        }.get(row["terminal_label"])
        if expected_terminal_status is not None and not any(
            attempt["status"] == expected_terminal_status for attempt in attempts
        ):
            raise CapabilitySchemaError(f"{label} provider terminal lacks matching evidence")
        for usage_field in ("input", "cached_input", "output", "reasoning"):
            attempt_usage = [attempt["usage"][usage_field] for attempt in attempts]
            expected_usage = (
                None if any(value is None for value in attempt_usage) else sum(attempt_usage)
            )
            if row["usage"][usage_field] != expected_usage:
                raise CapabilitySchemaError(f"{label} provider usage aggregation mismatch")
        if row["started"] is False and (
            row["started_ms"] is not None
            or row["first_unique_candidate_ms"] is not None
            or row["first_correct_ms"] is not None
            or row["candidate_unique_count"] != 0
            or row["candidate_repeat_count"] != 0
            or row["checker_call_count"] != 0
            or row["provider_invocation_count"] != 0
            or row["provider_failure_count"] != 0
            or attempts
            or row["candidate_checks"]
            or row["independent_verification"] is not None
            or row["tool_call_count"] != 0
            or row["tool_attempts"]
            or row["cleanup_passed"] is not None
        ):
            raise CapabilitySchemaError(f"{label} unstarted row contains execution evidence")
        _validate_resources(row["resources"], f"{label}.resources")
        failures = _sequence(row["tool_failure_labels"], f"{label}.tool_failure_labels")
        if any(item not in TOOL_FAILURE_LABELS for item in failures):
            raise CapabilitySchemaError(f"{label} tool failure label is invalid")
        candidate_checks = [
            _mapping(item, f"{label}.candidate_checks")
            for item in _sequence(row["candidate_checks"], f"{label}.candidate_checks")
        ]
        candidate_check_fields = {
            "ordinal",
            "candidate_returned_ms",
            "checker_started_ms",
            "checker_ended_ms",
            "result",
        }
        for candidate_index, candidate_check in enumerate(candidate_checks, start=1):
            check_label = f"{label}.candidate_checks[{candidate_index - 1}]"
            _exact_fields(candidate_check, candidate_check_fields, check_label)
            if candidate_check["ordinal"] != candidate_index:
                raise CapabilitySchemaError(f"{check_label} ordinal is invalid")
            returned_ms = _nonnegative_integer(
                candidate_check["candidate_returned_ms"], f"{check_label}.candidate_returned_ms"
            )
            checker_started_ms = _nonnegative_integer(
                candidate_check["checker_started_ms"], f"{check_label}.checker_started_ms"
            )
            checker_ended_ms = _nonnegative_integer(
                candidate_check["checker_ended_ms"], f"{check_label}.checker_ended_ms"
            )
            if not returned_ms <= checker_started_ms <= checker_ended_ms:
                raise CapabilitySchemaError(f"{check_label} offsets are out of order")
            if row["started_ms"] is not None and returned_ms < row["started_ms"]:
                raise CapabilitySchemaError(f"{check_label} precedes the task lifecycle")
            if row["terminal_ms"] is not None and checker_ended_ms > row["terminal_ms"]:
                raise CapabilitySchemaError(f"{check_label} exceeds the task lifecycle")
            if candidate_check["result"] not in {"correct", "incorrect", "inconclusive"}:
                raise CapabilitySchemaError(f"{check_label} result is invalid")
            all_candidate_checks.append((row, candidate_check))
        if len(candidate_checks) != row["candidate_unique_count"] or row[
            "checker_call_count"
        ] != len(candidate_checks):
            raise CapabilitySchemaError(f"{label} checker must run once per unique candidate")
        if (
            candidate_checks
            and row["first_unique_candidate_ms"] != candidate_checks[0]["candidate_returned_ms"]
        ):
            raise CapabilitySchemaError(f"{label} first candidate offset disagrees with checks")
        candidate_return_times = [check["candidate_returned_ms"] for check in candidate_checks]
        if candidate_return_times != sorted(candidate_return_times):
            raise CapabilitySchemaError(f"{label} candidate ordinals are not chronological")
        correct_check_times = [
            check["checker_ended_ms"] for check in candidate_checks if check["result"] == "correct"
        ]
        expected_first_correct = min(correct_check_times) if correct_check_times else None
        if row["first_correct_ms"] != expected_first_correct:
            raise CapabilitySchemaError(f"{label} first-correct offset disagrees with checks")
        terminal_label = row["terminal_label"]
        if terminal_label in {"unstarted_at_cap", "queued_at_cap"} and row["started"] is not False:
            raise CapabilitySchemaError(
                f"{label} unstarted terminal contradicts lifecycle evidence"
            )
        if (
            terminal_label in {"attempt_timeout", "global_cap", "usage_cap"}
            and row["started"] is not True
        ):
            raise CapabilitySchemaError(f"{label} running terminal lacks lifecycle evidence")
        if terminal_label == "incorrect" and not any(
            check["result"] == "incorrect" for check in candidate_checks
        ):
            raise CapabilitySchemaError(f"{label} incorrect terminal lacks checker evidence")
        if terminal_label == "oracle_inconclusive" and not any(
            check["result"] == "inconclusive" for check in candidate_checks
        ):
            raise CapabilitySchemaError(f"{label} oracle terminal lacks checker evidence")
        if terminal_label == "no_unique_candidate" and (
            row["candidate_unique_count"] != 0 or row["candidate_repeat_count"] != 0
        ):
            raise CapabilitySchemaError(f"{label} no-candidate terminal contradicts counts")
        if terminal_label == "repeated_candidate_only" and (
            row["candidate_unique_count"] != 0 or row["candidate_repeat_count"] == 0
        ):
            raise CapabilitySchemaError(f"{label} repeated-only terminal contradicts counts")
        if terminal_label == "method_replay_failure" and row["independent_check"] not in {
            "incorrect",
            "inconclusive",
        }:
            raise CapabilitySchemaError(f"{label} replay terminal lacks independent evidence")

        tool_attempts = [
            _mapping(item, f"{label}.tool_attempts")
            for item in _sequence(row["tool_attempts"], f"{label}.tool_attempts")
        ]
        tool_attempt_fields = {"ordinal", "status", "started_ms", "ended_ms", "failure_label"}
        observed_tool_failures: list[str] = []
        for tool_index, tool_attempt in enumerate(tool_attempts, start=1):
            tool_label = f"{label}.tool_attempts[{tool_index - 1}]"
            _exact_fields(tool_attempt, tool_attempt_fields, tool_label)
            if tool_attempt["ordinal"] != tool_index:
                raise CapabilitySchemaError(f"{tool_label} ordinal is invalid")
            started_ms = _nonnegative_integer(
                tool_attempt["started_ms"], f"{tool_label}.started_ms"
            )
            ended_ms = _nonnegative_integer(tool_attempt["ended_ms"], f"{tool_label}.ended_ms")
            if ended_ms < started_ms or tool_attempt["status"] not in {
                "completed",
                "failed",
                "cancelled",
            }:
                raise CapabilitySchemaError(f"{tool_label} lifecycle is invalid")
            if row["started_ms"] is not None and started_ms < row["started_ms"]:
                raise CapabilitySchemaError(f"{tool_label} precedes the task lifecycle")
            if (
                row["terminal_ms"] is not None
                and tool_attempt["status"] != "cancelled"
                and ended_ms > row["terminal_ms"]
            ):
                raise CapabilitySchemaError(f"{tool_label} exceeds the task lifecycle")
            failure_label = tool_attempt["failure_label"]
            if tool_attempt["status"] == "failed":
                if failure_label not in TOOL_FAILURE_LABELS:
                    raise CapabilitySchemaError(f"{tool_label} failure label is invalid")
                observed_tool_failures.append(failure_label)
            elif failure_label is not None:
                raise CapabilitySchemaError(f"{tool_label} non-failure has a failure label")
            all_tool_attempts.append((row, tool_attempt))
        if len(tool_attempts) != row["tool_call_count"] or list(failures) != observed_tool_failures:
            raise CapabilitySchemaError(f"{label} tool attempt evidence mismatch")
        if row["terminal_label"] in TOOL_FAILURE_LABELS and row["terminal_label"] not in failures:
            raise CapabilitySchemaError(f"{label} tool terminal lacks matching evidence")
        if row["qualification"] in {"accepted", "rejected"} and row["raw_correct"] is not True:
            raise CapabilitySchemaError(f"{label} qualification decision lacks raw correctness")
        if row["independent_check"] == "correct" and row["raw_correct"] is not True:
            raise CapabilitySchemaError(f"{label} independent correctness lacks raw correctness")
        if (row["qualification"] == "rejected") is not (
            row["qualification_rejection_stage"] is not None
        ):
            raise CapabilitySchemaError(f"{label} qualification rejection stage is inconsistent")
    if all_provider_attempts:
        descriptors_match = all(
            attempt["effective_model"] == attempt["requested_model"]
            and attempt["effective_effort"] == attempt["requested_effort"]
            and attempt["status"] not in {"provider_unavailable", "descriptor_mismatch"}
            for _, attempt in all_provider_attempts
        )
        if configuration["effective_descriptors_match"] is not descriptors_match:
            raise CapabilitySchemaError(
                "configuration descriptor result contradicts provider attempts"
            )
    row_ids = [row.get("task_id") for row in rows]
    if row_ids != task_ids or len(row_ids) != len(set(row_ids)):
        raise CapabilitySchemaError("task rows must match the frozen denominator order")
    if any((row.get("task_id") in SENTINEL_IDS) != (row.get("tier") == "sentinel") for row in rows):
        raise CapabilitySchemaError("sentinels must be separate from Tier A tasks")
    difficult = [row for row in rows if row.get("tier") == "A"]
    sentinel_rows = [row for row in rows if row.get("tier") == "sentinel"]
    if denominator.get("difficult_count") != len(difficult):
        raise CapabilitySchemaError("difficult denominator mismatch")
    if {row.get("task_id") for row in sentinel_rows} != SENTINEL_IDS:
        raise CapabilitySchemaError("sentinels must be separate from Tier A tasks")
    family_ids = {row.get("family_id") for row in difficult}
    categories = {row.get("category") for row in difficult}
    if denominator.get("family_count") != len(family_ids):
        raise CapabilitySchemaError("family denominator mismatch")
    if denominator.get("category_count") != len(categories):
        raise CapabilitySchemaError("category denominator mismatch")
    minimum, maximum, prefix, minimum_families, minimum_categories = (
        EXPERIMENT_DENOMINATOR_CONTRACTS[root["experiment_id"]]
    )
    if not minimum <= len(difficult) <= maximum:
        raise CapabilitySchemaError("difficult denominator contradicts the frozen experiment")
    if prefix is not None and any(not row["task_id"].startswith(prefix) for row in difficult):
        raise CapabilitySchemaError("difficult task namespace contradicts the frozen experiment")
    if len(family_ids) < minimum_families or len(categories) < minimum_categories:
        raise CapabilitySchemaError("denominator diversity contradicts the frozen experiment")

    sentinels = [_mapping(row, "sentinel") for row in _sequence(root["sentinels"], "sentinels")]
    sentinel_ids = [row.get("task_id") for row in sentinels]
    if len(sentinel_ids) != 6 or set(sentinel_ids) != SENTINEL_IDS or len(set(sentinel_ids)) != 6:
        raise CapabilitySchemaError("receipt requires each sentinel exactly once")
    task_by_id = {row["task_id"]: row for row in rows}
    for index, sentinel in enumerate(sentinels):
        _exact_fields(sentinel, {"task_id", "passed", "terminal_label"}, f"sentinels[{index}]")
        if type(sentinel["passed"]) is not bool or (
            sentinel["terminal_label"] is not None
            and sentinel["terminal_label"] not in TERMINAL_LABELS
        ):
            raise CapabilitySchemaError("sentinel result is invalid")
        task = task_by_id[sentinel["task_id"]]
        expected_pass = task["raw_correct"] is True and task["terminal_label"] == "correct"
        if (
            sentinel["passed"] is not expected_pass
            or sentinel["terminal_label"] != task["terminal_label"]
        ):
            raise CapabilitySchemaError("sentinel result does not match its task row")

    series = [_mapping(row, "timepoint") for row in _sequence(root["time_series"], "time_series")]
    if not series:
        raise CapabilitySchemaError("time series must be nonempty")
    offsets = [_nonnegative_integer(row.get("offset_ms"), "timepoint.offset_ms") for row in series]
    if offsets != sorted(set(offsets)):
        raise CapabilitySchemaError("time series offsets must be strictly increasing")
    timepoint_fields = {
        "offset_ms",
        "raw_correct_tasks",
        "fresh_family_solves",
        "qualification_projected",
        "independently_checked",
        "provider_failures",
        "tool_failures",
        "lane_time_ms",
        "global_active_wall_ms",
        "terminal",
        "active",
        "queued",
        "unstarted",
        "usage",
    }
    for index, row in enumerate(series):
        label = f"time_series[{index}]"
        _exact_fields(row, timepoint_fields, label)
        for field in timepoint_fields - {"usage"}:
            _nonnegative_integer(row[field], f"{label}.{field}")
        for field in (
            "raw_correct_tasks",
            "qualification_projected",
            "independently_checked",
        ):
            if row[field] > len(difficult):
                raise CapabilitySchemaError(f"{label}.{field} exceeds the difficult denominator")
        for field in ("terminal", "active", "queued", "unstarted"):
            if row[field] > len(rows):
                raise CapabilitySchemaError(f"{label}.{field} exceeds the full denominator")
        if row["fresh_family_solves"] > denominator["family_count"]:
            raise CapabilitySchemaError(f"{label}.fresh_family_solves exceeds the denominator")
        if (
            row["terminal"] + row["active"] > len(rows)
            or row["active"] + row["unstarted"] > len(rows)
            or row["queued"] > row["unstarted"]
        ):
            raise CapabilitySchemaError(f"{label} queue state is inconsistent")
        offset = row["offset_ms"]
        expected_terminal = sum(task["terminal_ms"] <= offset for task in rows)
        expected_active = sum(
            task["started_ms"] is not None and task["started_ms"] <= offset < task["terminal_ms"]
            for task in rows
        )
        expected_unstarted = sum(
            task["terminal_ms"] > offset
            and (task["started_ms"] is None or task["started_ms"] > offset)
            for task in rows
        )
        expected_queued = sum(
            task["terminal_ms"] > offset
            and task["admitted_ms"] is not None
            and task["admitted_ms"] <= offset
            and (task["started_ms"] is None or task["started_ms"] > offset)
            for task in rows
        )
        if (
            row["terminal"],
            row["active"],
            row["unstarted"],
            row["queued"],
        ) != (expected_terminal, expected_active, expected_unstarted, expected_queued):
            raise CapabilitySchemaError(f"{label} scheduler snapshot contradicts task lifecycle")
        expected_raw_correct = sum(
            task["first_correct_ms"] is not None and task["first_correct_ms"] <= offset
            for task in difficult
        )
        expected_solved_families = len(
            {
                task["family_id"]
                for task in difficult
                if task["first_correct_ms"] is not None and task["first_correct_ms"] <= offset
            }
        )
        expected_independently_checked = sum(
            task["independent_verification"] is not None
            and task["independent_verification"]["ended_ms"] <= offset
            and task["independent_verification"]["result"] in {"correct", "incorrect"}
            for task in difficult
        )
        expected_qualification_projected = sum(
            task["qualification"] == "accepted"
            and task["qualification_ms"] is not None
            and task["qualification_ms"] <= offset
            for task in difficult
        )
        expected_provider_failures = sum(
            attempt["ended_ms"] <= offset
            and attempt["status"]
            in {"provider_failure", "provider_unavailable", "descriptor_mismatch"}
            for _, attempt in all_provider_attempts
        )
        expected_tool_failures = sum(
            attempt["ended_ms"] <= offset and attempt["status"] == "failed"
            for _, attempt in all_tool_attempts
        )
        if (
            row["raw_correct_tasks"],
            row["fresh_family_solves"],
            row["qualification_projected"],
            row["independently_checked"],
            row["provider_failures"],
            row["tool_failures"],
        ) != (
            expected_raw_correct,
            expected_solved_families,
            expected_qualification_projected,
            expected_independently_checked,
            expected_provider_failures,
            expected_tool_failures,
        ):
            raise CapabilitySchemaError(f"{label} counters contradict task event timestamps")
        _validate_usage(row["usage"], f"{label}.usage")
    for field in (
        "raw_correct_tasks",
        "fresh_family_solves",
        "qualification_projected",
        "independently_checked",
        "provider_failures",
        "tool_failures",
        "terminal",
        "lane_time_ms",
        "global_active_wall_ms",
    ):
        values = [row[field] for row in series]
        if values != sorted(values):
            raise CapabilitySchemaError(f"time series {field} must be monotonic")
    for usage_field in ("input", "cached_input", "output", "reasoning"):
        values = [row["usage"][usage_field] for row in series]
        first_null = next(
            (index for index, value in enumerate(values) if value is None), len(values)
        )
        known = values[:first_null]
        if known != sorted(known) or any(value is not None for value in values[first_null:]):
            raise CapabilitySchemaError(f"time series usage.{usage_field} must be cumulative")

    aggregate = _mapping(root["aggregate"], "aggregate")
    aggregate_fields = {
        "raw_correct_tasks",
        "fresh_family_solves",
        "qualification_projected",
        "independently_checked",
        "provider_failures",
        "tool_failures",
        "lane_time_ms",
        "global_active_wall_ms",
        "terminal",
        "unstarted",
        "undersized_reservoir",
    }
    _exact_fields(aggregate, aggregate_fields, "aggregate")
    for field in aggregate_fields - {"undersized_reservoir"}:
        _nonnegative_integer(aggregate[field], f"aggregate.{field}")
    if type(aggregate["undersized_reservoir"]) is not bool:
        raise CapabilitySchemaError("aggregate.undersized_reservoir must be boolean")
    started = sum(row.get("started") is True for row in rows)
    unstarted = len(rows) - started
    if aggregate.get("unstarted") != unstarted:
        raise CapabilitySchemaError("aggregate unstarted count mismatch")
    if aggregate.get("raw_correct_tasks") != sum(
        row.get("raw_correct") is True for row in difficult
    ):
        raise CapabilitySchemaError("aggregate raw-correct count mismatch")
    if aggregate.get("terminal") != sum(row.get("terminal_label") is not None for row in rows):
        raise CapabilitySchemaError("aggregate terminal count mismatch")
    if aggregate.get("qualification_projected") != sum(
        row.get("qualification") == "accepted" for row in difficult
    ):
        raise CapabilitySchemaError("aggregate qualification count mismatch")
    if aggregate.get("independently_checked") != sum(
        row.get("independent_check") in {"correct", "incorrect"} for row in difficult
    ):
        raise CapabilitySchemaError("aggregate independent-check count mismatch")
    difficult_solved_families = {
        row["family_id"] for row in difficult if row.get("raw_correct") is True
    }
    if aggregate.get("fresh_family_solves") != len(difficult_solved_families):
        raise CapabilitySchemaError("aggregate fresh-family count mismatch")
    provider_failure_count = sum(row["provider_failure_count"] for row in rows)
    tool_failure_count = sum(len(row["tool_failure_labels"]) for row in rows)
    if aggregate["provider_failures"] != provider_failure_count:
        raise CapabilitySchemaError("aggregate provider-failure count mismatch")
    if aggregate["tool_failures"] != tool_failure_count:
        raise CapabilitySchemaError("aggregate tool-failure count mismatch")
    final_timepoint = series[-1]
    for aggregate_field in (
        "provider_failures",
        "tool_failures",
        "lane_time_ms",
        "global_active_wall_ms",
    ):
        if final_timepoint[aggregate_field] != aggregate[aggregate_field]:
            raise CapabilitySchemaError(f"final time series {aggregate_field} mismatch")
    for usage_field in ("input", "cached_input", "output", "reasoning"):
        task_usage = [row["usage"][usage_field] for row in rows]
        expected_usage = None if any(value is None for value in task_usage) else sum(task_usage)
        if final_timepoint["usage"][usage_field] != expected_usage:
            raise CapabilitySchemaError(f"final time series usage.{usage_field} mismatch")

    cleanup = _mapping(root["cleanup"], "cleanup")
    _exact_fields(
        cleanup,
        {
            "passed",
            "failure_label",
            "owned_processes_remaining",
            "owned_containers_remaining",
            "owned_volumes_remaining",
            "owned_networks_remaining",
            "owned_services_remaining",
            "owned_workspaces_remaining",
            "owned_state_objects_remaining",
            "owned_run_ids_remaining",
        },
        "cleanup",
    )
    if type(cleanup["passed"]) is not bool:
        raise CapabilitySchemaError("cleanup.passed must be boolean")
    residue = sum(
        _nonnegative_integer(cleanup.get(field), f"cleanup.{field}")
        for field in (
            "owned_processes_remaining",
            "owned_containers_remaining",
            "owned_volumes_remaining",
            "owned_networks_remaining",
            "owned_services_remaining",
            "owned_workspaces_remaining",
            "owned_state_objects_remaining",
            "owned_run_ids_remaining",
        )
    )
    if cleanup.get("passed") is True and (residue != 0 or cleanup.get("failure_label") is not None):
        raise CapabilitySchemaError("cleanup cannot pass with residue or a failure label")
    if cleanup.get("passed") is False and (
        not isinstance(cleanup.get("failure_label"), str) or not cleanup["failure_label"]
    ):
        raise CapabilitySchemaError("failed cleanup requires a failure label")
    if cleanup.get("failure_label") is not None and cleanup["failure_label"] != "cleanup_failure":
        raise CapabilitySchemaError("cleanup failure label is invalid")
    if cleanup["passed"] is True and any(row["cleanup_passed"] is False for row in rows):
        raise CapabilitySchemaError("global cleanup cannot pass when a task cleanup failed")

    privacy = _mapping(root["privacy"], "privacy")
    _exact_fields(
        privacy,
        {
            "scan_passed",
            "candidate_values_published",
            "candidate_derived_digests_published",
            "private_paths_published",
            "target_authorities_published",
        },
        "privacy",
    )
    if privacy.get("scan_passed") is not True or any(
        privacy.get(field) is not False
        for field in (
            "candidate_values_published",
            "candidate_derived_digests_published",
            "private_paths_published",
            "target_authorities_published",
        )
    ):
        raise CapabilitySchemaError("public privacy gate failed")

    service_attempts = [
        _mapping(item, "service_attempt")
        for item in _sequence(root["service_attempts"], "service_attempts")
    ]
    service_attempt_fields = {
        "ordinal",
        "service_id",
        "task_id",
        "status",
        "started_ms",
        "ready_ms",
        "ended_ms",
        "failure_label",
    }
    service_status_to_label = {
        "start_failure": "service_start_failure",
        "unready": "service_unready",
        "lost": "service_lost",
    }
    for service_index, service_attempt in enumerate(service_attempts, start=1):
        service_label = f"service_attempts[{service_index - 1}]"
        _exact_fields(service_attempt, service_attempt_fields, service_label)
        if service_attempt["ordinal"] != service_index:
            raise CapabilitySchemaError(f"{service_label} ordinal is invalid")
        if not isinstance(service_attempt["service_id"], str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9_-]{0,79}", service_attempt["service_id"]
        ):
            raise CapabilitySchemaError(f"{service_label} service ID is invalid")
        if service_attempt["task_id"] not in task_by_id:
            raise CapabilitySchemaError(f"{service_label} task ID is outside the denominator")
        started_ms = _nonnegative_integer(
            service_attempt["started_ms"], f"{service_label}.started_ms"
        )
        ready_ms = service_attempt["ready_ms"]
        _nullable_nonnegative_integer(ready_ms, f"{service_label}.ready_ms")
        ended_ms = _nonnegative_integer(service_attempt["ended_ms"], f"{service_label}.ended_ms")
        if ended_ms < started_ms or ready_ms is not None and not started_ms <= ready_ms <= ended_ms:
            raise CapabilitySchemaError(f"{service_label} offsets are out of order")
        status = service_attempt["status"]
        if status not in {"stopped", "start_failure", "unready", "lost", "cancelled"}:
            raise CapabilitySchemaError(f"{service_label} status is invalid")
        owner = task_by_id[service_attempt["task_id"]]
        if owner["admitted_ms"] is None or started_ms < owner["admitted_ms"]:
            raise CapabilitySchemaError(f"{service_label} precedes task admission")
        if owner["terminal_ms"] is not None and started_ms > owner["terminal_ms"]:
            raise CapabilitySchemaError(f"{service_label} starts after task termination")
        if status in {"start_failure", "unready"} and ready_ms is not None:
            raise CapabilitySchemaError(f"{service_label} failed readiness but reports ready")
        if status in {"stopped", "lost"} and ready_ms is None:
            raise CapabilitySchemaError(f"{service_label} ready lifecycle evidence is missing")
        expected_label = service_status_to_label.get(status)
        if service_attempt["failure_label"] != expected_label:
            raise CapabilitySchemaError(f"{service_label} failure label is inconsistent")
    for row in rows:
        expected_status = {
            "service_start_failure": "start_failure",
            "service_unready": "unready",
            "service_lost": "lost",
        }.get(row["terminal_label"])
        if expected_status is not None and not any(
            attempt["task_id"] == row["task_id"] and attempt["status"] == expected_status
            for attempt in service_attempts
        ):
            raise CapabilitySchemaError("service terminal lacks matching evidence")

    failure_counts = _mapping(root["failure_counts"], "failure_counts")
    _exact_fields(
        failure_counts, {"provider", "tool", "service", "privacy", "cleanup"}, "failure_counts"
    )
    for field in failure_counts:
        _nonnegative_integer(failure_counts[field], f"failure_counts.{field}")
    service_failure_count = sum(
        attempt["status"] in service_status_to_label for attempt in service_attempts
    )
    privacy_failure_count = sum(row["terminal_label"] == "privacy_boundary" for row in rows)
    expected_failures = {
        "provider": provider_failure_count,
        "tool": tool_failure_count,
        "service": service_failure_count,
        "privacy": privacy_failure_count,
        "cleanup": 0 if cleanup["passed"] else 1,
    }
    if failure_counts != expected_failures:
        raise CapabilitySchemaError("failure counts do not match task and boundary rows")

    capacity = _mapping(root["capacity"], "capacity")
    capacity_fields = {
        "lane_time_ms",
        "global_active_wall_ms",
        "global_wall_ms",
        "overlap_method",
        "admissions_closed_ms",
        "scoring_cap_ms",
        "settlement_end_ms",
        "cleanup_end_ms",
        "queue_at_cap",
        "active_at_cap",
        "unstarted_at_cap",
        "dynamic_instances_created",
        "dynamic_instances_deleted",
    }
    _exact_fields(capacity, capacity_fields, "capacity")
    for field in capacity_fields - {"overlap_method"}:
        _nonnegative_integer(capacity[field], f"capacity.{field}")
    if (
        capacity["overlap_method"] != "monotonic_union_v1"
        or capacity["scoring_cap_ms"] != configuration["wall_cap_seconds"] * 1000
    ):
        raise CapabilitySchemaError("capacity clock contract is invalid")
    if (
        capacity["global_active_wall_ms"] > capacity["global_wall_ms"]
        or capacity["lane_time_ms"] < capacity["global_active_wall_ms"]
        or capacity["global_wall_ms"] > capacity["scoring_cap_ms"]
        or capacity["admissions_closed_ms"] > capacity["global_wall_ms"]
        or capacity["settlement_end_ms"] < capacity["global_wall_ms"]
        or capacity["cleanup_end_ms"] < capacity["settlement_end_ms"]
        or capacity["settlement_end_ms"] > capacity["global_wall_ms"] + 180_000
        or capacity["cleanup_end_ms"] > capacity["global_wall_ms"] + 190_000
    ):
        raise CapabilitySchemaError("capacity timing relationship is invalid")
    if (
        capacity["lane_time_ms"] != aggregate["lane_time_ms"]
        or capacity["global_active_wall_ms"] != aggregate["global_active_wall_ms"]
    ):
        raise CapabilitySchemaError("capacity and aggregate timing disagree")
    if (
        cleanup["passed"]
        and capacity["dynamic_instances_created"] != capacity["dynamic_instances_deleted"]
    ):
        raise CapabilitySchemaError("dynamic instance cleanup count mismatch")
    if capacity["dynamic_instances_created"] != len(service_attempts) or capacity[
        "dynamic_instances_deleted"
    ] != sum(attempt["ended_ms"] is not None for attempt in service_attempts):
        raise CapabilitySchemaError("dynamic instance receipt evidence mismatch")
    cap_offset = capacity["global_wall_ms"]
    expected_active_at_cap = sum(
        row["started_ms"] is not None and row["started_ms"] <= cap_offset <= row["terminal_ms"]
        for row in rows
    )
    expected_unstarted_at_cap = sum(
        row["terminal_ms"] >= cap_offset
        and (row["started_ms"] is None or row["started_ms"] > cap_offset)
        for row in rows
    )
    expected_queue_at_cap = sum(
        row["terminal_ms"] >= cap_offset
        and row["admitted_ms"] is not None
        and row["admitted_ms"] <= cap_offset
        and (row["started_ms"] is None or row["started_ms"] > cap_offset)
        for row in rows
    )
    if (
        capacity["queue_at_cap"] != expected_queue_at_cap
        or capacity["active_at_cap"] != expected_active_at_cap
        or capacity["unstarted_at_cap"] != expected_unstarted_at_cap
        or cap_offset != final_timepoint["offset_ms"]
    ):
        raise CapabilitySchemaError("capacity cap snapshot does not match final time series")
    if root["experiment_id"] == "FINAL-CAPACITY":
        drained_early = capacity["global_wall_ms"] < capacity["scoring_cap_ms"]
        fully_terminal = aggregate["terminal"] == denominator["task_count"]
        if drained_early != aggregate["undersized_reservoir"] or (
            drained_early and (not fully_terminal or capacity["active_at_cap"] != 0)
        ):
            raise CapabilitySchemaError("final capacity early-drain state is invalid")
    if any(
        attempt["status"] == "cancelled" and attempt["ended_ms"] > capacity["settlement_end_ms"]
        for _, attempt in all_provider_attempts
    ):
        raise CapabilitySchemaError("cancelled provider attempt exceeded settlement")
    if any(
        attempt["started_ms"] > capacity["global_wall_ms"] for _, attempt in all_provider_attempts
    ):
        raise CapabilitySchemaError("provider attempt started after the scoring cap")
    if any(
        attempt["status"] != "cancelled" and attempt["ended_ms"] > capacity["global_wall_ms"]
        for _, attempt in all_provider_attempts
    ):
        raise CapabilitySchemaError("provider output completed after the scoring cap")
    if any(
        check["candidate_returned_ms"] > capacity["global_wall_ms"]
        or check["checker_started_ms"] > capacity["global_wall_ms"]
        or check["checker_ended_ms"] > capacity["settlement_end_ms"]
        for _, check in all_candidate_checks
    ):
        raise CapabilitySchemaError("candidate/check lifecycle exceeded the scoring boundary")
    if any(
        verification["started_ms"] > capacity["global_wall_ms"]
        or verification["ended_ms"] > capacity["settlement_end_ms"]
        for _, verification in all_independent_verifications
    ):
        raise CapabilitySchemaError("independent verification exceeded the scoring boundary")
    if any(
        row["qualification_ms"] is not None
        and row["qualification_ms"] > capacity["settlement_end_ms"]
        for row in rows
    ):
        raise CapabilitySchemaError("qualification exceeded the settlement boundary")
    if any(
        row["terminal_ms"]
        > (
            capacity["cleanup_end_ms"]
            if row["terminal_label"] == "cleanup_failure"
            else capacity["settlement_end_ms"]
        )
        for row in rows
    ):
        raise CapabilitySchemaError("task terminal exceeded the settlement/cleanup boundary")
    if any(
        attempt["started_ms"] > capacity["global_wall_ms"]
        or attempt["status"] != "cancelled"
        and attempt["ended_ms"] > capacity["global_wall_ms"]
        or attempt["status"] == "cancelled"
        and attempt["ended_ms"] > capacity["settlement_end_ms"]
        for _, attempt in all_tool_attempts
    ):
        raise CapabilitySchemaError("tool lifecycle exceeded the scoring boundary")
    if any(
        row["admitted_ms"] is not None
        and row["admitted_ms"] > capacity["global_wall_ms"]
        or row["started_ms"] is not None
        and row["started_ms"] > capacity["global_wall_ms"]
        for row in rows
    ):
        raise CapabilitySchemaError("task started after the scoring cap")
    if any(
        attempt["started_ms"] > capacity["global_wall_ms"]
        or attempt["ready_ms"] is not None
        and attempt["ready_ms"] > capacity["global_wall_ms"]
        or attempt["ended_ms"] > capacity["cleanup_end_ms"]
        for attempt in service_attempts
    ):
        raise CapabilitySchemaError("service lifecycle exceeded the scoring boundary")

    classification = _mapping(root["classification"], "classification")
    _exact_fields(
        classification,
        {"capability_status", "conversion_status", "limitations", "regression_risks"},
        "classification",
    )
    if classification["capability_status"] not in {
        "demonstrated",
        "not_demonstrated",
        "inconclusive",
    } or classification["conversion_status"] not in {
        "projected",
        "not_projected",
        "inconclusive",
    }:
        raise CapabilitySchemaError("capability/conversion classification is invalid")
    for field in ("limitations", "regression_risks"):
        labels = _sequence(classification[field], f"classification.{field}")
        if any(
            not isinstance(item, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,119}", item)
            for item in labels
        ):
            raise CapabilitySchemaError(f"classification.{field} contains an invalid label")
    decisions = _sequence(root["human_decisions"], "human_decisions")
    for index, raw in enumerate(decisions):
        decision = _mapping(raw, f"human_decisions[{index}]")
        _exact_fields(
            decision,
            {
                "delta_id",
                "decision",
                "approver",
                "decided_at",
                "evidence_ids",
                "uncertainty",
                "regression_risks",
                "rollback",
            },
            f"human_decisions[{index}]",
        )
        if not isinstance(decision["delta_id"], str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9_-]{0,79}", decision["delta_id"]
        ):
            raise CapabilitySchemaError("human decision delta ID is invalid")
        if decision["decision"] not in {"approve", "reject", "defer"}:
            raise CapabilitySchemaError("human decision result is invalid")
        for field in ("approver", "decided_at", "rollback"):
            if not isinstance(decision[field], str):
                raise CapabilitySchemaError(f"human decision {field} is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", decision["approver"]):
            raise CapabilitySchemaError("human decision approver is invalid")
        if not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            decision["decided_at"],
        ):
            raise CapabilitySchemaError("human decision time is invalid")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,119}", decision["rollback"]):
            raise CapabilitySchemaError("human decision rollback is invalid")
        evidence_ids = _sequence(decision["evidence_ids"], "human decision evidence IDs")
        if not evidence_ids or any(
            not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,119}", item)
            for item in evidence_ids
        ):
            raise CapabilitySchemaError("human decision evidence ID is invalid")
        for field in ("uncertainty", "regression_risks"):
            labels = _sequence(decision[field], f"human decision {field}")
            if any(
                not isinstance(item, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,119}", item)
                for item in labels
            ):
                raise CapabilitySchemaError(f"human decision {field} is invalid")
    _validate_resources(root["resources"], "resources")
