from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from rapido.offline_h24_evaluation import (
    ARMS,
    MODEL,
    ORDER_SEED,
    RECEIPT_SCHEMA,
    REGISTRATION_SCHEMA,
    build_evaluation_receipt,
    build_frozen_preregistration,
    classify_h24,
    evaluate_h24_receipt,
    preregistration_sha256,
    stable_task_order,
    validate_preregistration,
    validate_source_image_registration,
)


def _registration(preregistration: dict[str, object]) -> dict[str, object]:
    commit = "a" * 40
    return {
        "schema": REGISTRATION_SCHEMA,
        "preregistration_sha256": preregistration_sha256(preregistration),
        "registered_at_utc": "2026-09-19T00:00:00Z",
        "registration_state": "frozen_after_pr6_merge_before_outcomes",
        "source": {
            "commit_sha": commit,
            "tree_sha": "b" * 40,
            "worktree_status": "clean",
            "pr6_squash_merge_commit_sha": commit,
        },
        "image": {
            "id": f"sha256:{'c' * 64}",
            "platform": "linux/arm64",
            "build_source_commit_sha": commit,
            "immutable": True,
        },
    }


def _soak() -> dict[str, object]:
    scenarios = [
        (
            "distinct_submission_outcomes",
            {
                "correct": True,
                "incorrect": True,
                "historical": True,
                "historical_not_current": True,
            },
        ),
        (
            "ambiguous_write_reconciled_once",
            {"writes": 1, "reconciled": True, "second_write": False},
        ),
        (
            "transient_read_and_permanent_auth",
            {
                "transient_recovered": True,
                "auth_http_status": 401,
                "auth_error": "board_http_401",
                "attempt_delta": 0,
            },
        ),
        (
            "queued_job_unstarted",
            {
                "queued_jobs": 1,
                "started_jobs": 0,
                "attempt_count": 0,
                "submission_count": 0,
                "solve_count": 0,
                "current_verification_count": 0,
            },
        ),
        (
            "fresh_generation_exact_answer",
            {
                "fresh_generation": True,
                "exact_match": True,
                "current_verification_count": 1,
                "current_generation_match": True,
            },
        ),
        (
            "different_answer_separate_axes",
            {
                "exact_match": False,
                "current_verification_count": 0,
                "old_value_current": False,
                "new_value_current": False,
                "method_oracle_match": True,
                "method_axis": "synthetic_only",
            },
        ),
        (
            "changed_bytes_reset_context",
            {
                "refreshed": True,
                "context_advanced": True,
                "same_reference": True,
                "material_changed": True,
                "memory_record_count": 0,
                "prompt_memory_count": 0,
                "old_private_excluded": True,
            },
        ),
        (
            "watch_change_original_deadline",
            {
                "change_observed": True,
                "transient_offset_seconds": 9900.0,
                "change_offset_seconds": 18900.0,
                "deadline_seconds": 19800.0,
                "deadline_unchanged": True,
            },
        ),
        (
            "deadline_cancel_cleanup",
            {
                "status": "deadline",
                "active_jobs": 0,
                "queued_jobs": 0,
                "pending_writes": 0,
                "owned_instances": 0,
                "workspace_entries": 0,
                "instance_creates": 1,
                "instance_deletes": 1,
                "runtime_cancelled": True,
                "runtime_closed": True,
            },
        ),
        (
            "serialized_startup_independent_turns",
            {
                "startup_peak": 1,
                "turn_peak": 2,
                "pilot_result_rows": 24,
                "diagnostics_redacted": True,
                "startup_contract": "pr71_serialized",
                "diagnostics_contract": "pr70_closed_labels",
            },
        ),
    ]
    return {
        "schema": "rapido-benign-board-contract-v1",
        "evidence_level": "benign_controller_contract",
        "clock_mode": "real",
        "requested_seconds": 19800,
        "scenario_count": 10,
        "passed_count": 10,
        "passed": True,
        "correctness_denominator_included": False,
        "scenarios": [
            {"scenario_id": scenario_id, "passed": True, "facts": facts}
            for scenario_id, facts in scenarios
        ],
    }


def _outcome(task: dict[str, object], arm: str, *, correct: bool = True) -> dict[str, object]:
    start = 0 if arm == "one_shot" else 5
    return {
        "task_id": task["id"],
        "arm": arm,
        "order": task["order"],
        "group": task["group"],
        "terminal_outcome": "completed",
        "failure_class": "none",
        "oracle_correct": correct,
        "qualification_accepted": correct,
        "qualified_correct": correct,
        "qualification_reason": "qualified" if correct else "wrong",
        "false_accept": "none",
        "repair_trigger": "none",
        "repair_attempted": False,
        "first_candidate_elapsed_milliseconds": 50,
        "correct_offset_milliseconds": 500 if correct else None,
        "qualified_offset_milliseconds": 600 if correct else None,
        "paired_qualified_elapsed_milliseconds": 100 if correct else None,
        "terminal_offset_milliseconds": 1000,
        "usage": {
            "input_tokens": None,
            "output_tokens": None,
            "cached_input_tokens": None,
            "reasoning_tokens": None,
        },
        "tool_call_count": 1,
        "spans": [
            {
                "stage": "first_turn",
                "status": "completed",
                "start_offset_milliseconds": start,
                "end_offset_milliseconds": start + 10,
            }
        ],
        "artifact_bytes": 1,
    }


def _receipt(preregistration: dict[str, object]) -> dict[str, object]:
    tasks = preregistration["tasks"]
    assert isinstance(tasks, list)
    return {
        "schema": RECEIPT_SCHEMA,
        "preregistration_sha256": preregistration_sha256(preregistration),
        "registration": _registration(preregistration),
        "run_started_at_utc": "2026-09-19T00:01:00Z",
        "barrier": {
            "start_wall_epoch_milliseconds": 1_800_000_000_000,
            "global_deadline_wall_epoch_milliseconds": 1_800_019_800_000,
            "creation_before_barrier": True,
        },
        "scoring_elapsed_milliseconds": 19_800_000,
        "runtime_descriptor_preflight": copy.deepcopy(preregistration["descriptor_preflight"]),
        "runtime_spans": [],
        "fixture_preflight": {
            "catalogue_valid": True,
            "all_24_prepared": True,
            "private_oracle_isolated": True,
            "target_network_disabled": True,
            "provider_transport_available": True,
        },
        "runtime_resources": {
            "observation_status": "observed",
            "sample_interval_seconds": 10.0,
            "peak_cpu_percent": 900.0,
            "peak_rss_bytes": 8 * 1024 * 1024 * 1024,
            "peak_pids": 120,
            "oom_killed": False,
        },
        "outcomes": [_outcome(task, arm) for task in tasks for arm in ARMS],
        "soak": _soak(),
        "cleanup": {
            "started_offset_milliseconds": 19_800_000,
            "elapsed_milliseconds": 120_000,
            "completed": True,
            "orphan_process_count": 0,
            "fake_instance_count": 0,
            "pending_write_count": 0,
            "workspace_residue_bytes": 0,
            "privacy_scan_passed": True,
            "source_database_mutation_detected": False,
        },
    }


def _raw_h24(preregistration: dict[str, object]) -> dict[str, object]:
    registration = _registration(preregistration)
    tasks = preregistration["tasks"]
    assert isinstance(tasks, list)
    results = []
    for task in tasks:
        for arm in ARMS:
            start = 0 if arm == "one_shot" else 5
            results.append(
                {
                    "task_id": task["id"],
                    "family": task["group"],
                    "arm": arm,
                    "model": "gpt-daybreak-blue-latest",
                    "effort": "xhigh",
                    "role": "verifier",
                    "first": {
                        "outcome": "verified_correct",
                        "rejection_reason": None,
                        "verified": True,
                    },
                    "final": {
                        "outcome": "verified_correct",
                        "rejection_reason": None,
                        "verified": True,
                    },
                    "repair_attempted": False,
                    "continuation_count": 0,
                    "same_thread": False,
                    "continuation_prompt_candidate_free": True,
                    "elapsed_seconds": 0.1,
                    "spans": {
                        "fixture_setup_seconds": 0.01,
                        "first_turn_seconds": 0.09,
                        "repair_turn_seconds": 0.0,
                    },
                    "tool_calls": {"first_turn": 1, "final_turn": 1, "cumulative": 1},
                    "tool_errors": {},
                    "native_usage": {},
                    "failure_class": None,
                    "native_observability": {
                        "spans": [
                            {
                                "stage": "first_turn",
                                "status": "completed",
                                "start_offset_milliseconds": start,
                                "end_offset_milliseconds": start + 10,
                                "duration_milliseconds": 10,
                            },
                            {
                                "stage": "repair_turn",
                                "status": "not_run",
                                "start_offset_milliseconds": None,
                                "end_offset_milliseconds": None,
                                "duration_milliseconds": None,
                            },
                        ],
                        "usage": {
                            "accounted": {
                                "input_tokens": None,
                                "output_tokens": None,
                                "cached_input_tokens": None,
                                "reasoning_tokens": None,
                            }
                        },
                    },
                    "artifact_bytes": 1,
                }
            )
    runtime = {}
    for arm in ARMS:
        runtime[arm] = {
            "descriptor": {
                "returned_model": "gpt-daybreak-blue-latest",
                "effort_supported": True,
                "revision_status": "unavailable",
                "revision": None,
            },
            "spans": {
                "startup": {
                    "status": "completed",
                    "start_offset_milliseconds": 0,
                    "end_offset_milliseconds": 1,
                },
                "model_validation": {
                    "status": "completed",
                    "start_offset_milliseconds": 1,
                    "end_offset_milliseconds": 2,
                },
            },
        }
    return {
        "schema": "rapido-offline-h24-pilot-v1",
        "source": {"observed": {"head_sha": registration["source"]["commit_sha"]}},
        "image": {"declared": {"id": registration["image"]["id"]}},
        "protocol": {
            "task_order": [task["id"] for task in tasks],
            "preregistration_sha256": preregistration_sha256(preregistration),
            "randomization": "hmac_sha256_sort_v1",
            "task_resource_policies": [
                {
                    "task_id": task["id"],
                    "wall_seconds": task["wall_seconds"],
                    "artifact_bytes_ceiling": task["artifact_bytes_ceiling"],
                    "cpu_seconds_ceiling": task["cpu_seconds_ceiling"],
                    "memory_bytes_ceiling": task["memory_bytes_ceiling"],
                }
                for task in tasks
            ],
            "global_deadline_seconds": 19800,
            "pair_deadline": "minimum_of_global_and_admission_plus_task_cap",
            "startup": "serialized_shared_home",
            "paired_turns": "concurrent",
            "repair_same_thread": True,
            "repair_continuation_limit": 1,
            "repairable_rejections": [
                "candidate_unobserved",
                "verifier_requires_fixed_observation",
            ],
            "board_enabled": False,
            "submissions_enabled": False,
            "target_network_enabled": False,
            "provider_transport_required": True,
            "fallback_allowed": False,
            "roster": [
                {
                    "arm": "one_shot",
                    "model": "gpt-daybreak-blue-latest",
                    "effort": "xhigh",
                    "continuation": False,
                },
                {
                    "arm": "evidence_repair",
                    "model": "gpt-daybreak-blue-latest",
                    "effort": "xhigh",
                    "continuation": True,
                },
            ],
            "oracle_location": "controller_only_outside_repository_auth_and_workspaces",
        },
        "runtime": runtime,
        "results": results,
        "summary": {},
        "native_observability": {},
    }


@pytest.fixture
def preregistration() -> dict[str, object]:
    return build_frozen_preregistration()


def test_committed_preregistration_is_exact_and_order_is_deterministic(
    preregistration: dict[str, object],
) -> None:
    path = Path("notes/research/offline-h24-preregistration-v1.json")
    committed = json.loads(path.read_text())

    validate_preregistration(committed)
    assert committed == preregistration
    assert ORDER_SEED == "8a2ffd40fdeef877816275730e7bfce26eed11309b68136d2dcbbf4a4de4ede2"
    assert tuple(row["id"] for row in committed["tasks"]) == stable_task_order()
    assert stable_task_order(tuple(reversed(stable_task_order()))) == stable_task_order()
    assert len(stable_task_order()) == len(set(stable_task_order())) == 24


def test_exact_registration_binds_post_merge_source_and_image(
    preregistration: dict[str, object],
) -> None:
    registration = _registration(preregistration)
    validate_source_image_registration(registration, preregistration)

    for path, value in (
        (("source", "worktree_status"), "dirty"),
        (("source", "commit_sha"), "not-a-sha"),
        (("image", "id"), "latest"),
        (("image", "build_source_commit_sha"), "d" * 40),
    ):
        changed = copy.deepcopy(registration)
        changed[path[0]][path[1]] = value
        with pytest.raises(ValueError):
            validate_source_image_registration(changed, preregistration)


def test_recomputes_checkpoint_usage_and_overlapping_span_semantics(
    preregistration: dict[str, object],
) -> None:
    receipt = _receipt(preregistration)
    receipt["outcomes"][0]["usage"]["input_tokens"] = 10
    result = evaluate_h24_receipt(preregistration, receipt)

    assert result["counts"]["one_shot"]["C"] == 24
    assert result["counts"]["evidence_repair"]["Q"] == 24
    assert result["checkpoints"] == [
        {"minutes": minute, "arms": {arm: {"C": 24, "Q": 24} for arm in ARMS}}
        for minute in (30, 60, 120, 180, 330)
    ]
    input_usage = result["usage"]["arms"]["one_shot"]["fields"]["input_tokens"]
    assert input_usage == {
        "total": None,
        "observed_total": 10,
        "observed_attempt_count": 1,
        "missing_attempt_count": 23,
    }
    assert result["timing"] == {
        "lane_milliseconds": 480,
        "wall_active_milliseconds": 15,
        "concurrent_lane_milliseconds": 465,
        "semantics": "relative intervals; lane time additive; wall time interval union",
    }


def test_pure_adapter_maps_raw_pilot_into_exact_final_envelope(
    preregistration: dict[str, object],
) -> None:
    final = _receipt(preregistration)
    adapted = build_evaluation_receipt(
        preregistration=preregistration,
        registration=final["registration"],
        raw_h24=_raw_h24(preregistration),
        soak=final["soak"],
        barrier=final["barrier"],
        runtime_resources=final["runtime_resources"],
        cleanup=final["cleanup"],
        run_started_at_utc=final["run_started_at_utc"],
        scoring_elapsed_milliseconds=final["scoring_elapsed_milliseconds"],
    )

    assert adapted["schema"] == RECEIPT_SCHEMA
    assert len(adapted["outcomes"]) == 48
    assert len(adapted["runtime_spans"]) == 4
    assert evaluate_h24_receipt(preregistration, adapted)["counts"]["one_shot"]["C"] == 24


@pytest.mark.parametrize("mode", ["missing", "duplicate", "extra"])
def test_exact_48_row_join_rejects_missing_duplicate_and_extra(
    preregistration: dict[str, object], mode: str
) -> None:
    receipt = _receipt(preregistration)
    if mode == "missing":
        receipt["outcomes"].pop()
    elif mode == "duplicate":
        receipt["outcomes"][1] = copy.deepcopy(receipt["outcomes"][0])
    else:
        receipt["outcomes"].append(copy.deepcopy(receipt["outcomes"][0]))

    with pytest.raises(ValueError):
        evaluate_h24_receipt(preregistration, receipt)


def test_q_c_consistency_and_false_accept_boundary(preregistration: dict[str, object]) -> None:
    receipt = _receipt(preregistration)
    row = next(row for row in receipt["outcomes"] if row["group"] != "easy")
    row["oracle_correct"] = False
    row["correct_offset_milliseconds"] = None
    with pytest.raises(ValueError, match="qualified correctness"):
        evaluate_h24_receipt(preregistration, receipt)

    receipt = _receipt(preregistration)
    row = next(row for row in receipt["outcomes"] if row["group"] != "easy")
    row.update(
        {
            "oracle_correct": False,
            "qualification_accepted": True,
            "qualified_correct": False,
            "qualification_reason": "qualified",
            "false_accept": "incorrect_candidate",
            "correct_offset_milliseconds": None,
            "qualified_offset_milliseconds": None,
            "paired_qualified_elapsed_milliseconds": None,
        }
    )
    result = evaluate_h24_receipt(preregistration, receipt)
    assert result["gates"]["false_accept_free"] is False
    assert result["decision"] == "no_justified_change"


def test_easy_resource_cleanup_and_descriptor_gates(preregistration: dict[str, object]) -> None:
    receipt = _receipt(preregistration)
    easy_repair = next(
        row
        for row in receipt["outcomes"]
        if row["group"] == "easy" and row["arm"] == "evidence_repair"
    )
    easy_repair.update(
        {
            "oracle_correct": False,
            "qualification_accepted": False,
            "qualified_correct": False,
            "qualification_reason": "wrong",
            "correct_offset_milliseconds": None,
            "qualified_offset_milliseconds": None,
            "paired_qualified_elapsed_milliseconds": None,
        }
    )
    assert evaluate_h24_receipt(preregistration, receipt)["decision"] == "no_justified_change"

    receipt = _receipt(preregistration)
    receipt["runtime_resources"]["oom_killed"] = True
    result = evaluate_h24_receipt(preregistration, receipt)
    assert result["gates"]["resource_ceilings"] is False
    assert result["decision"] == "no_justified_change"

    receipt = _receipt(preregistration)
    receipt["cleanup"]["orphan_process_count"] = 1
    assert evaluate_h24_receipt(preregistration, receipt)["decision"] == "no_justified_change"

    receipt = _receipt(preregistration)
    receipt["runtime_descriptor_preflight"][0]["returned_model"] = "different"
    result = evaluate_h24_receipt(preregistration, receipt)
    assert result["gates"]["model_preflight"] is False
    assert result["decision"] == "inconclusive"


def test_provider_pair_failure_threshold_precedes_other_classification(
    preregistration: dict[str, object],
) -> None:
    receipt = _receipt(preregistration)
    task_ids = [row["id"] for row in preregistration["tasks"][:3]]
    for row in receipt["outcomes"]:
        if row["task_id"] in task_ids:
            row.update(
                {
                    "terminal_outcome": "provider_failure",
                    "failure_class": "provider_transport",
                    "oracle_correct": False,
                    "qualification_accepted": False,
                    "qualified_correct": False,
                    "qualification_reason": "provider_failure",
                    "correct_offset_milliseconds": None,
                    "qualified_offset_milliseconds": None,
                    "paired_qualified_elapsed_milliseconds": None,
                }
            )
    result = evaluate_h24_receipt(preregistration, receipt)
    assert result["gates"]["provider_pair_failures"] == 3
    assert result["decision"] == "inconclusive"


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"model_preflight_valid": False}, "inconclusive"),
        ({"provider_pair_failures": 3}, "inconclusive"),
        ({"safety_integrity_passed": False}, "no_justified_change"),
        ({"easy_passed": False}, "no_justified_change"),
        ({"repair_raw": 9}, "no_justified_change"),
        ({"repair_raw": 12, "repair_non_easy_raw": 10}, "capability_signal"),
        (
            {
                "repair_raw": 10,
                "repair_qualified": 8,
                "repair_opportunities": 3,
            },
            "conversion_only_signal",
        ),
        (
            {
                "repair_raw": 10,
                "repair_qualified": 8,
                "repair_opportunities": 2,
            },
            "inconclusive",
        ),
        ({"repair_opportunities": 3}, "no_justified_change"),
    ],
)
def test_classifier_precedence_and_complete_decision_domain(
    changes: dict[str, object], expected: str
) -> None:
    values: dict[str, object] = {
        "model_preflight_valid": True,
        "provider_pair_failures": 0,
        "safety_integrity_passed": True,
        "easy_passed": True,
        "one_raw": 10,
        "repair_raw": 10,
        "one_non_easy_raw": 8,
        "repair_non_easy_raw": 8,
        "one_qualified": 5,
        "repair_qualified": 5,
        "repair_opportunities": 2,
    }
    values.update(changes)
    assert classify_h24(**values) == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("failure_class", "INCYPHER{private}"),
        ("qualification_reason", "/private/host/path"),
        ("repair_trigger", "https://target.invalid"),
        ("false_accept", "a" * 64),
    ],
)
def test_closed_rows_reject_candidate_path_authority_and_digest_values(
    preregistration: dict[str, object], field: str, value: str
) -> None:
    receipt = _receipt(preregistration)
    receipt["outcomes"][0][field] = value
    with pytest.raises(ValueError):
        evaluate_h24_receipt(preregistration, receipt)

    receipt = _receipt(preregistration)
    receipt["outcomes"][0]["candidate"] = "INCYPHER{private}"
    with pytest.raises(ValueError, match="fields are not exact"):
        evaluate_h24_receipt(preregistration, receipt)


def test_registration_must_precede_run_and_artifact_ceiling_is_gated(
    preregistration: dict[str, object],
) -> None:
    receipt = _receipt(preregistration)
    receipt["registration"]["registered_at_utc"] = "2026-09-19T00:02:00Z"
    with pytest.raises(ValueError, match="after outcome collection"):
        evaluate_h24_receipt(preregistration, receipt)

    receipt = _receipt(preregistration)
    task = preregistration["tasks"][0]
    receipt["outcomes"][0]["artifact_bytes"] = task["artifact_bytes_ceiling"] + 1
    result = evaluate_h24_receipt(preregistration, receipt)
    assert result["gates"]["resource_ceilings"] is False
    assert result["decision"] == "no_justified_change"


def test_preregistration_and_receipt_extra_fields_fail_closed(
    preregistration: dict[str, object],
) -> None:
    changed = copy.deepcopy(preregistration)
    changed["result"] = "not-yet-run"
    with pytest.raises(ValueError):
        validate_preregistration(changed)

    receipt = _receipt(preregistration)
    receipt["target_authority"] = "example.invalid:443"
    with pytest.raises(ValueError):
        evaluate_h24_receipt(preregistration, receipt)


def test_model_identity_is_frozen_without_revision(preregistration: dict[str, object]) -> None:
    assert preregistration["descriptor_preflight"] == [
        {
            "arm": arm,
            "returned_model": MODEL,
            "returned_effort": "xhigh",
            "revision_status": "unavailable",
            "revision": None,
        }
        for arm in ARMS
    ]
