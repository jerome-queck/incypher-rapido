from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from rapido.offline_capability_schema import (
    ASSIGNMENT_COUNTS,
    SENTINEL_IDS,
    CapabilitySchemaError,
    validate_receipt,
    validate_registration,
    validate_task_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRATION = ROOT / "notes/research/capability-sprint-experiments-v1.json"
RECEIPT_SCHEMA_V1 = ROOT / "notes/research/capability-sprint-receipt-schema-v1.json"
RECEIPT_SCHEMA = ROOT / "notes/research/capability-sprint-receipt-schema-v2.json"


def _resource() -> dict[str, object]:
    return {
        "cpu_peak_cores": 0.1,
        "memory_peak_bytes": 1024,
        "pids_peak": 1,
        "disk_peak_bytes": 1024,
        "unavailable_reason": None,
    }


def _usage() -> dict[str, int]:
    return {"input": 0, "cached_input": 0, "output": 0, "reasoning": 0}


def _receipt() -> dict[str, object]:
    task_ids = sorted(SENTINEL_IDS)
    tasks = [
        {
            "task_id": task_id,
            "family_id": f"SENT-{task_id[-1]}",
            "category": "sentinel",
            "tier": "sentinel",
            "started": True,
            "admitted_ms": 0,
            "started_ms": 1,
            "first_unique_candidate_ms": 2,
            "first_correct_ms": 3,
            "terminal_ms": 4,
            "terminal_label": "correct",
            "raw_correct": True,
            "qualification": "accepted",
            "qualification_ms": 3,
            "qualification_rejection_stage": None,
            "independent_check": "correct",
            "independent_verification": {
                "started_ms": 3,
                "ended_ms": 3,
                "result": "correct",
                "method_version": "synthetic-replay-v1",
            },
            "candidate_unique_count": 1,
            "candidate_repeat_count": 0,
            "checker_call_count": 1,
            "candidate_checks": [
                {
                    "ordinal": 1,
                    "candidate_returned_ms": 2,
                    "checker_started_ms": 2,
                    "checker_ended_ms": 3,
                    "result": "correct",
                }
            ],
            "provider_invocation_count": 1,
            "provider_failure_count": 0,
            "provider_attempts": [
                {
                    "ordinal": 1,
                    "lane": 0,
                    "requested_model": "gpt-daybreak-blue-latest",
                    "requested_effort": "xhigh",
                    "effective_model": "gpt-daybreak-blue-latest",
                    "effective_effort": "xhigh",
                    "effective_revision_build": "provider-catalogue-v1",
                    "native_client_version": "codex-cli-0.154.0",
                    "status": "completed",
                    "started_ms": 1,
                    "ended_ms": 3,
                    "usage": _usage(),
                }
            ],
            "checker_version": "synthetic-v1",
            "usage": _usage(),
            "resources": _resource(),
            "tool_call_count": 0,
            "tool_attempts": [],
            "tool_failure_labels": [],
            "cleanup_passed": True,
        }
        for task_id in task_ids
    ]
    return {
        "schema": "rapido-capability-public-receipt-v2",
        "run_id": "synthetic-capability-receipt",
        "experiment_id": "BOARD-ACCEPT",
        "source": {
            "sha": "6aa26147c35fbc46affeeb77d93d6b88640564a8",
            "image_id": "sha256:0eef1ceb74759bf64e9a89ca0dd1cf722bd1f6967a9b53666577164ee4d71c52",
            "dirty": False,
            "registration_sha256": "f74810e1c43c0a1cbdebd196af6f76b1d96bfb6572b344129662dd9f2657ffd1",
            "task_manifest_sha256": "14a5dbd43fac8df0703b22a2cb258f458a7319c000f95e15b8ef5984a573981b",
        },
        "configuration": {
            "routing_profile": "mixed_v1",
            "requested_descriptors": ["DAYBREAK_XHIGH", "LUNA_MAX", "LUNA_XHIGH"],
            "lane_descriptors": [
                "DAYBREAK_XHIGH",
                "DAYBREAK_XHIGH",
                "LUNA_MAX",
                "LUNA_XHIGH",
            ],
            "effective_descriptors_match": True,
            "active_challenges": 5,
            "lane_admissions": 20,
            "dynamic_leases": 1,
            "attempt_seconds": 800,
            "episodes_per_task": 3,
            "wall_cap_seconds": 1800,
            "usage_caps": {"input": 1_000_000, "output": 50_000, "reasoning": 30_000},
        },
        "denominator": {
            "task_count": 6,
            "difficult_count": 0,
            "family_count": 0,
            "category_count": 0,
            "task_ids": task_ids,
        },
        "tasks": tasks,
        "time_series": [
            {
                "offset_ms": 0,
                "raw_correct_tasks": 0,
                "fresh_family_solves": 0,
                "qualification_projected": 0,
                "independently_checked": 0,
                "provider_failures": 0,
                "tool_failures": 0,
                "lane_time_ms": 0,
                "global_active_wall_ms": 0,
                "terminal": 0,
                "active": 0,
                "queued": 6,
                "unstarted": 6,
                "usage": _usage(),
            },
            {
                "offset_ms": 1000,
                "raw_correct_tasks": 0,
                "fresh_family_solves": 0,
                "qualification_projected": 0,
                "independently_checked": 0,
                "provider_failures": 0,
                "tool_failures": 0,
                "lane_time_ms": 6000,
                "global_active_wall_ms": 1000,
                "terminal": 6,
                "active": 0,
                "queued": 0,
                "unstarted": 0,
                "usage": _usage(),
            },
        ],
        "sentinels": [
            {"task_id": task_id, "passed": True, "terminal_label": "correct"}
            for task_id in task_ids
        ],
        "aggregate": {
            "raw_correct_tasks": 0,
            "fresh_family_solves": 0,
            "qualification_projected": 0,
            "independently_checked": 0,
            "provider_failures": 0,
            "tool_failures": 0,
            "lane_time_ms": 6000,
            "global_active_wall_ms": 1000,
            "terminal": 6,
            "unstarted": 0,
            "undersized_reservoir": False,
        },
        "failure_counts": {
            "provider": 0,
            "tool": 0,
            "service": 0,
            "privacy": 0,
            "cleanup": 0,
        },
        "capacity": {
            "lane_time_ms": 6000,
            "global_active_wall_ms": 1000,
            "global_wall_ms": 1000,
            "overlap_method": "monotonic_union_v1",
            "admissions_closed_ms": 1000,
            "scoring_cap_ms": 1_800_000,
            "settlement_end_ms": 1000,
            "cleanup_end_ms": 1000,
            "queue_at_cap": 0,
            "active_at_cap": 0,
            "unstarted_at_cap": 0,
            "dynamic_instances_created": 0,
            "dynamic_instances_deleted": 0,
        },
        "service_attempts": [],
        "classification": {
            "capability_status": "demonstrated",
            "conversion_status": "projected",
            "limitations": [],
            "regression_risks": [],
        },
        "resources": _resource(),
        "cleanup": {
            "passed": True,
            "inventory_complete": True,
            "failure_label": None,
            "owned_processes_remaining": 0,
            "owned_containers_remaining": 0,
            "owned_volumes_remaining": 0,
            "owned_networks_remaining": 0,
            "owned_services_remaining": 0,
            "owned_workspaces_remaining": 0,
            "owned_state_objects_remaining": 0,
            "owned_run_ids_remaining": 0,
        },
        "privacy": {
            "scan_passed": True,
            "candidate_values_published": False,
            "candidate_derived_digests_published": False,
            "private_paths_published": False,
            "target_authorities_published": False,
        },
        "human_decisions": [],
    }


def _historical_v1(receipt: dict[str, object]) -> dict[str, object]:
    receipt["schema"] = "rapido-capability-public-receipt-v1"
    del receipt["cleanup"]["inventory_complete"]
    return receipt


def _task_manifest() -> dict[str, object]:
    families = [{"family_id": f"FAMILY-{index}"} for index in range(12)]
    tasks: list[dict[str, object]] = []
    serial = 1
    for assignment, count in ASSIGNMENT_COUNTS.items():
        for index in range(count):
            task_id = f"EAS-{index + 1:03d}" if assignment == "sentinel" else f"TASK-{serial:04d}"
            tasks.append(
                {
                    "task_id": task_id,
                    "family_id": f"FAMILY-{index % len(families)}",
                    "assignment": assignment,
                }
            )
            serial += 1
    return {
        "schema": "rapido-capability-candidate-manifest-v1",
        "task_count": len(tasks),
        "family_count": len(families),
        "assignment_counts": dict(ASSIGNMENT_COUNTS),
        "families": families,
        "tasks": tasks,
    }


def _as_final_capacity(receipt: dict[str, object]) -> None:
    difficult = []
    for index in range(83):
        difficult.append(
            {
                "task_id": f"RES-SYNTH-{index + 1:03d}",
                "family_id": f"FAMILY-{index % 9}",
                "category": f"category-{index % 5}",
                "tier": "A",
                "started": False,
                "admitted_ms": None,
                "started_ms": None,
                "first_unique_candidate_ms": None,
                "first_correct_ms": None,
                "terminal_ms": 1000,
                "terminal_label": "unstarted_at_cap",
                "raw_correct": None,
                "qualification": "inconclusive",
                "qualification_ms": None,
                "qualification_rejection_stage": None,
                "independent_check": "not_invoked",
                "independent_verification": None,
                "candidate_unique_count": 0,
                "candidate_repeat_count": 0,
                "checker_call_count": 0,
                "candidate_checks": [],
                "provider_invocation_count": 0,
                "provider_failure_count": 0,
                "provider_attempts": [],
                "checker_version": "synthetic-v1",
                "usage": _usage(),
                "resources": _resource(),
                "tool_call_count": 0,
                "tool_attempts": [],
                "tool_failure_labels": [],
                "cleanup_passed": None,
            }
        )
    receipt["experiment_id"] = "FINAL-CAPACITY"
    receipt["configuration"]["routing_profile"] = "selected_mixed_v1"
    receipt["configuration"]["wall_cap_seconds"] = 19_800
    receipt["configuration"]["usage_caps"] = {
        "input": 100_000_000,
        "output": 5_000_000,
        "reasoning": 3_000_000,
    }
    receipt["tasks"].extend(difficult)
    receipt["denominator"].update(
        {
            "task_count": 89,
            "difficult_count": 83,
            "family_count": 9,
            "category_count": 5,
            "task_ids": [row["task_id"] for row in receipt["tasks"]],
        }
    )
    receipt["time_series"][0].update({"queued": 6, "unstarted": 89})
    receipt["time_series"][-1].update({"terminal": 89, "unstarted": 0})
    receipt["aggregate"].update({"terminal": 89, "unstarted": 83})
    receipt["capacity"].update({"scoring_cap_ms": 19_800_000, "unstarted_at_cap": 0})


def test_canonical_registration_is_complete_and_frozen() -> None:
    registration = json.loads(REGISTRATION.read_text(encoding="utf-8"))
    validate_registration(registration)


def test_registration_rejects_missing_budget_and_descriptor_fallback() -> None:
    registration = json.loads(REGISTRATION.read_text(encoding="utf-8"))
    del registration["experiments"][2]["per_task_budget"]
    with pytest.raises(CapabilitySchemaError, match="fields mismatch"):
        validate_registration(registration)

    registration = json.loads(REGISTRATION.read_text(encoding="utf-8"))
    registration["models"]["DAYBREAK_XHIGH"]["fallback"] = "allowed"
    with pytest.raises(CapabilitySchemaError, match="preflight mismatch"):
        validate_registration(registration)

    registration = json.loads(REGISTRATION.read_text(encoding="utf-8"))
    registration["experiments"][2]["wall_cap_seconds"] = 1
    with pytest.raises(CapabilitySchemaError, match="numeric contract changed"):
        validate_registration(registration)

    registration = json.loads(REGISTRATION.read_text(encoding="utf-8"))
    registration["resources"]["dynamic_service"]["network"] = "public_internet"
    with pytest.raises(CapabilitySchemaError, match="resource contract changed"):
        validate_registration(registration)

    registration = json.loads(REGISTRATION.read_text(encoding="utf-8"))
    registration["privacy"]["scored_runner_exclusions"] = []
    with pytest.raises(CapabilitySchemaError, match="privacy boundary changed"):
        validate_registration(registration)

    registration = json.loads(REGISTRATION.read_text(encoding="utf-8"))
    registration["source_delta"]["rapido_main_moved"] = "false"
    with pytest.raises(CapabilitySchemaError, match="source delta"):
        validate_registration(registration)

    registration = json.loads(REGISTRATION.read_text(encoding="utf-8"))
    registration["scheduler"]["lane_admissions"] = 1
    with pytest.raises(CapabilitySchemaError, match="scheduler contract"):
        validate_registration(registration)

    registration = json.loads(REGISTRATION.read_text(encoding="utf-8"))
    registration["experiments"][2]["decision_rule"] = "changed_after_freeze"
    with pytest.raises(CapabilitySchemaError, match="canonical commitment"):
        validate_registration(registration)


def test_private_task_manifest_rejects_overlap_and_assignment_drift() -> None:
    manifest = _task_manifest()
    validate_task_manifest(manifest)

    duplicate = copy.deepcopy(manifest)
    duplicate["tasks"][-1]["task_id"] = duplicate["tasks"][-2]["task_id"]
    with pytest.raises(CapabilitySchemaError, match="must be unique"):
        validate_task_manifest(duplicate)

    drift = copy.deepcopy(manifest)
    drift["tasks"][-1]["assignment"] = "calibration"
    with pytest.raises(CapabilitySchemaError, match="assignment counts"):
        validate_task_manifest(drift)


def test_receipt_schema_declares_closed_nonempty_privacy_and_cleanup_gates() -> None:
    schema = json.loads(RECEIPT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(_receipt())
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["tasks"]["minItems"] == 6
    assert schema["properties"]["time_series"]["minItems"] == 1
    assert schema["properties"]["sentinels"]["uniqueItems"] is True
    assert schema["properties"]["privacy"]["properties"]["scan_passed"] == {"const": True}
    assert schema["properties"]["schema"] == {"const": "rapido-capability-public-receipt-v2"}
    assert schema["properties"]["cleanup"]["properties"]["inventory_complete"] == {
        "type": "boolean"
    }
    assert schema["allOf"][0]["then"]["properties"]["cleanup"]["properties"][
        "owned_processes_remaining"
    ] == {"const": 0}

    duplicate = _receipt()
    duplicate["sentinels"][5] = {
        "task_id": "EAS-005",
        "passed": False,
        "terminal_label": "incorrect",
    }
    with pytest.raises(ValidationError):
        validator.validate(duplicate)

    unknown_terminal = _receipt()
    unknown_terminal["tasks"][0]["terminal_label"] = "unexpected"
    with pytest.raises(ValidationError):
        validator.validate(unknown_terminal)

    private_rollback = _receipt()
    private_rollback["human_decisions"].append(
        {
            "delta_id": "delta-1",
            "decision": "defer",
            "approver": "owner",
            "decided_at": "2026-09-20T00:00:00Z",
            "evidence_ids": ["evidence-1"],
            "uncertainty": [],
            "regression_risks": [],
            "rollback": "/Volumes/private/run",
        }
    )
    with pytest.raises(ValidationError):
        validator.validate(private_rollback)

    missing_start = _receipt()
    missing_start["tasks"][0]["started_ms"] = None
    with pytest.raises(ValidationError):
        validator.validate(missing_start)


def test_v1_requires_explicit_historical_opt_in_and_remains_unchanged() -> None:
    historical = _historical_v1(_receipt())

    with pytest.raises(CapabilitySchemaError, match="identity"):
        validate_receipt(historical)
    validate_receipt(historical, allow_historical_v1=True)

    v1_schema = json.loads(RECEIPT_SCHEMA_V1.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(v1_schema)
    Draft202012Validator(v1_schema).validate(historical)
    assert hashlib.sha256(RECEIPT_SCHEMA_V1.read_bytes()).hexdigest() == (
        "fdf8a5a2f87a09a5bd847be779ccc644b1d527d48ba44d0b6dbe07770f2f8e74"
    )


def test_historical_v1_retains_closed_cap_snapshot_semantics() -> None:
    historical = _historical_v1(_receipt())
    historical["tasks"][0]["terminal_ms"] = 1000
    historical["capacity"]["active_at_cap"] = 1

    with pytest.raises(CapabilitySchemaError, match="identity"):
        validate_receipt(historical)
    validate_receipt(historical, allow_historical_v1=True)

    current = _receipt()
    current["tasks"][0]["terminal_ms"] = 1000
    current["capacity"]["active_at_cap"] = 1
    with pytest.raises(CapabilitySchemaError, match="cap snapshot"):
        validate_receipt(current)


def test_historical_v1_does_not_inherit_v2_usage_lower_bound_rule() -> None:
    historical = _historical_v1(_receipt())
    task = historical["tasks"][0]
    task["provider_attempts"][0]["usage"].update({"input": 1_000_001, "output": None})
    task["usage"].update({"input": 1_000_001, "output": None})
    historical["time_series"][-1]["usage"].update({"input": 1_000_001, "output": None})
    validate_receipt(historical, allow_historical_v1=True)

    current = copy.deepcopy(historical)
    current["schema"] = "rapido-capability-public-receipt-v2"
    current["cleanup"]["inventory_complete"] = True
    with pytest.raises(CapabilitySchemaError, match="requires usage_cap terminal"):
        validate_receipt(current)


def test_v2_cleanup_requires_complete_zero_inventory_to_pass() -> None:
    schema = json.loads(RECEIPT_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    false_pass = _receipt()
    false_pass["cleanup"]["inventory_complete"] = False
    false_pass["cleanup"]["owned_processes_remaining"] = None
    with pytest.raises(ValidationError):
        validator.validate(false_pass)
    with pytest.raises(CapabilitySchemaError, match="cleanup cannot pass"):
        validate_receipt(false_pass)

    failed = _receipt()
    failed["cleanup"].update(
        {
            "passed": False,
            "inventory_complete": False,
            "failure_label": "cleanup_failure",
            "owned_processes_remaining": None,
            "owned_containers_remaining": None,
            "owned_volumes_remaining": None,
            "owned_networks_remaining": None,
            "owned_services_remaining": None,
            "owned_workspaces_remaining": None,
            "owned_state_objects_remaining": None,
            "owned_run_ids_remaining": None,
        }
    )
    failed["failure_counts"]["cleanup"] = 1
    validator.validate(failed)
    validate_receipt(failed)

    contradictory = copy.deepcopy(failed)
    contradictory["cleanup"]["inventory_complete"] = True
    with pytest.raises(CapabilitySchemaError, match="contradicts nullable"):
        validate_receipt(contradictory)


def test_receipt_semantics_accept_canonical_and_reject_cross_field_mismatch() -> None:
    receipt = _receipt()
    validate_receipt(receipt)
    assert receipt["denominator"]["difficult_count"] == 0
    assert receipt["aggregate"]["raw_correct_tasks"] == 0
    assert receipt["aggregate"]["qualification_projected"] == 0
    assert receipt["aggregate"]["independently_checked"] == 0

    duplicate = copy.deepcopy(receipt)
    duplicate["sentinels"][5]["task_id"] = "EAS-005"
    with pytest.raises(CapabilitySchemaError, match="each sentinel exactly once"):
        validate_receipt(duplicate)

    residue = copy.deepcopy(receipt)
    residue["cleanup"]["owned_services_remaining"] = 1
    with pytest.raises(CapabilitySchemaError, match="cleanup cannot pass"):
        validate_receipt(residue)

    bad_count = copy.deepcopy(receipt)
    bad_count["denominator"]["task_count"] = 5
    with pytest.raises(CapabilitySchemaError, match="task count mismatch"):
        validate_receipt(bad_count)

    tier_mix = copy.deepcopy(receipt)
    tier_mix["tasks"][0]["tier"] = "A"
    with pytest.raises(CapabilitySchemaError, match="sentinels must be separate"):
        validate_receipt(tier_mix)

    unknown_terminal = copy.deepcopy(receipt)
    unknown_terminal["tasks"][0]["terminal_label"] = "unexpected"
    with pytest.raises(CapabilitySchemaError, match="terminal label"):
        validate_receipt(unknown_terminal)

    terminal_count = copy.deepcopy(receipt)
    terminal_count["aggregate"]["terminal"] = 5
    with pytest.raises(CapabilitySchemaError, match="terminal count"):
        validate_receipt(terminal_count)

    skeletal = copy.deepcopy(receipt)
    del skeletal["tasks"][0]["checker_version"]
    with pytest.raises(CapabilitySchemaError, match="fields mismatch"):
        validate_receipt(skeletal)

    inconsistent_sentinel = copy.deepcopy(receipt)
    inconsistent_sentinel["sentinels"][0]["passed"] = False
    with pytest.raises(CapabilitySchemaError, match="does not match"):
        validate_receipt(inconsistent_sentinel)

    not_started = copy.deepcopy(receipt)
    not_started["tasks"][0]["started"] = False
    with pytest.raises(CapabilitySchemaError, match="without starting"):
        validate_receipt(not_started)

    failed_cleanup = copy.deepcopy(receipt)
    failed_cleanup["cleanup"]["passed"] = False
    with pytest.raises(CapabilitySchemaError, match="requires a failure label"):
        validate_receipt(failed_cleanup)

    model_fallback = copy.deepcopy(receipt)
    model_fallback["tasks"][0]["provider_attempts"][0]["effective_model"] = "gpt-5.6-luna"
    with pytest.raises(CapabilitySchemaError, match="model fallback"):
        validate_receipt(model_fallback)

    missing_start = copy.deepcopy(receipt)
    missing_start["tasks"][0]["started_ms"] = None
    with pytest.raises(CapabilitySchemaError, match="without admission/start"):
        validate_receipt(missing_start)

    duplicate_checks = copy.deepcopy(receipt)
    duplicate_checks["tasks"][0]["checker_call_count"] = 2
    with pytest.raises(CapabilitySchemaError, match="once per unique"):
        validate_receipt(duplicate_checks)

    terminal_disagreement = copy.deepcopy(receipt)
    terminal_disagreement["tasks"][0]["raw_correct"] = False
    with pytest.raises(CapabilitySchemaError, match="raw result|terminal and raw"):
        validate_receipt(terminal_disagreement)

    task_cleanup_failure = copy.deepcopy(receipt)
    task_cleanup_failure["tasks"][0]["cleanup_passed"] = False
    with pytest.raises(CapabilitySchemaError, match="global cleanup"):
        validate_receipt(task_cleanup_failure)

    impossible_series = copy.deepcopy(receipt)
    impossible_series["time_series"][0]["terminal"] = 999
    with pytest.raises(CapabilitySchemaError, match="exceeds the .*denominator"):
        validate_receipt(impossible_series)

    impossible_snapshot = copy.deepcopy(receipt)
    impossible_snapshot["time_series"][0].update(
        {"terminal": 6, "active": 0, "queued": 0, "unstarted": 0}
    )
    with pytest.raises(CapabilitySchemaError, match="snapshot contradicts task lifecycle"):
        validate_receipt(impossible_snapshot)

    wrong_experiment_contract = copy.deepcopy(receipt)
    wrong_experiment_contract["experiment_id"] = "HARD-BASELINE"
    with pytest.raises(CapabilitySchemaError, match="frozen experiment"):
        validate_receipt(wrong_experiment_contract)

    wrong_source = copy.deepcopy(receipt)
    wrong_source["source"]["sha"] = "b" * 40
    with pytest.raises(CapabilitySchemaError, match="frozen registration"):
        validate_receipt(wrong_source)

    wrong_scheduler = copy.deepcopy(receipt)
    wrong_scheduler["configuration"]["active_challenges"] = 1
    with pytest.raises(CapabilitySchemaError, match="scheduler"):
        validate_receipt(wrong_scheduler)

    wrong_roster = copy.deepcopy(receipt)
    wrong_roster["experiment_id"] = "RTE-DAYBREAK"
    wrong_roster["configuration"].update(
        {
            "routing_profile": "unregistered-profile",
            "wall_cap_seconds": 2700,
            "usage_caps": {"input": 15_000_000, "output": 750_000, "reasoning": 450_000},
        }
    )
    wrong_roster["capacity"]["scoring_cap_ms"] = 2_700_000
    with pytest.raises(CapabilitySchemaError, match="routing"):
        validate_receipt(wrong_roster)

    missing_hard_denominator = copy.deepcopy(receipt)
    missing_hard_denominator["experiment_id"] = "HARD-BASELINE"
    missing_hard_denominator["configuration"].update(
        {
            "wall_cap_seconds": 3600,
            "usage_caps": {"input": 20_000_000, "output": 1_000_000, "reasoning": 600_000},
        }
    )
    missing_hard_denominator["capacity"]["scoring_cap_ms"] = 3_600_000
    with pytest.raises(CapabilitySchemaError, match="difficult denominator"):
        validate_receipt(missing_hard_denominator)

    regressing_usage = copy.deepcopy(receipt)
    regressing_usage["time_series"][0]["usage"]["input"] = 100
    with pytest.raises(CapabilitySchemaError, match="must be cumulative"):
        validate_receipt(regressing_usage)

    unexplained_resource_null = copy.deepcopy(receipt)
    resource = unexplained_resource_null["tasks"][0]["resources"]
    resource["cpu_peak_cores"] = None
    resource["memory_peak_bytes"] = None
    resource["pids_peak"] = None
    resource["disk_peak_bytes"] = None
    with pytest.raises(CapabilitySchemaError, match="sample/reason mismatch"):
        validate_receipt(unexplained_resource_null)

    axis_inflation = copy.deepcopy(receipt)
    axis_inflation["tasks"][0]["raw_correct"] = False
    axis_inflation["tasks"][0]["first_correct_ms"] = None
    axis_inflation["tasks"][0]["terminal_label"] = "incorrect"
    axis_inflation["tasks"][0]["candidate_checks"][0]["result"] = "incorrect"
    with pytest.raises(CapabilitySchemaError, match="qualification decision"):
        validate_receipt(axis_inflation)

    early_qualification = copy.deepcopy(receipt)
    early_qualification["tasks"][0]["qualification_ms"] = 0
    with pytest.raises(CapabilitySchemaError, match="lifecycle offsets"):
        validate_receipt(early_qualification)

    wrong_cap = copy.deepcopy(receipt)
    wrong_cap["capacity"]["scoring_cap_ms"] = 1
    with pytest.raises(CapabilitySchemaError, match="clock contract"):
        validate_receipt(wrong_cap)

    incomplete_decision = copy.deepcopy(receipt)
    incomplete_decision["human_decisions"].append(
        {
            "delta_id": "delta-1",
            "decision": "approve",
            "approver": None,
            "decided_at": None,
            "evidence_ids": [],
            "uncertainty": [],
            "regression_risks": [],
            "rollback": None,
        }
    )
    with pytest.raises(CapabilitySchemaError, match="approver"):
        validate_receipt(incomplete_decision)


def test_receipt_preserves_transient_provider_invocation_failures() -> None:
    receipt = _receipt()
    receipt["tasks"][0]["provider_invocation_count"] = 2
    receipt["tasks"][0]["provider_failure_count"] = 1
    completed = receipt["tasks"][0]["provider_attempts"][0]
    completed["ordinal"] = 2
    completed["started_ms"] = 2
    receipt["tasks"][0]["provider_attempts"].insert(
        0,
        {
            "ordinal": 1,
            "lane": 0,
            "requested_model": "gpt-daybreak-blue-latest",
            "requested_effort": "xhigh",
            "effective_model": "gpt-daybreak-blue-latest",
            "effective_effort": "xhigh",
            "effective_revision_build": "provider-catalogue-v1",
            "native_client_version": "codex-cli-0.154.0",
            "status": "provider_failure",
            "started_ms": 1,
            "ended_ms": 2,
            "usage": _usage(),
        },
    )
    receipt["time_series"][-1]["provider_failures"] = 1
    receipt["aggregate"]["provider_failures"] = 1
    receipt["failure_counts"]["provider"] = 1
    validate_receipt(receipt)


def test_known_usage_lower_bound_over_cap_survives_other_nulls() -> None:
    receipt = _receipt()
    task = receipt["tasks"][0]
    task["provider_attempts"][0]["usage"].update({"input": 1_000_001, "output": None})
    task["usage"].update({"input": 1_000_001, "output": None})
    receipt["time_series"][-1]["usage"].update({"input": 1_000_001, "output": None})

    with pytest.raises(CapabilitySchemaError, match="requires usage_cap terminal"):
        validate_receipt(receipt)

    task.update(
        {
            "terminal_label": "usage_cap",
            "raw_correct": None,
            "first_correct_ms": None,
            "qualification": "inconclusive",
            "qualification_ms": None,
            "independent_check": "not_invoked",
            "independent_verification": None,
        }
    )
    task["candidate_checks"][0]["result"] = "incorrect"
    receipt["sentinels"][0].update({"passed": False, "terminal_label": "usage_cap"})
    with pytest.raises(CapabilitySchemaError, match="invalidates demonstrated/projected"):
        validate_receipt(receipt)

    receipt["classification"].update(
        {"capability_status": "inconclusive", "conversion_status": "inconclusive"}
    )
    validate_receipt(receipt)


def test_empty_provider_attempts_aggregate_to_exact_zero() -> None:
    receipt = _receipt()
    _as_final_capacity(receipt)
    receipt["aggregate"]["undersized_reservoir"] = True
    empty = receipt["tasks"][-1]
    assert empty["provider_attempts"] == []
    assert empty["usage"] == _usage()
    validate_receipt(receipt)


def test_provider_attempts_bind_lanes_and_allow_bounded_post_cap_cancellation() -> None:
    receipt = _receipt()
    task = receipt["tasks"][0]
    task["provider_invocation_count"] = 2
    task["provider_attempts"].append(
        {
            "ordinal": 2,
            "lane": 0,
            "requested_model": "gpt-daybreak-blue-latest",
            "requested_effort": "xhigh",
            "effective_model": "gpt-daybreak-blue-latest",
            "effective_effort": "xhigh",
            "effective_revision_build": "provider-catalogue-v1",
            "native_client_version": "codex-cli-0.154.0",
            "status": "cancelled",
            "started_ms": 4,
            "ended_ms": 5,
            "usage": _usage(),
        }
    )
    validate_receipt(receipt)

    wrong_lane = copy.deepcopy(receipt)
    wrong_lane["tasks"][0]["provider_attempts"][1]["lane"] = 2
    with pytest.raises(CapabilitySchemaError, match="does not match its lane"):
        validate_receipt(wrong_lane)

    late_cancel = copy.deepcopy(receipt)
    late_cancel["tasks"][0]["provider_attempts"][1]["ended_ms"] = 1001
    with pytest.raises(CapabilitySchemaError, match="exceeded settlement"):
        validate_receipt(late_cancel)

    post_cap_start = copy.deepcopy(receipt)
    post_cap_start["tasks"][0]["provider_attempts"][1].update(
        {"started_ms": 1001, "ended_ms": 1002}
    )
    post_cap_start["tasks"][0]["terminal_ms"] = 1002
    post_cap_start["time_series"][-1].update({"terminal": 5, "active": 1})
    post_cap_start["capacity"].update({"settlement_end_ms": 1002, "cleanup_end_ms": 1002})
    post_cap_start["capacity"]["active_at_cap"] = 1
    with pytest.raises(CapabilitySchemaError, match="started after the scoring cap"):
        validate_receipt(post_cap_start)


def test_post_cap_candidates_tools_and_terminal_evidence_are_rejected() -> None:
    receipt = _receipt()
    task = receipt["tasks"][0]
    task["candidate_checks"][0].update(
        {"candidate_returned_ms": 1001, "checker_started_ms": 1001, "checker_ended_ms": 1002}
    )
    task.update(
        {
            "first_unique_candidate_ms": 1001,
            "first_correct_ms": 1002,
            "qualification_ms": 1002,
            "terminal_ms": 1002,
        }
    )
    task["provider_attempts"][0]["ended_ms"] = 1001
    receipt["time_series"][-1].update({"terminal": 5, "active": 1})
    receipt["capacity"].update({"settlement_end_ms": 1002, "cleanup_end_ms": 1002})
    receipt["capacity"]["active_at_cap"] = 1
    with pytest.raises(CapabilitySchemaError, match="provider output|candidate/check"):
        validate_receipt(receipt)

    after_cleanup = _receipt()
    after_cleanup["tasks"][0]["terminal_ms"] = 2000
    after_cleanup["time_series"][-1].update({"terminal": 5, "active": 1})
    after_cleanup["capacity"]["active_at_cap"] = 1
    with pytest.raises(CapabilitySchemaError, match="terminal exceeded"):
        validate_receipt(after_cleanup)

    missing_provider_evidence = _receipt()
    task = missing_provider_evidence["tasks"][0]
    task.update(
        {
            "raw_correct": None,
            "first_correct_ms": None,
            "terminal_label": "provider_failure",
            "qualification": "inconclusive",
            "qualification_ms": None,
            "independent_check": "not_invoked",
            "independent_verification": None,
        }
    )
    task["candidate_checks"][0]["result"] = "inconclusive"
    missing_provider_evidence["sentinels"][0].update(
        {"passed": False, "terminal_label": "provider_failure"}
    )
    for target in (
        missing_provider_evidence["time_series"][-1],
        missing_provider_evidence["aggregate"],
    ):
        target.update(
            {"raw_correct_tasks": 0, "qualification_projected": 0, "independently_checked": 0}
        )
    with pytest.raises(CapabilitySchemaError, match="provider terminal lacks matching evidence"):
        validate_receipt(missing_provider_evidence)

    missing_tool_evidence = copy.deepcopy(missing_provider_evidence)
    missing_tool_evidence["tasks"][0]["terminal_label"] = "tool_absent"
    missing_tool_evidence["sentinels"][0]["terminal_label"] = "tool_absent"
    with pytest.raises(CapabilitySchemaError, match="tool terminal lacks matching evidence"):
        validate_receipt(missing_tool_evidence)


def test_nested_evidence_is_task_bound_and_axes_remain_separate() -> None:
    independent_mismatch = _receipt()
    independent_mismatch["tasks"][0]["independent_check"] = "incorrect"
    with pytest.raises(CapabilitySchemaError, match="independent result contradicts"):
        validate_receipt(independent_mismatch)

    early_tool = _receipt()
    early_tool["tasks"][0].update(
        {
            "tool_call_count": 1,
            "tool_attempts": [
                {
                    "ordinal": 1,
                    "status": "completed",
                    "started_ms": 0,
                    "ended_ms": 1,
                    "failure_label": None,
                }
            ],
        }
    )
    with pytest.raises(CapabilitySchemaError, match="precedes the task lifecycle"):
        validate_receipt(early_tool)

    late_candidate = _receipt()
    late_candidate["tasks"][0].update({"candidate_unique_count": 2, "checker_call_count": 2})
    late_candidate["tasks"][0]["candidate_checks"].append(
        {
            "ordinal": 2,
            "candidate_returned_ms": 5,
            "checker_started_ms": 5,
            "checker_ended_ms": 6,
            "result": "incorrect",
        }
    )
    with pytest.raises(CapabilitySchemaError, match="exceeds the task lifecycle"):
        validate_receipt(late_candidate)


def test_core_terminal_labels_require_matching_evidence() -> None:
    unstarted = _receipt()
    task = unstarted["tasks"][0]
    task.update(
        {
            "raw_correct": None,
            "first_correct_ms": None,
            "terminal_label": "unstarted_at_cap",
            "qualification": "inconclusive",
            "qualification_ms": None,
            "independent_check": "not_invoked",
            "independent_verification": None,
        }
    )
    task["candidate_checks"][0]["result"] = "inconclusive"
    with pytest.raises(CapabilitySchemaError, match="unstarted terminal contradicts"):
        validate_receipt(unstarted)

    incorrect = _receipt()
    task = incorrect["tasks"][0]
    task.update(
        {
            "raw_correct": False,
            "first_unique_candidate_ms": None,
            "first_correct_ms": None,
            "terminal_label": "incorrect",
            "candidate_unique_count": 0,
            "checker_call_count": 0,
            "candidate_checks": [],
            "qualification": "inconclusive",
            "qualification_ms": None,
            "independent_check": "not_invoked",
            "independent_verification": None,
        }
    )
    with pytest.raises(CapabilitySchemaError, match="incorrect terminal lacks checker evidence"):
        validate_receipt(incorrect)

    inconclusive = copy.deepcopy(incorrect)
    inconclusive["tasks"][0].update({"raw_correct": None, "terminal_label": "oracle_inconclusive"})
    with pytest.raises(CapabilitySchemaError, match="oracle terminal lacks checker evidence"):
        validate_receipt(inconclusive)


def test_service_evidence_is_bound_to_task_and_readiness_lifecycle() -> None:
    receipt = _receipt()
    receipt["service_attempts"] = [
        {
            "ordinal": 1,
            "task_id": "EAS-001",
            "status": "stopped",
            "started_ms": 5,
            "ready_ms": 5,
            "ended_ms": 6,
            "failure_label": None,
        }
    ]
    receipt["capacity"].update({"dynamic_instances_created": 1, "dynamic_instances_deleted": 1})
    with pytest.raises(CapabilitySchemaError, match="starts after task termination"):
        validate_receipt(receipt)

    bad_start_failure = copy.deepcopy(receipt)
    bad_start_failure["service_attempts"][0].update(
        {
            "status": "start_failure",
            "started_ms": 1,
            "ready_ms": 1,
            "ended_ms": 2,
            "failure_label": "service_start_failure",
        }
    )
    with pytest.raises(CapabilitySchemaError, match="failed readiness but reports ready"):
        validate_receipt(bad_start_failure)

    lost_without_ready = copy.deepcopy(receipt)
    lost_without_ready["service_attempts"][0].update(
        {
            "status": "lost",
            "started_ms": 1,
            "ready_ms": None,
            "ended_ms": 2,
            "failure_label": "service_lost",
        }
    )
    with pytest.raises(CapabilitySchemaError, match="ready lifecycle evidence is missing"):
        validate_receipt(lost_without_ready)


def test_final_capacity_requires_exact_cap_or_explicit_early_drain() -> None:
    receipt = _receipt()
    _as_final_capacity(receipt)
    with pytest.raises(CapabilitySchemaError, match="early-drain"):
        validate_receipt(receipt)

    receipt["aggregate"]["undersized_reservoir"] = True
    validate_receipt(receipt)

    closed_at_boundary = copy.deepcopy(receipt)
    closed_at_boundary["capacity"]["unstarted_at_cap"] = 83
    with pytest.raises(CapabilitySchemaError, match="cap snapshot"):
        validate_receipt(closed_at_boundary)


def test_cap_snapshot_is_half_open_at_terminal_boundary() -> None:
    receipt = _receipt()
    receipt["tasks"][0]["terminal_ms"] = 1000
    validate_receipt(receipt)

    false_active = copy.deepcopy(receipt)
    false_active["capacity"]["active_at_cap"] = 1
    with pytest.raises(CapabilitySchemaError, match="cap snapshot"):
        validate_receipt(false_active)


def test_cap_snapshot_excludes_already_terminal_unstarted_tasks() -> None:
    receipt = _receipt()
    task = receipt["tasks"][0]
    task.update(
        {
            "started": False,
            "started_ms": None,
            "first_unique_candidate_ms": None,
            "first_correct_ms": None,
            "terminal_label": "fixture_invalid",
            "raw_correct": None,
            "qualification": "inconclusive",
            "qualification_ms": None,
            "independent_check": "not_invoked",
            "independent_verification": None,
            "candidate_unique_count": 0,
            "checker_call_count": 0,
            "candidate_checks": [],
            "provider_invocation_count": 0,
            "provider_attempts": [],
            "cleanup_passed": None,
        }
    )
    receipt["sentinels"][0].update({"passed": False, "terminal_label": "fixture_invalid"})
    receipt["aggregate"]["unstarted"] = 1
    receipt["capacity"].update({"queue_at_cap": 1, "unstarted_at_cap": 1})
    with pytest.raises(CapabilitySchemaError, match="cap snapshot"):
        validate_receipt(receipt)


def test_receipt_preserves_privacy_failures_and_complete_human_decisions() -> None:
    receipt = _receipt()
    task = receipt["tasks"][0]
    task["raw_correct"] = None
    task["first_correct_ms"] = None
    task["terminal_label"] = "privacy_boundary"
    task["qualification"] = "inconclusive"
    task["qualification_ms"] = None
    task["independent_check"] = "not_invoked"
    task["independent_verification"] = None
    task["candidate_checks"][0]["result"] = "inconclusive"
    receipt["sentinels"][0]["passed"] = False
    receipt["sentinels"][0]["terminal_label"] = "privacy_boundary"
    for target in (receipt["time_series"][-1], receipt["aggregate"]):
        target["raw_correct_tasks"] = 0
        target["qualification_projected"] = 0
        target["independently_checked"] = 0
    receipt["failure_counts"]["privacy"] = 1
    receipt["human_decisions"].append(
        {
            "delta_id": "delta-1",
            "decision": "approve",
            "approver": "owner",
            "decided_at": "2026-09-20T12:34:56Z",
            "evidence_ids": ["evidence-1"],
            "uncertainty": [],
            "regression_risks": [],
            "rollback": "revert-delta-1",
        }
    )
    validate_receipt(receipt)


def test_public_scan_rejects_private_fields_and_paths() -> None:
    receipt = _receipt()
    receipt["tasks"][0]["candidate_value"] = "redacted"
    with pytest.raises(CapabilitySchemaError, match="forbidden public key"):
        validate_receipt(receipt)

    receipt = _receipt()
    receipt["human_decisions"].append(
        {
            "delta_id": "example",
            "decision": "defer",
            "approver": None,
            "evidence_ids": [],
            "rollback": "/Users/example/private-command",
        }
    )
    with pytest.raises(CapabilitySchemaError, match="forbidden public value"):
        validate_receipt(receipt)

    for fingerprint in ("a" * 40, "b" * 64, "run-" + "c" * 40):
        receipt = _receipt()
        receipt["tasks"][0]["provider_attempts"][0]["effective_revision_build"] = fingerprint
        with pytest.raises(CapabilitySchemaError, match="forbidden public value"):
            validate_receipt(receipt)

    for authority in ("target.example.com", "10.20.30.40", "2001:db8::1"):
        receipt = _receipt()
        receipt["tasks"][0]["provider_attempts"][0]["effective_revision_build"] = authority
        with pytest.raises(CapabilitySchemaError, match="forbidden public value"):
            validate_receipt(receipt)

    receipt = _receipt()
    receipt["human_decisions"].append(
        {
            "delta_id": "example",
            "decision": "defer",
            "approver": None,
            "evidence_ids": [],
            "rollback": "/Volumes/private/run",
        }
    )
    with pytest.raises(CapabilitySchemaError, match="forbidden public value"):
        validate_receipt(receipt)
