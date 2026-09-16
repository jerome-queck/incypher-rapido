from __future__ import annotations

import json
from pathlib import Path

PROTOCOL_PATH = (
    Path(__file__).resolve().parents[1]
    / "notes"
    / "research"
    / "issue-19-routing-operation-count-protocol-v1.json"
)
PARENT_PATH = PROTOCOL_PATH.with_name("issue-19-routing-comparison-protocol-v1.json")


def _invokes_policy(
    payload: dict[str, object], *, parent: dict[str, object], addendum: dict[str, object]
) -> bool:
    failure_kind = payload["failure_kind"]
    facts = payload["facts"]
    assert isinstance(facts, list)
    fact_types = {fact["fact_type"] for fact in facts}
    predicate = addendum["policy_invocation_contract"]["input_derived_predicate"]
    recognized = set(parent["fact_types"]) | set(predicate["recognized_non_authorizing_fact_types"])
    failure_kinds = {recipe["failure_kind"] for recipe in parent["route_recipes"].values()}
    if failure_kind is None or failure_kind not in failure_kinds:
        return False
    if any(fact["fact_type"] not in recognized for fact in facts):
        return False
    if any(fact["scope"] != "same_run_challenge_episode" for fact in facts):
        return False
    if {"private_candidate_proposal", "unsafe_native_failure"} <= fact_types:
        return False
    if any(
        fact["fact_type"] == "private_candidate_proposal"
        and fact["value"] == "multiple_verified_identities"
        for fact in facts
    ):
        return False
    if failure_kind == "board" and "indeterminate_board_observation" in fact_types:
        return False
    if payload["attempts_remaining"] is not True:
        return False
    if payload["remaining_milliseconds"] < 1000:
        return False
    return bool((payload["effects_safe"] and payload["instances_safe"]) or failure_kind == "board")


def _operation_count(arm: str, payload: dict[str, object], parent: dict[str, object]) -> int:
    if arm == "fifo_unchanged":
        return 1
    fact_types = {fact["fact_type"] for fact in payload["facts"]}
    failure_kind = payload["failure_kind"]
    if arm == "closed_rule_table":
        entries = parent["policy_configs"][arm]["rules"]
        base_per_entry = 2
        initial = 0
    elif arm == "graph_reducer":
        entries = parent["policy_configs"][arm]["transitions"]
        base_per_entry = 3
        initial = 1 + 2 * len(payload["facts"])
    else:
        operations = 0
        for recipe_id in sorted(parent["route_recipes"]):
            recipe = parent["route_recipes"][recipe_id]
            operations += 2
            if recipe["failure_kind"] != failure_kind:
                continue
            operations += len(recipe["required_facts"])
            if set(recipe["required_facts"]) <= fact_types:
                operations += 3
        return operations + 1
    operations = initial
    for entry in entries:
        operations += base_per_entry
        if entry["failure_kind"] != failure_kind:
            continue
        operations += len(entry["requires_all"])
        if set(entry["requires_all"]) <= fact_types:
            return operations + 1
    return operations


def test_operation_protocol_is_parent_bound_and_prospective() -> None:
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    assert protocol["schema_version"] == 1
    assert protocol["registered_before_implementation_measurement"] is True
    assert protocol["result_generated"] is False
    assert protocol["source_base_commit"] == "ecee4aec53e609fb2941548d9716171580eef2ea"
    assert (
        protocol["parent_protocol_sha256"]
        == "bc7a219c92e893b188584c4567bbb04b97d9be4ffaeaee90aa12d749ce5b5ef6"
    )


def test_operation_protocol_freezes_all_arms_and_excludes_common_work() -> None:
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    parent = json.loads(PARENT_PATH.read_text(encoding="utf-8"))
    assert set(protocol["operation_units"]) == {
        "fifo_unchanged",
        "closed_rule_table",
        "graph_reducer",
        "scored_policy",
    }
    assert all(protocol["operation_units"].values())
    assert len(protocol["common_work_excluded"]) == 7
    assert len(protocol["tamper_requirements"]) == 6
    expected_bytes = {
        "closed_rule_table": 1012,
        "fifo_unchanged": 140,
        "graph_reducer": 1427,
        "scored_policy": 429,
    }
    assert protocol["canonical_config_bytes"]["expected_by_arm"] == expected_bytes
    assert {
        arm: len(
            json.dumps(
                config,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        for arm, config in parent["policy_configs"].items()
    } == expected_bytes


def test_policy_invocation_and_gate_order_are_exact() -> None:
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    parent = json.loads(PARENT_PATH.read_text(encoding="utf-8"))
    invocation = protocol["policy_invocation_contract"]
    invoked = set(invocation["invoked_case_ids"])
    skipped = set(invocation["skipped_case_ids"])
    assert len(invoked) == 19
    assert len(skipped) == 8
    assert invoked.isdisjoint(skipped)
    parent_case_ids = [case["id"] for case in parent["cases"]]
    assert [case_id for case_id in parent_case_ids if case_id in invoked] == invocation[
        "invoked_case_ids"
    ]
    assert [case_id for case_id in parent_case_ids if case_id in skipped] == invocation[
        "skipped_case_ids"
    ]
    assert invoked | skipped == set(parent_case_ids)

    derived_invoked = []
    derived_skipped = []
    for case in parent["cases"]:
        payload = dict(parent["fixture_payload_defaults"])
        if case["fact_profile"] != "none":
            payload.update(parent["fixture_payload_overrides"][case["fact_profile"]])
        payload["failure_kind"] = case["failure_kind"]
        payload["failure_subreason"] = parent["failure_subreason_by_case"][case["id"]]
        target = (
            derived_invoked
            if _invokes_policy(payload, parent=parent, addendum=protocol)
            else derived_skipped
        )
        target.append(case["id"])
    assert derived_invoked == invocation["invoked_case_ids"]
    assert derived_skipped == invocation["skipped_case_ids"]
    assert invocation["operation_count_when_skipped"] == 0
    assert len(invocation["pre_policy_gate_order"]) == 7
    assert len(invocation["post_policy_gate_order"]) == 7
    assert invocation["config_bytes_per_row"].startswith("record the canonical byte length")
    predicate = invocation["input_derived_predicate"]
    assert len(predicate["ordered_precontain_predicates"]) == 11
    assert len(predicate["recognized_non_authorizing_fact_types"]) == 5


def test_measurement_domains_raw_semantics_and_totals_are_frozen() -> None:
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    parent = json.loads(PARENT_PATH.read_text(encoding="utf-8"))
    accounting = protocol["measurement_accounting"]
    assert accounting["tool_call_count"].startswith("exactly 0")
    assert len(accounting["replay_digest"]["fields"]) == 12
    assert len(accounting["replay_digest"]["excluded"]) == 6
    assert "operation_count" not in accounting["replay_digest"]["fields"]
    assert "fact_metadata_digest" not in accounting
    assert accounting["comparison_host_binding"]["rule"].endswith(
        "source_fact_public_metadata_digest"
    )
    completed = protocol["raw_row_semantics"]["completed_case"]
    assert completed["decision_sequence"] is None
    assert completed["policy_operation_count"] == 0
    assert set(completed) <= set(parent["observation_fields"])
    assert protocol["result_container_schema"]["exact_top_level_fields"] == [
        "schema_version",
        "protocol",
        "fixture",
        "observations",
        "gate",
        "provenance",
        "selection",
    ]
    expected_totals = {
        "closed_rule_table": 5120,
        "fifo_unchanged": 380,
        "graph_reducer": 8440,
        "scored_policy": 7500,
    }
    assert protocol["expected_twenty_repetition_operation_totals"] == expected_totals
    totals = {arm: 0 for arm in parent["arms"]}
    for case in parent["cases"]:
        payload = dict(parent["fixture_payload_defaults"])
        if case["fact_profile"] != "none":
            payload.update(parent["fixture_payload_overrides"][case["fact_profile"]])
        payload["failure_kind"] = case["failure_kind"]
        payload["failure_subreason"] = parent["failure_subreason_by_case"][case["id"]]
        if not _invokes_policy(payload, parent=parent, addendum=protocol):
            continue
        for arm in totals:
            totals[arm] += (
                _operation_count(arm, payload, parent) * parent["common_config"]["repetitions"]
            )
    assert totals == expected_totals
