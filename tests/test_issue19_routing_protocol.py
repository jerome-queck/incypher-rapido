from __future__ import annotations

import hashlib
import json
from pathlib import Path

from rapido.routing import FAILURE_KINDS, RouteSpec

PROTOCOL_PATH = (
    Path(__file__).resolve().parents[1]
    / "notes"
    / "research"
    / "issue-19-routing-comparison-protocol-v1.json"
)


def _protocol() -> dict[str, object]:
    return json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def test_protocol_is_registered_before_measurement_with_equal_arm_budgets() -> None:
    protocol = _protocol()
    assert protocol["schema_version"] == 1
    assert protocol["registered_before_measurement"] is True
    assert protocol["result_generated"] is False
    assert protocol["source_base_commit"] == "ae3da51aa675b6fdcfb1cbfe50a33cf5fbc4c954"
    assert protocol["arms"] == [
        "fifo_unchanged",
        "closed_rule_table",
        "graph_reducer",
        "scored_policy",
    ]
    assert protocol["common_config"] == {
        "active_challenges": 1,
        "attempt_seconds": 15,
        "attempts_per_challenge": 2,
        "concurrency": 2,
        "episodes_per_challenge": 3,
        "model": "gpt-daybreak-blue-latest",
        "reasoning_effort": "xhigh",
        "repetitions": 20,
        "run_seconds": 60,
    }
    assert all(protocol["disabled_surfaces"].values())


def test_protocol_covers_positive_and_negative_facts_for_all_eight_failure_kinds() -> None:
    protocol = _protocol()
    cases = protocol["cases"]
    assert isinstance(cases, list)
    for kind in FAILURE_KINDS:
        matching = [case for case in cases if case["failure_kind"] == kind]
        assert any(case["expected"] == "dispatch" for case in matching)
        assert any(case["expected"] == "contain" for case in matching)
    assert {case["id"] for case in cases} >= {
        "completed",
        "mixed_failure_quarantine",
        "duplicate_route",
        "deadline_exhausted",
        "episode_budget_exhausted",
        "persistent_failure_no_third_route",
    }
    assert len(cases) == 27
    case_ids = {case["id"] for case in cases}
    assert set(protocol["failure_subreason_by_case"]) == case_ids
    overrides = protocol["fixture_payload_overrides"]
    assert all(
        case["fact_profile"] == "none" or case["fact_profile"] in overrides for case in cases
    )

    evaluator = protocol["evaluator_contract"]
    dispatched = {case["id"] for case in cases if case["expected"] == "dispatch"}
    assert set(evaluator["expected_recipe_by_case"]) == dispatched
    projection = set(protocol["fixture_execution"]["policy_input_projection"])
    forbidden = set(protocol["fixture_execution"]["policy_must_not_receive"])
    assert projection.isdisjoint(forbidden)
    assert {"case_id", "expected", "expected_recipe_id"} <= forbidden


def test_protocol_freezes_fixture_policies_routes_and_budgets_by_digest() -> None:
    protocol = _protocol()
    fixture_payload = {
        "manifest": protocol["fixture_manifest"],
        "defaults": protocol["fixture_payload_defaults"],
        "overrides": protocol["fixture_payload_overrides"],
        "failure_subreason_by_case": protocol["failure_subreason_by_case"],
        "evaluator_contract": protocol["evaluator_contract"],
    }
    evaluation_contract = {
        key: protocol[key]
        for key in (
            "common_authority_gate",
            "disabled_surfaces",
            "fixture_execution",
            "observation_fields",
            "observation_schema",
            "selection_gate",
            "raw_derivation_contract",
            "required_measurement_tests",
            "result_provenance_contract",
            "tamper_gates",
            "prerequisite_status",
            "fifo_comparator_contract",
        )
    }
    frozen = protocol["frozen_digests"]
    assert frozen == {
        "cases": _digest(protocol["cases"]),
        "common_config": _digest(protocol["common_config"]),
        "evaluation_contract": _digest(evaluation_contract),
        "fixture_payload": _digest(fixture_payload),
        "policy_configs": _digest(protocol["policy_configs"]),
        "recipe_budgets": _digest(protocol["recipe_budgets"]),
        "route_recipes": _digest(protocol["route_recipes"]),
        "route_templates": _digest(protocol["route_templates"]),
    }

    recipes = protocol["route_recipes"]
    recipe_ids = set(recipes)
    comparator_id = protocol["fifo_comparator_contract"]["recipe"]["recipe_id"]
    assert set(protocol["recipe_budgets"]) == recipe_ids | {comparator_id}
    assert set(protocol["route_templates"]) == recipe_ids | {"baseline_v1", comparator_id}
    baseline = RouteSpec.from_dict(protocol["route_templates"]["baseline_v1"])
    for recipe_id, recipe in recipes.items():
        successor = RouteSpec.from_dict(protocol["route_templates"][recipe_id])
        assert list(baseline.changed_axes(successor)) == recipe["changed_axes"]
        assert successor.model == "gpt-daybreak-blue-latest"
        assert successor.effort == "xhigh"
        assert successor.effect_policy == "controller_only"
        budget = protocol["recipe_budgets"][recipe_id]
        assert budget["attempt_seconds"] == successor.attempt_seconds == 15
        assert budget["max_dispatches_per_challenge_failure_kind"] == 1
        assert budget["max_successor_episodes"] == 1
        assert budget["run_deadline_reset"] is False
    comparator = RouteSpec.from_dict(protocol["route_templates"][comparator_id])
    assert comparator == baseline
    assert protocol["recipe_budgets"][comparator_id]["attempt_seconds"] == 15


def test_policy_configs_are_exact_parallel_recipe_selectors_and_fifo_is_not_selectable() -> None:
    protocol = _protocol()
    configs = protocol["policy_configs"]
    recipes = protocol["route_recipes"]
    recipe_ids = set(recipes)
    expected_order = [
        "policy",
        "provenance",
        "disagreement",
        "timeout",
        "tool",
        "quota",
        "board",
        "container",
    ]
    rules = configs["closed_rule_table"]["rules"]
    transitions = configs["graph_reducer"]["transitions"]
    assert [rule["failure_kind"] for rule in rules] == expected_order
    assert [edge["failure_kind"] for edge in transitions] == expected_order
    assert {rule["recipe_id"] for rule in rules} == recipe_ids
    assert {edge["recipe_id"] for edge in transitions} == recipe_ids
    assert set(configs["scored_policy"]["recipe_weights"]) == recipe_ids
    for entry in (*rules, *transitions):
        assert entry["requires_all"] == recipes[entry["recipe_id"]]["required_facts"]
    assert configs["fifo_unchanged"]["selectable"] is False
    assert protocol["fifo_comparator_contract"]["selectable"] is False
    assert "only the changed-route" in protocol["fifo_comparator_contract"]["common_gate_exception"]


def test_fifo_has_nonzero_baseline_and_gate_negatives_are_otherwise_authorized() -> None:
    protocol = _protocol()
    evaluator = protocol["evaluator_contract"]
    fifo_schedule = evaluator["fifo_comparator_success_repetitions"]
    changed_schedule = evaluator["correct_recipe_success_repetitions"]
    assert fifo_schedule
    assert set(fifo_schedule) < set(range(protocol["common_config"]["repetitions"]))
    assert len(fifo_schedule) < len(changed_schedule)

    cases = {case["id"]: case for case in protocol["cases"]}
    assert cases["persistent_failure_no_third_route"]["failure_kind"] == "tool"
    overrides = protocol["fixture_payload_overrides"]
    required_fact_by_case = {
        "container_effect_fenced": "typed_local_container_origin",
        "deadline_exhausted": "alternate_tool_representation",
        "duplicate_route": "alternate_tool_representation",
        "episode_budget_exhausted": "alternate_tool_representation",
        "persistent_failure_no_third_route": "alternate_tool_representation",
    }
    for case_id, fact_type in required_fact_by_case.items():
        profile = cases[case_id]["fact_profile"]
        assert fact_type in {fact["fact_type"] for fact in overrides[profile]["facts"]}


def test_protocol_freezes_common_authority_and_raw_derived_selection() -> None:
    protocol = _protocol()
    recipes = protocol["route_recipes"]
    assert {recipe["failure_kind"] for recipe in recipes.values()} == set(FAILURE_KINDS)
    assert all(recipe["changed_axes"] for recipe in recipes.values())
    gate = protocol["selection_gate"]
    assert gate["eligible_policy_arms"] == [
        "closed_rule_table",
        "graph_reducer",
        "scored_policy",
    ]
    assert gate["ties"] == "no_selection"
    assert gate["require_unique_winner"] is True
    assert gate["require_strict_total_improvement_vs_fifo"] is True
    assert "elapsed_seconds" in gate["descriptive_only"]
    assert protocol["observation_schema"]["cardinality"].endswith("2160 rows")
    fields = protocol["observation_fields"]
    assert {"repetition", "terminal_outcome", "positive_conversion", "replay_digest"} <= set(fields)
    assert "repetition_count" not in fields
    assert "source_fact_digest" not in fields
    assert (
        "candidate values" in protocol["observation_schema"]["source_fact_public_metadata_digest"]
    )
    assert len(protocol["required_measurement_tests"]) == 10
    assert len(protocol["tamper_gates"]) == 5
    provenance = protocol["result_provenance_contract"]
    assert "scripts/issue19_routing_policy_comparison.py" in provenance["canonical_command"]
    assert "every rapido/**/*.py source file" in provenance["required_file_hashes"]
    assert len(provenance["environment_fields"]) == 9
    assert provenance["source_mismatch"].startswith("refuse measurement")
    assert protocol["prerequisite_status"] == {
        "board_recipes_live_locked_until_e6": True,
        "fixture_facts_never_authorize_live_dispatch": True,
        "policy_recipes_live_locked_until_e1": True,
    }
    assert all(protocol["disabled_surfaces"].values())
