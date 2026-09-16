from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from rapido.routing import FailureSignal, RouteRequest, baseline_route, route_failure
from rapido.routing_policy import (
    ComparisonContract,
    PolicyInput,
    authorize_comparison_evaluation,
    evaluate_comparison_policy,
)

ROOT = Path(__file__).resolve().parents[1]
PARENT_PATH = ROOT / "notes/research/issue-19-routing-comparison-protocol-v1.json"
OPERATION_PATH = ROOT / "notes/research/issue-19-routing-operation-count-protocol-v1.json"


def _documents() -> tuple[dict[str, object], dict[str, object]]:
    return (
        json.loads(PARENT_PATH.read_text(encoding="utf-8")),
        json.loads(OPERATION_PATH.read_text(encoding="utf-8")),
    )


def _contract() -> ComparisonContract:
    parent, operation = _documents()
    return ComparisonContract.from_documents(parent, operation)


def _case_payload(parent: dict[str, object], case: dict[str, object]) -> dict[str, object]:
    payload = copy.deepcopy(parent["fixture_payload_defaults"])
    if case["fact_profile"] != "none":
        payload.update(copy.deepcopy(parent["fixture_payload_overrides"][case["fact_profile"]]))
    payload["failure_kind"] = case["failure_kind"]
    payload["failure_subreason"] = parent["failure_subreason_by_case"][case["id"]]
    return payload


def test_policy_projection_is_strict_typed_and_oracle_blind() -> None:
    parent, _ = _documents()
    case = next(case for case in parent["cases"] if case["id"] == "policy_authorized_context")
    payload = _case_payload(parent, case)

    projected = PolicyInput.from_dict(payload)

    assert list(projected.as_dict()) == parent["fixture_execution"]["policy_input_projection"]
    assert set(projected.as_dict()).isdisjoint(
        parent["fixture_execution"]["policy_must_not_receive"]
    )
    for key in ("case_id", "expected", "repetition"):
        altered = copy.deepcopy(payload)
        altered[key] = "oracle"
        with pytest.raises(ValueError, match="policy input shape"):
            PolicyInput.from_dict(altered)
    malformed = copy.deepcopy(payload)
    malformed["facts"][0]["value"] = {"nested": "forbidden"}
    with pytest.raises((TypeError, ValueError), match="fact"):
        PolicyInput.from_dict(malformed)


def test_invocation_is_derived_from_projection_and_matches_registered_partition() -> None:
    parent, operation = _documents()
    contract = ComparisonContract.from_documents(parent, operation)
    observed_invoked: list[str] = []
    observed_skipped: list[str] = []
    for case in parent["cases"]:
        value = PolicyInput.from_dict(_case_payload(parent, case))
        evaluation = evaluate_comparison_policy("closed_rule_table", value, contract)
        target = observed_invoked if evaluation.invoked else observed_skipped
        target.append(case["id"])

    invocation = operation["policy_invocation_contract"]
    assert observed_invoked == invocation["invoked_case_ids"]
    assert observed_skipped == invocation["skipped_case_ids"]


def test_four_frozen_policies_choose_only_recipe_ids_and_match_operation_totals() -> None:
    parent, operation = _documents()
    contract = ComparisonContract.from_documents(parent, operation)
    expected_recipes = parent["evaluator_contract"]["expected_recipe_by_case"]
    totals = {arm: 0 for arm in parent["arms"]}

    for case in parent["cases"]:
        value = PolicyInput.from_dict(_case_payload(parent, case))
        for arm in parent["arms"]:
            evaluation = evaluate_comparison_policy(arm, value, contract)
            totals[arm] += evaluation.operation_count * parent["common_config"]["repetitions"]
            if not evaluation.invoked:
                assert evaluation.recipe_id is None
                assert evaluation.operation_count == 0
            elif arm == "fifo_unchanged":
                assert evaluation.recipe_id == "repeat_source_route_comparator_v1"
            elif case["id"] in expected_recipes:
                assert evaluation.recipe_id == expected_recipes[case["id"]]
            elif case["id"] in {"duplicate_route", "persistent_failure_no_third_route"}:
                assert evaluation.recipe_id == "tool_alternate_representation_v1"
            else:
                assert evaluation.recipe_id is None

    assert totals == operation["expected_twenty_repetition_operation_totals"]


def test_common_authority_materializes_routes_and_contains_every_negative() -> None:
    parent, _ = _documents()
    contract = _contract()
    expected_recipes = parent["evaluator_contract"]["expected_recipe_by_case"]

    for case in parent["cases"]:
        value = PolicyInput.from_dict(_case_payload(parent, case))
        for arm in parent["selection_gate"]["eligible_policy_arms"]:
            evaluation = evaluate_comparison_policy(arm, value, contract)
            decision = authorize_comparison_evaluation(value, evaluation, contract)
            expected = case["expected"]
            assert decision.disposition == expected.replace("no_route", "no_route")
            if expected == "dispatch":
                assert decision.recipe_id == expected_recipes[case["id"]]
                assert decision.successor is not None
                assert decision.changed_axes == tuple(
                    parent["route_recipes"][decision.recipe_id]["changed_axes"]
                )
                assert decision.successor.model == "gpt-daybreak-blue-latest"
                assert decision.successor.effort == "xhigh"
                assert decision.successor.effect_policy == "controller_only"
            else:
                assert decision.successor is None
                assert decision.changed_axes == ()
                if case["id"] == "duplicate_route":
                    assert decision.reason == "route fingerprint was already used"
                if case["id"] == "persistent_failure_no_third_route":
                    assert decision.reason == "route did not materially change"


def test_fifo_is_nonselectable_but_retains_only_unchanged_route_exemption() -> None:
    parent, _ = _documents()
    contract = _contract()
    for case in parent["cases"]:
        value = PolicyInput.from_dict(_case_payload(parent, case))
        evaluation = evaluate_comparison_policy("fifo_unchanged", value, contract)
        decision = authorize_comparison_evaluation(value, evaluation, contract)
        if case["id"] == "completed":
            assert decision.disposition == "no_route"
        elif evaluation.invoked:
            assert decision.disposition == "dispatch"
            assert decision.source_fingerprint == decision.successor_fingerprint
            assert decision.changed_axes == ()
        else:
            assert decision.disposition == "contain"


def test_policy_and_board_fixture_routes_do_not_unlock_live_router() -> None:
    current = baseline_route(
        model="gpt-daybreak-blue-latest",
        effort="xhigh",
        attempt_seconds=15,
    )
    for kind, subreason in (("policy", "cyber_policy"), ("board", "board_catch_boundary_failure")):
        decision = route_failure(
            RouteRequest(
                failure=FailureSignal(kind, subreason),
                current=current,
                used_fingerprints=frozenset({current.fingerprint}),
                attempts_remaining=True,
                remaining_milliseconds=10_000,
            )
        )
        assert decision.disposition == "contain"
        assert decision.successor is None


def test_contract_rejects_post_registration_policy_or_route_mutation() -> None:
    parent, operation = _documents()
    for mutation in ("policy", "route"):
        altered = copy.deepcopy(parent)
        if mutation == "policy":
            altered["policy_configs"]["scored_policy"]["recipe_weights"][
                "tool_alternate_representation_v1"
            ] += 1
        else:
            altered["route_templates"]["tool_alternate_representation_v1"]["tactic"] = "mutated"
        with pytest.raises(ValueError, match="frozen"):
            ComparisonContract.from_documents(altered, operation)

    contract = ComparisonContract.from_documents(parent, operation)
    contract.policy_configs["scored_policy"]["failure_match_weight"] += 1
    value = PolicyInput.from_dict(
        _case_payload(
            parent,
            next(case for case in parent["cases"] if case["id"] == "tool_alternate_representation"),
        )
    )
    with pytest.raises(ValueError, match="contract changed"):
        evaluate_comparison_policy("scored_policy", value, contract)
