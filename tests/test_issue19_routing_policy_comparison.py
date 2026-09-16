from __future__ import annotations

import _socket
import copy
import importlib.util
import json
import subprocess
import sys
import threading
from pathlib import Path
from types import FunctionType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "issue19_routing_policy_comparison",
    ROOT / "scripts" / "issue19_routing_policy_comparison.py",
)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


def _row(
    observations: list[dict[str, object]], arm: str, case: str, repetition: int = 0
) -> dict[str, object]:
    return next(
        row
        for row in observations
        if row["arm"] == arm and row["case"] == case and row["repetition"] == repetition
    )


def test_two_repetition_comparison_is_strict_raw_and_selects_closed_table(
    tmp_path: Path,
) -> None:
    result = HARNESS.run_comparison(tmp_path / "run", repetitions=2, require_clean_source=False)

    assert list(result) == [
        "schema_version",
        "protocol",
        "fixture",
        "observations",
        "gate",
        "provenance",
        "selection",
    ]
    assert len(result["observations"]) == 216
    assert all(
        set(row) == set(HARNESS.PARENT["observation_fields"]) for row in result["observations"]
    )
    assert result["gate"] == HARNESS.recompute_gate(result["observations"], repetitions=2)
    assert result["gate"]["passed"] is True
    assert result["gate"]["selected"] == "closed_rule_table"
    assert result["selection"]["arm"] == "closed_rule_table"
    summaries = result["gate"]["arm_summaries"]
    assert summaries["fifo_unchanged"]["positive_conversion"] == 9
    for arm in HARNESS.PARENT["selection_gate"]["eligible_policy_arms"]:
        assert summaries[arm]["positive_conversion"] == 18
    assert (
        summaries["closed_rule_table"]["policy_operation_count"]
        < summaries["graph_reducer"]["policy_operation_count"]
    )
    assert (
        summaries["closed_rule_table"]["policy_operation_count"]
        < summaries["scored_policy"]["policy_operation_count"]
    )
    stored = json.loads(json.dumps(result, sort_keys=True))
    HARNESS.validate_result(stored, repetitions=2)


def test_execution_rotates_but_rows_are_canonical_and_artifacts_are_cleaned(
    tmp_path: Path,
) -> None:
    root = tmp_path / "run"
    result = HARNESS.run_comparison(root, repetitions=2, require_clean_source=False)

    expected_identity = [
        (repetition, arm, case["id"])
        for repetition in range(2)
        for arm in HARNESS.PARENT["arms"]
        for case in HARNESS.PARENT["cases"]
    ]
    assert [
        (row["repetition"], row["arm"], row["case"]) for row in result["observations"]
    ] == expected_identity
    assert result["fixture"]["arm_execution_order"] == [
        HARNESS.PARENT["arms"],
        HARNESS.PARENT["arms"][1:] + HARNESS.PARENT["arms"][:1],
    ]
    assert result["fixture"]["lane_completion_order"] == [[0, 1], [1, 0]]
    assert list(root.iterdir()) == []
    assert all(row["workspace_residue"] == 0 for row in result["observations"])


def test_gate_rejects_raw_structure_safety_and_registered_cost_tampering(tmp_path: Path) -> None:
    result = HARNESS.run_comparison(tmp_path / "run", repetitions=2, require_clean_source=False)
    observations = result["observations"]
    mutations: list[list[dict[str, object]]] = []

    missing = copy.deepcopy(observations)
    missing.pop()
    mutations.append(missing)
    reordered = copy.deepcopy(observations)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    mutations.append(reordered)
    extra = copy.deepcopy(observations)
    extra[0]["unregistered"] = True
    mutations.append(extra)
    for field in (
        "false_dispatch",
        "candidate_leak",
        "model_effort_mismatch",
        "policy_operation_count",
        "policy_config_bytes",
        "context_bytes",
        "durable_event_bytes",
        "tool_call_count",
    ):
        altered = copy.deepcopy(observations)
        altered[0][field] += 1
        mutations.append(altered)

    for altered in mutations:
        assert HARNESS.recompute_gate(altered, repetitions=2)["passed"] is False

    changed_fact_sequence = copy.deepcopy(observations)
    changed_fact_sequence[1]["fact_event_sequences"][0] += 1
    assert HARNESS.recompute_gate(changed_fact_sequence, repetitions=2)["passed"] is False

    changed_digest = copy.deepcopy(observations)
    changed_digest[0]["policy_input_digest"] = "0" * 64
    assert HARNESS.recompute_gate(changed_digest, repetitions=2)["passed"] is False


def test_raw_row_recomputation_handles_permutations_every_winner_and_ties(
    tmp_path: Path,
) -> None:
    result = HARNESS.run_comparison(tmp_path / "run", repetitions=2, require_clean_source=False)
    observations = result["observations"]
    arms = HARNESS.PARENT["selection_gate"]["eligible_policy_arms"]
    for winner in arms:
        synthetic = copy.deepcopy(observations)
        for row in synthetic:
            if row["arm"] in arms:
                row["context_bytes"] = int(row["arm"] != winner)
        summaries, fifo_total = HARNESS.summarize_observations(synthetic)
        assert HARNESS.select_arm(summaries, fifo_total=fifo_total) == winner

    permutation = dict(zip(arms, arms[1:] + arms[:1], strict=True))
    permuted = copy.deepcopy(observations)
    for row in permuted:
        if row["arm"] in permutation:
            row["arm"] = permutation[row["arm"]]
    summaries, fifo_total = HARNESS.summarize_observations(permuted)
    assert (
        HARNESS.select_arm(summaries, fifo_total=fifo_total)
        == permutation[result["gate"]["selected"]]
    )

    tied = copy.deepcopy(observations)
    for row in tied:
        if row["arm"] in arms:
            for field in (
                "tool_call_count",
                "context_bytes",
                "durable_event_bytes",
                "policy_operation_count",
                "policy_config_bytes",
            ):
                row[field] = 0
    summaries, fifo_total = HARNESS.summarize_observations(tied)
    assert HARNESS.select_arm(summaries, fifo_total=fifo_total) is None

    ineligible = copy.deepcopy(tied)
    for row in ineligible:
        if row["arm"] in arms:
            row["candidate_leak"] = 1
    summaries, fifo_total = HARNESS.summarize_observations(ineligible)
    assert HARNESS.select_arm(summaries, fifo_total=fifo_total) is None


def test_result_contains_no_private_canary_or_disabled_surface_call(tmp_path: Path) -> None:
    result = HARNESS.run_comparison(tmp_path / "run", repetitions=1, require_clean_source=False)
    encoded = json.dumps(result, sort_keys=True)
    assert all(canary not in encoded for canary in HARNESS._private_encodings(0))
    assert result["provenance"]["disabled_surface_calls"] == {
        "containers": 0,
        "external_board": 0,
        "instances": 0,
        "model_inference": 0,
        "network": 0,
        "submissions": 0,
    }
    assert all(row["candidate_leak"] == 0 for row in result["observations"])
    assert all(row["tool_call_count"] == 0 for row in result["observations"])


def test_disabled_surface_monitor_counts_real_profiled_calls() -> None:
    def surface_call() -> None:
        return None

    def mark_instance() -> None:
        return None

    def reserve_submission() -> None:
        return None

    def invoke(module: str, function: object) -> None:
        FunctionType(function.__code__, {"__name__": module})()

    with HARNESS.DisabledSurfaceMonitor() as monitor:
        invoke("subprocess", surface_call)
        invoke("rapido.board", surface_call)
        invoke("rapido.state", mark_instance)
        invoke("rapido.solver", surface_call)
        invoke("socket", surface_call)
        invoke("rapido.state", reserve_submission)
        with pytest.raises(RuntimeError, match="network"):
            _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        with pytest.raises(RuntimeError, match="process"):
            subprocess.run([sys.executable, "-c", "pass"], check=False)

    assert all(count > 0 for count in monitor.counts.values())


def test_disabled_surface_monitor_profiles_new_threads() -> None:
    def model_call() -> None:
        return None

    target = FunctionType(model_call.__code__, {"__name__": "rapido.solver"})
    with HARNESS.DisabledSurfaceMonitor() as monitor:
        thread = threading.Thread(target=target)
        thread.start()
        thread.join()

    assert monitor.counts["model_inference"] > 0


def test_result_validator_rejects_stored_views_fixture_and_source_tampering(
    tmp_path: Path,
) -> None:
    result = HARNESS.run_comparison(tmp_path / "run", repetitions=2, require_clean_source=False)
    mutations = []
    changed_selection = copy.deepcopy(result)
    changed_selection["selection"]["arm"] = "graph_reducer"
    mutations.append(changed_selection)
    changed_gate = copy.deepcopy(result)
    changed_gate["gate"]["selected"] = "graph_reducer"
    mutations.append(changed_gate)
    changed_fixture = copy.deepcopy(result)
    changed_fixture["fixture"]["policy_configs"]["closed_rule_table"]["default"] = "dispatch"
    mutations.append(changed_fixture)
    changed_source = copy.deepcopy(result)
    source_path = next(iter(changed_source["provenance"]["source"]["files"]))
    changed_source["provenance"]["source"]["files"][source_path] = "0" * 64
    mutations.append(changed_source)

    for changed in mutations:
        with pytest.raises(ValueError):
            HARNESS.validate_result(changed, repetitions=2)


def test_full_registered_operation_totals_are_enforced(tmp_path: Path) -> None:
    result = HARNESS.run_comparison(tmp_path / "run", repetitions=20, require_clean_source=False)
    assert result["gate"]["passed"] is True
    summaries = result["gate"]["arm_summaries"]
    assert {
        arm: summary["policy_operation_count"] for arm, summary in summaries.items()
    } == HARNESS.OPERATION["expected_twenty_repetition_operation_totals"]


def test_measurement_refuses_dirty_source_before_first_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(HARNESS, "git_source_identity", lambda: {"clean": False})
    with pytest.raises(RuntimeError, match="clean merged source"):
        HARNESS.run_comparison(tmp_path / "run", repetitions=1, require_clean_source=True)
    assert not (tmp_path / "run").exists()
