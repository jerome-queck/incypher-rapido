from __future__ import annotations

import asyncio
import copy
import importlib.util
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path

from rapido.control import DurableJobControl

SPEC = importlib.util.spec_from_file_location(
    "issue19_replay",
    Path(__file__).resolve().parents[1] / "scripts" / "issue19_replay.py",
)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


def _cases(result: dict[str, object]) -> dict[str, dict[str, object]]:
    return {case["name"]: case for case in result["cases"]}


def _normalized(result: dict[str, object]) -> dict[str, object]:
    value = copy.deepcopy(result)
    run_id = value["production_run"]["run_id"]

    def scrub(item: object) -> object:
        if isinstance(item, str):
            return item.replace(run_id, "<run-id>")
        if isinstance(item, list):
            return [scrub(child) for child in item]
        if isinstance(item, dict):
            return {key: scrub(child) for key, child in item.items()}
        return item

    value = scrub(value)
    value["timing"].pop("elapsed_seconds")
    value["lifecycle"].pop("descriptor_count_observation")
    return value


def _assert_rejected(value: dict[str, object]) -> None:
    gate = HARNESS._expected_red_gate(value)
    assert gate["passed"] is False
    assert gate["failures"]


def test_expected_red_is_empirical_all_15_and_truthful() -> None:
    result = HARNESS.run_replay()
    assert result["gate"]["passed"] is True
    assert result["gate"]["observed_red"] is True
    assert "production_gate_passed" not in result["gate"]
    assert result["fixture"]["execution_surfaces"] == [
        "Orchestrator.run",
        "build_turn_prompt",
        "RunEvidence",
        "HostObservation",
        "StateStore",
        "production episode queue",
    ]
    for field in (
        "native_model_invoked",
        "fallback_enabled",
        "fallback_used",
        "network_enabled",
        "container_started",
        "board_writes_enabled",
        "candidate_values_emitted",
        "candidate_digests_emitted",
    ):
        assert result["fixture"][field] is False

    run = result["production_run"]
    assert re.fullmatch(r"[0-9a-f]{32}", run["run_id"])
    assert run["runtime_model_selections"] == [["gpt-daybreak-blue-latest", "xhigh"]]
    assert run["runtime_started"] is True
    assert run["runtime_closed"] is True
    assert run["runtime_solve_calls"] == run["evidence_manifests"] == 56
    assert run["board_instance_reads"] == 2
    assert run["board_instance_mutations"] == 0
    assert run["board_submission_calls"] == 0

    coverage = result["coverage"]
    assert coverage["catalogue_entries"] == 15
    assert coverage["initial_admitted"] == coverage["initial_completed"] == 15
    assert coverage["retry_admitted"] == coverage["retry_completed"] == 15
    assert coverage["initial_order"] == coverage["retry_order"]
    assert sorted(coverage["initial_order"]) == list(range(1, 16))
    assert coverage["all_initial_admitted_before_first_retry"] is True
    assert [item["challenge_id"] for item in coverage["episode_observations"]] == list(range(1, 16))
    assert all(
        item[phase] == {"admitted": True, "completed": True}
        for item in coverage["episode_observations"]
        for phase in ("initial", "retry")
    )

    routes = coverage["route_observations"]
    assert [item["challenge_id"] for item in routes] == list(range(1, 16))
    assert all(HARNESS._route_observation_satisfied(item) for item in routes)
    assert all(item["sanctioned_route_repeated"] for item in routes)
    assert sum(item["sanctioned_route_repeat_count"] for item in routes) == 29
    assert all(
        item["scope"] == ("board_preflight" if item["challenge_id"] == 7 else "lanes")
        for item in routes
    )

    cases = _cases(result)
    assert set(cases) == {
        "policy",
        "provenance",
        "disagreement",
        "timeout",
        "tool",
        "quota",
        "board",
        "container",
    }
    assert HARNESS._corpus_mapping_satisfied(result["cases"])
    assert all(HARNESS._case_satisfied(case, run["run_id"]) for case in result["cases"])
    assert all(
        attempt_id.startswith(f"{run['run_id']}:")
        for case in result["cases"]
        for attempt_id in case["durable_attempt_ids"]
    )
    assert cases["provenance"]["candidate_outputs"] == 4
    assert cases["provenance"]["candidate_rows_retained"] == 0
    assert cases["disagreement"]["candidate_outputs"] == 4
    assert cases["disagreement"]["candidate_rows_retained"] == 4
    assert cases["board"]["initial_attempt_ids"] == []
    assert cases["board"]["initial_failure_evidence"]["event_sequences"]
    assert all(
        not sequences
        for case in result["cases"]
        for sequences in case["gap_event_sequences"].values()
    )
    assert all(not sequences for sequences in result["gap_event_sequences"].values())

    assert result["metrics"] == HARNESS._metrics_from_raw(
        routes, result["cases"], result["gap_event_sequences"]
    )
    assert result["metrics"] == {
        "fixture_count": 8,
        "challenge_route_repeats": 15,
        "route_comparison_repeats": 29,
        "changed_retry_prompts": 14,
        "initial_failures_observed": 8,
        "unresolved_after_retry": 8,
        "typed_route_decision_events": 0,
        "private_candidate_retention_events": 0,
        "verifier_route_events": 0,
        "verifier_completion_events": 0,
        "recovery_terminal_events": 0,
        "recovery_disposition_events": 0,
    }

    assert result["recovery"] == {
        "scope": "unfinished durable rows only",
        "unfinished_attempts_recovered": 1,
        "unfinished_attempt_status": "interrupted",
        "unfinished_attempt_summary": "process ended before restart",
        "unfinished_run_status": "interrupted",
        "recovery_events": 1,
        "second_recovery": 0,
        "same_run_resumed": False,
        "abrupt_process_crash_exercised": False,
        "container_restart_exercised": False,
    }
    lifecycle = result["lifecycle"]
    assert lifecycle["sqlite_integrity"] == "ok"
    assert lifecycle["pending_submission_intents"] == 0
    assert lifecycle["owned_instances"] == 0
    assert lifecycle["new_pending_async_tasks"] == 0
    assert lifecycle["workspace_entries"] == 2
    assert lifecycle["workspace_symlinks"] == 0
    assert lifecycle["empty_run_roots"] == 1
    assert lifecycle["nested_run_entries"] == 0
    assert lifecycle["temporary_scope_removed"] is True
    assert lifecycle["descriptor_count_observation"]["identity_checked"] is False
    assert lifecycle["descriptor_count_observation"]["leak_absence_claimed"] is False


def test_adaptive_control_routes_eight_failures_without_unchanged_retry(tmp_path: Path) -> None:
    config = HARNESS._config(tmp_path)
    board = HARNESS._InertBoard()
    runtime = HARNESS._InertRuntime()

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    initial = {
        decision.failure_kind: decision
        for decision in view.route_decisions
        if decision.source_episode == 0
    }
    assert set(initial) >= {
        "policy",
        "provenance",
        "disagreement",
        "timeout",
        "tool",
        "quota",
        "board",
        "container",
    }
    assert {
        kind: initial[kind].disposition
        for kind in (
            "policy",
            "provenance",
            "disagreement",
            "timeout",
            "tool",
            "quota",
            "board",
            "container",
        )
    } == {
        "policy": "contain",
        "provenance": "contain",
        "disagreement": "dispatch",
        "timeout": "contain",
        "tool": "dispatch",
        "quota": "contain",
        "board": "contain",
        "container": "dispatch",
    }
    assert all(
        decision.changed_axes
        and decision.successor_route_fingerprint != decision.source_route_fingerprint
        for decision in view.route_decisions
        if decision.disposition == "dispatch"
    )
    assert all(
        decision.successor_route_fingerprint is None
        for decision in view.route_decisions
        if decision.disposition != "dispatch"
    )
    for challenge_id in range(1, 16):
        episode_routes = {
            job.episode: job.route_fingerprint
            for job in view.jobs
            if job.challenge_id == challenge_id
        }
        assert len(episode_routes) == len(set(episode_routes.values()))
    encoded = json.dumps(asdict(view), sort_keys=True)
    assert HARNESS._SYNTHETIC_PROVENANCE_VALUE not in encoded
    assert all(value not in encoded for value in HARNESS._SYNTHETIC_DISAGREEMENT_VALUES)
    assert re.search(r"\b[0-9a-f]{64}\b", encoded) is None


def test_persistent_failure_is_contained_before_an_unchanged_third_route(
    tmp_path: Path,
) -> None:
    config = replace(HARNESS._config(tmp_path), challenge_ids=(5,), episodes_per_challenge=4)

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=HARNESS._InertBoard(),
            runtime=HARNESS._InertRuntime(),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert {job.episode for job in view.jobs} == {0, 1}
    assert len({job.route_fingerprint for job in view.jobs}) == 2
    assert [decision.disposition for decision in view.route_decisions] == [
        "dispatch",
        "contain",
    ]
    assert view.route_decisions[-1].rule_id == "no_changed_route"
    assert all(job.state != "queued" for job in view.jobs)


def test_twenty_normalized_replays_are_identical() -> None:
    expected = _normalized(HARNESS.run_replay())
    for _ in range(19):
        assert _normalized(HARNESS.run_replay()) == expected


def test_expected_red_gate_recomputes_metrics_and_rejects_observation_tampering() -> None:
    baseline = HARNESS.run_replay()
    mutations = []

    missing_route = copy.deepcopy(baseline)
    missing_route["coverage"]["route_observations"].pop()
    mutations.append(missing_route)
    changed_axis = copy.deepcopy(baseline)
    changed_axis["coverage"]["route_observations"][0]["comparisons"][0]["strategy_repeated"] = False
    mutations.append(changed_axis)
    incomplete_axis_shape = copy.deepcopy(baseline)
    incomplete_axis_shape["coverage"]["route_observations"][0]["comparisons"][0].pop(
        "deadline_repeated"
    )
    mutations.append(incomplete_axis_shape)
    changed_order = copy.deepcopy(baseline)
    changed_order["coverage"]["retry_order"] = list(
        reversed(changed_order["coverage"]["retry_order"])
    )
    mutations.append(changed_order)
    incomplete_episode = copy.deepcopy(baseline)
    incomplete_episode["coverage"]["episode_observations"][0]["retry"]["completed"] = False
    mutations.append(incomplete_episode)
    wrong_corpus = copy.deepcopy(baseline)
    _cases(wrong_corpus)["policy"]["failure_cause"] = "other"
    mutations.append(wrong_corpus)
    missing_attempt = copy.deepcopy(baseline)
    _cases(missing_attempt)["policy"]["initial_attempt_ids"].pop()
    mutations.append(missing_attempt)
    missing_failure_sequence = copy.deepcopy(baseline)
    _cases(missing_failure_sequence)["policy"]["initial_failure_evidence"]["event_sequences"] = []
    mutations.append(missing_failure_sequence)
    changed_candidate_facts = copy.deepcopy(baseline)
    _cases(changed_candidate_facts)["provenance"]["candidate_rows_retained"] = 1
    mutations.append(changed_candidate_facts)

    for name in HARNESS._GAP_EVENT_KINDS:
        altered = copy.deepcopy(baseline)
        altered["gap_event_sequences"][name] = [1]
        mutations.append(altered)
    for name in baseline["metrics"]:
        altered = copy.deepcopy(baseline)
        altered["metrics"][name] += 1
        mutations.append(altered)

    for altered in mutations:
        _assert_rejected(altered)


def test_expected_red_gate_rejects_runtime_board_recovery_and_lifecycle_tampering() -> None:
    baseline = HARNESS.run_replay()
    mutations = []

    for field, replacement in (
        ("runtime_model_selections", [["fallback", "low"]]),
        ("runtime_solve_calls", 0),
        ("evidence_manifests", 0),
        ("board_submission_calls", 1),
        ("board_instance_mutations", 1),
    ):
        altered = copy.deepcopy(baseline)
        altered["production_run"][field] = replacement
        mutations.append(altered)
    non_board_mutation = copy.deepcopy(baseline)
    _cases(non_board_mutation)["policy"]["board_mutation_calls"] = 1
    mutations.append(non_board_mutation)
    fallback = copy.deepcopy(baseline)
    fallback["fixture"]["fallback_used"] = True
    mutations.append(fallback)
    recovery_overclaim = copy.deepcopy(baseline)
    recovery_overclaim["recovery"]["same_run_resumed"] = True
    mutations.append(recovery_overclaim)
    bad_integrity = copy.deepcopy(baseline)
    bad_integrity["lifecycle"]["sqlite_integrity"] = "corrupt"
    mutations.append(bad_integrity)
    residue = copy.deepcopy(baseline)
    residue["lifecycle"]["workspace_symlinks"] = 1
    mutations.append(residue)

    for altered in mutations:
        _assert_rejected(altered)


def test_report_privacy_scan_is_case_insensitive_and_allows_benign_ids() -> None:
    result = HARNESS.run_replay()
    encoded = json.dumps(result)
    flag_pattern = re.compile(r"(?i)(?:incypher|flag|ctf)\s*\{")
    digest_pattern = re.compile(r"\b[0-9a-fA-F]{64}\b")
    assert flag_pattern.search(encoded) is None
    assert digest_pattern.search(encoded) is None
    assert flag_pattern.search("fLaG{must-be-detected}")
    assert digest_pattern.search("a" * 64)
    assert re.fullmatch(r"[0-9a-f]{32}", result["production_run"]["run_id"])


def test_async_leak_scope_ignores_preexisting_unrelated_task() -> None:
    async def scenario() -> dict[str, object]:
        blocker = asyncio.Event()
        unrelated = asyncio.create_task(blocker.wait())
        try:
            return await HARNESS._run_fixture_async()
        finally:
            unrelated.cancel()
            await asyncio.gather(unrelated, return_exceptions=True)

    result = asyncio.run(scenario())
    assert result["lifecycle"]["new_pending_async_tasks"] == 0
    assert result["lifecycle"]["unrelated_preexisting_tasks_ignored"] >= 1


def test_lexical_inventory_counts_broken_link_without_following_link_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "work"
    root.mkdir()
    os.symlink(root / "missing-target", root / "broken-link")
    assert HARNESS._lexical_inventory(root)["symlinks"] == 1

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "must-not-be-counted").write_text("outside", encoding="ascii")
    linked_root = tmp_path / "work-link"
    os.symlink(outside, linked_root)
    assert HARNESS._lexical_inventory(linked_root) == {
        "entries": 1,
        "symlinks": 1,
        "run_roots": 0,
        "nested_run_entries": 0,
    }


def test_cli_emits_json_and_expected_red_exit() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/issue19_replay.py"],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path.cwd())},
    )
    result = json.loads(completed.stdout)
    assert result["gate"]["passed"] is True
    assert result["gate"]["observed_red"] is True
