from __future__ import annotations

import copy
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "issue19_candidate_flow_comparison",
    Path(__file__).resolve().parents[1] / "scripts" / "issue19_candidate_flow_comparison.py",
)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)
RECORDED_RESULT = (
    Path(__file__).resolve().parents[1]
    / "notes/research/issue-19-candidate-flow-comparison-v2.json"
)


def _normalized(result: dict[str, object]) -> dict[str, object]:
    normalized = copy.deepcopy(result)
    provenance = normalized["provenance"]
    assert isinstance(provenance, dict)
    provenance.pop("elapsed_seconds")
    provenance.pop("environment")
    # Behavior replay is independent of the immutable source manifest recorded
    # by the earlier E2 run; later compatibility and production commits must change it.
    provenance.pop("script_sha256")
    provenance.pop("production_source")
    observations = normalized["observations"]
    assert isinstance(observations, list)
    for row in observations:
        row.pop("elapsed_seconds")
    gate = normalized["gate"]
    assert isinstance(gate, dict)
    for summary in gate["arm_summaries"].values():
        summary.pop("elapsed_seconds")
    return normalized


def _row(observations: list[dict[str, object]], arm: str, case: str) -> dict[str, object]:
    return next(row for row in observations if row["arm"] == arm and row["case"] == case)


def test_comparison_selects_private_verification_from_raw_observations(
    tmp_path: Path,
) -> None:
    result = HARNESS.run_comparison(tmp_path / "run", repetitions=2)
    assert result["schema_version"] == 2
    fixture = result["fixture"]
    assert fixture["arms"] == ["exact_agreement", "private_verification"]
    assert fixture["artifact_backed"] is True
    assert fixture["external_board_enabled"] is False
    assert fixture["local_fixture_submission_enabled"] is True
    assert fixture["cases"] == list(HARNESS._CASES)
    assert fixture["repetitions"] == 2
    for arm in fixture["arms"]:
        assert fixture["arm_config"][arm] == {
            "active_challenges": 1,
            "attempt_seconds": 15,
            "concurrency": 2,
            "controller": arm,
            "episodes_per_challenge": 2,
            "model": "gpt-daybreak-blue-latest",
            "reasoning_effort": "xhigh",
            "run_seconds": 60,
        }
    assert len(result["observations"]) == 24
    assert result["gate"] == HARNESS.recompute_gate(result["observations"], 2)
    assert result["gate"]["failures"] == []
    assert result["gate"]["passed"] is True
    assert result["gate"]["selected"] == "private_verification"
    assert result["gate"]["arm_summaries"]["exact_agreement"]["positive_conversion_count"] == 2
    assert result["gate"]["arm_summaries"]["private_verification"]["positive_conversion_count"] == 6
    assert result["selection"]["arm"] == "private_verification"


def test_cases_exercise_retention_verification_and_adversarial_rejection(
    tmp_path: Path,
) -> None:
    result = HARNESS.run_comparison(tmp_path / "run", repetitions=1)
    observations = result["observations"]

    for case in HARNESS._CASES:
        legacy = _row(observations, "exact_agreement", case)
        private = _row(observations, "private_verification", case)
        assert legacy["model_effort_mismatch_count"] == 0
        assert private["model_effort_mismatch_count"] == 0
        assert private["attempt_candidate_count"] == 0
        assert private["verifier_prompt_leak_count"] == 0

    assert _row(observations, "exact_agreement", "valid_failed_peer")["qualified_count"] == 0
    assert _row(observations, "private_verification", "valid_failed_peer")["qualified_count"] == 1
    disagreement = _row(observations, "private_verification", "source_disagreement")
    assert disagreement["correct_admission_count"] == disagreement["submission_count"] == 1
    assert disagreement["false_admission_count"] == 0
    assert disagreement["proposal_count"] == 4
    assert disagreement["verified_candidate_count"] == 1
    assert disagreement["pending_candidate_count"] == 1
    assert disagreement["verifier_job_count"] == disagreement["verifier_prompt_count"] == 2
    for case in ("description_decoy", "verifier_mismatch", "model_reflection"):
        assert _row(observations, "private_verification", case)["qualified_count"] == 0


def test_fixture_runtime_reads_only_the_lane_artifact(tmp_path: Path) -> None:
    workspace = tmp_path / "lane"
    artifact = workspace / "artifacts" / "source.json"
    artifact.parent.mkdir(parents=True)
    board = HARNESS._Board("source_disagreement")
    board.download("/files/source.json", artifact, byte_limit=10_000)
    runtime = HARNESS._Runtime("source_disagreement")

    decoded = runtime._read_source(workspace, {"workspace_artifacts": ["artifacts/source.json"]})

    assert decoded == {
        "alternate": board.alternate,
        "primary": board.primary,
        "rule": "primary",
    }
    assert not hasattr(runtime, "board")


def test_gate_rejects_tampered_raw_safety_and_behavior_facts(tmp_path: Path) -> None:
    baseline = HARNESS.run_comparison(tmp_path / "run", repetitions=1)
    observations = baseline["observations"]
    mutations = []

    for case, field in (
        ("valid_failed_peer", "qualified_count"),
        ("valid_failed_peer", "false_admission_count"),
        ("valid_failed_peer", "verifier_prompt_leak_count"),
        ("valid_failed_peer", "model_effort_mismatch_count"),
        ("valid_failed_peer", "correct_admission_count"),
    ):
        altered = copy.deepcopy(observations)
        _row(altered, "private_verification", case)[field] += 1
        mutations.append(altered)

    missing = copy.deepcopy(observations)
    missing.pop()
    mutations.append(missing)
    reordered = copy.deepcopy(observations)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    mutations.append(reordered)
    extra_field = copy.deepcopy(observations)
    extra_field[0]["unregistered"] = True
    mutations.append(extra_field)
    invalid_elapsed = copy.deepcopy(observations)
    invalid_elapsed[0]["elapsed_seconds"] = -1.0
    mutations.append(invalid_elapsed)

    for altered in mutations:
        assert HARNESS.recompute_gate(altered, 1)["passed"] is False


def test_selection_is_derived_and_rejects_a_conversion_tie(tmp_path: Path) -> None:
    baseline = HARNESS.run_comparison(tmp_path / "run", repetitions=1)
    tied = copy.deepcopy(baseline["observations"])
    for case in ("valid_failed_peer", "source_disagreement"):
        row = _row(tied, "exact_agreement", case)
        row["correct_admission_count"] = 1
        row["qualified_count"] = 1
        row["submission_count"] = 1
    gate = HARNESS.recompute_gate(tied, 1)
    assert gate["passed"] is False
    assert gate["selected"] is None
    assert "conversion_selection_tie" in gate["failures"]


def test_report_contains_no_candidate_value_digest_or_common_encoding(
    tmp_path: Path,
) -> None:
    result = HARNESS.run_comparison(tmp_path / "run", repetitions=1)
    script_digest = result["provenance"].pop("script_sha256")
    assert script_digest == HARNESS.hashlib.sha256(Path(HARNESS.__file__).read_bytes()).hexdigest()
    production_source = result["provenance"].pop("production_source")
    assert production_source == HARNESS._production_source_identity()
    encoded = json.dumps(result, sort_keys=True)
    candidates = {HARNESS._candidate("decoy")}
    for case in HARNESS._CASES:
        candidates.add(HARNESS._candidate(f"{case}:primary"))
        candidates.add(HARNESS._candidate(f"{case}:alternate"))
    assert all(
        value not in encoded
        for candidate in candidates
        for value in HARNESS._candidate_encodings(candidate)
    )
    assert re.search(r"(?i)(?:incypher|flag|ctf)\s*\{", encoded) is None
    assert re.search(r"\b[0-9a-f]{64}\b", encoded) is None


def test_recorded_twenty_repetition_result_is_replay_deterministic(
    tmp_path: Path,
) -> None:
    observed = HARNESS.run_comparison(tmp_path / "run", repetitions=20)
    recorded = json.loads(RECORDED_RESULT.read_text(encoding="utf-8"))
    assert _normalized(observed) == _normalized(recorded)


def test_cli_emits_sanitized_json(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(HARNESS.__file__),
            "--pretty",
            "--repetitions",
            "1",
            "--output-root",
            str(tmp_path / "run"),
        ],
        check=False,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert completed.stdout.startswith("{\n  ")
    assert json.loads(completed.stdout)["selection"]["arm"] == "private_verification"
