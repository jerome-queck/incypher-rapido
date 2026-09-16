from __future__ import annotations

import copy
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "issue19_vault_comparison",
    Path(__file__).resolve().parents[1] / "scripts" / "issue19_vault_comparison.py",
)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)
RECORDED_RESULT = (
    Path(__file__).resolve().parents[1] / "notes/research/issue-19-vault-comparison-v1.json"
)


def _normalized(result: dict[str, object]) -> dict[str, object]:
    normalized = copy.deepcopy(result)
    provenance = normalized["provenance"]
    assert isinstance(provenance, dict)
    provenance.pop("elapsed_seconds")
    provenance.pop("environment")
    adapters = normalized["adapters"]
    assert isinstance(adapters, list)
    for adapter in adapters:
        adapter["cost"].pop("persistent_bytes")
        filesystem = next(case for case in adapter["cases"] if case["case"] == "filesystem_safety")
        filesystem.pop("persistent_bytes_observed")
    return normalized


def _case(adapters: list[dict[str, object]], adapter: int, name: str) -> dict[str, object]:
    return next(case for case in adapters[adapter]["cases"] if case["case"] == name)


def test_comparison_selects_only_after_recomputed_safety_gates(tmp_path: Path) -> None:
    result = HARNESS.run_comparison(tmp_path)
    assert result["schema_version"] == 1
    assert result["fixture"] == {
        "board_enabled": False,
        "container_enabled": False,
        "model_enabled": False,
        "network_enabled": False,
        "repetitions": 1,
    }
    assert [row["adapter"] for row in result["adapters"]] == [
        "sqlite_transaction",
        "file_index",
        "volatile",
    ]
    assert result["selection"]["adapter"] == "sqlite_transaction"
    assert result["selection"]["eligible"] == ["sqlite_transaction", "file_index"]
    assert result["selection"]["ineligible"] == ["volatile"]
    assert result["selection"]["criterion"] == [
        "durability_domains",
        "reconciliation_actions",
        "persistent_bytes",
    ]
    assert result["gate"] == HARNESS.recompute_gate(result["adapters"])
    assert result["gate"]["passed"] is True


def test_every_adapter_exercises_exact_crash_scope_peer_and_privacy_cases(tmp_path: Path) -> None:
    result = HARNESS.run_comparison(tmp_path)
    expected = {
        "clean_commit_reopen",
        "crash_after_catalogue_write",
        "crash_after_commit_return",
        "crash_after_material",
        "explicit_rollback",
        "filesystem_safety",
        "peer_retention",
        "public_leak",
        "replay_and_conflict",
        "same_process_commit",
        "scope_isolation",
    }
    for adapter in result["adapters"]:
        cases = {case["case"]: case for case in adapter["cases"]}
        assert set(cases) == expected
        assert cases["crash_after_material"]["exit_code"] == 91
        assert cases["crash_after_catalogue_write"]["exit_code"] == 91
        assert cases["crash_after_commit_return"]["exit_code"] == 91
        assert cases["explicit_rollback"]["acknowledged"] is False
        assert cases["explicit_rollback"]["committed_count"] == 0
        assert cases["peer_retention"]["peer_a_retained"] is True
        assert cases["peer_retention"]["peer_b_acknowledged"] is False
        assert cases["scope_isolation"]["scope_bypass_count"] == 0
        assert cases["public_leak"]["leak_count"] == 0
        assert cases["filesystem_safety"]["unsafe_entry_count"] == 0


def test_report_contains_no_candidate_value_digest_or_common_encoding(tmp_path: Path) -> None:
    result = HARNESS.run_comparison(tmp_path)
    script_digest = result["provenance"].pop("script_sha256")
    assert script_digest == HARNESS.hashlib.sha256(Path(HARNESS.__file__).read_bytes()).hexdigest()
    encoded = json.dumps(result, sort_keys=True)
    candidate = HARNESS._fixture_candidate()
    forbidden = HARNESS._private_encodings(candidate)
    assert all(value not in encoded for value in forbidden)
    assert re.search(r"(?i)(?:incypher|flag|ctf)\s*\{", encoded) is None
    assert re.search(r"\b[0-9a-f]{64}\b", encoded) is None


def test_normalized_comparison_is_replay_deterministic(tmp_path: Path) -> None:
    expected = HARNESS.run_comparison(tmp_path / "first")
    assert _normalized(expected) == _normalized(
        json.loads(RECORDED_RESULT.read_text(encoding="utf-8"))
    )
    for index in range(4):
        assert _normalized(HARNESS.run_comparison(tmp_path / f"replay-{index}")) == _normalized(
            expected
        )


def test_gate_rejects_tampered_safety_or_selection_facts(tmp_path: Path) -> None:
    baseline = HARNESS.run_comparison(tmp_path)
    for adapter_index, field in (
        (0, "acknowledged_loss_count"),
        (0, "conflict_acceptance_count"),
        (0, "public_leak_count"),
        (1, "post_reconciliation_residue_count"),
        (2, "scope_bypass_count"),
    ):
        altered = copy.deepcopy(baseline["adapters"])
        altered[adapter_index]["metrics"][field] += 1
        gate = HARNESS.recompute_gate(altered)
        assert gate["passed"] is False


def test_gate_rejects_tampered_raw_cases_costs_and_schema(tmp_path: Path) -> None:
    baseline = HARNESS.run_comparison(tmp_path)
    mutations = []

    rollback = copy.deepcopy(baseline["adapters"])
    _case(rollback, 0, "explicit_rollback")["committed_count"] = 99
    mutations.append(rollback)

    rollback_ack = copy.deepcopy(baseline["adapters"])
    _case(rollback_ack, 0, "explicit_rollback")["acknowledged"] = True
    mutations.append(rollback_ack)

    peer_ack = copy.deepcopy(baseline["adapters"])
    _case(peer_ack, 1, "peer_retention")["peer_b_acknowledged"] = True
    mutations.append(peer_ack)

    crash = copy.deepcopy(baseline["adapters"])
    _case(crash, 1, "crash_after_material")["exit_code"] = 0
    mutations.append(crash)

    retrieval = copy.deepcopy(baseline["adapters"])
    _case(retrieval, 0, "same_process_commit")["retrieved"] = False
    mutations.append(retrieval)

    fabricated_cost = copy.deepcopy(baseline["adapters"])
    fabricated_cost[0]["cost"] = {
        "durability_domains": 0,
        "persistent_bytes": 0,
        "reconciliation_actions": 0,
    }
    mutations.append(fabricated_cost)

    missing_case = copy.deepcopy(baseline["adapters"])
    missing_case[0]["cases"].pop()
    mutations.append(missing_case)

    for altered in mutations:
        assert HARNESS.recompute_gate(altered)["passed"] is False


def test_cli_emits_sanitized_json(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(HARNESS.__file__),
            "--pretty",
            "--output-root",
            str(tmp_path / "run"),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert completed.stdout.startswith("{\n  ")
    assert json.loads(completed.stdout)["selection"]["adapter"] == "sqlite_transaction"
