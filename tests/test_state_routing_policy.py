from __future__ import annotations

import copy
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from rapido.routing_policy import ComparisonContract, PolicyInput
from rapido.state import StateStore

ROOT = Path(__file__).resolve().parents[1]
PARENT_PATH = ROOT / "notes/research/issue-19-routing-comparison-protocol-v1.json"
OPERATION_PATH = ROOT / "notes/research/issue-19-routing-operation-count-protocol-v1.json"


def _documents() -> tuple[dict[str, object], dict[str, object]]:
    return (
        json.loads(PARENT_PATH.read_text(encoding="utf-8")),
        json.loads(OPERATION_PATH.read_text(encoding="utf-8")),
    )


def _contract() -> ComparisonContract:
    return ComparisonContract.from_documents(*_documents())


def _payload(case_id: str) -> PolicyInput:
    parent, _ = _documents()
    case = next(case for case in parent["cases"] if case["id"] == case_id)
    value = copy.deepcopy(parent["fixture_payload_defaults"])
    if case["fact_profile"] != "none":
        value.update(copy.deepcopy(parent["fixture_payload_overrides"][case["fact_profile"]]))
    value["failure_kind"] = case["failure_kind"]
    value["failure_subreason"] = parent["failure_subreason_by_case"][case_id]
    return PolicyInput.from_dict(value)


def _seed(
    state: StateStore,
    contract: ComparisonContract,
    value: PolicyInput,
    *,
    run_id: str = "a" * 32,
) -> None:
    state.start_run(run_id, {})
    state.upsert_challenge(1, "fixture", "crypto", "standard", 100)
    state.record_control_catalogue(run_id, [(1, 1, True)])
    current = contract.route_templates[value.current_route_id]
    state.admit_control_wave(run_id, 1, 0, 1, 2, current)
    for recipe_id in sorted(value.used_successor_recipe_ids):
        state.record_comparison_used_route(run_id, 1, contract.route_templates[recipe_id])
    state.start_control_wave(run_id, 1, 0)


def test_real_sqlite_facts_decision_and_two_lane_admission_are_atomic(tmp_path: Path) -> None:
    path = tmp_path / "private" / "state.sqlite3"
    state = StateStore(path)
    contract = _contract()
    value = _payload("tool_alternate_representation")
    try:
        _seed(state, contract, value)
        fact_sequences = state.record_comparison_route_facts(
            "a" * 32,
            1,
            0,
            value.facts,
            protocol_digest=contract.parent_protocol_sha256,
        )
        trace = state.finish_and_compare_control_wave(
            run_id="a" * 32,
            challenge_id=1,
            source_episode=0,
            next_episode=1,
            catalogue_rank=1,
            lanes=2,
            policy_input=value,
            arm="closed_rule_table",
            contract=contract,
        )
    finally:
        state.close()

    assert trace.decision.disposition == "dispatch"
    assert trace.decision_sequence is not None
    assert trace.fact_sequences == fact_sequences
    assert all(sequence < trace.decision_sequence for sequence in fact_sequences)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        jobs = connection.execute(
            "SELECT episode, state, route_fingerprint FROM control_jobs ORDER BY admitted_sequence"
        ).fetchall()
        assert [(row[0], row[1]) for row in jobs] == [
            (0, "failed"),
            (0, "failed"),
            (1, "queued"),
            (1, "queued"),
        ]
        assert len({row[2] for row in jobs if row[0] == 1}) == 1
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM control_route_comparison_decisions"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM control_route_comparison_decision_facts"
            ).fetchone()[0]
            == 1
        )


def test_precontained_and_completed_rows_admit_no_successor(tmp_path: Path) -> None:
    contract = _contract()
    for index, (case_id, disposition) in enumerate(
        (("mixed_failure_quarantine", "contain"), ("completed", "no_route"))
    ):
        path = tmp_path / str(index) / "state.sqlite3"
        state = StateStore(path)
        value = _payload(case_id)
        try:
            _seed(state, contract, value, run_id=str(index + 1) * 32)
            state.record_comparison_route_facts(
                str(index + 1) * 32,
                1,
                0,
                value.facts,
                protocol_digest=contract.parent_protocol_sha256,
            )
            trace = state.finish_and_compare_control_wave(
                run_id=str(index + 1) * 32,
                challenge_id=1,
                source_episode=0,
                next_episode=1,
                catalogue_rank=1,
                lanes=2,
                policy_input=value,
                arm="closed_rule_table",
                contract=contract,
            )
        finally:
            state.close()
        assert trace.decision.disposition == disposition
        if disposition == "no_route":
            assert trace.decision_sequence is None
        else:
            assert trace.decision_sequence is not None
        with sqlite3.connect(path) as connection:
            assert (
                connection.execute("SELECT COUNT(*) FROM control_jobs WHERE episode=1").fetchone()[
                    0
                ]
                == 0
            )


def test_host_binding_mismatch_refuses_before_wave_close(tmp_path: Path) -> None:
    path = tmp_path / "private" / "state.sqlite3"
    state = StateStore(path)
    contract = _contract()
    value = _payload("policy_authorized_context")
    try:
        _seed(state, contract, value)
        state.record_comparison_route_facts(
            "a" * 32,
            1,
            0,
            value.facts,
            protocol_digest=contract.parent_protocol_sha256,
        )
        with sqlite3.connect(path) as connection:
            connection.execute("UPDATE control_route_comparison_facts SET protocol_digest='wrong'")
        with pytest.raises(ValueError, match="protocol binding"):
            state.finish_and_compare_control_wave(
                run_id="a" * 32,
                challenge_id=1,
                source_episode=0,
                next_episode=1,
                catalogue_rank=1,
                lanes=2,
                policy_input=value,
                arm="closed_rule_table",
                contract=contract,
            )
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT DISTINCT state FROM control_jobs").fetchall() == [
                ("running",)
            ]
            assert (
                connection.execute(
                    "SELECT COUNT(*) FROM control_route_comparison_decisions"
                ).fetchone()[0]
                == 0
            )
    finally:
        state.close()


def test_decision_and_successor_admission_roll_back_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "private" / "state.sqlite3"
    state = StateStore(path)
    contract = _contract()
    value = _payload("tool_alternate_representation")
    try:
        _seed(state, contract, value)
        state.record_comparison_route_facts(
            "a" * 32,
            1,
            0,
            value.facts,
            protocol_digest=contract.parent_protocol_sha256,
        )

        def fail_admission(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise RuntimeError("comparison admission fault")

        monkeypatch.setattr(StateStore, "_admit_control_wave", fail_admission)
        with pytest.raises(RuntimeError, match="admission fault"):
            state.finish_and_compare_control_wave(
                run_id="a" * 32,
                challenge_id=1,
                source_episode=0,
                next_episode=1,
                catalogue_rank=1,
                lanes=2,
                policy_input=value,
                arm="closed_rule_table",
                contract=contract,
            )
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT DISTINCT state FROM control_jobs").fetchall() == [
                ("running",)
            ]
            assert (
                connection.execute(
                    "SELECT COUNT(*) FROM control_route_comparison_decisions"
                ).fetchone()[0]
                == 0
            )
    finally:
        state.close()


def test_process_crash_rolls_back_decision_and_preserves_closed_attempts(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private" / "state.sqlite3"
    contract = _contract()
    value = _payload("tool_alternate_representation")
    state = StateStore(path)
    try:
        _seed(state, contract, value)
        state.record_comparison_route_facts(
            "a" * 32,
            1,
            0,
            value.facts,
            protocol_digest=contract.parent_protocol_sha256,
        )
        for lane in range(2):
            attempt_id = f"attempt-{lane}"
            state.start_attempt(
                attempt_id,
                "a" * 32,
                1,
                0,
                lane,
                "gpt-daybreak-blue-latest",
                "xhigh",
            )
            state.finish_attempt(attempt_id, "failed")
    finally:
        state.close()

    child = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import copy
import json
import os
from pathlib import Path
from rapido.routing_policy import ComparisonContract, PolicyInput
from rapido.state import StateStore

root = Path.cwd()
parent = json.loads((root / 'notes/research/issue-19-routing-comparison-protocol-v1.json').read_text())
operation = json.loads((root / 'notes/research/issue-19-routing-operation-count-protocol-v1.json').read_text())
case = next(item for item in parent['cases'] if item['id'] == 'tool_alternate_representation')
value = copy.deepcopy(parent['fixture_payload_defaults'])
value.update(copy.deepcopy(parent['fixture_payload_overrides'][case['fact_profile']]))
value['failure_kind'] = case['failure_kind']
value['failure_subreason'] = parent['failure_subreason_by_case'][case['id']]
policy_input = PolicyInput.from_dict(value)
contract = ComparisonContract.from_documents(parent, operation)
state = StateStore(Path(os.environ['E3_CRASH_STATE']))
def crash(*args, **kwargs):
    os._exit(73)
StateStore._admit_control_wave = crash
state.finish_and_compare_control_wave(
    run_id='a' * 32,
    challenge_id=1,
    source_episode=0,
    next_episode=1,
    catalogue_rank=1,
    lanes=2,
    policy_input=policy_input,
    arm='closed_rule_table',
    contract=contract,
)
""",
        ],
        cwd=ROOT,
        env={"E3_CRASH_STATE": str(path)},
        capture_output=True,
        check=False,
        text=True,
    )
    assert child.returncode == 73, child.stderr

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("SELECT status FROM attempts ORDER BY lane").fetchall() == [
            ("failed",),
            ("failed",),
        ]
        assert connection.execute(
            "SELECT DISTINCT state FROM control_jobs WHERE episode=0"
        ).fetchall() == [("running",)]
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM control_route_comparison_decisions"
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM control_jobs WHERE episode=1").fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM submission_intents WHERE status='pending'"
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM instances WHERE status IN ('creating','owned','cleanup_pending')"
            ).fetchone()[0]
            == 0
        )

    recovered = StateStore(path)
    try:
        trace = recovered.finish_and_compare_control_wave(
            run_id="a" * 32,
            challenge_id=1,
            source_episode=0,
            next_episode=1,
            catalogue_rank=1,
            lanes=2,
            policy_input=value,
            arm="closed_rule_table",
            contract=contract,
        )
        assert trace.decision.disposition == "dispatch"
    finally:
        recovered.close()
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM control_route_comparison_decisions"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM control_jobs WHERE episode=1").fetchone()[0]
            == 2
        )
    assert not (tmp_path / "workspace").exists()


def test_replay_uses_persisted_input_and_refuses_changed_contract(tmp_path: Path) -> None:
    path = tmp_path / "private" / "state.sqlite3"
    state = StateStore(path)
    parent, operation = _documents()
    contract = ComparisonContract.from_documents(parent, operation)
    value = _payload("provenance_fresh_derivation")
    try:
        _seed(state, contract, value)
        state.record_comparison_route_facts(
            "a" * 32,
            1,
            0,
            value.facts,
            protocol_digest=contract.parent_protocol_sha256,
        )
        trace = state.finish_and_compare_control_wave(
            run_id="a" * 32,
            challenge_id=1,
            source_episode=0,
            next_episode=1,
            catalogue_rank=1,
            lanes=2,
            policy_input=value,
            arm="graph_reducer",
            contract=contract,
        )
        replay = state.replay_comparison_route_decision(trace.decision_sequence, contract)
        assert replay.decision_digest == trace.decision_digest

        changed = copy.deepcopy(parent)
        changed["policy_configs"]["graph_reducer"]["version"] = "changed"
        with pytest.raises(ValueError, match="frozen"):
            changed_contract = ComparisonContract.from_documents(changed, operation)
            state.replay_comparison_route_decision(trace.decision_sequence, changed_contract)
    finally:
        state.close()


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("missing_link", "fact links"),
        ("fact_value", "host binding"),
        ("fact_event", "host binding"),
        ("config_bytes", "diverged"),
        ("decision_event", "decision event"),
        ("successor_admission", "successor admission"),
    ),
)
def test_replay_rejects_durable_context_and_admission_tampering(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    path = tmp_path / mutation / "state.sqlite3"
    state = StateStore(path)
    contract = _contract()
    value = _payload("disagreement_distinct_candidates")
    try:
        _seed(state, contract, value)
        state.record_comparison_route_facts(
            "a" * 32,
            1,
            0,
            value.facts,
            protocol_digest=contract.parent_protocol_sha256,
        )
        trace = state.finish_and_compare_control_wave(
            run_id="a" * 32,
            challenge_id=1,
            source_episode=0,
            next_episode=1,
            catalogue_rank=1,
            lanes=2,
            policy_input=value,
            arm="closed_rule_table",
            contract=contract,
        )
        with sqlite3.connect(path) as connection:
            if mutation == "missing_link":
                connection.execute(
                    "DELETE FROM control_route_comparison_decision_facts "
                    "WHERE decision_sequence=? AND ordinal=0",
                    (trace.decision_sequence,),
                )
            elif mutation == "fact_value":
                connection.execute(
                    "UPDATE control_route_comparison_facts SET value='tampered' "
                    "WHERE fact_sequence=(SELECT MIN(fact_sequence) "
                    "FROM control_route_comparison_facts)"
                )
            elif mutation == "fact_event":
                connection.execute(
                    "UPDATE control_events SET data_json='{}' "
                    "WHERE sequence=(SELECT MIN(fact_sequence) "
                    "FROM control_route_comparison_facts)"
                )
            elif mutation == "config_bytes":
                connection.execute(
                    "UPDATE control_route_comparison_decisions "
                    "SET policy_config_bytes=policy_config_bytes+1"
                )
            elif mutation == "decision_event":
                connection.execute(
                    "UPDATE control_events SET data_json='{}' WHERE sequence=?",
                    (trace.decision_sequence,),
                )
            else:
                connection.execute("DELETE FROM control_jobs WHERE episode=1 AND lane=1")
        with pytest.raises(ValueError, match=message):
            state.replay_comparison_route_decision(trace.decision_sequence, contract)
    finally:
        state.close()
