from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from rapido.reporting import (
    EvaluationRow,
    PostrunEvaluation,
    ReconciliationInputs,
    StrictDecision,
    StrictEvaluation,
    UsageEvidence,
    UsageRow,
    clipped_seconds,
    parse_timestamp,
    reconcile_archive,
)
from rapido.state import StateStore

RUN_ID = "synthetic-run"


def _database(
    path: Path,
    *,
    duplicate_job: bool = False,
    duplicate_submission: bool = False,
    duplicate_unsettled_submission: bool = False,
    missing_settled_submission: bool = False,
    out_of_order_reconciliation: bool = False,
    valid_reconciliation: bool = False,
    late_not_delivered: bool = False,
    null_started_job: bool = False,
    mismatched_proof: bool = False,
    tampered_view: str | None = None,
) -> Path:
    store = StateStore(path)
    store.close()
    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
    connection.executescript(
        """
        CREATE TABLE evidence_objects(run_id TEXT, digest TEXT);
        CREATE TABLE evidence_items(run_id TEXT, object_digest TEXT);
        """
    )
    if tampered_view:
        view_sql = str(
            connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='view' "
                "AND name='current_candidate_verifications'"
            ).fetchone()[0]
        )
        connection.execute("DROP VIEW current_candidate_verifications")
        if tampered_view == "table":
            connection.execute(
                "CREATE TABLE current_candidate_verifications(run_id TEXT, challenge_id INTEGER)"
            )
        elif tampered_view == "literal_case":
            connection.execute(view_sql.replace("'dynamic_iac'", "'DYNAMIC_IAC'"))
        else:
            raise AssertionError("unknown view tamper")
    connection.execute(
        "INSERT INTO runs(id,started_at,finished_at,status,config_json) "
        "VALUES (?, '2026-09-19T00:00:00Z', '2026-09-19T00:01:00Z','completed','{}')",
        (RUN_ID,),
    )
    connection.executemany(
        "INSERT INTO challenges(id,name,category,challenge_type,value,status,updated_at) "
        "VALUES (?,'synthetic','offline','standard',1,'completed','2026-09-19T00:01:00Z')",
        ((1,), (2,)),
    )
    connection.executemany(
        "INSERT INTO control_catalogue(run_id,challenge_id,catalogue_rank,executable,"
        "context_sha256,context_episode) VALUES (?, ?, ?, 1, NULL, 0)",
        ((RUN_ID, task_id, task_id) for task_id in range(1, 16)),
    )
    attempts = (
        ("p1", 1, 0, "2026-09-18T23:59:50Z", "2026-09-19T00:00:20Z"),
        ("v1", 1, 1, "2026-09-19T00:00:10Z", "2026-09-19T00:00:50Z"),
        ("p2", 2, 0, "2026-09-19T00:00:40Z", "2026-09-19T00:01:10Z"),
        ("v2", 2, 1, "2026-09-19T00:00:50Z", "2026-09-19T00:00:55Z"),
    )
    for sequence, (attempt_id, challenge_id, episode, started, finished) in enumerate(attempts, 1):
        connection.execute(
            "INSERT INTO attempts(id,run_id,challenge_id,episode,lane,started_at,finished_at,"
            "status,model,effort,candidate) VALUES (?, ?, ?, ?, 0, ?, ?, 'running',"
            "'synthetic-model','xhigh',NULL)",
            (attempt_id, RUN_ID, challenge_id, episode, started, finished),
        )
        connection.execute(
            "INSERT INTO control_jobs(job_id,run_id,challenge_id,episode,catalogue_rank,phase,"
            "role,agent_role,model,effort,lane,state,route_fingerprint,admitted_sequence,"
            "started_sequence,closed_sequence) VALUES (?, ?, ?, ?, ?, 'analysis','specialist',"
            "'specialist','synthetic-model','xhigh',0,'completed',?, ?, ?, ?)",
            (
                f"job-{attempt_id}",
                RUN_ID,
                challenge_id,
                episode,
                challenge_id,
                f"route-{attempt_id}",
                sequence,
                sequence,
                sequence,
            ),
        )
    if duplicate_job:
        connection.execute(
            "INSERT INTO control_jobs(job_id,run_id,challenge_id,episode,catalogue_rank,phase,"
            "role,agent_role,model,effort,lane,state,route_fingerprint,admitted_sequence,"
            "started_sequence) VALUES ('duplicate',?,1,0,1,'analysis','verifier','verifier',"
            "'synthetic-model','xhigh',0,'completed','duplicate-route',99,99)",
            (RUN_ID,),
        )
    if null_started_job:
        connection.execute("UPDATE control_jobs SET started_sequence=NULL WHERE job_id='job-p1'")
    for index in range(42):
        candidate = f"synthetic-{index:02d}"
        challenge_id = index % 15
        connection.execute(
            "INSERT INTO submissions(sequence,run_id,challenge_id,at,candidate_sha256,"
            "context_episode,provenance_class,outcome,http_status) VALUES (?, ?, ?, "
            "'2026-09-19T00:00:30Z', ?, 0, 'source_observed_candidate','already_solved',200)",
            (index, RUN_ID, challenge_id, candidate),
        )
        connection.execute(
            "INSERT INTO submission_intents(challenge_id,candidate_sha256,first_run_id,"
            "context_episode,provenance_class,reserved_at,status,updated_at) VALUES (?, ?, ?, 0,"
            "'source_observed_candidate','2026-09-19T00:00:20Z','already_solved',"
            "'2026-09-19T00:00:30Z')",
            (challenge_id, candidate, RUN_ID),
        )
    if duplicate_submission:
        connection.execute(
            "INSERT INTO submissions(sequence,run_id,challenge_id,at,candidate_sha256,"
            "context_episode,provenance_class,outcome,http_status) VALUES (99,?,0,"
            "'2026-09-19T00:00:30Z','synthetic-00',0,'source_observed_candidate',"
            "'already_solved',200)",
            (RUN_ID,),
        )
    if duplicate_unsettled_submission:
        connection.execute("UPDATE submissions SET outcome='paused' WHERE sequence=0")
        connection.execute(
            "UPDATE submission_intents SET status='paused' WHERE candidate_sha256='synthetic-00'"
        )
        connection.execute(
            "INSERT INTO submissions(sequence,run_id,challenge_id,at,candidate_sha256,"
            "context_episode,provenance_class,outcome,http_status) VALUES (98,?,0,"
            "'2026-09-19T00:00:30Z','synthetic-00',0,'source_observed_candidate','paused',429)",
            (RUN_ID,),
        )
    if missing_settled_submission:
        connection.execute("DELETE FROM submissions WHERE sequence=0")
    if out_of_order_reconciliation:
        connection.execute("UPDATE submissions SET outcome='correct' WHERE sequence=0")
        connection.execute(
            "UPDATE submission_intents SET status='correct' WHERE candidate_sha256='synthetic-00'"
        )
        connection.execute(
            "INSERT INTO submissions(sequence,run_id,challenge_id,at,candidate_sha256,"
            "context_episode,provenance_class,outcome,http_status) VALUES (98,?,0,"
            "'2026-09-19T00:00:40Z','synthetic-00',0,'source_observed_candidate','unread',0)",
            (RUN_ID,),
        )
    if valid_reconciliation:
        connection.execute("UPDATE submissions SET outcome='unread' WHERE sequence=0")
        connection.execute(
            "UPDATE submission_intents SET status='correct', "
            "updated_at='2026-09-19T00:00:40Z' WHERE candidate_sha256='synthetic-00'"
        )
        connection.execute(
            "INSERT INTO submissions(sequence,run_id,challenge_id,at,candidate_sha256,"
            "context_episode,provenance_class,outcome,http_status) VALUES (97,?,0,"
            "'2026-09-19T00:00:35Z','synthetic-00',0,'source_observed_candidate','unread',0)",
            (RUN_ID,),
        )
        connection.execute(
            "INSERT INTO submissions(sequence,run_id,challenge_id,at,candidate_sha256,"
            "context_episode,provenance_class,outcome,http_status) VALUES (98,?,0,"
            "'2026-09-19T00:00:40Z','synthetic-00',0,'source_observed_candidate','correct',0)",
            (RUN_ID,),
        )
    if late_not_delivered:
        connection.execute("UPDATE submissions SET outcome='unread' WHERE sequence=0")
        connection.execute(
            "UPDATE submission_intents SET status='not_delivered', "
            "updated_at='2026-09-19T01:00:00+00:00' WHERE candidate_sha256='synthetic-00'"
        )
        connection.execute(
            "INSERT INTO submissions(sequence,run_id,challenge_id,at,candidate_sha256,"
            "context_episode,provenance_class,outcome,http_status) VALUES (97,?,0,"
            "'2026-09-19T10:00:00+10:00','synthetic-00',0,'source_observed_candidate','unread',0)",
            (RUN_ID,),
        )
        connection.execute(
            "INSERT INTO submissions(sequence,run_id,challenge_id,at,candidate_sha256,"
            "context_episode,provenance_class,outcome,http_status) VALUES (98,?,0,"
            "'2026-09-19T02:00:00+00:00','synthetic-00',0,'source_observed_candidate','unread',0)",
            (RUN_ID,),
        )
    for challenge_id, candidate_key in ((1, b"a" * 32), (2, b"b" * 32)):
        context = f"context-{challenge_id}"
        producer, verifier = f"p{challenge_id}", f"v{challenge_id}"
        connection.execute(
            "UPDATE control_catalogue SET context_sha256=? WHERE run_id=? AND challenge_id=?",
            (context, RUN_ID, challenge_id),
        )
        connection.executemany(
            "INSERT INTO candidate_proposals(source_attempt_id,run_id,challenge_id,episode,lane,"
            "role,recipe_kind,context_identity,instance_receipt_sha256,candidate_key,candidate,"
            "retained_at) VALUES (?, ?, ?, ?, 0, ?, 'synthetic-recipe', ?, NULL, ?, ?, "
            "'2026-09-19T00:00:30Z')",
            (
                (
                    producer,
                    RUN_ID,
                    challenge_id,
                    0,
                    "specialist",
                    context,
                    candidate_key,
                    b"private",
                ),
                (
                    verifier,
                    RUN_ID,
                    challenge_id,
                    1,
                    "verifier",
                    context,
                    candidate_key,
                    b"private",
                ),
            ),
        )
        connection.executemany(
            "INSERT INTO candidate_evidence_proofs(source_attempt_id,run_id,challenge_id,"
            "candidate_key,manifest_digest,attested_at) VALUES (?, ?, ?, ?, ?, "
            "'2026-09-19T00:00:30Z')",
            (
                (
                    producer,
                    RUN_ID,
                    challenge_id,
                    b"z" * 32 if mismatched_proof and challenge_id == 1 else candidate_key,
                    "0" * 64,
                ),
                (verifier, RUN_ID, challenge_id, candidate_key, "1" * 64),
            ),
        )
        connection.execute(
            "INSERT INTO candidate_verifications(run_id,challenge_id,candidate_key,"
            "producer_attempt_id,producer_role,verifier_attempt_id,verifier_role,recipe_kind,"
            "verification_scope,context_identity,instance_receipt_sha256,verified_at) VALUES "
            "(?, ?, ?, ?, 'specialist', ?, 'verifier','synthetic-recipe','static_material',?,NULL,"
            "'2026-09-19T00:00:40Z')",
            (RUN_ID, challenge_id, candidate_key, producer, verifier, context),
        )
    connection.execute("UPDATE attempts SET status='candidate' WHERE run_id=?", (RUN_ID,))
    connection.executemany(
        "INSERT INTO evidence_objects VALUES (?, ?)", ((RUN_ID, "o1"), (RUN_ID, "o2"))
    )
    connection.executemany(
        "INSERT INTO evidence_items VALUES (?, ?)",
        ((RUN_ID, "o1"), (RUN_ID, "o1"), (RUN_ID, "o2")),
    )
    connection.commit()
    connection.close()
    return path


def _inputs(*, usage: UsageEvidence | None = None) -> ReconciliationInputs:
    rows = tuple(
        EvaluationRow(
            task_id=task_id,
            correctness="correct",
            qualification=(
                "qualified" if task_id <= 5 else "not_qualified" if task_id <= 10 else "unknown"
            ),
        )
        for task_id in range(1, 16)
    )
    return ReconciliationInputs(
        postrun_evaluation=PostrunEvaluation("policy.synthetic_accepted_grade.v1", rows),
        strict_evaluator=StrictEvaluation(
            "policy.synthetic_strict_evaluator.v1",
            (
                StrictDecision(1, "excluded", "rule.synthetic_policy_scope_excluded.v1"),
                StrictDecision(2, "excluded", "rule.synthetic_policy_scope_excluded.v1"),
            ),
        ),
        native_usage=usage,
    )


def _usage() -> UsageEvidence:
    return UsageEvidence(
        "policy.native_attempt_usage.v1",
        (
            UsageRow(
                "p1",
                {
                    name: 1
                    for name in (
                        "input_tokens",
                        "output_tokens",
                        "cached_input_tokens",
                        "reasoning_tokens",
                    )
                },
            ),
            UsageRow(
                "v1",
                {
                    "input_tokens": None,
                    "output_tokens": 2,
                    "cached_input_tokens": 0,
                    "reasoning_tokens": None,
                },
            ),
            UsageRow(
                "p2",
                {
                    name: 3
                    for name in (
                        "input_tokens",
                        "output_tokens",
                        "cached_input_tokens",
                        "reasoning_tokens",
                    )
                },
            ),
            UsageRow(
                "v2",
                {
                    name: 4
                    for name in (
                        "input_tokens",
                        "output_tokens",
                        "cached_input_tokens",
                        "reasoning_tokens",
                    )
                },
            ),
        ),
    )


def test_synthetic_reconciliation_matches_golden_and_does_not_write(tmp_path: Path) -> None:
    database = _database(tmp_path / "archive.sqlite3")
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    report = reconcile_archive(database, RUN_ID, _inputs())
    after = hashlib.sha256(database.read_bytes()).hexdigest()
    expected = json.loads(
        (Path(__file__).parent / "fixtures" / "reporting" / "synthetic_expected_v1.json").read_text(
            encoding="utf-8"
        )
    )

    assert report == expected
    assert before == after
    assert not database.with_name(database.name + "-wal").exists()
    assert not database.with_name(database.name + "-shm").exists()


def test_already_solved_never_upgrades_other_axes(tmp_path: Path) -> None:
    report = reconcile_archive(_database(tmp_path / "archive.sqlite3"), RUN_ID, _inputs())

    assert report["metrics"]["postrun_correctness"]["value"] == 15
    assert report["metrics"]["board_new_correct"]["value"] == 0
    assert report["metrics"]["already_solved_history"]["value"] == 42
    assert report["metrics"]["runtime_current_verification"]["value"] == 2
    assert report["metrics"]["strict_evaluator"]["value"] == 0
    assert report["metrics"]["postrun_correctness_qualification_matrix"]["correct"] == {
        "not_qualified": 5,
        "qualified": 5,
        "unknown": 5,
    }


def test_null_attempt_candidate_does_not_erase_proof_backed_proposal(tmp_path: Path) -> None:
    database = _database(tmp_path / "archive.sqlite3")
    connection = sqlite3.connect(database)
    assert (
        connection.execute("SELECT COUNT(*) FROM attempts WHERE candidate IS NULL").fetchone()[0]
        == 4
    )
    connection.close()

    report = reconcile_archive(database, RUN_ID, _inputs())
    assert report["archive"]["proof_backed_proposal_attempt_count"] == 4


@pytest.mark.parametrize("duplicate", ["job", "submission"])
def test_identity_joins_must_be_bidirectionally_one_to_one(tmp_path: Path, duplicate: str) -> None:
    database = _database(
        tmp_path / "archive.sqlite3",
        duplicate_job=duplicate == "job",
        duplicate_submission=duplicate == "submission",
    )
    with pytest.raises(ValueError, match="one-to-one"):
        reconcile_archive(database, RUN_ID, _inputs())


def test_unstarted_job_and_unsettled_duplicate_submission_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="attempt and started-job"):
        reconcile_archive(
            _database(tmp_path / "unstarted.sqlite3", null_started_job=True), RUN_ID, _inputs()
        )


def test_settled_intent_without_submission_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="bidirectionally one-to-one"):
        reconcile_archive(
            _database(tmp_path / "missing.sqlite3", missing_settled_submission=True),
            RUN_ID,
            _inputs(),
        )


def test_reconciled_unread_must_precede_final_outcome(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="bidirectionally one-to-one"):
        reconcile_archive(
            _database(tmp_path / "ordering.sqlite3", out_of_order_reconciliation=True),
            RUN_ID,
            _inputs(),
        )

    report = reconcile_archive(
        _database(tmp_path / "valid.sqlite3", valid_reconciliation=True), RUN_ID, _inputs()
    )
    assert report["archive"]["submission_intent_join_count"] == 42
    with pytest.raises(ValueError, match="bidirectionally one-to-one"):
        reconcile_archive(
            _database(tmp_path / "late.sqlite3", late_not_delivered=True), RUN_ID, _inputs()
        )
    with pytest.raises(ValueError, match="bidirectionally one-to-one"):
        reconcile_archive(
            _database(tmp_path / "unsettled.sqlite3", duplicate_unsettled_submission=True),
            RUN_ID,
            _inputs(),
        )


def test_strict_evaluator_requires_exactly_one_registered_decision_per_runtime_task(
    tmp_path: Path,
) -> None:
    missing = replace(
        _inputs(),
        strict_evaluator=StrictEvaluation(
            "policy.synthetic_strict_evaluator.v1",
            (StrictDecision(1, "excluded", "rule.synthetic_policy_scope_excluded.v1"),),
        ),
    )
    with pytest.raises(ValueError, match="missing=1, unexpected=0"):
        reconcile_archive(_database(tmp_path / "missing.sqlite3"), RUN_ID, missing)

    unexpected = replace(
        _inputs(),
        strict_evaluator=StrictEvaluation(
            "policy.synthetic_strict_evaluator.v1",
            (
                *_inputs().strict_evaluator.decisions,
                StrictDecision(3, "excluded", "rule.synthetic_policy_scope_excluded.v1"),
            ),
        ),
    )
    with pytest.raises(ValueError, match="missing=0, unexpected=1"):
        reconcile_archive(_database(tmp_path / "unexpected.sqlite3"), RUN_ID, unexpected)

    unknown_rule = replace(
        _inputs(),
        strict_evaluator=StrictEvaluation(
            "policy.synthetic_strict_evaluator.v1",
            (StrictDecision(1, "excluded", "private"), *_inputs().strict_evaluator.decisions[1:]),
        ),
    )
    with pytest.raises(ValueError, match="registered rule"):
        reconcile_archive(_database(tmp_path / "rule.sqlite3"), RUN_ID, unknown_rule)


def test_duplicate_postrun_and_usage_identities_fail_closed(tmp_path: Path) -> None:
    inputs = _inputs()
    duplicate_postrun = replace(
        inputs,
        postrun_evaluation=replace(
            inputs.postrun_evaluation,
            rows=(*inputs.postrun_evaluation.rows, inputs.postrun_evaluation.rows[0]),
        ),
    )
    with pytest.raises(ValueError, match="duplicate task"):
        reconcile_archive(_database(tmp_path / "postrun.sqlite3"), RUN_ID, duplicate_postrun)

    usage = _usage()
    duplicate_usage = replace(usage, rows=(*usage.rows, usage.rows[0]))
    with pytest.raises(ValueError, match="duplicate attempt"):
        reconcile_archive(
            _database(tmp_path / "usage.sqlite3"),
            RUN_ID,
            _inputs(usage=duplicate_usage),
        )


def test_direct_constructor_invariants_fail_closed(tmp_path: Path) -> None:
    inputs = _inputs()
    bad_task = replace(
        inputs,
        postrun_evaluation=replace(
            inputs.postrun_evaluation,
            rows=(
                replace(inputs.postrun_evaluation.rows[0], task_id=0),
                *inputs.postrun_evaluation.rows[1:],
            ),
        ),
    )
    with pytest.raises(TypeError, match="task_id"):
        reconcile_archive(_database(tmp_path / "task.sqlite3"), RUN_ID, bad_task)

    usage = _usage()
    negative = replace(usage.rows[0], values={**usage.rows[0].values, "input_tokens": -100})
    with pytest.raises(TypeError, match="input_tokens"):
        reconcile_archive(
            _database(tmp_path / "usage.sqlite3"),
            RUN_ID,
            _inputs(usage=replace(usage, rows=(negative, *usage.rows[1:]))),
        )


def test_missing_and_unexpected_postrun_identities_fail_closed(tmp_path: Path) -> None:
    inputs = _inputs()
    missing = replace(
        inputs,
        postrun_evaluation=replace(
            inputs.postrun_evaluation, rows=inputs.postrun_evaluation.rows[:-1]
        ),
    )
    with pytest.raises(ValueError, match="missing=1, unexpected=0"):
        reconcile_archive(_database(tmp_path / "missing.sqlite3"), RUN_ID, missing)

    unexpected_row = replace(inputs.postrun_evaluation.rows[-1], task_id=16)
    unexpected = replace(
        inputs,
        postrun_evaluation=replace(
            inputs.postrun_evaluation,
            rows=(*inputs.postrun_evaluation.rows[:-1], unexpected_row),
        ),
    )
    with pytest.raises(ValueError, match="missing=1, unexpected=1"):
        reconcile_archive(_database(tmp_path / "unexpected.sqlite3"), RUN_ID, unexpected)


def test_missing_usage_is_null_and_partial_usage_keeps_complete_total_null(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path / "archive.sqlite3")
    missing = reconcile_archive(database, RUN_ID, _inputs())
    partial = reconcile_archive(database, RUN_ID, _inputs(usage=_usage()))

    assert missing["archive"]["native_usage"] is None
    usage = partial["archive"]["native_usage"]
    assert usage["metrics"]["input_tokens"] == {
        "observed_total": 8,
        "observed_attempt_count": 3,
        "missing_attempt_count": 1,
        "total": None,
    }
    assert usage["metrics"]["output_tokens"]["total"] == 10


def test_usage_identity_mismatch_fails_closed(tmp_path: Path) -> None:
    usage = replace(_usage(), rows=_usage().rows[:-1])
    with pytest.raises(ValueError, match="missing=1, unexpected=0"):
        reconcile_archive(_database(tmp_path / "archive.sqlite3"), RUN_ID, _inputs(usage=usage))


def test_production_verification_view_contract_is_required(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="production view"):
        reconcile_archive(
            _database(tmp_path / "archive.sqlite3", tampered_view="table"), RUN_ID, _inputs()
        )
    with pytest.raises(ValueError, match="view policy is incompatible"):
        reconcile_archive(
            _database(tmp_path / "case.sqlite3", tampered_view="literal_case"), RUN_ID, _inputs()
        )


def test_proof_backed_count_requires_matching_candidate_key(tmp_path: Path) -> None:
    inputs = _inputs()
    strict = replace(inputs.strict_evaluator, decisions=(inputs.strict_evaluator.decisions[1],))
    report = reconcile_archive(
        _database(tmp_path / "archive.sqlite3", mismatched_proof=True),
        RUN_ID,
        replace(inputs, strict_evaluator=strict),
    )
    assert report["archive"]["proof_backed_proposal_attempt_count"] == 3


def test_overlap_uses_one_window_and_keeps_overlapping_lane_time_additive() -> None:
    lower = parse_timestamp("2026-09-19T00:00:00Z")
    upper = parse_timestamp("2026-09-19T00:01:00Z")

    assert (
        clipped_seconds(
            parse_timestamp("2026-09-18T23:59:50Z"),
            parse_timestamp("2026-09-19T00:00:20Z"),
            lower,
            upper,
        )
        == 20
    )
    assert (
        clipped_seconds(
            parse_timestamp("2026-09-19T00:00:40Z"),
            parse_timestamp("2026-09-19T00:01:10Z"),
            lower,
            upper,
        )
        == 20
    )


def test_symlink_database_is_rejected(tmp_path: Path) -> None:
    database = _database(tmp_path / "archive.sqlite3")
    link = tmp_path / "linked.sqlite3"
    os.symlink(database, link)

    with pytest.raises(ValueError, match="regular file"):
        reconcile_archive(link, RUN_ID, _inputs())


def test_unregistered_caller_metadata_and_private_values_cannot_reach_output(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path / "private-marker.sqlite3")
    inputs = _inputs()
    digest_policy = replace(
        inputs,
        postrun_evaluation=replace(inputs.postrun_evaluation, policy_version="a" * 64),
    )
    with pytest.raises(ValueError, match="unknown postrun policy"):
        reconcile_archive(database, RUN_ID, digest_policy)

    encoded = json.dumps(reconcile_archive(database, RUN_ID, inputs), sort_keys=True)
    assert "private" not in encoded
    assert str(tmp_path) not in encoded
    assert RUN_ID not in encoded
    assert "70:72:69:76:61:74:65" not in encoded
