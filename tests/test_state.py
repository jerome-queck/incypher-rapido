import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import textwrap
from dataclasses import replace
from pathlib import Path

import pytest

import rapido.state as state_module
from rapido.evidence import EvidenceBatch, HostObservation, RunEvidence
from rapido.routing import baseline_route
from rapido.state import MAX_EVENT_BYTES, StateStore


def _attest_candidate(evidence: RunEvidence, attempt_id: str, candidate: str) -> None:
    fingerprint = hashlib.sha256(candidate.encode()).hexdigest()
    evidence.commit(
        attempt_id,
        EvidenceBatch(
            (
                HostObservation(
                    "inspect_file",
                    True,
                    True,
                    candidate_sha256s=(fingerprint,),
                ),
            )
        ),
    )
    assert evidence.attest_candidate(attempt_id, candidate_sha256=fingerprint) is not None


def _retain_private_wave_candidates(
    store: StateStore,
    run_id: str,
    challenge_id: int,
    episode: int,
    candidates: tuple[str, ...],
    *,
    attempt_prefix: str,
) -> None:
    store.start_control_wave(run_id, challenge_id, episode)
    for lane, candidate in enumerate(candidates):
        attempt_id = f"{attempt_prefix}-{lane}"
        store.start_attempt(
            attempt_id,
            run_id,
            challenge_id,
            episode,
            lane,
            "gpt-daybreak-blue-latest",
            "xhigh",
        )
        store.finish_attempt(
            attempt_id,
            "candidate",
            candidate=candidate,
            retain_private_candidate=True,
        )


def test_state_database_and_journal_are_private(tmp_path: Path) -> None:
    path = tmp_path / "private.sqlite3"
    store = StateStore(path)
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        if candidate.exists():
            assert stat.S_IMODE(candidate.stat().st_mode) & 0o077 == 0
    store.close()


def test_state_rejects_public_parent_directory(tmp_path: Path) -> None:
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    try:
        with pytest.raises(ValueError, match="mode 0700"):
            StateStore(public / "state.sqlite3")
    finally:
        public.chmod(0o700)


@pytest.mark.parametrize("suffix", ("-wal", "-shm"))
def test_state_rejects_preexisting_sidecar_symlink(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / "state.sqlite3"
    target = tmp_path / "outside"
    target.write_text("keep")
    target.chmod(0o644)
    Path(f"{path}{suffix}").symlink_to(target)
    with pytest.raises(ValueError, match="sidecars must be regular"):
        StateStore(path)
    assert target.read_text() == "keep"
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


def test_records_run_attempt_and_restart_recovery(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.acquire_supervisor()
    store.start_run("run-1", {"model": "gpt-5.6-luna"})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.set_challenge_status(1, "running")
    store.start_attempt("attempt-1", "run-1", 1, 0, "gpt-5.6-luna", "xhigh")
    assert len(store.active_attempts()) == 1
    assert store.recover_interrupted() == 1
    assert store.active_attempts() == []
    row = store._connection.execute("SELECT status FROM attempts WHERE id='attempt-1'").fetchone()
    event = store._connection.execute("SELECT kind, data_json FROM events").fetchone()
    assert row["status"] == "interrupted"
    assert event["kind"] == "recovery"
    assert event["data_json"] == '{"interrupted_attempts":1}'
    store.close()


def test_control_run_interruption_terminalizes_orphaned_running_attempt(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.start_attempt("attempt-1", "run-1", 1, 0, 0, "model", "xhigh")

    assert store.interrupt_control_run("run-1", "run_failed") == 0
    assert store.active_attempts() == []
    row = store._connection.execute(
        "SELECT status, finished_at, failure_class FROM attempts WHERE id='attempt-1'"
    ).fetchone()
    assert row["status"] == "interrupted"
    assert row["finished_at"] is not None
    assert row["failure_class"] == "interrupted"
    store.close()


def test_same_run_recovery_is_idempotent_and_rejects_config_change(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    config = {"run_seconds": 19_800, "model": "gpt-daybreak-blue-latest"}
    store.start_run("run-1", config)
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue("run-1", [(0, 1, True)])
    route = baseline_route(
        model="gpt-daybreak-blue-latest",
        effort="xhigh",
        attempt_seconds=800,
    )
    store.admit_control_wave(
        "run-1",
        1,
        0,
        0,
        2,
        route,
        (
            ("lead", "gpt-daybreak-blue-latest", "xhigh"),
            ("specialist", "gpt-5.6-luna", "max"),
        ),
    )
    store.start_control_wave("run-1", 1, 0)
    store.start_attempt(
        "attempt-1",
        "run-1",
        1,
        0,
        0,
        "gpt-daybreak-blue-latest",
        "xhigh",
        require_control_assignment=True,
    )
    store.acquire_supervisor()

    first = store.start_or_resume_run("unused", config)
    second = store.start_or_resume_run("unused-again", config)
    assert first.run_id == second.run_id == "run-1"
    assert first.resumed and second.resumed
    assert store.resume_control_waves("run-1", 10_000) == 1
    assert store.resume_control_waves("run-1", 10_000) == 0
    waves = store.queued_control_waves("run-1")
    assert [(wave.challenge_id, wave.episode, wave.route.role) for wave in waves] == [
        (1, 1, "recovery")
    ]
    assert store.attempts_for_challenge("run-1", 1)[0]["status"] == "interrupted"
    assert store.recovery_dispatch_count("run-1", 1) == 1
    with pytest.raises(RuntimeError, match="configuration differs"):
        store.start_or_resume_run("unused", {**config, "run_seconds": 60})
    assert len(store.queued_control_waves("run-1")) == 1
    store.close()


def test_repeated_restart_before_attempt_keeps_changing_recovery_route(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    config = {"run_seconds": 19_800}
    store.start_run("run-1", config)
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue("run-1", [(0, 1, True)])
    route = baseline_route(model="model", effort="xhigh", attempt_seconds=800)
    assignments = (("lead", "model", "xhigh"), ("specialist", "model", "xhigh"))
    store.admit_control_wave("run-1", 1, 0, 0, 2, route, assignments)
    store.start_control_wave("run-1", 1, 0)
    store.acquire_supervisor()

    store.start_or_resume_run("unused", config)
    assert store.resume_control_waves("run-1", 10_000) == 1
    first = store.queued_control_waves("run-1")[0]
    assert first.episode == first.route.workspace_generation == 1

    store.start_control_wave("run-1", 1, 1)
    store.start_or_resume_run("unused-again", config)
    assert store.resume_control_waves("run-1", 10_000) == 1
    second = store.queued_control_waves("run-1")[0]
    assert second.episode == second.route.workspace_generation == 2
    assert store.recovery_dispatch_count("run-1", 1) == 2
    store.close()


def test_reconciled_correct_closes_interrupted_challenge_without_retry(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    config = {"run_seconds": 19_800}
    store.start_run("run-1", config)
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue("run-1", [(0, 1, True)])
    route = baseline_route(model="model", effort="xhigh", attempt_seconds=800)
    store.admit_control_wave(
        "run-1",
        1,
        0,
        0,
        2,
        route,
        (("lead", "model", "xhigh"), ("specialist", "model", "xhigh")),
    )
    store.start_control_wave("run-1", 1, 0)
    candidate = "INCYPHER{delivered-before-process-loss}"
    assert store.reserve_submission(
        "run-1", 1, candidate, provenance_class="source_observed_candidate"
    )
    store.reconcile_submission_intent(
        1,
        hashlib.sha256(candidate.encode()).hexdigest(),
        "correct",
    )
    store.acquire_supervisor()

    store.start_or_resume_run("unused", config)
    assert store.resume_control_waves("run-1", 10_000) == 0
    assert store.queued_control_waves("run-1") == ()
    assert store.challenge_has_correct_submission("run-1", 1)
    assert store.run_terminal_outcomes("run-1") == {1: "solved"}
    row = store._connection.execute(
        "SELECT outcome, http_status, provenance_class FROM submissions"
    ).fetchone()
    assert tuple(row) == ("correct", 0, "source_observed_candidate")
    counts = store.run_evaluation_counts("run-1")
    assert counts["submission_correct"] == 1
    assert counts["submission_http_200_correct"] == 0
    assert counts["submission_reconciled_correct"] == 1
    assert counts["source_observed_correct"] == 1
    store.close()


def test_material_refresh_retires_old_correct_submission_authority(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    route = baseline_route(model="model", effort="xhigh", attempt_seconds=800)
    assignments = (("lead", "model", "xhigh"), ("specialist", "model", "xhigh"))
    store.initialize_control_catalogue(
        "run-1",
        [(0, 1, True)],
        2,
        route,
        assignments,
        {1: "a" * 64},
    )
    store.record_submission("run-1", 1, "INCYPHER{old_material}", "correct", 200)
    assert store.candidate_submission_status("run-1", 1, "INCYPHER{old_material}") == (
        "correct",
        "run-1",
        0,
        "a" * 64,
    )
    store.finish_control_wave("run-1", 1, 0, "solved")

    kind, episode, _ = store.admit_control_catalogue_revision(
        run_id="run-1",
        challenge_id=1,
        name="A",
        category="crypto",
        challenge_type="standard",
        value=100,
        executable=True,
        context_sha256="b" * 64,
        new_catalogue_rank=1,
        lanes=2,
        route=route,
        assignments=assignments,
    )

    assert (kind, episode) == ("refreshed", 1)
    assert not store.challenge_has_correct_submission("run-1", 1)
    assert store.reserve_submission("run-1", 1, "INCYPHER{old_material}")
    assert store.candidate_submission_status("run-1", 1, "INCYPHER{old_material}") == (
        "pending",
        "run-1",
        1,
        "b" * 64,
    )
    store.finalize_submission("run-1", 1, "INCYPHER{old_material}", "incorrect", 200)
    assert store.reserve_submission("run-1", 1, "INCYPHER{new_material}")
    store.finalize_submission("run-1", 1, "INCYPHER{new_material}", "incorrect", 200)
    rows = store._connection.execute(
        "SELECT context_episode, context_sha256, status FROM submission_intents "
        "WHERE challenge_id=1 ORDER BY context_episode, candidate_sha256"
    ).fetchall()
    assert [tuple(row) for row in rows] == [
        (0, "a" * 64, "correct"),
        (1, "b" * 64, "incorrect"),
        (1, "b" * 64, "incorrect"),
    ]
    assert store.challenge_incorrect_submission_count("run-1", 1) == 2
    store.finish_control_wave("run-1", 1, 1, "unsolved")
    kind, episode, _ = store.admit_control_catalogue_revision(
        run_id="run-1",
        challenge_id=1,
        name="A",
        category="crypto",
        challenge_type="standard",
        value=100,
        executable=True,
        context_sha256="a" * 64,
        new_catalogue_rank=2,
        lanes=2,
        route=route,
        assignments=assignments,
    )
    assert (kind, episode) == ("refreshed", 2)
    assert store.candidate_submission_status("run-1", 1, "INCYPHER{old_material}") == (
        "correct",
        "run-1",
        0,
        "a" * 64,
    )
    assert not store.reserve_submission("run-1", 1, "INCYPHER{old_material}")
    assert store.challenge_incorrect_submission_count("run-1", 1) == 0
    store.finish_control_wave("run-1", 1, 2, "unsolved")
    store.set_challenge_status(1, "unsolved")
    assert store.run_terminal_outcomes("run-1") == {1: "unsolved"}
    store.close()


def test_submission_provenance_is_atomic_without_telemetry_event(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue("run-1", [(0, 1, True)])
    candidate = "INCYPHER{atomic_provenance}"
    assert store.reserve_submission(
        "run-1", 1, candidate, provenance_class="source_observed_candidate"
    )
    assert (
        store._connection.execute("SELECT provenance_class FROM submission_intents").fetchone()[0]
        == "source_observed_candidate"
    )

    store.finalize_submission(
        "run-1",
        1,
        candidate,
        "correct",
        200,
        provenance_class="source_observed_candidate",
    )

    assert store._connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    counts = store.run_evaluation_counts("run-1")
    assert counts["submission_correct"] == 1
    assert counts["submission_http_200_correct"] == 1
    assert counts["submission_reconciled_correct"] == 0
    assert counts["source_observed_correct"] == 1
    assert counts["unknown_origin_correct"] == 0
    store.close()


def test_verification_is_retired_when_material_identity_changes_in_place(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    run_id = "scope-run"
    candidate = "INCYPHER{material_scoped}"
    producer = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    verifier = replace(
        producer,
        role="verifier",
        tactic="independent_source_reobservation",
        context_profile="fresh_source_only_no_candidate_carry",
        verification_recipe="fresh_source_reobservation_v1",
    )
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.initialize_control_catalogue(
        run_id,
        [(0, 1, True)],
        1,
        producer,
        (("specialist", producer.model, producer.effort),),
        {1: "a" * 64},
    )
    store.start_control_wave(run_id, 1, 0)
    store.start_attempt("producer", run_id, 1, 0, 0, producer.model, producer.effort)
    evidence = RunEvidence.open(store, run_id)
    _attest_candidate(evidence, "producer", candidate)
    store.finish_attempt(
        "producer", "candidate", candidate=candidate, retain_private_candidate=True
    )
    store.admit_control_wave(run_id, 1, 1, 0, 1, verifier)
    store.start_control_wave(run_id, 1, 1)
    store.start_attempt("verifier", run_id, 1, 1, 0, verifier.model, verifier.effort)
    _attest_candidate(evidence, "verifier", candidate)
    store.finish_attempt(
        "verifier", "candidate", candidate=candidate, retain_private_candidate=True
    )
    assert store.candidate_is_verified(run_id, 1, candidate)

    store._connection.execute(
        "UPDATE control_catalogue SET context_sha256=? WHERE run_id=? AND challenge_id=1",
        ("b" * 64, run_id),
    )

    assert not store.candidate_is_verified(run_id, 1, candidate)
    assert store.run_evaluation_counts(run_id)["independently_verified"] == 0
    store.close()


def test_dynamic_verifier_without_owned_generation_cannot_verify(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    run_id = "dynamic-scope-run"
    candidate = "INCYPHER{dynamic_requires_receipt}"
    producer = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    verifier = replace(
        producer,
        role="verifier",
        tactic="independent_source_reobservation",
        context_profile="fresh_source_only_no_candidate_carry",
        verification_recipe="fresh_source_reobservation_v1",
    )
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "pwn", "dynamic_iac", 100)
    store.initialize_control_catalogue(
        run_id,
        [(0, 1, True)],
        1,
        producer,
        (("specialist", producer.model, producer.effort),),
        {1: "a" * 64},
    )
    evidence = RunEvidence.open(store, run_id)
    store.start_control_wave(run_id, 1, 0)
    store.start_attempt("producer", run_id, 1, 0, 0, producer.model, producer.effort)
    _attest_candidate(evidence, "producer", candidate)
    store.finish_attempt(
        "producer", "candidate", candidate=candidate, retain_private_candidate=True
    )
    store.admit_control_wave(run_id, 1, 1, 0, 1, verifier)
    store.start_control_wave(run_id, 1, 1)
    store.start_attempt("verifier", run_id, 1, 1, 0, verifier.model, verifier.effort)
    _attest_candidate(evidence, "verifier", candidate)
    store.finish_attempt(
        "verifier", "candidate", candidate=candidate, retain_private_candidate=True
    )

    assert (
        store._connection.execute("SELECT COUNT(*) FROM candidate_verifications").fetchone()[0] == 0
    )
    assert not store.candidate_is_verified(run_id, 1, candidate)
    assert store.pending_candidate_count(run_id, 1) == 1
    store.close()


def test_dynamic_verification_rotates_with_instance_generation(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    run_id = "dynamic-generation-run"
    candidate = "INCYPHER{generation_scoped}"
    producer = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    verifier = replace(
        producer,
        role="verifier",
        tactic="independent_source_reobservation",
        context_profile="fresh_source_only_no_candidate_carry",
        verification_recipe="fresh_source_reobservation_v1",
    )
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "pwn", "dynamic_iac", 100)
    store.initialize_control_catalogue(
        run_id,
        [(0, 1, True)],
        1,
        producer,
        (("specialist", producer.model, producer.effort),),
        {1: "a" * 64},
    )
    evidence = RunEvidence.open(store, run_id)

    def retain(attempt_id: str, episode: int, route) -> None:
        store.admit_control_wave(run_id, 1, episode, 0, 1, route)
        store.start_control_wave(run_id, 1, episode)
        store.start_attempt(attempt_id, run_id, 1, episode, 0, route.model, route.effort)
        _attest_candidate(evidence, attempt_id, candidate)
        store.finish_attempt(
            attempt_id, "candidate", candidate=candidate, retain_private_candidate=True
        )

    store.mark_instance(run_id, 1, "owned", receipt_sha256="b" * 64)
    store.start_control_wave(run_id, 1, 0)
    store.start_attempt("producer-b", run_id, 1, 0, 0, producer.model, producer.effort)
    _attest_candidate(evidence, "producer-b", candidate)
    store.finish_attempt(
        "producer-b", "candidate", candidate=candidate, retain_private_candidate=True
    )
    retain("verifier-b", 1, verifier)
    assert store.candidate_is_verified(run_id, 1, candidate)

    store.mark_instance(run_id, 1, "creating")
    assert not store.candidate_is_verified(run_id, 1, candidate)
    assert (
        store._connection.execute(
            "SELECT instance_receipt_sha256 FROM candidate_verification_history"
        ).fetchone()[0]
        == "b" * 64
    )

    store.mark_instance(run_id, 1, "owned", receipt_sha256="c" * 64)
    retain("producer-c", 2, producer)
    retain("verifier-c", 3, verifier)
    current = store._connection.execute(
        "SELECT instance_receipt_sha256 FROM current_candidate_verifications"
    ).fetchone()
    assert current[0] == "c" * 64
    assert store.candidate_is_verified(run_id, 1, candidate)
    store.close()


def test_old_material_submission_does_not_hide_current_unverified_candidate(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    run_id = "rescope-run"
    candidate = "INCYPHER{same_value_new_material}"
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    assignment = (("specialist", route.model, route.effort),)
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.initialize_control_catalogue(run_id, [(0, 1, True)], 1, route, assignment, {1: "a" * 64})
    evidence = RunEvidence.open(store, run_id)
    store.start_control_wave(run_id, 1, 0)
    store.start_attempt("old", run_id, 1, 0, 0, route.model, route.effort)
    _attest_candidate(evidence, "old", candidate)
    store.finish_attempt("old", "candidate", candidate=candidate, retain_private_candidate=True)
    store.record_submission(run_id, 1, candidate, "incorrect", 200)
    store.finish_control_wave(run_id, 1, 0, "unsolved")
    _, episode, _ = store.admit_control_catalogue_revision(
        run_id=run_id,
        challenge_id=1,
        name="A",
        category="crypto",
        challenge_type="standard",
        value=100,
        executable=True,
        context_sha256="b" * 64,
        new_catalogue_rank=1,
        lanes=1,
        route=route,
        assignments=assignment,
    )
    store.start_control_wave(run_id, 1, episode)
    store.start_attempt("new", run_id, 1, episode, 0, route.model, route.effort)
    _attest_candidate(evidence, "new", candidate)
    store.finish_attempt("new", "candidate", candidate=candidate, retain_private_candidate=True)

    counts = store.run_evaluation_counts(run_id)
    assert counts["unverified_challenges"] == 1
    assert store.pending_candidate_count(run_id, 1) == 1
    store.close()


def test_supervisor_lease_excludes_concurrent_recovery(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    first = StateStore(path)
    second = StateStore(path)
    first.acquire_supervisor()
    with pytest.raises(RuntimeError, match="owns the state or native-auth lease"):
        second.acquire_supervisor()
    first.release_supervisor()
    second.acquire_supervisor()
    second.release_supervisor()
    first.close()
    second.close()


def test_supervisor_lease_refuses_preexisting_symlink(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    store = StateStore(path)
    target = tmp_path / "unrelated"
    target.write_text("keep")
    target.chmod(0o644)
    path.with_name(f"{path.name}.lock").symlink_to(target)
    with pytest.raises(RuntimeError, match="owns the state"):
        store.acquire_supervisor()
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    store.close()


def test_shared_auth_lease_excludes_distinct_state_paths(tmp_path: Path) -> None:
    auth = tmp_path / "auth"
    auth.mkdir()
    first = StateStore(tmp_path / "one.sqlite3")
    second = StateStore(tmp_path / "two.sqlite3")
    first.acquire_supervisor(auth / ".rapido-supervisor.lock")
    with pytest.raises(RuntimeError, match="owns the state or native-auth lease"):
        second.acquire_supervisor(auth / ".rapido-supervisor.lock")
    first.close()
    second.close()


def test_shared_work_lease_excludes_distinct_state_and_auth_paths(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    first = StateStore(tmp_path / "one.sqlite3")
    second = StateStore(tmp_path / "two.sqlite3")
    first.acquire_supervisor(work_lease_path=work / ".rapido-work.lock")
    with pytest.raises(RuntimeError, match="work lease"):
        second.acquire_supervisor(work_lease_path=work / ".rapido-work.lock")
    first.close()
    second.close()


def test_finishing_attempt_is_single_transition(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.start_attempt("attempt-1", "run-1", 1, 0, "model", "high")
    store.finish_attempt(
        "attempt-1", "candidate", candidate="INCYPHER{x}", confidence=0.9, summary="decoded"
    )
    with pytest.raises(ValueError, match="not running"):
        store.finish_attempt("attempt-1", "failed")
    store.close()


def test_productive_timeout_preserves_checkpoint_and_admits_daybreak_heavy_recovery(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    run_id = "timeout-run"
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=800)
    assignments = (
        ("lead", "gpt-daybreak-blue-latest", "xhigh"),
        ("lead", "gpt-daybreak-blue-latest", "xhigh"),
        ("specialist", "gpt-5.6-luna", "max"),
        ("specialist", "gpt-5.6-luna", "xhigh"),
    )
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue(run_id, [(0, 1, True)])
    store.admit_control_wave(run_id, 1, 0, 0, 4, route, assignments)
    store.start_control_wave(run_id, 1, 0)
    evidence = RunEvidence.open(store, run_id)
    for lane, (_, model, effort) in enumerate(assignments):
        attempt_id = f"timeout-{lane}"
        store.start_attempt(attempt_id, run_id, 1, 0, lane, model, effort)
        if lane == 0:
            store.checkpoint_attempt(
                attempt_id,
                summary="archive structure mapped",
                evidence=("header parsed",),
                next_steps=("try alternate decompressor",),
                observations=(
                    {
                        "ordinal": 0,
                        "complete": True,
                        "gap": None,
                        "tool": "inspect_file",
                        "success": True,
                        "source_bound": True,
                        "facts": {"format": "zip"},
                    },
                ),
                tool_count=1,
            )
        evidence.commit(
            attempt_id,
            EvidenceBatch(
                (HostObservation("inspect_file", True, True),),
                complete=False,
                gap="turn_timeout",
            ),
        )
        store.finish_attempt(
            attempt_id,
            "timeout",
            summary="native turn exceeded deadline",
            tool_count=1,
            failure_class="timeout",
        )

    decision = store.finish_and_decide_control_wave(
        run_id=run_id,
        challenge_id=1,
        source_episode=0,
        next_episode=1,
        catalogue_rank=0,
        lanes=4,
        terminal="error",
        attempts_remaining=True,
        remaining_milliseconds=2_000_000,
    )
    assert decision is not None and decision.rule_id == "typed_timeout_recovery_v1"
    rows = store._connection.execute(
        "SELECT agent_role, model, effort FROM control_jobs "
        "WHERE run_id=? AND challenge_id=1 AND episode=1 ORDER BY lane",
        (run_id,),
    ).fetchall()
    assert [tuple(row) for row in rows] == [
        ("recovery", "gpt-daybreak-blue-latest", "xhigh"),
        ("recovery", "gpt-daybreak-blue-latest", "xhigh"),
        ("recovery", "gpt-daybreak-blue-latest", "xhigh"),
        ("recovery", "gpt-5.6-luna", "max"),
    ]
    memory = store.same_run_memory_sources(run_id, 1, target_lane=0, before_episode=1)
    assert memory[0]["summary"] == "archive structure mapped"
    assert memory[0]["next_steps"] == ["try alternate decompressor"]
    assert memory[0]["checkpoint_observations"][0]["facts"] == {"format": "zip"}

    store.start_control_wave(run_id, 1, 1)
    for lane, row in enumerate(rows):
        attempt_id = f"interleaved-{lane}"
        store.start_attempt(attempt_id, run_id, 1, 1, lane, row["model"], row["effort"])
        evidence.commit(
            attempt_id,
            EvidenceBatch((HostObservation("inspect_file", True, True),)),
        )
        store.finish_attempt(
            attempt_id,
            "failed",
            tool_count=1,
            failure_class="solver_output",
        )
    interleaved = store.finish_and_decide_control_wave(
        run_id=run_id,
        challenge_id=1,
        source_episode=1,
        next_episode=2,
        catalogue_rank=0,
        lanes=4,
        terminal="error",
        attempts_remaining=True,
        remaining_milliseconds=10_000,
    )
    assert interleaved is not None and interleaved.rule_id == "tool_alternate_representation_v1"

    store.start_control_wave(run_id, 1, 2)
    rows = store._connection.execute(
        "SELECT model, effort FROM control_jobs "
        "WHERE run_id=? AND challenge_id=1 AND episode=2 ORDER BY lane",
        (run_id,),
    ).fetchall()
    for lane, row in enumerate(rows):
        attempt_id = f"second-timeout-{lane}"
        store.start_attempt(attempt_id, run_id, 1, 2, lane, row["model"], row["effort"])
        evidence.commit(
            attempt_id,
            EvidenceBatch(
                (HostObservation("inspect_file", True, True),),
                complete=False,
                gap="turn_timeout",
            ),
        )
        store.finish_attempt(
            attempt_id,
            "timeout",
            tool_count=1,
            failure_class="timeout",
        )
    repeated = store.finish_and_decide_control_wave(
        run_id=run_id,
        challenge_id=1,
        source_episode=2,
        next_episode=3,
        catalogue_rank=0,
        lanes=4,
        terminal="error",
        attempts_remaining=True,
        remaining_milliseconds=10_000,
    )
    assert repeated is not None and repeated.rule_id == "timeout_recovery_exhausted"
    assert repeated.disposition == "contain"
    assert (
        store._connection.execute(
            "SELECT COUNT(*) FROM control_jobs WHERE run_id=? AND episode=3", (run_id,)
        ).fetchone()[0]
        == 0
    )
    store.close()


def test_private_candidate_and_attempt_close_roll_back_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    run_id = "private-run"
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue(run_id, [(0, 1, True)])
    store.admit_control_wave(run_id, 1, 0, 0, 2, route)
    store.start_control_wave(run_id, 1, 0)
    store.start_attempt("attempt-1", run_id, 1, 0, 0, route.model, route.effort)
    original = store._retain_candidate

    def fail_after_insert(*args: object, **kwargs: object) -> None:
        original(*args, **kwargs)
        raise RuntimeError("fault after private insert")

    monkeypatch.setattr(store, "_retain_candidate", fail_after_insert)
    with pytest.raises(RuntimeError, match="fault after private insert"):
        store.finish_attempt(
            "attempt-1",
            "candidate",
            candidate="INCYPHER{atomic_private_close}",
            retain_private_candidate=True,
        )

    attempt = store._connection.execute(
        "SELECT status, candidate FROM attempts WHERE id='attempt-1'"
    ).fetchone()
    assert tuple(attempt) == ("running", None)
    assert store._connection.execute("SELECT COUNT(*) FROM candidate_proposals").fetchone()[0] == 0
    store.close()


def test_private_candidate_source_identity_is_immutable(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    run_id = "private-run"
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue(run_id, [(0, 1, True)])
    store.admit_control_wave(run_id, 1, 0, 0, 2, route)
    store.start_control_wave(run_id, 1, 0)
    store.start_attempt("attempt-1", run_id, 1, 0, 0, route.model, route.effort)
    first = "INCYPHER{immutable_private_source}"
    store.finish_attempt(
        "attempt-1",
        "candidate",
        candidate=first,
        retain_private_candidate=True,
    )
    with pytest.raises(ValueError, match="not running"):
        store.finish_attempt(
            "attempt-1",
            "candidate",
            candidate="INCYPHER{altered_replay}",
            retain_private_candidate=True,
        )
    row = store._connection.execute(
        "SELECT candidate FROM candidate_proposals WHERE source_attempt_id='attempt-1'"
    ).fetchone()
    assert bytes(row["candidate"]).decode() == first
    assert (
        store._connection.execute("SELECT candidate FROM attempts WHERE id='attempt-1'").fetchone()[
            0
        ]
        is None
    )
    store.close()


def test_private_candidate_source_scope_is_database_bound(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    store.start_run("source-run", {})
    store.start_run("forged-run", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue("source-run", [(0, 1, True)])
    store.admit_control_wave("source-run", 1, 0, 0, 1, route)
    store.start_control_wave("source-run", 1, 0)
    store.start_attempt("source-attempt", "source-run", 1, 0, 0, route.model, route.effort)

    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        store._connection.execute(
            """
            INSERT INTO candidate_proposals(
              source_attempt_id, run_id, challenge_id, episode, lane, role, recipe_kind,
              candidate_key, candidate, retained_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "source-attempt",
                "forged-run",
                1,
                0,
                0,
                "specialist",
                "source_bound_tool_observation_v1",
                b"x" * 32,
                b"INCYPHER{scope_forgery}",
                "2026-09-16T00:00:00+00:00",
            ),
        )
    assert store._connection.execute("SELECT COUNT(*) FROM candidate_proposals").fetchone()[0] == 0
    store.close()


@pytest.mark.parametrize("crash_before_commit", (True, False))
def test_private_candidate_crash_boundary_is_atomic(
    tmp_path: Path, crash_before_commit: bool
) -> None:
    path = tmp_path / "state.sqlite3"
    code = textwrap.dedent(
        """
        import os
        import sys
        from pathlib import Path

        from rapido.evidence import EvidenceBatch, HostObservation, RunEvidence
        from rapido.routing import baseline_route
        from rapido.state import StateStore

        path = Path(sys.argv[1])
        crash_before_commit = sys.argv[2] == "pre"
        store = StateStore(path)
        run_id = "crash-run"
        route = baseline_route(
            model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15
        )
        store.start_run(run_id, {})
        store.upsert_challenge(1, "A", "crypto", "standard", 100)
        store.record_control_catalogue(run_id, [(0, 1, True)])
        store.admit_control_wave(run_id, 1, 0, 0, 2, route)
        store.start_control_wave(run_id, 1, 0)
        store.start_attempt("attempt-1", run_id, 1, 0, 0, route.model, route.effort)
        if crash_before_commit:
            store._connection.create_function("crash_now", 0, lambda: os._exit(29))
            store._connection.execute(
                "CREATE TEMP TRIGGER crash_private AFTER INSERT ON candidate_proposals "
                "BEGIN SELECT crash_now(); END"
            )
        store.finish_attempt(
            "attempt-1",
            "candidate",
            candidate="INCYPHER{crash_atomic_private}",
            retain_private_candidate=True,
        )
        os._exit(29)
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", code, str(path), "pre" if crash_before_commit else "post"],
        check=False,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])},
        timeout=10,
    )
    assert completed.returncode == 29

    reopened = StateStore(path)
    attempt = reopened._connection.execute(
        "SELECT status, candidate FROM attempts WHERE id='attempt-1'"
    ).fetchone()
    proposal_count = reopened._connection.execute(
        "SELECT COUNT(*) FROM candidate_proposals"
    ).fetchone()[0]
    if crash_before_commit:
        assert tuple(attempt) == ("running", None)
        assert proposal_count == 0
    else:
        assert tuple(attempt) == ("candidate", None)
        assert proposal_count == 1
    reopened.close()


def test_attested_checkpoint_crash_routes_recovery_instead_of_verifier(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    code = textwrap.dedent(
        """
        import hashlib
        import os
        import sys
        from pathlib import Path

        from rapido.evidence import EvidenceBatch, HostObservation, RunEvidence
        from rapido.routing import baseline_route
        from rapido.state import StateStore

        path = Path(sys.argv[1])
        store = StateStore(path)
        store.acquire_supervisor()
        run_id = "attested-checkpoint-crash"
        candidate = "INCYPHER{attested_before_terminal_crash}"
        candidate_sha256 = hashlib.sha256(candidate.encode()).hexdigest()
        route = baseline_route(
            model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15
        )
        store.start_run(run_id, {})
        store.upsert_challenge(1, "A", "crypto", "standard", 100)
        store.record_control_catalogue(run_id, [(0, 1, True)])
        store.admit_control_wave(run_id, 1, 0, 0, 1, route)
        store.start_control_wave(run_id, 1, 0)
        store.start_attempt("producer", run_id, 1, 0, 0, route.model, route.effort)
        store.checkpoint_attempt("producer", summary="qualified", candidate=candidate)
        evidence = RunEvidence.open(store, run_id)
        evidence.commit(
            "producer",
            EvidenceBatch(
                (
                    HostObservation(
                        "inspect_file",
                        True,
                        True,
                        candidate_sha256s=(candidate_sha256,),
                    ),
                )
            ),
        )
        assert evidence.attest_candidate(
            "producer", candidate_sha256=candidate_sha256
        ) is not None
        os._exit(37)
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", code, str(path)],
        check=False,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])},
        timeout=10,
    )
    assert completed.returncode == 37

    reopened = StateStore(path)
    reopened.acquire_supervisor()
    assert reopened._connection.execute("SELECT status FROM attempts").fetchone()[0] == "running"
    assert (
        reopened._connection.execute("SELECT COUNT(*) FROM candidate_proposals").fetchone()[0] == 1
    )
    assert (
        reopened._connection.execute("SELECT COUNT(*) FROM candidate_evidence_proofs").fetchone()[0]
        == 1
    )
    session = reopened.start_or_resume_run("unused", {})
    assert session.run_id == "attested-checkpoint-crash" and session.resumed
    assert (
        reopened._connection.execute("SELECT status FROM attempts").fetchone()[0] == "interrupted"
    )
    assert reopened.candidate_counts("attested-checkpoint-crash") == (0, 0)
    assert reopened.pending_candidate_count("attested-checkpoint-crash", 1) == 0

    assert reopened.resume_control_waves("attested-checkpoint-crash", 10_000) == 1
    decision_row = reopened._connection.execute(
        "SELECT failure_kind, failure_subreason, rule_id "
        "FROM control_route_decisions WHERE run_id=?",
        ("attested-checkpoint-crash",),
    ).fetchone()
    assert tuple(decision_row) == (
        "container",
        "process_restart",
        "container_fresh_workspace_v1",
    )
    successor_roles = reopened._connection.execute(
        "SELECT DISTINCT role FROM control_jobs WHERE run_id=? AND episode=1",
        ("attested-checkpoint-crash",),
    ).fetchall()
    assert [row[0] for row in successor_roles] == ["recovery"]
    reopened.release_supervisor()
    reopened.close()


@pytest.mark.parametrize("crash_before_commit", (True, False))
def test_private_verification_crash_boundary_is_atomic(
    tmp_path: Path, crash_before_commit: bool
) -> None:
    path = tmp_path / "state.sqlite3"
    code = textwrap.dedent(
        """
        import os
        import sys
        from dataclasses import replace
        from pathlib import Path

        from rapido.evidence import EvidenceBatch, HostObservation, RunEvidence
        from rapido.routing import baseline_route
        from rapido.state import StateStore

        path = Path(sys.argv[1])
        crash_before_commit = sys.argv[2] == "pre"
        store = StateStore(path)
        run_id = "verification-crash-run"
        candidate = "INCYPHER{verification_crash_atomic}"
        producer = baseline_route(
            model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15
        )
        verifier = replace(
            producer,
            role="verifier",
            tactic="independent_source_reobservation",
            context_profile="fresh_source_only_no_candidate_carry",
            verification_recipe="fresh_source_reobservation_v1",
        )
        store.start_run(run_id, {})
        store.upsert_challenge(1, "A", "crypto", "standard", 100)
        store.record_control_catalogue(run_id, [(0, 1, True)])
        store.admit_control_wave(run_id, 1, 0, 0, 1, producer)
        store.start_control_wave(run_id, 1, 0)
        store.start_attempt("producer", run_id, 1, 0, 0, producer.model, producer.effort)
        evidence = RunEvidence.open(store, run_id)
        fingerprint = __import__("hashlib").sha256(candidate.encode()).hexdigest()
        evidence.commit(
            "producer",
            EvidenceBatch((HostObservation("inspect_file", True, True,
                candidate_sha256s=(fingerprint,)),)),
        )
        assert evidence.attest_candidate(
            "producer", candidate_sha256=fingerprint
        ) is not None
        store.finish_attempt(
            "producer", "candidate", candidate=candidate, retain_private_candidate=True
        )
        store.admit_control_wave(run_id, 1, 1, 1, 1, verifier)
        store.start_control_wave(run_id, 1, 1)
        store.start_attempt("verifier", run_id, 1, 1, 0, verifier.model, verifier.effort)
        evidence.commit(
            "verifier",
            EvidenceBatch((HostObservation("inspect_file", True, True,
                candidate_sha256s=(fingerprint,)),)),
        )
        assert evidence.attest_candidate(
            "verifier", candidate_sha256=fingerprint
        ) is not None
        if crash_before_commit:
            store._connection.create_function("crash_now", 0, lambda: os._exit(31))
            store._connection.execute(
                "CREATE TEMP TRIGGER crash_verification "
                "AFTER INSERT ON candidate_verifications BEGIN SELECT crash_now(); END"
            )
        store.finish_attempt(
            "verifier", "candidate", candidate=candidate, retain_private_candidate=True
        )
        os._exit(31)
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", code, str(path), "pre" if crash_before_commit else "post"],
        check=False,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])},
        timeout=10,
    )
    assert completed.returncode == 31

    reopened = StateStore(path)
    verifier = reopened._connection.execute(
        "SELECT status, candidate FROM attempts WHERE id='verifier'"
    ).fetchone()
    proposal_count = reopened._connection.execute(
        "SELECT COUNT(*) FROM candidate_proposals"
    ).fetchone()[0]
    verification_count = reopened._connection.execute(
        "SELECT COUNT(*) FROM candidate_verifications"
    ).fetchone()[0]
    if crash_before_commit:
        assert tuple(verifier) == ("running", None)
        assert proposal_count == 1
        assert verification_count == 0
    else:
        assert tuple(verifier) == ("candidate", None)
        assert proposal_count == 2
        assert verification_count == 1
    reopened.close()


def test_interrupted_checkpoint_candidate_cannot_be_verified(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.acquire_supervisor()
    run_id = "interrupted-proof-run"
    candidate = "INCYPHER{interrupted_proof_is_not_complete}"
    producer = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    verifier = replace(
        producer,
        role="verifier",
        tactic="independent_source_reobservation",
        context_profile="fresh_source_only_no_candidate_carry",
        verification_recipe="fresh_source_reobservation_v1",
    )
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue(run_id, [(0, 1, True)])
    store.admit_control_wave(run_id, 1, 0, 0, 1, producer)
    store.start_control_wave(run_id, 1, 0)
    store.start_attempt("producer", run_id, 1, 0, 0, producer.model, producer.effort)
    store.checkpoint_attempt("producer", summary="qualified", candidate=candidate)
    evidence = RunEvidence.open(store, run_id)
    evidence.commit("producer", EvidenceBatch(complete=False, gap="process_interrupted"))
    assert store.recover_interrupted() == 1

    store.admit_control_wave(run_id, 1, 1, 1, 1, verifier)
    store.start_control_wave(run_id, 1, 1)
    store.start_attempt("verifier", run_id, 1, 1, 0, verifier.model, verifier.effort)
    _attest_candidate(evidence, "verifier", candidate)
    store.finish_attempt(
        "verifier", "candidate", candidate=candidate, retain_private_candidate=True
    )

    assert store.verified_candidate(run_id, 1) is None
    assert not store.candidate_is_verified(run_id, 1, candidate)
    assert store.candidate_counts(run_id) == (0, 0)
    store.close()


def test_empty_manifest_candidate_cannot_be_verified(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    run_id = "empty-proof-run"
    candidate = "INCYPHER{empty_is_not_source_proof}"
    producer = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    verifier = replace(
        producer,
        role="verifier",
        tactic="independent_source_reobservation",
        context_profile="fresh_source_only_no_candidate_carry",
        verification_recipe="fresh_source_reobservation_v1",
    )
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue(run_id, [(0, 1, True)])
    store.admit_control_wave(run_id, 1, 0, 0, 1, producer)
    store.start_control_wave(run_id, 1, 0)
    store.start_attempt("producer", run_id, 1, 0, 0, producer.model, producer.effort)
    evidence = RunEvidence.open(store, run_id)
    evidence.commit("producer", EvidenceBatch())
    assert (
        evidence.attest_candidate(
            "producer", candidate_sha256=hashlib.sha256(candidate.encode()).hexdigest()
        )
        is None
    )
    store.finish_attempt(
        "producer", "candidate", candidate=candidate, retain_private_candidate=True
    )
    store.admit_control_wave(run_id, 1, 1, 1, 1, verifier)
    store.start_control_wave(run_id, 1, 1)
    store.start_attempt("verifier", run_id, 1, 1, 0, verifier.model, verifier.effort)
    _attest_candidate(evidence, "verifier", candidate)
    store.finish_attempt(
        "verifier", "candidate", candidate=candidate, retain_private_candidate=True
    )
    candidate_key = hashlib.sha256(candidate.encode()).digest()
    store._connection.execute(
        """
        INSERT INTO candidate_verifications(
            run_id, challenge_id, candidate_key, producer_attempt_id, producer_role,
            verifier_attempt_id, verifier_role, recipe_kind, verified_at
        ) VALUES (?, 1, ?, 'producer', 'specialist', 'verifier', 'verifier',
                  'fresh_source_reobservation_v1', ?)
        """,
        (run_id, candidate_key, store._now()),
    )

    assert store.verified_candidate(run_id, 1) is None
    assert not store.candidate_is_verified(run_id, 1, candidate)
    assert store.candidate_counts(run_id) == (0, 0)
    context = store.private_candidate_context_sources(run_id, 1, before_episode=2)
    assert context[0]["verifier_attempt_id"] is None
    store.close()


def test_private_incorrect_candidates_are_exactly_scoped_and_settled(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    main_candidates = (
        "INCYPHER{wrong_b}",
        "INCYPHER{wrong_a}",
        "INCYPHER{pending}",
        "INCYPHER{unread}",
        "INCYPHER{correct}",
        "INCYPHER{already_solved}",
    )
    assignments = tuple(("specialist", route.model, route.effort) for _ in main_candidates)
    store.start_run("main-run", {})
    store.start_run("other-run", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.upsert_challenge(2, "B", "crypto", "standard", 100)
    store.initialize_control_catalogue(
        "main-run",
        [(0, 1, True), (1, 2, True)],
        len(main_candidates),
        route,
        assignments,
        {1: "a" * 64, 2: "b" * 64},
    )
    _retain_private_wave_candidates(store, "main-run", 1, 0, main_candidates, attempt_prefix="main")
    other_challenge = "INCYPHER{other_challenge}"
    _retain_private_wave_candidates(
        store, "main-run", 2, 0, (other_challenge,), attempt_prefix="challenge-2"
    )
    store.initialize_control_catalogue(
        "other-run",
        [(0, 1, True)],
        1,
        route,
        (("specialist", route.model, route.effort),),
        {1: "a" * 64},
    )
    other_run = "INCYPHER{other_run}"
    _retain_private_wave_candidates(
        store, "other-run", 1, 0, (other_run,), attempt_prefix="other-run"
    )

    for candidate in main_candidates[:2]:
        store.record_submission("main-run", 1, candidate, "incorrect", 200)
    store.record_submission("main-run", 1, main_candidates[4], "correct", 200)
    store.record_submission("main-run", 1, main_candidates[5], "already_solved", 200)
    unretained = "INCYPHER{unretained_wrong}"
    store.record_submission("main-run", 1, unretained, "incorrect", 200)
    store.record_submission("main-run", 2, other_challenge, "incorrect", 200)
    store.record_submission("other-run", 1, other_run, "incorrect", 200)

    events_before = store._connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    expected = tuple(
        candidate.encode()
        for candidate in sorted(
            main_candidates[:2], key=lambda value: hashlib.sha256(value.encode()).digest()
        )
    )
    assert store.reserve_submission("main-run", 1, main_candidates[2])
    assert store.private_incorrect_candidate_bytes("main-run", 1) == expected
    store.finalize_submission("main-run", 1, main_candidates[2], "unread", 200)
    assert store.private_incorrect_candidate_bytes("main-run", 1) == expected
    assert store._connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == events_before
    event_payloads = "".join(
        str(row[0])
        for row in store._connection.execute(
            "SELECT data_json FROM events UNION ALL SELECT data_json FROM control_events"
        ).fetchall()
    )
    assert all(candidate not in event_payloads for candidate in (*main_candidates, unretained))
    store.close()


def test_private_incorrect_candidates_exclude_stale_material(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    run_id = "material-run"
    old_candidate = "INCYPHER{old_material_wrong}"
    current_candidate = "INCYPHER{current_material_wrong}"
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    assignment = ("specialist", route.model, route.effort)
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.initialize_control_catalogue(
        run_id, [(0, 1, True)], 1, route, (assignment,), {1: "a" * 64}
    )
    _retain_private_wave_candidates(store, run_id, 1, 0, (old_candidate,), attempt_prefix="old")
    store.record_submission(run_id, 1, old_candidate, "incorrect", 200)
    store.finish_control_wave(run_id, 1, 0, "unsolved")
    kind, episode, _ = store.admit_control_catalogue_revision(
        run_id=run_id,
        challenge_id=1,
        name="A",
        category="crypto",
        challenge_type="standard",
        value=100,
        executable=True,
        context_sha256="b" * 64,
        new_catalogue_rank=1,
        lanes=2,
        route=route,
        assignments=(assignment, assignment),
    )
    assert (kind, episode) == ("refreshed", 1)
    _retain_private_wave_candidates(
        store,
        run_id,
        1,
        1,
        (old_candidate, current_candidate),
        attempt_prefix="current",
    )
    store.record_submission(run_id, 1, current_candidate, "incorrect", 200)

    assert store.private_incorrect_candidate_bytes(run_id, 1) == (current_candidate.encode(),)
    store.close()


def test_private_incorrect_candidates_have_deterministic_count_and_byte_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    run_id = "bounded-run"
    candidates = tuple(f"INCYPHER{{bounded_{index}}}" for index in range(3))
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    assignments = tuple(("specialist", route.model, route.effort) for _ in candidates)
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.initialize_control_catalogue(
        run_id, [(0, 1, True)], len(candidates), route, assignments, {1: "a" * 64}
    )
    _retain_private_wave_candidates(store, run_id, 1, 0, candidates, attempt_prefix="bounded")
    for candidate in candidates:
        store.record_submission(run_id, 1, candidate, "incorrect", 200)
    ordered = tuple(
        candidate.encode()
        for candidate in sorted(
            candidates, key=lambda value: hashlib.sha256(value.encode()).digest()
        )
    )

    monkeypatch.setattr(state_module, "MAX_PRIVATE_INCORRECT_CANDIDATES", 2)
    monkeypatch.setattr(state_module, "MAX_PRIVATE_INCORRECT_CANDIDATE_BYTES", 64 * 1024)
    assert store.private_incorrect_candidate_bytes(run_id, 1) == ordered[:2]
    monkeypatch.setattr(state_module, "MAX_PRIVATE_INCORRECT_CANDIDATES", 64)
    monkeypatch.setattr(
        state_module,
        "MAX_PRIVATE_INCORRECT_CANDIDATE_BYTES",
        len(ordered[0]) + len(ordered[1]) - 1,
    )
    assert store.private_incorrect_candidate_bytes(run_id, 1) == ordered[:1]
    store.close()


def test_event_sequence_is_monotonic(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    first = store.event("run-1", "boot", {"ok": True})
    second = store.event("run-1", "queue", {"count": 2})
    assert second == first + 1
    store.close()


def test_event_payload_has_encoded_byte_ceiling(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    with pytest.raises(ValueError, match="durable audit limit"):
        store.event("run-1", "oversized", {"value": "😀" * MAX_EVENT_BYTES})
    store.close()


def test_submissions_store_only_fingerprints_and_enforce_wrong_ceiling_input(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    candidate = "INCYPHER{private_candidate}"
    store.record_submission("run-1", 1, candidate, "incorrect", 200)
    row = store._connection.execute("SELECT * FROM submissions").fetchone()
    assert candidate not in repr(dict(row))
    assert len(row["candidate_sha256"]) == 64
    assert store.incorrect_submission_count() == 1
    assert store.submission_risk_count() == 1
    store.close()


def test_pending_submission_intent_is_durable_and_not_retryable(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    candidate = "INCYPHER{ambiguous_effect}"
    assert store.reserve_submission("run-1", 1, candidate)
    assert not store.reserve_submission("run-1", 1, candidate)
    row = store._connection.execute("SELECT * FROM submission_intents").fetchone()
    assert row["status"] == "pending"
    assert candidate not in repr(dict(row))
    assert store.submission_risk_count() == 1
    store.close()


def test_explicit_reconciliation_can_settle_or_release_ambiguous_effect(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    candidate = "INCYPHER{operator_checked}"
    fingerprint = store._candidate_fingerprint(candidate)
    assert store.reserve_submission("run-1", 1, candidate)
    assert store.pending_submission_intents()[0]["candidate_sha256"] == fingerprint
    store.reconcile_submission_intent(1, fingerprint, "not_delivered")
    assert store.pending_submission_intents() == []
    assert store.reserve_submission("run-1", 1, candidate)
    store.reconcile_submission_intent(1, fingerprint, "correct")
    assert store.submission_risk_count() == 0
    assert not store.reserve_submission("run-1", 1, candidate)
    store.close()


def test_unread_submission_blocks_recovery_until_explicit_reconciliation(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    config = {"run_seconds": 19_800}
    store.start_run("run-1", config)
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue("run-1", [(0, 1, True)])
    route = baseline_route(model="model", effort="xhigh", attempt_seconds=800)
    store.admit_control_wave(
        "run-1",
        1,
        0,
        0,
        2,
        route,
        (("lead", "model", "xhigh"), ("specialist", "model", "xhigh")),
    )
    candidate = "INCYPHER{unread_board_effect}"
    fingerprint = store._candidate_fingerprint(candidate)
    assert store.reserve_submission("run-1", 1, candidate)
    store.finalize_submission("run-1", 1, candidate, "unread", 200)
    assert len(store.queued_control_waves("run-1")) == 1
    assert store.queued_control_waves("run-1", exclude_pending_submissions=True) == ()
    store.start_control_wave("run-1", 1, 0)
    store.acquire_supervisor()

    session = store.start_or_resume_run("unused", config)
    unresolved = store.pending_submission_intents()
    assert session.resumed
    assert unresolved[0]["candidate_sha256"] == fingerprint
    assert unresolved[0]["status"] == "unread"
    assert store.resume_control_waves("run-1", 10_000) == 0
    assert store.queued_control_waves("run-1") == ()
    assert not store.reserve_submission("run-1", 1, "INCYPHER{different_candidate}")
    with pytest.raises(ValueError, match="absent, settled, or owned"):
        store.finalize_submission("run-1", 1, candidate, "correct", 200)

    store.reconcile_submission_intent(1, fingerprint, "not_delivered")
    assert store.pending_submission_intents() == []
    assert store.resume_control_waves("run-1", 10_000) == 1
    assert store.queued_control_waves("run-1")[0].route.role == "recovery"
    store.close()


def test_owned_instance_lifecycle_is_restartable(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "web", "dynamic_iac", 100)
    store.mark_instance("run-1", 1, "owned", receipt_sha256="a" * 64)
    assert store.owned_instances()[0]["challenge_id"] == 1
    store.mark_instance("run-1", 1, "removed")
    assert store.owned_instances() == []
    store.close()


def test_state_is_bound_to_one_qualified_board_identity(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.bind_board_identity(10, 20)
    store.bind_board_identity(10, 20)
    with pytest.raises(RuntimeError, match="different qualified Board identity"):
        store.bind_board_identity(11, 20)
    store.close()


def test_create_intent_is_durable_before_instance_receipt_exists(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "web", "dynamic_iac", 100)
    store.mark_instance("run-1", 1, "creating")
    row = store.owned_instances()[0]
    assert row["status"] == "creating"
    assert row["receipt_sha256"] is None
    store.close()


def test_new_create_intent_clears_previous_generation_receipt(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.start_run("run-2", {})
    store.upsert_challenge(1, "A", "web", "dynamic_iac", 100)
    store.mark_instance("run-1", 1, "owned", receipt_sha256="a" * 64)
    store.mark_instance("run-2", 1, "creating")
    row = store.owned_instances()[0]
    assert row["run_id"] == "run-2"
    assert row["receipt_sha256"] is None
    store.close()


def test_legacy_external_effects_cannot_be_adopted_by_first_new_identity(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "web", "dynamic_iac", 100)
    store.mark_instance("run-1", 1, "creating")
    with pytest.raises(RuntimeError, match="legacy state has unbound external effects"):
        store.bind_board_identity(10, 20)
    store.close()


def test_attempt_episodes_allow_same_lane_and_persist_bounded_carry(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.start_attempt("attempt-0", "run-1", 1, 0, 0, "model", "high")
    store.finish_attempt(
        "attempt-0",
        "unsolved",
        summary="first try",
        evidence=("offset 12",),
        next_steps=["inspect bytes"],
        tool_count=3,
        failure_class="timeout",
    )
    store.start_attempt("attempt-1", "run-1", 1, 1, 0, "model", "high")
    store.finish_attempt(
        "attempt-1",
        "candidate",
        candidate="INCYPHER{private}",
        evidence=["verified output"],
    )

    rows = store.prior_attempts_for_lane("run-1", 1, 0)
    assert [row["episode"] for row in rows] == [0]
    assert rows[0]["evidence"] == ["offset 12"]
    assert rows[0]["next_steps"] == ["inspect bytes"]
    assert rows[0]["tool_count"] == 3
    assert rows[0]["failure_class"] == "timeout"
    assert all(
        set(row)
        == {
            "episode",
            "status",
            "summary",
            "evidence",
            "next_steps",
            "tool_count",
            "failure_class",
        }
        for row in rows
    )
    assert all("candidate" not in row for row in rows)
    store.close()


def test_prior_attempt_carry_is_terminal_prior_and_newest_bounded(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    for episode in range(6):
        attempt_id = f"attempt-{episode}"
        store.start_attempt(attempt_id, "run-1", 1, episode, 0, "model", "high")
        store.finish_attempt(attempt_id, "unsolved", summary=attempt_id)
    store.start_attempt("candidate", "run-1", 1, 6, 0, "model", "high")
    store.finish_attempt("candidate", "candidate", candidate="INCYPHER{private}")
    store.start_attempt("running", "run-1", 1, 7, 0, "model", "high")

    rows = store.prior_attempts_for_lane("run-1", 1, 0, before_episode=8, limit=4)
    assert [row["episode"] for row in rows] == [2, 3, 4, 5]
    assert all(row["status"] == "unsolved" for row in rows)
    store.close()


def test_prior_attempts_are_same_run_challenge_and_lane_local(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.start_run("run-2", {})
    for challenge_id in (1, 2):
        store.upsert_challenge(challenge_id, f"A{challenge_id}", "crypto", "standard", 100)
    for attempt_id, run_id, challenge_id, episode, lane in (
        ("wanted", "run-1", 1, 0, 2),
        ("other-lane", "run-1", 1, 0, 3),
        ("other-challenge", "run-1", 2, 0, 2),
        ("other-run", "run-2", 1, 0, 2),
    ):
        store.start_attempt(attempt_id, run_id, challenge_id, episode, lane, "model", "high")
        store.finish_attempt(attempt_id, "unsolved", summary=attempt_id)
    assert store.prior_attempts_for_lane("run-1", 1, 2) == [
        {
            "episode": 0,
            "status": "unsolved",
            "summary": "wanted",
            "evidence": [],
            "next_steps": [],
            "tool_count": 0,
            "failure_class": None,
        }
    ]
    store.close()


def test_typed_memory_sources_remove_cross_lane_model_prose(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    run_id = "memory-run"
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue(run_id, [(0, 1, True)])
    store.admit_control_wave(run_id, 1, 0, 0, 2, route)
    store.start_control_wave(run_id, 1, 0)
    for lane in (0, 1):
        attempt_id = f"attempt-{lane}"
        store.start_attempt(attempt_id, run_id, 1, 0, lane, route.model, route.effort)
        store.finish_attempt(
            attempt_id,
            "unsolved",
            summary=f"private-prose-{lane}",
            evidence=(f"evidence-{lane}",),
            next_steps=(f"next-{lane}",),
        )

    rows = store.same_run_memory_sources(
        run_id,
        1,
        target_lane=0,
        before_episode=1,
    )
    assert rows[0]["summary"] == "private-prose-0"
    assert rows[0]["evidence"] == ["evidence-0"]
    assert rows[1]["summary"] is None
    assert rows[1]["evidence"] == []
    assert rows[1]["next_steps"] == []
    assert rows[1]["tactic"] == "baseline"

    tampered = replace(route, tactic="tampered_tactic")
    store._connection.execute(
        "UPDATE control_routes SET route_json=? WHERE run_id=? AND challenge_id=?",
        (json.dumps(tampered.as_dict(), sort_keys=True, separators=(",", ":")), run_id, 1),
    )
    with pytest.raises(ValueError, match="route fingerprint changed"):
        store.same_run_memory_sources(run_id, 1, target_lane=0, before_episode=1)
    store.close()


def test_private_memory_verification_is_visible_only_after_its_episode(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    run_id = "private-memory-run"
    candidate = "INCYPHER{typed_memory_private}"
    producer = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    verifier = replace(
        producer,
        role="verifier",
        tactic="independent_source_reobservation",
        context_profile="fresh_source_only_no_candidate_carry",
        verification_recipe="fresh_source_reobservation_v1",
    )
    store.start_run(run_id, {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue(run_id, [(0, 1, True)])
    store.admit_control_wave(run_id, 1, 0, 0, 1, producer)
    store.start_control_wave(run_id, 1, 0)
    store.start_attempt("producer", run_id, 1, 0, 0, producer.model, producer.effort)
    evidence = RunEvidence.open(store, run_id)
    _attest_candidate(evidence, "producer", candidate)
    store.finish_attempt(
        "producer", "candidate", candidate=candidate, retain_private_candidate=True
    )
    store.admit_control_wave(run_id, 1, 1, 1, 1, verifier)
    store.start_control_wave(run_id, 1, 1)
    store.start_attempt("verifier", run_id, 1, 1, 0, verifier.model, verifier.effort)
    _attest_candidate(evidence, "verifier", candidate)
    store.finish_attempt(
        "verifier", "candidate", candidate=candidate, retain_private_candidate=True
    )

    before_verifier = store.private_candidate_context_sources(run_id, 1, before_episode=1)
    after_verifier = store.private_candidate_context_sources(run_id, 1, before_episode=2)
    assert len(before_verifier) == len(after_verifier) == 1
    assert before_verifier[0]["verifier_attempt_id"] is None
    assert after_verifier[0]["verifier_attempt_id"] == "verifier"
    assert after_verifier[0]["verifier_route_role"] == "verifier"
    assert after_verifier[0]["verifier_route_verification_recipe"] == (
        "fresh_source_reobservation_v1"
    )

    tampered_verifier = replace(verifier, tactic="tampered_verifier_tactic")
    store._connection.execute(
        "UPDATE control_routes SET route_json=? WHERE run_id=? AND challenge_id=? "
        "AND route_fingerprint=?",
        (
            json.dumps(tampered_verifier.as_dict(), sort_keys=True, separators=(",", ":")),
            run_id,
            1,
            verifier.fingerprint,
        ),
    )
    with pytest.raises(ValueError, match="verifier route fingerprint changed"):
        store.private_candidate_context_sources(run_id, 1, before_episode=2)
    store.close()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("evidence", ["x"] * 21),
        ("next_steps", ["x"] * 21),
        ("evidence", ["x" * 1001]),
        ("next_steps", {"x"}),
        ("tool_count", -1),
        ("tool_count", 2**63),
        ("tool_count", True),
        ("failure_class", "provider leaked details"),
    ),
)
def test_attempt_finish_rejects_unbounded_or_open_fields(
    tmp_path: Path, field: str, value: object
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.start_attempt("attempt-1", "run-1", 1, 0, 0, "model", "high")
    with pytest.raises(ValueError):
        store.finish_attempt("attempt-1", "failed", **{field: value})
    assert store.active_attempts()[0]["id"] == "attempt-1"
    store.close()


def test_pre_episode_attempts_migrate_without_loss_and_reopen_idempotently(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE runs (
            id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            config_json TEXT NOT NULL
        );
        CREATE TABLE challenges (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            challenge_type TEXT NOT NULL,
            value INTEGER NOT NULL,
            status TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE attempts (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(id),
            challenge_id INTEGER NOT NULL REFERENCES challenges(id),
            lane INTEGER NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            model TEXT NOT NULL,
            effort TEXT NOT NULL,
            summary TEXT NOT NULL DEFAULT '',
            candidate TEXT,
            confidence REAL,
            UNIQUE(run_id, challenge_id, lane)
        );
        INSERT INTO runs VALUES ('run-1', '2026-01-01', NULL, 'running', '{}');
        INSERT INTO challenges VALUES (1, 'A', 'crypto', 'standard', 100, 'running', '2026-01-01');
        INSERT INTO attempts VALUES (
            'legacy-finished', 'run-1', 1, 0, '2026-01-01', '2026-01-02',
            'candidate', 'old-model', 'high', 'legacy summary', 'INCYPHER{legacy}', 0.75
        );
        INSERT INTO attempts VALUES (
            'legacy-running', 'run-1', 1, 1, '2026-01-03', NULL,
            'running', 'old-model', 'high', '', NULL, NULL
        );
        """
    )
    connection.close()

    store = StateStore(path)
    rows = [
        dict(row)
        for row in store._connection.execute(
            "SELECT id, episode, lane, status, summary, candidate, evidence_json, "
            "next_steps_json, tool_count, failure_class FROM attempts ORDER BY id"
        )
    ]
    assert rows == [
        {
            "id": "legacy-finished",
            "episode": 0,
            "lane": 0,
            "status": "candidate",
            "summary": "legacy summary",
            "candidate": "INCYPHER{legacy}",
            "evidence_json": "[]",
            "next_steps_json": "[]",
            "tool_count": 0,
            "failure_class": None,
        },
        {
            "id": "legacy-running",
            "episode": 0,
            "lane": 1,
            "status": "running",
            "summary": "",
            "candidate": None,
            "evidence_json": "[]",
            "next_steps_json": "[]",
            "tool_count": 0,
            "failure_class": None,
        },
    ]
    store.close()

    reopened = StateStore(path)
    assert reopened._connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 2
    reopened.start_attempt("new-episode", "run-1", 1, 1, 0, "new-model", "high")
    assert reopened._connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 3
    reopened.close()
