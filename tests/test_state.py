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
    assert store.reserve_submission("run-1", 1, candidate)
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
    assert store._connection.execute("SELECT COUNT(*) FROM submissions").fetchone()[0] == 0
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
    assert store.candidate_counts(run_id) == (1, 0)
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
    assert store.candidate_counts(run_id) == (1, 0)
    context = store.private_candidate_context_sources(run_id, 1, before_episode=2)
    assert context[0]["verifier_attempt_id"] is None
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
        ("tool_count", 101),
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
