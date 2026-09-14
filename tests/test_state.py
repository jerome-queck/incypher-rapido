import stat
from pathlib import Path

import pytest

from rapido.state import MAX_EVENT_BYTES, StateStore


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
