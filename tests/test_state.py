import sqlite3
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
