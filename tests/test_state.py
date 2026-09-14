from pathlib import Path

import pytest

from rapido.state import StateStore


def test_records_run_attempt_and_restart_recovery(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
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
