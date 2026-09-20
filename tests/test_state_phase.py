"""Synthetic phase isolation; fixture candidates never reach a network transport."""

import asyncio
from dataclasses import replace
from pathlib import Path

import pytest

from rapido.config import RuntimeConfig
from rapido.orchestrator import Orchestrator
from rapido.state import StateStore


def scope(profile="practice"):
    return {"board_url": "https://hackathon.in-cypher.com", "profile": profile}


@pytest.mark.parametrize("terminal", ["completed", "failed", "interrupted"])
def test_restart_cannot_import_prior_phase_effects(tmp_path: Path, terminal: str) -> None:
    path = tmp_path / "state.sqlite3"
    store = StateStore(path)
    store.start_run("synthetic-practice", scope())
    store.upsert_challenge(1, "Synthetic reused ID", "misc", "standard", 0)
    store.set_challenge_status(1, "solved")
    store.reserve_submission("synthetic-practice", 1, "INCYPHER{synthetic-pending}")
    store.finish_run("synthetic-practice", terminal)
    store.close()

    reopened = StateStore(path)
    reopened.acquire_supervisor()
    try:
        with pytest.raises(RuntimeError, match="Board or phase"):
            reopened.start_or_resume_run("competition", scope("competition"))
        assert reopened._connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1
        assert len(reopened.pending_submission_intents()) == 1
        # Rejection does not reset, reinterpret or discard the original phase's evidence.
        assert (
            reopened._connection.execute("SELECT status FROM challenges").fetchone()[0] == "solved"
        )
    finally:
        reopened.close()


@pytest.mark.parametrize(
    "prior",
    [
        {},
        {"profile": "practice"},
        {"board_url": "https://synthetic.invalid", "profile": "practice"},
    ],
)
def test_unbound_or_different_board_history_requires_new_state(tmp_path: Path, prior) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("old", prior)
    store.finish_run("old", "completed")
    store.acquire_supervisor()
    try:
        with pytest.raises(RuntimeError, match="scope|Board or phase"):
            store.start_or_resume_run("new", scope())
        assert store._connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1
    finally:
        store.close()


def test_all_historical_run_scopes_are_checked(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    # Simulate a legacy database already containing two phases.
    for run_id, profile in [("practice", "practice"), ("competition", "competition")]:
        store.start_run(run_id, scope(profile))
        store.finish_run(run_id, "completed")
    store.acquire_supervisor()
    try:
        with pytest.raises(RuntimeError, match="Board or phase"):
            store.start_or_resume_run("new", scope("competition"))
    finally:
        store.close()


def test_same_phase_run_and_crash_resume_keep_original_identity(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    store = StateStore(path)
    store.acquire_supervisor()
    first = store.start_or_resume_run("first", scope())
    assert not first.resumed
    store.finish_run("first", "completed")
    second = store.start_or_resume_run("second", scope())
    store.close()
    reopened = StateStore(path)
    reopened.acquire_supervisor()
    try:
        resumed = reopened.start_or_resume_run("ignored", scope())
        assert resumed.resumed
        assert resumed.run_id == "second"
        assert resumed.started_at == second.started_at
    finally:
        reopened.close()


def test_phase_refusal_precedes_board_reads_or_cleanup(tmp_path: Path) -> None:
    config = replace(
        RuntimeConfig.from_env({}),
        state_path=tmp_path / "state.sqlite3",
        work_root=tmp_path / "work",
        codex_home=tmp_path / "auth",
        profile="competition",
    )
    config.codex_home.mkdir(mode=0o700)
    store = StateStore(config.state_path)
    store.start_run("practice", {**config.public_record(), "profile": "practice"})
    store.finish_run("practice", "failed")

    class NoExternalCalls:
        def __getattr__(self, name):
            raise AssertionError(f"phase refusal must precede external operation: {name}")

    try:
        runner = Orchestrator(
            config, board=NoExternalCalls(), runtime=NoExternalCalls(), state=store
        )
        with pytest.raises(RuntimeError, match="Board or phase"):
            asyncio.run(runner.run())
        assert not store._lease_files
    finally:
        store.close()
