"""Black-box acceptance tests for run-scoped durable evidence.

These fixtures deliberately use only synthetic facts.  The tests exercise the
public ``RunEvidence`` seam; storage layout and implementation details are not
part of the contract.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from collections.abc import Mapping
from pathlib import Path

import pytest

from rapido.evidence import EvidenceBatch, EvidenceLimits, HostObservation, RunEvidence
from rapido.state import StateStore


def _observation(
    summary: str,
    *,
    payload: bytes = b"synthetic fixture bytes",
    success: bool | None = True,
    source_bound: bool = True,
    candidate_sha256s: tuple[str, ...] = (),
    supplied_candidate_sha256s: tuple[str, ...] = (),
    facts: Mapping[str, object] | None = None,
) -> HostObservation:
    digest = hashlib.sha256(payload).hexdigest()
    values: dict[str, object] = {
        # These are intentionally metadata-shaped facts.  ``format`` carries
        # a deterministic fixture marker without pretending to be model prose.
        "format": summary,
        "source_sha256": digest,
        "size": len(payload),
    }
    if facts:
        values.update(facts)
    return HostObservation(
        tool="inspect_file",
        success=success,
        source_bound=source_bound,
        facts=values,
        candidate_sha256s=candidate_sha256s,
        supplied_candidate_sha256s=supplied_candidate_sha256s,
    )


def _batch(
    *observations: HostObservation,
    complete: bool = True,
    gap: str | None = None,
) -> EvidenceBatch:
    return EvidenceBatch(observations=observations, complete=complete, gap=gap)


def _state(
    path: Path,
    *,
    runs: tuple[str, ...],
    challenges: tuple[int, ...],
    attempts: tuple[tuple[str, str, int, int, int], ...],
) -> StateStore:
    state = StateStore(path)
    for run_id in runs:
        state.start_run(run_id, {"fixture": True})
    for challenge_id in challenges:
        state.upsert_challenge(challenge_id, f"fixture-{challenge_id}", "test", "standard", 1)
    for attempt_id, run_id, challenge_id, episode, lane in attempts:
        state.start_attempt(
            attempt_id,
            run_id,
            challenge_id,
            episode=episode,
            lane=lane,
            model="gpt-5.6-luna",
            effort="xhigh",
        )
    return state


def _public(bundle: object) -> object:
    as_dict = getattr(bundle, "as_dict", None)
    if not callable(as_dict):
        raise TypeError("EvidenceBundle must expose as_dict()")
    return as_dict()


def _encoded(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _values_for_key(value: object, key: str) -> list[object]:
    found: list[object] = []
    if isinstance(value, Mapping):
        for name, child in value.items():
            if name == key:
                found.append(child)
            found.extend(_values_for_key(child, key))
    elif isinstance(value, (list, tuple)):
        for child in value:
            found.extend(_values_for_key(child, key))
    return found


def _storage_bytes(path: Path) -> bytes:
    chunks: list[bytes] = []
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        if candidate.exists():
            chunks.append(candidate.read_bytes())
    return b"".join(chunks)


def test_two_episodes_survive_episode_workspace_deletion_and_reopen(tmp_path: Path) -> None:
    state_path = tmp_path / "state.sqlite3"
    episode_root = tmp_path / "episodes"
    episode_zero = episode_root / "run-a" / "challenge-7" / "episode-0"
    episode_one = episode_root / "run-a" / "challenge-7" / "episode-1"
    episode_zero.mkdir(parents=True)
    episode_one.mkdir(parents=True)
    (episode_zero / "artifact.bin").write_bytes(b"episode-zero")
    (episode_one / "artifact.bin").write_bytes(b"episode-one")

    attempts = (
        ("attempt-a0", "run-a", 7, 0, 0),
        ("attempt-a1", "run-a", 7, 1, 0),
    )
    state = _state(state_path, runs=("run-a",), challenges=(7,), attempts=attempts)
    evidence = RunEvidence.open(state, "run-a")
    evidence.commit("attempt-a0", _batch(_observation("episode-zero", payload=b"episode-zero")))
    evidence.commit("attempt-a1", _batch(_observation("episode-one", payload=b"episode-one")))
    state.finish_attempt("attempt-a0", "unsolved", summary="synthetic terminal")
    state.finish_attempt("attempt-a1", "unsolved", summary="synthetic terminal")
    state.close()
    shutil.rmtree(episode_root)

    reopened_state = StateStore(state_path)
    reopened = RunEvidence.open(reopened_state, "run-a")
    carried = _public(reopened.carry(7, 0, before_episode=2))
    rendered = _encoded(carried)
    assert "episode-zero" in rendered
    assert "episode-one" in rendered
    assert hashlib.sha256(b"episode-zero").hexdigest() in rendered
    assert hashlib.sha256(b"episode-one").hexdigest() in rendered
    assert str(episode_root) not in rendered
    reopened_state.close()


def test_carry_isolated_by_run_challenge_lane_and_episode(tmp_path: Path) -> None:
    state_path = tmp_path / "state.sqlite3"
    attempts = (
        ("expected", "run-a", 7, 0, 0),
        ("later", "run-a", 7, 1, 0),
        ("other-lane", "run-a", 7, 0, 1),
        ("other-challenge", "run-a", 8, 0, 0),
        ("other-run", "run-b", 7, 0, 0),
    )
    state = _state(
        state_path,
        runs=("run-a", "run-b"),
        challenges=(7, 8),
        attempts=attempts,
    )
    for attempt_id, run_id, challenge_id, episode, lane in attempts:
        RunEvidence.open(state, run_id).commit(
            attempt_id,
            _batch(_observation(f"marker-{attempt_id}", payload=attempt_id.encode())),
        )
        state.finish_attempt(attempt_id, "unsolved", summary="synthetic terminal")

    current = _encoded(_public(RunEvidence.open(state, "run-a").carry(7, 0, before_episode=1)))
    assert "marker-expected" in current
    assert "marker-later" not in current
    assert "marker-other-lane" not in current
    assert "marker-other-challenge" not in current
    assert "marker-other-run" not in current

    all_prior = _encoded(_public(RunEvidence.open(state, "run-a").carry(7, 0, before_episode=2)))
    assert "marker-expected" in all_prior
    assert "marker-later" in all_prior
    assert "marker-other-lane" not in all_prior
    state.close()


def test_new_run_receives_no_previous_evidence(tmp_path: Path) -> None:
    state_path = tmp_path / "state.sqlite3"
    state = _state(
        state_path,
        runs=("run-a", "run-b"),
        challenges=(7,),
        attempts=(("attempt-a", "run-a", 7, 0, 0),),
    )
    RunEvidence.open(state, "run-a").commit(
        "attempt-a", _batch(_observation("private-run-a", payload=b"run-a-source"))
    )
    state.finish_attempt("attempt-a", "unsolved", summary="synthetic terminal")
    with pytest.raises(ValueError, match="belongs to another run"):
        RunEvidence.open(state, "run-b").commit(
            "attempt-a", _batch(_observation("cross-run-attempt"))
        )
    fresh = _public(RunEvidence.open(state, "run-b").carry(7, 0, before_episode=1))
    rendered = _encoded(fresh)
    assert "private-run-a" not in rendered
    assert hashlib.sha256(b"run-a-source").hexdigest() not in rendered
    state.close()


def test_empty_and_incomplete_terminal_manifests_remain_explicit(tmp_path: Path) -> None:
    state_path = tmp_path / "state.sqlite3"
    state = _state(
        state_path,
        runs=("run-a",),
        challenges=(7,),
        attempts=(
            ("empty-terminal", "run-a", 7, 0, 0),
            ("incomplete-terminal", "run-a", 7, 1, 0),
        ),
    )
    evidence = RunEvidence.open(state, "run-a")
    evidence.commit("empty-terminal", _batch())
    evidence.commit(
        "incomplete-terminal",
        _batch(complete=False, gap="provenance_incomplete"),
    )
    state.finish_attempt("empty-terminal", "unsolved", summary="synthetic terminal")
    state.finish_attempt("incomplete-terminal", "failed", summary="synthetic terminal")
    carried = _public(evidence.carry(7, 0, before_episode=2))
    assert _values_for_key(carried, "complete").count(True) >= 1
    assert _values_for_key(carried, "complete").count(False) >= 1
    assert "provenance_incomplete" in _encoded(carried)
    state.close()


def test_carry_never_establishes_current_turn_candidate_provenance(tmp_path: Path) -> None:
    state_path = tmp_path / "state.sqlite3"
    state = _state(
        state_path,
        runs=("run-a",),
        challenges=(7,),
        attempts=(("attempt-a", "run-a", 7, 0, 0),),
    )
    private_candidate_hash = "a" * 64
    supplied_candidate_hash = "b" * 64
    evidence = RunEvidence.open(state, "run-a")
    evidence.commit(
        "attempt-a",
        _batch(
            _observation(
                "prior observation",
                candidate_sha256s=(private_candidate_hash,),
                supplied_candidate_sha256s=(supplied_candidate_hash,),
            )
        ),
    )
    state.finish_attempt("attempt-a", "candidate", summary="synthetic terminal")
    carried = _public(evidence.carry(7, 0, before_episode=1))
    rendered = _encoded(carried)
    assert private_candidate_hash not in rendered
    assert supplied_candidate_hash not in rendered
    assert all(value is not True for value in _values_for_key(carried, "current_turn_provenance"))
    assert all(value is not True for value in _values_for_key(carried, "candidate_provenance"))
    state.close()


def test_untrusted_candidate_token_authority_path_and_transcript_sentinels_never_escape(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.sqlite3"
    state = _state(
        state_path,
        runs=("run-a",),
        challenges=(7,),
        attempts=(("attempt-a", "run-a", 7, 0, 0),),
    )
    evidence = RunEvidence.open(state, "run-a")
    sentinels = {
        "candidate": "INCYPHER{CANDIDATE_SENTINEL}",
        "token": "TOKEN_SENTINEL",
        "authority": "AUTHORITY_SENTINEL",
        "path": "/PATH_SENTINEL",
        "transcript": "TRANSCRIPT_SENTINEL",
    }
    committed = False
    try:
        evidence.commit(
            "attempt-a",
            _batch(_observation("safe summary", facts=sentinels)),
        )
        committed = True
    except (TypeError, ValueError):
        # Rejecting unsafe dispatcher material is an accepted fail-closed path.
        pass
    if committed:
        state.finish_attempt("attempt-a", "unsolved", summary="synthetic terminal")
    carried = _encoded(_public(evidence.carry(7, 0, before_episode=1)))
    stored = _storage_bytes(state_path).decode("utf-8", errors="ignore")
    for sentinel in sentinels.values():
        assert sentinel not in stored
        assert sentinel not in carried
    state.close()


def test_carry_is_deterministic_and_respects_configured_byte_bound(tmp_path: Path) -> None:
    state_path = tmp_path / "state.sqlite3"
    attempts = tuple((f"attempt-{index:02d}", "run-a", 7, index, 0) for index in range(12))
    state = _state(state_path, runs=("run-a",), challenges=(7,), attempts=attempts)
    evidence = RunEvidence.open(
        state,
        "run-a",
        limits=EvidenceLimits(max_carry_bytes=512),
    )
    for attempt_id, *_ in attempts:
        evidence.commit(
            attempt_id,
            _batch(_observation(f"bounded-{attempt_id}-" + "x" * 72, payload=attempt_id.encode())),
        )
        state.finish_attempt(attempt_id, "unsolved", summary="synthetic terminal")

    first = _public(evidence.carry(7, 0, before_episode=12))
    second = _public(evidence.carry(7, 0, before_episode=12))
    first_bytes = _encoded(first).encode("utf-8")
    assert first == second
    assert len(first_bytes) <= 512
    state.close()


def test_malformed_commit_is_atomic_and_keeps_prior_manifest(tmp_path: Path) -> None:
    state_path = tmp_path / "state.sqlite3"
    state = _state(
        state_path,
        runs=("run-a",),
        challenges=(7,),
        attempts=(
            ("good", "run-a", 7, 0, 0),
            ("bad", "run-a", 7, 1, 0),
        ),
    )
    evidence = RunEvidence.open(state, "run-a")
    evidence.commit("good", _batch(_observation("good-manifest")))
    state.finish_attempt("good", "unsolved", summary="synthetic terminal")
    with pytest.raises((TypeError, ValueError)):
        evidence.commit("bad", EvidenceBatch(observations=("not-an-observation",)))  # type: ignore[arg-type]
    rendered = _encoded(_public(evidence.carry(7, 0, before_episode=2)))
    assert "good-manifest" in rendered
    assert "not-an-observation" not in rendered
    state.close()


def test_corruption_returns_no_partial_bundle(tmp_path: Path) -> None:
    state_path = tmp_path / "state.sqlite3"
    state = _state(
        state_path,
        runs=("run-a",),
        challenges=(7,),
        attempts=(("attempt-a", "run-a", 7, 0, 0),),
    )
    RunEvidence.open(state, "run-a").commit(
        "attempt-a", _batch(_observation("tamper-target", payload=b"tamper-source"))
    )
    state.finish_attempt("attempt-a", "unsolved", summary="synthetic terminal")
    state.close()
    original = _storage_bytes(state_path)
    assert b"tamper-target" in original
    for candidate in (state_path, Path(f"{state_path}-wal"), Path(f"{state_path}-shm")):
        if candidate.exists():
            raw = candidate.read_bytes()
            if b"tamper-target" in raw:
                candidate.write_bytes(raw.replace(b"tamper-target", b"tamper-forged", 1))
                break
    else:
        raise AssertionError("test fixture was not persisted in a readable SQLite page")

    with pytest.raises((ValueError, RuntimeError, sqlite3.DatabaseError)):
        reopened_state = StateStore(state_path)
        try:
            reopened = RunEvidence.open(reopened_state, "run-a")
            carried = _public(reopened.carry(7, 0, before_episode=1))
            assert "tamper-forged" not in _encoded(carried)
        finally:
            reopened_state.close()


def test_reopen_preserves_unrelated_legacy_state_and_evidence_schema(tmp_path: Path) -> None:
    state_path = tmp_path / "state.sqlite3"
    with sqlite3.connect(state_path) as legacy:
        legacy.execute("CREATE TABLE legacy_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        legacy.execute("INSERT INTO legacy_state(key, value) VALUES ('fixture', 'preserve-me')")
        legacy.commit()

    state = _state(
        state_path,
        runs=("run-a",),
        challenges=(7,),
        attempts=(("attempt-a", "run-a", 7, 0, 0),),
    )
    RunEvidence.open(state, "run-a").commit("attempt-a", _batch(_observation("legacy-compatible")))
    state.finish_attempt("attempt-a", "unsolved", summary="synthetic terminal")
    state.close()

    reopened_state = StateStore(state_path)
    row = reopened_state._connection.execute(
        "SELECT value FROM legacy_state WHERE key='fixture'"
    ).fetchone()
    assert row["value"] == "preserve-me"
    reopened = RunEvidence.open(reopened_state, "run-a")
    first = _public(reopened.carry(7, 0, before_episode=1))
    reopened_state.close()

    final_state = StateStore(state_path)
    final = _public(RunEvidence.open(final_state, "run-a").carry(7, 0, before_episode=1))
    assert first == final
    assert "legacy-compatible" in _encoded(final)
    final_state.close()
