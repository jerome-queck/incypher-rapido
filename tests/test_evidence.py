from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from rapido.evidence import (
    EvidenceBatch,
    EvidenceConflictError,
    EvidenceLimits,
    EvidenceTamperError,
    HostObservation,
    RunEvidence,
    project_tool_observation,
    seal_unavailable_attempt_evidence,
)
from rapido.state import StateStore


def _state(path: Path, *run_ids: str) -> StateStore:
    state = StateStore(path)
    for run_id in run_ids:
        state.start_run(run_id, {"fixture": True})
    for challenge_id in (7, 8):
        state.upsert_challenge(challenge_id, f"fixture-{challenge_id}", "test", "standard", 1)
    return state


def _attempt(
    state: StateStore,
    attempt_id: str,
    run_id: str = "run-a",
    challenge_id: int = 7,
    episode: int = 0,
    lane: int = 0,
) -> None:
    state.start_attempt(
        attempt_id,
        run_id,
        challenge_id,
        episode=episode,
        lane=lane,
        model="gpt-daybreak-blue-latest",
        effort="xhigh",
    )


def _observation(marker: str = "fixture", **facts: object) -> HostObservation:
    return HostObservation(
        tool="inspect_file",
        success=True,
        source_bound=True,
        facts={"format": marker, "size": 7, **facts},
    )


def _render(value: object) -> str:
    public = value.as_dict()  # type: ignore[attr-defined]
    return json.dumps(public, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _storage(path: Path) -> bytes:
    return b"".join(
        candidate.read_bytes()
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
        if candidate.exists()
    )


def test_canonical_objects_dedupe_and_survive_workspace_deletion(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite3"
    workspace = tmp_path / "episode-workspace"
    workspace.mkdir()
    source = workspace / "artifact.bin"
    source.write_bytes(b"durable fixture")
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    state = _state(database, "run-a")
    _attempt(state, "a0", episode=0)
    _attempt(state, "a1", episode=1)
    evidence = RunEvidence.open(state, "run-a")
    left = HostObservation(
        "inspect_file",
        True,
        True,
        {"size": 15, "format": "binary", "source_sha256": source_digest},
    )
    right = HostObservation(
        "inspect_file",
        True,
        True,
        {"source_sha256": source_digest, "format": "binary", "size": 15},
    )
    first = evidence.commit("a0", EvidenceBatch((left,)))
    second = evidence.commit("a1", EvidenceBatch((right,)))
    assert first.items[0].digest == second.items[0].digest
    assert first.items[0].digest != first.digest
    count = state._connection.execute("SELECT COUNT(*) FROM evidence_objects").fetchone()[0]
    assert count == 1
    state.finish_attempt("a0", "unsolved")
    state.finish_attempt("a1", "unsolved")
    state.close()
    shutil.rmtree(workspace)

    reopened_state = StateStore(database)
    carried = RunEvidence.open(reopened_state, "run-a").carry(7, 0, 2)
    assert source_digest in _render(carried)
    assert str(workspace) not in _render(carried)
    reopened_state.close()


def test_rows_are_immutable_and_verified_before_carry(tmp_path: Path) -> None:
    state = _state(tmp_path / "state.sqlite3", "run-a")
    _attempt(state, "a0")
    evidence = RunEvidence.open(state, "run-a")
    manifest = evidence.commit("a0", EvidenceBatch((_observation(),)))

    for statement in (
        "UPDATE evidence_objects SET byte_count=byte_count",
        "UPDATE evidence_manifests SET complete=complete",
        "UPDATE evidence_items SET ordinal=ordinal",
    ):
        with pytest.raises(sqlite3.IntegrityError), state.transaction() as connection:
            connection.execute(statement)
    with (
        pytest.raises(sqlite3.IntegrityError, match="identity is immutable"),
        state.transaction() as connection,
    ):
        connection.execute("UPDATE attempts SET challenge_id=8 WHERE id='a0'")

    row = state._connection.execute(
        "SELECT payload_json FROM evidence_objects WHERE run_id=? AND digest=?",
        ("run-a", manifest.items[0].digest),
    ).fetchone()
    payload = bytes(row["payload_json"])
    forged = payload.replace(b'"size":7', b'"size":8')
    assert forged != payload
    with state.transaction() as connection:
        connection.execute("DROP TRIGGER evidence_objects_no_update")
        connection.execute(
            "UPDATE evidence_objects SET payload_json=? WHERE run_id=? AND digest=?",
            (forged, "run-a", manifest.items[0].digest),
        )
    state.finish_attempt("a0", "unsolved")
    with pytest.raises(EvidenceTamperError):
        evidence.carry(7, 0, 1)
    state.close()


def test_database_rejects_mismatched_attempt_identity(tmp_path: Path) -> None:
    state = _state(tmp_path / "state.sqlite3", "run-a")
    _attempt(state, "a0", challenge_id=7)
    RunEvidence.open(state, "run-a")
    with (
        pytest.raises(sqlite3.IntegrityError, match="identity mismatch"),
        state.transaction() as connection,
    ):
        connection.execute(
            """
            INSERT INTO evidence_manifests(
                run_id, attempt_id, digest, challenge_id, episode, lane,
                complete, gap, observation_count, committed_count, omitted_count,
                item_bytes, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "run-a",
                "a0",
                "0" * 64,
                8,
                0,
                0,
                1,
                None,
                0,
                0,
                0,
                0,
                b"{}",
                state._now(),
            ),
        )
    state.close()


def test_newer_evidence_schema_fails_closed(tmp_path: Path) -> None:
    state = _state(tmp_path / "state.sqlite3", "run-a")
    with state.transaction() as connection:
        connection.execute(
            """
                CREATE TABLE evidence_schema (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                schema_version INTEGER NOT NULL
            )
            """
        )
        connection.execute("INSERT INTO evidence_schema VALUES (1, 2)")
    with pytest.raises(EvidenceConflictError, match="version conflict"):
        RunEvidence.open(state, "run-a")
    tables = {
        row["name"]
        for row in state._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'evidence_%'"
        )
    }
    assert tables == {"evidence_schema"}
    state.close()


def test_exact_empty_initial_schema_stub_recovers_atomically(tmp_path: Path) -> None:
    state = _state(tmp_path / "state.sqlite3", "run-a")
    with state.transaction() as connection:
        connection.execute(
            """
            CREATE TABLE evidence_schema (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                schema_version INTEGER NOT NULL
            )
            """
        )

    RunEvidence.open(state, "run-a")
    tables = {
        row["name"]
        for row in state._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'evidence_%'"
        )
    }
    assert tables == {
        "evidence_items",
        "evidence_manifests",
        "evidence_objects",
        "evidence_runs",
        "evidence_schema",
    }
    assert (
        state._connection.execute(
            "SELECT schema_version FROM evidence_schema WHERE singleton=1"
        ).fetchone()[0]
        == 1
    )
    state.close()


def test_empty_schema_stub_with_forged_colliding_trigger_fails_closed(tmp_path: Path) -> None:
    state = _state(tmp_path / "state.sqlite3", "run-a")
    with state.transaction() as connection:
        connection.execute(
            """
            CREATE TABLE evidence_schema (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                schema_version INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TRIGGER evidence_schema_no_update
            BEFORE UPDATE ON evidence_schema BEGIN SELECT 1; END
            """
        )

    with pytest.raises(EvidenceConflictError, match="object definition conflicts"):
        RunEvidence.open(state, "run-a")
    assert state._connection.execute("SELECT COUNT(*) FROM evidence_schema").fetchone()[0] == 0
    tables = {
        row["name"]
        for row in state._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'evidence_%'"
        )
    }
    assert tables == {"evidence_schema"}
    state.close()


def test_initial_schema_install_rolls_back_all_objects_on_failure(tmp_path: Path) -> None:
    state = _state(tmp_path / "state.sqlite3", "run-a")
    with state.transaction() as connection:
        connection.execute("CREATE VIEW evidence_runs AS SELECT id AS run_id FROM runs")

    with pytest.raises(sqlite3.OperationalError):
        RunEvidence.open(state, "run-a")
    objects = {
        (row["type"], row["name"])
        for row in state._connection.execute(
            "SELECT type, name FROM sqlite_master WHERE name LIKE 'evidence_%'"
        )
    }
    assert objects == {("view", "evidence_runs")}
    assert not state._connection.in_transaction
    state.close()


def test_running_commit_then_terminal_carry_and_idempotence(tmp_path: Path) -> None:
    state = _state(tmp_path / "state.sqlite3", "run-a")
    _attempt(state, "crash-window")
    evidence = RunEvidence.open(state, "run-a")
    batch = EvidenceBatch((_observation("crash-safe"),), complete=False, gap="process_interrupted")
    committed = evidence.commit("crash-window", batch)
    assert evidence.carry(7, 0, 1).manifests == ()
    assert "attempt_status" not in committed.as_dict()

    state.finish_attempt("crash-window", "interrupted")
    carried = evidence.carry(7, 0, 1)
    assert carried.manifests[0].digest == committed.digest
    assert evidence.commit("crash-window", batch).digest == committed.digest
    with pytest.raises(EvidenceConflictError):
        evidence.commit("crash-window", EvidenceBatch((_observation("different"),)))

    _attempt(state, "already-terminal", episode=1)
    state.finish_attempt("already-terminal", "unsolved")
    with pytest.raises(ValueError, match="running"):
        evidence.commit("already-terminal", EvidenceBatch())
    state.close()


def test_recovery_seals_missing_attempts_without_inventing_observations(tmp_path: Path) -> None:
    state = _state(tmp_path / "state.sqlite3", "run-a")
    _attempt(state, "interrupted", episode=0)
    _attempt(state, "legacy", episode=1)
    state.finish_attempt("interrupted", "interrupted")
    state.finish_attempt("legacy", "unsolved")

    assert seal_unavailable_attempt_evidence(state) == 2
    assert seal_unavailable_attempt_evidence(state) == 0
    carried = RunEvidence.open(state, "run-a").carry(7, 0, 2)
    assert [manifest.gap for manifest in carried.manifests] == [
        "legacy_unavailable",
        "process_interrupted",
    ]
    assert all(manifest.items == () and not manifest.complete for manifest in carried.manifests)
    state.close()


def test_carry_isolated_and_includes_candidate_attempts_without_candidate_hashes(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path / "state.sqlite3", "run-a", "run-b")
    candidate_digest = "a" * 64
    specifications = (
        ("expected", "run-a", 7, 0, 0, "unsolved"),
        ("later", "run-a", 7, 2, 0, "unsolved"),
        ("other-lane", "run-a", 7, 0, 1, "unsolved"),
        ("other-challenge", "run-a", 8, 0, 0, "unsolved"),
        ("other-run", "run-b", 7, 0, 0, "unsolved"),
        ("candidate", "run-a", 7, 1, 0, "candidate"),
    )
    for attempt_id, run_id, challenge_id, episode, lane, status in specifications:
        _attempt(state, attempt_id, run_id, challenge_id, episode, lane)
        observation = _observation(f"marker-{attempt_id}")
        if status == "candidate":
            observation = HostObservation(
                observation.tool,
                observation.success,
                observation.source_bound,
                observation.facts,
                candidate_sha256s=(candidate_digest,),
                supplied_candidate_sha256s=(candidate_digest,),
            )
        RunEvidence.open(state, run_id).commit(attempt_id, EvidenceBatch((observation,)))
        state.finish_attempt(attempt_id, status)

    rendered = _render(RunEvidence.open(state, "run-a").carry(7, 0, 2))
    assert "marker-expected" in rendered
    assert "marker-candidate" in rendered
    assert candidate_digest not in rendered
    for excluded in ("later", "other-lane", "other-challenge", "other-run"):
        assert f"marker-{excluded}" not in rendered
    state.close()


def test_candidate_carry_removes_private_raw_and_target_payload_digests(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite3"
    state = _state(database, "run-a")
    _attempt(state, "candidate-attempt")
    candidate = "INCYPHER{candidate-oracle-sentinel}"
    candidate_digest = hashlib.sha256(candidate.encode()).hexdigest()
    read_observation = project_tool_observation(
        "read_text",
        success=True,
        source_bound=True,
        result={"size": len(candidate.encode()), "text": candidate},
        candidate_sha256s=(candidate_digest,),
        supplied_candidate_sha256s=(candidate_digest,),
    )
    target_observation = project_tool_observation(
        "http_request",
        success=True,
        source_bound=True,
        result={"bytes": len(candidate.encode()), "status": 200, "text": candidate},
        candidate_sha256s=(candidate_digest,),
        supplied_candidate_sha256s=(candidate_digest,),
    )
    evidence = RunEvidence.open(state, "run-a")
    manifest = evidence.commit(
        "candidate-attempt", EvidenceBatch((read_observation, target_observation))
    )
    state.finish_attempt("candidate-attempt", "candidate")

    canonical_text = json.dumps(
        candidate, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()
    raw_digest = hashlib.sha256(canonical_text).hexdigest()
    target_digest = hashlib.sha256(
        b"rapido-target-response-payload-v1\0" + candidate.encode()
    ).hexdigest()
    private_digests = {
        candidate_digest,
        manifest.digest,
        raw_digest,
        target_digest,
        *(item.digest for item in manifest.items),
    }
    rendered = _render(evidence.carry(7, 0, 1))
    assert "text_bytes" in rendered
    assert '"status":200' in rendered
    assert '"payload_bytes"' in rendered
    assert '"payload_shape"' in rendered
    assert '"digest"' not in rendered
    assert "sha256" not in rendered
    for digest in private_digests:
        assert digest not in rendered
        assert digest.encode() in _storage(database)
    assert candidate not in rendered
    assert candidate.encode() not in _storage(database)
    state.close()


def test_projector_preserves_structure_but_not_raw_or_authority() -> None:
    candidate = "INCYPHER{projector-sentinel}"
    artifact = project_tool_observation(
        "inspect_artifact",
        success=True,
        source_bound=True,
        result={
            "coverage": "partial",
            "stop_reason": "record_limit",
            "data": {
                "sections": [
                    {
                        "name": ".text",
                        "address": "0x1000",
                        "size": 32,
                        "path": "/private/projector-sentinel",
                        "text": candidate,
                    }
                ],
                "instructions": [{"address": "0x1000", "mnemonic": "xor"}],
                "libraries": [{"name": "libc.so.6", "symbols": ["puts", "system"]}],
                "returncode": -9,
            },
        },
    )
    rendered = repr(artifact.facts)
    for expected in (
        "partial",
        "record_limit",
        ".text",
        "0x1000",
        "xor",
        "libc.so.6",
        "puts",
        "returncode",
    ):
        assert expected in rendered
    assert candidate not in rendered
    assert "/private/projector-sentinel" not in rendered
    assert "text_sha256" in rendered

    target = project_tool_observation(
        "http_request",
        success=True,
        source_bound=True,
        result={
            "status": 404,
            "bytes": len(candidate.encode()),
            "entry_count": 3,
            "content_length": 99,
            "body": candidate,
            "headers": {"authorization": "authority-sentinel"},
            "url": "https://target.invalid/private",
        },
    )
    target_facts = dict(target.facts)
    assert target_facts["status"] == 404
    assert target_facts["bytes"] == len(candidate.encode())
    assert target_facts["entry_count"] == 3
    assert target_facts["content_length"] == 99
    assert target_facts["payload_bytes"] == len(candidate.encode())
    assert target_facts["payload_digest_domain"] == "rapido-target-response-payload-v1"
    assert target_facts["payload_representation"] == "utf8"
    assert target_facts["payload_shape"] == {"kind": "text"}
    expected_payload_digest = hashlib.sha256(
        b"rapido-target-response-payload-v1\0" + candidate.encode()
    ).hexdigest()
    assert target_facts["payload_sha256"] == expected_payload_digest
    assert target_facts["payload_sha256"] != hashlib.sha256(candidate.encode()).hexdigest()
    assert target_facts["response_fields"] == (
        "body",
        "bytes",
        "content_length",
        "entry_count",
        "status",
    )
    target_rendered = repr(target_facts)
    assert candidate not in target_rendered
    assert "authority-sentinel" not in target_rendered
    assert "target.invalid" not in target_rendered

    json_payload = json.dumps(
        {
            "candidate": candidate,
            "path": "/private/shape-sentinel",
            "result": [1, 2],
            "token": "authority-sentinel",
        },
        separators=(",", ":"),
    )
    json_target = project_tool_observation(
        "http_request",
        success=True,
        source_bound=True,
        result={"status": 200, "text": json_payload},
    )
    assert dict(json_target.facts)["payload_shape"] == {
        "field_count": 4,
        "fields": ("result",),
        "kind": "object",
    }
    json_rendered = repr(json_target.facts)
    assert candidate not in json_rendered
    assert "shape-sentinel" not in json_rendered
    assert "authority-sentinel" not in json_rendered
    unknown = project_tool_observation(
        "future_tool", success=True, source_bound=True, result={"format": "unsafe-expansion"}
    )
    assert unknown.tool == "unknown_tool" and not unknown.facts


def test_floats_are_rejected_before_canonical_commit() -> None:
    with pytest.raises(TypeError, match="floats are not canonical"):
        HostObservation(
            tool="inspect_file",
            success=True,
            source_bound=True,
            facts={"size": 1.25},
        )


def test_commit_revalidates_sentinels_and_candidate_hashes_stay_private(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite3"
    state = _state(database, "run-a")
    _attempt(state, "a0")
    raw_candidate = "INCYPHER{raw-candidate-sentinel}"
    candidate_digest = hashlib.sha256(raw_candidate.encode()).hexdigest()
    observation = HostObservation(
        "inspect_file",
        True,
        True,
        {
            "format": "binary",
            "candidate": raw_candidate,
            "secret": "secret-sentinel",
            "authority": "authority-sentinel",
            "path": "/absolute/path-sentinel",
            "transcript": "transcript-sentinel",
        },
        candidate_sha256s=(candidate_digest,),
        supplied_candidate_sha256s=(candidate_digest,),
    )
    evidence = RunEvidence.open(state, "run-a")
    evidence.commit("a0", EvidenceBatch((observation,)))
    state.finish_attempt("a0", "unsolved")
    public = _render(evidence.carry(7, 0, 1))
    for sentinel in (
        raw_candidate,
        candidate_digest,
        "secret-sentinel",
        "authority-sentinel",
        "/absolute/path-sentinel",
        "transcript-sentinel",
    ):
        assert sentinel not in public
    stored = _storage(database)
    assert candidate_digest.encode() in stored
    for sentinel in (
        raw_candidate,
        "secret-sentinel",
        "authority-sentinel",
        "/absolute/path-sentinel",
        "transcript-sentinel",
    ):
        assert sentinel.encode() not in stored
    state.close()


def test_manifest_rejects_canonical_newer_document_with_valid_domain_digest(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path / "state.sqlite3", "run-a")
    _attempt(state, "a0")
    evidence = RunEvidence.open(state, "run-a")
    evidence.commit("a0", EvidenceBatch())
    state.finish_attempt("a0", "unsolved")
    row = state._connection.execute(
        "SELECT payload_json FROM evidence_manifests WHERE run_id='run-a' AND attempt_id='a0'"
    ).fetchone()
    document = json.loads(bytes(row["payload_json"]))
    document["schema_version"] = 2
    payload = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(b"rapido-host-evidence-manifest-v1\0" + payload).hexdigest()
    with state.transaction() as connection:
        connection.execute("DROP TRIGGER evidence_manifests_no_update")
        connection.execute(
            """
            UPDATE evidence_manifests SET digest=?, payload_json=?
            WHERE run_id='run-a' AND attempt_id='a0'
            """,
            (digest, payload),
        )
    with pytest.raises(EvidenceTamperError, match="schema version changed"):
        evidence.carry(7, 0, 1)
    state.close()


@pytest.mark.parametrize(
    ("limits", "omission"),
    (
        (EvidenceLimits(max_observations=1), "observation_limit"),
        (EvidenceLimits(max_object_bytes=1), "object_bytes"),
        (EvidenceLimits(max_attempt_bytes=1), "attempt_bytes"),
    ),
)
def test_quota_omissions_are_explicit(
    tmp_path: Path, limits: EvidenceLimits, omission: str
) -> None:
    state = _state(tmp_path / f"{omission}.sqlite3", "run-a")
    _attempt(state, "a0")
    observations = (_observation("one"), _observation("two"))
    manifest = RunEvidence.open(state, "run-a", limits).commit("a0", EvidenceBatch(observations))
    assert not manifest.complete
    assert manifest.gap == "quota_omitted"
    assert dict(manifest.omissions)[omission] > 0
    state.close()


def test_empty_incomplete_manifests_and_bounded_deterministic_carry(tmp_path: Path) -> None:
    state = _state(tmp_path / "state.sqlite3", "run-a")
    limits = EvidenceLimits(max_carry_bytes=512)
    evidence = RunEvidence.open(state, "run-a", limits)
    _attempt(state, "empty", episode=0)
    empty = evidence.commit("empty", EvidenceBatch())
    state.finish_attempt("empty", "unsolved")
    assert empty.complete and empty.committed_count == 0

    _attempt(state, "incomplete", episode=1)
    incomplete = evidence.commit(
        "incomplete", EvidenceBatch(complete=False, gap="provenance_incomplete")
    )
    state.finish_attempt("incomplete", "failed")
    assert not incomplete.complete and incomplete.gap == "provenance_incomplete"
    first = evidence.carry(7, 0, 2)
    second = evidence.carry(7, 0, 2)
    assert first.as_dict() == second.as_dict()
    assert len(_render(first).encode()) <= limits.max_carry_bytes
    state.close()


@pytest.mark.parametrize("value", (0, -1, True, 101))
def test_limits_are_strict_positive_bounded_integers(value: object) -> None:
    with pytest.raises(ValueError):
        EvidenceLimits(max_observations=value)  # type: ignore[arg-type]
