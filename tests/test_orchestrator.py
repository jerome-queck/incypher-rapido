from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from rapido.board import BoardError, Challenge, Verdict
from rapido.config import RuntimeConfig
from rapido.orchestrator import Orchestrator
from rapido.state import StateStore


class FakeBoard:
    def __init__(self, challenges: list[Challenge]) -> None:
        self.challenges = {challenge.id: challenge for challenge in challenges}
        self.submissions: list[tuple[int, str]] = []
        self.instance_calls: list[tuple[str, int]] = []
        self.active_instances: dict[int, dict[str, object]] = {}

    def list_challenges(self):
        return [{"id": challenge_id} for challenge_id in self.challenges]

    def identity(self):
        return {"id": 1, "team_id": 2}

    def anonymous_identity_is_rejected(self):
        return True

    def challenge(self, challenge_id: int) -> Challenge:
        return self.challenges[challenge_id]

    def download(self, file_ref: str, destination: Path, *, byte_limit: int):
        destination.write_bytes(b"artifact payload")
        return {"bytes": min(16, byte_limit), "redirect_hosts": ["board"]}

    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        self.submissions.append((challenge_id, candidate))
        return Verdict("correct", "ok", 200)

    def instance(self, method: str, challenge_id: int):
        self.instance_calls.append((method, challenge_id))
        if method == "POST":
            self.active_instances[challenge_id] = {
                "connection_info": "http://127.0.0.1:8135/",
                "until": 100,
            }
            return {"success": True, "status": 200, **self.active_instances[challenge_id]}
        if method == "DELETE":
            self.active_instances.pop(challenge_id, None)
            return {"success": True, "status": 200, "connection_info": "", "until": None}
        if challenge_id not in self.active_instances:
            return {
                "success": False,
                "status": 404,
                "connection_info": "",
                "until": None,
            }
        return {"success": True, "status": 200, **self.active_instances[challenge_id]}


class RejectingCreateBoard(FakeBoard):
    def instance(self, method: str, challenge_id: int):
        if method == "POST":
            self.instance_calls.append((method, challenge_id))
            return {"success": False, "status": 409, "connection_info": "", "until": None}
        return super().instance(method, challenge_id)


class SlowCreateBoard(FakeBoard):
    def __init__(self, challenges: list[Challenge]) -> None:
        super().__init__(challenges)
        self.post_started = threading.Event()
        self.post_release = threading.Event()

    def instance(self, method: str, challenge_id: int):
        if method == "POST":
            self.instance_calls.append((method, challenge_id))
            self.post_started.set()
            assert self.post_release.wait(timeout=2)
            self.active_instances[challenge_id] = {
                "connection_info": "http://127.0.0.1:8135/",
                "until": 100,
            }
            return {"success": True, "status": 200, **self.active_instances[challenge_id]}
        return super().instance(method, challenge_id)


class FakeRuntime:
    def __init__(self, candidates: dict[int, dict[int, str | None]]) -> None:
        self.candidates = candidates
        self.active = 0
        self.max_active = 0
        self.started = False
        self.closed = False
        self.solve_kwargs: list[dict[str, object]] = []

    async def start(self) -> None:
        self.started = True

    async def solve(self, workspace, prompt, **kwargs):
        self.solve_kwargs.append(kwargs)
        prompt = json.loads(prompt)
        challenge_id = prompt["challenge"]["id"]
        lane = prompt["lane"]
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        await asyncio.sleep(0.01)
        candidate = self.candidates.get(challenge_id, {}).get(lane)
        self.active -= 1
        document = {
            "status": "candidate" if candidate else "unsolved",
            "candidate": candidate,
            "confidence": 0.9 if candidate else 0,
            "summary": "derived from artifact",
            "evidence": ["artifact bytes"] if candidate else [],
            "next_steps": [],
        }
        return type(
            "FakeTurn",
            (),
            {
                "text": json.dumps(document),
                "status": "completed",
                "tool_calls": [
                    {
                        "name": "inspect_file",
                        "success": True,
                        "source_bound": True,
                        "candidate_sha256s": (
                            [hashlib.sha256(candidate.encode()).hexdigest()] if candidate else []
                        ),
                    }
                ],
            },
        )()

    async def close(self) -> None:
        self.closed = True


class ReplaceDuringSolveRuntime(FakeRuntime):
    def __init__(self, board: FakeBoard) -> None:
        super().__init__({2: {0: None, 1: None}})
        self.board = board

    async def solve(self, workspace, prompt, **kwargs):
        turn = await super().solve(workspace, prompt, **kwargs)
        self.board.active_instances[2] = {
            "connection_info": "http://127.0.0.2:8135/",
            "until": 101,
        }
        return turn


class FirstChallengeTimeoutRuntime(FakeRuntime):
    async def solve(self, workspace, prompt, **kwargs):
        document = json.loads(prompt)
        if document["challenge"]["id"] == 1:
            raise TimeoutError
        return await super().solve(workspace, prompt, **kwargs)


class HangingStartRuntime(FakeRuntime):
    async def start(self) -> None:
        await asyncio.sleep(60)


class CancelledStartRuntime(FakeRuntime):
    async def start(self) -> None:
        raise asyncio.CancelledError


class NoProvenanceRuntime(FakeRuntime):
    async def solve(self, workspace, prompt, **kwargs):
        turn = await super().solve(workspace, prompt, **kwargs)
        turn.tool_calls[0]["candidate_sha256s"] = []
        turn.tool_calls[0]["source_bound"] = False
        return turn


class ReflectedCandidateRuntime(FakeRuntime):
    async def solve(self, workspace, prompt, **kwargs):
        turn = await super().solve(workspace, prompt, **kwargs)
        candidate = json.loads(turn.text)["candidate"]
        fingerprint = hashlib.sha256(candidate.encode()).hexdigest()
        turn.tool_calls[0]["candidate_sha256s"] = [fingerprint]
        turn.tool_calls[0]["supplied_candidate_sha256s"] = [fingerprint]
        return turn


class SerialRuntime(FakeRuntime):
    async def solve(self, workspace, prompt, **kwargs):
        document = json.loads(prompt)
        candidate = self.candidates[document["challenge"]["id"]][document["lane"]]
        return type(
            "FakeTurn",
            (),
            {
                "text": json.dumps(
                    {
                        "status": "candidate",
                        "candidate": candidate,
                        "confidence": 0.9,
                        "summary": "serial",
                        "evidence": ["claimed"],
                        "next_steps": [],
                    }
                ),
                "status": "completed",
                "tool_calls": [
                    {
                        "name": "read_text",
                        "success": True,
                        "source_bound": True,
                        "candidate_sha256s": [hashlib.sha256(candidate.encode()).hexdigest()],
                    }
                ],
            },
        )()


class AmbiguousSubmitBoard(FakeBoard):
    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        self.submissions.append((challenge_id, candidate))
        raise BoardError("connection reset after request")


class ShortTimeoutBoard(FakeBoard):
    timeout = 0.1


class TransportBecomesTooSlowRuntime(FakeRuntime):
    def __init__(self, candidates, board: ShortTimeoutBoard) -> None:
        super().__init__(candidates)
        self.board = board

    async def solve(self, workspace, prompt, **kwargs):
        turn = await super().solve(workspace, prompt, **kwargs)
        self.board.timeout = 60.0
        return turn


class BudgetBoard(FakeBoard):
    def __init__(self, challenges: list[Challenge]) -> None:
        super().__init__(challenges)
        self.byte_limits: list[int] = []

    def download(self, file_ref: str, destination: Path, *, byte_limit: int):
        self.byte_limits.append(byte_limit)
        destination.write_bytes(b"bounded")
        return {"bytes": byte_limit, "redirect_hosts": ["board"]}


class ReplacedInstanceBoard(FakeBoard):
    def instance(self, method: str, challenge_id: int):
        self.instance_calls.append((method, challenge_id))
        if method == "DELETE":
            raise AssertionError("replacement generation must not be deleted")
        return {
            "success": True,
            "status": 200,
            "connection_info": "generation-two",
            "until": 200,
        }


class IndeterminateInstanceBoard(FakeBoard):
    def instance(self, method: str, challenge_id: int):
        self.instance_calls.append((method, challenge_id))
        return {
            "success": False,
            "status": 429,
            "connection_info": "",
            "until": None,
        }


class VolatileTimeoutBoard(FakeBoard):
    def __init__(self, challenges: list[Challenge]) -> None:
        super().__init__(challenges)
        self.detail_reads = 0

    def challenge(self, challenge_id: int) -> Challenge:
        self.detail_reads += 1
        return replace(
            self.challenges[challenge_id],
            timeout=self.detail_reads,
            files=(f"/files/a?signature={self.detail_reads}",),
        )


def challenge(challenge_id: int, *, challenge_type: str = "standard", files=()) -> Challenge:
    return Challenge(
        challenge_id,
        f"Challenge {challenge_id}",
        "crypto",
        challenge_type,
        "derive the value",
        100,
        tuple(files),
        False,
        0,
        0,
        None,
        None,
    )


def config(tmp_path: Path, *, submit: bool = True) -> RuntimeConfig:
    (tmp_path / "auth").mkdir(exist_ok=True)
    base = RuntimeConfig.from_env(
        {
            "RAPIDO_STATE_PATH": str(tmp_path / "state.sqlite3"),
            "RAPIDO_WORK_ROOT": str(tmp_path / "work"),
            "RAPIDO_CODEX_HOME": str(tmp_path / "auth"),
            "RAPIDO_SUBMIT_CANDIDATES": "true" if submit else "false",
        }
    )
    return replace(base, run_seconds=60, attempt_seconds=15)


def test_two_lanes_overlap_agree_submit_once_and_persist_without_plain_candidate(
    tmp_path: Path,
) -> None:
    answer = "INCYPHER{derived_42}"
    board = FakeBoard([challenge(1, files=("/files/input.bin",))])
    runtime = FakeRuntime({1: {0: answer, 1: answer}})
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(config(tmp_path), board, store, runtime).run())
    assert report.status == "completed"
    assert report.solved == 1
    assert report.overlapping_waves == 1
    assert runtime.max_active == 2
    assert board.submissions == [(1, answer)]
    row = store._connection.execute("SELECT * FROM submissions").fetchone()
    assert answer not in repr(dict(row))
    wave = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='attempt_wave'"
    ).fetchone()
    assert "inspect_file" in wave["data_json"]
    assert '"source_bound":true' in wave["data_json"]
    assert hashlib.sha256(answer.encode()).hexdigest() in wave["data_json"]
    assert runtime.started and runtime.closed
    store.close()


def test_disagreement_withholds_submission_and_continues_to_next_challenge(tmp_path: Path) -> None:
    board = FakeBoard([challenge(1), challenge(2)])
    runtime = FakeRuntime(
        {
            1: {0: "INCYPHER{one}", 1: "INCYPHER{two}"},
            2: {0: "INCYPHER{agreed}", 1: "INCYPHER{agreed}"},
        }
    )
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(config(tmp_path), board, store, runtime).run())
    assert report.solved == 1
    assert board.submissions == [(2, "INCYPHER{agreed}")]
    statuses = {
        row["id"]: row["status"]
        for row in store._connection.execute("SELECT id, status FROM challenges")
    }
    assert statuses == {1: "unsolved", 2: "solved"}
    store.close()


def test_disabled_submissions_and_dynamic_surface_are_truthful(tmp_path: Path) -> None:
    answer = "INCYPHER{agreed}"
    board = FakeBoard([challenge(1), challenge(2, challenge_type="dynamic_iac")])
    runtime = FakeRuntime({1: {0: answer, 1: answer}})
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(config(tmp_path, submit=False), board, store, runtime).run())
    assert report.candidates == 1
    assert report.unsupported == 1
    assert board.submissions == []
    statuses = [
        row["status"]
        for row in store._connection.execute("SELECT status FROM challenges ORDER BY id")
    ]
    assert statuses == ["candidate", "unsupported"]
    store.close()


def test_stale_owned_instance_with_matching_receipt_is_deleted_and_verified(
    tmp_path: Path,
) -> None:
    cfg = config(tmp_path)
    store = StateStore(tmp_path / "state.sqlite3")
    store.bind_board_identity(1, 2)
    store.start_run("old-run", cfg.public_record())
    store.upsert_challenge(9, "Dynamic", "web", "dynamic_iac", 100)
    receipt = hashlib.sha256(
        b'{"connection_info":"generation-one","since":null,"until":100}'
    ).hexdigest()
    store.mark_instance("old-run", 9, "owned", receipt_sha256=receipt)
    store.finish_run("old-run", "interrupted")
    board = FakeBoard([challenge(10, challenge_type="dynamic_iac")])
    board.active_instances[9] = {"connection_info": "generation-one", "until": 100}
    asyncio.run(Orchestrator(cfg, board, store, FakeRuntime({})).run())
    assert board.instance_calls == [("GET", 9), ("DELETE", 9), ("GET", 9)]
    assert store.owned_instances() == []
    event = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='instance_cleanup'"
    ).fetchone()
    assert '"status":"removed"' in event["data_json"]
    store.close()


def test_dynamic_challenge_creates_uses_and_removes_board_instance(tmp_path: Path) -> None:
    cfg = replace(config(tmp_path, submit=False), manage_dynamic_instances=True)
    dynamic = challenge(2, challenge_type="dynamic_iac")
    board = FakeBoard([dynamic])
    runtime = FakeRuntime({2: {0: None, 1: None}})
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(cfg, board, store, runtime).run())
    assert report.unsolved == 1
    assert board.instance_calls == [
        ("GET", 2),
        ("POST", 2),
        ("GET", 2),
        ("GET", 2),
        ("DELETE", 2),
        ("GET", 2),
    ]
    assert store.owned_instances() == []
    ready = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='instance_ready'"
    ).fetchone()
    assert '"protocol":"http"' in ready["data_json"]
    assert "127.0.0.1" not in ready["data_json"]
    assert all(kwargs["tool_registry"].endpoints[0].port == 8135 for kwargs in runtime.solve_kwargs)
    store.close()


def test_preexisting_unowned_instance_is_never_deleted(tmp_path: Path) -> None:
    cfg = replace(config(tmp_path, submit=False), manage_dynamic_instances=True)
    dynamic = challenge(2, challenge_type="dynamic_iac")
    board = FakeBoard([dynamic])
    board.active_instances[2] = {
        "connection_info": "http://127.0.0.1:8135/",
        "until": 100,
    }
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(cfg, board, store, FakeRuntime({})).run())
    assert report.errors == 1
    assert board.instance_calls == [("GET", 2)]
    assert 2 in board.active_instances
    assert store.owned_instances() == []
    store.close()


def test_rejected_create_cleans_intent_without_delete_when_absent(tmp_path: Path) -> None:
    cfg = replace(config(tmp_path, submit=False), manage_dynamic_instances=True)
    dynamic = challenge(2, challenge_type="dynamic_iac")
    board = RejectingCreateBoard([dynamic])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(cfg, board, store, FakeRuntime({})).run())
    assert report.errors == 1
    assert board.instance_calls == [("GET", 2), ("POST", 2), ("GET", 2)]
    assert store.owned_instances() == []
    store.close()


def test_create_cancellation_waits_for_teardown_and_verifies_absence(tmp_path: Path) -> None:
    async def exercise() -> tuple[SlowCreateBoard, StateStore]:
        cfg = replace(config(tmp_path, submit=False), manage_dynamic_instances=True)
        dynamic = challenge(2, challenge_type="dynamic_iac")
        board = SlowCreateBoard([dynamic])
        store = StateStore(tmp_path / "state.sqlite3")
        store.start_run("run", cfg.public_record())
        store.upsert_challenge(2, dynamic.name, dynamic.category, dynamic.type, dynamic.value)
        orchestrator = Orchestrator(cfg, board, store, FakeRuntime({}))
        task = asyncio.create_task(
            orchestrator._solve_dynamic_challenge(
                "run", tmp_path / "work", dynamic, asyncio.get_running_loop().time() + 60
            )
        )
        assert await asyncio.to_thread(board.post_started.wait, 1)
        task.cancel()
        board.post_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        return board, store

    board, store = asyncio.run(exercise())
    assert board.instance_calls == [
        ("GET", 2),
        ("POST", 2),
        ("GET", 2),
        ("DELETE", 2),
        ("GET", 2),
    ]
    assert board.active_instances == {}
    assert store.owned_instances() == []
    store.close()


def test_completion_never_deletes_replaced_generation(tmp_path: Path) -> None:
    cfg = replace(config(tmp_path, submit=False), manage_dynamic_instances=True)
    dynamic = challenge(2, challenge_type="dynamic_iac")
    board = FakeBoard([dynamic])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(cfg, board, store, ReplaceDuringSolveRuntime(board)).run())
    assert report.errors == 1
    assert board.instance_calls == [("GET", 2), ("POST", 2), ("GET", 2), ("GET", 2)]
    assert board.active_instances[2]["connection_info"] == "http://127.0.0.2:8135/"
    event = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='instance_cleanup'"
    ).fetchone()
    assert '"status":"skipped_replaced"' in event["data_json"]
    store.close()


def test_concurrency_cap_and_early_agreement_cancel_unstarted_lanes(tmp_path: Path) -> None:
    cfg = replace(config(tmp_path), concurrency=2, attempts_per_challenge=4)
    answer = "INCYPHER{early_agreement}"
    runtime = FakeRuntime({1: {lane: answer for lane in range(4)}})
    board = FakeBoard([challenge(1)])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(cfg, board, store, runtime).run())
    assert report.solved == 1
    assert runtime.max_active == 2
    attempts = store.attempts_for_challenge(report.run_id, 1)
    assert len(attempts) >= 2
    assert len(attempts) < 4 or any(row["status"] == "cancelled" for row in attempts)
    assert board.submissions == [(1, answer)]
    store.close()


def test_timed_out_slots_release_and_next_challenge_runs(tmp_path: Path) -> None:
    answer = "INCYPHER{after_timeout}"
    board = FakeBoard([challenge(1), challenge(2)])
    runtime = FirstChallengeTimeoutRuntime({2: {0: answer, 1: answer}})
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(config(tmp_path), board, store, runtime).run())
    assert report.errors == 1
    assert report.solved == 1
    assert board.submissions == [(2, answer)]
    store.close()


def test_whole_run_deadline_bounds_runtime_start(tmp_path: Path) -> None:
    cfg = replace(config(tmp_path), run_seconds=0.01)
    runtime = HangingStartRuntime({})
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(cfg, FakeBoard([]), store, runtime).run())
    assert report.status == "deadline"
    assert runtime.closed
    row = store._connection.execute(
        "SELECT status FROM runs WHERE id=?", (report.run_id,)
    ).fetchone()
    assert row["status"] == "deadline"
    store.close()


def test_cancellation_persists_interrupted_run(tmp_path: Path) -> None:
    runtime = CancelledStartRuntime({})
    store = StateStore(tmp_path / "state.sqlite3")
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(Orchestrator(config(tmp_path), FakeBoard([]), store, runtime).run())
    row = store._connection.execute("SELECT status FROM runs").fetchone()
    assert row["status"] == "interrupted"
    assert runtime.closed
    store.close()


def test_candidate_is_withheld_when_transport_cannot_finish_before_deadline(
    tmp_path: Path,
) -> None:
    answer = "INCYPHER{deadline_guard}"
    cfg = config(tmp_path)
    board = ShortTimeoutBoard([challenge(1)])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(
        Orchestrator(
            cfg,
            board,
            store,
            TransportBecomesTooSlowRuntime({1: {0: answer, 1: answer}}, board),
        ).run()
    )
    assert report.candidates == 1
    assert board.submissions == []
    event = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='candidate_withheld'"
    ).fetchone()
    assert '"reason":"run_deadline"' in event["data_json"]
    store.close()


def test_candidate_requires_host_observed_tool_provenance(tmp_path: Path) -> None:
    answer = "INCYPHER{fabricated}"
    board = FakeBoard([challenge(1)])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(
        Orchestrator(
            config(tmp_path),
            board,
            store,
            NoProvenanceRuntime({1: {0: answer, 1: answer}}),
        ).run()
    )
    assert report.errors == 1
    assert board.submissions == []
    failure = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='attempt_failure' ORDER BY sequence LIMIT 1"
    ).fetchone()
    assert '"reason":"solver_output"' in failure["data_json"]
    store.close()


def test_candidate_rejects_model_supplied_value_reflected_by_tool(tmp_path: Path) -> None:
    answer = "INCYPHER{reflected_input}"
    board = FakeBoard([challenge(1)])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(
        Orchestrator(
            config(tmp_path),
            board,
            store,
            ReflectedCandidateRuntime({1: {0: answer, 1: answer}}),
        ).run()
    )
    assert report.errors == 1
    assert board.submissions == []
    store.close()


def test_non_overlapping_lanes_are_rejected(tmp_path: Path) -> None:
    answer = "INCYPHER{serial}"
    board = FakeBoard([challenge(1)])
    store = StateStore(tmp_path / "state.sqlite3")
    cfg = replace(config(tmp_path), concurrency=1)
    report = asyncio.run(
        Orchestrator(
            cfg,
            board,
            store,
            SerialRuntime({1: {0: answer, 1: answer}}),
        ).run()
    )
    assert report.errors == 1
    assert report.overlapping_waves == 0
    assert board.submissions == []
    store.close()


def test_ambiguous_submission_is_reserved_before_effect_and_not_retried(
    tmp_path: Path,
) -> None:
    answer = "INCYPHER{ambiguous}"
    board = AmbiguousSubmitBoard([challenge(1)])
    cfg = config(tmp_path)
    store = StateStore(tmp_path / "state.sqlite3")
    first = asyncio.run(
        Orchestrator(cfg, board, store, FakeRuntime({1: {0: answer, 1: answer}})).run()
    )
    second = asyncio.run(
        Orchestrator(cfg, board, store, FakeRuntime({1: {0: answer, 1: answer}})).run()
    )
    assert first.candidates == second.candidates == 1
    assert board.submissions == [(1, answer)]
    intent = store._connection.execute("SELECT status FROM submission_intents").fetchone()
    assert intent["status"] == "pending"
    store.close()


def test_empty_board_catalogue_fails_closed(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    with pytest.raises(BoardError, match="empty"):
        asyncio.run(Orchestrator(config(tmp_path), FakeBoard([]), store, FakeRuntime({})).run())
    row = store._connection.execute("SELECT status FROM runs").fetchone()
    assert row["status"] == "failed"
    store.close()


def test_board_coherence_ignores_timeout_and_attachment_signature_volatility(
    tmp_path: Path,
) -> None:
    board = VolatileTimeoutBoard([challenge(1, challenge_type="dynamic_iac")])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(config(tmp_path), board, store, FakeRuntime({})).run())
    assert report.unsupported == 1
    assert board.detail_reads == 2
    store.close()


def test_challenge_artifact_aggregate_budget_prevents_disk_amplification(
    tmp_path: Path,
) -> None:
    cfg = replace(config(tmp_path), max_artifact_bytes=60, max_challenge_bytes=100)
    board = BudgetBoard([challenge(1, files=("/a", "/b", "/c"))])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(cfg, board, store, FakeRuntime({})).run())
    assert report.errors == 1
    assert board.byte_limits == [60, 40]
    run_root = cfg.work_root / f"run-{report.run_id}"
    assert list(run_root.iterdir()) == []
    store.close()


def test_stale_instance_generation_mismatch_never_deletes_replacement(
    tmp_path: Path,
) -> None:
    cfg = config(tmp_path)
    store = StateStore(tmp_path / "state.sqlite3")
    store.bind_board_identity(1, 2)
    store.start_run("old-run", cfg.public_record())
    store.upsert_challenge(9, "Dynamic", "web", "dynamic_iac", 100)
    old_receipt = hashlib.sha256(
        b'{"connection_info":"generation-one","since":null,"until":100}'
    ).hexdigest()
    store.mark_instance("old-run", 9, "owned", receipt_sha256=old_receipt)
    store.finish_run("old-run", "interrupted")
    board = ReplacedInstanceBoard([challenge(10, challenge_type="dynamic_iac")])
    asyncio.run(Orchestrator(cfg, board, store, FakeRuntime({})).run())
    assert board.instance_calls == [("GET", 9)]
    assert store.owned_instances() == []
    event = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='instance_cleanup'"
    ).fetchone()
    assert '"status":"skipped_replaced"' in event["data_json"]
    store.close()


def test_receiptless_stale_intent_never_authorizes_delete(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    store = StateStore(tmp_path / "state.sqlite3")
    store.bind_board_identity(1, 2)
    store.start_run("old-run", cfg.public_record())
    store.upsert_challenge(9, "Dynamic", "web", "dynamic_iac", 100)
    store.mark_instance("old-run", 9, "creating")
    store.finish_run("old-run", "interrupted")
    board = FakeBoard([challenge(10, challenge_type="dynamic_iac")])
    board.active_instances[9] = {
        "connection_info": "http://127.0.0.1:8135/",
        "until": 100,
    }
    asyncio.run(Orchestrator(cfg, board, store, FakeRuntime({})).run())
    assert board.instance_calls == [("GET", 9)]
    assert 9 in board.active_instances
    assert store.owned_instances()[0]["status"] == "cleanup_pending"
    event = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='instance_cleanup'"
    ).fetchone()
    assert '"reason":"no generation receipt proves ownership"' in event["data_json"]
    store.close()


def test_indeterminate_instance_state_retains_cleanup_ownership(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    store = StateStore(tmp_path / "state.sqlite3")
    store.bind_board_identity(1, 2)
    store.start_run("old-run", cfg.public_record())
    store.upsert_challenge(9, "Dynamic", "web", "dynamic_iac", 100)
    store.mark_instance("old-run", 9, "owned", receipt_sha256="a" * 64)
    store.finish_run("old-run", "interrupted")
    board = IndeterminateInstanceBoard([challenge(10, challenge_type="dynamic_iac")])
    asyncio.run(Orchestrator(cfg, board, store, FakeRuntime({})).run())
    assert board.instance_calls == [("GET", 9)]
    assert store.owned_instances()[0]["status"] == "cleanup_pending"
    event = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='instance_cleanup'"
    ).fetchone()
    assert '"detail":"Board state was indeterminate"' in event["data_json"]
    store.close()


def test_restart_removes_only_owned_shape_stale_workspace_roots(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    cfg.work_root.mkdir(mode=0o700)
    stale = cfg.work_root / ("run-" + "a" * 32)
    stale.mkdir()
    (stale / "artifact.bin").write_bytes(b"old")
    unrelated = cfg.work_root / "keep-me"
    unrelated.mkdir()
    store = StateStore(tmp_path / "state.sqlite3")
    asyncio.run(Orchestrator(cfg, FakeBoard([challenge(1)]), store, FakeRuntime({})).run())
    assert not stale.exists()
    assert unrelated.is_dir()
    store.close()


def test_run_rejects_public_work_root(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    cfg.work_root.mkdir(mode=0o755)
    cfg.work_root.chmod(0o755)
    store = StateStore(tmp_path / "state.sqlite3")
    try:
        with pytest.raises(OSError, match="private"):
            asyncio.run(Orchestrator(cfg, FakeBoard([]), store, FakeRuntime({})).run())
    finally:
        cfg.work_root.chmod(0o700)
        store.close()
