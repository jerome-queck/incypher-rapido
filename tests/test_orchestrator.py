from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

import rapido.orchestrator as orchestrator_module
from rapido.board import BoardError, BoardTransportError, Challenge, Verdict
from rapido.config import RuntimeConfig
from rapido.evidence import EvidenceError, EvidenceLimits, HostObservation, RunEvidence
from rapido.orchestrator import Orchestrator
from rapido.routing import baseline_route
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


class FailedTurnRuntime(FakeRuntime):
    async def solve(self, workspace, prompt, **kwargs):
        turn = await super().solve(workspace, prompt, **kwargs)
        turn.status = "failed"
        turn.failure_class = "usage_limit_exceeded"
        turn.tool_calls.append(
            {
                "name": "sensitive-model-tool-name-sentinel",
                "success": False,
                "source_bound": False,
                "candidate_sha256s": [],
            }
        )
        return turn


class ManyToolCallsRuntime(FakeRuntime):
    async def solve(self, workspace, prompt, **kwargs):
        turn = await super().solve(workspace, prompt, **kwargs)
        turn.text = json.dumps(
            {
                "status": "unsolved",
                "candidate": None,
                "confidence": 0.25,
                "summary": "bounded analysis remains unresolved",
                "evidence": ["archive header verified", "candidate path rejected"],
                "next_steps": ["inspect the remaining encoded member"],
            }
        )
        turn.tool_calls = [
            {
                "name": "inspect_file",
                "success": True,
                "source_bound": True,
                "candidate_sha256s": [],
            }
            for _ in range(133)
        ]
        return turn


class HangingStartRuntime(FakeRuntime):
    async def start(self) -> None:
        await asyncio.sleep(60)


class CancelledStartRuntime(FakeRuntime):
    async def start(self) -> None:
        raise asyncio.CancelledError


class CancelledSolveRuntime(FakeRuntime):
    def __init__(
        self,
        *,
        with_observation: bool,
        streamed_only: bool = False,
        streamed_incomplete: bool = False,
    ) -> None:
        super().__init__({})
        self.with_observation = with_observation
        self.streamed_only = streamed_only
        self.streamed_incomplete = streamed_incomplete
        self.solve_started = asyncio.Event()

    async def solve(self, workspace, prompt, **kwargs):
        del workspace, prompt
        self.solve_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError as exc:
            observation = HostObservation(
                tool="inspect_file",
                success=True,
                source_bound=True,
                facts={"format": "ELF"},
            )
            calls = (
                [
                    {
                        "name": observation.tool,
                        "success": observation.success,
                        "source_bound": observation.source_bound,
                        "candidate_sha256s": [],
                        "supplied_candidate_sha256s": [],
                        "host_observation": observation,
                    }
                ]
                if self.with_observation
                else []
            )
            if self.streamed_only and calls:
                if self.streamed_incomplete:
                    kwargs["progress_callback"](None)
                kwargs["progress_callback"](observation)
            else:
                exc.result = type("CancelledEvidence", (), {"tool_calls": calls})()
            raise


class BlockingCloseRuntime(FakeRuntime):
    def __init__(self) -> None:
        super().__init__({})
        self.close_started = asyncio.Event()
        self.release_close = asyncio.Event()

    async def close(self) -> None:
        self.close_started.set()
        await self.release_close.wait()
        self.closed = True


class NoProvenanceRuntime(FakeRuntime):
    async def solve(self, workspace, prompt, **kwargs):
        turn = await super().solve(workspace, prompt, **kwargs)
        turn.tool_calls[0]["candidate_sha256s"] = []
        turn.tool_calls[0]["source_bound"] = False
        return turn


class MalformedEvidenceRuntime(NoProvenanceRuntime):
    async def solve(self, workspace, prompt, **kwargs):
        turn = await super().solve(workspace, prompt, **kwargs)
        document = json.loads(turn.text)
        document["evidence"] = ["bad-surrogate-\ud800"]
        turn.text = json.dumps(document)
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


class FlakyIdentityBoard(FakeBoard):
    timeout = 0.01

    def __init__(self, challenges: list[Challenge]) -> None:
        super().__init__(challenges)
        self.identity_calls = 0

    def identity(self):
        self.identity_calls += 1
        if self.identity_calls == 1:
            raise BoardTransportError("Board transport failed")
        return super().identity()


class AlwaysFailingIdentityBoard(FakeBoard):
    timeout = 0.01

    def __init__(self, challenges: list[Challenge], error: BoardError) -> None:
        super().__init__(challenges)
        self.error = error
        self.identity_calls = 0

    def identity(self):
        self.identity_calls += 1
        raise self.error


class RecoveringWatchBoard(FakeBoard):
    timeout = 0.001

    def __init__(self, challenges: list[Challenge], failed_reads: set[int]) -> None:
        super().__init__(challenges)
        self.failed_reads = failed_reads
        self.list_calls = 0

    def list_challenges(self):
        self.list_calls += 1
        if self.list_calls in self.failed_reads:
            raise BoardTransportError("Board transport failed")
        return super().list_challenges()


class FlakyCreateTransportBoard(FakeBoard):
    timeout = 0.01

    def __init__(self, challenges: list[Challenge]) -> None:
        super().__init__(challenges)
        self.post_calls = 0

    def instance(self, method: str, challenge_id: int):
        if method == "POST":
            self.post_calls += 1
            self.instance_calls.append((method, challenge_id))
            raise BoardTransportError("Board transport failed")
        return super().instance(method, challenge_id)


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
            "RAPIDO_MANAGE_DYNAMIC_INSTANCES": "false",
            "RAPIDO_ACTIVE_CHALLENGES": "2",
            "RAPIDO_ATTEMPTS_PER_CHALLENGE": "2",
            "RAPIDO_CONCURRENCY": "4",
            "RAPIDO_PEER_PROFILE": "uniform_v1",
            "RAPIDO_MEMORY_ARM": "lane_local_v1",
            "RAPIDO_WATCH_BOARD": "false",
        }
    )
    return replace(base, run_seconds=60, attempt_seconds=15, episodes_per_challenge=1)


def test_every_lane_receives_source_bound_challenge_context(tmp_path: Path) -> None:
    item = challenge(7)
    board = FakeBoard([item])
    store = StateStore(tmp_path / "state.sqlite3")
    orchestrator = Orchestrator(config(tmp_path), board, store, FakeRuntime({}))
    prepared = asyncio.run(
        orchestrator._prepare_workspaces(
            "run",
            tmp_path / "run",
            item,
            0,
            float("inf"),
            lane_count=1,
        )
    )
    workspace, paths = prepared[0]
    assert paths == ["artifacts/.rapido-context.json"]
    assert json.loads((workspace / paths[0]).read_text()) == {
        "category": "crypto",
        "description": "derive the value",
        "id": 7,
        "name": "Challenge 7",
        "type": "standard",
        "value": 100,
    }
    store.close()


def test_incorrect_candidate_carry_tokens_only_expand_exact_crc32_forms() -> None:
    raw = b"Ab12cD34"
    flagged = b"INCYPHER{0123aBcD}"
    embedded = b"INCYPHER{prefix_cafebabe_suffix}"

    tokens = orchestrator_module._incorrect_candidate_carry_tokens((raw, flagged, embedded))

    assert {raw, flagged, embedded}.issubset(tokens)
    for crc in (raw, b"0123aBcD"):
        assert crc.lower() in tokens
        assert crc.upper() in tokens
        assert int(crc, 16).to_bytes(4, "big") in tokens
        assert int(crc, 16).to_bytes(4, "little") in tokens
    assert b"cafebabe" not in tokens
    assert b"CAFEBABE" not in tokens
    assert bytes.fromhex("cafebabe") not in tokens
    assert bytes.fromhex("cafebabe")[::-1] not in tokens


def test_incorrect_candidate_carry_tokens_fail_closed_on_unbounded_input() -> None:
    with pytest.raises(ValueError, match="count"):
        orchestrator_module._incorrect_candidate_carry_tokens(
            (b"x",) * (orchestrator_module.MAX_PRIVATE_INCORRECT_CANDIDATES + 1)
        )
    oversized = b"x" * (
        orchestrator_module.MAX_PRIVATE_INCORRECT_CANDIDATE_BYTES
        // orchestrator_module.MAX_PRIVATE_INCORRECT_CANDIDATES
        + 1
    )
    with pytest.raises(ValueError, match="exceed"):
        orchestrator_module._incorrect_candidate_carry_tokens(
            (oversized,) * orchestrator_module.MAX_PRIVATE_INCORRECT_CANDIDATES
        )


def test_analysis_carry_filters_rejected_candidate_content_and_paths(tmp_path: Path) -> None:
    cfg = config(tmp_path, submit=False)
    store = StateStore(cfg.state_path)
    item = challenge(1)
    run_id = "carry-filter-run"
    rejected_crc = "INCYPHER{deadBEEF}"
    non_crc = "INCYPHER{prefix_cafebabe_suffix}"
    route = baseline_route(model=cfg.model, effort=cfg.reasoning_effort, attempt_seconds=15)
    assignments = tuple(("specialist", route.model, route.effort) for _ in range(2))
    material = orchestrator_module._challenge_material_sha256(item)
    store.start_run(run_id, cfg.public_record())
    store.upsert_challenge(item.id, item.name, item.category, item.type, item.value)
    store.initialize_control_catalogue(
        run_id,
        [(0, item.id, True)],
        2,
        route,
        assignments,
        {item.id: material},
    )
    store.start_control_wave(run_id, item.id, 0)
    for lane, candidate in enumerate((rejected_crc, non_crc)):
        attempt_id = f"candidate-{lane}"
        store.start_attempt(attempt_id, run_id, item.id, 0, lane, route.model, route.effort)
        store.finish_attempt(
            attempt_id,
            "candidate",
            candidate=candidate,
            retain_private_candidate=True,
        )
        store.record_submission(run_id, item.id, candidate, "incorrect", 200)

    run_root = tmp_path / "run"
    analysis_root = (
        run_root / "challenge-1" / "episode-0" / "generation-0" / "lane-0" / "rapido-analysis"
    )
    analysis_root.mkdir(parents=True)
    safe_files = {
        Path("safe.txt"): b"keep this analysis",
        Path("cafebabe.txt"): b"inner substring was not an exact CRC candidate",
        Path("collision"): b"fresh file wins over a carried descendant",
    }
    shadowed_files = {
        Path("carried/collision/nested.txt"): b"stale descendant",
    }
    blocked_files = {
        Path("exact.txt"): rejected_crc.encode(),
        Path("lower.txt"): b"deadbeef",
        Path("upper.txt"): b"DEADBEEF",
        Path("big-endian.bin"): bytes.fromhex("deadbeef"),
        Path("little-endian.bin"): bytes.fromhex("deadbeef")[::-1],
        Path("deadbeef.txt"): b"safe payload in a rejected-derived path",
        Path(f"nested-{rejected_crc}") / "notes.txt": b"safe payload",
    }
    for relative, payload in {**safe_files, **shadowed_files, **blocked_files}.items():
        path = analysis_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    orchestrator = Orchestrator(cfg, FakeBoard([item]), store, FakeRuntime({}))
    events_before = store._connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    files, retained_bytes, telemetry = orchestrator._capture_analysis_carry(
        run_id, item, 0, run_root, ()
    )

    carry_root = run_root / "challenge-1" / "carry" / material / "lane-0"
    assert files == len(safe_files)
    assert retained_bytes == sum(len(payload) for payload in safe_files.values())
    assert telemetry["drop_counts"]["unsafe"] == len(blocked_files)
    assert telemetry["drop_counts"]["shadowed"] == len(shadowed_files)
    assert {
        path.relative_to(carry_root): path.read_bytes()
        for path in carry_root.rglob("*")
        if path.is_file()
    } == safe_files
    assert store._connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == events_before
    event_payloads = "".join(
        str(row[0])
        for row in store._connection.execute(
            "SELECT data_json FROM events UNION ALL SELECT data_json FROM control_events"
        ).fetchall()
    )
    for candidate in (rejected_crc, non_crc):
        assert candidate not in event_payloads
        assert hashlib.sha256(candidate.encode()).hexdigest() not in event_payloads
    store.close()


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


def test_finding_carry_and_uncensored_tool_count_are_durable_with_capped_wave_detail(
    tmp_path: Path,
) -> None:
    board = FakeBoard([challenge(1)])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(
        Orchestrator(config(tmp_path, submit=False), board, store, ManyToolCallsRuntime({})).run()
    )
    attempts = store.attempts_for_challenge(report.run_id, 1)
    assert len(attempts) == 2
    assert all(row["episode"] == 0 for row in attempts)
    assert all(row["id"].endswith(f":0:{row['lane']}") for row in attempts)
    assert all(row["tool_count"] == 133 for row in attempts)
    assert all(
        json.loads(row["evidence_json"]) == ["archive header verified", "candidate path rejected"]
        for row in attempts
    )
    assert all(
        json.loads(row["next_steps_json"]) == ["inspect the remaining encoded member"]
        for row in attempts
    )
    wave_row = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='attempt_wave'"
    ).fetchone()
    wave = json.loads(wave_row["data_json"])
    assert wave["episode"] == 0
    assert all(item["episode"] == 0 for item in wave["tool_calls"])
    assert all(item["tool_call_count"] == 133 for item in wave["tool_calls"])
    assert all(item["retained_tool_call_count"] == 10 for item in wave["tool_calls"])
    assert all(item["tool_calls_truncated"] is True for item in wave["tool_calls"])
    assert all(len(item["calls"]) == 10 for item in wave["tool_calls"])
    manifests = store._connection.execute(
        """
        SELECT complete, gap, observation_count, committed_count
        FROM evidence_manifests ORDER BY attempt_id
        """
    ).fetchall()
    assert len(manifests) == 2
    assert all(row["complete"] == 0 and row["gap"] == "provenance_incomplete" for row in manifests)
    assert all(
        row["observation_count"] == 133 and row["committed_count"] == 133 for row in manifests
    )
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
    with pytest.raises(BoardError, match="cleanup remained indeterminate"):
        asyncio.run(Orchestrator(cfg, board, store, ReplaceDuringSolveRuntime(board)).run())
    assert board.instance_calls == [("GET", 2), ("POST", 2), ("GET", 2), ("GET", 2)]
    assert board.active_instances[2]["connection_info"] == "http://127.0.0.2:8135/"
    assert store.owned_instances()[0]["status"] == "cleanup_pending"
    event = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='instance_cleanup'"
    ).fetchone()
    assert '"status":"manual_reconciliation_required"' in event["data_json"]
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


@pytest.mark.parametrize(
    ("with_observation", "streamed_only", "streamed_incomplete", "expected_count"),
    (
        (True, False, False, 1),
        (True, True, False, 1),
        (True, True, True, 2),
        (False, False, False, 0),
    ),
)
def test_lane_cancellation_commits_completed_tool_evidence_with_explicit_gap(
    tmp_path: Path,
    with_observation: bool,
    streamed_only: bool,
    streamed_incomplete: bool,
    expected_count: int,
) -> None:
    async def exercise() -> tuple[StateStore, str]:
        cfg = config(tmp_path)
        store = StateStore(cfg.state_path)
        store.start_run("run", cfg.public_record())
        store.upsert_challenge(1, "A", "crypto", "standard", 100)
        workspace = tmp_path / "lane"
        workspace.mkdir()
        runtime = CancelledSolveRuntime(
            with_observation=with_observation,
            streamed_only=streamed_only,
            streamed_incomplete=streamed_incomplete,
        )
        lane = asyncio.create_task(
            Orchestrator(cfg, FakeBoard([challenge(1)]), store, runtime)._lane(
                "run", challenge(1), 0, 0, workspace, [], 10
            )
        )
        await asyncio.wait_for(runtime.solve_started.wait(), 1)
        lane.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lane
        return store, "run:1:0:0"

    store, attempt_id = asyncio.run(exercise())
    attempt = store._connection.execute(
        "SELECT status, tool_count, failure_class FROM attempts WHERE id=?",
        (attempt_id,),
    ).fetchone()
    manifest = store._connection.execute(
        "SELECT complete, gap, observation_count FROM evidence_manifests WHERE attempt_id=?",
        (attempt_id,),
    ).fetchone()
    assert dict(attempt) == {
        "status": "cancelled",
        "tool_count": expected_count,
        "failure_class": "cancelled",
    }
    assert dict(manifest) == {
        "complete": 0,
        "gap": "turn_cancelled",
        "observation_count": int(with_observation),
    }
    if with_observation:
        payload = (
            store._connection.execute(
                """
            SELECT o.payload_json
            FROM evidence_items AS i
            JOIN evidence_manifests AS m
              ON m.run_id=i.run_id AND m.digest=i.manifest_digest
            JOIN evidence_objects AS o
              ON o.run_id=i.run_id AND o.digest=i.object_digest
            WHERE m.attempt_id=?
            """,
                (attempt_id,),
            )
            .fetchone()["payload_json"]
            .decode()
        )
        assert '"format":"ELF"' in payload
    store.close()


def test_repeated_shutdown_cancellation_drains_runtime_before_releasing_leases(
    tmp_path: Path,
) -> None:
    async def scenario() -> tuple[bool, bool]:
        runtime = BlockingCloseRuntime()
        store = StateStore(tmp_path / "state.sqlite3")
        run = asyncio.create_task(
            Orchestrator(config(tmp_path), FakeBoard([]), store, runtime).run()
        )
        await asyncio.wait_for(runtime.close_started.wait(), 1)
        run.cancel()
        await asyncio.sleep(0)
        run.cancel()
        await asyncio.sleep(0)
        retained_while_closing = bool(store._lease_files)
        still_draining = not run.done()
        runtime.release_close.set()
        with pytest.raises(asyncio.CancelledError):
            await run
        assert runtime.closed
        assert not store._lease_files
        store.close()
        return retained_while_closing, still_draining

    assert asyncio.run(scenario()) == (True, True)


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
    item = replace(challenge(1), description="metadata mentions " + answer)
    board = FakeBoard([item])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(
        Orchestrator(
            config(tmp_path, submit=False),
            board,
            store,
            NoProvenanceRuntime({1: {0: answer, 1: answer}}),
        ).run()
    )
    assert report.unsolved == 1
    assert report.errors == 0
    assert board.submissions == []
    failure = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='attempt_failure' ORDER BY sequence LIMIT 1"
    ).fetchone()
    assert '"reason":"candidate_provenance"' in failure["data_json"]
    store.close()


def test_source_observed_candidate_can_equal_visible_board_prose(tmp_path: Path) -> None:
    class PromptCheckingRuntime(FakeRuntime):
        async def solve(self, workspace, prompt, **kwargs):
            candidate = self.candidates[1][json.loads(prompt)["lane"]]
            assert candidate in prompt
            return await super().solve(workspace, prompt, **kwargs)

    answer = "INCYPHER{" + "independently_observed" + "}"
    item = replace(challenge(1), description="metadata mentions " + answer)
    board = FakeBoard([item])
    store = StateStore(tmp_path / "state.sqlite3")

    report = asyncio.run(
        Orchestrator(
            config(tmp_path, submit=False),
            board,
            store,
            PromptCheckingRuntime({1: {0: answer, 1: answer}}),
        ).run()
    )

    assert report.candidates == 1
    assert board.submissions == []
    store.close()


def test_board_description_candidate_correct_skips_lanes_and_is_not_fresh_evidence(
    tmp_path: Path,
) -> None:
    class NoLaneRuntime(FakeRuntime):
        async def solve(self, workspace, prompt, **kwargs):
            raise AssertionError("correct Board-description candidate must skip model lanes")

    answer = "INCYPHER{" + "trusted_board_literal" + "}"
    item = replace(challenge(1), description="metadata mentions " + answer)
    board = FakeBoard([item])
    store = StateStore(tmp_path / "state.sqlite3")

    report = asyncio.run(Orchestrator(config(tmp_path), board, store, NoLaneRuntime({})).run())

    assert report.solved == 1
    assert report.submission_correct == 1
    assert report.board_origin_correct == 1
    assert report.source_observed_correct == 0
    assert report.independently_verified == 0
    assert report.run_local_verified == 0
    assert report.unverified_challenges == 0
    assert len(board.submissions) == 1
    rows = store._connection.execute(
        "SELECT kind, data_json FROM events "
        "WHERE kind IN ('board_description_candidate_selected', 'submission') "
        "ORDER BY sequence"
    ).fetchall()
    assert [row["kind"] for row in rows] == [
        "board_description_candidate_selected",
        "submission",
    ]
    selected, submitted = (json.loads(row["data_json"]) for row in rows)
    assert selected == {
        "candidate_sha256": hashlib.sha256(answer.encode()).hexdigest(),
        "challenge_id": 1,
        "provenance_class": "board_description_candidate",
    }
    assert submitted["provenance_class"] == "board_description_candidate"
    assert submitted["run_local_verified"] is False
    started_initial = store._connection.execute(
        "SELECT COUNT(DISTINCT challenge_id) FROM control_jobs "
        "WHERE run_id=? AND phase='initial' AND started_sequence IS NOT NULL",
        (report.run_id,),
    ).fetchone()[0]
    assert started_initial == 0
    all_events = store._connection.execute("SELECT data_json FROM events").fetchall()
    assert answer not in "".join(row["data_json"] for row in all_events)
    store.close()


def test_wrong_board_description_candidate_retires_then_normal_lanes_solve(
    tmp_path: Path,
) -> None:
    class WrongThenCorrectBoard(FakeBoard):
        def submit(self, challenge_id: int, candidate: str) -> Verdict:
            self.submissions.append((challenge_id, candidate))
            outcome = "incorrect" if len(self.submissions) == 1 else "correct"
            return Verdict(outcome, "ok", 200)

    literal = "INCYPHER{" + "board_decoy" + "}"
    derived = "INCYPHER{" + "source_derived" + "}"
    item = replace(challenge(1), description="metadata mentions " + literal)
    board = WrongThenCorrectBoard([item])
    runtime = FakeRuntime({1: {0: derived, 1: derived}})
    store = StateStore(tmp_path / "state.sqlite3")

    report = asyncio.run(Orchestrator(config(tmp_path), board, store, runtime).run())

    assert report.solved == 1
    assert report.submission_correct == 1
    assert report.submission_incorrect == 1
    assert report.board_origin_correct == 0
    assert report.source_observed_correct == 1
    assert report.run_local_verified == 1
    assert len(runtime.solve_kwargs) == 2
    assert len(board.submissions) == 2
    submissions = [
        json.loads(row["data_json"])
        for row in store._connection.execute(
            "SELECT data_json FROM events WHERE kind='submission' ORDER BY sequence"
        )
    ]
    assert [row["provenance_class"] for row in submissions] == [
        "board_description_candidate",
        "source_observed_candidate",
    ]
    assert [row["run_local_verified"] for row in submissions] == [False, True]
    store.close()


def test_wrong_board_description_candidate_is_not_reselected_on_retry(tmp_path: Path) -> None:
    class WrongBoard(FakeBoard):
        def submit(self, challenge_id: int, candidate: str) -> Verdict:
            self.submissions.append((challenge_id, candidate))
            return Verdict("incorrect", "ok", 200)

    literal = "INCYPHER{" + "retired_board_literal" + "}"
    item = replace(challenge(1), description="metadata mentions " + literal)
    board = WrongBoard([item])
    runtime = FakeRuntime({1: {0: None, 1: None}})
    cfg = replace(config(tmp_path), episodes_per_challenge=2)
    store = StateStore(tmp_path / "state.sqlite3")

    report = asyncio.run(Orchestrator(cfg, board, store, runtime).run())

    assert report.unsolved == 1
    assert len(runtime.solve_kwargs) == 4
    assert len(board.submissions) == 1
    assert (
        store._connection.execute(
            "SELECT COUNT(*) FROM events WHERE kind='board_description_candidate_selected'"
        ).fetchone()[0]
        == 1
    )
    store.close()


@pytest.mark.parametrize(
    "item",
    (
        replace(
            challenge(1),
            description="metadata mentions INCYPHER{capped_literal}",
            max_attempts=3,
        ),
        replace(
            challenge(1),
            description=("metadata mentions INCYPHER{first_literal} and INCYPHER{second_literal}"),
        ),
        replace(
            challenge(1),
            description="metadata mentions INCYPHER{answer}",
        ),
    ),
)
def test_board_description_candidate_skips_capped_multiple_or_placeholder(
    tmp_path: Path,
    item: Challenge,
) -> None:
    board = FakeBoard([item])
    runtime = FakeRuntime({1: {0: None, 1: None}})
    store = StateStore(tmp_path / "state.sqlite3")

    asyncio.run(Orchestrator(config(tmp_path), board, store, runtime).run())

    assert len(runtime.solve_kwargs) == 2
    assert board.submissions == []
    assert (
        store._connection.execute(
            "SELECT COUNT(*) FROM events WHERE kind='board_description_candidate_selected'"
        ).fetchone()[0]
        == 0
    )
    store.close()


def test_board_description_candidate_skips_changed_refresh(tmp_path: Path) -> None:
    class ChangedDescriptionBoard(FakeBoard):
        def challenge(self, challenge_id: int) -> Challenge:
            return replace(super().challenge(challenge_id), description="changed material")

    literal = "INCYPHER{" + "stale_board_literal" + "}"
    item = replace(challenge(1), description="metadata mentions " + literal)
    board = ChangedDescriptionBoard([item])
    runtime = FakeRuntime({1: {0: None, 1: None}})
    store = StateStore(tmp_path / "state.sqlite3")

    asyncio.run(Orchestrator(config(tmp_path), board, store, runtime).run())

    assert len(runtime.solve_kwargs) == 2
    assert board.submissions == []
    assert (
        store._connection.execute(
            "SELECT COUNT(*) FROM events WHERE kind='board_description_candidate_selected'"
        ).fetchone()[0]
        == 0
    )
    store.close()


def test_candidate_rejected_when_committed_observation_is_omitted(tmp_path: Path) -> None:
    class AdaptiveOrchestrator(Orchestrator):
        _adaptive_control = True

    class CompleteEvidenceRuntime(FakeRuntime):
        async def solve(self, workspace, prompt, **kwargs):
            turn = await super().solve(workspace, prompt, **kwargs)
            candidate = json.loads(turn.text)["candidate"]
            fingerprint = hashlib.sha256(candidate.encode()).hexdigest()
            turn.tool_calls[0]["host_observation"] = HostObservation(
                "inspect_file",
                True,
                True,
                candidate_sha256s=(fingerprint,),
            )
            return turn

    answer = "INCYPHER{omitted_after_normalization}"
    cfg = config(tmp_path)
    store = StateStore(cfg.state_path)
    run_id = "omitted-proof-run"
    route = baseline_route(model=cfg.model, effort=cfg.reasoning_effort, attempt_seconds=15)
    store.start_run(run_id, cfg.public_record())
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue(run_id, [(0, 1, True)])
    store.admit_control_wave(run_id, 1, 0, 0, 1, route)
    store.start_control_wave(run_id, 1, 0)
    workspace = tmp_path / "lane"
    workspace.mkdir()
    orchestrator = AdaptiveOrchestrator(
        cfg, FakeBoard([challenge(1)]), store, CompleteEvidenceRuntime({1: {0: answer}})
    )
    orchestrator._run_evidence = RunEvidence.open(
        store,
        run_id,
        EvidenceLimits(max_object_bytes=1),
    )

    result = asyncio.run(
        orchestrator._lane(
            run_id,
            challenge(1),
            0,
            0,
            workspace,
            [],
            10,
            route=route,
        )
    )

    assert result.terminal_status == "unsolved"
    assert store.candidate_counts(run_id) == (0, 0)
    manifest = store._connection.execute(
        "SELECT complete, gap, omitted_count FROM evidence_manifests WHERE attempt_id=?",
        (f"{run_id}:1:0:0",),
    ).fetchone()
    assert tuple(manifest) == (0, "quota_omitted", 1)
    store.close()


def test_shell_only_candidate_is_retained_and_immediately_offered_to_unlimited_submitter(
    tmp_path: Path,
) -> None:
    class AdaptiveOrchestrator(Orchestrator):
        _adaptive_control = True

    class ShellEvidenceRuntime(FakeRuntime):
        async def solve(self, workspace, prompt, **kwargs):
            turn = await super().solve(workspace, prompt, **kwargs)
            candidate = json.loads(turn.text)["candidate"]
            fingerprint = hashlib.sha256(candidate.encode()).hexdigest()
            turn.tool_calls[0] = {
                "name": "run_shell",
                "success": True,
                "source_bound": True,
                "candidate_sha256s": [fingerprint],
                "host_observation": HostObservation(
                    "run_shell",
                    True,
                    True,
                    candidate_sha256s=(fingerprint,),
                ),
            }
            return turn

    answer = "INCYPHER{shell_requires_fresh_verifier}"
    cfg = config(tmp_path)
    store = StateStore(cfg.state_path)
    run_id = "shell-proof-run"
    route = baseline_route(model=cfg.model, effort=cfg.reasoning_effort, attempt_seconds=15)
    store.start_run(run_id, cfg.public_record())
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue(run_id, [(0, 1, True)])
    store.admit_control_wave(run_id, 1, 0, 0, 1, route)
    store.start_control_wave(run_id, 1, 0)
    workspace = tmp_path / "lane"
    workspace.mkdir()
    submitted: list[str] = []

    async def submit(candidate: str) -> str:
        submitted.append(candidate)
        return "solved"

    result = asyncio.run(
        AdaptiveOrchestrator(
            cfg, FakeBoard([challenge(1)]), store, ShellEvidenceRuntime({1: {0: answer}})
        )._lane(
            run_id,
            challenge(1),
            0,
            0,
            workspace,
            [],
            10,
            route=route,
            candidate_submitter=submit,
        )
    )

    assert result.terminal_status == "candidate"
    assert result.submission_status == "solved"
    assert submitted == [answer]
    assert store.candidate_counts(run_id) == (1, 0)
    store.close()


def test_candidate_after_133_tools_keeps_complete_proof_and_terminalizes(tmp_path: Path) -> None:
    class AdaptiveOrchestrator(Orchestrator):
        _adaptive_control = True

    class LongEvidenceRuntime(FakeRuntime):
        async def solve(self, workspace, prompt, **kwargs):
            turn = await super().solve(workspace, prompt, **kwargs)
            candidate = json.loads(turn.text)["candidate"]
            fingerprint = hashlib.sha256(candidate.encode()).hexdigest()
            ordinary_observation = HostObservation("inspect_file", True, True)
            ordinary = {
                "name": "inspect_file",
                "success": True,
                "source_bound": True,
                "candidate_sha256s": [],
                "host_observation": ordinary_observation,
            }
            candidate_observation = HostObservation(
                "inspect_file", True, True, candidate_sha256s=(fingerprint,)
            )
            final_call = {
                "name": "inspect_file",
                "success": True,
                "source_bound": True,
                "candidate_sha256s": [fingerprint],
                "host_observation": candidate_observation,
            }
            turn.tool_calls = [dict(ordinary) for _ in range(132)] + [final_call]
            turn.current_turn_tool_calls = [final_call]
            return turn

    answer = "INCYPHER{long_horizon_source_proof}"
    cfg = config(tmp_path)
    store = StateStore(cfg.state_path)
    run_id = "long-horizon-proof-run"
    route = baseline_route(model=cfg.model, effort=cfg.reasoning_effort, attempt_seconds=15)
    store.start_run(run_id, cfg.public_record())
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue(run_id, [(0, 1, True)])
    store.admit_control_wave(run_id, 1, 0, 0, 1, route)
    store.start_control_wave(run_id, 1, 0)
    workspace = tmp_path / "lane"
    workspace.mkdir()
    submitted: list[str] = []

    async def submit(candidate: str) -> str:
        submitted.append(candidate)
        return "solved"

    orchestrator = AdaptiveOrchestrator(
        cfg, FakeBoard([challenge(1)]), store, LongEvidenceRuntime({1: {0: answer}})
    )
    orchestrator._run_evidence = RunEvidence.open(store, run_id)
    result = asyncio.run(
        orchestrator._lane(
            run_id,
            challenge(1),
            0,
            0,
            workspace,
            [],
            10,
            route=route,
            candidate_submitter=submit,
        )
    )

    assert result.terminal_status == "candidate"
    assert result.tool_call_count == 133
    assert result.submission_status == "solved"
    assert submitted == [answer]
    attempt = store._connection.execute(
        "SELECT status, tool_count FROM attempts WHERE id=?", (f"{run_id}:1:0:0",)
    ).fetchone()
    manifest = store._connection.execute(
        "SELECT complete, observation_count, committed_count, omitted_count "
        "FROM evidence_manifests WHERE attempt_id=?",
        (f"{run_id}:1:0:0",),
    ).fetchone()
    assert tuple(attempt) == ("candidate", 133)
    assert tuple(manifest) == (1, 133, 133, 0)
    assert store.candidate_counts(run_id) == (1, 0)
    store.close()


def test_verifier_shell_only_candidate_reports_fixed_observation_requirement(
    tmp_path: Path,
) -> None:
    class AdaptiveOrchestrator(Orchestrator):
        _adaptive_control = True

    class ShellEvidenceRuntime(FakeRuntime):
        async def solve(self, workspace, prompt, **kwargs):
            turn = await super().solve(workspace, prompt, **kwargs)
            candidate = json.loads(turn.text)["candidate"]
            fingerprint = hashlib.sha256(candidate.encode()).hexdigest()
            turn.tool_calls[0] = {
                "name": "run_shell",
                "success": True,
                "source_bound": True,
                "candidate_sha256s": [fingerprint],
                "host_observation": HostObservation(
                    "run_shell",
                    True,
                    True,
                    candidate_sha256s=(fingerprint,),
                ),
            }
            return turn

    answer = "INCYPHER{verifier_needs_fixed_observation}"
    cfg = config(tmp_path)
    store = StateStore(cfg.state_path)
    run_id = "verifier-shell-proof-run"
    route = replace(
        baseline_route(model=cfg.model, effort=cfg.reasoning_effort, attempt_seconds=15),
        role="verifier",
        tactic="independent_source_reobservation",
        context_profile="fresh_source_only_no_candidate_carry",
        verification_recipe="fresh_source_reobservation_v1",
    )
    store.start_run(run_id, cfg.public_record())
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.record_control_catalogue(run_id, [(0, 1, True)])
    store.admit_control_wave(run_id, 1, 0, 0, 1, route)
    store.start_control_wave(run_id, 1, 0)
    workspace = tmp_path / "lane"
    workspace.mkdir()

    result = asyncio.run(
        AdaptiveOrchestrator(
            cfg, FakeBoard([challenge(1)]), store, ShellEvidenceRuntime({1: {0: answer}})
        )._lane(
            run_id,
            challenge(1),
            0,
            0,
            workspace,
            [],
            10,
            route=route,
        )
    )

    assert result.terminal_status == "unsolved"
    failure = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='attempt_failure' ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    assert '"reason":"candidate_provenance"' in failure["data_json"]
    assert '"subreason":"verifier_requires_fixed_observation"' in failure["data_json"]
    store.close()


def test_malformed_model_text_terminalizes_every_attempt(tmp_path: Path) -> None:
    answer = "INCYPHER{fabricated}"
    board = FakeBoard([challenge(1)])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(
        Orchestrator(
            config(tmp_path),
            board,
            store,
            MalformedEvidenceRuntime({1: {0: answer, 1: answer}}),
        ).run()
    )
    assert report.errors == 1
    assert store.active_attempts() == []
    attempts = store.attempts_for_challenge(report.run_id, 1)
    assert all(row["status"] == "failed" for row in attempts)
    assert all(row["failure_class"] == "solver_output" for row in attempts)
    failures = [
        json.loads(row["data_json"])
        for row in store._connection.execute(
            "SELECT data_json FROM events WHERE kind='attempt_failure' ORDER BY sequence"
        )
    ]
    assert {failure["subreason"] for failure in failures} == {"evidence"}
    store.close()


def test_restart_seals_interrupted_attempt_as_explicit_unavailable_evidence(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    store = StateStore(cfg.state_path)
    store.start_run("old-run", cfg.public_record())
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.start_attempt("old-attempt", "old-run", 1, 0, 0, cfg.model, cfg.reasoning_effort)

    report = asyncio.run(Orchestrator(cfg, FakeBoard([challenge(2)]), store, FakeRuntime({})).run())
    manifest = store._connection.execute(
        "SELECT complete, gap, observation_count FROM evidence_manifests WHERE attempt_id=?",
        ("old-attempt",),
    ).fetchone()
    assert report.status == "completed"
    assert dict(manifest) == {
        "complete": 0,
        "gap": "process_interrupted",
        "observation_count": 0,
    }
    store.close()


def test_restart_reconciles_changed_material_before_resuming_interrupted_wave(
    tmp_path: Path,
) -> None:
    class AdaptiveOrchestrator(Orchestrator):
        _adaptive_control = True

        async def _wait_for_catalogue_revision(self, *args, **kwargs):
            return None

    previous = challenge(1)
    current = replace(previous, description="changed solver material")
    cfg = replace(
        config(tmp_path, submit=False),
        active_challenges=1,
        attempts_per_challenge=1,
        concurrency=1,
        watch_board=True,
    )
    store = StateStore(cfg.state_path)
    run_id = "material-recovery-run"
    route = baseline_route(model=cfg.model, effort=cfg.reasoning_effort, attempt_seconds=15)
    orchestrator = AdaptiveOrchestrator(cfg, FakeBoard([current]), store, FakeRuntime({}))
    store.start_run(run_id, cfg.public_record())
    store.upsert_challenge(
        previous.id,
        previous.name,
        previous.category,
        previous.type,
        previous.value,
    )
    store.initialize_control_catalogue(
        run_id,
        [(0, previous.id, True)],
        1,
        route,
        orchestrator._initial_peer_assignments(),
        {previous.id: orchestrator_module._challenge_material_sha256(previous)},
    )
    store.start_control_wave(run_id, previous.id, 0)
    original_resume = store.resume_control_waves
    resume_observations: list[tuple[str, tuple[int, ...]]] = []

    def observe_resume(active_run_id: str, remaining_milliseconds: int) -> int:
        resume_observations.append(
            (
                store.control_catalogue_contexts(active_run_id)[previous.id],
                tuple(wave.episode for wave in store.queued_control_waves(active_run_id)),
            )
        )
        return original_resume(active_run_id, remaining_milliseconds)

    store.resume_control_waves = observe_resume  # type: ignore[method-assign]

    report = asyncio.run(orchestrator.run())

    current_context = orchestrator_module._challenge_material_sha256(current)
    assert report.status == "completed"
    assert resume_observations == [(current_context, (1,))]
    assert store.control_catalogue_context_episode(run_id, previous.id) == 1
    assert (
        store._connection.execute(
            "SELECT COUNT(*) FROM control_route_decisions WHERE run_id=? AND source_episode=0",
            (run_id,),
        ).fetchone()[0]
        == 0
    )
    store.close()


def test_oversized_prior_attempt_is_compacted_before_successor(tmp_path: Path) -> None:
    board = FakeBoard([challenge(1)])
    runtime = FakeRuntime({1: {0: None}})
    store = StateStore(tmp_path / "state.sqlite3")
    store.start_run("run-1", {})
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    store.start_attempt("attempt-0", "run-1", 1, 0, 0, "model", "high")
    store.finish_attempt("attempt-0", "unsolved", summary="x" * 4000)
    workspace = tmp_path / "lane"
    workspace.mkdir()

    result = asyncio.run(
        Orchestrator(config(tmp_path), board, store, runtime)._lane(
            "run-1", challenge(1), 1, 0, workspace, [], 10
        )
    )
    assert result.terminal_status == "unsolved"
    assert store.active_attempts() == []
    event = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='attempt_carry_sanitized'"
    ).fetchone()
    assert json.loads(event["data_json"])["compacted_records"] == 1
    store.close()


def test_adaptive_memory_is_verified_before_attempt_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class AdaptiveOrchestrator(Orchestrator):
        _adaptive_control = True

    cfg = config(tmp_path)
    store = StateStore(cfg.state_path)
    store.start_run("run-1", cfg.public_record())
    store.upsert_challenge(1, "A", "crypto", "standard", 100)
    workspace = tmp_path / "lane"
    workspace.mkdir()
    orchestrator = AdaptiveOrchestrator(cfg, FakeBoard([challenge(1)]), store, FakeRuntime({}))

    def reject_memory(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise EvidenceError("prior memory failed verification")

    monkeypatch.setattr(orchestrator, "_typed_same_run_memory", reject_memory)
    route = baseline_route(model=cfg.model, effort=cfg.reasoning_effort, attempt_seconds=15)
    with pytest.raises(EvidenceError, match="prior memory failed verification"):
        asyncio.run(orchestrator._lane("run-1", challenge(1), 1, 0, workspace, [], 10, route=route))
    assert store._connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0
    store.close()


def test_failed_native_turn_persists_closed_class_and_tool_evidence(tmp_path: Path) -> None:
    board = FakeBoard([challenge(1)])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(
        Orchestrator(
            config(tmp_path),
            board,
            store,
            FailedTurnRuntime({1: {0: None, 1: None}}),
        ).run()
    )
    assert report.errors == 1
    failures = [
        row["data_json"]
        for row in store._connection.execute(
            "SELECT data_json FROM events WHERE kind='attempt_failure' ORDER BY sequence"
        )
    ]
    assert len(failures) == 2
    assert all('"reason":"native_turn_incomplete"' in event for event in failures)
    assert all('"status":"failed"' in event for event in failures)
    assert all('"failure_class":"usage_limit_exceeded"' in event for event in failures)
    attempts = store.attempts_for_challenge(report.run_id, 1)
    assert all(row["failure_class"] == "usage_limit_exceeded" for row in attempts)
    assert all(row["tool_count"] == 2 for row in attempts)
    wave = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='attempt_wave'"
    ).fetchone()
    assert "inspect_file" in wave["data_json"]
    assert "unknown_tool" in wave["data_json"]
    assert "sensitive-model-tool-name-sentinel" not in wave["data_json"]
    store.close()


def test_candidate_rejects_model_supplied_value_reflected_by_tool(tmp_path: Path) -> None:
    answer = "INCYPHER{reflected_input}"
    item = replace(challenge(1), description="metadata mentions " + answer)
    board = FakeBoard([item])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(
        Orchestrator(
            config(tmp_path, submit=False),
            board,
            store,
            ReflectedCandidateRuntime({1: {0: answer, 1: answer}}),
        ).run()
    )
    assert report.unsolved == 1
    assert report.errors == 0
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


def test_transient_identity_transport_is_retried_without_operator_restart(tmp_path: Path) -> None:
    board = FlakyIdentityBoard([challenge(1)])
    store = StateStore(tmp_path / "state.sqlite3")
    report = asyncio.run(Orchestrator(config(tmp_path), board, store, FakeRuntime({})).run())
    assert report.status == "completed"
    assert board.identity_calls == 4
    store.close()


def test_board_read_transport_retry_is_bounded_to_three_attempts(tmp_path: Path) -> None:
    board = AlwaysFailingIdentityBoard(
        [challenge(1)], BoardTransportError("Board transport failed")
    )
    store = StateStore(tmp_path / "state.sqlite3")
    with pytest.raises(BoardTransportError):
        asyncio.run(Orchestrator(config(tmp_path), board, store, FakeRuntime({})).run())
    assert board.identity_calls == 3
    store.close()


def test_semantic_board_error_is_not_retried(tmp_path: Path) -> None:
    board = AlwaysFailingIdentityBoard([challenge(1)], BoardError("invalid response"))
    store = StateStore(tmp_path / "state.sqlite3")
    with pytest.raises(BoardError, match="invalid response"):
        asyncio.run(Orchestrator(config(tmp_path), board, store, FakeRuntime({})).run())
    assert board.identity_calls == 1
    store.close()


def test_active_watch_transport_outage_restarts_pair_without_cancelling_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator_module, "MIN_MEANINGFUL_ATTEMPT_SECONDS", 0.01)
    monkeypatch.setattr(
        orchestrator_module, "_BOARD_READ_RETRY_DELAYS", (0.001, 0.002), raising=False
    )
    real_time = orchestrator_module.time

    class ControlledClock:
        expired = False

        def monotonic(self) -> float:
            return real_time.monotonic() + (120 if self.expired else 0)

        def __getattr__(self, name: str):
            return getattr(real_time, name)

    clock = ControlledClock()
    monkeypatch.setattr(orchestrator_module, "time", clock)

    class CoordinatedWatchBoard(RecoveringWatchBoard):
        def __init__(self) -> None:
            super().__init__([challenge(1)], {5, 6, 7})
            self.solve_started = threading.Event()

        def list_challenges(self):
            if self.list_calls + 1 == 5:
                assert self.solve_started.wait(timeout=1)
            return super().list_challenges()

    board = CoordinatedWatchBoard()
    cfg = replace(
        config(tmp_path, submit=False),
        active_challenges=1,
        attempts_per_challenge=1,
        concurrency=1,
        attempt_seconds=1,
        run_seconds=60,
        watch_board=True,
        board_watch_seconds=0.001,
        board_full_refresh_seconds=0.02,
    )

    async def exercise_watch_recovery():
        recovered = asyncio.Event()

        class ExpireAfterWatchRecovery(FakeRuntime):
            def __init__(self) -> None:
                super().__init__({})
                self.entries = 0
                self.cancellations = 0
                self.in_solve = False
                self.recovered_while_solving = False

            async def solve(self, workspace, prompt, **kwargs):
                self.entries += 1
                self.in_solve = True
                board.solve_started.set()
                try:
                    await recovered.wait()
                    self.recovered_while_solving = True
                    result = await super().solve(workspace, prompt, **kwargs)
                    clock.expired = True
                    return result
                except asyncio.CancelledError:
                    self.cancellations += 1
                    raise
                finally:
                    self.in_solve = False

        runtime = ExpireAfterWatchRecovery()

        class AdaptiveOrchestrator(Orchestrator):
            _adaptive_control = True

            def __init__(self, *args, **kwargs) -> None:
                super().__init__(*args, **kwargs)
                self.outage_saw_active_solve = False

            def _record_board_watch_transport_outage(self, *args, **kwargs):
                self.outage_saw_active_solve = runtime.in_solve
                return super()._record_board_watch_transport_outage(*args, **kwargs)

            def _record_board_watch_transport_recovered(self, *args, **kwargs):
                result = super()._record_board_watch_transport_recovered(*args, **kwargs)
                if kwargs["consecutive_failures"]:
                    recovered.set()
                return result

        store = StateStore(cfg.state_path)
        orchestrator = AdaptiveOrchestrator(cfg, board, store, runtime)
        report = await asyncio.wait_for(orchestrator.run(), timeout=2)
        return report, runtime, orchestrator, store

    report, runtime, orchestrator, store = asyncio.run(exercise_watch_recovery())

    assert report.status == "deadline"
    assert board.list_calls >= 9
    assert orchestrator.outage_saw_active_solve
    assert runtime.recovered_while_solving
    assert runtime.entries == 1
    assert runtime.cancellations == 0
    assert len(runtime.solve_kwargs) == 1
    rows = store._connection.execute(
        "SELECT kind, data_json FROM events "
        "WHERE kind LIKE 'board_watch_transport_%' ORDER BY sequence"
    ).fetchall()
    assert [row["kind"] for row in rows] == [
        "board_watch_transport_outage",
        "board_watch_transport_recovered",
    ]
    outage, recovered = (json.loads(row["data_json"]) for row in rows)
    assert outage == {
        "consecutive_failures": 1,
        "next_delay_milliseconds": 2,
        "operation": "catalogue_cycle",
        "watcher": "active",
    }
    assert recovered == {
        "consecutive_failures": 1,
        "operation": "catalogue_cycle",
        "watcher": "active",
    }
    store.close()


def test_active_watch_retries_whole_new_id_refresh_after_detail_and_material_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class AdaptiveOrchestrator(Orchestrator):
        _adaptive_control = True

    class GrowingRefreshTransportBoard(FakeBoard):
        timeout = 0.001

        def __init__(self) -> None:
            super().__init__([challenge(1)])
            self.appended = challenge(2, files=("/files/new-material",))
            self.appended_detail_calls = 0
            self.download_list_counts: list[int] = []
            self.list_calls = 0

        def list_challenges(self):
            self.list_calls += 1
            if self.list_calls >= 4:
                self.challenges[self.appended.id] = self.appended
            return super().list_challenges()

        def challenge(self, challenge_id: int) -> Challenge:
            if challenge_id == self.appended.id:
                self.appended_detail_calls += 1
                if self.appended_detail_calls <= 3:
                    raise BoardTransportError("Board transport failed")
            return super().challenge(challenge_id)

        def download(self, file_ref: str, destination: Path, *, byte_limit: int):
            self.download_list_counts.append(self.list_calls)
            if len(self.download_list_counts) == 1:
                raise BoardTransportError("Board transport failed")
            return super().download(file_ref, destination, byte_limit=byte_limit)

    class HoldAppendedWork(FakeRuntime):
        def __init__(self) -> None:
            super().__init__({})
            self.challenge_ids: list[int] = []
            self.appended_started = asyncio.Event()
            self.release_appended = asyncio.Event()

        async def solve(self, workspace, prompt, **kwargs):
            challenge_id = json.loads(prompt)["challenge"]["id"]
            self.challenge_ids.append(challenge_id)
            if challenge_id == 2:
                self.appended_started.set()
                await self.release_appended.wait()
            return await super().solve(workspace, prompt, **kwargs)

    monkeypatch.setattr(orchestrator_module, "MIN_MEANINGFUL_ATTEMPT_SECONDS", 0.01)
    monkeypatch.setattr(
        orchestrator_module, "_BOARD_READ_RETRY_DELAYS", (0.001, 0.002), raising=False
    )
    board = GrowingRefreshTransportBoard()
    runtime = HoldAppendedWork()
    cfg = replace(
        config(tmp_path, submit=False),
        active_challenges=2,
        attempts_per_challenge=1,
        concurrency=2,
        attempt_seconds=1,
        run_seconds=60,
        watch_board=True,
        board_watch_seconds=0.001,
        board_full_refresh_seconds=0.02,
    )
    store = StateStore(cfg.state_path)

    async def observe_refresh_recovery() -> None:
        task = asyncio.create_task(AdaptiveOrchestrator(cfg, board, store, runtime).run())
        try:
            await asyncio.wait_for(runtime.appended_started.wait(), timeout=5)
        finally:
            task.cancel()
            result = await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), timeout=2)
            assert isinstance(result[0], asyncio.CancelledError)

    asyncio.run(observe_refresh_recovery())

    assert (
        store._connection.execute("SELECT status FROM runs").fetchone()["status"] == "interrupted"
    )
    assert board.appended_detail_calls >= 7
    assert board.download_list_counts[:2] == [12, 17]
    assert 2 in runtime.challenge_ids
    rows = store._connection.execute(
        "SELECT kind, data_json FROM events "
        "WHERE kind LIKE 'board_watch_transport_%' ORDER BY sequence"
    ).fetchall()
    assert [row["kind"] for row in rows] == [
        "board_watch_transport_outage",
        "board_watch_transport_outage",
        "board_watch_transport_recovered",
    ]
    assert [json.loads(row["data_json"])["consecutive_failures"] for row in rows] == [
        1,
        2,
        2,
    ]
    assert all(json.loads(row["data_json"])["operation"] == "catalogue_cycle" for row in rows)
    store.close()


def test_idle_watch_transport_outage_restarts_pair_and_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        orchestrator_module, "_BOARD_READ_RETRY_DELAYS", (0.001, 0.002), raising=False
    )
    board = RecoveringWatchBoard([challenge(1)], {2, 3, 4})
    cfg = replace(
        config(tmp_path, submit=False),
        watch_board=True,
        board_watch_seconds=0.001,
        board_full_refresh_seconds=1.0,
    )
    store = StateStore(cfg.state_path)
    store.start_run("run-1", cfg.public_record())
    run_root = tmp_path / "run"
    run_root.mkdir()
    orchestrator = Orchestrator(cfg, board, store, FakeRuntime({}))

    result = asyncio.run(
        orchestrator._wait_for_catalogue_revision(
            "run-1",
            run_root,
            time.monotonic() + 0.2,
            (1, 2),
            [challenge(1)],
        )
    )

    assert result is None
    assert board.list_calls >= 6
    rows = store._connection.execute(
        "SELECT kind, data_json FROM events "
        "WHERE kind LIKE 'board_watch_transport_%' ORDER BY sequence"
    ).fetchall()
    assert [row["kind"] for row in rows] == [
        "board_watch_transport_outage",
        "board_watch_transport_recovered",
    ]
    assert json.loads(rows[0]["data_json"])["watcher"] == "idle"
    assert json.loads(rows[1]["data_json"])["watcher"] == "idle"
    store.close()


def test_idle_watch_retries_whole_cycle_after_identity_transport_outage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class RecoveringIdentityBoard(FakeBoard):
        timeout = 0.001

        def __init__(self) -> None:
            super().__init__([challenge(1)])
            self.identity_calls = 0
            self.list_calls = 0

        def list_challenges(self):
            self.list_calls += 1
            return super().list_challenges()

        def identity(self):
            self.identity_calls += 1
            if self.identity_calls <= 3:
                raise BoardTransportError("Board transport failed")
            return super().identity()

    monkeypatch.setattr(
        orchestrator_module, "_BOARD_READ_RETRY_DELAYS", (0.001, 0.002), raising=False
    )
    board = RecoveringIdentityBoard()
    cfg = replace(
        config(tmp_path, submit=False),
        watch_board=True,
        board_watch_seconds=0.001,
        board_full_refresh_seconds=1.0,
    )
    store = StateStore(cfg.state_path)
    store.start_run("run-1", cfg.public_record())
    run_root = tmp_path / "run"
    run_root.mkdir()

    result = asyncio.run(
        Orchestrator(cfg, board, store, FakeRuntime({}))._wait_for_catalogue_revision(
            "run-1",
            run_root,
            time.monotonic() + 0.2,
            (1, 2),
            [challenge(1)],
        )
    )

    assert result is None
    assert board.identity_calls >= 4
    assert board.list_calls >= 4
    rows = store._connection.execute(
        "SELECT kind, data_json FROM events "
        "WHERE kind LIKE 'board_watch_transport_%' ORDER BY sequence"
    ).fetchall()
    assert [row["kind"] for row in rows] == [
        "board_watch_transport_outage",
        "board_watch_transport_recovered",
    ]
    assert json.loads(rows[0]["data_json"])["operation"] == "catalogue_cycle"
    assert json.loads(rows[1]["data_json"])["operation"] == "catalogue_cycle"
    store.close()


def test_idle_watch_retries_whole_cycle_after_material_refresh_transport_outage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class RecoveringMaterialBoard(FakeBoard):
        timeout = 0.001

        def __init__(self, item: Challenge) -> None:
            super().__init__([item])
            self.download_calls = 0
            self.identity_calls = 0
            self.list_calls = 0

        def list_challenges(self):
            self.list_calls += 1
            return super().list_challenges()

        def identity(self):
            self.identity_calls += 1
            return super().identity()

        def download(self, file_ref: str, destination: Path, *, byte_limit: int):
            self.download_calls += 1
            if self.download_calls == 1:
                raise BoardTransportError("Board transport failed")
            return super().download(file_ref, destination, byte_limit=byte_limit)

    monkeypatch.setattr(
        orchestrator_module, "_BOARD_READ_RETRY_DELAYS", (0.001, 0.002), raising=False
    )
    item = challenge(1, files=("/files/material",))
    board = RecoveringMaterialBoard(item)
    cfg = replace(
        config(tmp_path, submit=False),
        attempts_per_challenge=1,
        watch_board=True,
        board_watch_seconds=0.001,
        board_full_refresh_seconds=0.001,
    )
    store = StateStore(cfg.state_path)
    store.start_run("run-1", cfg.public_record())
    store.upsert_challenge(item.id, item.name, item.category, item.type, item.value)
    orchestrator = Orchestrator(cfg, board, store, FakeRuntime({}))
    store.initialize_control_catalogue(
        "run-1",
        [(0, item.id, True)],
        1,
        baseline_route(model=cfg.model, effort=cfg.reasoning_effort, attempt_seconds=15),
        orchestrator._initial_peer_assignments(),
        {item.id: orchestrator_module._challenge_material_sha256(item)},
    )
    run_root = tmp_path / "run"
    run_root.mkdir()

    result = asyncio.run(
        orchestrator._wait_for_catalogue_revision(
            "run-1",
            run_root,
            time.monotonic() + 0.2,
            (1, 2),
            [item],
        )
    )

    assert result is not None
    assert board.download_calls == 2
    assert board.list_calls == 10
    assert board.identity_calls == 4
    rows = store._connection.execute(
        "SELECT kind, data_json FROM events "
        "WHERE kind LIKE 'board_watch_transport_%' ORDER BY sequence"
    ).fetchall()
    assert [row["kind"] for row in rows] == [
        "board_watch_transport_outage",
        "board_watch_transport_recovered",
    ]
    assert json.loads(rows[0]["data_json"])["operation"] == "catalogue_cycle"
    assert json.loads(rows[1]["data_json"])["operation"] == "catalogue_cycle"
    store.close()


def test_active_watch_semantic_board_error_still_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class AdaptiveOrchestrator(Orchestrator):
        _adaptive_control = True

    class SemanticWatchBoard(FakeBoard):
        timeout = 0.001

        def __init__(self) -> None:
            super().__init__([challenge(1)])
            self.list_calls = 0

        def list_challenges(self):
            self.list_calls += 1
            if self.list_calls >= 4:
                raise BoardError("semantic watch failure")
            return super().list_challenges()

    monkeypatch.setattr(orchestrator_module, "MIN_MEANINGFUL_ATTEMPT_SECONDS", 0.01)
    monkeypatch.setattr(orchestrator_module, "_BOARD_READ_RETRY_DELAYS", (0.001, 0.002))
    board = SemanticWatchBoard()
    cfg = replace(
        config(tmp_path, submit=False),
        active_challenges=1,
        attempts_per_challenge=1,
        concurrency=1,
        attempt_seconds=1,
        run_seconds=0.3,
        watch_board=True,
        board_watch_seconds=0.001,
    )
    store = StateStore(cfg.state_path)

    with pytest.raises(BoardError, match="semantic watch failure"):
        asyncio.run(AdaptiveOrchestrator(cfg, board, store, FakeRuntime({})).run())

    assert store._connection.execute("SELECT status FROM runs").fetchone()["status"] == "failed"
    assert (
        store._connection.execute(
            "SELECT COUNT(*) FROM events WHERE kind LIKE 'board_watch_transport_%'"
        ).fetchone()[0]
        == 0
    )
    store.close()


def test_instance_create_transport_is_never_retried(tmp_path: Path) -> None:
    board = FlakyCreateTransportBoard([challenge(2, challenge_type="dynamic_iac")])
    store = StateStore(tmp_path / "state.sqlite3")
    cfg = replace(config(tmp_path), manage_dynamic_instances=True)
    report = asyncio.run(Orchestrator(cfg, board, store, FakeRuntime({})).run())
    assert report.errors == 1
    assert board.post_calls == 1
    store.close()


def test_dynamic_readiness_retry_uses_the_120_second_deadline(tmp_path: Path) -> None:
    class RecordingOrchestrator(Orchestrator):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self.instance_get_deadlines: list[float] = []

        async def _board_read(self, deadline, function, /, *args, **kwargs):
            if getattr(function, "__name__", "") == "instance" and args[:1] == ("GET",):
                self.instance_get_deadlines.append(deadline)
            return await super()._board_read(deadline, function, *args, **kwargs)

    board = FakeBoard([challenge(2, challenge_type="dynamic_iac")])
    store = StateStore(tmp_path / "state.sqlite3")
    cfg = replace(config(tmp_path), manage_dynamic_instances=True, run_seconds=300)
    orchestrator = RecordingOrchestrator(cfg, board, store, FakeRuntime({}))
    report = asyncio.run(orchestrator.run())
    assert report.status == "completed"
    preflight_deadline, readiness_deadline = orchestrator.instance_get_deadlines[:2]
    assert preflight_deadline - readiness_deadline > 150
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
    with pytest.raises(BoardError, match="cleanup remains indeterminate"):
        asyncio.run(Orchestrator(cfg, board, store, FakeRuntime({})).run())
    assert board.instance_calls == [("GET", 9)]
    assert store.owned_instances()[0]["status"] == "cleanup_pending"
    event = store._connection.execute(
        "SELECT data_json FROM events WHERE kind='instance_cleanup'"
    ).fetchone()
    assert '"status":"manual_reconciliation_required"' in event["data_json"]
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
    with pytest.raises(BoardError, match="cleanup remains indeterminate"):
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
    with pytest.raises(BoardError, match="cleanup remains indeterminate"):
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
