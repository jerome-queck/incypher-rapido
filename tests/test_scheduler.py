from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections import Counter
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from rapido.board import Challenge, Verdict
from rapido.config import RuntimeConfig
from rapido.orchestrator import Orchestrator
from rapido.state import StateStore


def challenge(
    challenge_id: int,
    *,
    solved: bool = False,
    challenge_type: str = "standard",
) -> Challenge:
    return Challenge(
        challenge_id,
        f"Challenge {challenge_id}",
        "crypto",
        challenge_type,
        "derive the value",
        100,
        (),
        solved,
        0,
        0,
        None,
        None,
    )


def config(tmp_path: Path, **changes: object) -> RuntimeConfig:
    (tmp_path / "auth").mkdir(exist_ok=True)
    base = RuntimeConfig.from_env(
        {
            "RAPIDO_STATE_PATH": str(tmp_path / "state.sqlite3"),
            "RAPIDO_WORK_ROOT": str(tmp_path / "work"),
            "RAPIDO_CODEX_HOME": str(tmp_path / "auth"),
            "RAPIDO_ACTIVE_CHALLENGES": "2",
            "RAPIDO_EPISODES_PER_CHALLENGE": "1",
            "RAPIDO_DYNAMIC_CONCURRENCY": "1",
            "RAPIDO_CONCURRENCY": "4",
            "RAPIDO_ATTEMPTS_PER_CHALLENGE": "2",
            "RAPIDO_SUBMIT_CANDIDATES": "false",
            "RAPIDO_PEER_PROFILE": "uniform_v1",
            "RAPIDO_MEMORY_ARM": "lane_local_v1",
        }
    )
    overrides = {"run_seconds": 60, "attempt_seconds": 15, **changes}
    return replace(base, **overrides)


class OfflineBoard:
    timeout = 0.01

    def __init__(self, challenges: list[Challenge], *, outcome: str = "correct") -> None:
        self.challenges = {item.id: item for item in challenges}
        self.outcome = outcome
        self.submissions: list[tuple[int, str]] = []
        self.instance_calls: list[tuple[str, int]] = []
        self.active_instances: dict[int, dict[str, object]] = {}
        self.max_active_instances = 0
        self.second_instance_active = threading.Event()
        self._lock = threading.Lock()

    def anonymous_identity_is_rejected(self) -> bool:
        return True

    def identity(self) -> dict[str, int]:
        return {"id": 1, "team_id": 2}

    def list_challenges(self) -> list[dict[str, int]]:
        return [{"id": challenge_id} for challenge_id in self.challenges]

    def challenge(self, challenge_id: int) -> Challenge:
        return self.challenges[challenge_id]

    def download(self, file_ref: str, destination: Path, *, byte_limit: int) -> dict[str, object]:
        raise AssertionError("scheduler fixtures have no downloads")

    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        with self._lock:
            self.submissions.append((challenge_id, candidate))
        return Verdict(self.outcome, self.outcome, 200)

    def instance(self, method: str, challenge_id: int) -> dict[str, object]:
        with self._lock:
            self.instance_calls.append((method, challenge_id))
            if method == "POST":
                record = {
                    "connection_info": f"http://127.0.0.1:{8100 + challenge_id}/",
                    "since": 1,
                    "until": 100,
                }
                self.active_instances[challenge_id] = record
                self.max_active_instances = max(
                    self.max_active_instances, len(self.active_instances)
                )
                if len(self.active_instances) > 1:
                    self.second_instance_active.set()
                return {"success": True, "status": 200, **record}
            if method == "DELETE":
                self.active_instances.pop(challenge_id, None)
                return {
                    "success": True,
                    "status": 200,
                    "connection_info": "",
                    "since": None,
                    "until": None,
                }
            record = self.active_instances.get(challenge_id)
            if record is None:
                return {
                    "success": False,
                    "status": 404,
                    "connection_info": "",
                    "since": None,
                    "until": None,
                }
            return {"success": True, "status": 200, **record}


def turn(document: dict[str, object], candidate: str | None = None) -> SimpleNamespace:
    summary = f"carry-c{document['challenge']['id']}-lane-{document['lane']}"
    payload = {
        "status": "candidate" if candidate is not None else "unsolved",
        "candidate": candidate,
        "confidence": 0.9 if candidate is not None else 0.2,
        "summary": summary,
        "evidence": ["source observation"] if candidate is not None else [summary],
        "next_steps": [f"continue lane {document['lane']}"] if candidate is None else [],
    }
    candidate_hashes = (
        [hashlib.sha256(candidate.encode()).hexdigest()] if candidate is not None else []
    )
    return SimpleNamespace(
        text=json.dumps(payload),
        status="completed",
        failure_class=None,
        tool_calls=[
            {
                "name": "inspect_file",
                "success": True,
                "source_bound": True,
                "candidate_sha256s": candidate_hashes,
            }
        ],
    )


class FourTurnBarrierRuntime:
    def __init__(self, *, candidates: dict[int, str] | None = None) -> None:
        self.candidates = candidates or {}
        self.release = asyncio.Event()
        self.four_active = asyncio.Event()
        self.all_exited = asyncio.Event()
        self.admissions: list[tuple[int, int, int]] = []
        self.active = 0
        self.max_active = 0
        self.exited = 0
        self.closed = False

    async def start(self) -> None:
        pass

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> SimpleNamespace:
        document = json.loads(prompt)
        admission = (
            document["challenge"]["id"],
            document["episode"],
            document["lane"],
        )
        self.admissions.append(admission)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        if self.active == 4:
            self.four_active.set()
        try:
            await self.release.wait()
            return turn(document, self.candidates.get(document["challenge"]["id"]))
        finally:
            self.active -= 1
            self.exited += 1
            if self.exited == 4:
                self.all_exited.set()

    async def close(self) -> None:
        self.closed = True


class CoverageBarrierRuntime:
    def __init__(self) -> None:
        self.release_slow_episode_zero = asyncio.Event()
        self.all_episode_zero_admitted = asyncio.Event()
        self.episode_one_admitted = asyncio.Event()
        self.admissions: list[tuple[int, int, int]] = []
        self.invalid_carry: list[tuple[int, int, list[dict[str, object]]]] = []
        self.invalid_observations: list[tuple[int, int, dict[str, object]]] = []
        self.overlapping_episode_violations: list[tuple[int, int, int]] = []
        self._wave_arrivals: Counter[tuple[int, int]] = Counter()
        self._wave_ready: dict[tuple[int, int], asyncio.Event] = {}
        self._active_episode: dict[int, int] = {}
        self._active_lanes: Counter[int] = Counter()

    async def start(self) -> None:
        pass

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> SimpleNamespace:
        document = json.loads(prompt)
        challenge_id = document["challenge"]["id"]
        episode = document["episode"]
        lane = document["lane"]
        self.admissions.append((challenge_id, episode, lane))
        if episode == 0:
            episode_zero_turns = {item for item in self.admissions if item[1] == 0}
            if len(episode_zero_turns) == 6:
                self.all_episode_zero_admitted.set()
        else:
            self.episode_one_admitted.set()
            expected = [
                {
                    "episode": 0,
                    "status": "unsolved",
                    "summary": f"carry-c{challenge_id}-lane-{lane}",
                    "evidence": [f"carry-c{challenge_id}-lane-{lane}"],
                    "next_steps": [f"continue lane {lane}"],
                    "tool_count": 1,
                    "failure_class": None,
                }
            ]
            if document["prior_attempts"] != expected:
                self.invalid_carry.append((challenge_id, lane, document["prior_attempts"]))
            observations = document["prior_observations"]
            manifests = observations.get("manifests", [])
            if not (
                observations.get("challenge_id") == challenge_id
                and observations.get("lane") == lane
                and observations.get("before_episode") == episode
                and len(manifests) == 1
                and manifests[0].get("episode") == 0
                and manifests[0].get("gap") == "provenance_incomplete"
                and len(manifests[0].get("items", [])) == 1
                and manifests[0]["items"][0].get("tool") == "inspect_file"
            ):
                self.invalid_observations.append((challenge_id, lane, observations))

        active_episode = self._active_episode.get(challenge_id)
        if active_episode is not None and active_episode != episode:
            self.overlapping_episode_violations.append((challenge_id, active_episode, episode))
        self._active_episode[challenge_id] = episode
        self._active_lanes[challenge_id] += 1

        wave = (challenge_id, episode)
        ready = self._wave_ready.setdefault(wave, asyncio.Event())
        self._wave_arrivals[wave] += 1
        if self._wave_arrivals[wave] == 2:
            ready.set()
        try:
            await ready.wait()
            if wave == (2, 0):
                await self.release_slow_episode_zero.wait()
            return turn(document)
        finally:
            self._active_lanes[challenge_id] -= 1
            if self._active_lanes[challenge_id] == 0:
                del self._active_lanes[challenge_id]
                self._active_episode.pop(challenge_id, None)

    async def close(self) -> None:
        pass


class ImmediateWaveRuntime:
    def __init__(self, candidates: dict[int, str]) -> None:
        self.candidates = candidates
        self._arrivals: Counter[tuple[int, int]] = Counter()
        self._ready: dict[tuple[int, int], asyncio.Event] = {}

    async def start(self) -> None:
        pass

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> SimpleNamespace:
        document = json.loads(prompt)
        wave = (document["challenge"]["id"], document["episode"])
        ready = self._ready.setdefault(wave, asyncio.Event())
        self._arrivals[wave] += 1
        if self._arrivals[wave] == 2:
            ready.set()
        await ready.wait()
        return turn(document, self.candidates[document["challenge"]["id"]])

    async def close(self) -> None:
        pass


class SerializedRiskBoard(OfflineBoard):
    def __init__(self, challenges: list[Challenge]) -> None:
        super().__init__(challenges)
        self.release_first = threading.Event()
        self.first_submit_started = threading.Event()
        self.second_submit_started = threading.Event()
        self.active_submits = 0
        self.max_active_submits = 0

    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        with self._lock:
            self.submissions.append((challenge_id, candidate))
            call_number = len(self.submissions)
            self.active_submits += 1
            self.max_active_submits = max(self.max_active_submits, self.active_submits)
            if call_number == 1:
                self.first_submit_started.set()
            else:
                self.second_submit_started.set()
        try:
            if call_number == 1:
                assert self.release_first.wait(timeout=2)
            return Verdict("incorrect", "incorrect", 200)
        finally:
            with self._lock:
                self.active_submits -= 1


class BlockingDynamicRuntime:
    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.first_wave_active = asyncio.Event()
        self.active = 0
        self.max_active = 0
        self.closed = False

    async def start(self) -> None:
        pass

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> SimpleNamespace:
        document = json.loads(prompt)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        if self.active >= 2:
            self.first_wave_active.set()
        try:
            await self.release.wait()
            return turn(document)
        finally:
            self.active -= 1

    async def close(self) -> None:
        self.closed = True


def assert_drained(cfg: RuntimeConfig, board: OfflineBoard, store: StateStore) -> None:
    assert board.active_instances == {}
    assert store.owned_instances() == []
    assert store.active_attempts() == []
    run_roots = list(cfg.work_root.glob("run-*"))
    assert run_roots
    assert all(not any(root.rglob("*")) for root in run_roots)


def test_distinct_challenges_fill_four_turn_capacity_without_oversubscription(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        cfg = config(tmp_path, active_challenges=2, concurrency=4)
        runtime = FourTurnBarrierRuntime()
        board = OfflineBoard([challenge(1), challenge(2)])
        store = StateStore(cfg.state_path)
        task = asyncio.create_task(Orchestrator(cfg, board, store, runtime).run())
        try:
            await asyncio.wait_for(runtime.four_active.wait(), timeout=1)
            assert runtime.active == 4
            assert runtime.max_active == cfg.concurrency
            assert {challenge_id for challenge_id, _, _ in runtime.admissions} == {1, 2}
        finally:
            runtime.release.set()
            await task
            store.close()

    asyncio.run(exercise())


def test_fifo_coverage_precedes_successors_and_carry_is_lane_local(tmp_path: Path) -> None:
    async def exercise() -> None:
        cfg = config(
            tmp_path,
            active_challenges=2,
            concurrency=4,
            episodes_per_challenge=2,
        )
        runtime = CoverageBarrierRuntime()
        store = StateStore(cfg.state_path)
        task = asyncio.create_task(
            Orchestrator(
                cfg,
                OfflineBoard([challenge(1), challenge(2), challenge(3)]),
                store,
                runtime,
            ).run()
        )
        episode_zero = asyncio.create_task(runtime.all_episode_zero_admitted.wait())
        episode_one = asyncio.create_task(runtime.episode_one_admitted.wait())
        try:
            done, _ = await asyncio.wait(
                {episode_zero, episode_one},
                timeout=1,
                return_when=asyncio.FIRST_COMPLETED,
            )
            assert episode_zero in done, "episode 1 bypassed unseen challenge episode 0"
        finally:
            runtime.release_slow_episode_zero.set()
            await task
            for waiter in (episode_zero, episode_one):
                if not waiter.done():
                    waiter.cancel()
            await asyncio.gather(episode_zero, episode_one, return_exceptions=True)

        first_episode_one = min(
            index for index, (_, episode, _) in enumerate(runtime.admissions) if episode == 1
        )
        last_episode_zero = max(
            index for index, (_, episode, _) in enumerate(runtime.admissions) if episode == 0
        )
        assert last_episode_zero < first_episode_one
        assert runtime.overlapping_episode_violations == []
        assert runtime.invalid_carry == []
        assert runtime.invalid_observations == []
        assert Counter(runtime.admissions) == Counter(
            (challenge_id, episode, lane)
            for challenge_id in (1, 2, 3)
            for episode in (0, 1)
            for lane in (0, 1)
        )
        store.close()

    asyncio.run(exercise())


def test_catalogue_solved_metadata_does_not_create_run_local_solve(
    tmp_path: Path,
) -> None:
    candidate = "INCYPHER{freshly_derived}"
    cfg = config(tmp_path, submit_candidates=True)
    board = OfflineBoard([challenge(90, solved=True)], outcome="already_solved")
    store = StateStore(cfg.state_path)
    report = asyncio.run(
        Orchestrator(cfg, board, store, ImmediateWaveRuntime({90: candidate})).run()
    )

    assert board.submissions == [(90, candidate)]
    assert report.solved == 0
    assert report.candidates == 1
    store.close()


def test_simultaneous_candidates_serialize_post_and_atomically_stop_at_risk_one(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        candidates = {1: "INCYPHER{one}", 2: "INCYPHER{two}"}
        cfg = config(
            tmp_path,
            submit_candidates=True,
            wrong_submission_ceiling=1,
        )
        board = SerializedRiskBoard([challenge(1), challenge(2)])
        runtime = FourTurnBarrierRuntime(candidates=candidates)
        store = StateStore(cfg.state_path)
        task = asyncio.create_task(Orchestrator(cfg, board, store, runtime).run())
        try:
            await asyncio.wait_for(runtime.four_active.wait(), timeout=1)
            runtime.release.set()
            assert await asyncio.to_thread(board.first_submit_started.wait, 1)
            await asyncio.wait_for(runtime.all_exited.wait(), timeout=1)
            await asyncio.to_thread(board.second_submit_started.wait, 0.1)
            assert board.second_submit_started.is_set() is False
            assert board.max_active_submits == 1
        finally:
            board.release_first.set()
            report = await task

        assert len(board.submissions) == 1
        assert store.submission_risk_count() == 1
        assert report.unsolved == 1
        assert report.candidates == 1
        store.close()

    asyncio.run(exercise())


def test_dynamic_instance_cap_and_cancellation_drain_owned_resources(tmp_path: Path) -> None:
    async def exercise() -> None:
        cfg = config(
            tmp_path,
            manage_dynamic_instances=True,
            active_challenges=2,
            dynamic_concurrency=1,
        )
        board = OfflineBoard(
            [
                challenge(1, challenge_type="dynamic_iac"),
                challenge(2, challenge_type="dynamic_iac"),
            ]
        )
        runtime = BlockingDynamicRuntime()
        store = StateStore(cfg.state_path)
        task = asyncio.create_task(Orchestrator(cfg, board, store, runtime).run())
        try:
            await asyncio.wait_for(runtime.first_wave_active.wait(), timeout=1)
            await asyncio.to_thread(board.second_instance_active.wait, 0.1)
            assert board.max_active_instances == 1
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            runtime.release.set()
            if not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

        assert runtime.active == 0
        assert runtime.closed
        assert_drained(cfg, board, store)
        store.close()

    asyncio.run(exercise())


def test_deadline_drains_tasks_owned_instance_and_workspaces(tmp_path: Path) -> None:
    async def exercise() -> None:
        cfg = config(
            tmp_path,
            manage_dynamic_instances=True,
            run_seconds=0.3,
        )
        board = OfflineBoard([challenge(1, challenge_type="dynamic_iac")])
        runtime = BlockingDynamicRuntime()
        store = StateStore(cfg.state_path)
        report = await Orchestrator(cfg, board, store, runtime).run()

        assert report.status == "deadline"
        assert runtime.active == 0
        assert runtime.closed
        assert_drained(cfg, board, store)
        store.close()

    asyncio.run(exercise())
