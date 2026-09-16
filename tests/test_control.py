from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import textwrap
import threading
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from rapido.board import BoardError, Challenge, Verdict
from rapido.config import RuntimeConfig
from rapido.control import DurableJobControl
from rapido.evidence import project_tool_observation
from rapido.routing import baseline_route
from rapido.state import StateStore


class BoundaryBoard:
    timeout = 0.01

    def __init__(self, challenges: list[Challenge]) -> None:
        self._challenges = {challenge.id: challenge for challenge in challenges}
        self.submissions: list[tuple[int, str]] = []

    def identity(self) -> dict[str, int]:
        return {"id": 1, "team_id": 2}

    def anonymous_identity_is_rejected(self) -> bool:
        return True

    def list_challenges(self) -> list[dict[str, int]]:
        return [{"id": challenge_id} for challenge_id in self._challenges]

    def challenge(self, challenge_id: int) -> Challenge:
        return self._challenges[challenge_id]

    def download(self, file_ref: str, destination: Path, *, byte_limit: int) -> dict[str, object]:
        del file_ref
        destination.write_bytes(b"fixture")
        return {"bytes": min(7, byte_limit), "redirect_hosts": ["board"]}

    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        self.submissions.append((challenge_id, candidate))
        return Verdict("correct", "ok", 200)


class AmbiguousBoundaryBoard(BoundaryBoard):
    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        self.submissions.append((challenge_id, candidate))
        raise BoardError("ambiguous delivery")


class IndeterminateCleanupBoundaryBoard(BoundaryBoard):
    def __init__(self, challenges: list[Challenge]) -> None:
        super().__init__(challenges)
        self.active: dict[int, dict[str, object]] = {}
        self.get_calls = 0

    def instance(self, method: str, challenge_id: int) -> dict[str, object]:
        if method == "POST":
            self.active[challenge_id] = {
                "connection_info": "http://127.0.0.1:8135/",
                "until": 100,
            }
            return {"success": True, "status": 200, **self.active[challenge_id]}
        if method == "DELETE":
            raise AssertionError("indeterminate ownership must fence deletion")
        self.get_calls += 1
        if challenge_id not in self.active:
            return {"success": False, "status": 404, "connection_info": "", "until": None}
        if self.get_calls >= 3:
            return {"success": False, "status": 429, "connection_info": "", "until": None}
        return {"success": True, "status": 200, **self.active[challenge_id]}


class WorkspaceAndCleanupFailureBoard(BoundaryBoard):
    def __init__(self, challenges: list[Challenge]) -> None:
        super().__init__(challenges)
        self.get_calls = 0
        self.post_calls = 0
        self.download_calls = 0

    def download(self, file_ref: str, destination: Path, *, byte_limit: int) -> dict[str, object]:
        del file_ref, destination, byte_limit
        self.download_calls += 1
        raise OSError("local workspace write failed")

    def instance(self, method: str, challenge_id: int) -> dict[str, object]:
        del challenge_id
        current = {
            "success": True,
            "status": 200,
            "connection_info": "http://127.0.0.1:8135/",
            "until": 100,
        }
        if method == "POST":
            self.post_calls += 1
            return current
        if method == "GET":
            self.get_calls += 1
            if self.get_calls == 1:
                return {"success": False, "status": 404, "connection_info": "", "until": None}
            if self.get_calls == 2:
                return current
            return {"success": False, "status": 429, "connection_info": "", "until": None}
        raise AssertionError("indeterminate cleanup must not attempt deletion")


class BoundaryRuntime:
    def __init__(self, candidate: str) -> None:
        self._candidate = candidate
        self.started = False
        self.closed = False

    async def start(self) -> None:
        self.started = True

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        del workspace, kwargs
        document = json.loads(prompt)
        candidate_digest = hashlib.sha256(self._candidate.encode()).hexdigest()
        await asyncio.sleep(0.01)
        observation = project_tool_observation(
            "inspect_file",
            success=True,
            source_bound=True,
            candidate_sensitive=True,
            candidate_sha256s=(candidate_digest,),
        )
        return type(
            "BoundaryTurn",
            (),
            {
                "status": "completed",
                "text": json.dumps(
                    {
                        "status": "candidate",
                        "candidate": self._candidate,
                        "confidence": 0.9,
                        "summary": f"lane {document['lane']} independently derived a value",
                        "evidence": ["fixture bytes"],
                        "next_steps": [],
                    }
                ),
                "tool_calls": [
                    {
                        "name": "inspect_file",
                        "success": True,
                        "source_bound": True,
                        "candidate_sensitive": True,
                        "candidate_sha256s": [candidate_digest],
                        "supplied_candidate_sha256s": [],
                        "host_observation": observation,
                    }
                ],
            },
        )()

    async def close(self) -> None:
        self.closed = True


class UnsolvedBoundaryRuntime(BoundaryRuntime):
    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        del workspace, prompt, kwargs
        await asyncio.sleep(0.01)
        return type(
            "BoundaryTurn",
            (),
            {
                "status": "completed",
                "text": json.dumps(
                    {
                        "status": "unsolved",
                        "candidate": None,
                        "confidence": 0.2,
                        "summary": "bounded route exhausted",
                        "evidence": [],
                        "next_steps": [],
                    }
                ),
                "tool_calls": [],
            },
        )()


class MixedBoundaryRuntime(BoundaryRuntime):
    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        if json.loads(prompt)["lane"] == 0:
            return await super().solve(workspace, prompt, **kwargs)
        return await UnsolvedBoundaryRuntime.solve(self, workspace, prompt, **kwargs)


class BlockingBoundaryRuntime(UnsolvedBoundaryRuntime):
    def __init__(self) -> None:
        super().__init__("unused")
        self.ready = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()
        self._active = 0

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        with self._lock:
            self._active += 1
            if self._active == 2:
                self.ready.set()
        assert await asyncio.to_thread(self.release.wait, 5)
        return await super().solve(workspace, prompt, **kwargs)


class HangingBoundaryRuntime(BoundaryRuntime):
    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        del workspace, prompt, kwargs
        await asyncio.sleep(60)
        raise AssertionError("deadline must cancel the hanging turn")


def _config(tmp_path: Path) -> RuntimeConfig:
    (tmp_path / "auth").mkdir(exist_ok=True)
    base = RuntimeConfig.from_env(
        {
            "RAPIDO_STATE_PATH": str(tmp_path / "state.sqlite3"),
            "RAPIDO_WORK_ROOT": str(tmp_path / "work"),
            "RAPIDO_CODEX_HOME": str(tmp_path / "auth"),
            "RAPIDO_SUBMIT_CANDIDATES": "false",
            "RAPIDO_MANAGE_DYNAMIC_INSTANCES": "false",
        }
    )
    return replace(base, run_seconds=60, attempt_seconds=15, episodes_per_challenge=1)


def _challenge(challenge_id: int, *, challenge_type: str = "standard") -> Challenge:
    return Challenge(
        challenge_id,
        f"Fixture {challenge_id}",
        "crypto",
        challenge_type,
        "derive the value",
        100,
        (),
        False,
        0,
        0,
        None,
        None,
    )


def _file_challenge(challenge_id: int, *, challenge_type: str) -> Challenge:
    value = _challenge(challenge_id, challenge_type=challenge_type)
    return replace(value, files=("fixture-file",))


def test_drive_inspect_round_trip_exposes_only_sanitized_run_contract(tmp_path: Path) -> None:
    candidate = "INCYPHER{control-view-must-not-leak}"
    board = BoundaryBoard([_challenge(1)])
    runtime = BoundaryRuntime(candidate)
    config = _config(tmp_path)

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert view.run_id == report.run_id
    assert view.status == "completed"
    assert view.catalogue_count == 1
    assert view.initial_coverage_count == 1
    assert view.pending_submission_count == 0
    assert view.owned_instance_count == 0
    assert runtime.started and runtime.closed
    assert board.submissions == []

    encoded = json.dumps(asdict(view), sort_keys=True)
    assert candidate not in encoded
    assert re.search(r"\b[0-9a-fA-F]{64}\b", encoded) is None


def test_initial_queue_identity_and_order_survive_reopened_inspection(tmp_path: Path) -> None:
    board = BoundaryBoard([_challenge(1), _challenge(2), _challenge(3)])
    runtime = BoundaryRuntime("INCYPHER{durable-job-fixture}")
    config = _config(tmp_path)

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))
    first = DurableJobControl.inspect(config.state_path, run_id=report.run_id)
    second = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert first == second
    assert [(job.challenge_id, job.phase, job.role, job.lane, job.state) for job in first.jobs] == [
        (1, "initial", "specialist", 0, "candidate"),
        (1, "initial", "specialist", 1, "candidate"),
        (2, "initial", "specialist", 0, "candidate"),
        (2, "initial", "specialist", 1, "candidate"),
        (3, "initial", "specialist", 0, "candidate"),
        (3, "initial", "specialist", 1, "candidate"),
    ]
    assert len({job.job_id for job in first.jobs}) == 6
    assert max(job.admitted_sequence for job in first.jobs) < min(
        job.started_sequence for job in first.jobs
    )
    assert all(job.started_sequence < job.closed_sequence for job in first.jobs)


def test_closed_job_state_matches_each_lane_terminal(tmp_path: Path) -> None:
    config = _config(tmp_path)
    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=BoundaryBoard([_challenge(1)]),
            runtime=MixedBoundaryRuntime("INCYPHER{one-lane-only}"),
        )
    )

    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)
    assert {job.lane: job.state for job in view.jobs} == {0: "candidate", 1: "unsolved"}


def test_pending_effect_count_is_global_when_inspecting_prior_or_current_run(
    tmp_path: Path,
) -> None:
    candidate = "INCYPHER{ambiguous-control-effect}"
    board = AmbiguousBoundaryBoard([_challenge(1)])
    config = replace(_config(tmp_path), submit_candidates=True)

    first_report = asyncio.run(
        DurableJobControl.drive(config, board=board, runtime=BoundaryRuntime(candidate))
    )
    second_report = asyncio.run(
        DurableJobControl.drive(config, board=board, runtime=BoundaryRuntime(candidate))
    )

    first = DurableJobControl.inspect(config.state_path, run_id=first_report.run_id)
    second = DurableJobControl.inspect(config.state_path, run_id=second_report.run_id)
    assert first.pending_submission_count == second.pending_submission_count == 1
    assert board.submissions == [(1, candidate)]


def test_owned_instance_count_is_global_when_inspecting_prior_or_current_run(
    tmp_path: Path,
) -> None:
    board = IndeterminateCleanupBoundaryBoard([_challenge(2, challenge_type="dynamic_iac")])
    config = replace(_config(tmp_path), manage_dynamic_instances=True)

    first_report = asyncio.run(
        DurableJobControl.drive(config, board=board, runtime=UnsolvedBoundaryRuntime("unused"))
    )
    second_report = asyncio.run(
        DurableJobControl.drive(config, board=board, runtime=UnsolvedBoundaryRuntime("unused"))
    )

    first = DurableJobControl.inspect(config.state_path, run_id=first_report.run_id)
    second = DurableJobControl.inspect(config.state_path, run_id=second_report.run_id)
    assert first.owned_instance_count == second.owned_instance_count == 1


def test_catalogue_count_includes_entries_that_are_not_executable(tmp_path: Path) -> None:
    board = BoundaryBoard([_challenge(1), _challenge(2, challenge_type="dynamic_iac")])
    config = _config(tmp_path)

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=board,
            runtime=BoundaryRuntime("INCYPHER{catalogue-denominator}"),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.challenge_count == view.catalogue_count == 2
    assert report.unsupported == 1
    assert view.initial_coverage_count == 1
    assert {(job.challenge_id, job.catalogue_rank) for job in view.jobs} == {(1, 1)}


def test_unclassified_analysis_is_contained_and_config_changes_change_routes(
    tmp_path: Path,
) -> None:
    board = BoundaryBoard([_challenge(1)])
    base = replace(_config(tmp_path), episodes_per_challenge=2)

    first_report = asyncio.run(
        DurableJobControl.drive(base, board=board, runtime=UnsolvedBoundaryRuntime("unused"))
    )
    first = DurableJobControl.inspect(base.state_path, run_id=first_report.run_id)
    initial_routes = {job.route_fingerprint for job in first.jobs if job.phase == "initial"}
    assert len(initial_routes) == 1
    assert not [job for job in first.jobs if job.phase == "retry"]
    assert first.route_decisions == ()

    changed = replace(base, episodes_per_challenge=1, attempt_seconds=14)
    second_report = asyncio.run(
        DurableJobControl.drive(changed, board=board, runtime=UnsolvedBoundaryRuntime("unused"))
    )
    second = DurableJobControl.inspect(changed.state_path, run_id=second_report.run_id)
    assert {job.route_fingerprint for job in second.jobs}.isdisjoint(initial_routes)


def test_wave_close_decision_and_successor_admission_roll_back_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "private" / "state.sqlite3"
    state = StateStore(path)
    run_id = "1" * 32
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=15)
    try:
        state.start_run(run_id, {})
        state.upsert_challenge(1, "fixture", "crypto", "standard", 100)
        state.record_control_catalogue(run_id, [(1, 1, True)])
        state.admit_control_wave(run_id, 1, 0, 1, 2, route)
        state.start_control_wave(run_id, 1, 0)
        for lane in range(2):
            attempt_id = f"{run_id}:1:0:{lane}"
            state.start_attempt(attempt_id, run_id, 1, 0, lane, "gpt-daybreak-blue-latest", "xhigh")
            state.finish_attempt(attempt_id, "failed", failure_class="solver_output")

        def fail_admission(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise RuntimeError("crash before successor admission")

        monkeypatch.setattr(StateStore, "_admit_control_wave", fail_admission)
        with pytest.raises(RuntimeError, match="crash before successor"):
            state.finish_and_decide_control_wave(
                run_id=run_id,
                challenge_id=1,
                source_episode=0,
                next_episode=1,
                catalogue_rank=1,
                lanes=2,
                terminal="error",
                attempts_remaining=True,
                remaining_milliseconds=10_000,
            )
        view = DurableJobControl.inspect(path, run_id=run_id)
        assert {job.state for job in view.jobs} == {"running"}
        assert view.route_decisions == ()
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT COUNT(*) FROM control_routes").fetchone()[0] == 1
    finally:
        state.close()


def test_inspect_supports_main_schema_without_route_decisions(tmp_path: Path) -> None:
    config = _config(tmp_path)
    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=BoundaryBoard([_challenge(1)]),
            runtime=UnsolvedBoundaryRuntime("unused"),
        )
    )
    with sqlite3.connect(config.state_path) as connection:
        connection.execute("DROP TABLE control_route_decisions")
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)
    assert view.route_decisions == ()


def test_jobs_reference_the_single_route_authority(tmp_path: Path) -> None:
    config = _config(tmp_path)
    asyncio.run(
        DurableJobControl.drive(
            config,
            board=BoundaryBoard([_challenge(1)]),
            runtime=UnsolvedBoundaryRuntime("unused"),
        )
    )
    with sqlite3.connect(config.state_path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(control_jobs)")}
        foreign_keys = list(connection.execute("PRAGMA foreign_key_list(control_jobs)"))
    assert "route_json" not in columns
    assert sum(row[2] == "control_routes" for row in foreign_keys) == 3


def test_concurrent_openers_recheck_route_authority_migration(tmp_path: Path) -> None:
    path = tmp_path / "private" / "state.sqlite3"
    StateStore(path).close()
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE control_jobs")
        connection.execute(
            """
            CREATE TABLE control_jobs (
                job_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES runs(id),
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                episode INTEGER NOT NULL,
                catalogue_rank INTEGER NOT NULL,
                phase TEXT NOT NULL,
                role TEXT NOT NULL,
                lane INTEGER NOT NULL,
                state TEXT NOT NULL,
                route_fingerprint TEXT NOT NULL,
                admitted_sequence INTEGER NOT NULL UNIQUE REFERENCES control_events(sequence),
                started_sequence INTEGER UNIQUE REFERENCES control_events(sequence),
                closed_sequence INTEGER UNIQUE REFERENCES control_events(sequence),
                UNIQUE(run_id, challenge_id, episode, role, lane)
            )
            """
        )
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def open_state() -> None:
        barrier.wait()
        try:
            StateStore(path).close()
        except (OSError, RuntimeError, sqlite3.Error, ValueError) as exc:
            errors.append(exc)

    threads = [threading.Thread(target=open_state) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    with sqlite3.connect(path) as connection:
        assert (
            sum(
                row[2] == "control_routes"
                for row in connection.execute("PRAGMA foreign_key_list(control_jobs)")
            )
            == 3
        )


def test_failure_origin_escalates_to_board_and_never_downgrades(tmp_path: Path) -> None:
    path = tmp_path / "private" / "state.sqlite3"
    state = StateStore(path)
    run_id = "2" * 32
    try:
        state.start_run(run_id, {})
        state.upsert_challenge(1, "fixture", "crypto", "dynamic_iac", 100)
        state.record_control_failure_origin(run_id, 1, 0, "container")
        state.record_control_failure_origin(run_id, 1, 0, "board")
        state.record_control_failure_origin(run_id, 1, 0, "container")
        with sqlite3.connect(path) as connection:
            origin = connection.execute(
                "SELECT origin FROM control_failure_origins "
                "WHERE run_id=? AND challenge_id=1 AND episode=0",
                (run_id,),
            ).fetchone()[0]
            kinds = [
                row[0]
                for row in connection.execute(
                    "SELECT kind FROM control_events WHERE run_id=? ORDER BY sequence", (run_id,)
                )
            ]
        assert origin == "board"
        assert kinds == ["failure_origin_recorded", "failure_origin_escalated"]
    finally:
        state.close()


def test_dynamic_workspace_then_cleanup_failure_escalates_and_contains(tmp_path: Path) -> None:
    board = WorkspaceAndCleanupFailureBoard([_file_challenge(1, challenge_type="dynamic_iac")])
    config = replace(_config(tmp_path), manage_dynamic_instances=True, episodes_per_challenge=2)
    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=board,
            runtime=UnsolvedBoundaryRuntime("unused"),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)
    assert report.status == "completed"
    assert [(item.failure_kind, item.disposition) for item in view.route_decisions] == [
        ("board", "contain")
    ]
    assert {job.episode for job in view.jobs} == {0}
    assert board.post_calls == board.download_calls == 1
    assert board.get_calls >= 3
    assert view.owned_instance_count == 1


def test_inspect_is_consistent_while_one_wave_runs_and_another_is_queued(tmp_path: Path) -> None:
    runtime = BlockingBoundaryRuntime()
    config = replace(_config(tmp_path), active_challenges=1, concurrency=2)
    outcome: dict[str, object] = {}

    def drive() -> None:
        try:
            outcome["report"] = asyncio.run(
                DurableJobControl.drive(
                    config,
                    board=BoundaryBoard([_challenge(1), _challenge(2)]),
                    runtime=runtime,
                )
            )
        except (AssertionError, BoardError, OSError, RuntimeError, TypeError, ValueError) as exc:
            outcome["error"] = exc

    thread = threading.Thread(target=drive)
    thread.start()
    assert runtime.ready.wait(timeout=5)
    try:
        view = DurableJobControl.inspect(config.state_path)
        assert view.catalogue_count == 2
        assert view.initial_coverage_count == 1
        assert [(job.challenge_id, job.state) for job in view.jobs] == [
            (1, "running"),
            (1, "running"),
            (2, "queued"),
            (2, "queued"),
        ]
        assert all(job.started_sequence is not None for job in view.jobs[:2])
        assert all(job.closed_sequence is None for job in view.jobs)
        assert all(job.started_sequence is None for job in view.jobs[2:])
    finally:
        runtime.release.set()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert "error" not in outcome


def test_deadline_closes_running_and_queued_jobs_durably(tmp_path: Path) -> None:
    config = replace(_config(tmp_path), active_challenges=1, concurrency=2, run_seconds=0.5)

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=BoundaryBoard([_challenge(1), _challenge(2)]),
            runtime=HangingBoundaryRuntime("unused"),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.status == view.status == "deadline"
    assert len(view.jobs) == 4
    assert {(job.challenge_id, job.state) for job in view.jobs} == {
        (1, "cancelled"),
        (2, "interrupted"),
    }
    assert all(job.closed_sequence is not None for job in view.jobs)


def test_restart_closes_jobs_left_open_by_process_loss(tmp_path: Path) -> None:
    config = _config(tmp_path)
    code = textwrap.dedent(
        """
        import asyncio
        import json
        import os
        from dataclasses import replace
        from pathlib import Path

        from rapido.board import Challenge, Verdict
        from rapido.config import RuntimeConfig
        from rapido.control import DurableJobControl

        class Board:
            timeout = 0.01
            def identity(self): return {"id": 1, "team_id": 2}
            def anonymous_identity_is_rejected(self): return True
            def list_challenges(self): return [{"id": 1}, {"id": 2}]
            def challenge(self, challenge_id):
                return Challenge(challenge_id, f"Crash {challenge_id}", "crypto", "standard",
                                 "derive", 100, (), False, 0, 0, None, None)
            def download(self, file_ref, destination, *, byte_limit):
                destination.write_bytes(b"fixture")
                return {"bytes": min(7, byte_limit), "redirect_hosts": ["board"]}
            def submit(self, challenge_id, candidate): return Verdict("correct", "ok", 200)

        class Runtime:
            async def start(self): pass
            async def solve(self, workspace, prompt, **kwargs):
                if json.loads(prompt)["lane"] == 0:
                    return type("Turn", (), {
                        "status": "completed",
                        "text": json.dumps({
                            "status": "unsolved", "candidate": None, "confidence": 0.2,
                            "summary": "terminal lane committed", "evidence": [], "next_steps": []
                        }),
                        "tool_calls": [],
                    })()
                await asyncio.sleep(0.2)
                os._exit(23)
            async def close(self): pass

        config = RuntimeConfig.from_env({
            "RAPIDO_STATE_PATH": os.environ["CRASH_STATE"],
            "RAPIDO_WORK_ROOT": os.environ["CRASH_WORK"],
            "RAPIDO_CODEX_HOME": os.environ["CRASH_AUTH"],
            "RAPIDO_SUBMIT_CANDIDATES": "false",
            "RAPIDO_MANAGE_DYNAMIC_INSTANCES": "false",
            "RAPIDO_ACTIVE_CHALLENGES": "1",
            "RAPIDO_CONCURRENCY": "2",
        })
        asyncio.run(DurableJobControl.drive(config, board=Board(), runtime=Runtime()))
        """
    )
    environment = dict(os.environ)
    environment.update(
        {
            "CRASH_STATE": str(config.state_path),
            "CRASH_WORK": str(config.work_root),
            "CRASH_AUTH": str(config.codex_home),
            "PYTHONPATH": str(Path(__file__).parents[1]),
        }
    )

    crashed_process = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        env=environment,
        timeout=10,
    )
    assert crashed_process.returncode == 23
    crashed = DurableJobControl.inspect(config.state_path)
    assert crashed.status == "running"
    assert {job.state for job in crashed.jobs} == {"queued", "running"}
    assert all(job.closed_sequence is None for job in crashed.jobs)

    asyncio.run(
        DurableJobControl.drive(
            config,
            board=BoundaryBoard([_challenge(1)]),
            runtime=UnsolvedBoundaryRuntime("unused"),
        )
    )
    recovered = DurableJobControl.inspect(config.state_path, run_id=crashed.run_id)
    assert recovered.status == "interrupted"
    assert {(job.challenge_id, job.lane): job.state for job in recovered.jobs} == {
        (1, 0): "unsolved",
        (1, 1): "interrupted",
        (2, 0): "interrupted",
        (2, 1): "interrupted",
    }
    assert all(job.closed_sequence is not None for job in recovered.jobs)
