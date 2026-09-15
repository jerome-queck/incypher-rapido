"""Small offline measurement of the challenge scheduler topology.

The fixture deliberately uses the production ``Orchestrator.run`` seam with a
local catalogue and a synthetic runtime.  It does not construct a BoardClient,
open a network connection, invoke a model, download an artifact, or submit a
candidate.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rapido.board import Challenge
from rapido.config import RuntimeConfig
from rapido.orchestrator import Orchestrator
from rapido.state import StateStore

CHALLENGE_COUNT = 15
LANES = 2
EPISODES = 1
TURN_DELAY_SECONDS = 0.020


def _challenge(challenge_id: int) -> Challenge:
    return Challenge(
        challenge_id,
        f"Synthetic challenge {challenge_id}",
        "crypto",
        "standard",
        "derive the value from the provided fixture",
        100,
        (),
        False,
        0,
        0,
        None,
        None,
    )


class SyntheticCatalogue:
    """The synchronous, local-only Board-shaped catalogue used by the fixture."""

    timeout = 0.01

    def __init__(self) -> None:
        self._challenges = {
            challenge_id: _challenge(challenge_id) for challenge_id in range(1, CHALLENGE_COUNT + 1)
        }
        self.downloads = 0
        self.submissions = 0

    def anonymous_identity_is_rejected(self) -> bool:
        return True

    def identity(self) -> dict[str, int]:
        return {"id": 1, "team_id": 1}

    def list_challenges(self) -> list[dict[str, int]]:
        return [{"id": challenge_id} for challenge_id in self._challenges]

    def challenge(self, challenge_id: int) -> Challenge:
        return self._challenges[challenge_id]

    def download(self, file_ref: str, destination: Path, *, byte_limit: int) -> dict[str, object]:
        self.downloads += 1
        raise AssertionError("the scheduler fixture has no artifacts")

    def submit(self, challenge_id: int, candidate: str) -> object:
        self.submissions += 1
        raise AssertionError("the scheduler fixture never submits")


class SyntheticRuntime:
    """Fixed-duration runtime with counters for scheduler admission evidence."""

    def __init__(self, delay_seconds: float = TURN_DELAY_SECONDS) -> None:
        self.delay_seconds = delay_seconds
        self.active_turns = 0
        self.max_turns = 0
        self.max_active_challenges = 0
        self._active_challenges: Counter[int] = Counter()
        self.closed = False

    async def start(self) -> None:
        return None

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> SimpleNamespace:
        del workspace, kwargs
        document = json.loads(prompt)
        challenge_id = int(document["challenge"]["id"])
        self.active_turns += 1
        self.max_turns = max(self.max_turns, self.active_turns)
        self._active_challenges[challenge_id] += 1
        self.max_active_challenges = max(self.max_active_challenges, len(self._active_challenges))
        try:
            await asyncio.sleep(self.delay_seconds)
            return SimpleNamespace(
                text=json.dumps(
                    {
                        "status": "unsolved",
                        "candidate": None,
                        "confidence": 0.0,
                        "summary": f"synthetic challenge {challenge_id}",
                        "evidence": ["fixed offline wait"],
                        "next_steps": ["synthetic fixture complete"],
                    }
                ),
                status="completed",
                failure_class=None,
                tool_calls=[],
            )
        finally:
            # Keep both counters correct even when the orchestrator cancels a lane.
            self.active_turns -= 1
            self._active_challenges[challenge_id] -= 1
            if self._active_challenges[challenge_id] == 0:
                del self._active_challenges[challenge_id]

    async def close(self) -> None:
        self.closed = True


@dataclass(frozen=True)
class Arm:
    name: str
    active_challenges: int
    concurrency: int


ARMS = (
    Arm("A", active_challenges=1, concurrency=2),
    Arm("C", active_challenges=2, concurrency=4),
)


def _config(root: Path, arm: Arm) -> RuntimeConfig:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    auth = root / "auth"
    auth.mkdir(mode=0o700)
    auth_file = auth / "auth.json"
    auth_file.write_text("{}", encoding="utf-8")
    auth_file.chmod(0o600)
    return RuntimeConfig.from_env(
        {
            "RAPIDO_STATE_PATH": str(root / "state.sqlite3"),
            "RAPIDO_WORK_ROOT": str(root / "work"),
            "RAPIDO_CODEX_HOME": str(auth),
            "RAPIDO_MODEL": "gpt-5.6-luna",
            "RAPIDO_REASONING_EFFORT": "xhigh",
            "RAPIDO_ACTIVE_CHALLENGES": str(arm.active_challenges),
            "RAPIDO_CONCURRENCY": str(arm.concurrency),
            "RAPIDO_EPISODES_PER_CHALLENGE": str(EPISODES),
            "RAPIDO_ATTEMPTS_PER_CHALLENGE": str(LANES),
            "RAPIDO_RUN_SECONDS": "60",
            "RAPIDO_ATTEMPT_SECONDS": "15",
            "RAPIDO_SUBMIT_CANDIDATES": "false",
            "RAPIDO_MANAGE_DYNAMIC_INSTANCES": "false",
        }
    )


async def _run_arm(root: Path, arm: Arm, turn_delay_seconds: float) -> dict[str, Any]:
    config = _config(root, arm)
    board = SyntheticCatalogue()
    runtime = SyntheticRuntime(turn_delay_seconds)
    state = StateStore(config.state_path)
    started = time.perf_counter()
    try:
        report = await Orchestrator(config, board, state, runtime).run()
        elapsed = time.perf_counter() - started
        current = asyncio.current_task()
        leftover_tasks = sum(
            1 for task in asyncio.all_tasks() if task is not current and not task.done()
        )
    finally:
        state.close()

    with sqlite3.connect(config.state_path) as connection:
        sqlite_integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        attempts = int(connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0])
        outcomes = [
            str(status)
            for (_, status) in connection.execute(
                "SELECT id, status FROM challenges ORDER BY id"
            ).fetchall()
        ]

    work_roots = list(config.work_root.glob("run-*"))
    leftover_workspaces = sum(sum(1 for _ in run_root.rglob("*")) for run_root in work_roots)
    return {
        "active_challenges": arm.active_challenges,
        "concurrency": arm.concurrency,
        "elapsed_seconds": elapsed,
        "max_active_distinct_challenges": runtime.max_active_challenges,
        "max_turns": runtime.max_turns,
        "outcomes": outcomes,
        "attempts": attempts,
        "leftover_tasks": leftover_tasks,
        "leftover_workspaces": leftover_workspaces,
        "sqlite_integrity": sqlite_integrity,
        "report_status": report.status,
        "runtime_active_turns": runtime.active_turns,
        "runtime_closed": runtime.closed,
        "catalogue_downloads": board.downloads,
        "catalogue_submissions": board.submissions,
    }


def _gate(
    arms: dict[str, dict[str, Any]],
    ratio: float,
    max_elapsed_ratio: float | None,
) -> list[str]:
    a = arms["A"]
    c = arms["C"]
    failures: list[str] = []
    if a["outcomes"] != c["outcomes"] or len(a["outcomes"]) != CHALLENGE_COUNT:
        failures.append("outcomes are not identical across all 15 challenges")
    if a["max_active_distinct_challenges"] != 1 or a["max_turns"] != 2:
        failures.append("arm A did not admit one challenge with two turns")
    if c["max_active_distinct_challenges"] != 2 or c["max_turns"] != 4:
        failures.append("arm C did not admit two challenges with four turns")
    for name, result in arms.items():
        if result["attempts"] != CHALLENGE_COUNT * LANES:
            failures.append(f"arm {name} attempt count changed")
        if result["leftover_tasks"] or result["leftover_workspaces"]:
            failures.append(f"arm {name} left owned work behind")
        if result["runtime_active_turns"] or not result["runtime_closed"]:
            failures.append(f"arm {name} runtime did not drain")
        if result["sqlite_integrity"] != "ok":
            failures.append(f"arm {name} SQLite integrity failed")
        if result["report_status"] != "completed":
            failures.append(f"arm {name} did not complete")
        if result["catalogue_downloads"] or result["catalogue_submissions"]:
            failures.append(f"arm {name} touched forbidden external seams")
    if max_elapsed_ratio is not None and ratio > max_elapsed_ratio:
        failures.append(f"arm C elapsed ratio exceeded {max_elapsed_ratio:.2f}")
    return failures


def run_benchmark(
    turn_delay_seconds: float = TURN_DELAY_SECONDS,
    *,
    max_elapsed_ratio: float | None = 0.70,
) -> dict[str, Any]:
    """Run both arms in fresh temporary state and return JSON-compatible evidence.

    ``max_elapsed_ratio=None`` checks only deterministic scheduler/lifecycle
    contracts. Wall-clock acceptance remains enabled for deliberate benchmark
    runs, but must not gate CI on a contended shared runner.
    """
    with tempfile.TemporaryDirectory(prefix="rapido-scheduler-acceptance-") as temporary:
        root = Path(temporary)
        results: dict[str, dict[str, Any]] = {}
        for arm in ARMS:
            results[arm.name] = asyncio.run(_run_arm(root / arm.name, arm, turn_delay_seconds))
    ratio = results["C"]["elapsed_seconds"] / results["A"]["elapsed_seconds"]
    failures = _gate(results, ratio, max_elapsed_ratio)
    return {
        "fixture": {
            "challenges": CHALLENGE_COUNT,
            "lanes": LANES,
            "episodes": EPISODES,
            "runtime_wait_seconds": turn_delay_seconds,
            "model": "gpt-5.6-luna",
            "reasoning_effort": "xhigh",
            "fallback": False,
            "max_elapsed_ratio": max_elapsed_ratio,
        },
        "arms": results,
        "ratio": ratio,
        "gate": {"passed": not failures, "failures": failures},
    }


def main() -> int:
    result = run_benchmark()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
