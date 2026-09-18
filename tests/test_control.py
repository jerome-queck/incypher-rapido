from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import textwrap
import threading
import urllib.parse
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import rapido.orchestrator as orchestrator_module
from rapido.board import BoardError, Challenge, Verdict
from rapido.config import RuntimeConfig
from rapido.control import DurableJobControl
from rapido.evidence import EvidenceError, project_tool_observation
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


class UnreadBoundaryBoard(BoundaryBoard):
    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        self.submissions.append((challenge_id, candidate))
        return Verdict("unread", "ambiguous response", 200)


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


class ManagedInstanceBoundaryBoard(BoundaryBoard):
    def __init__(self, challenges: list[Challenge]) -> None:
        super().__init__(challenges)
        self.active: set[int] = set()
        self.instance_calls: list[tuple[str, int]] = []
        self.peak_active = 0

    def instance(self, method: str, challenge_id: int) -> dict[str, object]:
        self.instance_calls.append((method, challenge_id))
        if method == "POST":
            assert not self.active
            self.active.add(challenge_id)
            self.peak_active = max(self.peak_active, len(self.active))
        elif method == "DELETE":
            self.active.discard(challenge_id)
            return {"success": True, "status": 200, "connection_info": "", "until": None}
        elif method != "GET":
            raise AssertionError("unexpected instance method")
        if challenge_id in self.active:
            return {
                "success": True,
                "status": 200,
                "connection_info": "http://127.0.0.1:8135/",
                "until": 100,
            }
        return {"success": False, "status": 404, "connection_info": "", "until": None}


class FailedCreateBoundaryBoard(ManagedInstanceBoundaryBoard):
    def __init__(self, challenges: list[Challenge], *, invalid_connection: bool) -> None:
        super().__init__(challenges)
        self.invalid_connection = invalid_connection

    def instance(self, method: str, challenge_id: int) -> dict[str, object]:
        if method == "POST" and not self.invalid_connection:
            self.instance_calls.append((method, challenge_id))
            return {"success": False, "status": 429, "connection_info": "", "until": None}
        result = super().instance(method, challenge_id)
        if challenge_id in self.active and self.invalid_connection:
            result["connection_info"] = "invalid connection"
        return result


class WrongThenCorrectBoundaryBoard(BoundaryBoard):
    def __init__(self, challenges: list[Challenge], correct: str) -> None:
        super().__init__(challenges)
        self.correct = correct

    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        self.submissions.append((challenge_id, candidate))
        outcome = "correct" if candidate == self.correct else "incorrect"
        return Verdict(outcome, outcome, 200)


class AlreadySolvedBoundaryBoard(BoundaryBoard):
    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        self.submissions.append((challenge_id, candidate))
        return Verdict("already_solved", "already solved", 200)


class WorkspaceAndCleanupFailureBoard(BoundaryBoard):
    def __init__(self, challenges: list[Challenge]) -> None:
        super().__init__(challenges)
        self.get_calls = 0
        self.post_calls = 0
        self.download_calls = 0

    def download(self, file_ref: str, destination: Path, *, byte_limit: int) -> dict[str, object]:
        del file_ref
        self.download_calls += 1
        if self.download_calls == 1:
            destination.write_bytes(b"fixture")
            return {"bytes": min(7, byte_limit), "redirect_hosts": ["board"]}
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
        self.calls: list[tuple[dict[str, object], dict[str, object]]] = []
        self.validated: list[tuple[str, str]] = []

    async def start(self) -> None:
        self.started = True

    async def validate_model(self, model: str, effort: str) -> None:
        self.validated.append((model, effort))

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        del workspace
        document = json.loads(prompt)
        self.calls.append((document, dict(kwargs)))
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


class FatalEvidenceBoundaryRuntime(UnsolvedBoundaryRuntime):
    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        del workspace, prompt, kwargs
        raise EvidenceError("synthetic lane finalization failure")


class MixedBoundaryRuntime(BoundaryRuntime):
    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        if json.loads(prompt)["lane"] == 0:
            return await super().solve(workspace, prompt, **kwargs)
        return await UnsolvedBoundaryRuntime.solve(self, workspace, prompt, **kwargs)


class PersistentPrimaryRuntime(BoundaryRuntime):
    def __init__(self, candidate: str, checkpoint: str) -> None:
        super().__init__(candidate)
        self.checkpoint = checkpoint
        self.continuations: list[dict[str, object]] = []

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        del workspace
        document = json.loads(prompt)
        callback = kwargs.get("continuation_callback")
        if kwargs.get("model") != "gpt-daybreak-blue-latest" or not callable(callback):
            return await UnsolvedBoundaryRuntime.solve(self, Path(), prompt, **kwargs)
        self.calls.append((document, dict(kwargs)))
        checkpoint_candidate = (
            "INCYPHER{answer}" if self.checkpoint == "ineligible" else self._candidate
        )
        checkpoint_digest = hashlib.sha256(checkpoint_candidate.encode()).hexdigest()
        checkpoint_calls: list[dict[str, object]] = []
        if self.checkpoint == "supplied":
            checkpoint_calls.append(
                {
                    "name": "inspect_file",
                    "success": True,
                    "source_bound": True,
                    "candidate_sensitive": True,
                    "candidate_sha256s": [],
                    "supplied_candidate_sha256s": [checkpoint_digest],
                    "host_observation": project_tool_observation(
                        "inspect_file",
                        success=True,
                        source_bound=True,
                        candidate_sensitive=True,
                        supplied_candidate_sha256s=(checkpoint_digest,),
                    ),
                }
            )
        elif self.checkpoint == "incomplete":
            checkpoint_calls.append({"name": "inspect_file", "success": "unknown"})
        checkpoint = type(
            "PrimaryCheckpoint",
            (),
            {
                "status": "completed",
                "text": json.dumps(
                    {
                        "status": "candidate" if self.checkpoint != "unsolved" else "unsolved",
                        "candidate": (
                            checkpoint_candidate if self.checkpoint != "unsolved" else None
                        ),
                        "confidence": 0.5,
                        "summary": "unfinished primary checkpoint",
                        "evidence": ["hypothesis"] if self.checkpoint != "unsolved" else [],
                        "next_steps": ["continue"],
                    }
                ),
                "tool_calls": checkpoint_calls,
            },
        )()
        follow_up = callback(checkpoint, float(kwargs["timeout"]) - 1.0)
        assert isinstance(follow_up, str)
        self.continuations.append(json.loads(follow_up))
        candidate_digest = hashlib.sha256(self._candidate.encode()).hexdigest()
        observation = project_tool_observation(
            "inspect_file",
            success=True,
            source_bound=True,
            candidate_sensitive=True,
            candidate_sha256s=(candidate_digest,),
        )
        candidate = type(
            "PrimaryCandidate",
            (),
            {
                "status": "completed",
                "text": json.dumps(
                    {
                        "status": "candidate",
                        "candidate": self._candidate,
                        "confidence": 0.9,
                        "summary": "primary derived a source-bound candidate",
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
        assert callback(candidate, float(kwargs["timeout"]) - 2.0) is None
        return candidate


class CandidateVerifierRuntime(BoundaryRuntime):
    def __init__(self, candidate: str, verifier_candidate: str | None) -> None:
        super().__init__(candidate)
        self.verifier_candidate = verifier_candidate
        self.prompts: list[tuple[dict[str, object], dict[str, object]]] = []

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        document = json.loads(prompt)
        self.prompts.append((document, dict(kwargs)))
        role = document["control_route"]["role"]
        selected = self._candidate if role == "specialist" else self.verifier_candidate
        if document["lane"] != 0 or selected is None:
            return await UnsolvedBoundaryRuntime.solve(self, workspace, prompt, **kwargs)
        candidate_digest = hashlib.sha256(selected.encode()).hexdigest()
        observation = project_tool_observation(
            "inspect_file",
            success=True,
            source_bound=True,
            candidate_sensitive=True,
            candidate_sha256s=(candidate_digest,),
        )
        return type(
            "CandidateVerifierTurn",
            (),
            {
                "status": "completed",
                "text": json.dumps(
                    {
                        "status": "candidate",
                        "candidate": selected,
                        "confidence": 0.9,
                        "summary": f"{role} independently derived {selected}",
                        "evidence": [
                            selected,
                            hashlib.sha256(selected.encode()).hexdigest(),
                            base64.b64encode(selected.encode()).decode(),
                        ],
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


class ReflectedCandidateRuntime(BoundaryRuntime):
    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        turn = await super().solve(workspace, prompt, **kwargs)
        digest = hashlib.sha256(self._candidate.encode()).hexdigest()
        turn.tool_calls[0]["supplied_candidate_sha256s"] = [digest]
        turn.tool_calls[0]["host_observation"] = project_tool_observation(
            "inspect_file",
            success=True,
            source_bound=True,
            candidate_sensitive=True,
            candidate_sha256s=(digest,),
            supplied_candidate_sha256s=(digest,),
        )
        return turn


class IncompleteHostEvidenceRuntime(CandidateVerifierRuntime):
    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        turn = await super().solve(workspace, prompt, **kwargs)
        if turn.tool_calls:
            turn.tool_calls[0].pop("host_observation", None)
        return turn


class VerifierDisagreementRuntime(CandidateVerifierRuntime):
    def __init__(self, candidates: tuple[str, str], delayed_lane: int) -> None:
        super().__init__(candidates[0], None)
        self.candidates = candidates
        self.delayed_lane = delayed_lane

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        document = json.loads(prompt)
        lane = document["lane"]
        role = document["control_route"]["role"]
        if lane == self.delayed_lane:
            await asyncio.sleep(0.02)
        selected = self.candidates[lane]
        candidate_digest = hashlib.sha256(selected.encode()).hexdigest()
        observation = project_tool_observation(
            "inspect_file",
            success=True,
            source_bound=True,
            candidate_sensitive=True,
            candidate_sha256s=(candidate_digest,),
        )
        self.prompts.append((document, dict(kwargs)))
        return type(
            "VerifierDisagreementTurn",
            (),
            {
                "status": "completed",
                "text": json.dumps(
                    {
                        "status": "candidate",
                        "candidate": selected,
                        "confidence": 0.9,
                        "summary": f"{role} source-derived candidate",
                        "evidence": ["source bytes independently re-observed"],
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


class CrossChallengeVerifierRuntime(CandidateVerifierRuntime):
    def __init__(self, candidates: dict[int, str]) -> None:
        super().__init__("unused", None)
        self.candidates = candidates

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        document = json.loads(prompt)
        challenge_id = document["challenge"]["id"]
        role = document["control_route"]["role"]
        self._candidate = self.candidates[challenge_id]
        self.verifier_candidate = self.candidates[3 - challenge_id] if role == "verifier" else None
        return await super().solve(workspace, prompt, **kwargs)


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


class LiveHangingBoundaryRuntime(UnsolvedBoundaryRuntime):
    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        if kwargs.get("tool_registry") is None:
            return await super().solve(workspace, prompt, **kwargs)
        await asyncio.sleep(60)
        raise AssertionError("deadline must cancel the live turn")


class ToolRetryMemoryRuntime(UnsolvedBoundaryRuntime):
    def __init__(self) -> None:
        super().__init__("unused")
        self.prompts: list[dict[str, object]] = []

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        document = json.loads(prompt)
        self.prompts.append(document)
        if document["episode"] != 0:
            return await super().solve(workspace, prompt, **kwargs)
        lane = document["lane"]
        observation = project_tool_observation(
            "inspect_file",
            success=True,
            source_bound=True,
            result={"format": f"lane{lane}", "size": lane + 1},
        )
        return type(
            "ToolRetryMemoryTurn",
            (),
            {
                "status": "failed",
                "failure_class": "sandbox_error",
                "text": "",
                "tool_calls": [
                    {
                        "name": "inspect_file",
                        "success": True,
                        "source_bound": True,
                        "candidate_sensitive": False,
                        "candidate_sha256s": [],
                        "supplied_candidate_sha256s": [],
                        "host_observation": observation,
                    }
                ],
            },
        )()


class DynamicPhaseRuntime(UnsolvedBoundaryRuntime):
    def __init__(self) -> None:
        super().__init__("unused")
        self.prompts: list[tuple[dict[str, object], bool]] = []
        self.continuations: list[tuple[str, str, bool]] = []

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        del workspace
        document = json.loads(prompt)
        self.prompts.append((document, kwargs.get("tool_registry") is not None))
        self.continuations.append(
            (
                str(document["execution_phase"]),
                str(kwargs.get("model")),
                callable(kwargs.get("continuation_callback")),
            )
        )
        observation = project_tool_observation(
            "inspect_file",
            success=True,
            source_bound=True,
            result={"format": "fixture", "size": document["lane"] + 1},
        )
        await asyncio.sleep(0.01)
        return type(
            "DynamicPhaseTurn",
            (),
            {
                "status": "completed",
                "text": json.dumps(
                    {
                        "status": "unsolved",
                        "candidate": None,
                        "confidence": 0.3,
                        "summary": "source inventory completed",
                        "evidence": ["fixture inspected"],
                        "next_steps": ["test the strongest hypothesis against the target"],
                    }
                ),
                "tool_calls": [
                    {
                        "name": "inspect_file",
                        "success": True,
                        "source_bound": True,
                        "candidate_sensitive": False,
                        "candidate_sha256s": [],
                        "supplied_candidate_sha256s": [],
                        "host_observation": observation,
                    }
                ],
            },
        )()


class DynamicTimeoutRecoveryRuntime(DynamicPhaseRuntime):
    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        document = json.loads(prompt)
        if document["control_route"]["tactic"] != "instance_enabled_follow_on":
            return await super().solve(workspace, prompt, **kwargs)
        self.prompts.append((document, kwargs.get("tool_registry") is not None))
        observation = project_tool_observation(
            "inspect_file",
            success=True,
            source_bound=True,
            result={"format": "fixture", "size": document["lane"] + 1},
        )
        error = TimeoutError("synthetic productive timeout")
        error.result = type(
            "DynamicTimeoutTurn",
            (),
            {
                "tool_calls": [
                    {
                        "name": "inspect_file",
                        "success": True,
                        "source_bound": True,
                        "candidate_sensitive": False,
                        "candidate_sha256s": [],
                        "supplied_candidate_sha256s": [],
                        "host_observation": observation,
                    }
                ]
            },
        )()
        raise error


class DynamicLocalFailureRuntime(DynamicPhaseRuntime):
    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        if kwargs.get("tool_registry") is not None:
            return await super().solve(workspace, prompt, **kwargs)
        del workspace
        document = json.loads(prompt)
        self.prompts.append((document, False))
        return type(
            "DynamicLocalFailureTurn",
            (),
            {
                "status": "failed",
                "failure_class": "sandbox_error",
                "text": "",
                "tool_calls": [],
            },
        )()


class WrongThenRecoveryRuntime(UnsolvedBoundaryRuntime):
    def __init__(self, wrongs: tuple[str, ...], correct: str) -> None:
        super().__init__("unused")
        self.wrongs = wrongs
        self.correct = correct

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        document = json.loads(prompt)
        episode = int(document["episode"])
        lane = int(document["lane"])
        if episode == 0 and lane != 0:
            return await super().solve(workspace, prompt, **kwargs)
        candidate = self.wrongs[episode] if episode < len(self.wrongs) else self.correct
        candidate_digest = hashlib.sha256(candidate.encode()).hexdigest()
        observation = project_tool_observation(
            "inspect_file",
            success=True,
            source_bound=True,
            candidate_sensitive=True,
            candidate_sha256s=(candidate_digest,),
        )
        await asyncio.sleep(0.01)
        return type(
            "WrongThenRecoveryTurn",
            (),
            {
                "status": "completed",
                "text": json.dumps(
                    {
                        "status": "candidate",
                        "candidate": candidate,
                        "confidence": 0.9,
                        "summary": "source-derived candidate",
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


def _config(tmp_path: Path) -> RuntimeConfig:
    (tmp_path / "auth").mkdir(exist_ok=True)
    base = RuntimeConfig.from_env(
        {
            "RAPIDO_STATE_PATH": str(tmp_path / "state.sqlite3"),
            "RAPIDO_WORK_ROOT": str(tmp_path / "work"),
            "RAPIDO_CODEX_HOME": str(tmp_path / "auth"),
            "RAPIDO_SUBMIT_CANDIDATES": "false",
            "RAPIDO_MANAGE_DYNAMIC_INSTANCES": "false",
            "RAPIDO_WATCH_BOARD": "false",
            "RAPIDO_ACTIVE_CHALLENGES": "2",
            "RAPIDO_ATTEMPTS_PER_CHALLENGE": "2",
            "RAPIDO_CONCURRENCY": "4",
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


def _limited_challenge(challenge_id: int, *, challenge_type: str = "standard") -> Challenge:
    return replace(_challenge(challenge_id, challenge_type=challenge_type), max_attempts=3)


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
    monitor = DurableJobControl.monitor_snapshot(config.state_path, run_id=report.run_id)

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
    monitor_encoded = json.dumps(asdict(monitor), sort_keys=True)
    assert candidate not in monitor_encoded
    assert monitor.status == "completed"
    assert monitor.terminal_challenge_ids == (1,)
    assert monitor.tool_call_count == 2


def test_monitor_does_not_report_a_finished_attempt_as_running(tmp_path: Path) -> None:
    config = _config(tmp_path)
    state = StateStore(config.state_path)
    run_id = "monitor-finished-lane"
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=800)
    state.start_run(run_id, config.public_record())
    state.upsert_challenge(1, "A", "crypto", "standard", 100)
    state.record_control_catalogue(run_id, [(0, 1, True)])
    state.admit_control_wave(run_id, 1, 0, 0, 1, route)
    state.start_control_wave(run_id, 1, 0)
    attempt_id = f"{run_id}:1:0:0"
    state.start_attempt(
        attempt_id,
        run_id,
        1,
        0,
        0,
        "gpt-daybreak-blue-latest",
        "xhigh",
        require_control_assignment=True,
    )
    state.finish_attempt(attempt_id, "unsolved")
    state.close()

    monitor = DurableJobControl.monitor_snapshot(config.state_path, run_id=run_id)
    assert monitor.schema == "rapido.monitor.v2"
    assert monitor.active_challenge_ids == ()
    assert monitor.running_lanes == ()
    assert monitor.completed_waiting_lane_count == 1
    assert monitor.terminal_challenge_ids == ()


@pytest.mark.parametrize(
    "closing_kind", ("instance_lease_deferred", "instance_lease_admission_expired")
)
def test_monitor_does_not_leave_closed_instance_waiter_waiting(
    tmp_path: Path, closing_kind: str
) -> None:
    config = _config(tmp_path)
    state = StateStore(config.state_path)
    run_id = f"monitor-{closing_kind}"
    route = baseline_route(model=config.model, effort=config.reasoning_effort, attempt_seconds=800)
    state.start_run(run_id, config.public_record())
    state.upsert_challenge(1, "A", "web", "dynamic_iac", 100)
    state.initialize_control_catalogue(
        run_id,
        [(0, 1, True)],
        1,
        route,
        (("lead", config.model, config.reasoning_effort),),
        {1: "a" * 64},
    )
    state.event(
        run_id,
        "instance_lease_waiting",
        {"challenge_id": 1, "episode": 0, "ticket": 0},
    )
    state.event(
        run_id,
        closing_kind,
        {"challenge_id": 1, "episode": 0, "ticket": 0},
    )

    monitor = DurableJobControl.monitor_snapshot(config.state_path, run_id=run_id)

    assert monitor.instance_waiting_challenge_ids == ()
    assert monitor.queued_challenge_ids == (1,)
    state.close()


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


def test_mixed_peer_defaults_cover_all_fifteen_with_two_daybreak_leads_each(
    tmp_path: Path,
) -> None:
    runtime = BoundaryRuntime("INCYPHER{mixed-peer-fixture}")
    config = replace(
        _config(tmp_path),
        active_challenges=5,
        attempts_per_challenge=4,
        concurrency=20,
        lead_lanes=2,
        specialist_reasoning_efforts=("max", "xhigh", "max"),
    )
    challenges = [_challenge(challenge_id) for challenge_id in range(1, 16)]

    report = asyncio.run(
        DurableJobControl.drive(config, board=BoundaryBoard(challenges), runtime=runtime)
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert view.catalogue_count == view.initial_coverage_count == 15
    assert set(runtime.validated) == {
        ("gpt-daybreak-blue-latest", "xhigh"),
        ("gpt-5.6-luna", "xhigh"),
        ("gpt-5.6-luna", "max"),
    }
    for challenge_id in range(1, 16):
        jobs = [job for job in view.jobs if job.challenge_id == challenge_id]
        assert [(job.agent_role, job.model, job.effort) for job in jobs] == [
            ("lead", "gpt-daybreak-blue-latest", "xhigh"),
            ("lead", "gpt-daybreak-blue-latest", "xhigh"),
            ("specialist", "gpt-5.6-luna", "max"),
            ("specialist", "gpt-5.6-luna", "xhigh"),
        ]
        assert all(
            job.started_sequence is not None and job.closed_sequence is not None for job in jobs
        )
    for document, kwargs in runtime.calls:
        lane = int(document["lane"])
        job = next(
            item
            for item in view.jobs
            if item.challenge_id == int(document["challenge"]["id"]) and item.lane == lane
        )
        assert document["agent_role"] == job.agent_role
        assert kwargs["model"] == job.model
        assert kwargs["reasoning_effort"] == job.effort
        assert document["control_route"]["model"] == job.model
        assert document["control_route"]["effort"] == job.effort
        if job.agent_role == "lead":
            assert "same cumulative solve window" in document["persistent_window"]
            assert callable(kwargs["continuation_callback"])
        else:
            assert "persistent_window" not in document
            assert kwargs["continuation_callback"] is None


def test_focus_order_and_value_scale_initial_attempt_time_without_narrowing_coverage(
    tmp_path: Path,
) -> None:
    challenges = [
        replace(_challenge(1), value=100),
        replace(_challenge(2), value=500),
        replace(_challenge(3), value=300),
        replace(_challenge(4), value=100, solved=True),
    ]
    runtime = BoundaryRuntime("INCYPHER{budget-fixture}")
    config = replace(
        _config(tmp_path),
        run_seconds=7_200,
        attempt_seconds=800,
        focus_challenge_ids=(3,),
    )

    report = asyncio.run(
        DurableJobControl.drive(config, board=BoundaryBoard(challenges), runtime=runtime)
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    first_rank = {job.challenge_id: job.catalogue_rank for job in view.jobs if job.episode == 0}
    assert sorted(first_rank, key=first_rank.__getitem__) == [3, 1, 2, 4]
    budgets = {
        int(document["challenge"]["id"]): int(document["control_route"]["attempt_seconds"])
        for document, _ in runtime.calls
    }
    assert budgets[1] == budgets[4] == 800
    assert budgets[2] == 1_800
    assert budgets[3] == 1_800
    assert view.initial_coverage_count == 4


def test_missing_focus_id_fails_before_any_solver_work(tmp_path: Path) -> None:
    runtime = BoundaryRuntime("unused")
    config = replace(_config(tmp_path), focus_challenge_ids=(99,))

    with pytest.raises(BoardError, match="focus challenge ids are absent"):
        asyncio.run(
            DurableJobControl.drive(
                config,
                board=BoundaryBoard([_challenge(1)]),
                runtime=runtime,
            )
        )

    assert runtime.calls == []


def test_idle_watch_appends_and_solves_a_new_challenge_before_original_deadline(
    tmp_path: Path,
) -> None:
    class GrowingBoard(BoundaryBoard):
        def __init__(self) -> None:
            super().__init__([_challenge(1)])
            self.list_calls = 0

        def list_challenges(self) -> list[dict[str, int]]:
            self.list_calls += 1
            if self.list_calls >= 4:
                self._challenges[2] = _challenge(2)
            return super().list_challenges()

    board = GrowingBoard()
    runtime = UnsolvedBoundaryRuntime("unused")
    config = replace(
        _config(tmp_path),
        run_seconds=2.0,
        watch_board=True,
        board_watch_seconds=0.01,
        board_full_refresh_seconds=0.1,
    )

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.status == "completed"
    assert report.challenge_count == 2
    assert view.catalogue_count == view.initial_coverage_count == 2
    assert {job.challenge_id for job in view.jobs} == {1, 2}
    connection = sqlite3.connect(config.state_path)
    try:
        kinds = [row[0] for row in connection.execute("SELECT kind FROM control_events")]
    finally:
        connection.close()
    assert "catalogue_appended" in kinds


def test_idle_watch_requeues_when_attachment_bytes_change_at_same_url(tmp_path: Path) -> None:
    class ChangingFileBoard(BoundaryBoard):
        def __init__(self) -> None:
            super().__init__([_file_challenge(1, challenge_type="standard")])
            self.download_calls = 0

        def download(
            self, file_ref: str, destination: Path, *, byte_limit: int
        ) -> dict[str, object]:
            del file_ref, byte_limit
            self.download_calls += 1
            payload = b"old-material" if self.download_calls == 1 else b"new-material"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
            return {"bytes": len(payload), "redirect_hosts": ["board"]}

    board = ChangingFileBoard()
    config = replace(
        _config(tmp_path),
        run_seconds=2.0,
        watch_board=True,
        board_watch_seconds=0.01,
        board_full_refresh_seconds=0.05,
    )

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=board,
            runtime=UnsolvedBoundaryRuntime("unused"),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.status == "completed"
    assert {job.episode for job in view.jobs} == {0, 1}
    assert board.download_calls >= 3
    with sqlite3.connect(config.state_path) as connection:
        context_episode = connection.execute(
            "SELECT context_episode FROM control_catalogue WHERE run_id=? AND challenge_id=1",
            (report.run_id,),
        ).fetchone()[0]
    assert context_episode == 1


def test_idle_watch_does_not_requeue_unchanged_attachment_bytes(tmp_path: Path) -> None:
    class StableFileBoard(BoundaryBoard):
        def __init__(self) -> None:
            super().__init__([_file_challenge(1, challenge_type="standard")])
            self.download_calls = 0

        def download(
            self, file_ref: str, destination: Path, *, byte_limit: int
        ) -> dict[str, object]:
            del file_ref, byte_limit
            self.download_calls += 1
            payload = b"stable-material"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
            return {"bytes": len(payload), "redirect_hosts": ["board"]}

    board = StableFileBoard()
    config = replace(
        _config(tmp_path),
        run_seconds=2.0,
        watch_board=True,
        board_watch_seconds=0.01,
        board_full_refresh_seconds=0.05,
    )

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=board,
            runtime=UnsolvedBoundaryRuntime("unused"),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.status == "completed"
    assert {job.episode for job in view.jobs} == {0}
    assert board.download_calls >= 2


@pytest.mark.parametrize(
    ("checkpoint", "reason"),
    (
        ("unsolved", "unsolved"),
        ("provenance", "candidate_unobserved"),
        ("ineligible", "candidate_ineligible"),
        ("supplied", "candidate_supplied"),
        ("incomplete", "candidate_evidence_incomplete"),
    ),
)
def test_daybreak_primary_continues_changed_same_session_until_source_bound_candidate(
    tmp_path: Path, checkpoint: str, reason: str
) -> None:
    candidate = "INCYPHER{persistent_primary_source_proof}"
    runtime = PersistentPrimaryRuntime(candidate, checkpoint)
    config = replace(
        _config(tmp_path),
        attempts_per_challenge=4,
        concurrency=4,
        lead_lanes=1,
        episodes_per_challenge=1,
        submit_candidates=True,
    )

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=BoundaryBoard([_challenge(1)]),
            runtime=runtime,
        )
    )

    assert report.solved == 1
    assert len(runtime.continuations) == 1
    follow_up = runtime.continuations[0]
    assert follow_up["label"] == "TRUSTED_PRIMARY_SOLVER_CONTINUATION"
    assert follow_up["continuation_round"] == 1
    assert follow_up["reason"] == reason
    assert follow_up["remaining_milliseconds"] == 14_000
    initial = runtime.calls[0][0]
    assert initial["task"].startswith("Capture the flag for this challenge.")
    assert "same cumulative solve window" in initial["persistent_window"]
    with sqlite3.connect(config.state_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM candidate_proposals").fetchone()[0] == 1
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE kind='primary_candidate_checkpointed'"
            ).fetchone()[0]
            == 1
        )


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


def test_failed_peer_cannot_discard_private_candidate(tmp_path: Path) -> None:
    candidate = "INCYPHER{retained_after_peer_failure}"
    board = BoundaryBoard([_challenge(1)])
    runtime = CandidateVerifierRuntime(candidate, None)
    config = replace(_config(tmp_path), episodes_per_challenge=2)

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.candidates == 1
    assert view.pending_candidate_count == 1
    assert view.verified_candidate_count == 0
    assert {job.role for job in view.jobs} == {"specialist", "verifier"}
    assert board.submissions == []
    with sqlite3.connect(config.state_path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM attempts WHERE candidate IS NOT NULL"
            ).fetchone()[0]
            == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM candidate_proposals").fetchone()[0] == 1


def test_verifier_reobserves_without_candidate_in_prompt(tmp_path: Path) -> None:
    candidate = "INCYPHER{fresh_verifier_reobservation}"
    runtime = CandidateVerifierRuntime(candidate, candidate)
    config = replace(_config(tmp_path), episodes_per_challenge=2)

    report = asyncio.run(
        DurableJobControl.drive(config, board=BoundaryBoard([_challenge(1)]), runtime=runtime)
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert view.pending_candidate_count == 0
    assert view.verified_candidate_count == 1
    assert [(decision.failure_kind, decision.disposition) for decision in view.route_decisions] == [
        ("disagreement", "dispatch")
    ]
    verifier_calls = [
        call for call in runtime.prompts if call[0]["control_route"]["role"] == "verifier"
    ]
    assert verifier_calls
    forbidden = (
        candidate,
        hashlib.sha256(candidate.encode()).hexdigest(),
        candidate.encode().hex(),
        base64.b64encode(candidate.encode()).decode(),
        base64.urlsafe_b64encode(candidate.encode()).decode().rstrip("="),
        urllib.parse.quote(candidate, safe=""),
    )
    assert all(value not in json.dumps(asdict(view), sort_keys=True) for value in forbidden)
    with sqlite3.connect(config.state_path) as connection:
        durable_attempts = json.dumps(
            connection.execute(
                "SELECT summary, evidence_json, next_steps_json, candidate FROM attempts"
            ).fetchall()
        )
        durable_events = json.dumps(
            connection.execute("SELECT kind, data_json FROM events").fetchall()
        )
    assert all(value not in durable_attempts for value in forbidden)
    assert all(value not in durable_events for value in forbidden)
    for document, kwargs in verifier_calls:
        encoded = json.dumps(document, sort_keys=True)
        assert document["prior_attempts"] == []
        assert document["prior_observations"] is None
        assert document["same_run_memory"] == []
        assert all(value not in encoded for value in forbidden)
        assert kwargs["model"] == "gpt-daybreak-blue-latest"
        assert kwargs["reasoning_effort"] == "xhigh"


def test_typed_memory_reuses_verified_cross_lane_host_facts_after_changed_route(
    tmp_path: Path,
) -> None:
    runtime = ToolRetryMemoryRuntime()
    config = replace(
        _config(tmp_path),
        episodes_per_challenge=2,
        memory_arm="typed_challenge_v1",
    )
    report = asyncio.run(
        DurableJobControl.drive(config, board=BoundaryBoard([_challenge(1)]), runtime=runtime)
    )

    assert report.status == "completed"
    successor_prompts = [prompt for prompt in runtime.prompts if prompt["episode"] == 1]
    assert len(successor_prompts) == 2
    for prompt in successor_prompts:
        host_records = [
            record for record in prompt["same_run_memory"] if record["kind"] == "host_observation"
        ]
        assert {record["source_lane"] for record in host_records} == {0, 1}
        assert {record["facts"]["size"] for record in host_records} == {1, 2}
        assert prompt["prior_attempts"] == []
        assert prompt["prior_observations"] is None


def test_wave_failure_fact_is_available_to_each_lane_without_false_lane_attribution(
    tmp_path: Path,
) -> None:
    runtime = ToolRetryMemoryRuntime()
    config = replace(_config(tmp_path), episodes_per_challenge=2, memory_arm="lane_local_v1")
    asyncio.run(
        DurableJobControl.drive(config, board=BoundaryBoard([_challenge(1)]), runtime=runtime)
    )

    successor_prompts = [prompt for prompt in runtime.prompts if prompt["episode"] == 1]
    assert len(successor_prompts) == 2
    for prompt in successor_prompts:
        failures = [record for record in prompt["same_run_memory"] if record["kind"] == "failure"]
        assert len(failures) == 1
        assert failures[0]["source_lane"] == prompt["lane"]


def test_incomplete_host_evidence_cannot_enter_private_vault(tmp_path: Path) -> None:
    candidate = "INCYPHER{unattested_candidate}"
    config = replace(_config(tmp_path), episodes_per_challenge=2, submit_candidates=True)

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=BoundaryBoard([_challenge(1)]),
            runtime=IncompleteHostEvidenceRuntime(candidate, candidate),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert view.pending_candidate_count == view.verified_candidate_count == 0
    assert {job.role for job in view.jobs} == {"specialist"}
    with sqlite3.connect(config.state_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM candidate_proposals").fetchone()[0] == 0


@pytest.mark.parametrize("delayed_lane", (0, 1))
def test_one_fresh_verifier_resolves_disagreement_independent_of_completion_order(
    tmp_path: Path, delayed_lane: int
) -> None:
    candidates = (
        "INCYPHER{verified_identity_a}",
        "INCYPHER{verified_identity_b}",
    )
    board = BoundaryBoard([_limited_challenge(1)])
    config = replace(_config(tmp_path), episodes_per_challenge=2, submit_candidates=True)

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=board,
            runtime=VerifierDisagreementRuntime(candidates, delayed_lane),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert board.submissions == [(1, candidates[0])]
    assert view.verified_candidate_count == 1
    assert view.pending_candidate_count == 1
    assert sum(job.role == "verifier" and job.state == "candidate" for job in view.jobs) == 1
    store = StateStore(config.state_path)
    assert store.verified_candidate(report.run_id, 1) == candidates[0]
    assert store.candidate_is_verified(report.run_id, 1, candidates[0])
    assert not store.candidate_is_verified(report.run_id, 1, candidates[1])
    store.close()


@pytest.mark.parametrize("matches", (True, False))
def test_submission_requires_same_run_private_verification(tmp_path: Path, matches: bool) -> None:
    candidate = "INCYPHER{verification_gates_submission}"
    verifier = candidate if matches else "INCYPHER{independent_mismatch}"
    board = BoundaryBoard([_limited_challenge(1)])
    runtime = CandidateVerifierRuntime(candidate, verifier)
    config = replace(_config(tmp_path), episodes_per_challenge=2, submit_candidates=True)

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert board.submissions == ([(1, candidate)] if matches else [])
    assert view.verified_candidate_count == int(matches)
    assert view.pending_candidate_count == int(not matches)
    with sqlite3.connect(config.state_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM candidate_proposals").fetchone()[0] == 2


def test_first_unlimited_candidate_submits_immediately_without_verifier(tmp_path: Path) -> None:
    candidate = "INCYPHER{immediate_unlimited_candidate}"
    board = BoundaryBoard([_challenge(1)])
    config = replace(_config(tmp_path), episodes_per_challenge=3, submit_candidates=True)

    report = asyncio.run(
        DurableJobControl.drive(config, board=board, runtime=MixedBoundaryRuntime(candidate))
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.solved == 1
    assert board.submissions == [(1, candidate)]
    assert {job.role for job in view.jobs} == {"specialist"}
    assert view.verified_candidate_count == 0
    assert view.pending_candidate_count == 0


def test_limited_candidate_waits_for_one_fresh_verifier(tmp_path: Path) -> None:
    candidate = "INCYPHER{peer_agreement_qualification}"
    board = BoundaryBoard([_limited_challenge(1)])
    config = replace(_config(tmp_path), episodes_per_challenge=3, submit_candidates=True)

    report = asyncio.run(
        DurableJobControl.drive(config, board=board, runtime=BoundaryRuntime(candidate))
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.solved == 1
    assert board.submissions == [(1, candidate)]
    assert {job.role for job in view.jobs} == {"specialist", "verifier"}
    assert sum(job.role == "verifier" for job in view.jobs) == 1


def test_repeated_wrong_unlimited_candidates_keep_routing_recovery_until_correct(
    tmp_path: Path,
) -> None:
    wrongs = (
        "INCYPHER{first_hypothesis_wrong}",
        "INCYPHER{second_hypothesis_wrong}",
    )
    correct = "INCYPHER{recovery_peer_agreement}"
    board = WrongThenCorrectBoundaryBoard([_challenge(1)], correct)
    config = replace(_config(tmp_path), episodes_per_challenge=4, submit_candidates=True)

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=board,
            runtime=WrongThenRecoveryRuntime(wrongs, correct),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.solved == 1
    assert board.submissions == [(1, wrongs[0]), (1, wrongs[1]), (1, correct)]
    assert {job.role for job in view.jobs} == {"specialist", "recovery"}
    assert [decision.rule_id for decision in view.route_decisions] == [
        "board_rejection_recovery_v1",
        "board_rejection_recovery_v1",
    ]


@pytest.mark.parametrize(("prior_wrong", "submitted"), ((4, True), (5, False)))
def test_unlimited_candidates_submit_until_five_wrong_then_require_verification(
    tmp_path: Path, prior_wrong: int, submitted: bool
) -> None:
    config = replace(_config(tmp_path), submit_candidates=True)
    challenge = _challenge(1)
    board = BoundaryBoard([challenge])
    store = StateStore(config.state_path)
    run_id = "wrong-threshold-run"
    store.start_run(run_id, config.public_record())
    store.upsert_challenge(1, challenge.name, challenge.category, challenge.type, challenge.value)
    for index in range(prior_wrong):
        store.record_submission(
            run_id,
            1,
            f"INCYPHER{{wrong_{index}}}",
            "incorrect",
            200,
        )

    class AdaptiveOrchestrator(orchestrator_module.Orchestrator):
        _adaptive_control = True

    orchestrator = AdaptiveOrchestrator(config, board, store, UnsolvedBoundaryRuntime("unused"))

    outcome = asyncio.run(
        orchestrator._submit_candidate(
            run_id,
            challenge,
            "INCYPHER{new_source_qualified_candidate}",
            orchestrator_module.time.monotonic() + 10,
        )
    )

    assert board.submissions == (
        [(1, "INCYPHER{new_source_qualified_candidate}")] if submitted else []
    )
    assert outcome == ("solved" if submitted else "candidate")
    store.close()


def test_known_incorrect_candidate_is_not_resubmitted_or_left_candidate_like(
    tmp_path: Path,
) -> None:
    config = replace(_config(tmp_path), submit_candidates=True)
    challenge = _challenge(1)
    board = BoundaryBoard([challenge])
    store = StateStore(config.state_path)
    run_id = "known-wrong-run"
    candidate = "INCYPHER{known_wrong_candidate}"
    store.start_run(run_id, config.public_record())
    store.upsert_challenge(1, challenge.name, challenge.category, challenge.type, challenge.value)
    store.record_submission(run_id, 1, candidate, "incorrect", 200)

    class AdaptiveOrchestrator(orchestrator_module.Orchestrator):
        _adaptive_control = True

    orchestrator = AdaptiveOrchestrator(config, board, store, UnsolvedBoundaryRuntime("unused"))
    outcome = asyncio.run(
        orchestrator._submit_candidate(
            run_id,
            challenge,
            candidate,
            orchestrator_module.time.monotonic() + 10,
        )
    )

    assert outcome == "unsolved"
    assert board.submissions == []
    assert (
        store._connection.execute("SELECT status FROM challenges WHERE id=1").fetchone()[0]
        == "unsolved"
    )
    store.close()


@pytest.mark.parametrize(
    "prior_outcome",
    ("correct", "already_solved", "incorrect"),
)
def test_historical_candidate_effect_does_not_suppress_a_fresh_submission(
    tmp_path: Path, prior_outcome: str
) -> None:
    candidate = "INCYPHER{historical_candidate_identity}"
    challenge = _challenge(1)
    config = replace(
        _config(tmp_path),
        episodes_per_challenge=1,
        submit_candidates=True,
    )
    store = StateStore(config.state_path)
    store.bind_board_identity(1, 2)
    store.start_run("historical-run", config.public_record())
    store.upsert_challenge(1, challenge.name, challenge.category, challenge.type, challenge.value)
    route = baseline_route(
        model=config.model,
        effort=config.reasoning_effort,
        attempt_seconds=config.attempt_seconds,
    )
    store.initialize_control_catalogue(
        "historical-run",
        [(0, 1, True)],
        config.attempts_per_challenge,
        route,
        (("lead", config.model, config.reasoning_effort),) * config.attempts_per_challenge,
        {1: orchestrator_module._challenge_material_sha256(challenge)},
    )
    store.record_submission("historical-run", 1, candidate, prior_outcome, 200)
    store.finish_run("historical-run", "completed")
    store.close()
    board = BoundaryBoard([challenge])

    report = asyncio.run(
        DurableJobControl.drive(config, board=board, runtime=BoundaryRuntime(candidate))
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.solved == 1
    assert report.candidates == 0
    assert report.unsolved == 0
    assert view.pending_candidate_count == 0
    assert board.submissions == [(1, candidate)]


def test_already_solved_candidate_closes_without_wasting_a_verifier(tmp_path: Path) -> None:
    candidate = "INCYPHER{fresh_candidate_for_solved_board_item}"
    board = AlreadySolvedBoundaryBoard([_challenge(1)])
    config = replace(_config(tmp_path), episodes_per_challenge=2, submit_candidates=True)

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=board,
            runtime=CandidateVerifierRuntime(candidate, candidate),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.solved == 0
    assert report.candidates == 1
    assert board.submissions == [(1, candidate)]
    assert {job.role for job in view.jobs} == {"specialist"}
    assert view.pending_candidate_count == 0
    assert view.verified_candidate_count == 0


def test_dynamic_challenges_analyze_locally_then_share_one_leased_instance(
    tmp_path: Path,
) -> None:
    challenges = [
        _challenge(1, challenge_type="dynamic_iac"),
        _challenge(2, challenge_type="dynamic_iac"),
    ]
    board = ManagedInstanceBoundaryBoard(challenges)
    runtime = DynamicPhaseRuntime()
    config = replace(
        _config(tmp_path),
        manage_dynamic_instances=True,
        episodes_per_challenge=2,
    )

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.status == "completed"
    assert board.peak_active == 1
    assert board.active == set()
    post_ids = [challenge_id for method, challenge_id in board.instance_calls if method == "POST"]
    delete_ids = [
        challenge_id for method, challenge_id in board.instance_calls if method == "DELETE"
    ]
    assert sorted(post_ids) == [1, 2]
    assert delete_ids == post_ids
    local = [item for item in runtime.prompts if item[0]["execution_phase"] == "local_analysis"]
    live = [item for item in runtime.prompts if item[0]["execution_phase"] == "shared_instance"]
    assert len(local) == len(live) == 4
    assert all(not has_target for _, has_target in local)
    assert all(has_target for _, has_target in live)
    assert all(document["same_run_memory"] for document, _ in live)
    assert {job.role for job in view.jobs if job.episode == 1} == {"recovery"}
    assert any(
        continued
        for phase, model, continued in runtime.continuations
        if phase == "local_analysis" and model == "gpt-daybreak-blue-latest"
    )
    assert any(
        continued
        for phase, model, continued in runtime.continuations
        if phase == "shared_instance" and model == "gpt-daybreak-blue-latest"
    )


def test_dynamic_waiters_stay_in_five_residencies_and_rotate_the_instance(tmp_path: Path) -> None:
    challenges = [_challenge(value, challenge_type="dynamic_iac") for value in range(1, 7)]
    board = ManagedInstanceBoundaryBoard(challenges)

    class ParkedWaitRuntime(DynamicPhaseRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.local_started: set[int] = set()
            self.first_five_started = asyncio.Event()
            self.all_local_started = asyncio.Event()

        async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
            document = json.loads(prompt)
            challenge_id = int(document["challenge"]["id"])
            if document["execution_phase"] == "local_analysis":
                self.local_started.add(challenge_id)
                if len(self.local_started) >= 5:
                    self.first_five_started.set()
                if challenge_id <= 5:
                    await asyncio.wait_for(self.first_five_started.wait(), timeout=2)
                if self.local_started == set(range(1, 7)):
                    self.all_local_started.set()
            elif challenge_id == 1:
                await asyncio.wait_for(self.all_local_started.wait(), timeout=2)
            return await super().solve(workspace, prompt, **kwargs)

    runtime = ParkedWaitRuntime()
    config = replace(
        _config(tmp_path),
        active_challenges=5,
        attempts_per_challenge=2,
        concurrency=10,
        manage_dynamic_instances=True,
        episodes_per_challenge=2,
        run_seconds=700,
        attempt_seconds=800,
    )

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))

    assert report.status == "completed"
    assert runtime.local_started == set(range(1, 7))
    assert board.peak_active == 1
    assert board.active == set()
    post_ids = [challenge_id for method, challenge_id in board.instance_calls if method == "POST"]
    delete_ids = [
        challenge_id for method, challenge_id in board.instance_calls if method == "DELETE"
    ]
    assert sorted(post_ids) == list(range(1, 7))
    assert delete_ids == post_ids
    connection = sqlite3.connect(config.state_path)
    try:
        events = [
            (row[0], json.loads(row[1]))
            for row in connection.execute(
                "SELECT kind, data_json FROM events WHERE run_id=? ORDER BY sequence",
                (report.run_id,),
            )
        ]
    finally:
        connection.close()
    kinds = [kind for kind, _ in events]
    waits = [data for kind, data in events if kind == "instance_lease_waiting"]
    wait_ids = [data["challenge_id"] for data in waits]
    deferred = [data for kind, data in events if kind == "instance_lease_deferred"]
    grant_ids = [data["challenge_id"] for kind, data in events if kind == "instance_lease_granted"]
    grant_tickets = [data["ticket"] for kind, data in events if kind == "instance_lease_granted"]
    assert len(wait_ids) == len(grant_ids) + len(deferred)
    assert sorted(wait_ids) == sorted([*grant_ids, *(data["challenge_id"] for data in deferred)])
    assert grant_tickets == sorted(grant_tickets)
    assert grant_ids == post_ids
    assert "instance_wait_parked" not in kinds


def test_instance_waiters_yield_slots_to_queued_static_work(tmp_path: Path) -> None:
    challenges = [
        *[_challenge(value, challenge_type="dynamic_iac") for value in range(1, 6)],
        _challenge(6),
    ]
    board = ManagedInstanceBoundaryBoard(challenges)

    class MixedQueueRuntime(DynamicPhaseRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.static_started = asyncio.Event()

        async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
            document = json.loads(prompt)
            challenge_id = int(document["challenge"]["id"])
            if challenge_id == 6:
                self.static_started.set()
            elif document["execution_phase"] == "shared_instance":
                await asyncio.wait_for(self.static_started.wait(), timeout=2)
            return await super().solve(workspace, prompt, **kwargs)

    runtime = MixedQueueRuntime()
    config = replace(
        _config(tmp_path),
        active_challenges=5,
        attempts_per_challenge=2,
        concurrency=10,
        manage_dynamic_instances=True,
        episodes_per_challenge=2,
    )

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))

    assert report.status == "completed"
    assert runtime.static_started.is_set()
    assert board.peak_active == 1
    assert board.active == set()


def test_persistent_scheduler_requeues_unresolved_past_episode_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator_module, "MIN_MEANINGFUL_ATTEMPT_SECONDS", 0.05)
    config = replace(
        _config(tmp_path),
        active_challenges=1,
        attempts_per_challenge=1,
        concurrency=1,
        episodes_per_challenge=1,
        run_seconds=0.25,
        watch_board=True,
    )

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=BoundaryBoard([_challenge(1)]),
            runtime=UnsolvedBoundaryRuntime("unused"),
        )
    )
    with sqlite3.connect(config.state_path) as connection:
        max_episode = connection.execute(
            "SELECT MAX(episode) FROM control_jobs WHERE run_id=?", (report.run_id,)
        ).fetchone()[0]
        closed = connection.execute(
            "SELECT COUNT(*) FROM events WHERE run_id=? AND kind='challenge_engagement_closed'",
            (report.run_id,),
        ).fetchone()[0]

    assert report.status == "deadline"
    assert max_episode > config.episodes_per_challenge
    assert closed == 0


def test_active_watch_appends_new_work_while_prior_challenge_remains_unresolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator_module, "MIN_MEANINGFUL_ATTEMPT_SECONDS", 0.05)

    class GrowingBoard(BoundaryBoard):
        def __init__(self) -> None:
            super().__init__([_challenge(1)])
            self.list_calls = 0

        def list_challenges(self) -> list[dict[str, int]]:
            self.list_calls += 1
            if self.list_calls >= 4:
                self._challenges[2] = _challenge(2)
            return super().list_challenges()

    config = replace(
        _config(tmp_path),
        active_challenges=2,
        attempts_per_challenge=1,
        concurrency=2,
        episodes_per_challenge=1,
        run_seconds=0.3,
        watch_board=True,
        board_watch_seconds=0.01,
    )

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=GrowingBoard(),
            runtime=UnsolvedBoundaryRuntime("unused"),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.status == "deadline"
    assert view.catalogue_count == 2
    assert {job.challenge_id for job in view.jobs} == {1, 2}


def test_instance_waiter_crossing_admission_floor_never_starts_late_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator_module, "MIN_MEANINGFUL_ATTEMPT_SECONDS", 0.5)
    challenges = [_challenge(value, challenge_type="dynamic_iac") for value in (1, 2)]
    board = ManagedInstanceBoundaryBoard(challenges)

    class SlowLiveRuntime(DynamicPhaseRuntime):
        async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
            document = json.loads(prompt)
            if document["execution_phase"] == "shared_instance":
                await asyncio.sleep(0.4)
            return await super().solve(workspace, prompt, **kwargs)

    config = replace(
        _config(tmp_path),
        active_challenges=2,
        attempts_per_challenge=2,
        concurrency=4,
        manage_dynamic_instances=True,
        run_seconds=0.8,
        watch_board=True,
    )

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=SlowLiveRuntime()))

    posts = [call for call in board.instance_calls if call[0] == "POST"]
    assert report.status == "deadline"
    assert len(posts) == 1
    assert board.active == set()


def test_dynamic_productive_timeout_releases_then_reacquires_for_changed_recovery(
    tmp_path: Path,
) -> None:
    challenge = _challenge(1, challenge_type="dynamic_iac")
    board = ManagedInstanceBoundaryBoard([challenge])
    runtime = DynamicTimeoutRecoveryRuntime()
    config = replace(
        _config(tmp_path),
        active_challenges=1,
        attempts_per_challenge=4,
        concurrency=4,
        lead_lanes=2,
        specialist_reasoning_efforts=("max", "xhigh", "max"),
        manage_dynamic_instances=True,
        episodes_per_challenge=3,
        run_seconds=1_200,
    )

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.status == "completed"
    assert [call for call in board.instance_calls if call[0] == "POST"] == [
        ("POST", 1),
        ("POST", 1),
    ]
    assert [call for call in board.instance_calls if call[0] == "DELETE"] == [
        ("DELETE", 1),
        ("DELETE", 1),
    ]
    recovery_jobs = [job for job in view.jobs if job.episode == 2]
    assert [(job.model, job.effort) for job in recovery_jobs] == [
        ("gpt-daybreak-blue-latest", "xhigh"),
        ("gpt-daybreak-blue-latest", "xhigh"),
        ("gpt-5.6-luna", "max"),
        ("gpt-5.6-luna", "xhigh"),
    ]
    recovery_prompts = [document for document, _ in runtime.prompts if document["episode"] == 2]
    assert len(recovery_prompts) == 4
    assert all(document["same_run_memory"] for document in recovery_prompts)


@pytest.mark.parametrize("invalid_connection", (False, True))
def test_dynamic_create_failure_is_not_retried_unchanged(
    tmp_path: Path, invalid_connection: bool
) -> None:
    dynamic = _challenge(1, challenge_type="dynamic_iac")
    board = FailedCreateBoundaryBoard([dynamic], invalid_connection=invalid_connection)
    config = replace(
        _config(tmp_path),
        manage_dynamic_instances=True,
        episodes_per_challenge=3,
    )

    report = asyncio.run(
        DurableJobControl.drive(config, board=board, runtime=DynamicPhaseRuntime())
    )

    assert report.status == "completed"
    assert [call for call in board.instance_calls if call[0] == "POST"] == [("POST", 1)]
    assert board.active == set()


def test_dynamic_local_failure_changes_local_strategy_without_wasting_an_instance(
    tmp_path: Path,
) -> None:
    dynamic = _challenge(1, challenge_type="dynamic_iac")
    board = ManagedInstanceBoundaryBoard([dynamic])
    runtime = DynamicLocalFailureRuntime()
    config = replace(
        _config(tmp_path),
        manage_dynamic_instances=True,
        episodes_per_challenge=3,
    )

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))

    assert report.status == "completed"
    phases = [(document["execution_phase"], document["episode"]) for document, _ in runtime.prompts]
    assert phases[:2] == [("local_analysis", 0), ("local_analysis", 0)]
    assert all(phase == "local_analysis" for phase, _ in phases)
    assert [call for call in board.instance_calls if call[0] == "POST"] == []
    assert board.active == set()


def test_limited_dynamic_candidate_gets_a_fresh_instance_for_verifier(tmp_path: Path) -> None:
    candidate = "INCYPHER{limited_dynamic_verified}"
    dynamic = replace(
        _challenge(1, challenge_type="dynamic_iac"),
        max_attempts=3,
    )
    board = ManagedInstanceBoundaryBoard([dynamic])
    runtime = CandidateVerifierRuntime(candidate, candidate)
    config = replace(
        _config(tmp_path),
        manage_dynamic_instances=True,
        episodes_per_challenge=3,
        submit_candidates=True,
    )

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.solved == 1
    assert board.submissions == [(1, candidate)]
    assert [call for call in board.instance_calls if call[0] == "POST"] == [
        ("POST", 1),
        ("POST", 1),
    ]
    assert [call for call in board.instance_calls if call[0] == "DELETE"] == [
        ("DELETE", 1),
        ("DELETE", 1),
    ]
    assert {job.role for job in view.jobs} == {"specialist", "recovery", "verifier"}
    auxiliary = [
        (document["control_route"]["role"], kwargs["tool_registry"] is not None)
        for document, kwargs in runtime.prompts
        if document["control_route"]["role"] in {"recovery", "verifier"}
    ]
    assert {role for role, _ in auxiliary} == {"recovery", "verifier"}
    assert all(has_target for _, has_target in auxiliary)


@pytest.mark.parametrize(
    ("candidate", "description"),
    (
        ("INCYPHER{answer}", "derive the value"),
        ("INCYPHER{description_decoy}", "ignore INCYPHER{description_decoy}"),
    ),
)
def test_placeholder_and_description_decoys_never_enter_vault(
    tmp_path: Path, candidate: str, description: str
) -> None:
    challenge = replace(_challenge(1), description=description)
    runtime = CandidateVerifierRuntime(candidate, candidate)
    config = replace(_config(tmp_path), episodes_per_challenge=2, submit_candidates=True)

    report = asyncio.run(
        DurableJobControl.drive(config, board=BoundaryBoard([challenge]), runtime=runtime)
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert view.pending_candidate_count == view.verified_candidate_count == 0
    assert {job.role for job in view.jobs} == {"specialist"}
    with sqlite3.connect(config.state_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM candidate_proposals").fetchone()[0] == 0


def test_model_supplied_reflection_never_enters_vault(tmp_path: Path) -> None:
    candidate = "INCYPHER{reflected_model_input}"
    config = replace(_config(tmp_path), episodes_per_challenge=2, submit_candidates=True)

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=BoundaryBoard([_challenge(1)]),
            runtime=ReflectedCandidateRuntime(candidate),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert view.pending_candidate_count == view.verified_candidate_count == 0
    assert {job.role for job in view.jobs} == {"specialist"}
    with sqlite3.connect(config.state_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM candidate_proposals").fetchone()[0] == 0


def test_cross_challenge_verifier_values_cannot_qualify(tmp_path: Path) -> None:
    candidates = {
        1: "INCYPHER{challenge_one_private}",
        2: "INCYPHER{challenge_two_private}",
    }
    board = BoundaryBoard([_limited_challenge(1), _limited_challenge(2)])
    runtime = CrossChallengeVerifierRuntime(candidates)
    config = replace(_config(tmp_path), episodes_per_challenge=2, submit_candidates=True)

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert board.submissions == []
    assert view.pending_candidate_count == 2
    assert view.verified_candidate_count == 0


def test_prior_run_candidate_cannot_qualify_current_run(tmp_path: Path) -> None:
    prior = "INCYPHER{prior_run_private_value}"
    current = "INCYPHER{current_run_private_value}"
    board = BoundaryBoard([_limited_challenge(1)])
    config = replace(_config(tmp_path), episodes_per_challenge=2, submit_candidates=True)

    first_report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=board,
            runtime=CandidateVerifierRuntime(prior, None),
        )
    )
    second_report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=board,
            runtime=CandidateVerifierRuntime(current, prior),
        )
    )

    first = DurableJobControl.inspect(config.state_path, run_id=first_report.run_id)
    second = DurableJobControl.inspect(config.state_path, run_id=second_report.run_id)
    assert first.pending_candidate_count == second.pending_candidate_count == 1
    assert first.verified_candidate_count == second.verified_candidate_count == 0
    assert board.submissions == []


def test_pending_effect_count_is_global_when_inspecting_prior_or_current_run(
    tmp_path: Path,
) -> None:
    candidate = "INCYPHER{ambiguous-control-effect}"
    board = AmbiguousBoundaryBoard([_challenge(1)])
    config = replace(_config(tmp_path), episodes_per_challenge=2, submit_candidates=True)

    with pytest.raises(orchestrator_module.RecoveryBlocked, match="explicit reconciliation"):
        asyncio.run(
            DurableJobControl.drive(config, board=board, runtime=BoundaryRuntime(candidate))
        )
    first = DurableJobControl.inspect(config.state_path)
    with pytest.raises(orchestrator_module.RecoveryBlocked, match="explicit reconciliation"):
        asyncio.run(
            DurableJobControl.drive(config, board=board, runtime=BoundaryRuntime(candidate))
        )
    second = DurableJobControl.inspect(config.state_path)
    assert first.run_id == second.run_id
    assert first.status == second.status == "running"
    assert first.pending_submission_count == second.pending_submission_count == 1
    assert board.submissions == [(1, candidate)]


def test_unread_effect_is_reported_and_never_resubmitted_on_resume(tmp_path: Path) -> None:
    candidate = "INCYPHER{unread-control-effect}"
    board = UnreadBoundaryBoard([_challenge(1)])
    config = replace(_config(tmp_path), episodes_per_challenge=2, submit_candidates=True)

    with pytest.raises(orchestrator_module.RecoveryBlocked, match="explicit reconciliation"):
        asyncio.run(
            DurableJobControl.drive(config, board=board, runtime=BoundaryRuntime(candidate))
        )
    first = DurableJobControl.inspect(config.state_path)
    monitor = DurableJobControl.monitor_snapshot(config.state_path, run_id=first.run_id)
    with sqlite3.connect(config.state_path) as connection:
        status = connection.execute("SELECT status FROM submission_intents").fetchone()[0]

    with pytest.raises(orchestrator_module.RecoveryBlocked, match="explicit reconciliation"):
        asyncio.run(
            DurableJobControl.drive(config, board=board, runtime=BoundaryRuntime(candidate))
        )
    second = DurableJobControl.inspect(config.state_path)

    assert status == "unread"
    assert first.run_id == second.run_id
    assert first.pending_submission_count == second.pending_submission_count == 1
    assert monitor.pending_submission_count == 1
    assert board.submissions == [(1, candidate)]


def test_indeterminate_cleanup_poison_is_durable_and_fences_reassignment(
    tmp_path: Path,
) -> None:
    board = IndeterminateCleanupBoundaryBoard([_challenge(2, challenge_type="dynamic_iac")])
    config = replace(_config(tmp_path), manage_dynamic_instances=True, episodes_per_challenge=2)

    with pytest.raises(BoardError, match="cleanup remained indeterminate"):
        asyncio.run(
            DurableJobControl.drive(config, board=board, runtime=UnsolvedBoundaryRuntime("unused"))
        )
    first = DurableJobControl.inspect(config.state_path)
    assert first.owned_instance_count == 1
    assert first.status == "failed"


def test_deadline_never_hides_indeterminate_instance_cleanup(tmp_path: Path) -> None:
    board = IndeterminateCleanupBoundaryBoard([_challenge(2, challenge_type="dynamic_iac")])
    config = replace(
        _config(tmp_path),
        manage_dynamic_instances=True,
        episodes_per_challenge=2,
        run_seconds=0.5,
    )

    with pytest.raises(BoardError, match="cleanup remained indeterminate"):
        asyncio.run(
            DurableJobControl.drive(
                config,
                board=board,
                runtime=LiveHangingBoundaryRuntime("unused"),
            )
        )
    view = DurableJobControl.inspect(config.state_path)
    assert view.status == "failed"
    assert view.owned_instance_count == 1
    assert board.active


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
    assert {(job.challenge_id, job.catalogue_rank) for job in view.jobs} == {(1, 0)}


def test_fatal_lane_error_terminalizes_attempts_and_seals_missing_evidence(tmp_path: Path) -> None:
    config = replace(_config(tmp_path), episodes_per_challenge=1)

    with pytest.raises(EvidenceError, match="synthetic lane finalization failure"):
        asyncio.run(
            DurableJobControl.drive(
                config,
                board=BoundaryBoard([_challenge(1)]),
                runtime=FatalEvidenceBoundaryRuntime("unused"),
            )
        )

    view = DurableJobControl.inspect(config.state_path)
    assert view.status == "failed"
    assert all(job.state == "interrupted" for job in view.jobs)
    with sqlite3.connect(config.state_path) as connection:
        attempt_count = connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        assert attempt_count > 0
        assert (
            connection.execute("SELECT COUNT(*) FROM attempts WHERE status='running'").fetchone()[0]
            == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM evidence_manifests").fetchone()[0] == (
            attempt_count
        )


def test_unsolved_analysis_routes_to_typed_recovery_and_config_changes_change_routes(
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
    retry_jobs = [job for job in first.jobs if job.phase == "retry"]
    assert len(retry_jobs) == 2
    assert {job.role for job in retry_jobs} == {"recovery"}
    assert [(item.failure_kind, item.disposition) for item in first.route_decisions] == [
        ("tool", "dispatch"),
        ("tool", "contain"),
    ]

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


def test_quota_successor_preserves_the_exact_mixed_peer_roster(tmp_path: Path) -> None:
    path = tmp_path / "private" / "state.sqlite3"
    state = StateStore(path)
    run_id = "2" * 32
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=300)
    assignments = (
        ("lead", "gpt-daybreak-blue-latest", "xhigh"),
        ("specialist", "gpt-5.6-luna", "max"),
        ("specialist", "gpt-5.6-luna", "xhigh"),
        ("specialist", "gpt-5.6-luna", "max"),
    )
    try:
        state.start_run(run_id, {})
        state.upsert_challenge(1, "fixture", "crypto", "standard", 100)
        state.record_control_catalogue(run_id, [(1, 1, True)])
        state.admit_control_wave(run_id, 1, 0, 1, 4, route, assignments)
        state.start_control_wave(run_id, 1, 0)
        for lane, (_, model, effort) in enumerate(assignments):
            attempt_id = f"{run_id}:1:0:{lane}"
            state.start_attempt(attempt_id, run_id, 1, 0, lane, model, effort)
            state.finish_attempt(attempt_id, "failed", failure_class="rate_limit_exceeded")

        decision = state.finish_and_decide_control_wave(
            run_id=run_id,
            challenge_id=1,
            source_episode=0,
            next_episode=1,
            catalogue_rank=1,
            lanes=4,
            terminal="error",
            attempts_remaining=True,
            remaining_milliseconds=180_000,
        )
        assert decision is not None and decision.rule_id == "quota_bounded_wait_v1"
        retry = [
            job for job in DurableJobControl.inspect(path, run_id=run_id).jobs if job.episode == 1
        ]
        assert [(job.agent_role, job.model, job.effort) for job in retry] == list(assignments)
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
    with pytest.raises(BoardError, match="cleanup remained indeterminate"):
        asyncio.run(
            DurableJobControl.drive(
                config,
                board=board,
                runtime=UnsolvedBoundaryRuntime("unused"),
            )
        )
    view = DurableJobControl.inspect(config.state_path)
    assert view.status == "failed"
    assert {job.episode for job in view.jobs} == {0, 1}
    assert board.post_calls == 1
    assert board.download_calls == 2
    assert board.get_calls >= 3
    assert view.owned_instance_count == 1
    assert all(job.started_sequence is not None for job in view.jobs if job.episode == 0)
    assert all(job.started_sequence is None for job in view.jobs if job.episode == 1)


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


def test_no_tool_progress_cancels_lane_and_routes_changed_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator_module, "_NO_PROGRESS_SECONDS", 0.02)
    config = replace(_config(tmp_path), episodes_per_challenge=2)

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=BoundaryBoard([_challenge(1)]),
            runtime=HangingBoundaryRuntime("unused"),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert report.status == "completed"
    assert [(item.failure_kind, item.disposition) for item in view.route_decisions] == [
        ("tool", "dispatch"),
        ("tool", "contain"),
    ]
    with sqlite3.connect(config.state_path) as connection:
        assert {
            row[0]
            for row in connection.execute(
                "SELECT failure_class FROM attempts WHERE run_id=?", (report.run_id,)
            )
        } == {"no_progress"}


@pytest.mark.parametrize("candidate_checkpoint", [False, True])
def test_restart_closes_jobs_left_open_by_process_loss(
    tmp_path: Path, candidate_checkpoint: bool
) -> None:
    config = replace(_config(tmp_path), active_challenges=1, concurrency=2)
    code = textwrap.dedent(
        """
        import asyncio
        import hashlib
        import json
        import os
        from dataclasses import replace
        from pathlib import Path

        from rapido.board import Challenge, Verdict
        from rapido.config import RuntimeConfig
        from rapido.control import DurableJobControl
        from rapido.evidence import project_tool_observation

        class Board:
            timeout = 0.01
            def identity(self): return {"id": 1, "team_id": 2}
            def anonymous_identity_is_rejected(self): return True
            def list_challenges(self): return [{"id": 1}, {"id": 2}]
            def challenge(self, challenge_id):
                return Challenge(challenge_id, f"Crash {challenge_id}", "crypto", "standard",
                                 "derive", 100, ("fixture-file",), False, 0, 0, None, None)
            def download(self, file_ref, destination, *, byte_limit):
                destination.write_bytes(b"fixture")
                return {"bytes": min(7, byte_limit), "redirect_hosts": ["board"]}
            def submit(self, challenge_id, candidate): return Verdict("correct", "ok", 200)

        class Runtime:
            async def start(self): pass
            async def solve(self, workspace, prompt, **kwargs):
                if json.loads(prompt)["lane"] == 1:
                    return type("Turn", (), {
                        "status": "completed",
                        "text": json.dumps({
                            "status": "unsolved", "candidate": None, "confidence": 0.2,
                            "summary": "terminal lane committed", "evidence": [], "next_steps": []
                        }),
                        "tool_calls": [],
                    })()
                candidate_checkpoint = os.environ["CRASH_CANDIDATE"] == "1"
                candidate = "INCYPHER{candidate_survives_process_loss}"
                candidate_digest = hashlib.sha256(candidate.encode()).hexdigest()
                checkpoint = type("Turn", (), {
                    "status": "completed",
                    "text": json.dumps({
                        "status": "candidate" if candidate_checkpoint else "unsolved",
                        "candidate": candidate if candidate_checkpoint else None,
                        "confidence": 0.9 if candidate_checkpoint else 0.2,
                        "summary": "primary checkpoint survived", "evidence": ["local branch"],
                        "next_steps": ["test the other branch"]
                    }),
                    "tool_calls": [{
                        "name": "inspect_file", "success": True, "source_bound": True,
                        "candidate_sensitive": candidate_checkpoint,
                        "candidate_sha256s": [candidate_digest] if candidate_checkpoint else [],
                        "supplied_candidate_sha256s": [],
                        "host_observation": project_tool_observation(
                            "inspect_file", success=True, source_bound=True,
                            candidate_sensitive=candidate_checkpoint,
                            candidate_sha256s=(candidate_digest,) if candidate_checkpoint else (),
                            result={"format": "text", "size": 7}
                        ),
                    }],
                })()
                follow_up = kwargs["continuation_callback"](checkpoint, 14.0)
                assert (follow_up is None) is candidate_checkpoint
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
            "RAPIDO_ATTEMPTS_PER_CHALLENGE": "2",
            "RAPIDO_CONCURRENCY": "2",
            "RAPIDO_EPISODES_PER_CHALLENGE": "1",
            "RAPIDO_ATTEMPT_SECONDS": "600",
                "RAPIDO_RUN_SECONDS": "60",
                "RAPIDO_WATCH_BOARD": "false",
            })
        config = replace(config, attempt_seconds=15)
        asyncio.run(DurableJobControl.drive(config, board=Board(), runtime=Runtime()))
        """
    )
    environment = dict(os.environ)
    environment.update(
        {
            "CRASH_STATE": str(config.state_path),
            "CRASH_WORK": str(config.work_root),
            "CRASH_AUTH": str(config.codex_home),
            "CRASH_CANDIDATE": "1" if candidate_checkpoint else "0",
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
    with sqlite3.connect(config.state_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM candidate_proposals").fetchone()[0] == int(
            candidate_checkpoint
        )

    class RecoveryRuntime(UnsolvedBoundaryRuntime):
        def __init__(self) -> None:
            super().__init__("unused")
            self.documents: list[dict[str, object]] = []

        async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
            self.documents.append(json.loads(prompt))
            return await super().solve(workspace, prompt, **kwargs)

    runtime = RecoveryRuntime()
    resumed_challenges = [
        replace(
            _challenge(challenge_id),
            name=f"Crash {challenge_id}",
            description="derive",
            files=("fixture-file",),
        )
        for challenge_id in (1, 2)
    ]
    changed_runtime = BoundaryRuntime("unused")
    with pytest.raises(orchestrator_module.RecoveryBlocked, match="material changed"):
        asyncio.run(
            DurableJobControl.drive(
                config,
                board=BoundaryBoard(
                    [
                        replace(challenge, description=f"{challenge.description} changed")
                        for challenge in resumed_challenges
                    ]
                ),
                runtime=changed_runtime,
            )
        )
    assert not changed_runtime.started
    assert changed_runtime.closed

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=BoundaryBoard(resumed_challenges),
            runtime=runtime,
        )
    )
    recovered = DurableJobControl.inspect(config.state_path, run_id=crashed.run_id)
    assert report.run_id == crashed.run_id
    assert recovered.status == "completed"
    expected_jobs = [
        (1, 0, 0, "interrupted"),
        (1, 0, 1, "unsolved"),
        (2, 0, 0, "unsolved"),
        (2, 0, 1, "unsolved"),
    ]
    expected_jobs.extend(
        [(1, 1, 0, "unsolved")]
        if candidate_checkpoint
        else [(1, 1, 0, "unsolved"), (1, 1, 1, "unsolved")]
    )
    assert [
        (job.challenge_id, job.episode, job.lane, job.state) for job in recovered.jobs
    ] == expected_jobs
    assert all(job.closed_sequence is not None for job in recovered.jobs)
    recovery_documents = [
        document
        for document in runtime.documents
        if document["challenge"]["id"] == 1 and document["episode"] == 1
    ]
    assert len(recovery_documents) == (1 if candidate_checkpoint else 2)
    expected_role = "verifier" if candidate_checkpoint else "recovery"
    assert all(document["agent_role"] == expected_role for document in recovery_documents)
    if not candidate_checkpoint:
        assert all(document["same_run_memory"] for document in recovery_documents)
        primary_recovery = next(
            document for document in recovery_documents if document["lane"] == 0
        )
        assert any(
            record.get("summary") == "primary checkpoint survived"
            for record in primary_recovery["same_run_memory"]
        )
        assert any(
            record.get("kind") == "host_observation"
            and record.get("tool") == "inspect_file"
            and record.get("facts", {}).get("format") == "text"
            for record in primary_recovery["same_run_memory"]
        )
    engagement_order: list[tuple[int, int]] = []
    for document in runtime.documents:
        key = (int(document["challenge"]["id"]), int(document["episode"]))
        if not engagement_order or engagement_order[-1] != key:
            engagement_order.append(key)
    assert engagement_order == [(2, 0), (1, 1)]


def test_restart_keeps_original_wall_deadline_and_starts_no_solver(tmp_path: Path) -> None:
    config = replace(_config(tmp_path), active_challenges=1, concurrency=2)
    store = StateStore(config.state_path)
    store.start_run("deadline-run", config.public_record())
    fixture = _challenge(1)
    store.upsert_challenge(1, fixture.name, fixture.category, fixture.type, fixture.value)
    store.record_control_catalogue("deadline-run", [(0, 1, True)])
    store.admit_control_wave(
        "deadline-run",
        1,
        0,
        0,
        config.attempts_per_challenge,
        baseline_route(
            model=config.model,
            effort=config.reasoning_effort,
            attempt_seconds=config.attempt_seconds,
        ),
        (("lead", config.model, config.reasoning_effort),) * 2,
    )
    expired = (datetime.now(UTC) - timedelta(seconds=config.run_seconds + 1)).isoformat()
    with store.transaction() as connection:
        connection.execute("UPDATE runs SET started_at=? WHERE id='deadline-run'", (expired,))
    store.close()

    runtime = BoundaryRuntime("unused")
    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=BoundaryBoard([_challenge(1)]),
            runtime=runtime,
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id="deadline-run")

    assert report.run_id == "deadline-run"
    assert report.status == view.status == "deadline"
    assert not runtime.started
    assert runtime.closed
    assert {job.state for job in view.jobs} == {"interrupted"}


@pytest.mark.parametrize("expired", [False, True])
def test_restart_finalizes_fully_closed_run_without_starting_runtime(
    tmp_path: Path, expired: bool
) -> None:
    config = replace(_config(tmp_path), active_challenges=1, concurrency=2)
    challenge = _challenge(1)
    store = StateStore(config.state_path)
    store.start_run("closed-run", config.public_record())
    store.upsert_challenge(
        challenge.id,
        challenge.name,
        challenge.category,
        challenge.type,
        challenge.value,
    )
    route = baseline_route(
        model=config.model,
        effort=config.reasoning_effort,
        attempt_seconds=config.attempt_seconds,
    )
    assignments = (("lead", config.model, config.reasoning_effort),) * 2
    store.record_control_catalogue("closed-run", [(0, 1, True)])
    store.admit_control_wave("closed-run", 1, 0, 0, 2, route, assignments)
    store.start_control_wave("closed-run", 1, 0)
    for lane in range(2):
        attempt_id = f"closed-run:1:0:{lane}"
        store.start_attempt(
            attempt_id,
            "closed-run",
            1,
            0,
            lane,
            config.model,
            config.reasoning_effort,
            require_control_assignment=True,
        )
        store.finish_attempt(attempt_id, "unsolved", summary="closed")
    store.finish_control_wave("closed-run", 1, 0, "unsolved")
    store.set_challenge_status(1, "unsolved")
    if expired:
        started_at = (datetime.now(UTC) - timedelta(seconds=config.run_seconds + 1)).isoformat()
        with store.transaction() as connection:
            connection.execute("UPDATE runs SET started_at=? WHERE id='closed-run'", (started_at,))
    store.close()

    class CatalogueUnavailableBoard(BoundaryBoard):
        def list_challenges(self) -> list[dict[str, int]]:
            raise BoardError("durable closed work must not refetch catalogue")

    runtime = BoundaryRuntime("unused")
    report = asyncio.run(
        DurableJobControl.drive(
            config, board=CatalogueUnavailableBoard([challenge]), runtime=runtime
        )
    )

    assert report.run_id == "closed-run"
    assert report.status == "completed"
    assert report.unsolved == 1
    assert not runtime.started
    assert runtime.closed


@pytest.mark.parametrize("expired", [False, True])
def test_restart_fences_ambiguous_submission_until_explicit_reconciliation(
    tmp_path: Path, expired: bool
) -> None:
    config = replace(
        _config(tmp_path),
        active_challenges=1,
        concurrency=2,
        submit_candidates=True,
    )
    candidate = "INCYPHER{effect-may-have-landed}"
    store = StateStore(config.state_path)
    store.start_run("effect-run", config.public_record())
    store.bind_board_identity(1, 2)
    fixture = _challenge(1)
    store.upsert_challenge(1, fixture.name, fixture.category, fixture.type, fixture.value)
    store.record_control_catalogue("effect-run", [(0, 1, True)])
    store.admit_control_wave(
        "effect-run",
        1,
        0,
        0,
        config.attempts_per_challenge,
        baseline_route(
            model=config.model,
            effort=config.reasoning_effort,
            attempt_seconds=config.attempt_seconds,
        ),
        (("lead", config.model, config.reasoning_effort),) * 2,
    )
    assert store.reserve_submission("effect-run", 1, candidate)
    if expired:
        started_at = (datetime.now(UTC) - timedelta(seconds=config.run_seconds + 1)).isoformat()
        with store.transaction() as connection:
            connection.execute("UPDATE runs SET started_at=? WHERE id='effect-run'", (started_at,))
    store.close()

    board = BoundaryBoard([_challenge(1)])
    blocked_runtime = BoundaryRuntime("unused")
    with pytest.raises(
        orchestrator_module.RecoveryBlocked,
        match="explicit reconciliation",
    ):
        asyncio.run(DurableJobControl.drive(config, board=board, runtime=blocked_runtime))
    blocked = DurableJobControl.inspect(config.state_path, run_id="effect-run")
    assert blocked.status == "running"
    assert not blocked_runtime.started
    assert blocked_runtime.closed
    assert board.submissions == []
    assert blocked.pending_submission_count == 1

    store = StateStore(config.state_path)
    store.reconcile_submission_intent(
        1,
        hashlib.sha256(candidate.encode()).hexdigest(),
        "not_delivered",
    )
    store.close()
    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=board,
            runtime=UnsolvedBoundaryRuntime("unused"),
        )
    )
    assert report.run_id == "effect-run"
    assert report.status == ("deadline" if expired else "completed")
    assert board.submissions == []


def test_pending_submission_does_not_block_unaffected_challenge_recovery(
    tmp_path: Path,
) -> None:
    config = replace(_config(tmp_path), active_challenges=1, concurrency=2, submit_candidates=True)
    candidate = "INCYPHER{effect-may-have-landed}"
    challenges = [_challenge(1), _challenge(2)]
    store = StateStore(config.state_path)
    store.start_run("effect-run", config.public_record())
    store.bind_board_identity(1, 2)
    route = baseline_route(
        model=config.model,
        effort=config.reasoning_effort,
        attempt_seconds=config.attempt_seconds,
    )
    assignments = (("lead", config.model, config.reasoning_effort),) * 2
    for challenge in challenges:
        store.upsert_challenge(
            challenge.id,
            challenge.name,
            challenge.category,
            challenge.type,
            challenge.value,
        )
    store.record_control_catalogue("effect-run", [(0, 1, True), (1, 2, True)])
    for rank, challenge in enumerate(challenges):
        store.admit_control_wave("effect-run", challenge.id, 0, rank, 2, route, assignments)
    store.start_control_wave("effect-run", 1, 0)
    assert store.reserve_submission("effect-run", 1, candidate)
    store.close()

    class RecordingRuntime(UnsolvedBoundaryRuntime):
        def __init__(self) -> None:
            super().__init__("unused")
            self.work: list[tuple[int, int]] = []

        async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
            document = json.loads(prompt)
            self.work.append((int(document["challenge"]["id"]), int(document["episode"])))
            return await super().solve(workspace, prompt, **kwargs)

    board = BoundaryBoard(challenges)
    first_runtime = RecordingRuntime()
    with pytest.raises(orchestrator_module.RecoveryBlocked, match="explicit reconciliation"):
        asyncio.run(DurableJobControl.drive(config, board=board, runtime=first_runtime))
    assert {challenge_id for challenge_id, _ in first_runtime.work} == {2}
    assert board.submissions == []

    store = StateStore(config.state_path)
    store.reconcile_submission_intent(
        1,
        hashlib.sha256(candidate.encode()).hexdigest(),
        "not_delivered",
    )
    store.close()
    second_runtime = RecordingRuntime()
    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=second_runtime))
    assert report.run_id == "effect-run"
    assert report.status == "completed"
    assert {challenge_id for challenge_id, _ in second_runtime.work} == {1}


@pytest.mark.parametrize("expired", [False, True])
def test_restart_removes_receipt_bound_instance_before_starting_solver(
    tmp_path: Path, expired: bool
) -> None:
    config = replace(
        _config(tmp_path),
        active_challenges=1,
        concurrency=2,
        manage_dynamic_instances=True,
    )
    challenge = _challenge(1, challenge_type="dynamic_iac")
    board = ManagedInstanceBoundaryBoard([challenge])
    board.active.add(1)
    receipt = hashlib.sha256(
        json.dumps(
            {
                "connection_info": "http://127.0.0.1:8135/",
                "since": None,
                "until": 100,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    store = StateStore(config.state_path)
    store.start_run("instance-run", config.public_record())
    store.bind_board_identity(1, 2)
    store.upsert_challenge(
        1,
        challenge.name,
        challenge.category,
        challenge.type,
        challenge.value,
    )
    store.record_control_catalogue("instance-run", [(0, 1, True)])
    store.admit_control_wave(
        "instance-run",
        1,
        0,
        0,
        config.attempts_per_challenge,
        baseline_route(
            model=config.model,
            effort=config.reasoning_effort,
            attempt_seconds=config.attempt_seconds,
        ),
        (("lead", config.model, config.reasoning_effort),) * 2,
    )
    store.mark_instance("instance-run", 1, "owned", receipt_sha256=receipt)
    if expired:
        started_at = (datetime.now(UTC) - timedelta(seconds=config.run_seconds + 1)).isoformat()
        with store.transaction() as connection:
            connection.execute(
                "UPDATE runs SET started_at=? WHERE id='instance-run'", (started_at,)
            )
    store.close()

    class OrderedRuntime(UnsolvedBoundaryRuntime):
        async def start(self) -> None:
            assert not board.active
            assert ("DELETE", 1) in board.instance_calls
            await super().start()

    runtime = OrderedRuntime("unused")
    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))

    assert report.run_id == "instance-run"
    assert report.status == ("deadline" if expired else "completed")
    assert runtime.started is (not expired)
    assert runtime.closed
    assert not board.active
    assert ("POST", 1) not in board.instance_calls
    assert DurableJobControl.inspect(config.state_path).owned_instance_count == 0


def test_restart_fences_mismatched_instance_generation_before_solver(tmp_path: Path) -> None:
    config = replace(
        _config(tmp_path),
        active_challenges=1,
        concurrency=2,
        manage_dynamic_instances=True,
    )
    challenge = _challenge(1, challenge_type="dynamic_iac")
    board = ManagedInstanceBoundaryBoard([challenge])
    board.active.add(1)
    store = StateStore(config.state_path)
    store.start_run("instance-run", config.public_record())
    store.bind_board_identity(1, 2)
    store.upsert_challenge(1, challenge.name, challenge.category, challenge.type, challenge.value)
    store.record_control_catalogue("instance-run", [(0, 1, True)])
    store.admit_control_wave(
        "instance-run",
        1,
        0,
        0,
        config.attempts_per_challenge,
        baseline_route(
            model=config.model,
            effort=config.reasoning_effort,
            attempt_seconds=config.attempt_seconds,
        ),
        (("lead", config.model, config.reasoning_effort),) * 2,
    )
    store.mark_instance("instance-run", 1, "owned", receipt_sha256="a" * 64)
    store.close()

    runtime = BoundaryRuntime("unused")
    with pytest.raises(orchestrator_module.RecoveryBlocked, match="indeterminate"):
        asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))

    view = DurableJobControl.inspect(config.state_path, run_id="instance-run")
    assert view.status == "running"
    assert view.owned_instance_count == 1
    assert not runtime.started
    assert runtime.closed
    assert board.active == {1}
    assert ("DELETE", 1) not in board.instance_calls


def test_restart_fences_receiptless_current_instance_before_solver(tmp_path: Path) -> None:
    config = replace(
        _config(tmp_path),
        active_challenges=1,
        concurrency=2,
        manage_dynamic_instances=True,
    )
    challenge = _challenge(1, challenge_type="dynamic_iac")
    board = ManagedInstanceBoundaryBoard([challenge])
    board.active.add(1)
    store = StateStore(config.state_path)
    store.start_run("instance-run", config.public_record())
    store.bind_board_identity(1, 2)
    store.upsert_challenge(1, challenge.name, challenge.category, challenge.type, challenge.value)
    store.record_control_catalogue("instance-run", [(0, 1, True)])
    store.mark_instance("instance-run", 1, "creating")
    store.close()

    runtime = BoundaryRuntime("unused")
    with pytest.raises(orchestrator_module.RecoveryBlocked, match="indeterminate"):
        asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))

    view = DurableJobControl.inspect(config.state_path, run_id="instance-run")
    assert view.status == "running"
    assert view.owned_instance_count == 1
    assert not runtime.started
    assert runtime.closed
    assert board.active == {1}
    assert board.instance_calls == [("GET", 1)]
