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
    config = replace(_config(tmp_path), episodes_per_challenge=2)
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
def test_distinct_verified_candidates_are_fenced_independent_of_completion_order(
    tmp_path: Path, delayed_lane: int
) -> None:
    candidates = (
        "INCYPHER{verified_identity_a}",
        "INCYPHER{verified_identity_b}",
    )
    board = BoundaryBoard([_challenge(1)])
    config = replace(_config(tmp_path), episodes_per_challenge=2, submit_candidates=True)

    report = asyncio.run(
        DurableJobControl.drive(
            config,
            board=board,
            runtime=VerifierDisagreementRuntime(candidates, delayed_lane),
        )
    )
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert board.submissions == []
    assert view.verified_candidate_count == 2
    assert view.pending_candidate_count == 0
    assert sum(job.role == "verifier" and job.state == "candidate" for job in view.jobs) == 2
    store = StateStore(config.state_path)
    assert store.verified_candidate(report.run_id, 1) is None
    assert all(
        not store.candidate_is_verified(report.run_id, 1, candidate) for candidate in candidates
    )
    store.close()


@pytest.mark.parametrize("matches", (True, False))
def test_submission_requires_same_run_private_verification(tmp_path: Path, matches: bool) -> None:
    candidate = "INCYPHER{verification_gates_submission}"
    verifier = candidate if matches else "INCYPHER{independent_mismatch}"
    board = BoundaryBoard([_challenge(1)])
    runtime = CandidateVerifierRuntime(candidate, verifier)
    config = replace(_config(tmp_path), episodes_per_challenge=2, submit_candidates=True)

    report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)

    assert board.submissions == ([(1, candidate)] if matches else [])
    assert view.verified_candidate_count == int(matches)
    assert view.pending_candidate_count == int(not matches)
    with sqlite3.connect(config.state_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM candidate_proposals").fetchone()[0] == 2


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
    board = BoundaryBoard([_challenge(1), _challenge(2)])
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
    board = BoundaryBoard([_challenge(1)])
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
