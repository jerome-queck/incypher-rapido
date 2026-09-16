"""Inert production-path replay for issue #19's expected-red baseline.

The replay uses the public ``Orchestrator.run`` path, its real episode queue,
``build_turn_prompt``, ``RunEvidence`` projection, and ``StateStore``
transitions. Board and native-runtime adapters are deterministic local fakes:
no socket, model, container, credential, submission, or instance mutation is
available. Synthetic flag-shaped values exist only inside the temporary state
needed to exercise conservative provenance and peer disagreement; no value or
candidate digest is returned by this module.

Exit zero means the current production shortcomings were reproduced safely.
It does not mean issue #19's production acceptance gate passed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import tempfile
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from rapido.board import Challenge, Verdict
from rapido.config import RuntimeConfig
from rapido.evidence import HostObservation, project_tool_observation
from rapido.orchestrator import Orchestrator
from rapido.state import StateStore
from rapido.tools import ToolRegistry

CHALLENGE_COUNT = 15
LANES = 2
MODEL = "gpt-daybreak-blue-latest"
REASONING_EFFORT = "xhigh"
BOARD_CASE_ID = 7
UNFINISHED_RUN_ID = "19".rjust(32, "0")
_SYNTHETIC_PROVENANCE_VALUE = "INCYPHER{offline_replay_provenance_only}"
_SYNTHETIC_DISAGREEMENT_VALUES = (
    "INCYPHER{offline_replay_peer_a_only}",
    "INCYPHER{offline_replay_peer_b_only}",
)


@dataclass(frozen=True)
class FailureFixture:
    name: str
    challenge_id: int
    representative: str
    expected_failure_class: str | None


FAILURE_FIXTURES: tuple[FailureFixture, ...] = (
    FailureFixture("policy", 1, "native cyber-policy stop", "cyber_policy"),
    FailureFixture("provenance", 2, "source-unbound model candidate", "candidate_provenance"),
    FailureFixture("disagreement", 3, "two source-bound unequal candidates", None),
    FailureFixture("timeout", 4, "native turn timeout", "timeout"),
    FailureFixture("tool", 5, "native sandbox/tool failure", "sandbox_error"),
    FailureFixture("quota", 6, "native usage limit", "usage_limit_exceeded"),
    FailureFixture("board", BOARD_CASE_ID, "indeterminate dynamic preflight", None),
    FailureFixture("container", 8, "inert operating-system boundary error", "operating_system"),
)
_FIXTURE_BY_ID = {fixture.challenge_id: fixture for fixture in FAILURE_FIXTURES}


@dataclass(frozen=True)
class _Turn:
    text: str
    status: str = "completed"
    failure_class: str | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class _PromptRecord:
    challenge_id: int
    episode: int
    lane: int
    full_prompt: str
    sanctioned_route: tuple[object, ...]
    strategy_route: tuple[object, ...]
    prior_context_identity: str
    tool_set_identity: str
    budget_identity: float
    deadline_identity: tuple[object, ...]
    prior_attempt_count: int
    prior_manifest_count: int


def _observation_call(
    *,
    success: bool,
    source_bound: bool,
    candidate: str | None = None,
) -> dict[str, Any]:
    candidate_hashes = (hashlib.sha256(candidate.encode("utf-8")).hexdigest(),) if candidate else ()
    observation: HostObservation = project_tool_observation(
        "inspect_file",
        success=success,
        source_bound=source_bound,
        candidate_sha256s=candidate_hashes,
        candidate_sensitive=bool(candidate_hashes),
    )
    return {
        "name": observation.tool,
        "success": observation.success,
        "source_bound": observation.source_bound,
        "candidate_sensitive": observation.candidate_sensitive,
        "candidate_sha256s": list(observation.candidate_sha256s),
        "supplied_candidate_sha256s": list(observation.supplied_candidate_sha256s),
        "host_observation": observation,
    }


def _finding(candidate: str | None = None) -> str:
    return json.dumps(
        {
            "status": "candidate" if candidate else "unsolved",
            "candidate": candidate,
            "confidence": 0.9 if candidate else 0.2,
            "summary": "bounded offline fixture analysis",
            "evidence": ["synthetic source observation"] if candidate else [],
            "next_steps": ["use a materially different route"] if not candidate else [],
        },
        sort_keys=True,
    )


class _InertRuntime:
    """Typed local adapter; it never starts a native process or model."""

    def __init__(self) -> None:
        self.started = False
        self.closed = False
        self.prompts: list[_PromptRecord] = []
        self.candidate_outputs: dict[int, int] = {}
        self.solve_models: list[tuple[str, str]] = []

    async def start(self) -> None:
        self.started = True

    async def solve(self, workspace: Path, prompt: str, **kwargs: Any) -> _Turn:
        document = json.loads(prompt)
        challenge_id = int(document["challenge"]["id"])
        lane = int(document["lane"])
        episode = int(document["episode"])
        model = str(kwargs["model"])
        effort = str(kwargs["reasoning_effort"])
        self.solve_models.append((model, effort))
        prior = document.get("prior_observations")
        manifests = prior.get("manifests", []) if isinstance(prior, dict) else []
        strategy_route = (
            lane,
            document["lineage"],
            document["strategy"],
            document["task"],
            model,
            effort,
            kwargs["developer_instructions"],
            json.dumps(kwargs["output_schema"], sort_keys=True, separators=(",", ":")),
        )
        prior_context_identity = json.dumps(
            {
                "prior_attempts": document["prior_attempts"],
                "prior_observations": prior,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        tool_registry = kwargs.get("tool_registry") or ToolRegistry(workspace)
        tool_set_identity = json.dumps(
            tool_registry.dynamic_tools(), sort_keys=True, separators=(",", ":")
        )
        budget_identity = float(kwargs["timeout"])
        deadline_identity = (
            "native_relative_deadline",
            budget_identity,
            "orchestrator_outer_grace_seconds",
            5,
        )
        sanctioned_route = (
            *strategy_route,
            tool_set_identity,
            budget_identity,
            deadline_identity,
        )
        self.prompts.append(
            _PromptRecord(
                challenge_id=challenge_id,
                episode=episode,
                lane=lane,
                full_prompt=prompt,
                sanctioned_route=sanctioned_route,
                strategy_route=strategy_route,
                prior_context_identity=prior_context_identity,
                tool_set_identity=tool_set_identity,
                budget_identity=budget_identity,
                deadline_identity=deadline_identity,
                prior_attempt_count=len(document["prior_attempts"]),
                prior_manifest_count=len(manifests),
            )
        )
        await asyncio.sleep(0)

        fixture = _FIXTURE_BY_ID.get(challenge_id)
        if fixture is None:
            return _Turn(
                _finding(),
                tool_calls=[_observation_call(success=True, source_bound=True)],
            )
        if fixture.name == "policy":
            return _Turn("", status="failed", failure_class="cyber_policy")
        if fixture.name == "provenance":
            self.candidate_outputs[challenge_id] = self.candidate_outputs.get(challenge_id, 0) + 1
            return _Turn(
                _finding(_SYNTHETIC_PROVENANCE_VALUE),
                tool_calls=[_observation_call(success=True, source_bound=True)],
            )
        if fixture.name == "disagreement":
            candidate = _SYNTHETIC_DISAGREEMENT_VALUES[lane]
            self.candidate_outputs[challenge_id] = self.candidate_outputs.get(challenge_id, 0) + 1
            return _Turn(
                _finding(candidate),
                tool_calls=[
                    _observation_call(success=True, source_bound=True, candidate=candidate),
                ],
            )
        if fixture.name == "timeout":
            raise TimeoutError
        if fixture.name == "tool":
            return _Turn(
                "",
                status="failed",
                failure_class="sandbox_error",
                tool_calls=[_observation_call(success=False, source_bound=True)],
            )
        if fixture.name == "quota":
            return _Turn("", status="failed", failure_class="usage_limit_exceeded")
        if fixture.name == "container":
            raise OSError("inert container-boundary representative")
        if fixture.name == "board" and document["execution_phase"] == "local_analysis":
            return _Turn(
                _finding(),
                tool_calls=[_observation_call(success=True, source_bound=True)],
            )
        raise AssertionError("the Board representative must stop before runtime.solve")

    async def close(self) -> None:
        self.closed = True


class _InertBoard:
    """Local Board protocol fake with one fail-closed dynamic preflight."""

    timeout = 0.01

    def __init__(self) -> None:
        self.challenges = {item.id: item for item in _catalogue()}
        self.instance_calls: list[tuple[str, int]] = []
        self.instance_observations: list[dict[str, object]] = []
        self.submissions: list[tuple[int, str]] = []

    def anonymous_identity_is_rejected(self) -> bool:
        return True

    def identity(self) -> dict[str, int]:
        return {"id": 1, "team_id": 2}

    def list_challenges(self) -> list[dict[str, int]]:
        return [{"id": challenge_id} for challenge_id in sorted(self.challenges)]

    def challenge(self, challenge_id: int) -> Challenge:
        return self.challenges[challenge_id]

    def download(self, file_ref: str, destination: Path, *, byte_limit: int) -> dict[str, Any]:
        del file_ref, destination, byte_limit
        raise AssertionError("offline fixtures have no downloadable files")

    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        self.submissions.append((challenge_id, candidate))
        return Verdict("unread", "offline submission is unavailable", 503)

    def instance(self, method: str, challenge_id: int) -> dict[str, Any]:
        self.instance_calls.append((method, challenge_id))
        self.instance_observations.append(
            {
                "method": method,
                "challenge_id": challenge_id,
                "status": 200,
                "success": False,
                "connection_info_present": False,
            }
        )
        return {
            "success": False,
            "status": 200,
            "connection_info": "",
            "since": None,
            "until": None,
        }


def _catalogue() -> list[Challenge]:
    return [
        Challenge(
            id=challenge_id,
            name=f"Offline fixture {challenge_id}",
            category="misc",
            type="dynamic_iac" if challenge_id == BOARD_CASE_ID else "standard",
            description="Authorized inert replay data; no challenge material or target exists.",
            value=100,
            files=(),
            solved=False,
            max_attempts=0,
            attempts=0,
            timeout=None,
            shared=None,
        )
        for challenge_id in range(1, CHALLENGE_COUNT + 1)
    ]


def _config(root: Path) -> RuntimeConfig:
    auth = root / "auth"
    auth.mkdir(mode=0o700)
    work = root / "work"
    work.mkdir(mode=0o700)
    base = RuntimeConfig.from_env(
        {
            "RAPIDO_STATE_PATH": str(root / "state.sqlite3"),
            "RAPIDO_WORK_ROOT": str(work),
            "RAPIDO_CODEX_HOME": str(auth),
            "RAPIDO_MODEL": MODEL,
            "RAPIDO_REASONING_EFFORT": REASONING_EFFORT,
            "RAPIDO_ACTIVE_CHALLENGES": "1",
            "RAPIDO_ATTEMPTS_PER_CHALLENGE": "2",
            "RAPIDO_CONCURRENCY": "2",
            "RAPIDO_EPISODES_PER_CHALLENGE": "2",
            "RAPIDO_SUBMIT_CANDIDATES": "false",
            "RAPIDO_MANAGE_DYNAMIC_INSTANCES": "true",
            "RAPIDO_PEER_PROFILE": "uniform_v1",
            "RAPIDO_MEMORY_ARM": "lane_local_v1",
        }
    )
    return replace(base, run_seconds=60, attempt_seconds=15)


def _seed_unfinished_row(path: Path, config: RuntimeConfig) -> None:
    state = StateStore(path)
    try:
        state.acquire_supervisor(
            config.codex_home / ".rapido-supervisor.lock",
            config.work_root / ".rapido-work.lock",
        )
        state.start_run(UNFINISHED_RUN_ID, config.public_record())
        state.upsert_challenge(1000, "Unfinished row fixture", "misc", "standard", 0)
        state.start_attempt(
            f"{UNFINISHED_RUN_ID}:1000:0:0",
            UNFINISHED_RUN_ID,
            1000,
            0,
            0,
            MODEL,
            REASONING_EFFORT,
        )
    finally:
        state.close()


def _event_rows(state: StateStore, run_id: str) -> list[dict[str, Any]]:
    rows = state._connection.execute(
        "SELECT sequence, kind, data_json FROM events WHERE run_id=? ORDER BY sequence",
        (run_id,),
    ).fetchall()
    return [
        {
            "sequence": int(row["sequence"]),
            "kind": str(row["kind"]),
            "data": json.loads(row["data_json"]),
        }
        for row in rows
    ]


def _failure_cause(fixture: FailureFixture) -> str:
    if fixture.expected_failure_class is not None:
        return fixture.expected_failure_class
    return "peer_disagreement" if fixture.name == "disagreement" else "board_indeterminate"


_SANCTIONED_ROUTE_AXES = (
    "strategy_repeated",
    "tool_set_repeated",
    "budget_repeated",
    "deadline_repeated",
)
_ROUTE_COMPARISON_KEYS = {
    "scope",
    "lane",
    "sanctioned_route_repeated",
    "full_material_input_repeated",
    "strategy_repeated",
    "prior_context_repeated",
    "tool_set_repeated",
    "budget_repeated",
    "deadline_repeated",
}
_GAP_EVENT_KINDS = {
    "typed_route_decision": "failure_route_decision",
    "private_candidate_retention": "private_candidate_retained",
    "verifier_route": "candidate_verifier_routed",
    "verifier_completion": "candidate_verifier_completed",
    "recovery_terminal": "failure_recovery_terminal",
    "recovery_disposition": "failure_recovery_disposition",
}


def _comparison_sanctioned_route_repeated(comparison: dict[str, Any]) -> bool:
    return all(comparison.get(axis) is True for axis in _SANCTIONED_ROUTE_AXES)


def _comparison_full_material_input_repeated(comparison: dict[str, Any]) -> bool:
    return bool(
        _comparison_sanctioned_route_repeated(comparison)
        and comparison.get("prior_context_repeated") is True
    )


def _event_sequences(
    events: list[dict[str, Any]],
    *,
    kind: str,
    challenge_id: int,
    cause: str | None = None,
    episode: int | None = None,
) -> list[int]:
    return [
        row["sequence"]
        for row in events
        if row["kind"] == kind
        and row["data"].get("challenge_id") == challenge_id
        and (cause is None or row["data"].get("cause") == cause)
        and (episode is None or row["data"].get("episode") == episode)
    ]


def _route_observation(
    challenge_id: int, runtime: _InertRuntime, board: _InertBoard
) -> dict[str, Any]:
    prompts = [item for item in runtime.prompts if item.challenge_id == challenge_id]
    initial = {item.lane: item for item in prompts if item.episode == 0}
    retry = {item.lane: item for item in prompts if item.episode == 1}
    lanes = sorted(set(initial) & set(retry))
    if lanes:
        comparisons = [
            {
                "scope": "lane",
                "lane": lane,
                "sanctioned_route_repeated": initial[lane].sanctioned_route
                == retry[lane].sanctioned_route,
                "full_material_input_repeated": (
                    initial[lane].sanctioned_route == retry[lane].sanctioned_route
                    and initial[lane].prior_context_identity == retry[lane].prior_context_identity
                ),
                "strategy_repeated": initial[lane].strategy_route == retry[lane].strategy_route,
                "prior_context_repeated": initial[lane].prior_context_identity
                == retry[lane].prior_context_identity,
                "tool_set_repeated": initial[lane].tool_set_identity
                == retry[lane].tool_set_identity,
                "budget_repeated": initial[lane].budget_identity == retry[lane].budget_identity,
                "deadline_repeated": initial[lane].deadline_identity
                == retry[lane].deadline_identity,
            }
            for lane in lanes
        ]
        scope = "lanes"
        full_prompt_changed: bool | None = all(
            initial[lane].full_prompt != retry[lane].full_prompt for lane in lanes
        )
    else:
        repeated_preflight = board.instance_calls.count(("GET", challenge_id)) >= 2
        comparisons = [
            {
                "scope": "board_preflight",
                "lane": None,
                "sanctioned_route_repeated": repeated_preflight,
                "full_material_input_repeated": repeated_preflight,
                "strategy_repeated": repeated_preflight,
                "prior_context_repeated": repeated_preflight,
                "tool_set_repeated": repeated_preflight,
                "budget_repeated": repeated_preflight,
                "deadline_repeated": repeated_preflight,
            }
        ]
        scope = "board_preflight"
        full_prompt_changed = None
    return {
        "challenge_id": challenge_id,
        "scope": scope,
        "initial_lanes": sorted(initial),
        "retry_lanes": sorted(retry),
        "full_prompt_changed": full_prompt_changed,
        "comparisons": comparisons,
        "sanctioned_route_repeated": bool(comparisons)
        and any(_comparison_sanctioned_route_repeated(item) for item in comparisons),
        "sanctioned_route_repeat_count": sum(
            _comparison_sanctioned_route_repeated(item) for item in comparisons
        ),
        "retry_prior_attempt_records": sum(item.prior_attempt_count for item in retry.values()),
        "retry_prior_evidence_manifests": sum(item.prior_manifest_count for item in retry.values()),
    }


def _episode_observation(
    state: StateStore,
    run_id: str,
    challenge_id: int,
    episode: int,
    events: list[dict[str, Any]],
    board: _InertBoard,
) -> dict[str, bool]:
    admitted = any(
        row["kind"] == "challenge_episode_admitted"
        and row["data"].get("challenge_id") == challenge_id
        and row["data"].get("episode") == episode
        for row in events
    )
    if challenge_id == BOARD_CASE_ID:
        observations = [
            item
            for item in board.instance_observations
            if item["challenge_id"] == challenge_id
            and item["method"] == "GET"
            and item["status"] == 200
            and item["success"] is False
            and item["connection_info_present"] is False
        ]
        if episode == 0:
            completed = bool(
                observations
                and any(
                    row["kind"] == "challenge_episode_queued"
                    and row["data"].get("challenge_id") == challenge_id
                    and row["data"].get("episode") == 1
                    and row["data"].get("reason") == "error"
                    for row in events
                )
            )
        else:
            status = state._connection.execute(
                "SELECT status FROM challenges WHERE id=?", (challenge_id,)
            ).fetchone()
            completed = bool(len(observations) >= 2 and status["status"] == "error")
    else:
        selected = [
            row
            for row in state.attempts_for_challenge(run_id, challenge_id)
            if row["episode"] == episode
        ]
        terminal_wave = any(
            row["kind"] == "attempt_wave"
            and row["data"].get("challenge_id") == challenge_id
            and row["data"].get("episode") == episode
            for row in events
        )
        completed = bool(
            terminal_wave
            and len(selected) == LANES
            and all(row["status"] != "running" for row in selected)
        )
    return {"admitted": admitted, "completed": admitted and completed}


def _case_report(
    fixture: FailureFixture,
    state: StateStore,
    run_id: str,
    runtime: _InertRuntime,
    board: _InertBoard,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    rows = state.attempts_for_challenge(run_id, fixture.challenge_id)
    initial_rows = [row for row in rows if row["episode"] == 0]
    retry_rows = [row for row in rows if row["episode"] == 1]
    status = state._connection.execute(
        "SELECT status FROM challenges WHERE id=?", (fixture.challenge_id,)
    ).fetchone()["status"]

    def exposes_failure(selected: list[dict[str, Any]]) -> bool:
        if fixture.expected_failure_class is not None:
            return any(row["failure_class"] == fixture.expected_failure_class for row in selected)
        if fixture.name == "disagreement":
            return sum(row["candidate"] is not None for row in selected) == LANES
        return fixture.name == "board" and not selected

    preflight_reads = board.instance_calls.count(("GET", fixture.challenge_id))
    initial_failure = exposes_failure(initial_rows)
    unresolved_retry = exposes_failure(retry_rows)
    if fixture.name == "board":
        initial_failure = initial_failure and preflight_reads >= 1
        unresolved_retry = unresolved_retry and preflight_reads >= 2 and status == "error"
        initial_failure_sequences = [
            row["sequence"]
            for row in events
            if row["kind"] == "challenge_episode_queued"
            and row["data"].get("challenge_id") == fixture.challenge_id
            and row["data"].get("episode") == 1
            and row["data"].get("reason") == "error"
        ]
    else:
        initial_failure_sequences = _event_sequences(
            events,
            kind="attempt_wave",
            challenge_id=fixture.challenge_id,
            episode=0,
        )

    failure_cause = _failure_cause(fixture)
    gap_event_sequences = {
        "typed_route_decision": _event_sequences(
            events,
            kind="failure_route_decision",
            challenge_id=fixture.challenge_id,
            cause=failure_cause,
            episode=1,
        ),
        "private_candidate_retention": _event_sequences(
            events,
            kind="private_candidate_retained",
            challenge_id=fixture.challenge_id,
            cause=(
                "peer_disagreement" if fixture.name == "disagreement" else "candidate_provenance"
            ),
        ),
        "verifier_route": _event_sequences(
            events,
            kind="candidate_verifier_routed",
            challenge_id=fixture.challenge_id,
            cause="peer_disagreement",
        ),
        "verifier_completion": _event_sequences(
            events,
            kind="candidate_verifier_completed",
            challenge_id=fixture.challenge_id,
            cause="peer_disagreement",
        ),
        "recovery_terminal": _event_sequences(
            events,
            kind="failure_recovery_terminal",
            challenge_id=fixture.challenge_id,
            cause=failure_cause,
            episode=1,
        ),
        "recovery_disposition": _event_sequences(
            events,
            kind="failure_recovery_disposition",
            challenge_id=fixture.challenge_id,
            cause=failure_cause,
            episode=1,
        ),
    }
    prompts = [item for item in runtime.prompts if item.challenge_id == fixture.challenge_id]
    return {
        "name": fixture.name,
        "challenge_id": fixture.challenge_id,
        "representative": fixture.representative,
        "failure_cause": failure_cause,
        "challenge_status": str(status),
        "attempt_rows": len(rows),
        "durable_attempt_ids": [row["id"] for row in rows],
        "initial_attempt_ids": [row["id"] for row in initial_rows],
        "retry_attempt_ids": [row["id"] for row in retry_rows],
        "episodes": sorted({int(row["episode"]) for row in rows}),
        "failure_classes": sorted(
            {str(row["failure_class"]) for row in rows if row["failure_class"] is not None}
        ),
        "retry_terminal_failure_classes": sorted(
            {str(row["failure_class"]) for row in retry_rows if row["failure_class"] is not None}
        ),
        "initial_failure_evidence": {
            "event_kind": (
                "challenge_episode_queued" if fixture.name == "board" else "attempt_wave"
            ),
            "event_sequences": initial_failure_sequences,
            "attempt_ids": [row["id"] for row in initial_rows],
        },
        "episode_observation": {
            "initial": _episode_observation(state, run_id, fixture.challenge_id, 0, events, board),
            "retry": _episode_observation(state, run_id, fixture.challenge_id, 1, events, board),
        },
        "gap_event_sequences": gap_event_sequences,
        "candidate_outputs": runtime.candidate_outputs.get(fixture.challenge_id, 0),
        "candidate_rows_retained": sum(row["candidate"] is not None for row in rows),
        "lane_invocations": len(prompts),
        "board_preflight_reads": preflight_reads,
        "board_mutation_calls": sum(
            method in {"POST", "DELETE"} and challenge_id == fixture.challenge_id
            for method, challenge_id in board.instance_calls
        )
        + sum(
            challenge_id == fixture.challenge_id for challenge_id, _candidate in board.submissions
        ),
        "initial_failure_observed": initial_failure,
        "unresolved_after_retry": unresolved_retry,
    }


def _metrics_from_raw(
    route_observations: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    global_gap_event_sequences: dict[str, list[int]],
) -> dict[str, int]:
    metrics = {
        "fixture_count": len(cases),
        "challenge_route_repeats": sum(
            observation["sanctioned_route_repeated"] for observation in route_observations
        ),
        "route_comparison_repeats": sum(
            observation["sanctioned_route_repeat_count"] for observation in route_observations
        ),
        "changed_retry_prompts": sum(
            observation["full_prompt_changed"] is True for observation in route_observations
        ),
        "initial_failures_observed": sum(case["initial_failure_observed"] for case in cases),
        "unresolved_after_retry": sum(case["unresolved_after_retry"] for case in cases),
    }
    metrics.update(
        {f"{name}_events": len(global_gap_event_sequences[name]) for name in _GAP_EVENT_KINDS}
    )
    return metrics


def _lexical_inventory(root: Path) -> dict[str, int]:
    """Count owned paths without following or hiding broken symlinks."""
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        return {"entries": 0, "symlinks": 0, "run_roots": 0, "nested_run_entries": 0}
    if stat.S_ISLNK(root_metadata.st_mode):
        return {"entries": 1, "symlinks": 1, "run_roots": 0, "nested_run_entries": 0}
    if not stat.S_ISDIR(root_metadata.st_mode):
        return {"entries": 1, "symlinks": 0, "run_roots": 0, "nested_run_entries": 0}
    entries = symlinks = run_roots = nested_run_entries = 0
    stack: list[tuple[Path, bool]] = [(root, False)]
    while stack:
        directory, inside_run = stack.pop()
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                metadata = child.stat(follow_symlinks=False)
                is_link = stat.S_ISLNK(metadata.st_mode)
                symlinks += int(is_link)
                child_inside_run = inside_run or child.name.startswith("run-")
                if (
                    not inside_run
                    and child.name.startswith("run-")
                    and stat.S_ISDIR(metadata.st_mode)
                ):
                    run_roots += 1
                elif child_inside_run:
                    nested_run_entries += 1
                if stat.S_ISDIR(metadata.st_mode) and not is_link:
                    stack.append((Path(child.path), child_inside_run))
    return {
        "entries": entries,
        "symlinks": symlinks,
        "run_roots": run_roots,
        "nested_run_entries": nested_run_entries,
    }


def _descriptor_count() -> dict[str, object]:
    """Return a count snapshot only; descriptor identity is deliberately not claimed."""
    for directory in (Path("/proc/self/fd"), Path("/dev/fd")):
        try:
            count = sum(item.name.isdigit() for item in directory.iterdir())
        except OSError:
            continue
        return {"available": True, "source": str(directory), "count": count}
    return {"available": False, "source": None, "count": None}


async def _run_fixture_async() -> dict[str, Any]:
    current = asyncio.current_task()
    tasks_before = set(asyncio.all_tasks())
    descriptor_before = _descriptor_count()
    started = time.perf_counter()
    report: dict[str, Any]
    temporary_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="rapido-issue19-red-") as temporary:
        root = Path(temporary)
        temporary_path = root
        config = _config(root)
        _seed_unfinished_row(config.state_path, config)
        board = _InertBoard()
        runtime = _InertRuntime()
        state = StateStore(config.state_path)
        try:
            run = await Orchestrator(config, board, state, runtime).run()
            events = _event_rows(state, run.run_id)
            admissions = [row for row in events if row["kind"] == "challenge_episode_admitted"]
            initial = [row for row in admissions if row["data"]["episode"] == 0]
            retries = [row for row in admissions if row["data"]["episode"] == 1]
            initial_ids = [int(row["data"]["challenge_id"]) for row in initial]
            retry_ids = [int(row["data"]["challenge_id"]) for row in retries]
            all_initial_before_retry = bool(initial and retries) and max(
                row["sequence"] for row in initial
            ) < min(row["sequence"] for row in retries)
            cases = [
                _case_report(fixture, state, run.run_id, runtime, board, events)
                for fixture in FAILURE_FIXTURES
            ]
            route_observations = [
                _route_observation(challenge_id, runtime, board)
                for challenge_id in sorted(board.challenges)
            ]
            global_gap_event_sequences = {
                name: [row["sequence"] for row in events if row["kind"] == event_kind]
                for name, event_kind in _GAP_EVENT_KINDS.items()
            }
            episode_observations = {
                challenge_id: {
                    episode: _episode_observation(
                        state, run.run_id, challenge_id, episode, events, board
                    )
                    for episode in (0, 1)
                }
                for challenge_id in sorted(board.challenges)
            }
            initial_completed = sum(
                observations[0]["completed"] for observations in episode_observations.values()
            )
            retry_completed = sum(
                observations[1]["completed"] for observations in episode_observations.values()
            )
            unfinished_attempt = state._connection.execute(
                "SELECT status, summary FROM attempts WHERE id=?",
                (f"{UNFINISHED_RUN_ID}:1000:0:0",),
            ).fetchone()
            unfinished_run = state._connection.execute(
                "SELECT status FROM runs WHERE id=?", (UNFINISHED_RUN_ID,)
            ).fetchone()
            recovery_events = state._connection.execute(
                "SELECT COUNT(*) FROM events WHERE run_id=? AND kind='recovery'",
                (UNFINISHED_RUN_ID,),
            ).fetchone()[0]
            state.acquire_supervisor(
                config.codex_home / ".rapido-supervisor.lock",
                config.work_root / ".rapido-work.lock",
            )
            second_recovery = state.recover_interrupted()
            state.release_supervisor()
            integrity = str(state._connection.execute("PRAGMA integrity_check").fetchone()[0])
            evidence_manifests = int(
                state._connection.execute(
                    "SELECT COUNT(*) FROM evidence_manifests WHERE run_id=?", (run.run_id,)
                ).fetchone()[0]
            )
            pending_intents = len(state.pending_submission_intents())
            owned_instances = len(state.owned_instances())
        finally:
            state.close()

        await asyncio.sleep(0)
        new_pending_tasks = [
            task
            for task in asyncio.all_tasks()
            if task is not current and task not in tasks_before and not task.done()
        ]
        workspace = _lexical_inventory(config.work_root)
        descriptor_after = _descriptor_count()
        report = {
            "fixture": {
                "name": "issue19-production-path-red-v2",
                "execution_surfaces": [
                    "Orchestrator.run",
                    "build_turn_prompt",
                    "RunEvidence",
                    "HostObservation",
                    "StateStore",
                    "production episode queue",
                ],
                "configured_model": MODEL,
                "configured_reasoning_effort": REASONING_EFFORT,
                "native_model_invoked": False,
                "fallback_enabled": False,
                "fallback_used": False,
                "network_enabled": False,
                "container_started": False,
                "board_writes_enabled": False,
                "candidate_values_emitted": False,
                "candidate_digests_emitted": False,
            },
            "production_run": {
                "run_id": run.run_id,
                "status": run.status,
                "challenge_count": run.challenge_count,
                "solved": run.solved,
                "candidates": run.candidates,
                "unsolved": run.unsolved,
                "unsupported": run.unsupported,
                "errors": run.errors,
                "overlapping_waves": run.overlapping_waves,
                "runtime_started": runtime.started,
                "runtime_closed": runtime.closed,
                "runtime_solve_calls": len(runtime.prompts),
                "runtime_model_selections": [
                    list(selection) for selection in sorted(set(runtime.solve_models))
                ],
                "board_submission_calls": len(board.submissions),
                "board_instance_reads": sum(
                    method == "GET" for method, _challenge_id in board.instance_calls
                ),
                "board_instance_mutations": sum(
                    method in {"POST", "DELETE"} for method, _challenge_id in board.instance_calls
                ),
                "evidence_manifests": evidence_manifests,
            },
            "coverage": {
                "catalogue_entries": run.challenge_count,
                "initial_admitted": len(initial),
                "initial_completed": initial_completed,
                "retry_admitted": len(retries),
                "retry_completed": retry_completed,
                "initial_order": initial_ids,
                "retry_order": retry_ids,
                "all_initial_admitted_before_first_retry": all_initial_before_retry,
                "episode_observations": [
                    {
                        "challenge_id": challenge_id,
                        "initial": observations[0],
                        "retry": observations[1],
                    }
                    for challenge_id, observations in episode_observations.items()
                ],
                "route_observations": route_observations,
            },
            "cases": cases,
            "gap_event_sequences": global_gap_event_sequences,
            "recovery": {
                "scope": "same-run unfinished durable row",
                "unfinished_attempts_recovered": int(unfinished_attempt["status"] == "interrupted"),
                "unfinished_attempt_status": str(unfinished_attempt["status"]),
                "unfinished_attempt_summary": str(unfinished_attempt["summary"]),
                "unfinished_run_status": str(unfinished_run["status"]),
                "recovery_events": int(recovery_events),
                "second_recovery": second_recovery,
                "same_run_resumed": run.run_id == UNFINISHED_RUN_ID,
                "abrupt_process_crash_exercised": False,
                "container_restart_exercised": False,
            },
            "lifecycle": {
                "sqlite_integrity": integrity,
                "pending_submission_intents": pending_intents,
                "owned_instances": owned_instances,
                "new_pending_async_tasks": len(new_pending_tasks),
                "unrelated_preexisting_tasks_ignored": len(tasks_before - {current}),
                "workspace_entries": workspace["entries"],
                "workspace_symlinks": workspace["symlinks"],
                "empty_run_roots": workspace["run_roots"],
                "nested_run_entries": workspace["nested_run_entries"],
                "descriptor_count_observation": {
                    "before": descriptor_before,
                    "after": descriptor_after,
                    "identity_checked": False,
                    "leak_absence_claimed": False,
                },
            },
            "metrics": _metrics_from_raw(route_observations, cases, global_gap_event_sequences),
            "timing": {"elapsed_seconds": round(time.perf_counter() - started, 6)},
        }
    report["lifecycle"]["temporary_scope_removed"] = bool(
        temporary_path is not None
        and not temporary_path.exists()
        and not temporary_path.is_symlink()
    )
    return report


def _corpus_mapping_satisfied(cases: list[dict[str, Any]]) -> bool:
    expected = {
        (fixture.name, fixture.challenge_id, _failure_cause(fixture))
        for fixture in FAILURE_FIXTURES
    }
    observed = [
        (case.get("name"), case.get("challenge_id"), case.get("failure_cause")) for case in cases
    ]
    return (
        len(observed) == len(expected)
        and len(set(observed)) == len(observed)
        and set(observed) == expected
    )


def _route_observation_satisfied(observation: dict[str, Any]) -> bool:
    required_keys = {
        "challenge_id",
        "scope",
        "initial_lanes",
        "retry_lanes",
        "full_prompt_changed",
        "comparisons",
        "sanctioned_route_repeated",
        "sanctioned_route_repeat_count",
        "retry_prior_attempt_records",
        "retry_prior_evidence_manifests",
    }
    comparisons = observation.get("comparisons", [])
    if set(observation) != required_keys or not comparisons:
        return False
    if any(set(comparison) != _ROUTE_COMPARISON_KEYS for comparison in comparisons):
        return False
    if any(
        comparison["sanctioned_route_repeated"] != _comparison_sanctioned_route_repeated(comparison)
        or comparison["full_material_input_repeated"]
        != _comparison_full_material_input_repeated(comparison)
        for comparison in comparisons
    ):
        return False
    repeated = [
        comparison
        for comparison in comparisons
        if _comparison_sanctioned_route_repeated(comparison)
    ]
    if observation["sanctioned_route_repeated"] is not bool(repeated) or observation[
        "sanctioned_route_repeat_count"
    ] != len(repeated):
        return False
    challenge_id = observation["challenge_id"]
    if challenge_id == BOARD_CASE_ID:
        return bool(
            observation["scope"] == "board_preflight"
            and observation["initial_lanes"] == []
            and observation["retry_lanes"] == []
            and observation["full_prompt_changed"] is None
            and observation["retry_prior_attempt_records"] == 0
            and observation["retry_prior_evidence_manifests"] == 0
            and len(comparisons) == 1
            and comparisons[0]["scope"] == "board_preflight"
            and comparisons[0]["lane"] is None
            and all(comparisons[0][axis] is True for axis in _SANCTIONED_ROUTE_AXES)
            and comparisons[0]["prior_context_repeated"] is True
            and comparisons[0]["full_material_input_repeated"] is True
        )
    return bool(
        observation["scope"] == "lanes"
        and observation["initial_lanes"] == list(range(LANES))
        and observation["retry_lanes"] == list(range(LANES))
        and observation["full_prompt_changed"] is True
        and observation["retry_prior_attempt_records"] == (0 if challenge_id == 3 else LANES)
        and observation["retry_prior_evidence_manifests"] == LANES
        and len(comparisons) == LANES
        and [comparison["lane"] for comparison in comparisons] == list(range(LANES))
        and all(comparison["scope"] == "lane" for comparison in comparisons)
        and all(
            all(comparison[axis] is True for axis in _SANCTIONED_ROUTE_AXES)
            and comparison["prior_context_repeated"] is False
            and comparison["full_material_input_repeated"] is False
            for comparison in comparisons
        )
    )


def _case_satisfied(case: dict[str, Any], run_id: str) -> bool:
    fixture = _FIXTURE_BY_ID.get(case.get("challenge_id"))
    if fixture is None or fixture.name != case.get("name"):
        return False
    expected_initial = [f"{run_id}:{fixture.challenge_id}:0:{lane}" for lane in range(LANES)]
    expected_retry = [f"{run_id}:{fixture.challenge_id}:1:{lane}" for lane in range(LANES)]
    if fixture.name == "board":
        expected_initial = []
        expected_retry = []
    expected_episode_observation = (
        {
            "initial": {"admitted": False, "completed": False},
            "retry": {"admitted": False, "completed": False},
        }
        if fixture.name == "board"
        else {
            "initial": {"admitted": True, "completed": True},
            "retry": {"admitted": True, "completed": True},
        }
    )
    failure_evidence = case["initial_failure_evidence"]
    gap_sequences = case["gap_event_sequences"]
    if (
        case["initial_attempt_ids"] != expected_initial
        or case["retry_attempt_ids"] != expected_retry
        or sorted(case["durable_attempt_ids"]) != sorted([*expected_initial, *expected_retry])
        or failure_evidence["attempt_ids"] != expected_initial
        or len(failure_evidence["event_sequences"]) != 1
        or not isinstance(failure_evidence["event_sequences"][0], int)
        or failure_evidence["event_sequences"][0] <= 0
        or set(gap_sequences) != set(_GAP_EVENT_KINDS)
        or any(gap_sequences.values())
        or case["episode_observation"] != expected_episode_observation
        or case["initial_failure_observed"] is not True
        or case["unresolved_after_retry"] is not True
        or case["board_mutation_calls"] != 0
    ):
        return False
    if fixture.name == "board":
        return bool(
            failure_evidence["event_kind"] == "challenge_episode_queued"
            and case["attempt_rows"] == 0
            and case["episodes"] == []
            and case["lane_invocations"] == 0
            and case["board_preflight_reads"] == 2
            and case["challenge_status"] == "error"
            and not case["failure_classes"]
            and not case["retry_terminal_failure_classes"]
            and case["candidate_outputs"] == 0
            and case["candidate_rows_retained"] == 0
        )
    if (
        failure_evidence["event_kind"] != "attempt_wave"
        or case["attempt_rows"] != LANES * 2
        or case["episodes"] != [0, 1]
        or case["lane_invocations"] != LANES * 2
        or case["board_preflight_reads"] != 0
    ):
        return False
    expected_failure_classes = (
        [fixture.expected_failure_class] if fixture.expected_failure_class is not None else []
    )
    expected_status = "unsolved" if fixture.name in {"provenance", "disagreement"} else "error"
    expected_candidate_outputs = 4 if fixture.name in {"provenance", "disagreement"} else 0
    expected_candidate_rows = 4 if fixture.name == "disagreement" else 0
    return bool(
        case["challenge_status"] == expected_status
        and case["failure_classes"] == expected_failure_classes
        and case["retry_terminal_failure_classes"] == expected_failure_classes
        and case["candidate_outputs"] == expected_candidate_outputs
        and case["candidate_rows_retained"] == expected_candidate_rows
    )


def _expected_red_gate(report: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    cases = report["cases"]
    coverage = report["coverage"]
    routes = coverage["route_observations"]
    run = report["production_run"]

    if not _corpus_mapping_satisfied(cases):
        failures.append("typed failure corpus mapping changed")
    if [item["challenge_id"] for item in routes] != list(range(1, CHALLENGE_COUNT + 1)):
        failures.append("all-15 route observation coverage changed")
    elif any(not _route_observation_satisfied(item) for item in routes):
        failures.append("observed retry route shape or unchanged axes changed")

    expected_ids = list(range(1, CHALLENGE_COUNT + 1))
    episode_observations = coverage["episode_observations"]
    if (
        coverage["catalogue_entries"] != CHALLENGE_COUNT
        or coverage["initial_admitted"] != CHALLENGE_COUNT - 1
        or coverage["initial_completed"] != CHALLENGE_COUNT - 1
        or coverage["retry_admitted"] != CHALLENGE_COUNT - 1
        or coverage["retry_completed"] != CHALLENGE_COUNT - 1
        or coverage["initial_order"] != coverage["retry_order"]
        or sorted(coverage["initial_order"])
        != [challenge_id for challenge_id in expected_ids if challenge_id != BOARD_CASE_ID]
        or coverage["all_initial_admitted_before_first_retry"] is not False
        or [item["challenge_id"] for item in episode_observations] != expected_ids
        or any(
            (
                item["initial"] != {"admitted": False, "completed": False}
                or item["retry"] != {"admitted": False, "completed": False}
            )
            if item["challenge_id"] == BOARD_CASE_ID
            else (
                item["initial"] != {"admitted": True, "completed": True}
                or item["retry"] != {"admitted": True, "completed": True}
            )
            for item in episode_observations
        )
    ):
        failures.append("observed queue admission/completion coverage changed")

    run_id = run.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        failures.append("durable run identifier is absent")
    elif _corpus_mapping_satisfied(cases) and any(
        not _case_satisfied(case, run_id) for case in cases
    ):
        failures.append("failure representative evidence changed")

    raw_gap_sequences = report["gap_event_sequences"]
    if set(raw_gap_sequences) != set(_GAP_EVENT_KINDS) or any(raw_gap_sequences.values()):
        failures.append("current mechanism gaps are no longer all observed")

    recomputed_metrics = _metrics_from_raw(routes, cases, raw_gap_sequences)
    if report["metrics"] != recomputed_metrics:
        failures.append("reported expected-red metrics do not match raw observations")
    if (
        recomputed_metrics["challenge_route_repeats"] != CHALLENGE_COUNT
        or recomputed_metrics["route_comparison_repeats"] != (CHALLENGE_COUNT - 1) * LANES + 1
        or recomputed_metrics["changed_retry_prompts"] != CHALLENGE_COUNT - 1
        or recomputed_metrics["initial_failures_observed"] != len(FAILURE_FIXTURES)
        or recomputed_metrics["unresolved_after_retry"] != len(FAILURE_FIXTURES)
        or any(recomputed_metrics[f"{name}_events"] != 0 for name in _GAP_EVENT_KINDS)
    ):
        failures.append("expected-red metric values changed")

    fixture = report["fixture"]
    expected_fixture = {
        "configured_model": MODEL,
        "configured_reasoning_effort": REASONING_EFFORT,
        "native_model_invoked": False,
        "fallback_enabled": False,
        "fallback_used": False,
        "network_enabled": False,
        "container_started": False,
        "board_writes_enabled": False,
        "candidate_values_emitted": False,
        "candidate_digests_emitted": False,
    }
    observed_solve_calls = sum(
        len(item["initial_lanes"]) + len(item["retry_lanes"]) for item in routes
    )
    if (
        any(fixture.get(name) != value for name, value in expected_fixture.items())
        or run["status"] != "completed"
        or run["challenge_count"] != CHALLENGE_COUNT
        or run["runtime_started"] is not True
        or run["runtime_closed"] is not True
        or run["runtime_model_selections"] != [[MODEL, REASONING_EFFORT]]
        or run["runtime_solve_calls"] <= 0
        or run["runtime_solve_calls"] != observed_solve_calls
        or run["evidence_manifests"] != run["runtime_solve_calls"] + 1
        or run["board_submission_calls"] != 0
        or run["board_instance_mutations"] != 0
        or run["board_instance_reads"] != 2
        or [run[name] for name in ("solved", "candidates", "unsolved", "unsupported", "errors")]
        != [0, 0, 9, 0, 6]
    ):
        failures.append("inert production-run observations changed")

    recovery = report["recovery"]
    if recovery != {
        "scope": "same-run unfinished durable row",
        "unfinished_attempts_recovered": 1,
        "unfinished_attempt_status": "interrupted",
        "unfinished_attempt_summary": "process ended before restart",
        "unfinished_run_status": "completed",
        "recovery_events": 1,
        "second_recovery": 0,
        "same_run_resumed": True,
        "abrupt_process_crash_exercised": False,
        "container_restart_exercised": False,
    }:
        failures.append("limited unfinished-row recovery observation changed")

    lifecycle = report["lifecycle"]
    for name, expected in (
        ("sqlite_integrity", "ok"),
        ("pending_submission_intents", 0),
        ("owned_instances", 0),
        ("new_pending_async_tasks", 0),
        ("workspace_entries", 2),
        ("workspace_symlinks", 0),
        ("empty_run_roots", 1),
        ("nested_run_entries", 0),
        ("temporary_scope_removed", True),
    ):
        if lifecycle.get(name) != expected:
            failures.append(f"lifecycle observation changed: {name}")
    descriptor = lifecycle["descriptor_count_observation"]
    if descriptor["identity_checked"] or descriptor["leak_absence_claimed"]:
        failures.append("descriptor count observation overclaims identity")

    observed_red = bool(
        recomputed_metrics["challenge_route_repeats"] == CHALLENGE_COUNT
        and recomputed_metrics["initial_failures_observed"] == len(FAILURE_FIXTURES)
        and recomputed_metrics["unresolved_after_retry"] == len(FAILURE_FIXTURES)
        and not any(raw_gap_sequences.values())
    )
    return {
        "expected_red": True,
        "observed_red": observed_red,
        "passed": observed_red and not failures,
        "failures": failures,
        "red_signals": recomputed_metrics,
    }


def run_replay() -> dict[str, Any]:
    """Run in a dedicated event loop and return secret-free JSON evidence."""
    report = asyncio.run(_run_fixture_async())
    report["gate"] = _expected_red_gate(report)
    return report


def main() -> int:
    result = run_replay()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
