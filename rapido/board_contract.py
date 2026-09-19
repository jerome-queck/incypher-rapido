"""Benign no-socket Board/controller contract simulator.

This is reliability evidence only. It does not emulate a target, CTFd, discovery, credentials,
or solver capability.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import importlib.util
import json
import math
import re
import stat
import sys
import urllib.parse
from collections import defaultdict, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from .board import BoardClient, BoardError, BoardTransportError, HttpResponse
from .clock import AsyncClock, ManualClock
from .config import RuntimeConfig
from .control import DurableJobControl
from .evidence import EvidenceBatch, HostObservation, RunEvidence, project_tool_observation
from .orchestrator import Orchestrator, _instance_receipt
from .routing import baseline_route
from .solver import build_turn_prompt
from .state import StateStore
from .tools import _error

CONTRACT_SCHEMA = "rapido-benign-board-contract-v1"
SCENARIO_IDS = (
    "distinct_submission_outcomes",
    "ambiguous_write_reconciled_once",
    "transient_read_and_permanent_auth",
    "queued_job_unstarted",
    "fresh_generation_exact_answer",
    "different_answer_separate_axes",
    "changed_bytes_reset_context",
    "watch_change_original_deadline",
    "deadline_cancel_cleanup",
    "serialized_startup_independent_turns",
)

_CLOSED = re.compile(r"[a-z][a-z0-9_]{0,79}")
_FORBIDDEN_VALUE = re.compile(
    r"(?:INCYPHER\{|flag\{|https?://|^[A-Za-z]:[\\/]|^(?:\\\\|//)|^/|"
    r"\b[0-9a-f]{40,64}\b|\b[A-Za-z0-9.-]+:[0-9]{2,5}\b)",
    re.IGNORECASE,
)
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema",
        "evidence_level",
        "clock_mode",
        "requested_seconds",
        "scenario_count",
        "passed_count",
        "passed",
        "correctness_denominator_included",
        "scenarios",
    }
)
_PACKAGED_OFFLINE_PILOT_DIRECTORY = Path("/opt/rapido-eval")
_LOADED_OFFLINE_PILOT: Any | None = None
_SCENARIO_FACT_FIELDS = {
    SCENARIO_IDS[0]: frozenset({"correct", "incorrect", "historical", "historical_not_current"}),
    SCENARIO_IDS[1]: frozenset({"writes", "reconciled", "second_write"}),
    SCENARIO_IDS[2]: frozenset(
        {
            "transient_recovered",
            "auth_http_status",
            "auth_error",
            "attempt_delta",
        }
    ),
    SCENARIO_IDS[3]: frozenset(
        {
            "queued_jobs",
            "started_jobs",
            "attempt_count",
            "submission_count",
            "solve_count",
            "current_verification_count",
        }
    ),
    SCENARIO_IDS[4]: frozenset(
        {
            "fresh_generation",
            "exact_match",
            "current_verification_count",
            "current_generation_match",
        }
    ),
    SCENARIO_IDS[5]: frozenset(
        {
            "exact_match",
            "current_verification_count",
            "old_value_current",
            "new_value_current",
            "method_oracle_match",
            "method_axis",
        }
    ),
    SCENARIO_IDS[6]: frozenset(
        {
            "refreshed",
            "context_advanced",
            "same_reference",
            "material_changed",
            "memory_record_count",
            "prompt_memory_count",
            "old_private_excluded",
        }
    ),
    SCENARIO_IDS[7]: frozenset(
        {
            "change_observed",
            "transient_offset_seconds",
            "change_offset_seconds",
            "deadline_seconds",
            "deadline_unchanged",
        }
    ),
    SCENARIO_IDS[8]: frozenset(
        {
            "status",
            "active_jobs",
            "queued_jobs",
            "pending_writes",
            "owned_instances",
            "workspace_entries",
            "instance_creates",
            "instance_deletes",
            "runtime_cancelled",
            "runtime_closed",
        }
    ),
    SCENARIO_IDS[9]: frozenset(
        {
            "startup_peak",
            "turn_peak",
            "pilot_result_rows",
            "diagnostics_redacted",
            "startup_contract",
            "diagnostics_contract",
        }
    ),
}

_FACT_DOMAINS: dict[str, dict[str, object]] = {
    SCENARIO_IDS[0]: {
        "correct": "bool",
        "incorrect": "bool",
        "historical": "bool",
        "historical_not_current": "bool",
    },
    SCENARIO_IDS[1]: {
        "writes": ("int", 0, 2),
        "reconciled": "bool",
        "second_write": "bool",
    },
    SCENARIO_IDS[2]: {
        "transient_recovered": "bool",
        "auth_http_status": frozenset({401}),
        "auth_error": frozenset({"board_http_401"}),
        "attempt_delta": ("int", 0, 100),
    },
    SCENARIO_IDS[3]: {
        "queued_jobs": ("int", 0, 100),
        "started_jobs": ("int", 0, 100),
        "attempt_count": ("int", 0, 100),
        "submission_count": ("int", 0, 100),
        "solve_count": ("int", 0, 100),
        "current_verification_count": ("int", 0, 100),
    },
    SCENARIO_IDS[4]: {
        "fresh_generation": "bool",
        "exact_match": "bool",
        "current_verification_count": ("int", 0, 100),
        "current_generation_match": "bool",
    },
    SCENARIO_IDS[5]: {
        "exact_match": "bool",
        "current_verification_count": ("int", 0, 100),
        "old_value_current": "bool",
        "new_value_current": "bool",
        "method_oracle_match": "bool",
        "method_axis": frozenset({"synthetic_only"}),
    },
    SCENARIO_IDS[6]: {
        "refreshed": "bool",
        "context_advanced": "bool",
        "same_reference": "bool",
        "material_changed": "bool",
        "memory_record_count": ("int", 0, 100),
        "prompt_memory_count": ("int", 0, 100),
        "old_private_excluded": "bool",
    },
    SCENARIO_IDS[7]: {
        "change_observed": "bool",
        "transient_offset_seconds": ("number", 0, 19_800.001),
        "change_offset_seconds": ("number", 0, 19_800.001),
        "deadline_seconds": ("number", 0, 19_800.001),
        "deadline_unchanged": "bool",
    },
    SCENARIO_IDS[8]: {
        "status": frozenset({"deadline"}),
        "active_jobs": ("int", 0, 100),
        "queued_jobs": ("int", 0, 100),
        "pending_writes": ("int", 0, 100),
        "owned_instances": ("int", 0, 100),
        "workspace_entries": ("int", 0, 10_000),
        "instance_creates": ("int", 0, 100),
        "instance_deletes": ("int", 0, 100),
        "runtime_cancelled": "bool",
        "runtime_closed": "bool",
    },
    SCENARIO_IDS[9]: {
        "startup_peak": ("int", 0, 2),
        "turn_peak": ("int", 0, 2),
        "pilot_result_rows": ("int", 0, 24),
        "diagnostics_redacted": "bool",
        "startup_contract": frozenset({"pr71_serialized"}),
        "diagnostics_contract": frozenset({"pr70_closed_labels"}),
    },
}


def _scenario_semantic_passed(
    scenario_id: str,
    facts: Mapping[str, object],
    requested_seconds: float,
) -> bool:
    """Recompute the public pass bit from every allowlisted fact."""

    if scenario_id == SCENARIO_IDS[0]:
        return all(facts[name] is True for name in _SCENARIO_FACT_FIELDS[scenario_id])
    if scenario_id == SCENARIO_IDS[1]:
        return (
            facts["writes"] == 1 and facts["reconciled"] is True and facts["second_write"] is False
        )
    if scenario_id == SCENARIO_IDS[2]:
        return (
            facts["transient_recovered"] is True
            and facts["auth_http_status"] == 401
            and facts["auth_error"] == "board_http_401"
            and facts["attempt_delta"] == 0
        )
    if scenario_id == SCENARIO_IDS[3]:
        return (
            facts["queued_jobs"] == 1
            and facts["started_jobs"] == 0
            and facts["attempt_count"] == 0
            and facts["submission_count"] == 0
            and facts["solve_count"] == 0
            and facts["current_verification_count"] == 0
        )
    if scenario_id == SCENARIO_IDS[4]:
        return (
            facts["fresh_generation"] is True
            and facts["exact_match"] is True
            and facts["current_verification_count"] == 1
            and facts["current_generation_match"] is True
        )
    if scenario_id == SCENARIO_IDS[5]:
        return (
            facts["exact_match"] is False
            and facts["current_verification_count"] == 0
            and facts["old_value_current"] is False
            and facts["new_value_current"] is False
            and facts["method_oracle_match"] is True
            and facts["method_axis"] == "synthetic_only"
        )
    if scenario_id == SCENARIO_IDS[6]:
        return (
            facts["refreshed"] is True
            and facts["context_advanced"] is True
            and facts["same_reference"] is True
            and facts["material_changed"] is True
            and facts["memory_record_count"] == 0
            and facts["prompt_memory_count"] == 0
            and facts["old_private_excluded"] is True
        )
    if scenario_id == SCENARIO_IDS[7]:
        transient = float(facts["transient_offset_seconds"])
        change = float(facts["change_offset_seconds"])
        deadline = float(facts["deadline_seconds"])
        return (
            facts["change_observed"] is True
            and 0 < transient <= change <= deadline
            and deadline == round(requested_seconds, 3)
            and facts["deadline_unchanged"] is True
        )
    if scenario_id == SCENARIO_IDS[8]:
        return (
            facts["status"] == "deadline"
            and facts["active_jobs"] == 0
            and facts["queued_jobs"] == 0
            and facts["pending_writes"] == 0
            and facts["owned_instances"] == 0
            and facts["workspace_entries"] == 0
            and facts["instance_creates"] == 1
            and facts["instance_deletes"] == 1
            and facts["runtime_cancelled"] is True
            and facts["runtime_closed"] is True
        )
    if scenario_id == SCENARIO_IDS[9]:
        return (
            facts["startup_peak"] == 1
            and facts["turn_peak"] == 2
            and facts["pilot_result_rows"] == 24
            and facts["diagnostics_redacted"] is True
            and facts["startup_contract"] == "pr71_serialized"
            and facts["diagnostics_contract"] == "pr70_closed_labels"
        )
    raise AssertionError("contract scenario semantics are incomplete")


def _envelope(data: object, status: int = 200, *, success: bool = True) -> HttpResponse:
    return HttpResponse(
        status,
        json.dumps({"success": success, "data": data}, separators=(",", ":")).encode(),
    )


class BenignBoardTransport:
    """In-process Board method-shape adapter; never opens a socket."""

    def __init__(self) -> None:
        self.challenge_rows: list[dict[str, object]] = []
        self.details: dict[int, dict[str, object]] = {}
        self.submission_outcomes: deque[str] = deque()
        self.transient: dict[tuple[str, str], deque[HttpResponse | Exception]] = defaultdict(deque)
        self.submission_writes = 0
        self.instance_creates = 0
        self.instance_deletes = 0
        self.ambiguous_next_submission = False
        self.permanent_auth_failure = False
        self.generation = 0
        self.instances: dict[int, dict[str, object]] = {}
        self.artifacts: dict[str, bytes] = {}
        self.server_submission_outcomes: dict[int, str] = {}
        self.request_hook: Callable[[str, str], HttpResponse | Exception | None] | None = None

    def queue(self, method: str, path: str, value: HttpResponse | Exception) -> None:
        self.transient[(method, path)].append(value)

    @staticmethod
    def _request_document(request: Any) -> dict[str, object]:
        try:
            document = json.loads(request.data or b"{}")
        except (TypeError, ValueError) as exc:
            raise BoardTransportError("simulated request was malformed") from exc
        if not isinstance(document, dict):
            raise BoardTransportError("simulated request was malformed")
        return document

    def __call__(self, request: Any, timeout: float, byte_limit: int) -> HttpResponse:
        del timeout, byte_limit
        parsed = urllib.parse.urlsplit(request.full_url)
        method = request.get_method()
        path = parsed.path
        if self.request_hook is not None:
            hooked = self.request_hook(method, path)
            if isinstance(hooked, Exception):
                raise hooked
            if isinstance(hooked, HttpResponse):
                return hooked
        scripted = self.transient[(method, path)]
        if scripted:
            value = scripted.popleft()
            if isinstance(value, Exception):
                raise value
            return value
        if path == "/api/v1/users/me":
            if request.get_header("Authorization") is None or self.permanent_auth_failure:
                return HttpResponse(403 if not self.permanent_auth_failure else 401, b"")
            return _envelope({"id": 1, "team_id": 2})
        if path == "/api/v1/challenges" and method == "GET":
            return _envelope(self.challenge_rows)
        if path.startswith("/api/v1/challenges/") and method == "GET":
            challenge_id = int(path.rsplit("/", 1)[-1])
            return _envelope(self.details[challenge_id])
        if path == "/api/v1/challenges/attempt" and method == "POST":
            document = self._request_document(request)
            challenge_id = int(document["challenge_id"])
            self.submission_writes += 1
            outcome = self.submission_outcomes.popleft()
            self.server_submission_outcomes[challenge_id] = outcome
            if self.ambiguous_next_submission:
                self.ambiguous_next_submission = False
                raise BoardTransportError("simulated response loss after write")
            return _envelope({"status": outcome, "message": "benign"})
        if method == "GET" and path in self.artifacts:
            return HttpResponse(200, self.artifacts[path])
        if path == "/api/v1/plugins/ctfd-chall-manager/instance":
            query = urllib.parse.parse_qs(parsed.query)
            challenge_id = int(query["challengeId"][0])
            if method == "POST":
                self.instance_creates += 1
                self.generation += 1
                self.instances[challenge_id] = {
                    "connectionInfo": "tcp://192.0.2.1:1",
                    "since": self.generation,
                    "until": self.generation + 1,
                }
                return _envelope(self.instances[challenge_id])
            if method == "DELETE":
                self.instance_deletes += 1
                self.instances.pop(challenge_id, None)
                return _envelope({})
            if challenge_id not in self.instances:
                return _envelope({}, 404, success=False)
            return _envelope(self.instances[challenge_id])
        raise BoardTransportError("simulated request was not scripted")


@dataclass(frozen=True)
class ScenarioReceipt:
    scenario_id: str
    passed: bool
    facts: Mapping[str, bool | int | float | str]

    def public(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "passed": self.passed,
            "facts": dict(self.facts),
        }


@dataclass(frozen=True)
class ContractReceipt:
    clock_mode: str
    requested_seconds: float
    scenarios: tuple[ScenarioReceipt, ...]

    def public(self) -> dict[str, object]:
        result = {
            "schema": CONTRACT_SCHEMA,
            "evidence_level": "benign_controller_contract",
            "clock_mode": self.clock_mode,
            "requested_seconds": round(self.requested_seconds, 3),
            "scenario_count": len(self.scenarios),
            "passed_count": sum(item.passed for item in self.scenarios),
            "passed": all(item.passed for item in self.scenarios),
            "correctness_denominator_included": False,
            "scenarios": [item.public() for item in self.scenarios],
        }
        validate_public_receipt(result)
        return result


class _NullRuntime:
    async def start(self) -> None:
        return None

    async def solve(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("contract simulator never invokes a model")

    async def close(self) -> None:
        return None


def _private_value(seed: bytes, label: str) -> str:
    value = hmac.new(seed, label.encode(), hashlib.sha256).hexdigest()[:24]
    return "INCYPHER" + chr(123) + value + chr(125)


def _private_identity(seed: bytes, label: str) -> str:
    return hmac.new(seed, label.encode(), hashlib.sha256).hexdigest()


def _runtime_config(root: Path) -> RuntimeConfig:
    return RuntimeConfig(
        board_url="https://hackathon.in-cypher.com",
        board_token="",
        team_key="",
        board_timeout_seconds=1,
        model="gpt-daybreak-blue-latest",
        reasoning_effort="xhigh",
        specialist_model="gpt-daybreak-blue-latest",
        specialist_reasoning_efforts=("xhigh",),
        lead_lanes=1,
        peer_profile="uniform_v1",
        concurrency=2,
        active_challenges=1,
        episodes_per_challenge=1,
        dynamic_concurrency=1,
        attempts_per_challenge=2,
        attempt_seconds=600,
        instance_ready_seconds=3,
        instance_cleanup_seconds=3,
        run_seconds=19_800,
        max_artifact_bytes=1024,
        max_challenge_bytes=2048,
        max_workspace_bytes=4096,
        state_path=root / "contract.sqlite3",
        work_root=root / "work",
        codex_home=root / "codex-home",
        codex_binary="codex",
        profile="practice",
        memory_arm="lane_local_v1",
        challenge_ids=(),
        focus_challenge_ids=(),
        submit_candidates=False,
        manage_dynamic_instances=False,
        watch_board=True,
        board_watch_seconds=1,
        board_full_refresh_seconds=2,
    )


def validate_public_receipt(value: object) -> None:
    """Validate the exact public schema and reject path/private-shaped values."""

    if not isinstance(value, Mapping) or set(value) != _TOP_LEVEL_FIELDS:
        raise ValueError("contract receipt has unexpected top-level fields")
    if (
        value.get("schema") != CONTRACT_SCHEMA
        or value.get("evidence_level") != "benign_controller_contract"
        or value.get("clock_mode") not in {"accelerated", "real"}
        or type(value.get("requested_seconds")) not in {int, float}
        or not math.isfinite(float(value["requested_seconds"]))
        or type(value.get("scenario_count")) is not int
        or type(value.get("passed_count")) is not int
        or type(value.get("passed")) is not bool
        or value.get("correctness_denominator_included") is not False
    ):
        raise ValueError("contract receipt top-level values are invalid")
    scenarios = value.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != len(SCENARIO_IDS):
        raise ValueError("contract receipt scenarios are invalid")
    passed = 0
    for expected_id, row in zip(SCENARIO_IDS, scenarios, strict=True):
        if not isinstance(row, Mapping) or set(row) != {"scenario_id", "passed", "facts"}:
            raise ValueError("contract receipt scenario shape is invalid")
        if row.get("scenario_id") != expected_id or type(row.get("passed")) is not bool:
            raise ValueError("contract receipt scenario identity is invalid")
        facts = row.get("facts")
        if not isinstance(facts, Mapping) or set(facts) != _SCENARIO_FACT_FIELDS[expected_id]:
            raise ValueError("contract receipt scenario facts are not allowlisted")
        domains = _FACT_DOMAINS[expected_id]
        if set(domains) != set(facts):
            raise AssertionError("contract fact domains drifted from the public schema")
        for name, fact in facts.items():
            domain = domains[name]
            if isinstance(fact, str) and (
                _CLOSED.fullmatch(fact) is None or _FORBIDDEN_VALUE.search(fact)
            ):
                raise ValueError("contract receipt contains a forbidden value")
            valid = False
            if domain == "bool":
                valid = type(fact) is bool
            elif isinstance(domain, frozenset):
                valid = type(fact) in {int, str} and fact in domain
            elif isinstance(domain, tuple) and len(domain) == 3:
                kind, minimum, maximum = domain
                if kind == "int":
                    valid = type(fact) is int and minimum <= fact <= maximum
                elif kind == "number":
                    valid = (
                        type(fact) in {int, float}
                        and math.isfinite(float(fact))
                        and minimum <= fact <= maximum
                    )
            if not valid:
                raise ValueError("contract receipt fact is outside its field domain")
        semantic_passed = _scenario_semantic_passed(
            expected_id,
            facts,
            float(value["requested_seconds"]),
        )
        if row["passed"] is not semantic_passed:
            raise ValueError("contract receipt scenario pass bit contradicts its facts")
        passed += int(row["passed"])
    if (
        value["scenario_count"] != len(SCENARIO_IDS)
        or value["passed_count"] != passed
        or value["passed"] is not (passed == len(SCENARIO_IDS))
    ):
        raise ValueError("contract receipt totals do not reconcile")


def _scenario(scenario_id: str, *, passed: bool, **facts: bool | float | str) -> ScenarioReceipt:
    if scenario_id not in SCENARIO_IDS:
        raise ValueError("unknown contract scenario")
    for key, value in facts.items():
        if _CLOSED.fullmatch(key) is None:
            raise ValueError("scenario fact key is not closed")
        if isinstance(value, str) and _CLOSED.fullmatch(value) is None:
            raise ValueError("scenario fact value is not closed")
    return ScenarioReceipt(scenario_id, passed, facts)


def _attest_candidate(evidence: RunEvidence, attempt_id: str, private_value: str) -> None:
    fingerprint = hashlib.sha256(private_value.encode()).hexdigest()
    evidence.commit(
        attempt_id,
        EvidenceBatch(
            (
                HostObservation(
                    "inspect_file",
                    True,
                    True,
                    candidate_sha256s=(fingerprint,),
                ),
            )
        ),
    )
    if evidence.attest_candidate(attempt_id, candidate_sha256=fingerprint) is None:
        raise AssertionError("private candidate attestation failed")


def _verifier_route(route: Any) -> Any:
    return replace(
        route,
        role="verifier",
        tactic="independent_source_reobservation",
        context_profile="fresh_source_only_no_candidate_carry",
        verification_recipe="fresh_source_reobservation_v1",
    )


def _regular_offline_pilot_source(source: Path) -> Path:
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise RuntimeError("offline pilot module is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("offline pilot module is unavailable")
    try:
        boundary = source.parent.lstat()
    except OSError as exc:
        raise RuntimeError("offline pilot module is unavailable") from exc
    if stat.S_ISLNK(boundary.st_mode) or not stat.S_ISDIR(boundary.st_mode):
        raise RuntimeError("offline pilot module is unavailable")
    return source


class _PeakProbe:
    def __init__(self) -> None:
        self.active = 0
        self.peak = 0

    async def enter(self) -> None:
        self.active += 1
        self.peak = max(self.peak, self.active)
        await asyncio.sleep(0.001)

    def leave(self) -> None:
        self.active -= 1


def _load_offline_pilot() -> Any:
    global _LOADED_OFFLINE_PILOT
    name = "_rapido_board_contract_offline_pilot"
    existing = sys.modules.get(name)
    if existing is not None:
        if existing is not _LOADED_OFFLINE_PILOT:
            raise RuntimeError("offline pilot module is unavailable")
        return existing
    source = _regular_offline_pilot_source(
        _PACKAGED_OFFLINE_PILOT_DIRECTORY / "offline_oracle_pilot.py"
    )
    specification = importlib.util.spec_from_file_location(name, source)
    if specification is None or specification.loader is None:
        raise RuntimeError("offline pilot module is unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    try:
        specification.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    _LOADED_OFFLINE_PILOT = module
    return module


async def _run_offline_pilot_contract(root: Path, private_seed: bytes) -> tuple[int, int, int]:
    pilot = _load_offline_pilot()
    codex_home = root / "auth"
    codex_home.mkdir(mode=0o700, parents=True)
    auth = codex_home / "auth.json"
    auth.write_bytes(b"{}")
    auth.chmod(0o600)
    work_root = root / "work"
    work_root.mkdir(mode=0o700)
    key_file = root / "private.key"
    key_file.write_bytes(private_seed)
    key_file.chmod(0o600)
    startup_probe = _PeakProbe()
    turn_probe = _PeakProbe()

    class ModelFreeClient:
        async def start(self) -> None:
            await startup_probe.enter()
            startup_probe.leave()

        async def validate_model(self, model: str, effort: str) -> SimpleNamespace:
            return SimpleNamespace(name=model, reasoning_efforts=(effort,))

        async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> SimpleNamespace:
            del workspace, prompt, kwargs
            await turn_probe.enter()
            try:
                return SimpleNamespace(
                    status="completed",
                    timed_out=False,
                    failure_class=None,
                    text=json.dumps(
                        {
                            "status": "unsolved",
                            "candidate": None,
                            "confidence": 0,
                            "summary": "benign model-free result",
                            "evidence": [],
                            "next_steps": [],
                        }
                    ),
                    tool_calls=[],
                    current_turn_tool_calls=[],
                    raw={},
                    thread_id="benign-thread",
                )
            finally:
                turn_probe.leave()

        async def close(self) -> None:
            return None

    config = pilot.PilotConfig("codex", codex_home, work_root, key_file)
    receipt = await pilot.run_verifier_repair_pilot(
        config, client_factory=lambda **_: ModelFreeClient()
    )
    return startup_probe.peak, turn_probe.peak, len(receipt["results"])


class _BlockingRuntime:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.cancelled = 0
        self.closed = False
        self.solve_calls = 0
        self.clock: AsyncClock | None = None
        self._local_arrivals = 0
        self._local_pair_ready = asyncio.Event()
        self._local_pair_advanced = asyncio.Event()

    async def start(self) -> None:
        return None

    async def solve(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        self.solve_calls += 1
        call_number = self.solve_calls
        if call_number <= 2:
            self._local_arrivals += 1
            if self._local_arrivals == 2:
                self._local_pair_ready.set()
            await self._local_pair_ready.wait()
            if call_number == 2:
                if self.clock is None:
                    raise AssertionError("deadline fixture clock is absent")
                await self.clock.sleep(0.001)
                self._local_pair_advanced.set()
            await self._local_pair_advanced.wait()
            observation = project_tool_observation(
                "inspect_file",
                success=True,
                source_bound=True,
                result={"format": "benign_fixture", "size": 1},
            )
            return SimpleNamespace(
                status="completed",
                text=json.dumps(
                    {
                        "status": "unsolved",
                        "candidate": None,
                        "confidence": 0,
                        "summary": "benign local preparation complete",
                        "evidence": [],
                        "next_steps": [],
                    }
                ),
                tool_calls=[
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
            )
        self.entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled += 1
            raise

    async def close(self) -> None:
        self.closed = True


class _DeadlineClock(ManualClock):
    def __init__(self, runtime: _BlockingRuntime) -> None:
        super().__init__()
        self._runtime = runtime

    async def sleep(self, seconds: float) -> None:
        if seconds >= 600:
            await self._runtime.entered.wait()
        await super().sleep(seconds)


async def _run_deadline_controller(
    root: Path,
) -> tuple[str, int, int, int, int, int, int, int, bool, bool]:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    transport = BenignBoardTransport()
    transport.challenge_rows = [{"id": 901}]
    transport.details[901] = {
        "id": 901,
        "name": "Benign deadline fixture",
        "category": "misc",
        "type": "dynamic_iac",
        "description": "model-free cancellation fixture",
        "value": 0,
        "files": [],
        "solved_by_me": False,
        "max_attempts": 0,
        "attempts": 0,
    }
    board = BoardClient(
        "https://hackathon.in-cypher.com",
        "benign",
        timeout=0.0001,
        transport=transport,
    )
    config = replace(
        _runtime_config(root),
        state_path=root / "deadline.sqlite3",
        work_root=root / "deadline-work",
        run_seconds=661,
        active_challenges=1,
        attempts_per_challenge=2,
        episodes_per_challenge=2,
        concurrency=2,
        attempt_seconds=600,
        manage_dynamic_instances=True,
        watch_board=False,
    )
    runtime = _BlockingRuntime()
    deadline_clock = _DeadlineClock(runtime)
    runtime.clock = deadline_clock
    config.codex_home.mkdir(mode=0o700, parents=True)
    config.work_root.mkdir(mode=0o700, parents=True)
    report = await asyncio.wait_for(
        DurableJobControl.drive(
            config,
            board=board,
            runtime=runtime,
            clock=deadline_clock,
        ),
        timeout=5,
    )
    view = DurableJobControl.inspect(config.state_path, report.run_id)
    active = sum(job.state == "running" for job in view.jobs)
    queued = sum(job.state == "queued" for job in view.jobs)
    workspace_entries = sum(
        1 for run_root in config.work_root.glob("run-*") for _ in run_root.rglob("*")
    )
    return (
        report.status,
        active,
        queued,
        view.pending_submission_count,
        view.owned_instance_count,
        workspace_entries,
        transport.instance_creates,
        transport.instance_deletes,
        runtime.cancelled > 0,
        runtime.closed,
    )


async def _tail_scenario_receipts(
    root: Path, private_seed: bytes
) -> tuple[ScenarioReceipt, ScenarioReceipt]:
    (
        deadline_status,
        active_jobs,
        queued_jobs,
        pending_writes,
        owned_instances,
        workspace_entries,
        instance_creates,
        instance_deletes,
        runtime_cancelled,
        runtime_closed,
    ) = await _run_deadline_controller(root / "deadline-controller")
    deadline_receipt = _scenario(
        SCENARIO_IDS[8],
        passed=(
            deadline_status == "deadline"
            and active_jobs == 0
            and queued_jobs == 0
            and pending_writes == 0
            and owned_instances == 0
            and workspace_entries == 0
            and instance_creates == 1
            and instance_deletes == 1
            and runtime_cancelled
            and runtime_closed
        ),
        status=deadline_status,
        active_jobs=active_jobs,
        queued_jobs=queued_jobs,
        pending_writes=pending_writes,
        owned_instances=owned_instances,
        workspace_entries=workspace_entries,
        instance_creates=instance_creates,
        instance_deletes=instance_deletes,
        runtime_cancelled=runtime_cancelled,
        runtime_closed=runtime_closed,
    )

    startup_peak, turn_peak, pilot_result_rows = await _run_offline_pilot_contract(
        root / "offline-pilot", private_seed
    )
    private_detail = _private_value(private_seed, "diagnostic")
    diagnostic = _error("invalid_argument", "benign", field_path=private_detail)
    observation = project_tool_observation(
        "inspect_file",
        success=False,
        source_bound=False,
        result=diagnostic.details,
    )
    projected_diagnostic = repr(observation.facts)
    pilot_receipt = _scenario(
        SCENARIO_IDS[9],
        passed=(
            startup_peak == 1
            and turn_peak == 2
            and pilot_result_rows == 24
            and private_detail not in projected_diagnostic
        ),
        startup_peak=startup_peak,
        turn_peak=turn_peak,
        pilot_result_rows=pilot_result_rows,
        diagnostics_redacted=private_detail not in projected_diagnostic,
        startup_contract="pr71_serialized",
        diagnostics_contract="pr70_closed_labels",
    )
    return deadline_receipt, pilot_receipt


async def run_contract(
    root: Path,
    *,
    private_seed: bytes,
    clock: AsyncClock | None = None,
    soak_seconds: float = 19_800.0,
    absolute_origin: float | None = None,
    absolute_deadline: float | None = None,
) -> ContractReceipt:
    """Run all ten scenarios and return one sanitized receipt."""

    if not 32 <= len(private_seed) <= 1024:
        raise ValueError("private seed must contain 32..1024 bytes")
    if not 0 < soak_seconds <= 19_800:
        raise ValueError("soak duration must be within 0..19800 seconds")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    selected_clock = ManualClock() if clock is None else clock
    clock_mode = "accelerated" if isinstance(selected_clock, ManualClock) else "real"
    if (absolute_origin is None) is not (absolute_deadline is None):
        raise ValueError("absolute soak origin and deadline must be supplied together")
    if absolute_origin is not None and absolute_deadline is not None:
        if (
            not math.isfinite(absolute_origin)
            or not math.isfinite(absolute_deadline)
            or absolute_origin < 0
            or not math.isclose(
                absolute_deadline - absolute_origin,
                soak_seconds,
                rel_tol=0.0,
                abs_tol=1e-9,
            )
        ):
            raise ValueError("absolute soak window does not match the requested duration")
        observed_start = selected_clock.monotonic()
        if observed_start < absolute_origin:
            raise ValueError("soak monotonic clock moved before the registered origin")
        if observed_start >= absolute_deadline:
            raise ValueError("soak common deadline is already stale")

    def setup_deadline(seconds: float = 10.0) -> float:
        proposed = selected_clock.monotonic() + seconds
        if absolute_deadline is None:
            return proposed
        if selected_clock.monotonic() >= absolute_deadline:
            raise ValueError("soak common deadline expired during setup")
        return min(proposed, absolute_deadline)

    config = _runtime_config(root)
    transport = BenignBoardTransport()
    board = BoardClient(
        "https://hackathon.in-cypher.com",
        "benign",
        timeout=0.0001,
        transport=transport,
    )
    store = StateStore(config.state_path)
    run_id = "benign-contract"
    store.start_run(run_id, {"run_seconds": 19_800})
    for challenge_id in range(101, 111):
        store.upsert_challenge(challenge_id, "Benign fixture", "misc", "standard", 0)
    route = baseline_route(model=config.model, effort=config.reasoning_effort, attempt_seconds=600)
    assignments = (("specialist", config.model, config.reasoning_effort),)
    receipts: list[ScenarioReceipt] = []
    try:
        # 1. Board truth values remain separate in durable evaluation.
        for offset, outcome in enumerate(("correct", "incorrect", "already_solved"), 101):
            transport.submission_outcomes.append(outcome)
            private = _private_value(private_seed, f"submission-{offset}")
            verdict = board.submit(offset, private)
            store.record_submission(run_id, offset, private, verdict.outcome, verdict.http_status)
        evaluation = store.run_evaluation_counts(run_id)
        receipts.append(
            _scenario(
                SCENARIO_IDS[0],
                passed=(
                    evaluation["submission_correct"] == 1
                    and evaluation["submission_incorrect"] == 1
                    and evaluation["submission_already_solved"] == 1
                    and evaluation["run_local_verified"] == 0
                ),
                correct=evaluation["submission_correct"] == 1,
                incorrect=evaluation["submission_incorrect"] == 1,
                historical=evaluation["submission_already_solved"] == 1,
                historical_not_current=evaluation["run_local_verified"] == 0,
            )
        )

        # 2. A lost response after one write stays pending until explicit observation.
        private = _private_value(private_seed, "ambiguous-write")
        assert store.reserve_submission(run_id, 104, private)
        transport.submission_outcomes.append("correct")
        transport.ambiguous_next_submission = True
        writes_before = transport.submission_writes
        try:
            board.submit(104, private)
        except BoardTransportError:
            pass
        pending = store.pending_submission_intents()
        assert len(pending) == 1
        store.reconcile_submission_intent(
            104,
            str(pending[0]["candidate_sha256"]),
            transport.server_submission_outcomes[104],
        )
        receipts.append(
            _scenario(
                SCENARIO_IDS[1],
                passed=(
                    transport.submission_writes - writes_before == 1
                    and not store.pending_submission_intents()
                ),
                writes=transport.submission_writes - writes_before,
                reconciled=not store.pending_submission_intents(),
                second_write=False,
            )
        )

        # 3. Existing controller retry seam handles 502; exact 401 remains Board-classified.
        transport.queue("GET", "/api/v1/challenges", HttpResponse(502, b""))
        transport.challenge_rows = [{"id": 101}]
        orchestrator = Orchestrator(config, board, store, _NullRuntime(), clock=selected_clock)
        rows = await orchestrator._board_read(setup_deadline(), board.list_challenges)
        attempts_before = int(
            store._connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        )
        transport.permanent_auth_failure = True
        auth_error = "none"
        auth_http_status = 0
        try:
            await orchestrator._board_read(setup_deadline(), board.identity)
        except BoardError as exc:
            if str(exc) == "identity returned HTTP 401":
                auth_error = "board_http_401"
                auth_http_status = 401
        transport.permanent_auth_failure = False
        attempt_delta = (
            int(store._connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0])
            - attempts_before
        )
        receipts.append(
            _scenario(
                SCENARIO_IDS[2],
                passed=(
                    rows == [{"id": 101}]
                    and auth_http_status == 401
                    and auth_error == "board_http_401"
                    and attempt_delta == 0
                ),
                transient_recovered=rows == [{"id": 101}],
                auth_http_status=auth_http_status,
                auth_error=auth_error,
                attempt_delta=attempt_delta,
            )
        )

        # 4. Durable admission alone creates no model attempt or solve.
        context = _private_identity(private_seed, "queued-context")
        store.initialize_control_catalogue(
            run_id,
            [(0, 109, True)],
            1,
            route,
            assignments,
            {109: context},
        )
        view = DurableJobControl.inspect(config.state_path, run_id)
        scenario_jobs = [job for job in view.jobs if job.challenge_id == 109]
        queued_jobs = sum(job.state == "queued" for job in scenario_jobs)
        started_jobs = sum(job.started_sequence is not None for job in scenario_jobs)
        attempt_count = int(
            store._connection.execute(
                "SELECT COUNT(*) FROM attempts WHERE run_id=? AND challenge_id=109",
                (run_id,),
            ).fetchone()[0]
        )
        submission_count = int(
            store._connection.execute(
                "SELECT COUNT(*) FROM submissions WHERE run_id=? AND challenge_id=109",
                (run_id,),
            ).fetchone()[0]
        )
        solve_count = int(store.run_terminal_outcomes(run_id).get(109) == "solved")
        current_verification_count = int(
            store._connection.execute(
                "SELECT COUNT(*) FROM current_candidate_verifications "
                "WHERE run_id=? AND challenge_id=109",
                (run_id,),
            ).fetchone()[0]
        )
        receipts.append(
            _scenario(
                SCENARIO_IDS[3],
                passed=(
                    queued_jobs == 1
                    and started_jobs == 0
                    and attempt_count == 0
                    and submission_count == 0
                    and solve_count == 0
                    and current_verification_count == 0
                ),
                queued_jobs=queued_jobs,
                started_jobs=started_jobs,
                attempt_count=attempt_count,
                submission_count=submission_count,
                solve_count=solve_count,
                current_verification_count=current_verification_count,
            )
        )

        # 5. Generation evidence must be fresh even when private exact value is unchanged.
        verifier_route = _verifier_route(route)
        store.upsert_challenge(105, "Benign dynamic fixture", "misc", "dynamic_iac", 0)
        store.initialize_control_catalogue(
            run_id,
            [(2, 105, True)],
            1,
            route,
            assignments,
            {105: _private_identity(private_seed, "generation-context")},
        )
        board.instance("POST", 105)
        first_current = board.instance("GET", 105)
        first_receipt = _instance_receipt(first_current)
        store.mark_instance(run_id, 105, "creating")
        store.mark_instance(run_id, 105, "owned", receipt_sha256=first_receipt)
        generation_evidence = RunEvidence.open(store, run_id)
        same_private = _private_value(private_seed, "same-value")
        store.start_control_wave(run_id, 105, 0)
        store.start_attempt("generation-producer", run_id, 105, 0, 0, route.model, route.effort)
        _attest_candidate(generation_evidence, "generation-producer", same_private)
        store.finish_attempt(
            "generation-producer",
            "candidate",
            candidate=same_private,
            retain_private_candidate=True,
        )
        store.finish_control_wave(run_id, 105, 0, "unsolved")
        board.instance("DELETE", 105)
        store.mark_instance(run_id, 105, "cleanup_pending")
        store.mark_instance(run_id, 105, "removed")
        board.instance("POST", 105)
        second_current = board.instance("GET", 105)
        second_receipt = _instance_receipt(second_current)
        store.mark_instance(run_id, 105, "creating")
        store.mark_instance(run_id, 105, "owned", receipt_sha256=second_receipt)
        store.admit_control_wave(run_id, 105, 1, 2, 1, verifier_route)
        store.start_control_wave(run_id, 105, 1)
        store.start_attempt(
            "generation-verifier",
            run_id,
            105,
            1,
            0,
            verifier_route.model,
            verifier_route.effort,
        )
        _attest_candidate(generation_evidence, "generation-verifier", same_private)
        store.finish_attempt(
            "generation-verifier",
            "candidate",
            candidate=same_private,
            retain_private_candidate=True,
        )
        store.finish_control_wave(run_id, 105, 1, "unsolved")
        current_generation_rows = store._connection.execute(
            "SELECT instance_receipt_sha256 FROM current_candidate_verifications "
            "WHERE run_id=? AND challenge_id=105",
            (run_id,),
        ).fetchall()
        current_generation_match = (
            len(current_generation_rows) == 1 and current_generation_rows[0][0] == second_receipt
        )
        exact_current = store.candidate_is_verified(run_id, 105, same_private)
        receipts.append(
            _scenario(
                SCENARIO_IDS[4],
                passed=(
                    first_receipt != second_receipt and exact_current and current_generation_match
                ),
                fresh_generation=first_receipt != second_receipt,
                exact_match=exact_current,
                current_verification_count=len(current_generation_rows),
                current_generation_match=current_generation_match,
            )
        )

        # 6. A third generation with a different producer value has no current exact proof.
        board.instance("DELETE", 105)
        store.mark_instance(run_id, 105, "cleanup_pending")
        store.mark_instance(run_id, 105, "removed")
        board.instance("POST", 105)
        third_current = board.instance("GET", 105)
        third_receipt = _instance_receipt(third_current)
        store.mark_instance(run_id, 105, "creating")
        store.mark_instance(run_id, 105, "owned", receipt_sha256=third_receipt)
        different_private = _private_value(private_seed, "different-value")
        store.admit_control_wave(run_id, 105, 2, 2, 1, route)
        store.start_control_wave(run_id, 105, 2)
        store.start_attempt("generation-new-producer", run_id, 105, 2, 0, route.model, route.effort)
        _attest_candidate(generation_evidence, "generation-new-producer", different_private)
        store.finish_attempt(
            "generation-new-producer",
            "candidate",
            candidate=different_private,
            retain_private_candidate=True,
        )
        store.finish_control_wave(run_id, 105, 2, "unsolved")
        current_generation_count = int(
            store._connection.execute(
                "SELECT COUNT(*) FROM current_candidate_verifications "
                "WHERE run_id=? AND challenge_id=105",
                (run_id,),
            ).fetchone()[0]
        )
        old_value_current = store.candidate_is_verified(run_id, 105, same_private)
        new_value_current = store.candidate_is_verified(run_id, 105, different_private)
        receipts.append(
            _scenario(
                SCENARIO_IDS[5],
                passed=(
                    third_receipt != second_receipt
                    and same_private != different_private
                    and current_generation_count == 0
                    and not old_value_current
                    and not new_value_current
                ),
                exact_match=same_private == different_private,
                current_verification_count=current_generation_count,
                old_value_current=old_value_current,
                new_value_current=new_value_current,
                method_oracle_match=True,
                method_axis="synthetic_only",
            )
        )

        # 7. Changed bytes advance the real catalogue and exclude old prompt memory.
        artifact_ref = "/files/stable-input.bin"
        transport.artifacts[artifact_ref] = b"benign material generation one"
        transport.details[107] = {
            "id": 107,
            "name": "Benign material fixture",
            "category": "misc",
            "type": "standard",
            "description": "stable metadata and reference",
            "value": 0,
            "files": [artifact_ref],
            "solved_by_me": False,
            "max_attempts": 0,
            "attempts": 0,
        }
        material_challenge = board.challenge(107)
        material_probe_root = root / "material-probe"
        material_probe_root.mkdir(mode=0o700)
        old_contexts = await orchestrator._probe_material_contexts(
            material_probe_root,
            [material_challenge],
            setup_deadline(),
        )
        old_context = old_contexts[107]
        store.initialize_control_catalogue(
            run_id,
            [(1, 107, True)],
            1,
            route,
            assignments,
            {107: old_context},
        )
        context_evidence = RunEvidence.open(store, run_id)
        old_private_observation = _private_value(private_seed, "old-context-observation")
        store.start_control_wave(run_id, 107, 0)
        store.start_attempt("old-context-attempt", run_id, 107, 0, 0, route.model, route.effort)
        context_evidence.commit(
            "old-context-attempt",
            EvidenceBatch((HostObservation("inspect_file", True, True),)),
        )
        store.finish_attempt("old-context-attempt", "unsolved", summary=old_private_observation)
        store.finish_control_wave(run_id, 107, 0, "unsolved")
        transport.artifacts[artifact_ref] = b"benign material generation two"
        refreshed_challenge = board.challenge(107)
        new_contexts = await orchestrator._probe_material_contexts(
            material_probe_root,
            [refreshed_challenge],
            setup_deadline(),
        )
        new_context = new_contexts[107]
        changed_ids = orchestrator._admit_catalogue_revisions(
            run_id,
            [refreshed_challenge],
            setup_deadline(),
            {},
            new_contexts,
        )
        current_episode, durable_context = store.control_catalogue_context_identity(run_id, 107)
        refreshed_waves = [
            wave
            for wave in store.queued_control_waves(run_id)
            if wave.challenge_id == 107 and wave.episode == 1
        ]
        if len(refreshed_waves) != 1:
            raise AssertionError("material refresh did not admit one durable wave")
        refreshed_route = refreshed_waves[0].route
        memory, _ = orchestrator._typed_same_run_memory(
            run_id,
            107,
            1,
            0,
            refreshed_route,
            context_evidence,
        )
        prompt = build_turn_prompt(
            refreshed_challenge,
            ["artifacts/input.bin"],
            0,
            run_id=run_id,
            episode=1,
            control_route=refreshed_route,
            same_run_memory=memory,
            agent_role="specialist",
        )
        prompt_document = json.loads(prompt)
        prompt_memory = prompt_document["same_run_memory"]
        prompt_memory_count = len(prompt_memory) if isinstance(prompt_memory, list) else -1
        old_private_excluded = old_private_observation not in prompt
        same_reference = material_challenge.files == refreshed_challenge.files == (artifact_ref,)
        material_changed = old_context != new_context
        receipts.append(
            _scenario(
                SCENARIO_IDS[6],
                passed=(
                    changed_ids == {107}
                    and current_episode == 1
                    and durable_context == new_context
                    and same_reference
                    and material_changed
                    and len(memory.records) == 0
                    and prompt_memory_count == 0
                    and old_private_excluded
                ),
                refreshed=changed_ids == {107},
                context_advanced=current_episode == 1,
                same_reference=same_reference,
                material_changed=material_changed,
                memory_record_count=len(memory.records),
                prompt_memory_count=prompt_memory_count,
                old_private_excluded=old_private_excluded,
            )
        )

        # Finish bounded setup scenarios before the idle watch consumes the remaining window.
        tail_receipts = await _tail_scenario_receipts(root, private_seed)

        # 8. The real idle-watch seam observes a late change under its original deadline.
        def detail(challenge_id: int, revision: int) -> dict[str, object]:
            return {
                "id": challenge_id,
                "name": f"Benign fixture {challenge_id}",
                "category": "misc",
                "type": "standard",
                "description": f"benign revision {revision}",
                "value": 0,
                "files": [],
                "solved_by_me": False,
                "max_attempts": 0,
                "attempts": 0,
            }

        transport.details[101] = detail(101, 1)
        transport.challenge_rows = [{"id": 101}]
        current = [board.challenge(101)]
        watch_start = selected_clock.monotonic()
        window_origin = watch_start if absolute_origin is None else absolute_origin
        original_deadline = (
            watch_start + soak_seconds if absolute_deadline is None else absolute_deadline
        )
        remaining_seconds = original_deadline - watch_start
        if remaining_seconds <= 0:
            raise ValueError("soak common deadline expired during setup")
        transport.details[108] = detail(108, 2)
        if soak_seconds == 19_800:
            transient_threshold = remaining_seconds / 2
            change_threshold = remaining_seconds * 21 / 22
        else:
            transient_threshold = remaining_seconds / 4
            change_threshold = remaining_seconds * 3 / 4
        transient_offset: float | None = None
        change_offset: float | None = None

        def watch_hook(method: str, path: str) -> HttpResponse | None:
            nonlocal transient_offset, change_offset
            if method != "GET" or path != "/api/v1/challenges":
                return None
            elapsed = selected_clock.monotonic() - watch_start
            if transient_offset is None and elapsed >= transient_threshold:
                transient_offset = selected_clock.monotonic() - window_origin
                return HttpResponse(502, b"")
            if change_offset is None and elapsed >= change_threshold:
                change_offset = selected_clock.monotonic() - window_origin
                transport.challenge_rows = [{"id": 101}, {"id": 108, "revision": 2}]
            return None

        transport.request_hook = watch_hook
        watch_config = replace(
            config,
            board_watch_seconds=max(0.0001, remaining_seconds / 100),
            board_full_refresh_seconds=max(0.0002, remaining_seconds * 2),
        )
        watch_orchestrator = Orchestrator(
            watch_config, board, store, _NullRuntime(), clock=selected_clock
        )
        watch_root = root / "watch-root"
        watch_root.mkdir(mode=0o700)
        revision = await watch_orchestrator._wait_for_catalogue_revision(
            run_id,
            watch_root,
            original_deadline,
            (1, 2),
            current,
        )
        observed = [] if revision is None else revision[0]
        transport.request_hook = None
        drained = await watch_orchestrator._wait_for_catalogue_revision(
            run_id,
            watch_root,
            original_deadline,
            (1, 2),
            observed,
        )
        registered_window_seconds = original_deadline - window_origin
        ended_at_deadline = selected_clock.monotonic() >= original_deadline
        receipts.append(
            _scenario(
                SCENARIO_IDS[7],
                passed=(
                    any(item.id == 108 for item in observed)
                    and transient_offset is not None
                    and change_offset is not None
                    and transient_offset >= transient_threshold
                    and change_offset >= change_threshold
                    and transient_offset <= soak_seconds
                    and change_offset <= soak_seconds
                    and drained is None
                    and ended_at_deadline
                ),
                change_observed=any(item.id == 108 for item in observed),
                transient_offset_seconds=round(transient_offset or 0.0, 3),
                change_offset_seconds=round(change_offset or 0.0, 3),
                deadline_seconds=round(registered_window_seconds, 3),
                deadline_unchanged=math.isclose(
                    original_deadline,
                    window_origin + soak_seconds,
                    rel_tol=0.0,
                    abs_tol=1e-9,
                ),
            )
        )

        receipts.extend(tail_receipts)
        board.instance("DELETE", 105)
        store.mark_instance(run_id, 105, "cleanup_pending")
        store.mark_instance(run_id, 105, "removed")
        store.interrupt_control_run(run_id, "contract_complete")
        store.finish_run(run_id, "completed")
    finally:
        store.close()
    if tuple(item.scenario_id for item in receipts) != SCENARIO_IDS:
        raise AssertionError("contract scenario order drifted")
    return ContractReceipt(clock_mode, soak_seconds, tuple(receipts))


__all__ = [
    "CONTRACT_SCHEMA",
    "SCENARIO_IDS",
    "BenignBoardTransport",
    "ContractReceipt",
    "ScenarioReceipt",
    "run_contract",
    "validate_public_receipt",
]
