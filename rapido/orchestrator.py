"""Durable two-lane challenge orchestration with serial candidate submission."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import stat
import time
import urllib.parse
import uuid
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .board import FLAG_RE, BoardClient, BoardError, BoardTransportError, Challenge, Verdict
from .config import RuntimeConfig
from .evidence import (
    EvidenceBatch,
    EvidenceError,
    HostObservation,
    RunEvidence,
    project_tool_observation,
    seal_unavailable_attempt_evidence,
)
from .memory import (
    AnalysisClaim,
    CandidateContext,
    CandidateEvidence,
    CandidateMemoryAggregate,
    CandidateVerification,
    FailureRecord,
    MemoryProjection,
    MemoryTarget,
    TacticOutcome,
    project_memory,
    sanitize_public_value,
)
from .memory import HostObservation as MemoryHostObservation
from .routing import RouteSpec, baseline_route, instance_follow_on_route
from .solver import (
    DEVELOPER_INSTRUCTIONS,
    MAX_PRIOR_ATTEMPTS,
    SOLVER_OUTPUT_SCHEMA,
    CandidateProvenanceError,
    SolverFinding,
    SolverOutputError,
    admitted_candidate,
    build_primary_continuation_prompt,
    build_turn_prompt,
    candidate_is_eligible,
    challenge_candidate_prose,
    project_attempt_carry,
)
from .state import StateStore
from .target import TargetEndpoint, TargetToolRegistry, parse_connection_info


class NativeTurn(Protocol):
    text: str
    status: str
    failure_class: str | None
    tool_calls: list[dict[str, Any]]


class NativeRuntime(Protocol):
    async def start(self) -> None: ...

    async def solve(
        self,
        workspace: Path,
        prompt: str,
        *,
        developer_instructions: str,
        model: str,
        reasoning_effort: str,
        output_schema: dict[str, Any],
        timeout: float,
        tool_registry: Any | None = None,
        progress_callback: Callable[[], None] | None = None,
        continuation_callback: (Callable[[NativeTurn, float | None], str | None] | None) = None,
    ) -> NativeTurn: ...

    async def close(self) -> None: ...


class RunDeadlineReached(TimeoutError):
    """The whole-run work deadline elapsed."""


class NoProgressError(TimeoutError):
    """A native lane made no host-visible tool progress for its bounded window."""


class RecoveryBlocked(RuntimeError):
    """A process-lost run cannot safely resume until its ambiguous effect is reconciled."""


_NATIVE_FAILURE_CLASSES = frozenset(
    {
        "active_turn_not_steerable",
        "bad_request",
        "context_window_exceeded",
        "cyber_policy",
        "http_connection_failed",
        "internal_server_error",
        "interrupted",
        "misalignment_policy_violation",
        "other",
        "rate_limit_exceeded",
        "response_stream_connection_failed",
        "response_stream_disconnected",
        "response_too_many_failed_attempts",
        "sandbox_error",
        "server_overloaded",
        "session_budget_exceeded",
        "thread_rollback_failed",
        "unauthorized",
        "unknown",
        "usage_limit_exceeded",
    }
)


class NativeTurnIncompleteError(RuntimeError):
    """A terminal native turn failed with a closed, non-secret classification."""

    def __init__(self, status: object, failure_class: object) -> None:
        self.status = (
            status
            if isinstance(status, str) and status in {"failed", "interrupted", "inProgress"}
            else "unknown"
        )
        self.failure_class = (
            failure_class
            if isinstance(failure_class, str) and failure_class in _NATIVE_FAILURE_CLASSES
            else "unknown"
        )
        super().__init__(f"native turn {self.status}: {self.failure_class}")


@dataclass(frozen=True)
class LaneResult:
    episode: int
    lane: int
    started: float
    finished: float
    finding: SolverFinding | None
    terminal_status: str
    tool_call_count: int
    tool_calls: tuple[ToolCallEvidence, ...]
    submission_status: str | None = None


@dataclass(frozen=True)
class ToolCallEvidence:
    name: str
    success: bool | None
    source_bound: bool
    candidate_sensitive: bool
    candidate_sha256s: tuple[str, ...]
    supplied_candidate_sha256s: tuple[str, ...]
    observation: HostObservation


@dataclass(frozen=True)
class RunReport:
    run_id: str
    status: str
    challenge_count: int
    solved: int
    candidates: int
    unsolved: int
    unsupported: int
    errors: int
    overlapping_waves: int


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_RUN_ROOT_NAME = re.compile(r"run-[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_DURABLE_TOOL_CALLS = 10
_MAX_DURABLE_TOOL_HASHES = 2
_UNLIMITED_SUBMISSION_WRONG_THRESHOLD = 5
_NO_PROGRESS_SECONDS = 600.0
_DURABLE_TOOL_NAMES = frozenset(
    {
        "audio_metadata",
        "decode_base64",
        "decode_hex",
        "decode_url",
        "decompress_gzip",
        "compute_exact",
        "derive_artifact",
        "dicom_metadata",
        "disassemble_elf",
        "elf_symbols",
        "extract_archive",
        "extract_strings",
        "http_request",
        "image_metadata",
        "inspect_artifact",
        "inspect_binary",
        "inspect_elf",
        "inspect_file",
        "inspect_filesystem",
        "list_tar",
        "list_workspace",
        "list_zip",
        "read_bytes",
        "read_text",
        "run_shell",
        "search_text",
        "target_info",
        "tcp_close",
        "tcp_exchange",
        "tcp_open",
        "wav_analyze",
    }
)


_CATEGORY_ORDER = {
    name: index
    for index, name in enumerate(("misc", "crypto", "forensics", "rev", "pwn", "network", "web"))
}


def _category_rank(value: str) -> int:
    normalized = re.sub(r"^\(practice\)\s*", "", value.strip(), flags=re.IGNORECASE).lower()
    return _CATEGORY_ORDER.get(normalized, len(_CATEGORY_ORDER))


def _durable_tool_name(value: object) -> str:
    return value if isinstance(value, str) and value in _DURABLE_TOOL_NAMES else "unknown_tool"


def _normalize_tool_calls(
    raw_calls: object,
) -> tuple[int, tuple[ToolCallEvidence, ...], bool]:
    if not isinstance(raw_calls, list):
        return 0, (), False
    evidence: list[ToolCallEvidence] = []
    complete = True
    for call in raw_calls:
        if not isinstance(call, dict) or not isinstance(call.get("success"), (bool, type(None))):
            complete = False
            continue
        raw_hashes = call.get("candidate_sha256s", ())
        hashes = (
            tuple(
                value
                for value in raw_hashes[:20]
                if isinstance(value, str) and _SHA256.fullmatch(value)
            )
            if isinstance(raw_hashes, (list, tuple))
            else ()
        )
        raw_supplied_hashes = call.get("supplied_candidate_sha256s", ())
        supplied_hashes = (
            tuple(
                value
                for value in raw_supplied_hashes[:20]
                if isinstance(value, str) and _SHA256.fullmatch(value)
            )
            if isinstance(raw_supplied_hashes, (list, tuple))
            else ()
        )
        name = _durable_tool_name(call.get("name"))
        success = call.get("success")
        source_bound = call.get("source_bound") is True
        raw_candidate_sensitive = call.get("candidate_sensitive")
        candidate_sensitive = (
            raw_candidate_sensitive is True or bool(hashes) or bool(supplied_hashes)
        )
        if raw_candidate_sensitive is not None and type(raw_candidate_sensitive) is not bool:
            complete = False
        observation = call.get("host_observation")
        if not isinstance(observation, HostObservation) or (
            observation.tool != name
            or observation.success is not success
            or observation.source_bound is not source_bound
            or observation.candidate_sensitive is not candidate_sensitive
            or observation.candidate_sha256s != hashes
            or observation.supplied_candidate_sha256s != supplied_hashes
        ):
            complete = False
            observation = project_tool_observation(
                name,
                success=success,
                source_bound=source_bound,
                candidate_sha256s=hashes,
                supplied_candidate_sha256s=supplied_hashes,
                candidate_sensitive=candidate_sensitive,
            )
        evidence.append(
            ToolCallEvidence(
                name=name,
                success=success,
                source_bound=source_bound,
                candidate_sensitive=candidate_sensitive,
                candidate_sha256s=hashes,
                supplied_candidate_sha256s=supplied_hashes,
                observation=observation,
            )
        )
    return len(raw_calls), tuple(evidence), complete and len(evidence) == len(raw_calls)


def _artifact_name(file_ref: str, index: int) -> str:
    raw = Path(urllib.parse.unquote(urllib.parse.urlsplit(file_ref).path)).name
    safe = _SAFE_NAME.sub("_", raw).strip("._")[:100] or "artifact.bin"
    return f"artifact-{index:03d}-{safe}"


def _max_parallel(results: list[LaneResult]) -> int:
    events: list[tuple[float, int]] = []
    for result in results:
        events.append((result.started, 1))
        events.append((result.finished, -1))
    active = maximum = 0
    for _, delta in sorted(events, key=lambda item: (item[0], item[1])):
        active += delta
        maximum = max(maximum, active)
    return maximum


def _instance_receipt(result: dict[str, Any]) -> str:
    encoded = json.dumps(
        {
            "connection_info": result.get("connection_info"),
            "since": result.get("since"),
            "until": result.get("until"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode()).hexdigest()


def _stable_challenge_files(challenge: Challenge) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        (parsed.scheme, parsed.netloc, parsed.path)
        for parsed in (urllib.parse.urlsplit(file_ref) for file_ref in challenge.files)
    )


def _challenge_coherence_key(challenge: Challenge) -> tuple[object, ...]:
    """Stable fields; timeout and attachment signatures are live Board values."""
    return (
        challenge.id,
        challenge.name,
        challenge.category,
        challenge.type,
        challenge.description,
        challenge.value,
        _stable_challenge_files(challenge),
        challenge.solved,
        challenge.max_attempts,
        challenge.attempts,
        challenge.shared,
    )


def _challenge_material_sha256(challenge: Challenge) -> str:
    """Bind same-run memory to stable solver inputs, excluding mutable Board counters."""
    encoded = json.dumps(
        {
            "id": challenge.id,
            "name": challenge.name,
            "category": challenge.category,
            "type": challenge.type,
            "description": challenge.description,
            "value": challenge.value,
            "files": _stable_challenge_files(challenge),
            "shared": challenge.shared,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode()).hexdigest()


class Orchestrator:
    _adaptive_control = False

    def __init__(
        self,
        config: RuntimeConfig,
        board: BoardClient,
        state: StateStore,
        runtime: NativeRuntime,
    ) -> None:
        self.config = config
        self.board = board
        self.state = state
        self.runtime = runtime
        self._slots = asyncio.Semaphore(config.concurrency)
        self._submission_lock = asyncio.Lock()
        self._run_evidence: RunEvidence | None = None

    def _run_report(
        self,
        run_id: str,
        status: str,
        challenge_count: int,
        outcomes: dict[int, str],
    ) -> RunReport:
        counts = {name: 0 for name in ("solved", "candidate", "unsolved", "unsupported", "error")}
        for terminal in outcomes.values():
            if terminal in counts:
                counts[terminal] += 1
        return RunReport(
            run_id=run_id,
            status=status,
            challenge_count=challenge_count,
            solved=counts["solved"],
            candidates=counts["candidate"],
            unsolved=counts["unsolved"],
            unsupported=counts["unsupported"],
            errors=counts["error"],
            overlapping_waves=self.state.overlapping_wave_count(run_id),
        )

    def _initial_peer_assignments(self) -> tuple[tuple[str, str, str], ...]:
        if self.config.peer_profile == "uniform_v1":
            return tuple(
                ("specialist", self.config.model, self.config.reasoning_effort)
                for _ in range(self.config.attempts_per_challenge)
            )
        assignments: list[tuple[str, str, str]] = []
        for lane in range(self.config.attempts_per_challenge):
            if lane < self.config.lead_lanes:
                assignments.append(("lead", self.config.model, self.config.reasoning_effort))
                continue
            effort_index = (lane - self.config.lead_lanes) % len(
                self.config.specialist_reasoning_efforts
            )
            assignments.append(
                (
                    "specialist",
                    self.config.specialist_model,
                    self.config.specialist_reasoning_efforts[effort_index],
                )
            )
        return tuple(assignments)

    async def _validate_peer_models(self, run_id: str, deadline: float) -> None:
        validator = getattr(self.runtime, "validate_model", None)
        if not callable(validator):
            return
        selections = {(self.config.model, self.config.reasoning_effort)}
        if self.config.peer_profile == "mixed_v1":
            selections.update(
                (self.config.specialist_model, effort)
                for effort in self.config.specialist_reasoning_efforts
            )
        for model, effort in sorted(selections):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RunDeadlineReached
            await asyncio.wait_for(validator(model, effort), timeout=remaining)
        self.state.event(
            run_id,
            "peer_models_validated",
            {
                "selections": [
                    {"model": model, "effort": effort} for model, effort in sorted(selections)
                ],
                "fallback": False,
            },
        )

    async def _board_call(
        self, deadline: float, function: Any, /, *args: Any, **kwargs: Any
    ) -> Any:
        """Run one bounded Board call without abandoning its worker on cancellation."""
        transport_timeout = float(getattr(self.board, "timeout", 15.0))
        if deadline - time.monotonic() <= transport_timeout:
            raise RunDeadlineReached
        task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            with suppress(Exception):
                await task
            raise

    async def _board_read(
        self, deadline: float, function: Any, /, *args: Any, **kwargs: Any
    ) -> Any:
        """Retry only idempotent Board reads after transport-level failures."""
        transport_timeout = float(getattr(self.board, "timeout", 15.0))
        for attempt in range(3):
            try:
                return await self._board_call(deadline, function, *args, **kwargs)
            except BoardTransportError:
                if attempt == 2:
                    raise
                delay = 0.25 * (2**attempt)
                if deadline - time.monotonic() <= transport_timeout + delay:
                    raise
                await asyncio.sleep(delay)
        raise AssertionError("unreachable Board read retry state")

    async def _cleanup_owned_instances(self, deadline: float) -> None:
        clean = True
        for record in self.state.owned_instances():
            clean = await self._cleanup_instance_record(record, deadline) and clean
        if not clean or self.state.owned_instances():
            raise BoardError("owned instance cleanup remains indeterminate")

    async def _cleanup_instance_record(
        self,
        record: dict[str, Any],
        deadline: float,
    ) -> bool:
        run_id = str(record["run_id"])
        challenge_id = int(record["challenge_id"])
        expected_receipt = record.get("receipt_sha256")
        if isinstance(expected_receipt, str):
            return await self._delete_instance(
                run_id,
                challenge_id,
                deadline,
                expected_receipt=expected_receipt,
                reason="restart_recovery",
            )
        try:
            current = await self._board_read(deadline, self.board.instance, "GET", challenge_id)
        except (BoardError, RunDeadlineReached):
            self.state.mark_instance(run_id, challenge_id, "cleanup_pending")
            self.state.event(
                run_id, "instance_cleanup", {"challenge_id": challenge_id, "status": "failed"}
            )
            return False
        if current.get("status") == 404:
            self.state.mark_instance(run_id, challenge_id, "removed")
            self.state.event(
                run_id, "instance_cleanup", {"challenge_id": challenge_id, "status": "absent"}
            )
            return True
        self.state.mark_instance(run_id, challenge_id, "cleanup_pending")
        self.state.event(
            run_id,
            "instance_cleanup",
            {
                "challenge_id": challenge_id,
                "status": "manual_reconciliation_required",
                "reason": "no generation receipt proves ownership",
            },
        )
        return False

    async def _delete_instance(
        self,
        run_id: str,
        challenge_id: int,
        deadline: float,
        *,
        expected_receipt: str,
        reason: str,
    ) -> bool:
        """Request deletion and verify remote absence without abandoning ownership."""
        self.state.mark_instance(run_id, challenge_id, "cleanup_pending")
        try:
            current = await self._board_read(deadline, self.board.instance, "GET", challenge_id)
        except (BoardError, RunDeadlineReached):
            self.state.event(
                run_id,
                "instance_cleanup",
                {"challenge_id": challenge_id, "status": "predelete_failed", "reason": reason},
            )
            return False
        if current.get("status") == 404:
            self.state.mark_instance(run_id, challenge_id, "removed")
            self.state.event(
                run_id,
                "instance_cleanup",
                {"challenge_id": challenge_id, "status": "absent", "reason": reason},
            )
            return True
        if current.get("success") is not True:
            self.state.event(
                run_id,
                "instance_cleanup",
                {
                    "challenge_id": challenge_id,
                    "status": "manual_reconciliation_required",
                    "reason": reason,
                    "detail": "Board state was indeterminate",
                },
            )
            return False
        if _instance_receipt(current) != expected_receipt:
            self.state.event(
                run_id,
                "instance_cleanup",
                {
                    "challenge_id": challenge_id,
                    "status": "manual_reconciliation_required",
                    "reason": reason,
                    "detail": "Board generation no longer matches owned receipt",
                },
            )
            return False
        try:
            result = await self._board_call(deadline, self.board.instance, "DELETE", challenge_id)
        except (BoardError, RunDeadlineReached):
            self.state.event(
                run_id,
                "instance_cleanup",
                {"challenge_id": challenge_id, "status": "delete_failed", "reason": reason},
            )
            return False
        if result.get("success") is not True:
            if result.get("status") == 404:
                self.state.mark_instance(run_id, challenge_id, "removed")
                self.state.event(
                    run_id,
                    "instance_cleanup",
                    {"challenge_id": challenge_id, "status": "absent", "reason": reason},
                )
                return True
            self.state.event(
                run_id,
                "instance_cleanup",
                {
                    "challenge_id": challenge_id,
                    "status": "delete_rejected",
                    "http_status": result.get("status"),
                    "reason": reason,
                },
            )
            return False
        while deadline - time.monotonic() > float(getattr(self.board, "timeout", 15.0)):
            try:
                current = await self._board_read(deadline, self.board.instance, "GET", challenge_id)
            except (BoardError, RunDeadlineReached):
                break
            if current.get("status") == 404:
                self.state.mark_instance(run_id, challenge_id, "removed")
                self.state.event(
                    run_id,
                    "instance_cleanup",
                    {"challenge_id": challenge_id, "status": "removed", "reason": reason},
                )
                return True
            if current.get("success") is not True:
                break
            await asyncio.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
        self.state.event(
            run_id,
            "instance_cleanup",
            {"challenge_id": challenge_id, "status": "absence_unverified", "reason": reason},
        )
        return False

    async def _recover_created_instance_receipt(
        self, run_id: str, challenge_id: int, deadline: float
    ) -> str:
        """Boundedly recover ownership evidence after a cancelled successful create."""
        transport_timeout = float(getattr(self.board, "timeout", 15.0))
        while deadline - time.monotonic() > transport_timeout:
            current = await self._board_read(deadline, self.board.instance, "GET", challenge_id)
            info = current.get("connection_info")
            if current.get("success") is True and isinstance(info, str) and info:
                receipt = _instance_receipt(current)
                self.state.mark_instance(run_id, challenge_id, "owned", receipt_sha256=receipt)
                self.state.event(
                    run_id,
                    "instance_receipt_recovered",
                    {"challenge_id": challenge_id, "receipt_sha256": receipt},
                )
                return receipt
            if current.get("status") in {403, 429}:
                break
            await asyncio.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
        raise BoardError("dynamic instance ownership receipt could not be recovered")

    async def _start_instance(
        self,
        run_id: str,
        challenge: Challenge,
        deadline: float,
        *,
        on_create_attempt: Callable[[], None] | None = None,
    ) -> tuple[tuple[TargetEndpoint, ...], str]:
        """Persist intent, create once, poll boundedly, and parse Board-issued endpoints."""
        existing = await self._board_read(deadline, self.board.instance, "GET", challenge.id)
        if existing.get("success") is True:
            raise BoardError("dynamic instance is already active without runtime ownership")
        if existing.get("status") != 404:
            raise BoardError("dynamic instance preflight was indeterminate")
        self.state.mark_instance(run_id, challenge.id, "creating")
        self.state.event(
            run_id, "instance_create_intent", {"challenge_id": challenge.id, "writes": 0}
        )
        transport_timeout = float(getattr(self.board, "timeout", 15.0))
        if deadline - time.monotonic() <= transport_timeout:
            raise RunDeadlineReached
        if on_create_attempt is not None:
            on_create_attempt()
        create_task = asyncio.create_task(
            asyncio.to_thread(self.board.instance, "POST", challenge.id)
        )
        cancelled: asyncio.CancelledError | None = None
        try:
            result = await asyncio.shield(create_task)
        except asyncio.CancelledError as exc:
            cancelled = exc
            try:
                result = await create_task
            except (BoardError, RunDeadlineReached):
                self.state.mark_instance(run_id, challenge.id, "cleanup_pending")
                raise cancelled
        except (BoardError, RunDeadlineReached):
            self.state.mark_instance(run_id, challenge.id, "cleanup_pending")
            raise
        self.state.event(
            run_id,
            "instance_create",
            {
                "challenge_id": challenge.id,
                "success": result.get("success") is True,
                "http_status": result.get("status"),
            },
        )
        if result.get("success") is not True:
            self.state.mark_instance(run_id, challenge.id, "cleanup_pending")
            if cancelled is not None:
                raise cancelled
            raise BoardError("dynamic instance creation was rejected")
        provisional_receipt: str | None = None
        if isinstance(result.get("connection_info"), str) and result["connection_info"]:
            provisional_receipt = _instance_receipt(result)
            self.state.mark_instance(
                run_id, challenge.id, "owned", receipt_sha256=provisional_receipt
            )
        if cancelled is not None:
            if provisional_receipt is None:
                recovery = asyncio.create_task(
                    self._recover_created_instance_receipt(
                        run_id,
                        challenge.id,
                        min(deadline, time.monotonic() + self.config.instance_cleanup_seconds),
                    )
                )
                while not recovery.done():
                    try:
                        provisional_receipt = await asyncio.shield(recovery)
                    except asyncio.CancelledError as exc:
                        cancelled = exc
                        continue
                    except (BoardError, RunDeadlineReached):
                        self.state.mark_instance(run_id, challenge.id, "cleanup_pending")
                        break
                if provisional_receipt is None:
                    try:
                        provisional_receipt = recovery.result()
                    except (BoardError, RunDeadlineReached):
                        self.state.mark_instance(run_id, challenge.id, "cleanup_pending")
            raise cancelled
        ready_deadline = min(deadline, time.monotonic() + self.config.instance_ready_seconds)
        while ready_deadline - time.monotonic() > float(getattr(self.board, "timeout", 15.0)):
            current = await self._board_read(
                ready_deadline, self.board.instance, "GET", challenge.id
            )
            info = current.get("connection_info")
            if current.get("success") is True and isinstance(info, str) and info:
                try:
                    endpoints = parse_connection_info(info)
                except ValueError as exc:
                    raise BoardError(
                        "dynamic instance returned invalid connection information"
                    ) from exc
                receipt = _instance_receipt(current)
                if provisional_receipt is not None and receipt != provisional_receipt:
                    raise BoardError("dynamic instance generation changed during creation")
                self.state.mark_instance(run_id, challenge.id, "owned", receipt_sha256=receipt)
                self.state.event(
                    run_id,
                    "instance_ready",
                    {
                        "challenge_id": challenge.id,
                        "receipt_sha256": receipt,
                        "endpoints": [
                            endpoint.public_record(index)
                            for index, endpoint in enumerate(endpoints)
                        ],
                    },
                )
                return endpoints, receipt
            if current.get("status") in {403, 429}:
                raise BoardError("dynamic instance readiness was rejected")
            await asyncio.sleep(min(2.0, max(0.0, ready_deadline - time.monotonic())))
        raise BoardError("dynamic instance did not become ready before the bounded deadline")

    async def _qualified_identity(self, deadline: float) -> tuple[int, int]:
        anonymous_rejected = await self._board_read(
            deadline, self.board.anonymous_identity_is_rejected
        )
        if anonymous_rejected is not True:
            raise BoardError("anonymous Board identity negative control failed")
        identity = await self._board_read(deadline, self.board.identity)
        confirmation = await self._board_read(deadline, self.board.identity)
        user_id = identity.get("id")
        team_id = identity.get("team_id")
        if type(user_id) is not int or user_id <= 0:
            raise BoardError("Board identity is not qualified")
        if type(team_id) is not int or team_id <= 0:
            raise BoardError("Board identity has no qualified team")
        if confirmation.get("id") != user_id or confirmation.get("team_id") != team_id:
            raise BoardError("consecutive Board identities were incoherent")
        self.state.bind_board_identity(user_id, team_id)
        return user_id, team_id

    async def _challenge_catalogue(
        self, deadline: float, identity: tuple[int, int]
    ) -> list[Challenge]:
        reads = [
            await self._board_read(deadline, self.board.list_challenges),
            await self._board_read(deadline, self.board.list_challenges),
        ]
        id_reads: list[list[int]] = []
        for rows in reads:
            ids: list[int] = []
            for row in rows:
                challenge_id = row.get("id")
                if type(challenge_id) is not int or challenge_id <= 0:
                    raise BoardError("challenge list contains an invalid id")
                ids.append(challenge_id)
            if not ids or len(ids) != len(set(ids)):
                raise BoardError("challenge list is empty or contains duplicate ids")
            id_reads.append(ids)
        if sorted(id_reads[0]) != sorted(id_reads[1]):
            raise BoardError("consecutive challenge lists were incoherent")
        ids = id_reads[0]
        for challenge_id in ids:
            if type(challenge_id) is not int or challenge_id <= 0:
                raise BoardError("challenge list contains an invalid id")
        details: list[Challenge] = []
        for challenge_id in ids:
            detail = await self._board_read(deadline, self.board.challenge, challenge_id)
            confirmation = await self._board_read(deadline, self.board.challenge, challenge_id)
            if _challenge_coherence_key(detail) != _challenge_coherence_key(confirmation):
                raise BoardError("consecutive challenge details were incoherent")
            details.append(detail)
        final_rows = await self._board_read(deadline, self.board.list_challenges)
        final_ids = [row.get("id") for row in final_rows]
        if (
            any(type(value) is not int or value <= 0 for value in final_ids)
            or len(final_ids) != len(set(final_ids))
            or sorted(final_ids) != sorted(ids)
        ):
            raise BoardError("challenge list changed during qualification")
        final_identity = await self._board_read(deadline, self.board.identity)
        if final_identity.get("id") != identity[0] or final_identity.get("team_id") != identity[1]:
            raise BoardError("Board identity changed during qualification")
        details.sort(
            key=lambda challenge: (
                _category_rank(challenge.category),
                challenge.value,
                challenge.id,
            )
        )
        balanced: list[Challenge] = []
        standard_slots = max(1, self.config.active_challenges - 1)
        for solved in (False, True):
            group = [challenge for challenge in details if challenge.solved is solved]
            dynamics = [challenge for challenge in group if challenge.type == "dynamic_iac"]
            standards = [challenge for challenge in group if challenge.type == "standard"]
            others = [
                challenge
                for challenge in group
                if challenge.type not in {"dynamic_iac", "standard"}
            ]
            while dynamics or standards:
                if dynamics:
                    balanced.append(dynamics.pop(0))
                for _ in range(standard_slots):
                    if standards:
                        balanced.append(standards.pop(0))
                    elif dynamics:
                        balanced.append(dynamics.pop(0))
            balanced.extend(others)
        details = balanced
        if self.config.challenge_ids:
            available = {challenge.id for challenge in details}
            missing = sorted(set(self.config.challenge_ids) - available)
            if missing:
                raise BoardError("configured challenge ids are absent from the qualified catalogue")
            selected = set(self.config.challenge_ids)
            details = [challenge for challenge in details if challenge.id in selected]
        return details

    async def _prepare_workspaces(
        self,
        run_root: Path,
        challenge: Challenge,
        episode: int,
        deadline: float,
        workspace_generation: int = 0,
        lane_count: int | None = None,
    ) -> list[tuple[Path, list[str]]]:
        lanes = self.config.attempts_per_challenge if lane_count is None else lane_count
        challenge_root = (
            run_root
            / f"challenge-{challenge.id}"
            / f"episode-{episode}"
            / f"generation-{workspace_generation}"
        )
        source_root = challenge_root / "source"
        source_root.mkdir(parents=True, exist_ok=False)
        context_payload = json.dumps(
            {
                "id": challenge.id,
                "name": challenge.name,
                "category": challenge.category,
                "type": challenge.type,
                "description": challenge.description,
                "value": challenge.value,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        source_paths: list[Path] = []
        total_bytes = 0
        for index, file_ref in enumerate(challenge.files, 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RunDeadlineReached
            destination = source_root / _artifact_name(file_ref, index)
            remaining_bytes = self.config.max_challenge_bytes - total_bytes
            if remaining_bytes <= 0:
                raise BoardError("challenge artifacts exceed the aggregate byte limit")
            result = await self._board_call(
                deadline,
                self.board.download,
                file_ref,
                destination,
                byte_limit=min(self.config.max_artifact_bytes, remaining_bytes),
            )
            downloaded = result.get("bytes") if isinstance(result, dict) else None
            if type(downloaded) is not int or downloaded < 0:
                raise BoardError("challenge download returned invalid byte evidence")
            total_bytes += downloaded
            if total_bytes > self.config.max_challenge_bytes:
                raise BoardError("challenge artifacts exceed the aggregate byte limit")
            source_paths.append(destination)

        if total_bytes * (lanes + 1) + len(context_payload) * lanes > (
            self.config.max_challenge_workspace_bytes
        ):
            raise BoardError("challenge artifact copies exceed the workspace byte limit")

        workspaces: list[tuple[Path, list[str]]] = []
        for lane in range(lanes):
            workspace = challenge_root / f"lane-{lane}"
            artifact_root = workspace / "artifacts"
            artifact_root.mkdir(parents=True, exist_ok=False)
            context_path = artifact_root / ".rapido-context.json"
            context_path.write_bytes(context_payload)
            context_path.chmod(0o600)
            relative_paths: list[str] = [context_path.relative_to(workspace).as_posix()]
            for source in source_paths:
                destination = artifact_root / source.name
                await self._drain_copyfile(source, destination)
                relative_paths.append(destination.relative_to(workspace).as_posix())
            workspaces.append((workspace, relative_paths))
        return workspaces

    async def _remove_tree_before(self, root: Path, deadline: float) -> None:
        stack: list[tuple[Path, bool]] = [(root, False)]
        operations = 0
        while stack:
            if time.monotonic() >= deadline:
                raise RunDeadlineReached
            path, visited = stack.pop()
            try:
                if path.is_symlink() or not path.is_dir():
                    path.unlink(missing_ok=True)
                elif visited:
                    path.rmdir()
                else:
                    stack.append((path, True))
                    stack.extend((child, False) for child in path.iterdir())
            except FileNotFoundError:
                continue
            operations += 1
            if operations % 64 == 0:
                await asyncio.sleep(0)

    async def _drain_rmtree(self, root: Path) -> None:
        task = asyncio.create_task(asyncio.to_thread(shutil.rmtree, root, True))
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            with suppress(Exception):
                await task
            raise

    async def _drain_copyfile(self, source: Path, destination: Path) -> None:
        task = asyncio.create_task(asyncio.to_thread(shutil.copyfile, source, destination))
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            with suppress(Exception):
                await task
            raise

    async def _drain_runtime_close(self) -> None:
        """Finish native teardown before propagating repeated cancellation."""
        close_task = asyncio.create_task(self.runtime.close())
        cancelled: asyncio.CancelledError | None = None
        while not close_task.done():
            try:
                await asyncio.shield(close_task)
            except asyncio.CancelledError as exc:
                cancelled = exc
        close_task.result()
        if cancelled is not None:
            raise cancelled

    async def _cleanup_stale_workspaces(self, deadline: float, current: Path) -> int:
        root = self.config.work_root
        self._ensure_private_work_root()
        stale = [
            child
            for child in root.iterdir()
            if child != current and _RUN_ROOT_NAME.fullmatch(child.name)
        ]
        for child in stale:
            await self._remove_tree_before(child, deadline)
        return len(stale)

    def _ensure_private_work_root(self) -> None:
        root = self.config.work_root
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = root.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_mode & 0o077
            or not os.access(root, os.R_OK | os.W_OK | os.X_OK)
        ):
            raise OSError("work root must be runtime/root owned, private, and writable")

    def _typed_same_run_memory(
        self,
        run_id: str,
        challenge_id: int,
        episode: int,
        lane: int,
        route: RouteSpec,
        run_evidence: RunEvidence,
    ) -> tuple[MemoryProjection, CandidateMemoryAggregate]:
        """Project verified earlier-episode facts; keep candidate identity controller-private."""
        target = MemoryTarget(run_id, challenge_id, episode, lane, route.role)
        contexts: list[CandidateContext] = []
        for source in self.state.private_candidate_context_sources(
            run_id,
            challenge_id,
            before_episode=episode,
        ):
            try:
                candidate = source["candidate"].decode("utf-8")
            except (AttributeError, UnicodeDecodeError) as exc:
                raise EvidenceError("private candidate encoding changed") from exc
            if (
                source["route_role"] != source["role"]
                or source["recipe_kind"] != "source_bound_tool_observation_v1"
            ):
                raise EvidenceError("private producer route or recipe changed")
            candidate_sha256 = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
            producer_source = run_evidence.memory_source(
                source["source_attempt_id"],
                candidate_sha256=candidate_sha256,
            )
            producer_evidence = CandidateEvidence(
                run_id=producer_source.run_id,
                challenge_id=producer_source.challenge_id,
                source_episode=producer_source.episode,
                source_lane=producer_source.lane,
                source_attempt_id=producer_source.attempt_id,
                role=source["route_role"],
                recipe_kind=source["recipe_kind"],
                manifest_complete=producer_source.complete,
                manifest_gap=producer_source.gap,
                candidate_observed=producer_source.candidate_observed,
                candidate_supplied=producer_source.candidate_supplied,
            )
            verification = None
            verifier_attempt_id = source["verifier_attempt_id"]
            if verifier_attempt_id is not None:
                try:
                    verifier_candidate = source["verifier_candidate"].decode("utf-8")
                except (AttributeError, UnicodeDecodeError) as exc:
                    raise EvidenceError("private verifier candidate encoding changed") from exc
                if (
                    verifier_candidate != candidate
                    or source["verifier_route_role"] != "verifier"
                    or source["verification_recipe_kind"] != "fresh_source_reobservation_v1"
                    or source["verifier_route_verification_recipe"]
                    != "fresh_source_reobservation_v1"
                ):
                    raise EvidenceError("private verifier linkage changed")
                verifier_source = run_evidence.memory_source(
                    verifier_attempt_id,
                    candidate_sha256=candidate_sha256,
                )
                verifier_evidence = CandidateEvidence(
                    run_id=verifier_source.run_id,
                    challenge_id=verifier_source.challenge_id,
                    source_episode=verifier_source.episode,
                    source_lane=verifier_source.lane,
                    source_attempt_id=verifier_source.attempt_id,
                    role="verifier",
                    recipe_kind=source["verification_recipe_kind"],
                    manifest_complete=verifier_source.complete,
                    manifest_gap=verifier_source.gap,
                    candidate_observed=verifier_source.candidate_observed,
                    candidate_supplied=verifier_source.candidate_supplied,
                )
                verification = CandidateVerification(
                    run_id=run_id,
                    challenge_id=challenge_id,
                    producer_attempt_id=source["source_attempt_id"],
                    verifier_attempt_id=verifier_attempt_id,
                    recipe_kind=source["verification_recipe_kind"],
                    candidate=candidate,
                    evidence=verifier_evidence,
                )
            contexts.append(
                CandidateContext(
                    run_id=run_id,
                    challenge_id=challenge_id,
                    source_episode=source["episode"],
                    source_lane=source["lane"],
                    source_attempt_id=source["source_attempt_id"],
                    role=source["role"],
                    recipe_kind=source["recipe_kind"],
                    candidate=candidate,
                    evidence=producer_evidence,
                    verification=verification,
                )
            )
        candidate_memory = CandidateMemoryAggregate.from_contexts(contexts)
        if route.role == "verifier":
            return (
                project_memory(
                    (),
                    target,
                    arm=self.config.memory_arm,
                    candidate_memory=candidate_memory,
                ),
                candidate_memory,
            )

        records = []
        for source in self.state.same_run_memory_sources(
            run_id,
            challenge_id,
            target_lane=lane,
            before_episode=episode,
        ):
            evidence_source = run_evidence.memory_source(source["source_attempt_id"])
            if source["summary"] is not None:
                records.append(
                    AnalysisClaim(
                        record_id=f"{source['source_attempt_id']}:analysis",
                        run_id=run_id,
                        challenge_id=challenge_id,
                        source_episode=source["source_episode"],
                        source_lane=source["source_lane"],
                        source_attempt_id=source["source_attempt_id"],
                        status=source["status"],
                        summary=source["summary"],
                        evidence=tuple(source["evidence"]),
                        next_steps=tuple(source["next_steps"]),
                        tool_count=source["tool_count"],
                    )
                )
            if (
                source["role"] is not None
                and source["tactic"] is not None
                and source["tool_profile"] is not None
            ):
                records.append(
                    TacticOutcome(
                        record_id=f"{source['source_attempt_id']}:tactic",
                        run_id=run_id,
                        challenge_id=challenge_id,
                        source_episode=source["source_episode"],
                        source_lane=source["source_lane"],
                        source_attempt_id=source["source_attempt_id"],
                        role=source["role"],
                        tactic=source["tactic"],
                        tool_profile=source["tool_profile"],
                        status=source["status"],
                    )
                )
            for observation in evidence_source.observations:
                records.append(
                    MemoryHostObservation(
                        record_id=f"{source['source_attempt_id']}:host:{observation.ordinal}",
                        run_id=run_id,
                        challenge_id=challenge_id,
                        source_episode=source["source_episode"],
                        source_lane=source["source_lane"],
                        source_attempt_id=source["source_attempt_id"],
                        complete=evidence_source.complete,
                        gap=evidence_source.gap,
                        tool=observation.tool,
                        success=observation.success,
                        source_bound=observation.source_bound,
                        facts=observation.facts,
                    )
                )
            for observation in source["checkpoint_observations"]:
                if (
                    type(observation.get("ordinal")) is not int
                    or type(observation.get("complete")) is not bool
                    or observation.get("gap") is not None
                    and not isinstance(observation.get("gap"), str)
                    or not isinstance(observation.get("tool"), str)
                    or observation.get("success") is not None
                    and type(observation.get("success")) is not bool
                    or type(observation.get("source_bound")) is not bool
                    or not isinstance(observation.get("facts"), dict)
                ):
                    raise EvidenceError("durable primary checkpoint observation is invalid")
                records.append(
                    MemoryHostObservation(
                        record_id=(
                            f"{source['source_attempt_id']}:checkpoint:"
                            f"{int(observation['ordinal'])}"
                        ),
                        run_id=run_id,
                        challenge_id=challenge_id,
                        source_episode=source["source_episode"],
                        source_lane=source["source_lane"],
                        source_attempt_id=source["source_attempt_id"],
                        complete=observation["complete"],
                        gap=(None if observation["gap"] is None else str(observation["gap"])),
                        tool=str(observation["tool"]),
                        success=observation["success"],
                        source_bound=observation["source_bound"],
                        facts=observation["facts"],
                    )
                )
        for failure in self.state.same_run_memory_failures(
            run_id,
            challenge_id,
            before_episode=episode,
        ):
            records.append(
                FailureRecord(
                    record_id=failure["record_id"],
                    run_id=run_id,
                    challenge_id=challenge_id,
                    source_episode=failure["source_episode"],
                    source_lane=failure["source_lane"],
                    source_attempt_id=failure["source_attempt_id"],
                    failure_kind=failure["failure_kind"],
                    subreason=failure["subreason"],
                )
            )
        return (
            project_memory(
                records,
                target,
                arm=self.config.memory_arm,
                candidate_memory=candidate_memory,
            ),
            candidate_memory,
        )

    async def _lane(
        self,
        run_id: str,
        challenge: Challenge,
        episode: int,
        lane: int,
        workspace: Path,
        artifact_paths: list[str],
        timeout_seconds: float,
        target_endpoints: tuple[TargetEndpoint, ...] = (),
        route: RouteSpec | None = None,
        candidate_submitter: Callable[[str], Awaitable[str]] | None = None,
    ) -> LaneResult:
        attempt_id = f"{run_id}:{challenge.id}:{episode}:{lane}"
        run_evidence = self._run_evidence
        if run_evidence is None or run_evidence.run_id != run_id:
            run_evidence = RunEvidence.open(self.state, run_id)
        verifier_route = route is not None and route.role == "verifier"
        same_run_memory = None
        candidate_memory = CandidateMemoryAggregate()
        if self._adaptive_control:
            if route is None:
                raise ValueError("adaptive lane requires a typed route")
            same_run_memory, candidate_memory = self._typed_same_run_memory(
                run_id,
                challenge.id,
                episode,
                lane,
                route,
                run_evidence,
            )
            agent_role, model, effort = self.state.control_assignment(
                run_id, challenge.id, episode, lane
            )
            execution_route = replace(route, model=model, effort=effort)
        else:
            agent_role = "specialist"
            model = self.config.model
            effort = self.config.reasoning_effort
            execution_route = route
        self.state.start_attempt(
            attempt_id,
            run_id,
            challenge.id,
            episode,
            lane,
            model,
            effort,
            require_control_assignment=self._adaptive_control,
        )
        started = time.monotonic()
        tool_call_count = 0
        tool_calls: tuple[ToolCallEvidence, ...] = ()
        tool_evidence_complete = False
        target_registry = None
        submission_status: str | None = None

        def finish_attempt(
            status: str,
            *,
            evidence_gap: str | None = None,
            **fields: Any,
        ) -> None:
            complete = tool_evidence_complete and evidence_gap is None
            gap = evidence_gap or (None if complete else "provenance_incomplete")
            run_evidence.commit(
                attempt_id,
                EvidenceBatch(
                    observations=tuple(call.observation for call in tool_calls),
                    complete=complete,
                    gap=gap,
                ),
            )
            if self._adaptive_control and status == "candidate":
                candidate = fields.get("candidate")
                if not isinstance(candidate, str):
                    raise CandidateProvenanceError("candidate_evidence_incomplete")
                proof = run_evidence.attest_candidate(
                    attempt_id,
                    candidate_sha256=hashlib.sha256(candidate.encode()).hexdigest(),
                    require_non_execution_observation=verifier_route,
                )
                if proof is None:
                    reason = (
                        "verifier_requires_fixed_observation"
                        if verifier_route
                        else "candidate_evidence_incomplete"
                    )
                    raise CandidateProvenanceError(reason)
            try:
                self.state.finish_attempt(
                    attempt_id,
                    status,
                    retain_private_candidate=self._adaptive_control and status == "candidate",
                    **fields,
                )
            except ValueError as exc:
                raise EvidenceError(
                    "sealed attempt could not transition to terminal state"
                ) from exc

        try:
            if target_endpoints:
                target_registry = TargetToolRegistry(
                    workspace,
                    target_endpoints,
                    team_key=self.config.team_key,
                    max_workspace_bytes=self.config.max_lane_workspace_bytes,
                )
            prior_attempts = []
            compacted_records = 0
            rejected_records = 0
            if not self._adaptive_control and not verifier_route:
                for record in self.state.prior_attempts_for_lane(
                    run_id,
                    challenge.id,
                    lane,
                    before_episode=episode,
                    limit=MAX_PRIOR_ATTEMPTS,
                ):
                    try:
                        projected, compacted = project_attempt_carry(record)
                    except (TypeError, ValueError):
                        rejected_records += 1
                        continue
                    prior_attempts.append(projected)
                    compacted_records += int(compacted)
            persistent_primary = (
                self._adaptive_control
                and self.config.peer_profile == "mixed_v1"
                and route is not None
                and route.role != "verifier"
                and (challenge.type != "dynamic_iac" or bool(target_endpoints))
            )
            turn_prompt = build_turn_prompt(
                challenge,
                artifact_paths,
                lane,
                run_id=run_id if self._adaptive_control else None,
                episode=episode,
                prior_attempts=tuple(prior_attempts),
                prior_observations=(
                    None
                    if verifier_route or self._adaptive_control
                    else run_evidence.carry(
                        challenge.id,
                        lane,
                        before_episode=episode,
                    )
                ),
                control_route=execution_route,
                same_run_memory=same_run_memory,
                agent_role=(
                    agent_role
                    if self._adaptive_control and self.config.peer_profile == "mixed_v1"
                    else None
                ),
                execution_phase=(
                    "shared_instance"
                    if target_endpoints
                    else "local_analysis"
                    if challenge.type == "dynamic_iac"
                    else "standard"
                ),
                persistent_primary=persistent_primary,
            )
            omitted_for_budget = len(prior_attempts) - len(
                json.loads(turn_prompt)["prior_attempts"]
            )
            if compacted_records or rejected_records or omitted_for_budget:
                self.state.event(
                    run_id,
                    "attempt_carry_sanitized",
                    {
                        "challenge_id": challenge.id,
                        "episode": episode,
                        "lane": lane,
                        "compacted_records": compacted_records,
                        "rejected_records": rejected_records,
                        "omitted_for_prompt_budget": omitted_for_budget,
                    },
                )
            if same_run_memory is not None:
                if (
                    target_endpoints
                    and route is not None
                    and route.role == "recovery"
                    and not same_run_memory.records
                ):
                    raise EvidenceError("shared-instance recovery has no typed local memory")
                self.state.event(
                    run_id,
                    "same_run_memory_projected",
                    {
                        "challenge_id": challenge.id,
                        "episode": episode,
                        "lane": lane,
                        "role": route.role if route is not None else "specialist",
                        "arm": self.config.memory_arm,
                        "record_count": len(same_run_memory.records),
                        "deduplicated_record_count": (same_run_memory.deduplicated_record_count),
                        "omitted_record_count": same_run_memory.omitted_record_count,
                        "encoded_bytes": same_run_memory.encoded_bytes,
                        **candidate_memory.public_counts(),
                    },
                )
            progress_at = time.monotonic()

            def note_progress() -> None:
                nonlocal progress_at
                progress_at = time.monotonic()

            continuation_round = 0

            def validate_candidate(
                finding: SolverFinding,
                calls: tuple[ToolCallEvidence, ...],
                complete: bool,
            ) -> None:
                if finding.candidate is None:
                    return
                if self._adaptive_control and not complete:
                    raise CandidateProvenanceError("candidate_evidence_incomplete")
                if not candidate_is_eligible(
                    finding.candidate, challenge_candidate_prose(challenge)
                ):
                    raise CandidateProvenanceError("candidate_ineligible")
                candidate_fingerprint = hashlib.sha256(finding.candidate.encode()).hexdigest()
                candidate_observed = False
                candidate_supplied = False
                for call in calls:
                    candidate_supplied |= candidate_fingerprint in call.supplied_candidate_sha256s
                    if call.success is True and call.source_bound:
                        observed_here = candidate_fingerprint in call.candidate_sha256s
                        candidate_observed |= observed_here
                if candidate_supplied:
                    raise CandidateProvenanceError("candidate_supplied")
                if not candidate_observed:
                    raise CandidateProvenanceError("candidate_unobserved")

            def continue_primary(turn: NativeTurn, remaining_seconds: float | None) -> str | None:
                nonlocal continuation_round
                if not persistent_primary or turn.status != "completed":
                    return None
                checkpoint: SolverFinding | None = None
                qualified_candidate = False
                try:
                    checkpoint = SolverFinding.from_message(turn.text)
                    _, checkpoint_calls, checkpoint_complete = _normalize_tool_calls(
                        getattr(turn, "current_turn_tool_calls", turn.tool_calls)
                    )
                    validate_candidate(checkpoint, checkpoint_calls, checkpoint_complete)
                except CandidateProvenanceError as exc:
                    reason = str(exc)
                except SolverOutputError:
                    reason = "solver_output"
                else:
                    if checkpoint.candidate is not None:
                        qualified_candidate = True
                        reason = "qualified_candidate"
                    else:
                        reason = checkpoint.status
                if (
                    not qualified_candidate
                    and remaining_seconds is not None
                    and remaining_seconds <= 1
                ):
                    return None
                if not qualified_candidate:
                    continuation_round += 1
                checkpoint_tool_count, checkpoint_calls, checkpoint_complete = (
                    _normalize_tool_calls(turn.tool_calls)
                )
                checkpoint_observations = []
                for ordinal, call in enumerate(checkpoint_calls[-_MAX_DURABLE_TOOL_CALLS:]):
                    facts = sanitize_public_value(call.observation.facts)
                    checkpoint_observations.append(
                        {
                            "ordinal": ordinal,
                            "complete": checkpoint_complete,
                            "gap": None if checkpoint_complete else "provenance_incomplete",
                            "tool": call.name,
                            "success": call.success,
                            "source_bound": call.source_bound,
                            "facts": facts if isinstance(facts, dict) else {},
                        }
                    )
                checkpoint_text = (
                    ()
                    if checkpoint is None
                    else (checkpoint.summary, *checkpoint.evidence, *checkpoint.next_steps)
                )
                candidate_free_checkpoint = (
                    checkpoint is not None
                    and checkpoint.candidate is None
                    and not any(FLAG_RE.search(value) for value in checkpoint_text)
                )
                self.state.checkpoint_attempt(
                    attempt_id,
                    summary=(
                        checkpoint.summary
                        if candidate_free_checkpoint
                        else (
                            "primary checkpoint retained a qualified private candidate"
                            if qualified_candidate
                            else f"primary checkpoint requires {reason}"
                        )
                    ),
                    candidate=(
                        checkpoint.candidate
                        if qualified_candidate and checkpoint is not None
                        else None
                    ),
                    evidence=(checkpoint.evidence if candidate_free_checkpoint else ()),
                    next_steps=(
                        checkpoint.next_steps
                        if candidate_free_checkpoint
                        else ("continue with changed evidence-specific work",)
                    ),
                    observations=checkpoint_observations,
                    tool_count=checkpoint_tool_count,
                )
                if qualified_candidate:
                    self.state.event(
                        run_id,
                        "primary_candidate_checkpointed",
                        {
                            "challenge_id": challenge.id,
                            "episode": episode,
                            "lane": lane,
                            "tool_call_count": checkpoint_tool_count,
                        },
                    )
                    return None
                self.state.event(
                    run_id,
                    "primary_solver_continued",
                    {
                        "challenge_id": challenge.id,
                        "episode": episode,
                        "lane": lane,
                        "continuation_round": continuation_round,
                        "reason": reason,
                        "tool_call_count": checkpoint_tool_count,
                        "remaining_milliseconds": (
                            None
                            if remaining_seconds is None
                            else max(0, int(remaining_seconds * 1000))
                        ),
                    },
                )
                return build_primary_continuation_prompt(
                    reason=reason,
                    continuation_round=continuation_round,
                    remaining_seconds=remaining_seconds,
                )

            async with asyncio.timeout(timeout_seconds + 5):
                solve_call = self.runtime.solve(
                    workspace,
                    turn_prompt,
                    developer_instructions=DEVELOPER_INSTRUCTIONS,
                    model=model,
                    reasoning_effort=effort,
                    output_schema=SOLVER_OUTPUT_SCHEMA,
                    timeout=timeout_seconds,
                    tool_registry=target_registry,
                    progress_callback=note_progress,
                    continuation_callback=continue_primary if persistent_primary else None,
                )
                if timeout_seconds <= _NO_PROGRESS_SECONDS:
                    turn = await solve_call
                else:
                    solve_task = asyncio.create_task(solve_call)
                    try:
                        while True:
                            quiet_remaining = _NO_PROGRESS_SECONDS - (
                                time.monotonic() - progress_at
                            )
                            done, _ = await asyncio.wait(
                                {solve_task},
                                timeout=max(0.0, quiet_remaining),
                            )
                            if done:
                                turn = solve_task.result()
                                break
                            if time.monotonic() - progress_at < _NO_PROGRESS_SECONDS:
                                continue
                            solve_task.cancel()
                            cancelled = (await asyncio.gather(solve_task, return_exceptions=True))[
                                0
                            ]
                            error = NoProgressError(
                                "native turn exceeded its no-tool-progress window"
                            )
                            result = getattr(cancelled, "result", None)
                            if result is not None:
                                error.result = result
                            raise error
                    finally:
                        if not solve_task.done():
                            solve_task.cancel()
                            await asyncio.gather(solve_task, return_exceptions=True)
            tool_call_count, tool_calls, tool_evidence_complete = _normalize_tool_calls(
                turn.tool_calls
            )
            if turn.status != "completed":
                raise NativeTurnIncompleteError(
                    turn.status,
                    getattr(turn, "failure_class", None),
                )
            finding = SolverFinding.from_message(turn.text)
            _, candidate_calls, candidate_evidence_complete = _normalize_tool_calls(
                getattr(turn, "current_turn_tool_calls", turn.tool_calls)
            )
            validate_candidate(finding, candidate_calls, candidate_evidence_complete)
            terminal = "candidate" if finding.status == "candidate" else finding.status
            private_candidate = self._adaptive_control and finding.candidate is not None
            finish_attempt(
                terminal,
                summary="candidate retained privately" if private_candidate else finding.summary,
                candidate=finding.candidate,
                confidence=None if private_candidate else finding.confidence,
                evidence=() if private_candidate else finding.evidence,
                next_steps=() if private_candidate else finding.next_steps,
                tool_count=tool_call_count,
            )
        except TimeoutError as exc:
            finding = None
            terminal = "timeout"
            no_progress = isinstance(exc, NoProgressError)
            timeout_calls = getattr(getattr(exc, "result", None), "tool_calls", None)
            tool_count_known = isinstance(timeout_calls, list)
            if tool_count_known:
                tool_call_count, tool_calls, tool_evidence_complete = _normalize_tool_calls(
                    timeout_calls
                )
            finish_attempt(
                terminal,
                evidence_gap="turn_no_progress" if no_progress else "turn_timeout",
                summary=(
                    "native turn made no host-visible tool progress"
                    if no_progress
                    else "native turn exceeded deadline"
                ),
                tool_count=tool_call_count,
                failure_class="no_progress" if no_progress else "timeout",
            )
            self.state.event(
                run_id,
                "attempt_timeout_telemetry",
                {
                    "challenge_id": challenge.id,
                    "episode": episode,
                    "lane": lane,
                    "reason": "no_progress" if no_progress else "deadline",
                    "tool_call_count": tool_call_count if tool_count_known else None,
                },
            )
        except asyncio.CancelledError as exc:
            cancelled_calls = getattr(getattr(exc, "result", None), "tool_calls", None)
            if isinstance(cancelled_calls, list):
                tool_call_count, tool_calls, tool_evidence_complete = _normalize_tool_calls(
                    cancelled_calls
                )
            finish_attempt(
                "cancelled",
                evidence_gap="turn_cancelled",
                summary="run shutdown",
                tool_count=tool_call_count,
                failure_class="cancelled",
            )
            raise
        except CandidateProvenanceError as exc:
            subreason = str(exc)
            finding = None
            terminal = "unsolved"
            finish_attempt(
                terminal,
                summary=f"flag-shaped hypothesis rejected by provenance policy: {subreason}",
                tool_count=tool_call_count,
                failure_class="candidate_provenance",
            )
            self.state.event(
                run_id,
                "attempt_failure",
                {
                    "challenge_id": challenge.id,
                    "episode": episode,
                    "lane": lane,
                    "reason": "candidate_provenance",
                    "subreason": subreason,
                },
            )
        except SolverOutputError:
            finding = None
            terminal = "failed"
            finish_attempt(
                terminal,
                summary="native turn failed safely",
                tool_count=tool_call_count,
                failure_class="solver_output",
            )
            self.state.event(
                run_id,
                "attempt_failure",
                {
                    "challenge_id": challenge.id,
                    "episode": episode,
                    "lane": lane,
                    "reason": "solver_output",
                },
            )
        except NativeTurnIncompleteError as exc:
            finding = None
            terminal = "failed"
            finish_attempt(
                terminal,
                summary="native turn failed safely",
                tool_count=tool_call_count,
                failure_class=exc.failure_class,
            )
            self.state.event(
                run_id,
                "attempt_failure",
                {
                    "challenge_id": challenge.id,
                    "episode": episode,
                    "lane": lane,
                    "reason": "native_turn_incomplete",
                    "status": exc.status,
                    "failure_class": exc.failure_class,
                },
            )
        except EvidenceError:
            raise
        except RuntimeError:
            finding = None
            terminal = "failed"
            finish_attempt(
                terminal,
                evidence_gap="turn_failed",
                summary="native turn failed safely",
                tool_count=tool_call_count,
                failure_class="native_runtime",
            )
            self.state.event(
                run_id,
                "attempt_failure",
                {
                    "challenge_id": challenge.id,
                    "episode": episode,
                    "lane": lane,
                    "reason": "native_runtime",
                },
            )
        except OSError:
            finding = None
            terminal = "failed"
            finish_attempt(
                terminal,
                evidence_gap="turn_failed",
                summary="native turn failed safely",
                tool_count=tool_call_count,
                failure_class="operating_system",
            )
            self.state.event(
                run_id,
                "attempt_failure",
                {
                    "challenge_id": challenge.id,
                    "episode": episode,
                    "lane": lane,
                    "reason": "operating_system",
                },
            )
        except ValueError:
            finding = None
            terminal = "failed"
            finish_attempt(
                terminal,
                evidence_gap="turn_failed",
                summary="native turn failed safely",
                tool_count=tool_call_count,
                failure_class="invalid_value",
            )
            self.state.event(
                run_id,
                "attempt_failure",
                {
                    "challenge_id": challenge.id,
                    "episode": episode,
                    "lane": lane,
                    "reason": "invalid_value",
                },
            )
        finally:
            if target_registry is not None:
                target_registry.close()
        if (
            finding is not None
            and finding.candidate is not None
            and candidate_submitter is not None
        ):
            submission_status = await candidate_submitter(finding.candidate)
        return LaneResult(
            episode,
            lane,
            started,
            time.monotonic(),
            finding,
            terminal,
            tool_call_count,
            tool_calls,
            submission_status,
        )

    def _withhold_candidate(
        self,
        run_id: str,
        challenge_id: int,
        candidate_sha256: str,
        reason: str,
    ) -> str:
        self.state.event(
            run_id,
            "candidate_withheld",
            {
                "challenge_id": challenge_id,
                **({} if self._adaptive_control else {"candidate_sha256": candidate_sha256}),
                "reason": reason,
            },
        )
        self.state.set_challenge_status(challenge_id, "candidate")
        return "candidate"

    async def _submit_candidate(
        self,
        run_id: str,
        challenge: Challenge,
        candidate: str,
        deadline: float,
    ) -> str:
        """Serialize eligibility, reservation, Board effect, and finalization."""
        fingerprint = hashlib.sha256(candidate.encode()).hexdigest()
        async with self._submission_lock:
            if self.state.challenge_has_correct_submission(run_id, challenge.id):
                return self._withhold_candidate(
                    run_id, challenge.id, fingerprint, "challenge_already_solved_in_run"
                )
            if self.state.challenge_unresolved_submission_count(challenge.id) > 0:
                return self._withhold_candidate(
                    run_id, challenge.id, fingerprint, "submission_pending_reconciliation"
                )
            unlimited = challenge.max_attempts in (None, 0)
            prior_wrong = self.state.challenge_incorrect_submission_count(challenge.id)
            verified = self.state.candidate_is_verified(run_id, challenge.id, candidate)
            qualified = verified
            if (
                self._adaptive_control
                and not qualified
                and (not unlimited or prior_wrong >= _UNLIMITED_SUBMISSION_WRONG_THRESHOLD)
            ):
                return self._withhold_candidate(
                    run_id,
                    challenge.id,
                    fingerprint,
                    "candidate_unverified_after_limit_or_wrong_threshold",
                )
            transport_timeout = float(getattr(self.board, "timeout", 15.0))
            if deadline - time.monotonic() <= transport_timeout:
                return self._withhold_candidate(run_id, challenge.id, fingerprint, "run_deadline")
            current = challenge
            if not unlimited:
                try:
                    current = await self._board_read(deadline, self.board.challenge, challenge.id)
                except (BoardError, RunDeadlineReached):
                    return self._withhold_candidate(
                        run_id, challenge.id, fingerprint, "eligibility_refresh_failed"
                    )
                unlimited = current.max_attempts in (None, 0)
                if self._adaptive_control and not qualified and not unlimited:
                    return self._withhold_candidate(
                        run_id, challenge.id, fingerprint, "candidate_unverified_after_limit"
                    )
            if (
                not current.solved
                and current.max_attempts not in (None, 0)
                and current.attempts >= current.max_attempts
            ):
                return self._withhold_candidate(run_id, challenge.id, fingerprint, "board_limit")
            if deadline - time.monotonic() <= transport_timeout:
                return self._withhold_candidate(run_id, challenge.id, fingerprint, "run_deadline")
            if not self.state.reserve_submission(run_id, challenge.id, candidate):
                return self._withhold_candidate(
                    run_id, challenge.id, fingerprint, "submission_already_reserved"
                )
            try:
                verdict: Verdict = await self._board_call(
                    deadline, self.board.submit, challenge.id, candidate
                )
            except (BoardError, RunDeadlineReached):
                return self._withhold_candidate(
                    run_id,
                    challenge.id,
                    fingerprint,
                    "submission_pending_reconciliation",
                )
            self.state.finalize_submission(
                run_id, challenge.id, candidate, verdict.outcome, verdict.http_status
            )
            self.state.event(
                run_id,
                "submission",
                {
                    "challenge_id": challenge.id,
                    "outcome": verdict.outcome,
                    "http_status": verdict.http_status,
                    "run_local_verified": verdict.outcome == "correct",
                },
            )
            if verdict.outcome == "correct":
                status = "solved"
            elif verdict.outcome in {"already_solved", "paused", "ratelimited", "unread"}:
                status = "candidate"
            else:
                status = "unsolved"
            self.state.set_challenge_status(challenge.id, status)
            return status

    async def _solve_challenge(
        self,
        run_id: str,
        run_root: Path,
        challenge: Challenge,
        deadline: float,
        target_endpoints: tuple[TargetEndpoint, ...] = (),
        *,
        episode: int = 0,
        route: RouteSpec | None = None,
        lane_count: int | None = None,
    ) -> str:
        self.state.set_challenge_status(challenge.id, "running")
        try:
            workspaces = await self._prepare_workspaces(
                run_root,
                challenge,
                episode,
                deadline,
                0 if route is None else route.workspace_generation,
                lane_count,
            )
        except RunDeadlineReached:
            self.state.set_challenge_status(challenge.id, "unsolved")
            raise
        except BoardError:
            if self._adaptive_control:
                self.state.record_control_failure_origin(run_id, challenge.id, episode, "board")
            self.state.set_challenge_status(challenge.id, "error")
            return "error"
        except OSError:
            if self._adaptive_control:
                self.state.record_control_failure_origin(run_id, challenge.id, episode, "container")
            self.state.set_challenge_status(challenge.id, "error")
            return "error"
        if self._adaptive_control:
            started_lanes = self.state.start_control_wave(run_id, challenge.id, episode)
            if lane_count is not None and started_lanes != lane_count:
                raise RuntimeError("control wave lane count changed before execution")
            lane_count = started_lanes
        remaining = max(0.0, deadline - time.monotonic())
        attempt_seconds = self.config.attempt_seconds if route is None else route.attempt_seconds
        timeout = min(float(attempt_seconds), remaining)
        if timeout <= 0:
            self.state.set_challenge_status(challenge.id, "unsolved")
            return "unsolved"

        async def scheduled_lane(lane: int, workspace: Path, artifacts: list[str]) -> LaneResult:
            async with self._slots:
                return await self._lane(
                    run_id,
                    challenge,
                    episode,
                    lane,
                    workspace,
                    artifacts,
                    timeout,
                    target_endpoints,
                    route,
                    submit_from_lane if self._adaptive_control else None,
                )

        async def submit_from_lane(candidate: str) -> str:
            fingerprint = hashlib.sha256(candidate.encode()).hexdigest()
            if not self.config.submit_candidates:
                return self._withhold_candidate(
                    run_id, challenge.id, fingerprint, "submissions_disabled"
                )
            return await self._submit_candidate(run_id, challenge, candidate, deadline)

        pending = {
            asyncio.create_task(scheduled_lane(lane, workspace, artifacts))
            for lane, (workspace, artifacts) in enumerate(workspaces)
        }
        results: list[LaneResult] = []
        winner_found = False
        try:
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    results.append(task.result())
                if any(result.submission_status == "solved" for result in results):
                    winner_found = True
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    pending.clear()
                    break
                current_findings = [
                    result.finding for result in results if result.finding is not None
                ]
                legacy_agreement = (
                    not self._adaptive_control
                    and admitted_candidate(current_findings, challenge.description) is not None
                )
                if legacy_agreement:
                    winner_found = True
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    pending.clear()
        except BaseException:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            self.state.set_challenge_status(challenge.id, "queued")
            raise
        parallel = _max_parallel(results)
        self.state.event(
            run_id,
            "attempt_wave",
            {
                "challenge_id": challenge.id,
                "episode": episode,
                "lanes": len(results),
                "max_parallel": parallel,
                "overlap": parallel >= 2,
                "winner_cancelled_pending": winner_found,
                "durations_seconds": [round(item.finished - item.started, 3) for item in results],
                "tool_calls": [
                    {
                        "episode": item.episode,
                        "lane": item.lane,
                        "tool_call_count": item.tool_call_count,
                        "retained_tool_call_count": min(
                            len(item.tool_calls), _MAX_DURABLE_TOOL_CALLS
                        ),
                        "tool_calls_truncated": item.tool_call_count
                        > min(len(item.tool_calls), _MAX_DURABLE_TOOL_CALLS),
                        "calls": [
                            {
                                "name": call.name,
                                "success": call.success,
                                "source_bound": call.source_bound,
                                "candidate_sensitive": call.candidate_sensitive,
                                **(
                                    {}
                                    if self._adaptive_control
                                    else {
                                        "candidate_sha256s": list(
                                            call.candidate_sha256s[:_MAX_DURABLE_TOOL_HASHES]
                                        ),
                                        "supplied_candidate_sha256s": list(
                                            call.supplied_candidate_sha256s[
                                                :_MAX_DURABLE_TOOL_HASHES
                                            ]
                                        ),
                                    }
                                ),
                            }
                            for call in item.tool_calls[:_MAX_DURABLE_TOOL_CALLS]
                        ],
                    }
                    for item in results
                ],
            },
        )
        verified_candidate = (
            self.state.verified_candidate(run_id, challenge.id) if self._adaptive_control else None
        )
        if any(result.submission_status == "solved" for result in results):
            self.state.set_challenge_status(challenge.id, "solved")
            return "solved"
        if (
            self._adaptive_control
            and verified_candidate is None
            and self.state.pending_candidate_count(run_id, challenge.id) > 0
        ):
            self.state.set_challenge_status(challenge.id, "candidate")
            return "candidate"
        if parallel < 2 and verified_candidate is None:
            self.state.set_challenge_status(challenge.id, "error")
            return "error"
        findings = [result.finding for result in results if result.finding is not None]
        candidate = (
            verified_candidate
            if self._adaptive_control
            else admitted_candidate(findings, challenge.description)
        )
        if candidate is None:
            terminals = {result.terminal_status for result in results}
            status = "unsupported" if terminals == {"unsupported"} else "unsolved"
            if terminals <= {"failed", "timeout"}:
                status = "error"
            self.state.set_challenge_status(challenge.id, status)
            return status

        fingerprint = hashlib.sha256(candidate.encode()).hexdigest()
        if not self.config.submit_candidates:
            return self._withhold_candidate(
                run_id, challenge.id, fingerprint, "submissions_disabled"
            )
        return await self._submit_candidate(run_id, challenge, candidate, deadline)

    async def _solve_dynamic_challenge(
        self,
        run_id: str,
        run_root: Path,
        challenge: Challenge,
        deadline: float,
        *,
        episode: int = 0,
        route: RouteSpec | None = None,
        lane_count: int | None = None,
    ) -> str:
        """Own the complete create/use/delete lifecycle for one dynamic challenge."""
        try:
            endpoints, receipt = await self._start_instance(run_id, challenge, deadline)
        except BaseException as exc:
            owned_record = next(
                (
                    record
                    for record in self.state.owned_instances()
                    if record["run_id"] == run_id and record["challenge_id"] == challenge.id
                ),
                None,
            )
            if owned_record is not None:
                cleanup = asyncio.create_task(
                    self._cleanup_instance_record(
                        owned_record,
                        time.monotonic() + self.config.instance_cleanup_seconds,
                    )
                )
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    with suppress(Exception):
                        await cleanup
            if isinstance(exc, BoardError):
                if self._adaptive_control:
                    self.state.record_control_failure_origin(run_id, challenge.id, episode, "board")
                self.state.set_challenge_status(challenge.id, "error")
                return "error"
            if isinstance(exc, RunDeadlineReached):
                self.state.set_challenge_status(challenge.id, "error")
                return "error"
            raise
        terminal = "error"
        cleanup_ok = False
        try:
            terminal = await self._solve_challenge(
                run_id,
                run_root,
                challenge,
                deadline,
                endpoints,
                episode=episode,
                route=route,
                lane_count=lane_count,
            )
        finally:
            cleanup_deadline = time.monotonic() + self.config.instance_cleanup_seconds
            cleanup = asyncio.create_task(
                self._delete_instance(
                    run_id,
                    challenge.id,
                    cleanup_deadline,
                    expected_receipt=receipt,
                    reason="challenge_complete",
                )
            )
            cancelled: asyncio.CancelledError | None = None
            while not cleanup.done():
                try:
                    cleanup_ok = await asyncio.shield(cleanup)
                except asyncio.CancelledError as exc:
                    cancelled = exc
            if cleanup.done():
                cleanup_ok = cleanup.result()
            if cancelled is not None:
                raise cancelled
        if not cleanup_ok:
            if self._adaptive_control:
                self.state.record_control_failure_origin(run_id, challenge.id, episode, "board")
            self.state.set_challenge_status(challenge.id, "error")
            return "error"
        return terminal

    async def _run_challenge_queue(
        self,
        run_id: str,
        run_root: Path,
        challenges: list[Challenge],
        catalogue_ranks: dict[int, int],
        deadline: float,
        outcomes: dict[int, str],
        *,
        resumed: bool = False,
    ) -> dict[int, str]:
        """Keep five challenge engagements active; auxiliary waves stay inside them."""
        queue: asyncio.PriorityQueue[tuple[int, Challenge | None, float, int, RouteSpec]] = (
            asyncio.PriorityQueue()
        )
        active: set[int] = set()
        peak_active = 0
        admitted_episodes = 0
        dynamic_ids = {challenge.id for challenge in challenges if challenge.type == "dynamic_iac"}
        instance_condition = asyncio.Condition()
        instance_holders: set[int] = set()
        instance_completed: set[int] = set()
        initial_route = baseline_route(
            model=self.config.model,
            effort=self.config.reasoning_effort,
            attempt_seconds=self.config.attempt_seconds,
        )

        def record_queued(challenge: Challenge, episode: int, reason: str) -> float:
            queued_at = time.monotonic()
            self.state.event(
                run_id,
                "challenge_episode_queued",
                {
                    "challenge_id": challenge.id,
                    "episode": episode,
                    "reason": reason,
                },
            )
            return queued_at

        challenges_by_id = {challenge.id: challenge for challenge in challenges}
        if resumed:
            for wave in self.state.queued_control_waves(run_id, exclude_pending_submissions=True):
                challenge = challenges_by_id.get(wave.challenge_id)
                if challenge is None:
                    raise RecoveryBlocked("durable queued challenge is absent from the Board")
                queued_at = record_queued(challenge, wave.episode, "supervisor_restart")
                replay_priority = (
                    wave.catalogue_rank if wave.episode == 0 else 2**30 + wave.catalogue_rank
                )
                queue.put_nowait(
                    (
                        replay_priority,
                        challenge,
                        queued_at,
                        wave.episode,
                        wave.route,
                    )
                )
        else:
            for challenge in challenges:
                queued_at = record_queued(challenge, 0, "initial_coverage")
                queue.put_nowait(
                    (catalogue_ranks[challenge.id], challenge, queued_at, 0, initial_route)
                )
                if challenge.solved:
                    self.state.event(
                        run_id,
                        "prior_board_solved_ignored",
                        {"challenge_id": challenge.id, "run_local_verified": False},
                    )

        async def execute_episode(
            challenge: Challenge,
            episode: int,
            queued_at: float,
            route: RouteSpec,
            target_endpoints: tuple[TargetEndpoint, ...],
        ) -> str:
            nonlocal admitted_episodes
            if time.monotonic() >= deadline:
                raise RunDeadlineReached
            if challenge.id not in active:
                raise RuntimeError("challenge episode escaped its engagement")
            if route.backoff_policy == "bounded_60_seconds":
                if deadline - time.monotonic() <= 60:
                    raise RunDeadlineReached
                self.state.event(
                    run_id,
                    "challenge_episode_backoff",
                    {
                        "challenge_id": challenge.id,
                        "episode": episode,
                        "seconds": 60,
                    },
                )
                await asyncio.sleep(60)
            elif route.backoff_policy != "none":
                raise ValueError("unsupported durable backoff policy")
            admitted_episodes += 1
            lane_count = (
                self.state.control_wave_lane_count(run_id, challenge.id, episode)
                if self._adaptive_control
                else self.config.attempts_per_challenge
            )
            self.state.event(
                run_id,
                "challenge_episode_admitted",
                {
                    "challenge_id": challenge.id,
                    "episode": episode,
                    "queue_wait_seconds": round(time.monotonic() - queued_at, 3),
                    "active_challenges": len(active),
                    "auxiliary": route.role in {"recovery", "verifier"},
                    "execution_phase": (
                        "shared_instance"
                        if target_endpoints
                        else "local_analysis"
                        if challenge.type == "dynamic_iac"
                        else "standard"
                    ),
                },
            )
            try:
                return await self._solve_challenge(
                    run_id,
                    run_root,
                    challenge,
                    deadline,
                    target_endpoints,
                    episode=episode,
                    route=route if self._adaptive_control else None,
                    lane_count=lane_count,
                )
            finally:
                challenge_root = run_root / f"challenge-{challenge.id}"
                await self._drain_rmtree(challenge_root / f"episode-{episode}")
                with suppress(FileNotFoundError, OSError):
                    challenge_root.rmdir()

        async def run_engagement(
            challenge: Challenge,
            initial_queued_at: float,
            initial_episode: int,
            resumed_route: RouteSpec,
        ) -> None:
            nonlocal peak_active
            episode = initial_episode
            route = resumed_route
            queued_at = initial_queued_at
            target_endpoints: tuple[TargetEndpoint, ...] = ()
            receipt: str | None = None
            lease_acquired = False
            create_attempted = False
            outcome: str | None = None
            active.add(challenge.id)
            peak_active = max(peak_active, len(active))
            self.state.event(
                run_id,
                "challenge_engagement_started",
                {"challenge_id": challenge.id, "active_challenges": len(active)},
            )

            async def acquire_instance() -> None:
                nonlocal create_attempted, lease_acquired, receipt, target_endpoints
                self.state.event(
                    run_id,
                    "instance_lease_waiting",
                    {"challenge_id": challenge.id, "episode": episode},
                )
                async with instance_condition:
                    while True:
                        eligible = sorted(
                            active & dynamic_ids - instance_completed - instance_holders,
                            key=catalogue_ranks.__getitem__,
                        )
                        if (
                            len(instance_holders) < self.config.dynamic_concurrency
                            and challenge.id
                            in eligible[: self.config.dynamic_concurrency - len(instance_holders)]
                        ):
                            instance_holders.add(challenge.id)
                            lease_acquired = True
                            break
                        await instance_condition.wait()
                existing = self.state.owned_instances()
                unsafe = any(record["status"] != "owned" for record in existing)
                if unsafe or len(existing) >= self.config.dynamic_concurrency:
                    self.state.event(
                        run_id,
                        "instance_lease_blocked",
                        {
                            "challenge_id": challenge.id,
                            "episode": episode,
                            "reason": "cleanup_indeterminate",
                        },
                    )
                    raise BoardError("instance manager is fenced by indeterminate ownership")
                self.state.event(
                    run_id,
                    "instance_lease_granted",
                    {"challenge_id": challenge.id, "episode": episode},
                )

                def note_create_attempt() -> None:
                    nonlocal create_attempted
                    create_attempted = True

                target_endpoints, receipt = await self._start_instance(
                    run_id,
                    challenge,
                    deadline,
                    on_create_attempt=note_create_attempt,
                )

            async def release_instance() -> bool:
                nonlocal lease_acquired, receipt, target_endpoints
                if not lease_acquired:
                    return True

                cancelled: asyncio.CancelledError | None = None

                async def drain_cleanup(cleanup: asyncio.Task[bool]) -> bool:
                    nonlocal cancelled
                    while not cleanup.done():
                        try:
                            await asyncio.shield(cleanup)
                        except asyncio.CancelledError as exc:
                            cancelled = exc
                    result = cleanup.result()
                    return result

                clean = True
                try:
                    records = [
                        record
                        for record in self.state.owned_instances()
                        if record["run_id"] == run_id and record["challenge_id"] == challenge.id
                    ]
                    if receipt is not None:
                        cleanup = asyncio.create_task(
                            self._delete_instance(
                                run_id,
                                challenge.id,
                                time.monotonic() + self.config.instance_cleanup_seconds,
                                expected_receipt=receipt,
                                reason="engagement_complete",
                            )
                        )
                        clean = await drain_cleanup(cleanup)
                    elif records:
                        cleanup = asyncio.create_task(
                            self._cleanup_instance_record(
                                records[0],
                                time.monotonic() + self.config.instance_cleanup_seconds,
                            )
                        )
                        clean = await drain_cleanup(cleanup)
                    remaining = [
                        record
                        for record in self.state.owned_instances()
                        if record["run_id"] == run_id and record["challenge_id"] == challenge.id
                    ]
                    clean = clean and not remaining
                    self.state.event(
                        run_id,
                        "instance_lease_released" if clean else "instance_lease_poisoned",
                        {
                            "challenge_id": challenge.id,
                            "episode": episode,
                            **({} if clean else {"reason": "cleanup_indeterminate"}),
                        },
                    )
                finally:
                    lease_acquired = False
                    receipt = None
                    target_endpoints = ()
                    async with instance_condition:
                        instance_holders.discard(challenge.id)
                        if create_attempted:
                            instance_completed.add(challenge.id)
                        instance_condition.notify_all()
                if not clean:
                    return False
                if cancelled is not None:
                    raise cancelled
                return True

            try:
                while True:
                    needs_instance = challenge.type == "dynamic_iac" and (
                        not self._adaptive_control
                        or route.tactic == "instance_enabled_follow_on"
                        or lease_acquired
                    )
                    if needs_instance and not lease_acquired:
                        try:
                            await acquire_instance()
                        except BoardError:
                            if self._adaptive_control:
                                self.state.record_control_failure_origin(
                                    run_id, challenge.id, episode, "board"
                                )
                            self.state.set_challenge_status(challenge.id, "error")
                            if not await release_instance():
                                raise BoardError("instance startup cleanup remained indeterminate")
                            terminal = "error"
                        else:
                            terminal = await execute_episode(
                                challenge, episode, queued_at, route, target_endpoints
                            )
                    else:
                        terminal = await execute_episode(
                            challenge, episode, queued_at, route, target_endpoints
                        )

                    recovery_allowance = self.state.recovery_dispatch_count(run_id, challenge.id)
                    has_successor_budget = (
                        episode + 1 < self.config.episodes_per_challenge + recovery_allowance
                        and time.monotonic() < deadline
                    )
                    dynamic_local_follow_on = (
                        self._adaptive_control
                        and challenge.type == "dynamic_iac"
                        and not lease_acquired
                        and not create_attempted
                        and route.tactic != "instance_enabled_follow_on"
                        and terminal in {"candidate", "unsolved", "error"}
                        and has_successor_budget
                    )
                    should_retry = (
                        terminal in {"unsolved", "error", "candidate"}
                        and has_successor_budget
                        and not (
                            challenge.type == "dynamic_iac"
                            and create_attempted
                            and not lease_acquired
                        )
                    )
                    if dynamic_local_follow_on:
                        successor = instance_follow_on_route(route)
                        assignments = tuple(
                            ("recovery", model, effort)
                            for _, model, effort in self._initial_peer_assignments()
                        )
                        self.state.finish_and_admit_control_wave(
                            run_id=run_id,
                            challenge_id=challenge.id,
                            source_episode=episode,
                            next_episode=episode + 1,
                            catalogue_rank=catalogue_ranks[challenge.id],
                            terminal=terminal,
                            route=successor,
                            assignments=assignments,
                            reason="local_analysis_complete",
                        )
                        episode += 1
                        route = successor
                        queued_at = record_queued(challenge, episode, "local_analysis_complete")
                        continue
                    if self._adaptive_control:
                        decision = self.state.finish_and_decide_control_wave(
                            run_id=run_id,
                            challenge_id=challenge.id,
                            source_episode=episode,
                            next_episode=episode + 1,
                            catalogue_rank=catalogue_ranks[challenge.id],
                            lanes=self.config.attempts_per_challenge,
                            terminal=terminal,
                            attempts_remaining=should_retry,
                            remaining_milliseconds=max(
                                0, int((deadline - time.monotonic()) * 1000)
                            ),
                        )
                        if decision is not None and decision.disposition == "dispatch":
                            assert decision.successor is not None
                            episode += 1
                            route = decision.successor
                            queued_at = record_queued(challenge, episode, decision.failure.kind)
                            continue
                    else:
                        self.state.finish_control_wave(run_id, challenge.id, episode, terminal)
                        if should_retry:
                            episode += 1
                            self.state.admit_control_wave(
                                run_id,
                                challenge.id,
                                episode,
                                catalogue_ranks[challenge.id],
                                self.config.attempts_per_challenge,
                                route,
                            )
                            queued_at = record_queued(challenge, episode, terminal)
                            continue
                    outcome = terminal
                    break
            finally:
                clean = True
                try:
                    clean = await release_instance()
                finally:
                    active.remove(challenge.id)
                    async with instance_condition:
                        instance_condition.notify_all()
                if not clean:
                    raise BoardError("instance cleanup did not prove absence")
            assert outcome is not None
            outcomes[challenge.id] = outcome
            self.state.event(
                run_id,
                "challenge_engagement_closed",
                {
                    "challenge_id": challenge.id,
                    "terminal": outcome,
                    "active_challenges": len(active),
                },
            )

        async def worker() -> None:
            while True:
                item = await queue.get()
                try:
                    _, challenge, queued_at, episode, route = item
                    if challenge is None:
                        return
                    await run_engagement(challenge, queued_at, episode, route)
                finally:
                    queue.task_done()

        workers = [
            asyncio.create_task(worker())
            for _ in range(min(self.config.active_challenges, max(1, len(challenges))))
        ]
        join = asyncio.create_task(queue.join())
        timer = asyncio.create_task(asyncio.sleep(max(0.0, deadline - time.monotonic())))
        try:
            watched: set[asyncio.Task[Any]] = {join, timer, *workers}
            done, _ = await asyncio.wait(watched, return_when=asyncio.FIRST_COMPLETED)
            if join in done:
                await join
            elif timer in done:
                raise RunDeadlineReached
            else:
                failed_worker = next(task for task in done if task in workers)
                await failed_worker
                raise RuntimeError("challenge queue worker exited before drain")
            for _ in workers:
                queue.put_nowait((2**31, None, 0.0, 0, initial_route))
            await asyncio.gather(*workers)
        finally:
            for task in (join, timer, *workers):
                if not task.done():
                    task.cancel()
            shutdown = await asyncio.gather(join, timer, *workers, return_exceptions=True)
            if self.state.owned_instances():
                raise BoardError("instance cleanup remained indeterminate during queue shutdown")
            failure = next(
                (
                    result
                    for result in shutdown
                    if isinstance(result, BaseException)
                    and not isinstance(result, (asyncio.CancelledError, RunDeadlineReached))
                ),
                None,
            )
            if failure is not None:
                raise failure
        self.state.event(
            run_id,
            "challenge_queue_summary",
            {
                "admitted_episodes": admitted_episodes,
                "completed_challenges": len(outcomes),
                "peak_active_challenges": peak_active,
            },
        )
        return outcomes

    async def run(self) -> RunReport:
        self._ensure_private_work_root()
        self.state.acquire_supervisor(
            self.config.codex_home / ".rapido-supervisor.lock",
            self.config.work_root / ".rapido-work.lock",
        )
        try:
            session = self.state.start_or_resume_run(uuid.uuid4().hex, self.config.public_record())
            seal_unavailable_attempt_evidence(self.state)
        except BaseException:
            self.state.release_supervisor()
            raise
        run_id = session.run_id
        try:
            started_at = datetime.fromisoformat(session.started_at)
            if started_at.tzinfo is None:
                raise ValueError("running run has a timezone-free start time")
            elapsed = (datetime.now(UTC) - started_at.astimezone(UTC)).total_seconds()
            if elapsed < -1:
                raise ValueError("wall clock precedes the durable run start")
        except (TypeError, ValueError) as exc:
            self.state.release_supervisor()
            raise RuntimeError("running run has an invalid durable deadline") from exc
        remaining_run_seconds = max(0.0, float(self.config.run_seconds) - max(0.0, elapsed))
        deadline = time.monotonic() + remaining_run_seconds
        run_root = self.config.work_root / f"run-{run_id}"
        outcomes: dict[int, str] = {}
        challenge_count = 0
        status = "failed"
        try:
            if session.resumed:
                identity_deadline = time.monotonic() + max(
                    float(self.config.instance_cleanup_seconds),
                    float(self.config.board_timeout_seconds * 3 + 1),
                )
                try:
                    identity = await self._qualified_identity(identity_deadline)
                    await self._cleanup_owned_instances(
                        time.monotonic() + float(self.config.instance_cleanup_seconds)
                    )
                except BoardError as exc:
                    raise RecoveryBlocked(
                        "Board recovery reconciliation remained indeterminate"
                    ) from exc

                if deadline - time.monotonic() > 0:
                    self.state.resume_control_waves(
                        run_id,
                        max(0, int((deadline - time.monotonic()) * 1000)),
                    )
                durable_catalogue = self.state.control_catalogue_entries(run_id)
                outcomes.update(self.state.run_terminal_outcomes(run_id))
                challenge_count = len(durable_catalogue)
                pending_effects = self.state.pending_submission_intents()
                if durable_catalogue and not pending_effects and len(outcomes) == challenge_count:
                    status = "completed"
                    self.state.finish_run(run_id, status)
                    return self._run_report(run_id, status, challenge_count, outcomes)
                if pending_effects and deadline - time.monotonic() <= 0:
                    raise RecoveryBlocked(
                        "pending submission effect requires explicit reconciliation"
                    )
            else:
                identity = await self._qualified_identity(deadline)
                await self._cleanup_owned_instances(deadline)
            self._ensure_private_work_root()
            if session.resumed and run_root.exists():
                await self._remove_tree_before(
                    run_root,
                    time.monotonic() + float(self.config.instance_cleanup_seconds),
                )
            run_root.mkdir(mode=0o700, exist_ok=False)
            self._run_evidence = RunEvidence.open(self.state, run_id)
            await self._cleanup_stale_workspaces(
                (
                    time.monotonic() + float(self.config.instance_cleanup_seconds)
                    if session.resumed
                    else deadline
                ),
                run_root,
            )
            if session.resumed:
                self.state.resume_control_waves(
                    run_id,
                    max(0, int((deadline - time.monotonic()) * 1000)),
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RunDeadlineReached
            if not self._adaptive_control:
                try:
                    await asyncio.wait_for(self.runtime.start(), timeout=remaining)
                except TimeoutError as exc:
                    raise RunDeadlineReached from exc
                await self._validate_peer_models(run_id, deadline)
            challenges = await self._challenge_catalogue(deadline, identity)
            challenge_count = len(challenges)
            durable_catalogue = (
                self.state.control_catalogue_entries(run_id) if session.resumed else []
            )
            durable_signature = (
                self.state.control_catalogue_signature(run_id) if durable_catalogue else {}
            )
            durable_contexts = (
                self.state.control_catalogue_contexts(run_id) if durable_catalogue else {}
            )
            eligible: list[Challenge] = []
            catalogue_entries: list[tuple[int, int, bool]] = []
            current_signature: dict[int, tuple[str, str, str, int, bool]] = {}
            current_contexts: dict[int, str] = {}
            for catalogue_rank, challenge in enumerate(challenges):
                executable = not (
                    challenge.type != "standard"
                    and (
                        challenge.type != "dynamic_iac" or not self.config.manage_dynamic_instances
                    )
                )
                catalogue_entries.append((catalogue_rank, challenge.id, executable))
                current_signature[challenge.id] = (
                    challenge.name,
                    challenge.category,
                    challenge.type,
                    challenge.value,
                    executable,
                )
                current_contexts[challenge.id] = _challenge_material_sha256(challenge)
                if executable:
                    eligible.append(challenge)
            if durable_signature and durable_signature != current_signature:
                raise RecoveryBlocked("Board catalogue identity changed during same-run recovery")
            if durable_contexts and durable_contexts != current_contexts:
                raise RecoveryBlocked("Board challenge material changed during same-run recovery")
            for challenge, (_, _, executable) in zip(challenges, catalogue_entries, strict=True):
                self.state.upsert_challenge(
                    challenge.id,
                    challenge.name,
                    challenge.category,
                    challenge.type,
                    challenge.value,
                )
                if not executable:
                    self.state.set_challenge_status(challenge.id, "unsupported")
                    self.state.event(
                        run_id,
                        "challenge_unsupported",
                        {
                            "challenge_id": challenge.id,
                            "reason": (
                                "dynamic_management_disabled"
                                if challenge.type == "dynamic_iac"
                                else "organizer_challenge_type_unavailable"
                            ),
                        },
                    )
                    outcomes[challenge.id] = "unsupported"
            if not durable_catalogue:
                initial_route = baseline_route(
                    model=self.config.model,
                    effort=self.config.reasoning_effort,
                    attempt_seconds=self.config.attempt_seconds,
                )
                self.state.initialize_control_catalogue(
                    run_id,
                    catalogue_entries,
                    self.config.attempts_per_challenge,
                    initial_route,
                    self._initial_peer_assignments(),
                    current_contexts,
                )
            catalogue_ranks = {
                challenge_id: catalogue_rank
                for catalogue_rank, challenge_id, _ in (durable_catalogue or catalogue_entries)
            }
            outcomes.update(self.state.run_terminal_outcomes(run_id))
            queued_waves = self.state.queued_control_waves(
                run_id,
                exclude_pending_submissions=session.resumed and self._adaptive_control,
            )
            if (
                session.resumed
                and not queued_waves
                and len(outcomes) != challenge_count
                and not self.state.pending_submission_intents()
            ):
                raise RecoveryBlocked("durable run has neither queued nor terminal challenge work")
            if eligible and queued_waves:
                if self._adaptive_control:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RunDeadlineReached
                    try:
                        await asyncio.wait_for(self.runtime.start(), timeout=remaining)
                    except TimeoutError as exc:
                        raise RunDeadlineReached from exc
                    await self._validate_peer_models(run_id, deadline)
                await self._run_challenge_queue(
                    run_id,
                    run_root,
                    eligible,
                    catalogue_ranks,
                    deadline,
                    outcomes,
                    resumed=session.resumed and bool(durable_catalogue),
                )
            outcomes.update(self.state.run_terminal_outcomes(run_id))
            if self._adaptive_control and self.state.pending_submission_intents():
                raise RecoveryBlocked("pending submission effect requires explicit reconciliation")
            status = "completed"
            self.state.finish_run(run_id, status)
        except RecoveryBlocked as exc:
            self.state.event(
                run_id,
                "recovery_blocked",
                {"reason": str(exc)},
            )
            raise
        except RunDeadlineReached:
            if self._adaptive_control and self.state.pending_submission_intents():
                reason = "pending submission effect requires explicit reconciliation"
                self.state.event(run_id, "recovery_blocked", {"reason": reason})
                raise RecoveryBlocked(reason)
            status = "deadline"
            self.state.interrupt_control_run(run_id, "run_deadline")
            seal_unavailable_attempt_evidence(self.state)
            self.state.finish_run(run_id, status)
        except (asyncio.CancelledError, KeyboardInterrupt):
            try:
                self.state.interrupt_control_run(run_id, "supervisor_interrupted")
                seal_unavailable_attempt_evidence(self.state)
                self.state.finish_run(run_id, "interrupted")
            except ValueError:
                pass
            raise
        except BaseException:
            try:
                self.state.interrupt_control_run(run_id, "run_failed")
                seal_unavailable_attempt_evidence(self.state)
                self.state.finish_run(run_id, "failed")
            except ValueError:
                pass
            raise
        finally:
            try:
                await self._drain_runtime_close()
            finally:
                self._run_evidence = None
                self.state.release_supervisor()
        return self._run_report(run_id, status, challenge_count, outcomes)


__all__ = [
    "LaneResult",
    "NativeRuntime",
    "NativeTurn",
    "Orchestrator",
    "RunDeadlineReached",
    "RunReport",
]
