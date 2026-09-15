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
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .board import BoardClient, BoardError, Challenge, Verdict
from .config import RuntimeConfig
from .solver import (
    DEVELOPER_INSTRUCTIONS,
    SOLVER_OUTPUT_SCHEMA,
    CandidateProvenanceError,
    SolverFinding,
    SolverOutputError,
    admitted_candidate,
    build_turn_prompt,
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
    ) -> NativeTurn: ...

    async def close(self) -> None: ...


class RunDeadlineReached(TimeoutError):
    """The whole-run work deadline elapsed."""


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
    lane: int
    started: float
    finished: float
    finding: SolverFinding | None
    terminal_status: str
    tool_calls: tuple[ToolCallEvidence, ...]


@dataclass(frozen=True)
class ToolCallEvidence:
    name: str
    success: bool | None
    source_bound: bool
    candidate_sha256s: tuple[str, ...]
    supplied_candidate_sha256s: tuple[str, ...]


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
_DURABLE_TOOL_NAMES = frozenset(
    {
        "audio_metadata",
        "decode_base64",
        "decode_hex",
        "decode_url",
        "decompress_gzip",
        "dicom_metadata",
        "disassemble_elf",
        "elf_symbols",
        "extract_archive",
        "extract_strings",
        "http_request",
        "image_metadata",
        "inspect_binary",
        "inspect_elf",
        "inspect_file",
        "inspect_filesystem",
        "list_tar",
        "list_workspace",
        "list_zip",
        "read_bytes",
        "read_text",
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


def _challenge_coherence_key(challenge: Challenge) -> tuple[object, ...]:
    """Stable fields; timeout and attachment signatures are live Board values."""
    stable_files = tuple(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
        )
        for parsed in (urllib.parse.urlsplit(file_ref) for file_ref in challenge.files)
    )
    return (
        challenge.id,
        challenge.name,
        challenge.category,
        challenge.type,
        challenge.description,
        challenge.value,
        stable_files,
        challenge.solved,
        challenge.max_attempts,
        challenge.attempts,
        challenge.shared,
    )


class Orchestrator:
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

    async def _cleanup_owned_instances(self, deadline: float) -> None:
        for record in self.state.owned_instances():
            await self._cleanup_instance_record(record, deadline)

    async def _cleanup_instance_record(self, record: dict[str, Any], deadline: float) -> bool:
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
            current = await self._board_call(deadline, self.board.instance, "GET", challenge_id)
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
            current = await self._board_call(deadline, self.board.instance, "GET", challenge_id)
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
            self.state.mark_instance(run_id, challenge_id, "removed")
            self.state.event(
                run_id,
                "instance_cleanup",
                {"challenge_id": challenge_id, "status": "skipped_replaced", "reason": reason},
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
                current = await self._board_call(deadline, self.board.instance, "GET", challenge_id)
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

    async def _start_instance(
        self, run_id: str, challenge: Challenge, deadline: float
    ) -> tuple[tuple[TargetEndpoint, ...], str]:
        """Persist intent, create once, poll boundedly, and parse Board-issued endpoints."""
        existing = await self._board_call(deadline, self.board.instance, "GET", challenge.id)
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
                self.state.mark_instance(run_id, challenge.id, "cleanup_pending")
            raise cancelled
        ready_deadline = min(deadline, time.monotonic() + 120.0)
        while ready_deadline - time.monotonic() > float(getattr(self.board, "timeout", 15.0)):
            current = await self._board_call(deadline, self.board.instance, "GET", challenge.id)
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
        anonymous_rejected = await self._board_call(
            deadline, self.board.anonymous_identity_is_rejected
        )
        if anonymous_rejected is not True:
            raise BoardError("anonymous Board identity negative control failed")
        identity = await self._board_call(deadline, self.board.identity)
        confirmation = await self._board_call(deadline, self.board.identity)
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
            await self._board_call(deadline, self.board.list_challenges),
            await self._board_call(deadline, self.board.list_challenges),
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
            detail = await self._board_call(deadline, self.board.challenge, challenge_id)
            confirmation = await self._board_call(deadline, self.board.challenge, challenge_id)
            if _challenge_coherence_key(detail) != _challenge_coherence_key(confirmation):
                raise BoardError("consecutive challenge details were incoherent")
            details.append(detail)
        final_rows = await self._board_call(deadline, self.board.list_challenges)
        final_ids = [row.get("id") for row in final_rows]
        if (
            any(type(value) is not int or value <= 0 for value in final_ids)
            or len(final_ids) != len(set(final_ids))
            or sorted(final_ids) != sorted(ids)
        ):
            raise BoardError("challenge list changed during qualification")
        final_identity = await self._board_call(deadline, self.board.identity)
        if final_identity.get("id") != identity[0] or final_identity.get("team_id") != identity[1]:
            raise BoardError("Board identity changed during qualification")
        details.sort(
            key=lambda challenge: (
                challenge.type != "dynamic_iac",
                _category_rank(challenge.category),
                challenge.value,
                challenge.id,
            )
        )
        if self.config.challenge_ids:
            available = {challenge.id for challenge in details}
            missing = sorted(set(self.config.challenge_ids) - available)
            if missing:
                raise BoardError("configured challenge ids are absent from the qualified catalogue")
            selected = set(self.config.challenge_ids)
            details = [challenge for challenge in details if challenge.id in selected]
        return details

    async def _prepare_workspaces(
        self, run_root: Path, challenge: Challenge, deadline: float
    ) -> list[tuple[Path, list[str]]]:
        challenge_root = run_root / f"challenge-{challenge.id}"
        source_root = challenge_root / "source"
        source_root.mkdir(parents=True, exist_ok=False)
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

        if total_bytes * (self.config.attempts_per_challenge + 1) > self.config.max_workspace_bytes:
            raise BoardError("challenge artifact copies exceed the workspace byte limit")

        workspaces: list[tuple[Path, list[str]]] = []
        for lane in range(self.config.attempts_per_challenge):
            workspace = challenge_root / f"lane-{lane}"
            artifact_root = workspace / "artifacts"
            artifact_root.mkdir(parents=True, exist_ok=False)
            relative_paths: list[str] = []
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

    async def _lane(
        self,
        run_id: str,
        challenge: Challenge,
        lane: int,
        workspace: Path,
        artifact_paths: list[str],
        timeout_seconds: float,
        target_endpoints: tuple[TargetEndpoint, ...] = (),
    ) -> LaneResult:
        attempt_id = f"{run_id}:{challenge.id}:{lane}"
        self.state.start_attempt(
            attempt_id,
            run_id,
            challenge.id,
            lane,
            self.config.model,
            self.config.reasoning_effort,
        )
        started = time.monotonic()
        tool_calls: tuple[ToolCallEvidence, ...] = ()
        target_registry = (
            TargetToolRegistry(
                workspace,
                target_endpoints,
                team_key=self.config.team_key,
                max_workspace_bytes=self.config.max_lane_workspace_bytes,
            )
            if target_endpoints
            else None
        )
        try:
            turn = await asyncio.wait_for(
                self.runtime.solve(
                    workspace,
                    build_turn_prompt(challenge, artifact_paths, lane),
                    developer_instructions=DEVELOPER_INSTRUCTIONS,
                    model=self.config.model,
                    reasoning_effort=self.config.reasoning_effort,
                    output_schema=SOLVER_OUTPUT_SCHEMA,
                    timeout=timeout_seconds,
                    tool_registry=target_registry,
                ),
                timeout=timeout_seconds + 5,
            )
            call_evidence: list[ToolCallEvidence] = []
            for call in turn.tool_calls[:100]:
                if not isinstance(call, dict) or not isinstance(
                    call.get("success"), (bool, type(None))
                ):
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
                call_evidence.append(
                    ToolCallEvidence(
                        name=_durable_tool_name(call.get("name")),
                        success=call.get("success"),
                        source_bound=call.get("source_bound") is True,
                        candidate_sha256s=hashes,
                        supplied_candidate_sha256s=supplied_hashes,
                    )
                )
            tool_calls = tuple(call_evidence)
            if turn.status != "completed":
                raise NativeTurnIncompleteError(
                    turn.status,
                    getattr(turn, "failure_class", None),
                )
            finding = SolverFinding.from_message(turn.text)
            if finding.candidate is not None:
                candidate_fingerprint = hashlib.sha256(finding.candidate.encode()).hexdigest()
                candidate_observed = False
                candidate_supplied = False
                for call in call_evidence:
                    candidate_supplied |= candidate_fingerprint in call.supplied_candidate_sha256s
                    if call.success is True and call.source_bound:
                        candidate_observed |= candidate_fingerprint in call.candidate_sha256s
                if not candidate_observed:
                    raise CandidateProvenanceError(
                        "candidate was not observed in a successful source-bound tool result"
                    )
                if candidate_supplied:
                    raise CandidateProvenanceError(
                        "candidate originated in model-supplied tool input"
                    )
            terminal = "candidate" if finding.status == "candidate" else finding.status
            self.state.finish_attempt(
                attempt_id,
                terminal,
                summary=finding.summary,
                candidate=finding.candidate,
                confidence=finding.confidence,
            )
        except TimeoutError:
            finding = None
            terminal = "timeout"
            self.state.finish_attempt(attempt_id, terminal, summary="native turn exceeded deadline")
        except asyncio.CancelledError:
            self.state.finish_attempt(attempt_id, "cancelled", summary="run shutdown")
            raise
        except CandidateProvenanceError:
            finding = None
            terminal = "unsolved"
            self.state.finish_attempt(
                attempt_id,
                terminal,
                summary="flag-shaped hypothesis rejected by provenance policy",
            )
            self.state.event(
                run_id,
                "attempt_failure",
                {"challenge_id": challenge.id, "lane": lane, "reason": "candidate_provenance"},
            )
        except SolverOutputError:
            finding = None
            terminal = "failed"
            self.state.finish_attempt(attempt_id, terminal, summary="native turn failed safely")
            self.state.event(
                run_id,
                "attempt_failure",
                {"challenge_id": challenge.id, "lane": lane, "reason": "solver_output"},
            )
        except NativeTurnIncompleteError as exc:
            finding = None
            terminal = "failed"
            self.state.finish_attempt(attempt_id, terminal, summary="native turn failed safely")
            self.state.event(
                run_id,
                "attempt_failure",
                {
                    "challenge_id": challenge.id,
                    "lane": lane,
                    "reason": "native_turn_incomplete",
                    "status": exc.status,
                    "failure_class": exc.failure_class,
                },
            )
        except RuntimeError:
            finding = None
            terminal = "failed"
            self.state.finish_attempt(attempt_id, terminal, summary="native turn failed safely")
            self.state.event(
                run_id,
                "attempt_failure",
                {"challenge_id": challenge.id, "lane": lane, "reason": "native_runtime"},
            )
        except OSError:
            finding = None
            terminal = "failed"
            self.state.finish_attempt(attempt_id, terminal, summary="native turn failed safely")
            self.state.event(
                run_id,
                "attempt_failure",
                {"challenge_id": challenge.id, "lane": lane, "reason": "operating_system"},
            )
        except ValueError:
            finding = None
            terminal = "failed"
            self.state.finish_attempt(attempt_id, terminal, summary="native turn failed safely")
            self.state.event(
                run_id,
                "attempt_failure",
                {"challenge_id": challenge.id, "lane": lane, "reason": "invalid_value"},
            )
        finally:
            if target_registry is not None:
                target_registry.close()
        return LaneResult(lane, started, time.monotonic(), finding, terminal, tool_calls)

    async def _solve_challenge(
        self,
        run_id: str,
        run_root: Path,
        challenge: Challenge,
        deadline: float,
        target_endpoints: tuple[TargetEndpoint, ...] = (),
    ) -> str:
        self.state.set_challenge_status(challenge.id, "running")
        try:
            workspaces = await self._prepare_workspaces(run_root, challenge, deadline)
        except RunDeadlineReached:
            self.state.set_challenge_status(challenge.id, "unsolved")
            raise
        except (BoardError, OSError):
            self.state.set_challenge_status(challenge.id, "error")
            return "error"
        remaining = max(0.0, deadline - time.monotonic())
        timeout = min(float(self.config.attempt_seconds), remaining)
        if timeout <= 0:
            self.state.set_challenge_status(challenge.id, "unsolved")
            return "unsolved"

        async def scheduled_lane(lane: int, workspace: Path, artifacts: list[str]) -> LaneResult:
            async with self._slots:
                return await self._lane(
                    run_id,
                    challenge,
                    lane,
                    workspace,
                    artifacts,
                    timeout,
                    target_endpoints,
                )

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
                current_findings = [
                    result.finding for result in results if result.finding is not None
                ]
                if admitted_candidate(current_findings, challenge.description) is not None:
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
                "lanes": len(results),
                "max_parallel": parallel,
                "overlap": parallel >= 2,
                "winner_cancelled_pending": winner_found,
                "durations_seconds": [round(item.finished - item.started, 3) for item in results],
                "tool_calls": [
                    {
                        "lane": item.lane,
                        "calls": [
                            {
                                "name": call.name,
                                "success": call.success,
                                "source_bound": call.source_bound,
                                "candidate_sha256s": list(
                                    call.candidate_sha256s[:_MAX_DURABLE_TOOL_HASHES]
                                ),
                                "supplied_candidate_sha256s": list(
                                    call.supplied_candidate_sha256s[:_MAX_DURABLE_TOOL_HASHES]
                                ),
                            }
                            for call in item.tool_calls[:_MAX_DURABLE_TOOL_CALLS]
                        ],
                    }
                    for item in results
                ],
            },
        )
        if parallel < 2:
            self.state.set_challenge_status(challenge.id, "error")
            return "error"
        findings = [result.finding for result in results if result.finding is not None]
        candidate = admitted_candidate(findings, challenge.description)
        if candidate is None:
            terminals = {result.terminal_status for result in results}
            status = "unsupported" if terminals == {"unsupported"} else "unsolved"
            if terminals <= {"failed", "timeout"}:
                status = "error"
            self.state.set_challenge_status(challenge.id, status)
            return status

        fingerprint = hashlib.sha256(candidate.encode()).hexdigest()
        if not self.config.submit_candidates:
            self.state.event(
                run_id,
                "candidate_withheld",
                {
                    "challenge_id": challenge.id,
                    "candidate_sha256": fingerprint,
                    "reason": "submissions_disabled",
                },
            )
            self.state.set_challenge_status(challenge.id, "candidate")
            return "candidate"
        if self.state.submission_risk_count() >= self.config.wrong_submission_ceiling:
            self.state.event(
                run_id,
                "candidate_withheld",
                {
                    "challenge_id": challenge.id,
                    "candidate_sha256": fingerprint,
                    "reason": "submission_risk_ceiling",
                },
            )
            self.state.set_challenge_status(challenge.id, "candidate")
            return "candidate"
        if challenge.max_attempts not in (None, 0) and challenge.attempts >= challenge.max_attempts:
            self.state.event(
                run_id,
                "candidate_withheld",
                {
                    "challenge_id": challenge.id,
                    "candidate_sha256": fingerprint,
                    "reason": "board_limit",
                },
            )
            self.state.set_challenge_status(challenge.id, "candidate")
            return "candidate"

        remaining = deadline - time.monotonic()
        transport_timeout = float(getattr(self.board, "timeout", 15.0))
        if remaining <= transport_timeout:
            self.state.event(
                run_id,
                "candidate_withheld",
                {
                    "challenge_id": challenge.id,
                    "candidate_sha256": fingerprint,
                    "reason": "run_deadline",
                },
            )
            self.state.set_challenge_status(challenge.id, "candidate")
            return "candidate"
        if not self.state.reserve_submission(run_id, challenge.id, candidate):
            self.state.event(
                run_id,
                "candidate_withheld",
                {
                    "challenge_id": challenge.id,
                    "candidate_sha256": fingerprint,
                    "reason": "submission_already_reserved",
                },
            )
            self.state.set_challenge_status(challenge.id, "candidate")
            return "candidate"
        try:
            verdict: Verdict = await self._board_call(
                deadline, self.board.submit, challenge.id, candidate
            )
        except (BoardError, RunDeadlineReached):
            self.state.event(
                run_id,
                "candidate_withheld",
                {
                    "challenge_id": challenge.id,
                    "candidate_sha256": fingerprint,
                    "reason": "submission_pending_reconciliation",
                },
            )
            self.state.set_challenge_status(challenge.id, "candidate")
            return "candidate"
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
            },
        )
        status = "solved" if verdict.outcome in {"correct", "already_solved"} else "unsolved"
        if verdict.outcome in {"paused", "ratelimited", "unread"}:
            status = "candidate"
        self.state.set_challenge_status(challenge.id, status)
        return status

    async def _solve_dynamic_challenge(
        self, run_id: str, run_root: Path, challenge: Challenge, deadline: float
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
                    self._cleanup_instance_record(owned_record, time.monotonic() + 45.0)
                )
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    with suppress(Exception):
                        await cleanup
            if isinstance(exc, (BoardError, RunDeadlineReached)):
                self.state.set_challenge_status(challenge.id, "error")
                return "error"
            raise
        terminal = "error"
        cleanup_ok = False
        try:
            terminal = await self._solve_challenge(run_id, run_root, challenge, deadline, endpoints)
        finally:
            cleanup_deadline = time.monotonic() + 45.0
            cleanup_ok = await self._delete_instance(
                run_id,
                challenge.id,
                cleanup_deadline,
                expected_receipt=receipt,
                reason="challenge_complete",
            )
        if not cleanup_ok:
            self.state.set_challenge_status(challenge.id, "error")
            return "error"
        return terminal

    async def run(self) -> RunReport:
        deadline = time.monotonic() + self.config.run_seconds
        self._ensure_private_work_root()
        self.state.acquire_supervisor(
            self.config.codex_home / ".rapido-supervisor.lock",
            self.config.work_root / ".rapido-work.lock",
        )
        try:
            self.state.recover_interrupted()
        except BaseException:
            self.state.release_supervisor()
            raise
        run_id = uuid.uuid4().hex
        run_root = self.config.work_root / f"run-{run_id}"
        try:
            self._ensure_private_work_root()
            run_root.mkdir(mode=0o700, exist_ok=False)
            self.state.start_run(run_id, self.config.public_record())
        except BaseException:
            self.state.release_supervisor()
            raise
        counts = {name: 0 for name in ("solved", "candidate", "unsolved", "unsupported", "error")}
        challenge_count = 0
        status = "failed"
        try:
            await self._cleanup_stale_workspaces(deadline, run_root)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RunDeadlineReached
            identity = await self._qualified_identity(deadline)
            await self._cleanup_owned_instances(deadline)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RunDeadlineReached
            try:
                await asyncio.wait_for(self.runtime.start(), timeout=remaining)
            except TimeoutError as exc:
                raise RunDeadlineReached from exc
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RunDeadlineReached
            challenges = await self._challenge_catalogue(deadline, identity)
            challenge_count = len(challenges)
            for challenge in challenges:
                self.state.upsert_challenge(
                    challenge.id,
                    challenge.name,
                    challenge.category,
                    challenge.type,
                    challenge.value,
                )
                if challenge.solved:
                    self.state.set_challenge_status(challenge.id, "solved")
                    counts["solved"] += 1
                    continue
                if time.monotonic() >= deadline:
                    status = "deadline"
                    break
                if challenge.type != "standard" and (
                    challenge.type != "dynamic_iac" or not self.config.manage_dynamic_instances
                ):
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
                    counts["unsupported"] += 1
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RunDeadlineReached
                try:
                    try:
                        operation = (
                            self._solve_dynamic_challenge(run_id, run_root, challenge, deadline)
                            if challenge.type == "dynamic_iac"
                            else self._solve_challenge(run_id, run_root, challenge, deadline)
                        )
                        terminal = await asyncio.wait_for(
                            operation,
                            timeout=remaining,
                        )
                    except TimeoutError as exc:
                        raise RunDeadlineReached from exc
                finally:
                    await self._drain_rmtree(run_root / f"challenge-{challenge.id}")
                if terminal in counts:
                    counts[terminal] += 1
            else:
                status = "completed"
            self.state.finish_run(run_id, status)
        except RunDeadlineReached:
            status = "deadline"
            self.state.finish_run(run_id, status)
        except (asyncio.CancelledError, KeyboardInterrupt):
            try:
                self.state.finish_run(run_id, "interrupted")
            except ValueError:
                pass
            raise
        except BaseException:
            try:
                self.state.finish_run(run_id, "failed")
            except ValueError:
                pass
            raise
        finally:
            try:
                await self.runtime.close()
            finally:
                self.state.release_supervisor()
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


__all__ = [
    "LaneResult",
    "NativeRuntime",
    "NativeTurn",
    "Orchestrator",
    "RunDeadlineReached",
    "RunReport",
]
