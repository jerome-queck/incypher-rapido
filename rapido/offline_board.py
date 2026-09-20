"""Secret-free folder-backed Board adapter for registered offline experiments.

This module deliberately has no production authority, transport, credential, or target parsing.
Private checkers and service controllers are supplied directly by the offline runner.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
import stat
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from .board import FLAG_RE, MAX_CHALLENGE_DESCRIPTION_BYTES, BoardError, Challenge, Verdict
from .target import parse_connection_info

OFFLINE_BOARD_IMPLEMENTATION_VERSION = "offline-board-v1"
_CATALOGUE_LIMIT = 4 * 1024 * 1024
_MAX_TASKS = 1000
_MAX_FILES = 100
_MAX_TEXT_BYTES = 4096
_MAX_CONNECTION_BYTES = 32 * 1024
_COPY_CHUNK = 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

Checker = Callable[[str, bytes], bool]


class OfflineCheckerPort(Protocol):
    """Process-isolated deterministic checker boundary."""

    process_isolated: bool
    private_roots: tuple[Path, ...]

    def check(self, task_id: str, candidate: bytes, *, deadline_ns: int) -> bool: ...

    def abort_and_reap(self, *, deadline_ns: int) -> Any: ...


class OfflineServiceController(Protocol):
    """Private process owner for one registered dynamic service."""

    process_isolated: bool
    private_roots: tuple[Path, ...]

    def start(
        self, task_id: str, resource_profile_id: str, *, deadline_ns: int
    ) -> Mapping[str, Any]: ...

    def renew(self, task_id: str, *, deadline_ns: int) -> Mapping[str, Any]: ...

    def stop(self, task_id: str, *, deadline_ns: int) -> Any: ...

    def inventory(self, *, deadline_ns: int) -> int: ...

    def preflight(self, task_id: str, resource_profile_id: str, *, deadline_ns: int) -> bool: ...

    def abort_and_reap(self, *, deadline_ns: int) -> Any: ...


@dataclass(frozen=True)
class _Task:
    challenge: Challenge
    task_id: str
    service_required: bool
    resource_profile_id: str
    generator_version: str
    checker_version: str
    service_version: str


@dataclass(frozen=True)
class _SourceIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    digest: bytes


@dataclass
class _CandidateResult:
    ordinal: int
    checker_version: str
    checker_invoked: bool
    checked_monotonic_ns: int
    outcome: str
    message: str
    http_status: int
    repeat_count: int = 0


@dataclass(frozen=True)
class _Lease:
    challenge_id: int
    task_id: str
    connection_info: str
    since: str | int | float | None
    until: str | int | float | None


def _bounded_text(value: Any, label: str, *, limit: int = _MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str):
        raise BoardError(f"offline catalogue {label} is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise BoardError(f"offline catalogue {label} is invalid") from None
    if not value or len(encoded) > limit or any(ord(character) < 32 for character in value):
        raise BoardError(f"offline catalogue {label} is invalid")
    return value


def _component(value: Any, label: str) -> str:
    text = _bounded_text(value, label, limit=128)
    if text in {".", ".."} or any(character in text for character in "/\\:"):
        raise BoardError(f"offline catalogue {label} is invalid")
    if not all(
        character.isascii() and (character.isalnum() or character in "._-") for character in text
    ):
        raise BoardError(f"offline catalogue {label} is invalid")
    return text


def _file_parts(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise BoardError("offline challenge file reference is invalid")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise BoardError("offline challenge file reference is invalid") from None
    if (
        value.startswith(("/", "\\"))
        or "\\" in value
        or ":" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BoardError("offline challenge file reference is invalid")
    parts = tuple(value.split("/"))
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise BoardError("offline challenge file reference is invalid")
    if PurePosixPath(*parts).as_posix() != value:
        raise BoardError("offline challenge file reference is invalid")
    return parts


def _nonnegative_integer(value: Any, label: str, *, optional: bool = False) -> int | None:
    if optional and value is None:
        return None
    if type(value) is not int or value < 0 or value > 2**31 - 1:
        raise BoardError(f"offline catalogue {label} is invalid")
    return value


def _directory_fd(path: Path) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        metadata = os.fstat(descriptor)
    except OSError:
        raise BoardError("offline directory boundary is invalid") from None
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise BoardError("offline directory boundary is invalid")
    return descriptor


def _pinned_directory_fd(path: Path, identity: tuple[int, int]) -> int:
    descriptor = _directory_fd(path)
    metadata = os.fstat(descriptor)
    if (metadata.st_dev, metadata.st_ino) != identity:
        os.close(descriptor)
        raise BoardError("offline directory boundary changed")
    return descriptor


def _child_directory_fd(parent_fd: int, name: str, *, create: bool = False) -> int:
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError:
            raise BoardError("offline destination directory is invalid") from None
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise BoardError("offline directory component is not a directory")
        descriptor = os.open(name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=parent_fd)
        after = os.fstat(descriptor)
    except BoardError:
        raise
    except OSError:
        raise BoardError("offline directory component is invalid") from None
    if not stat.S_ISDIR(after.st_mode) or (before.st_dev, before.st_ino) != (
        after.st_dev,
        after.st_ino,
    ):
        os.close(descriptor)
        raise BoardError("offline directory component changed")
    return descriptor


def _regular_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise BoardError("offline source must be one regular unlinked file")


class OfflineBoard:
    """Fresh run-local Board implementation backed by one registered private bank."""

    def __init__(
        self,
        bank_root: Path,
        workspace_root: Path,
        checker: Checker,
        *,
        service_controller: OfflineServiceController | None = None,
        offline_profile_id: str = "offline-capability-v1",
        timeout: float = 15.0,
        instance_ready_timeout: float = 6.0,
        instance_cleanup_timeout: float = 3.0,
        artifact_limit: int = 128 * 1024 * 1024,
        capsule_limit: int = 512 * 1024 * 1024,
        synthetic_in_process: bool = False,
    ) -> None:
        if not callable(checker):
            checker_method = getattr(checker, "check", None)
            if not callable(checker_method):
                raise BoardError("offline checker is unavailable")
        if type(synthetic_in_process) is not bool:
            raise BoardError("offline synthetic boundary flag is invalid")
        checker_isolated = (
            getattr(checker, "process_isolated", False) is True
            and getattr(checker, "descendant_confined", False) is True
        )
        if not checker_isolated and not synthetic_in_process:
            raise BoardError("offline checker must use a process-isolated port")
        if service_controller is not None:
            controller_isolated = (
                getattr(service_controller, "process_isolated", False) is True
                and getattr(service_controller, "descendant_confined", False) is True
            )
            if not controller_isolated and not synthetic_in_process:
                raise BoardError("offline service must use a process-isolated port")
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < timeout <= 120
        ):
            raise BoardError("offline Board timeout is out of bounds")
        for lifecycle_timeout in (instance_ready_timeout, instance_cleanup_timeout):
            if (
                not isinstance(lifecycle_timeout, (int, float))
                or isinstance(lifecycle_timeout, bool)
                or not 0 < lifecycle_timeout <= 120
            ):
                raise BoardError("offline service lifecycle timeout is out of bounds")
        if type(artifact_limit) is not int or not 0 < artifact_limit <= 2**40:
            raise BoardError("offline artifact limit is invalid")
        if type(capsule_limit) is not int or not artifact_limit <= capsule_limit <= 2**40:
            raise BoardError("offline capsule limit is invalid")
        self.timeout = float(timeout)
        self.instance_ready_timeout = float(instance_ready_timeout)
        self.instance_cleanup_timeout = float(instance_cleanup_timeout)
        self.artifact_limit = artifact_limit
        self.capsule_limit = capsule_limit
        self._bank_root = Path(bank_root).absolute()
        self._workspace_root = Path(workspace_root).absolute()
        self._checker = checker
        self._service_controller = service_controller
        self._synthetic_in_process = synthetic_in_process
        self._offline_profile_id = _component(offline_profile_id, "offline_profile_id")
        self._run_id = secrets.token_bytes(32)
        first_identity = secrets.randbits(62) + 1
        second_identity = secrets.randbits(62) + 1
        while second_identity == first_identity:
            second_identity = secrets.randbits(62) + 1
        self._identity = {"id": first_identity, "team_id": second_identity}
        self._lock = threading.RLock()
        self._candidate_cache: dict[tuple[bytes, str, bytes], _CandidateResult] = {}
        self._next_ordinal: dict[str, int] = {}
        self._checker_calls = 0
        self._repeat_candidates = 0
        self._solved: set[int] = set()
        self._attempts: dict[int, int] = {}
        self._lease: _Lease | None = None
        self._cleanup_pending_task_id: str | None = None
        self._closed_candidates: list[tuple[str, _CandidateResult]] | None = None
        self._closed = False
        self._service_counts = {"create": 0, "renew": 0, "delete": 0, "absence": 0}

        bank_fd = _directory_fd(self._bank_root)
        workspace_fd = _directory_fd(self._workspace_root)
        bank_metadata = os.fstat(bank_fd)
        workspace_metadata = os.fstat(workspace_fd)
        for metadata in (bank_metadata, workspace_metadata):
            if metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o077:
                os.close(bank_fd)
                os.close(workspace_fd)
                raise BoardError("offline directory boundary must be owner-only and owned")
        self._bank_identity = (bank_metadata.st_dev, bank_metadata.st_ino)
        self._workspace_identity = (workspace_metadata.st_dev, workspace_metadata.st_ino)
        os.close(bank_fd)
        os.close(workspace_fd)

        document = self._load_catalogue()
        self._catalogue_version = _component(document.get("catalogue_version"), "catalogue_version")
        rows = document.get("tasks")
        if not isinstance(rows, list) or not rows or len(rows) > _MAX_TASKS:
            raise BoardError("offline catalogue task rows are invalid")
        tasks = [self._parse_task(row) for row in rows]
        if len({task.challenge.id for task in tasks}) != len(tasks):
            raise BoardError("offline catalogue contains duplicate board ids")
        if len({task.task_id for task in tasks}) != len(tasks):
            raise BoardError("offline catalogue contains duplicate task ids")
        self._tasks = {task.challenge.id: task for task in tasks}
        self._ordered_ids = tuple(task.challenge.id for task in tasks)
        self._attempts = {task.challenge.id: 0 for task in tasks}
        self._files: dict[str, tuple[int, _SourceIdentity]] = {}
        per_task_bytes: dict[int, int] = {}
        for task in tasks:
            for file_ref in task.challenge.files:
                if file_ref in self._files:
                    raise BoardError("offline catalogue contains a duplicate file reference")
                identity = self._snapshot_source(task, file_ref)
                total = per_task_bytes.get(task.challenge.id, 0) + identity.size
                if total > self.capsule_limit:
                    raise BoardError("offline capsule exceeds the aggregate byte limit")
                per_task_bytes[task.challenge.id] = total
                self._files[file_ref] = (task.challenge.id, identity)

    def _deadline_ns(self, timeout: float | None = None) -> int:
        selected = self.timeout if timeout is None else timeout
        return time.monotonic_ns() + int(selected * 1_000_000_000)

    def _cleanup_absent(self, proof: Any) -> bool:
        if self._synthetic_in_process and (proof is None or proof is True):
            return True
        return (
            getattr(proof, "exact_cleanup", False) is True and getattr(proof, "remaining", 0) == 0
        )

    def _check_candidate(self, task_id: str, candidate: bytes) -> bool:
        check = getattr(self._checker, "check", None)
        if callable(check):
            return check(task_id, candidate, deadline_ns=self._deadline_ns())
        if self._synthetic_in_process and callable(self._checker):
            return self._checker(task_id, candidate)
        raise BoardError("offline checker port is unavailable")

    def _start_service(self, task: _Task) -> Mapping[str, Any]:
        assert self._service_controller is not None
        if getattr(self._service_controller, "process_isolated", False) is True:
            return self._service_controller.start(
                task.task_id,
                task.resource_profile_id,
                deadline_ns=self._deadline_ns(self.instance_ready_timeout),
            )
        if self._synthetic_in_process:
            return self._service_controller.start(task.task_id)  # type: ignore[call-arg]
        raise BoardError("offline service port is unavailable")

    def _renew_service(self, task: _Task) -> Mapping[str, Any]:
        assert self._service_controller is not None
        if getattr(self._service_controller, "process_isolated", False) is True:
            return self._service_controller.renew(
                task.task_id,
                deadline_ns=self._deadline_ns(self.instance_ready_timeout),
            )
        if self._synthetic_in_process:
            return self._service_controller.renew(task.task_id)  # type: ignore[call-arg]
        raise BoardError("offline service port is unavailable")

    def _stop_service(self, task_id: str) -> None:
        assert self._service_controller is not None
        if getattr(self._service_controller, "process_isolated", False) is True:
            proof = self._service_controller.stop(
                task_id,
                deadline_ns=self._deadline_ns(self.instance_cleanup_timeout),
            )
            if not self._cleanup_absent(proof):
                raise BoardError("offline service absence was not proven")
            return
        if self._synthetic_in_process:
            self._service_controller.stop(task_id)  # type: ignore[call-arg]
            return
        raise BoardError("offline service port is unavailable")

    def _force_reap_service(self) -> bool:
        if self._service_controller is None:
            return False
        abort = getattr(self._service_controller, "abort_and_reap", None)
        if not callable(abort):
            return False
        try:
            proof = abort(deadline_ns=self._deadline_ns(self.instance_cleanup_timeout))
        except BaseException:  # noqa: BLE001 - cleanup proof fails closed
            return False
        return self._cleanup_absent(proof)

    def isolation_roots(self) -> tuple[Path, ...]:
        """Return private roots for the runner's non-public sandbox preflight."""
        roots = {self._bank_root.resolve(strict=True)}
        for boundary in (self._checker, self._service_controller):
            if boundary is None:
                continue
            values = getattr(boundary, "private_roots", ())
            if isinstance(values, tuple):
                for value in values:
                    if isinstance(value, Path):
                        roots.add(value.resolve(strict=True))
        ordered = sorted(roots, key=lambda value: (len(value.parts), str(value)))
        minimal: list[Path] = []
        for root in ordered:
            if not any(parent == root or parent in root.parents for parent in minimal):
                minimal.append(root)
        return tuple(minimal)

    def is_process_isolated(self) -> bool:
        checker_isolated = (
            getattr(self._checker, "process_isolated", False) is True
            and getattr(self._checker, "descendant_confined", False) is True
        )
        controller_isolated = self._service_controller is None or (
            getattr(self._service_controller, "process_isolated", False) is True
            and getattr(self._service_controller, "descendant_confined", False) is True
        )
        return checker_isolated and controller_isolated

    def preflight(self) -> bool:
        """Validate checker/service registrations before any model work."""
        self._require_open()
        if self._synthetic_in_process:
            return True
        if not self.is_process_isolated():
            return False
        checker_inventory = getattr(self._checker, "inventory", None)
        checker_preflight = getattr(self._checker, "preflight", None)
        if not callable(checker_inventory) or not callable(checker_preflight):
            return False
        try:
            if checker_inventory(deadline_ns=self._deadline_ns()) != 0:
                return False
            for task in self._tasks.values():
                if not checker_preflight(
                    task.task_id,
                    task.checker_version,
                    deadline_ns=self._deadline_ns(),
                ):
                    return False
        except BaseException:  # noqa: BLE001 - preflight fails closed
            return False
        dynamic = [task for task in self._tasks.values() if task.service_required]
        if dynamic and self._service_controller is None:
            return False
        if self._service_controller is not None:
            try:
                if (
                    self._service_controller.inventory(
                        deadline_ns=self._deadline_ns(self.instance_ready_timeout)
                    )
                    != 0
                ):
                    return False
                for task in dynamic:
                    if (
                        task.service_version == "none"
                        or getattr(self._service_controller, "source_version", None)
                        != task.service_version
                    ):
                        return False
                    if not self._service_controller.preflight(
                        task.task_id,
                        task.resource_profile_id,
                        deadline_ns=self._deadline_ns(self.instance_ready_timeout),
                    ):
                        return False
            except BaseException:  # noqa: BLE001 - preflight fails closed
                return False
        return True

    def _load_catalogue(self) -> dict[str, Any]:
        root = _pinned_directory_fd(self._bank_root, self._bank_identity)
        try:
            before = os.stat("public-catalogue.json", dir_fd=root, follow_symlinks=False)
            _regular_metadata(before)
            if before.st_size > _CATALOGUE_LIMIT:
                raise BoardError("offline catalogue exceeds the byte limit")
            descriptor = os.open(
                "public-catalogue.json",
                os.O_RDONLY | _NOFOLLOW | _NONBLOCK,
                dir_fd=root,
            )
            try:
                chunks: list[bytes] = []
                remaining = _CATALOGUE_LIMIT + 1
                while remaining:
                    chunk = os.read(descriptor, min(remaining, _COPY_CHUNK))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            _regular_metadata(after)
            if len(b"".join(chunks)) > _CATALOGUE_LIMIT:
                raise BoardError("offline catalogue exceeds the byte limit")
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise BoardError("offline catalogue changed during validation")
            document = json.loads(b"".join(chunks))
        except BoardError:
            raise
        except (OSError, UnicodeError, ValueError, RecursionError):
            raise BoardError("offline catalogue is unreadable") from None
        finally:
            os.close(root)
        if not isinstance(document, dict):
            raise BoardError("offline catalogue root is invalid")
        return document

    def _parse_task(self, row: Any) -> _Task:
        if not isinstance(row, dict):
            raise BoardError("offline catalogue task row is invalid")
        board_id = row.get("board_id")
        if type(board_id) is not int or board_id <= 0 or board_id > 2**31 - 1:
            raise BoardError("offline catalogue board_id is invalid")
        task_id = _component(row.get("task_id"), "task_id")
        category = _bounded_text(row.get("category"), "category")
        challenge_type = _bounded_text(row.get("type"), "type")
        if challenge_type not in {"standard", "dynamic_iac"}:
            raise BoardError("offline catalogue challenge type is invalid")
        description = _bounded_text(
            row.get("description"),
            "description",
            limit=MAX_CHALLENGE_DESCRIPTION_BYTES,
        )
        name = _bounded_text(row.get("name", task_id), "name")
        files = row.get("files", [])
        if not isinstance(files, list) or len(files) > _MAX_FILES:
            raise BoardError("offline catalogue files are invalid")
        normalized_files = tuple("/".join(_file_parts(file_ref)) for file_ref in files)
        if len(set(normalized_files)) != len(normalized_files):
            raise BoardError("offline catalogue files contain duplicates")
        solved = row.get("solved", False)
        attempts = _nonnegative_integer(row.get("attempts", 0), "attempts")
        if solved is not False or attempts != 0:
            raise BoardError("offline catalogue must begin fresh")
        shared = row.get("shared")
        if shared is not None and type(shared) is not bool:
            raise BoardError("offline catalogue shared is invalid")
        service_required = row.get("service_required", False)
        if type(service_required) is not bool or service_required != (
            challenge_type == "dynamic_iac"
        ):
            raise BoardError("offline catalogue service registration is incoherent")
        challenge = Challenge(
            id=board_id,
            name=name,
            category=category,
            type=challenge_type,
            description=description,
            value=_nonnegative_integer(row.get("value", 0), "value") or 0,
            files=normalized_files,
            solved=False,
            max_attempts=_nonnegative_integer(
                row.get("max_attempts"), "max_attempts", optional=True
            ),
            attempts=0,
            timeout=_nonnegative_integer(row.get("timeout"), "timeout", optional=True),
            shared=shared,
        )
        return _Task(
            challenge=challenge,
            task_id=task_id,
            service_required=service_required,
            resource_profile_id=_component(
                row.get("resource_profile_id", "none"), "resource_profile_id"
            ),
            generator_version=_component(row.get("generator_version"), "generator_version"),
            checker_version=_component(row.get("checker_version"), "checker_version"),
            service_version=_component(row.get("service_version", "none"), "service_version"),
        )

    def _visible_fd(self, task: _Task) -> int:
        bank_fd = _pinned_directory_fd(self._bank_root, self._bank_identity)
        descriptors = [bank_fd]
        try:
            for name in ("capsules", task.task_id, "visible"):
                descriptors.append(_child_directory_fd(descriptors[-1], name))
            return os.dup(descriptors[-1])
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _open_source(self, task: _Task, file_ref: str) -> int:
        parts = _file_parts(file_ref)
        descriptor = self._visible_fd(task)
        try:
            for name in parts[:-1]:
                child = _child_directory_fd(descriptor, name)
                os.close(descriptor)
                descriptor = child
            try:
                before = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
                _regular_metadata(before)
                source = os.open(
                    parts[-1],
                    os.O_RDONLY | _NOFOLLOW | _NONBLOCK,
                    dir_fd=descriptor,
                )
                after = os.fstat(source)
                _regular_metadata(after)
            except BoardError:
                raise
            except OSError:
                raise BoardError("offline source file is invalid") from None
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                os.close(source)
                raise BoardError("offline source file changed")
            return source
        finally:
            os.close(descriptor)

    def _snapshot_source(self, task: _Task, file_ref: str) -> _SourceIdentity:
        descriptor = self._open_source(task, file_ref)
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_size > self.artifact_limit:
                raise BoardError("offline source exceeds the per-file byte limit")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, _COPY_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.artifact_limit:
                    raise BoardError("offline source exceeds the per-file byte limit")
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (metadata.st_size, metadata.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise BoardError("offline source changed during registration")
        return _SourceIdentity(
            device=after.st_dev,
            inode=after.st_ino,
            size=total,
            modified_ns=after.st_mtime_ns,
            digest=digest.digest(),
        )

    def identity(self) -> dict[str, Any]:
        self._require_open()
        return dict(self._identity)

    def anonymous_identity_is_rejected(self) -> bool:
        self._require_open()
        return True

    def list_challenges(self) -> list[dict[str, Any]]:
        self._require_open()
        with self._lock:
            rows = []
            for challenge_id in self._ordered_ids:
                task = self._tasks[challenge_id]
                challenge = task.challenge
                rows.append(
                    {
                        "id": challenge.id,
                        "task_id": task.task_id,
                        "name": challenge.name,
                        "category": challenge.category,
                        "type": challenge.type,
                        "value": challenge.value,
                        "solved_by_me": challenge_id in self._solved,
                        "attempts": self._attempts[challenge_id],
                        "service_required": task.service_required,
                        "resource_profile_id": task.resource_profile_id,
                        "generator_version": task.generator_version,
                        "checker_version": task.checker_version,
                        "service_version": task.service_version,
                    }
                )
            return rows

    def challenge(self, challenge_id: int) -> Challenge:
        self._require_open()
        if type(challenge_id) is not int or challenge_id <= 0:
            raise BoardError("challenge id must be a positive integer")
        with self._lock:
            try:
                task = self._tasks[challenge_id]
            except KeyError:
                raise BoardError("offline challenge is not selected") from None
            return replace(
                task.challenge,
                solved=challenge_id in self._solved,
                attempts=self._attempts[challenge_id],
            )

    def _destination_parent(self, destination: Path) -> tuple[int, str]:
        destination = Path(destination)
        if destination.is_absolute():
            absolute = destination.absolute()
        else:
            absolute = self._workspace_root / destination
        try:
            relative = absolute.relative_to(self._workspace_root)
        except ValueError:
            raise BoardError("offline destination escapes the workspace") from None
        parts = relative.parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise BoardError("offline destination is invalid")
        if any(any(ord(character) < 32 for character in part) for part in parts):
            raise BoardError("offline destination is invalid")
        descriptor = _pinned_directory_fd(self._workspace_root, self._workspace_identity)
        try:
            for name in parts[:-1]:
                child = _child_directory_fd(descriptor, name, create=True)
                os.close(descriptor)
                descriptor = child
            return descriptor, parts[-1]
        except Exception:
            os.close(descriptor)
            raise

    def download(
        self,
        file_ref: str,
        destination: Path,
        *,
        byte_limit: int | None = None,
    ) -> dict[str, Any]:
        self._require_open()
        normalized = "/".join(_file_parts(file_ref))
        try:
            challenge_id, registered = self._files[normalized]
        except KeyError:
            raise BoardError("offline challenge file is not registered") from None
        limit = self.artifact_limit if byte_limit is None else byte_limit
        if type(limit) is not int or not 0 < limit <= self.artifact_limit:
            raise BoardError("offline challenge file byte limit is invalid")
        if registered.size > limit:
            raise BoardError("offline challenge file exceeds the byte limit")
        task = self._tasks[challenge_id]
        source = self._open_source(task, normalized)
        parent = -1
        temporary_name = ""
        temporary = -1
        try:
            before = os.fstat(source)
            observed = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            expected = (
                registered.device,
                registered.inode,
                registered.size,
                registered.modified_ns,
            )
            if observed != expected:
                raise BoardError("offline source identity changed after registration")
            parent, final_name = self._destination_parent(Path(destination))
            try:
                existing = os.stat(final_name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            except OSError:
                raise BoardError("offline destination is invalid") from None
            if existing is not None:
                _regular_metadata(existing)
            for _ in range(8):
                temporary_name = f".offline-copy-{secrets.token_hex(12)}"
                try:
                    temporary = os.open(
                        temporary_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                        0o600,
                        dir_fd=parent,
                    )
                    break
                except FileExistsError:
                    continue
                except OSError:
                    raise BoardError("offline destination temporary file is invalid") from None
            if temporary < 0:
                raise BoardError("offline destination temporary file could not be allocated")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(source, min(_COPY_CHUNK, limit - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise BoardError("offline challenge file exceeded the byte limit")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(temporary, view)
                    if written <= 0:
                        raise BoardError("offline destination write failed")
                    view = view[written:]
            os.fsync(temporary)
            after = os.fstat(source)
            final_identity = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
            if (
                final_identity != expected
                or total != registered.size
                or digest.digest() != registered.digest
            ):
                raise BoardError("offline source changed during copy")
            os.close(temporary)
            temporary = -1
            os.replace(temporary_name, final_name, src_dir_fd=parent, dst_dir_fd=parent)
            temporary_name = ""
            os.fsync(parent)
            return {"bytes": total, "status": "closed"}
        finally:
            os.close(source)
            if temporary >= 0:
                os.close(temporary)
            if parent >= 0:
                if temporary_name:
                    try:
                        os.unlink(temporary_name, dir_fd=parent)
                    except FileNotFoundError:
                        pass
                os.close(parent)

    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        self._require_open()
        task = self._tasks.get(challenge_id) if type(challenge_id) is int else None
        if task is None:
            raise BoardError("offline challenge is not selected")
        if (
            not isinstance(candidate, str)
            or len(candidate) > 600
            or not FLAG_RE.fullmatch(candidate)
        ):
            raise BoardError("candidate does not match a supported flag shape")
        try:
            candidate_bytes = candidate.encode("utf-8")
        except UnicodeError:
            raise BoardError("candidate does not match a supported flag shape") from None
        key = (self._run_id, task.task_id, candidate_bytes)
        with self._lock:
            cached = self._candidate_cache.get(key)
            if cached is not None:
                cached.repeat_count += 1
                self._repeat_candidates += 1
                return Verdict(cached.outcome, cached.message, cached.http_status)
            attempt_limit = task.challenge.max_attempts
            if attempt_limit not in {None, 0} and self._attempts[challenge_id] >= attempt_limit:
                return Verdict("paused", "attempt limit reached", 403)
            ordinal = self._next_ordinal.get(task.task_id, 0) + 1
            self._next_ordinal[task.task_id] = ordinal
            self._checker_calls += 1
            self._attempts[challenge_id] += 1
            checked_monotonic_ns = time.monotonic_ns()
            try:
                accepted = self._check_candidate(task.task_id, candidate_bytes)
                if type(accepted) is not bool:
                    raise TypeError("checker returned a non-boolean result")
            except BaseException:  # noqa: BLE001 - every private checker failure fails closed
                result = _CandidateResult(
                    ordinal,
                    task.checker_version,
                    True,
                    checked_monotonic_ns,
                    "unread",
                    "oracle_inconclusive",
                    503,
                )
            else:
                outcome = "correct" if accepted else "incorrect"
                result = _CandidateResult(
                    ordinal,
                    task.checker_version,
                    True,
                    checked_monotonic_ns,
                    outcome,
                    outcome,
                    200,
                )
                if accepted:
                    self._solved.add(challenge_id)
            self._candidate_cache[key] = result
            return Verdict(result.outcome, result.message, result.http_status)

    @staticmethod
    def _scalar(value: Any, label: str) -> str | int | float | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            raise BoardError(f"offline service {label} is invalid")
        if len(str(value)) > 256:
            raise BoardError(f"offline service {label} is invalid")
        return value

    def _lease_from_record(self, challenge_id: int, task: _Task, record: Any) -> _Lease:
        if not isinstance(record, Mapping):
            raise BoardError("offline service returned an invalid record")
        connection_info = record.get("connection_info")
        if not isinstance(connection_info, str):
            raise BoardError("offline service connection information is invalid")
        try:
            encoded = connection_info.encode("utf-8")
        except UnicodeError:
            raise BoardError("offline service connection information is invalid") from None
        if (
            not connection_info
            or len(encoded) > _MAX_CONNECTION_BYTES
            or any(ord(character) < 32 for character in connection_info)
        ):
            raise BoardError("offline service connection information is invalid")
        try:
            endpoints = parse_connection_info(connection_info)
            if any(not ipaddress.ip_address(endpoint.host).is_loopback for endpoint in endpoints):
                raise ValueError("non-loopback endpoint")
        except ValueError:
            raise BoardError("offline service endpoint is not loopback-only") from None
        return _Lease(
            challenge_id=challenge_id,
            task_id=task.task_id,
            connection_info=connection_info,
            since=self._scalar(record.get("since"), "since"),
            until=self._scalar(record.get("until"), "until"),
        )

    @staticmethod
    def _instance_result(
        *,
        success: bool,
        status: int,
        message: str,
        lease: _Lease | None = None,
    ) -> dict[str, Any]:
        return {
            "success": success,
            "status": status,
            "connection_info": lease.connection_info if lease is not None else "",
            "until": lease.until if lease is not None else None,
            "since": lease.since if lease is not None else None,
            "message": message,
        }

    def instance(self, method: str, challenge_id: int) -> dict[str, Any]:
        self._require_open()
        if method not in {"GET", "POST", "PATCH", "DELETE"}:
            raise BoardError("unsupported instance method")
        task = self._tasks.get(challenge_id) if type(challenge_id) is int else None
        if task is None:
            raise BoardError("offline challenge is not selected")
        if not task.service_required:
            raise BoardError("offline challenge has no registered service")
        with self._lock:
            pending_for_current = self._cleanup_pending_task_id == task.task_id
            if self._cleanup_pending_task_id is not None:
                if method == "DELETE" and pending_for_current:
                    if self._service_controller is None:
                        return self._instance_result(
                            success=False, status=503, message="service cleanup pending"
                        )
                    try:
                        self._stop_service(task.task_id)
                    except Exception:  # noqa: BLE001 - private cleanup failure stays fenced
                        return self._instance_result(
                            success=False, status=503, message="service cleanup pending"
                        )
                    self._cleanup_pending_task_id = None
                    self._service_counts["delete"] += 1
                    return self._instance_result(
                        success=True, status=200, message="instance deleted"
                    )
                return self._instance_result(
                    success=False, status=503, message="service cleanup pending"
                )
            current = (
                self._lease if self._lease and self._lease.challenge_id == challenge_id else None
            )
            if method == "GET":
                if current is None:
                    self._service_counts["absence"] += 1
                    return self._instance_result(
                        success=False, status=404, message="instance absent"
                    )
                return self._instance_result(
                    success=True, status=200, message="instance ready", lease=current
                )
            if method == "POST":
                if self._lease is not None:
                    status = 409 if current is not None else 429
                    message = (
                        "instance already ready"
                        if current is not None
                        else "dynamic lease unavailable"
                    )
                    return self._instance_result(success=False, status=status, message=message)
                if self._service_controller is None:
                    return self._instance_result(
                        success=False, status=503, message="service controller unavailable"
                    )
                self._cleanup_pending_task_id = task.task_id
                try:
                    lease = self._lease_from_record(
                        challenge_id,
                        task,
                        self._start_service(task),
                    )
                except Exception:  # noqa: BLE001 - private controller failures fail closed
                    try:
                        self._stop_service(task.task_id)
                    except Exception:  # noqa: BLE001 - best-effort partial-create cleanup
                        cleaned = self._force_reap_service()
                    else:
                        cleaned = True
                    if cleaned:
                        self._cleanup_pending_task_id = None
                        self._service_counts["delete"] += 1
                    return self._instance_result(
                        success=False, status=503, message="service create failed"
                    )
                self._lease = lease
                self._cleanup_pending_task_id = None
                self._service_counts["create"] += 1
                return self._instance_result(
                    success=True, status=200, message="instance ready", lease=lease
                )
            if current is None:
                return self._instance_result(success=False, status=404, message="instance absent")
            if method == "PATCH":
                if self._service_controller is None:
                    return self._instance_result(
                        success=False, status=503, message="service controller unavailable"
                    )
                try:
                    renewed = self._lease_from_record(
                        challenge_id,
                        task,
                        self._renew_service(task),
                    )
                except Exception:  # noqa: BLE001 - private controller failures fail closed
                    if self._force_reap_service():
                        self._lease = None
                        self._service_counts["delete"] += 1
                        current = None
                    return self._instance_result(
                        success=False, status=503, message="service renew failed", lease=current
                    )
                self._lease = renewed
                self._service_counts["renew"] += 1
                return self._instance_result(
                    success=True, status=200, message="instance ready", lease=renewed
                )
            if self._service_controller is None:
                return self._instance_result(
                    success=False,
                    status=503,
                    message="service controller unavailable",
                    lease=current,
                )
            try:
                self._stop_service(task.task_id)
            except Exception:  # noqa: BLE001 - private controller failures fail closed
                return self._instance_result(
                    success=False, status=503, message="service delete failed", lease=current
                )
            self._lease = None
            self._service_counts["delete"] += 1
            return self._instance_result(success=True, status=200, message="instance deleted")

    def public_snapshot(self) -> dict[str, Any]:
        """Return a closed, candidate-free record suitable for public acceptance evidence."""
        with self._lock:
            source = (
                self._closed_candidates
                if self._closed_candidates is not None
                else [
                    (task_id, result)
                    for (_run_id, task_id, _candidate), result in self._candidate_cache.items()
                ]
            )
            candidates = sorted(
                (
                    {
                        "task_id": task_id,
                        "candidate_ordinal": result.ordinal,
                        "outcome": (
                            "oracle_inconclusive" if result.outcome == "unread" else result.outcome
                        ),
                        "repeat_count": result.repeat_count,
                    }
                    for task_id, result in source
                ),
                key=lambda row: (str(row["task_id"]), int(row["candidate_ordinal"])),
            )
            return {
                "offline_profile_id": self._offline_profile_id,
                "catalogue_version": self._catalogue_version,
                "implementation_version": OFFLINE_BOARD_IMPLEMENTATION_VERSION,
                "task_registrations": [
                    {
                        "board_id": task.challenge.id,
                        "task_id": task.task_id,
                        "generator_version": task.generator_version,
                        "checker_version": task.checker_version,
                        "service_version": task.service_version,
                    }
                    for task in (self._tasks[challenge_id] for challenge_id in self._ordered_ids)
                ],
                "selected_task_count": len(self._tasks),
                "solved_task_count": len(self._solved),
                "unique_candidate_count": len(source),
                "repeat_candidate_count": self._repeat_candidates,
                "checker_call_count": self._checker_calls,
                "attempt_counts": [
                    {
                        "task_id": self._tasks[challenge_id].task_id,
                        "attempts": self._attempts[challenge_id],
                    }
                    for challenge_id in self._ordered_ids
                ],
                "candidates": candidates,
                "active_service_count": int(
                    self._lease is not None or self._cleanup_pending_task_id is not None
                ),
                "cleanup_pending_service_count": int(self._cleanup_pending_task_id is not None),
                "service_counts": dict(self._service_counts),
                "service_runtime": (
                    self._service_controller.registration_record()
                    if self._service_controller is not None
                    and callable(getattr(self._service_controller, "registration_record", None))
                    else None
                ),
            }

    def registration_record(self) -> dict[str, Any]:
        """Candidate-free immutable registration used before any model work."""
        self._require_open()
        snapshot = self.public_snapshot()
        return {
            "offline_profile_id": snapshot["offline_profile_id"],
            "catalogue_version": snapshot["catalogue_version"],
            "implementation_version": snapshot["implementation_version"],
            "task_registrations": snapshot["task_registrations"],
            "service_runtime": snapshot["service_runtime"],
        }

    def _require_open(self) -> None:
        if self._closed:
            raise BoardError("offline Board is closed")

    def close(self) -> None:
        """Delete an owned service and erase candidate bytes while retaining closed counts."""
        with self._lock:
            if self._closed:
                return
            if self._cleanup_pending_task_id is not None:
                if self._service_controller is None:
                    raise BoardError("offline service cleanup has no controller")
                try:
                    self._stop_service(self._cleanup_pending_task_id)
                except Exception:  # noqa: BLE001 - private cleanup is normalized
                    if not self._force_reap_service():
                        raise BoardError("offline service cleanup failed") from None
                self._cleanup_pending_task_id = None
                self._service_counts["delete"] += 1
            if self._lease is not None:
                if self._service_controller is None:
                    raise BoardError("offline service cleanup has no controller")
                try:
                    self._stop_service(self._lease.task_id)
                except Exception:  # noqa: BLE001 - private cleanup is normalized
                    if not self._force_reap_service():
                        raise BoardError("offline service cleanup failed") from None
                self._service_counts["delete"] += 1
                self._lease = None
            for boundary in (self._checker, self._service_controller):
                abort = getattr(boundary, "abort_and_reap", None)
                if callable(abort):
                    try:
                        proof = abort(deadline_ns=self._deadline_ns(self.instance_cleanup_timeout))
                    except BaseException:  # noqa: BLE001 - cleanup proof fails closed
                        raise BoardError("offline callback cleanup failed") from None
                    if not self._cleanup_absent(proof):
                        raise BoardError("offline callback absence was not proven")
            self._closed_candidates = [
                (task_id, result)
                for (_run_id, task_id, _candidate), result in self._candidate_cache.items()
            ]
            self._candidate_cache.clear()
            self._next_ordinal.clear()
            self._run_id = b""
            self._closed = True
