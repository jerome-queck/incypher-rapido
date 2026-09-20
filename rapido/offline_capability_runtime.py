"""Private registry seam for the registered CAP-05 durable flow.

Only candidate-free canonical configuration crosses the public supervisor pipe.  A disposable
worker resolves one owner-only registry root from its environment, verifies an exact public and
task-registration binding, loads one content-pinned private adapter, and then constructs the
existing OfflineBoard -> DurableJobControl/NativeRuntime flow.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import os
import re
import stat
import types
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .offline_board import OfflineBoard
from .offline_capability_runner import (
    CapabilityFlow,
    CapabilityRunnerError,
    CleanupInventory,
    FlowEvidence,
    RunControl,
    RunnerContract,
    durable_job_control_flow,
)
from .offline_profile import OfflineRuntimeConfig, assert_offline_environment, offline_child_env
from .orchestrator import NativeRuntime

PRIVATE_RUNTIME_REGISTRY_SCHEMA = "rapido-offline-capability-private-runtime-v1"
PRIVATE_RUNTIME_ROOT_ENV = "RAPIDO_OFFLINE_CAPABILITY_ROOT"
PRIVATE_RUNTIME_REGISTRY_DIGEST_ENV = "RAPIDO_OFFLINE_CAPABILITY_REGISTRY_SHA256"
_REGISTRY_NAME = "registry.json"
_CATALOGUE_NAME = "public-catalogue.json"
_MANIFEST_NAME = "public-readiness.json"
_REGISTRY_LIMIT = 1_048_576
_ADAPTER_LIMIT = 1_048_576
_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PUBLIC_CONFIGURATION_KEYS = frozenset(
    {
        "registry_id",
        "offline_profile_id",
        "catalogue_version",
        "board_implementation_version",
        "runner_image",
        "requires_provider_auth",
    }
)


class _EvidenceSource(Protocol):
    def __call__(self) -> FlowEvidence: ...


@dataclass(frozen=True)
class RegisteredDurableRuntime:
    """Exact private adapter result consumed by the public registered factory."""

    config: OfflineRuntimeConfig
    board: OfflineBoard
    runtime: NativeRuntime
    evidence_source: _EvidenceSource
    cleanup: Callable[[float], Awaitable[CleanupInventory]]
    private_roots: tuple[Path, ...]
    isolation_probe: Callable[[], Awaitable[bool] | bool]


@dataclass
class _PinnedDirectory:
    source: Path
    descriptor: int
    identity: tuple[int, int, int, int]

    @property
    def path(self) -> Path:
        prefix = "/proc" if os.path.isdir("/proc/self/fd") else "/dev"
        return (
            Path(prefix)
            / (str(os.getpid()) if prefix == "/proc" else "fd")
            / ("fd" if prefix == "/proc" else str(self.descriptor))
            / (str(self.descriptor) if prefix == "/proc" else "")
        )

    def revalidate(self, label: str) -> None:
        _reject_symlink_components(self.source, label)
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(self.source, flags)
            metadata = os.fstat(descriptor)
        except OSError:
            raise CapabilityRunnerError(f"{label} changed") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        observed = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
        )
        if observed != self.identity:
            raise CapabilityRunnerError(f"{label} changed")

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass
class _PinnedFile:
    name: str
    descriptor: int
    identity: tuple[int, int, int, int, int, int, int]
    parent: _PinnedDirectory

    def revalidate(self, label: str) -> None:
        try:
            opened = os.fstat(self.descriptor)
            named = os.stat(self.name, dir_fd=self.parent.descriptor, follow_symlinks=False)
        except OSError:
            raise CapabilityRunnerError(f"{label} changed") from None
        for metadata in (opened, named):
            observed = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_ctime_ns,
            )
            if observed != self.identity:
                raise CapabilityRunnerError(f"{label} changed")

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


class _PinnedDurableFlow:
    def __init__(
        self,
        flow: CapabilityFlow,
        probe: Callable[[], Awaitable[bool] | bool],
        runtime_root: _PinnedDirectory,
        capsule_files: tuple[_PinnedFile, ...],
        codex_home: _PinnedDirectory | None,
        auth_file: _PinnedFile | None,
        owned_runtime_cleanup: Callable[[], Awaitable[Mapping[str, object]]] | None,
    ) -> None:
        self._flow = flow
        self._probe = probe
        self._runtime_root = runtime_root
        self._capsule_files = capsule_files
        self._codex_home = codex_home
        self._auth_file = auth_file
        self._owned_runtime_cleanup = owned_runtime_cleanup

    def _revalidate(self) -> None:
        self._runtime_root.revalidate("private runtime root")
        for pinned in self._capsule_files:
            pinned.revalidate("private capsule projection")
        if self._codex_home is not None:
            self._codex_home.revalidate("provider authentication home")
        if self._auth_file is not None:
            self._auth_file.revalidate("provider authentication file")

    async def drive(self, control: RunControl) -> None:
        self._revalidate()
        result = self._probe()
        if inspect.isawaitable(result):
            result = await result
        if result is not True:
            raise CapabilityRunnerError("native runtime isolation preflight failed")
        self._revalidate()
        await self._flow.drive(control)
        self._revalidate()

    def snapshot(self) -> FlowEvidence:
        self._revalidate()
        result = self._flow.snapshot()
        self._revalidate()
        return result

    async def cleanup(self, deadline: float) -> CleanupInventory:
        result = CleanupInventory.unavailable()
        boundary_record: Mapping[str, object] | None = None
        try:
            self._revalidate()
            result = await self._flow.cleanup(deadline)
            self._revalidate()
        finally:
            if self._owned_runtime_cleanup is not None:
                try:
                    boundary_record = await self._owned_runtime_cleanup()
                except BaseException:  # noqa: BLE001 - cleanup proof fails closed
                    boundary_record = None
            if self._auth_file is not None:
                self._auth_file.close()
            if self._codex_home is not None:
                self._codex_home.close()
            for pinned in self._capsule_files:
                pinned.close()
            self._runtime_root.close()
        if self._owned_runtime_cleanup is None:
            return result
        active = None if boundary_record is None else boundary_record.get("active_process_count")
        absent = None if boundary_record is None else boundary_record.get("process_absent")
        if type(active) is not int or active < 0 or absent is not True or active != 0:
            return CleanupInventory(
                active if type(active) is int and active >= 0 else None,
                result.containers,
                result.volumes,
                result.networks,
                result.services,
                result.workspaces,
                result.state_objects,
                result.run_ids,
                failure_label="owned_runtime_cleanup_failed",
            )
        return result


def _reject_symlink_components(path: Path, label: str) -> None:
    """Reject a path whose pinned boundary depends on any symbolic-link component."""

    if not path.is_absolute():
        raise CapabilityRunnerError(f"{label} is not absolute")
    current = Path(path.anchor)
    try:
        for component in path.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                raise CapabilityRunnerError(f"{label} contains a symbolic link")
    except OSError:
        raise CapabilityRunnerError(f"{label} is unavailable") from None


def _owner_only_directory(path: Path, label: str) -> tuple[int, int, int, int]:
    _reject_symlink_components(path, label)
    try:
        metadata = path.lstat()
    except OSError:
        raise CapabilityRunnerError(f"{label} is unavailable") from None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o077
        or not os.access(path, os.R_OK | os.X_OK)
    ):
        raise CapabilityRunnerError(f"{label} is not owner-only")
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid


def _pin_owner_only_directory(path: Path, label: str) -> _PinnedDirectory:
    identity = _owner_only_directory(path, label)
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
    except OSError:
        raise CapabilityRunnerError(f"{label} is unavailable") from None
    observed = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
    )
    if observed != identity:
        os.close(descriptor)
        raise CapabilityRunnerError(f"{label} changed")
    return _PinnedDirectory(path, descriptor, identity)


def _pin_owner_only_file(
    parent: _PinnedDirectory, name: str, label: str, *, limit: int
) -> _PinnedFile:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent.descriptor)
        metadata = os.fstat(descriptor)
    except OSError:
        raise CapabilityRunnerError(f"{label} is unavailable") from None
    identity = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_ctime_ns,
    )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o077
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= limit
    ):
        os.close(descriptor)
        raise CapabilityRunnerError(f"{label} is not owner-only")
    pinned = _PinnedFile(name, descriptor, identity, parent)
    pinned.revalidate(label)
    return pinned


def _read_pinned_file(pinned: _PinnedFile, *, limit: int) -> bytes:
    try:
        before = os.fstat(pinned.descriptor)
        if not 0 < before.st_size <= limit:
            raise OSError("pinned file size changed")
        descriptor = os.dup(pinned.descriptor)
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65_536))
                if not chunk:
                    raise OSError("short pinned file")
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(descriptor)
        pinned.revalidate("private capsule projection")
        after = os.fstat(pinned.descriptor)
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            raise OSError("pinned file changed")
        return b"".join(chunks)
    except OSError:
        raise CapabilityRunnerError("private capsule projection is unsafe") from None


def _owner_only_file(root_descriptor: int, name: str, *, limit: int) -> bytes:
    if _COMPONENT.fullmatch(name) is None or name in {".", ".."}:
        raise CapabilityRunnerError("private runtime file name is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=root_descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_mode & 0o077
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= limit
        ):
            raise OSError("unsafe private runtime file")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise OSError("short private runtime file")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ):
            raise OSError("private runtime file changed")
        return b"".join(chunks)
    except OSError:
        raise CapabilityRunnerError("private runtime file is unsafe") from None
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _public_configuration(configuration: Mapping[str, object]) -> dict[str, object]:
    if set(configuration) != _PUBLIC_CONFIGURATION_KEYS:
        raise CapabilityRunnerError("durable factory public configuration is invalid")
    expected_text = {
        "registry_id",
        "offline_profile_id",
        "catalogue_version",
        "board_implementation_version",
        "runner_image",
    }
    if (
        any(
            type(configuration[name]) is not str or not configuration[name]
            for name in expected_text
        )
        or type(configuration["requires_provider_auth"]) is not bool
    ):
        raise CapabilityRunnerError("durable factory public configuration is invalid")
    return dict(configuration)


def _contract_binding(contract: RunnerContract) -> dict[str, object]:
    return {
        "run_id": contract.run_id,
        "experiment_id": contract.experiment_id,
        "execution_policy": contract.execution_policy.public(),
        "task_registrations": [
            {
                "task_id": task.task_id,
                "family_id": task.family_id,
                "category": task.category,
                "tier": task.tier,
                "generator_version": task.generator_version,
                "checker_version": task.checker_version,
                "service_version": task.service_version,
            }
            for task in contract.tasks
        ],
    }


def _load_registry(root: Path, expected_digest: str) -> tuple[dict[str, object], _PinnedDirectory]:
    if _SHA256.fullmatch(expected_digest) is None:
        raise CapabilityRunnerError("private runtime registry commitment is invalid")
    pinned = _pin_owner_only_directory(root, "private runtime root")
    try:
        payload = _owner_only_file(pinned.descriptor, _REGISTRY_NAME, limit=_REGISTRY_LIMIT)
        if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), expected_digest):
            raise OSError("private runtime registry commitment changed")
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError):
        pinned.close()
        raise CapabilityRunnerError("private runtime registry is invalid") from None
    if not isinstance(value, dict):
        pinned.close()
        raise CapabilityRunnerError("private runtime registry is invalid")
    return value, pinned


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _validate_capsule_binding(
    binding: object,
    catalogue_payload: bytes,
    manifest_payload: bytes,
    contract: RunnerContract,
    configuration: Mapping[str, object],
) -> tuple[Mapping[str, object], ...]:
    if not isinstance(binding, Mapping) or set(binding) != {
        "namespace",
        "catalogue_sha256",
        "manifest_sha256",
        "tasks",
    }:
        raise CapabilityRunnerError("private capsule binding is invalid")
    namespace = binding.get("namespace")
    catalogue_digest = binding.get("catalogue_sha256")
    manifest_digest = binding.get("manifest_sha256")
    raw_tasks = binding.get("tasks")
    if (
        type(namespace) is not str
        or namespace != configuration["registry_id"]
        or type(catalogue_digest) is not str
        or _SHA256.fullmatch(catalogue_digest) is None
        or type(manifest_digest) is not str
        or _SHA256.fullmatch(manifest_digest) is None
        or not isinstance(raw_tasks, list)
        or len(raw_tasks) != len(contract.tasks)
    ):
        raise CapabilityRunnerError("private capsule binding is invalid")
    if not hmac.compare_digest(hashlib.sha256(catalogue_payload).hexdigest(), catalogue_digest):
        raise CapabilityRunnerError("private capsule catalogue binding changed")
    if not hmac.compare_digest(hashlib.sha256(manifest_payload).hexdigest(), manifest_digest):
        raise CapabilityRunnerError("private capsule manifest binding changed")
    try:
        catalogue = json.loads(catalogue_payload)
        manifest = json.loads(manifest_payload)
    except (UnicodeError, json.JSONDecodeError):
        raise CapabilityRunnerError("private capsule projection is invalid") from None
    if (
        not isinstance(catalogue, Mapping)
        or catalogue.get("catalogue_version") != configuration["catalogue_version"]
        or not isinstance(catalogue.get("tasks"), list)
        or not isinstance(manifest, Mapping)
        or manifest.get("schema") != "rapido-offline-capsule-export-v1"
        or manifest.get("catalogue_version") != configuration["catalogue_version"]
        or not isinstance(manifest.get("admitted"), list)
        or not isinstance(manifest.get("excluded"), list)
    ):
        raise CapabilityRunnerError("private capsule projection is invalid")
    catalogue_tasks = catalogue["tasks"]
    admitted_tasks = manifest["admitted"]
    assert isinstance(catalogue_tasks, list)
    assert isinstance(admitted_tasks, list)
    if len(catalogue_tasks) != len(contract.tasks) or len(admitted_tasks) != len(contract.tasks):
        raise CapabilityRunnerError("private capsule task inventory changed")
    excluded_ids = {
        row.get("task_id")
        for row in manifest["excluded"]
        if isinstance(row, Mapping) and type(row.get("task_id")) is str
    }
    offline_tasks: list[Mapping[str, object]] = []
    board_ids: set[int] = set()
    task_ids: set[str] = set()
    binding_keys = {
        "board_id",
        "task_id",
        "family_id",
        "category",
        "tier",
        "assignment",
        "description_commitment",
        "files_commitment",
        "resource_profile_id",
        "generator_version",
        "checker_version",
        "service_version",
        "task_commitment",
    }
    for task, catalogue_row, manifest_row, raw_binding in zip(
        contract.tasks, catalogue_tasks, admitted_tasks, raw_tasks, strict=True
    ):
        if (
            not isinstance(catalogue_row, Mapping)
            or not isinstance(manifest_row, Mapping)
            or not isinstance(raw_binding, Mapping)
            or set(raw_binding) != binding_keys
        ):
            raise CapabilityRunnerError("private capsule task binding is invalid")
        board_id = raw_binding.get("board_id")
        task_id = raw_binding.get("task_id")
        assignment = raw_binding.get("assignment")
        resource_profile = raw_binding.get("resource_profile_id")
        if (
            type(board_id) is not int
            or board_id <= 0
            or board_id in board_ids
            or task_id != task.task_id
            or task_id in task_ids
            or type(assignment) is not str
            or _COMPONENT.fullmatch(assignment) is None
            or type(resource_profile) is not str
            or _COMPONENT.fullmatch(resource_profile) is None
            or task_id in excluded_ids
        ):
            raise CapabilityRunnerError("private capsule task binding is invalid")
        board_ids.add(board_id)
        task_ids.add(task.task_id)
        expected_contract = (
            task.task_id,
            task.family_id,
            task.category,
            task.tier,
            task.generator_version,
            task.checker_version,
            task.service_version,
        )
        observed_binding = tuple(
            raw_binding.get(name)
            for name in (
                "task_id",
                "family_id",
                "category",
                "tier",
                "generator_version",
                "checker_version",
                "service_version",
            )
        )
        if observed_binding != expected_contract:
            raise CapabilityRunnerError("private capsule contract binding changed")
        if tuple(
            catalogue_row.get(name)
            for name in (
                "board_id",
                "task_id",
                "category",
                "resource_profile_id",
                "generator_version",
                "checker_version",
                "service_version",
            )
        ) != (
            board_id,
            task.task_id,
            task.category,
            resource_profile,
            task.generator_version,
            task.checker_version,
            task.service_version,
        ):
            raise CapabilityRunnerError("private capsule catalogue binding changed")
        if tuple(
            manifest_row.get(name)
            for name in (
                "task_id",
                "family_id",
                "category",
                "assignment",
                "tier",
                "resource_profile_id",
                "generator_version",
                "checker_version",
                "service_version",
            )
        ) != (
            task.task_id,
            task.family_id,
            task.category,
            assignment,
            task.tier,
            resource_profile,
            task.generator_version,
            task.checker_version,
            task.service_version,
        ):
            raise CapabilityRunnerError("private capsule manifest binding changed")
        if (
            type(catalogue_row.get("description")) is not str
            or not isinstance(catalogue_row.get("files"), list)
            or raw_binding.get("description_commitment")
            != _canonical_sha256(catalogue_row["description"])
            or raw_binding.get("files_commitment") != _canonical_sha256(catalogue_row["files"])
        ):
            raise CapabilityRunnerError("private capsule content binding changed")
        task_binding = dict(raw_binding)
        task_commitment = task_binding.pop("task_commitment")
        if type(task_commitment) is not str or not hmac.compare_digest(
            task_commitment, _canonical_sha256(task_binding)
        ):
            raise CapabilityRunnerError("private capsule task commitment changed")
        offline_tasks.append(
            {
                "board_id": board_id,
                "task_id": task.task_id,
                "generator_version": task.generator_version,
                "checker_version": task.checker_version,
                "service_version": task.service_version,
            }
        )
    return tuple(offline_tasks)


def _validate_registry(
    registry: dict[str, object],
    contract: RunnerContract,
    configuration: dict[str, object],
    root: _PinnedDirectory,
) -> tuple[
    Mapping[str, object],
    tuple[Mapping[str, object], ...],
    tuple[_PinnedFile, ...],
]:
    if (
        set(registry)
        != {
            "schema",
            "registry_id",
            "public_configuration",
            "contract",
            "offline_task_registrations",
            "capsule_binding",
            "adapter",
        }
        or registry.get("schema") != PRIVATE_RUNTIME_REGISTRY_SCHEMA
    ):
        raise CapabilityRunnerError("private runtime registry shape is invalid")
    if (
        registry.get("registry_id") != configuration["registry_id"]
        or registry.get("public_configuration") != configuration
        or registry.get("contract") != _contract_binding(contract)
    ):
        raise CapabilityRunnerError("private runtime registration binding changed")
    capsule_files: tuple[_PinnedFile, ...] = ()
    try:
        capsule_files = (
            _pin_owner_only_file(
                root, _CATALOGUE_NAME, "private capsule catalogue", limit=_REGISTRY_LIMIT
            ),
            _pin_owner_only_file(
                root, _MANIFEST_NAME, "private capsule manifest", limit=_REGISTRY_LIMIT
            ),
        )
        capsule_tasks = _validate_capsule_binding(
            registry.get("capsule_binding"),
            _read_pinned_file(capsule_files[0], limit=_REGISTRY_LIMIT),
            _read_pinned_file(capsule_files[1], limit=_REGISTRY_LIMIT),
            contract,
            configuration,
        )
    except BaseException:
        for pinned in capsule_files:
            pinned.close()
        raise
    raw_offline_tasks = registry.get("offline_task_registrations")
    if not isinstance(raw_offline_tasks, list) or len(raw_offline_tasks) != len(contract.tasks):
        raise CapabilityRunnerError("private offline task registration is invalid")
    offline_tasks: list[Mapping[str, object]] = []
    board_ids: set[int] = set()
    for raw, task in zip(raw_offline_tasks, contract.tasks, strict=True):
        if not isinstance(raw, Mapping) or set(raw) != {
            "board_id",
            "task_id",
            "generator_version",
            "checker_version",
            "service_version",
        }:
            raise CapabilityRunnerError("private offline task registration is invalid")
        board_id = raw.get("board_id")
        if type(board_id) is not int or board_id <= 0 or board_id in board_ids:
            raise CapabilityRunnerError("private offline task registration is invalid")
        board_ids.add(board_id)
        if tuple(
            raw.get(name)
            for name in (
                "task_id",
                "generator_version",
                "checker_version",
                "service_version",
            )
        ) != (
            task.task_id,
            task.generator_version,
            task.checker_version,
            task.service_version,
        ):
            raise CapabilityRunnerError("private offline task registration binding changed")
        offline_tasks.append(dict(raw))
    adapter = registry.get("adapter")
    if not isinstance(adapter, Mapping) or set(adapter) != {"module", "sha256", "callable"}:
        raise CapabilityRunnerError("private runtime adapter registration is invalid")
    if (
        type(adapter["module"]) is not str
        or _COMPONENT.fullmatch(adapter["module"]) is None
        or not adapter["module"].endswith(".py")
        or type(adapter["callable"]) is not str
        or _COMPONENT.fullmatch(adapter["callable"]) is None
        or type(adapter["sha256"]) is not str
        or _SHA256.fullmatch(adapter["sha256"]) is None
    ):
        raise CapabilityRunnerError("private runtime adapter registration is invalid")
    if tuple(offline_tasks) != capsule_tasks:
        for pinned in capsule_files:
            pinned.close()
        raise CapabilityRunnerError("private capsule registration binding changed")
    return adapter, tuple(offline_tasks), capsule_files


def _load_adapter(
    root: Path, root_descriptor: int, adapter: Mapping[str, object]
) -> Callable[..., object]:
    module_name = adapter["module"]
    expected_digest = adapter["sha256"]
    callable_name = adapter["callable"]
    assert isinstance(module_name, str)
    assert isinstance(expected_digest, str)
    assert isinstance(callable_name, str)
    source = _owner_only_file(root_descriptor, module_name, limit=_ADAPTER_LIMIT)
    if hashlib.sha256(source).hexdigest() != expected_digest:
        raise CapabilityRunnerError("private runtime adapter digest changed")
    private_module_name = f"_rapido_private_runtime_{expected_digest}"
    module = types.ModuleType(private_module_name)
    module.__file__ = str(root / module_name)
    try:
        code = compile(source, module.__file__, "exec", dont_inherit=True)
        exec(code, module.__dict__)  # noqa: S102 - exact owner-only, digest-pinned adapter
    except BaseException as exc:  # private details stay inside the worker
        raise CapabilityRunnerError("private runtime adapter could not be loaded") from exc
    value = getattr(module, callable_name, None)
    if not callable(value) or inspect.iscoroutinefunction(value):
        raise CapabilityRunnerError("private runtime adapter callable is invalid")
    return value


def _path_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _resolved_boundary(path: Path) -> Path:
    if len(path.parts) >= 3 and path.parts[:3] == ("/", "dev", "fd"):
        return path.absolute()
    return path.resolve(strict=True)


def _resolve_boundary_or_fail(path: Path, label: str) -> Path:
    try:
        return _resolved_boundary(path)
    except (OSError, RuntimeError, ValueError):
        raise CapabilityRunnerError(f"{label} is unavailable") from None


def _resolve_public_boundary(path: Path, label: str) -> Path:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        raise CapabilityRunnerError(f"{label} is invalid") from None


def _owner_only_boundary(path: Path, label: str) -> None:
    _reject_symlink_components(path, label)
    try:
        metadata = path.lstat()
    except OSError:
        raise CapabilityRunnerError(f"{label} is unavailable") from None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o077
    ):
        raise CapabilityRunnerError(f"{label} is not owner-only")


def _validate_adapter_result(
    result: object,
    contract: RunnerContract,
    configuration: Mapping[str, object],
    runtime_root: Path,
    codex_home: Path | None,
    offline_task_registrations: tuple[Mapping[str, object], ...],
) -> tuple[
    RegisteredDurableRuntime,
    Callable[[], Awaitable[Mapping[str, object]]] | None,
]:
    if type(result) is not RegisteredDurableRuntime:
        raise CapabilityRunnerError("private runtime adapter returned an invalid registration")
    config = result.config
    if type(config) is not OfflineRuntimeConfig or not isinstance(result.board, OfflineBoard):
        raise CapabilityRunnerError("private runtime adapter returned an invalid runtime")
    if configuration["requires_provider_auth"] is True:
        if codex_home is None or config.codex_home != codex_home:
            raise CapabilityRunnerError("private runtime provider authentication binding changed")
    elif codex_home is not None:
        raise CapabilityRunnerError("model-free runtime unexpectedly received provider auth")
    if (
        config.offline_profile_id != configuration["offline_profile_id"]
        or config.catalogue_version != configuration["catalogue_version"]
        or config.board_implementation_version != configuration["board_implementation_version"]
        or config.runner_image != configuration["runner_image"]
        or float(config.run_seconds) != float(contract.scoring_seconds)
    ):
        raise CapabilityRunnerError("private runtime public configuration changed")
    frozen = tuple(
        (
            task.task_id,
            task.generator_version,
            task.checker_version,
            task.service_version,
        )
        for task in contract.tasks
    )
    observed = tuple(
        (
            task.task_id,
            task.generator_version,
            task.checker_version,
            task.service_version,
        )
        for task in config.task_registrations
    )
    if observed != frozen:
        raise CapabilityRunnerError("private runtime task registration changed")
    if tuple(task.public_record() for task in config.task_registrations) != (
        offline_task_registrations
    ):
        raise CapabilityRunnerError("private offline task registration changed")
    if any(
        not callable(getattr(result.runtime, name, None)) for name in ("start", "solve", "close")
    ) or any(
        not callable(port)
        for port in (result.evidence_source, result.cleanup, result.isolation_probe)
    ):
        raise CapabilityRunnerError("private runtime ports are invalid")
    roots = tuple(result.private_roots)
    if not roots:
        raise CapabilityRunnerError("private runtime roots are absent")
    normalized_root = _resolve_boundary_or_fail(runtime_root, "private runtime root")
    public_paths = (config.state_path, config.work_root, config.codex_home)
    resolved_public_paths = tuple(
        _resolve_public_boundary(path, "private runtime public path") for path in public_paths
    )
    if any(_path_overlap(normalized_root, path) for path in resolved_public_paths):
        raise CapabilityRunnerError("private runtime root overlaps a model-visible path")
    normalized_private: set[Path] = set()
    for path in roots:
        if not isinstance(path, Path) or not path.is_absolute():
            raise CapabilityRunnerError("private runtime roots are invalid")
        resolved = _resolve_boundary_or_fail(path, "private runtime isolation root")
        _owner_only_boundary(path, "private runtime isolation root")
        if resolved in normalized_private or not (
            resolved == normalized_root or normalized_root in resolved.parents
        ):
            raise CapabilityRunnerError("private runtime roots are not registry-bound")
        if any(_path_overlap(resolved, prior) for prior in normalized_private):
            raise CapabilityRunnerError("private runtime roots overlap")
        normalized_private.add(resolved)
    for resolved_public in resolved_public_paths:
        if any(_path_overlap(resolved_public, private) for private in normalized_private):
            raise CapabilityRunnerError("private runtime root overlaps a model-visible path")
    if normalized_root not in normalized_private:
        raise CapabilityRunnerError("private runtime registry root is not isolated")
    registration = result.board.registration_record()
    if registration != config.offline_board_registration():
        raise CapabilityRunnerError("offline Board registration changed")
    try:
        board_roots = {
            _resolve_boundary_or_fail(Path(path), "offline Board isolation root")
            for path in result.board.isolation_roots()
        }
    except (TypeError, ValueError):
        raise CapabilityRunnerError("offline Board isolation roots are invalid") from None
    if not board_roots or not board_roots <= normalized_private:
        raise CapabilityRunnerError("offline Board escaped the private runtime registry")
    owned_runtime_cleanup: Callable[[], Awaitable[Mapping[str, object]]] | None = None
    if configuration["requires_provider_auth"] is True:
        from .offline_run import _DockerRuntimeBoundary, _OfflineCodexClient

        if type(result.runtime) is not _OfflineCodexClient:
            raise CapabilityRunnerError("provider-auth runtime boundary is invalid")
        boundary = result.runtime._offline_boundary
        if type(boundary) is not _DockerRuntimeBoundary:
            raise CapabilityRunnerError("provider-auth runtime boundary is invalid")
        process_factory = result.runtime.process_factory
        if (
            boundary.codex_home != config.codex_home
            or boundary.workspace_root != config.work_root
            or boundary.image != config.runner_image
            or boundary.max_workspace_bytes != config.max_lane_workspace_bytes
            or {_resolved_boundary(path) for path in boundary.private_roots} != normalized_private
            or getattr(process_factory, "__self__", None) is not boundary
            or getattr(process_factory, "__func__", None)
            is not _DockerRuntimeBoundary.process_factory
            or result.runtime.env != offline_child_env(config)
            or result.runtime.binary != config.codex_binary
            or result.runtime.model != config.model
            or result.runtime.reasoning_effort != config.reasoning_effort
            or result.runtime.cwd != str(config.work_root)
            or result.runtime.max_workspace_bytes != config.max_lane_workspace_bytes
        ):
            raise CapabilityRunnerError("provider-auth runtime boundary binding changed")
        probe = result.isolation_probe
        if (
            getattr(probe, "__self__", None) is not boundary
            or getattr(probe, "__func__", None) is not _DockerRuntimeBoundary.verify
        ):
            raise CapabilityRunnerError("provider-auth isolation proof is not concrete")
        cleanup = getattr(boundary, "cleanup_record", None)
        if (
            getattr(cleanup, "__self__", None) is not boundary
            or getattr(cleanup, "__func__", None) is not _DockerRuntimeBoundary.cleanup_record
        ):
            raise CapabilityRunnerError("provider-auth cleanup proof is not concrete")
        owned_runtime_cleanup = cleanup
        if not result.board.is_process_isolated():
            raise CapabilityRunnerError("provider-auth runtime callbacks are not process isolated")
    if result.board.preflight() is not True:
        raise CapabilityRunnerError("offline Board preflight failed")
    return result, owned_runtime_cleanup


def registered_durable_flow_factory(
    contract: RunnerContract, configuration: Mapping[str, object]
) -> CapabilityFlow:
    """Resolve the digest-pinned private adapter from its worker-only root and digest envs."""

    assert_offline_environment()
    public_configuration = _public_configuration(configuration)
    raw_root = os.environ.get(PRIVATE_RUNTIME_ROOT_ENV)
    if raw_root is None:
        raise CapabilityRunnerError("private runtime root environment is absent")
    runtime_root = Path(raw_root)
    if not runtime_root.is_absolute():
        raise CapabilityRunnerError("private runtime root is not absolute")
    raw_codex_home = os.environ.get("CODEX_HOME")
    codex_home_source = Path(raw_codex_home) if raw_codex_home is not None else None
    if codex_home_source is not None and not codex_home_source.is_absolute():
        raise CapabilityRunnerError("provider authentication home is not absolute")
    expected_registry_digest = os.environ.get(PRIVATE_RUNTIME_REGISTRY_DIGEST_ENV)
    if expected_registry_digest is None:
        raise CapabilityRunnerError("private runtime registry commitment is absent")
    registry, pinned_root = _load_registry(runtime_root, expected_registry_digest)
    pinned_codex: _PinnedDirectory | None = None
    pinned_auth: _PinnedFile | None = None
    capsule_files: tuple[_PinnedFile, ...] = ()
    try:
        if public_configuration["requires_provider_auth"] is True:
            if codex_home_source is None:
                raise CapabilityRunnerError("provider authentication home is absent")
            pinned_codex = _pin_owner_only_directory(
                codex_home_source, "provider authentication home"
            )
            pinned_auth = _pin_owner_only_file(
                pinned_codex,
                "auth.json",
                "provider authentication file",
                limit=1_048_576,
            )
        elif codex_home_source is not None:
            raise CapabilityRunnerError("model-free runtime unexpectedly received provider auth")
        adapter_registration, offline_task_registrations, capsule_files = _validate_registry(
            registry, contract, public_configuration, pinned_root
        )
        adapter = _load_adapter(runtime_root, pinned_root.descriptor, adapter_registration)
        pinned_root.revalidate("private runtime root")
        result = adapter(
            contract,
            dict(public_configuration),
            runtime_root,
            codex_home_source,
        )
        pinned_root.revalidate("private runtime root")
        if pinned_codex is not None:
            pinned_codex.revalidate("provider authentication home")
        registration, owned_runtime_cleanup = _validate_adapter_result(
            result,
            contract,
            public_configuration,
            runtime_root,
            codex_home_source,
            offline_task_registrations,
        )
        flow = durable_job_control_flow(
            contract=contract,
            config=registration.config,
            board=registration.board,
            runtime=registration.runtime,
            evidence_source=registration.evidence_source,
            cleanup=registration.cleanup,
        )
        return _PinnedDurableFlow(
            flow,
            registration.isolation_probe,
            pinned_root,
            capsule_files,
            pinned_codex,
            pinned_auth,
            owned_runtime_cleanup,
        )
    except BaseException as exc:  # private details stay inside the worker
        if pinned_auth is not None:
            pinned_auth.close()
        if pinned_codex is not None:
            pinned_codex.close()
        for pinned in capsule_files:
            pinned.close()
        pinned_root.close()
        if isinstance(exc, CapabilityRunnerError):
            raise
        raise CapabilityRunnerError("private runtime adapter failed") from exc


__all__ = [
    "PRIVATE_RUNTIME_REGISTRY_DIGEST_ENV",
    "PRIVATE_RUNTIME_REGISTRY_SCHEMA",
    "PRIVATE_RUNTIME_ROOT_ENV",
    "RegisteredDurableRuntime",
    "registered_durable_flow_factory",
]
