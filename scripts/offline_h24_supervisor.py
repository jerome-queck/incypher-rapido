#!/usr/bin/env python3
"""Run the sealed offline H24 comparison and benign Board-contract soak.

The module deliberately owns Docker lifecycle only. The H24 runner owns private
fixture/oracle handling and scoring. All subprocesses use fixed argv; raw Docker
output is retained only in the private output directory.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import math
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from rapido.offline_h24_evaluation import (
    CLEANUP_GRACE_SECONDS,
    GLOBAL_SCORING_SECONDS,
    build_evaluation_receipt,
    evaluate_h24_receipt,
    preregistration_sha256,
    validate_preregistration,
    validate_source_image_registration,
)
from rapido.offline_h24_evaluation import (
    RECEIPT_SCHEMA as EVALUATION_RECEIPT_SCHEMA,
)

PREREGISTRATION_SCHEMA = "rapido-offline-h24-preregistration-v1"
DESCRIPTOR_SCHEMA = "rapido-offline-h24-descriptor-preflight-v1"
SUPERVISOR_SCHEMA = "rapido-offline-h24-supervisor-v1"
SCORING_SECONDS = GLOBAL_SCORING_SECONDS
CLEANUP_SECONDS = CLEANUP_GRACE_SECONDS
WORKER_DRAIN_SECONDS = 180
SAMPLE_TARGET_SECONDS = 5.0
CLEANUP_POLL_SECONDS = 10.0
OWNER_POLL_SECONDS = 0.25
OWNER_QUIET_SECONDS = 1.0
CREATE_RECONCILIATION_SECONDS = 5.0
OWNER_CLEANUP_SECONDS = 10.0
CONTAINER_UID = 10_001
CONTAINER_USER = "10001:10001"
H24_RECEIPT = "h24-receipt.json"
SOAK_RECEIPT = "soak-receipt.json"
DESCRIPTOR_RECEIPT = "descriptor-preflight.json"
SUPERVISOR_RECEIPT = "supervisor-receipt.json"
FINAL_RECEIPT = "h24-evaluation-receipt.json"
EVALUATION_RESULT = "h24-evaluation-result.json"
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_REFERENCE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
_BASE_REFERENCE = re.compile(r"(?:sha256:[0-9a-f]{64}|[^\s@]+@sha256:[0-9a-f]{64})\Z")
_RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
_CLOSED_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,95}\Z")
_CONTAINER_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}\Z")
_FORBIDDEN_ENV = frozenset(
    {
        "CTFD_URL",
        "CTFD_API_TOKEN",
        "TEAM_KEY",
        "RAPIDO_CTFD_URL",
        "RAPIDO_CTFD_API_TOKEN",
        "RAPIDO_TEAM_KEY",
    }
)
_CAPABILITY_FILES = frozenset({"config.toml", "config.json", "mcp.json"})
_H24_NAME = "rapido-h24-eval"
_SOAK_NAME = "rapido-h24-soak"
_SOURCE_PROBE_NAME = "rapido-h24-source-probe"
_OWNER_LABEL = "io.incypher.rapido.offline-h24-owner"
_ROLE_LABEL = "io.incypher.rapido.offline-h24-role"
_OWNER_TOKEN = re.compile(r"[0-9a-f]{64}\Z")
_ORACLE_ID = "rapido-offline-h24-oracle-v1"
_INSTALLED_RAPIDO = "/opt/venv/lib/python3.12/site-packages/rapido"
_WRAPPER_SOURCES = {
    "offline_oracle_pilot.py": Path("scripts/offline_oracle_pilot.py"),
    "board_contract_soak.py": Path("scripts/board_contract_soak.py"),
    "offline-h24-preregistration-v1.json": Path(
        "notes/research/offline-h24-preregistration-v1.json"
    ),
}


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class Runner(Protocol):
    def __call__(self, argv: Sequence[str], *, timeout: float | None = None) -> CommandResult: ...


class Clock(Protocol):
    def monotonic(self) -> float: ...

    def time(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def time(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def subprocess_runner(argv: Sequence[str], *, timeout: float | None = None) -> CommandResult:
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(124)
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True)
class Resources:
    cpus: int
    memory_gib: int
    pids: int


@dataclass(frozen=True)
class Protocol:
    protocol_id: str
    source_sha: str
    source_tree_sha: str
    image_reference: str
    image_id: str
    image_revision: str
    image_platform: str
    scoring_seconds: int
    barrier_delay_seconds: int
    h24_name: str
    soak_name: str
    h24: Resources
    soak: Resources
    cleanup_work: bool
    cleanup_seed: bool
    oracle_id: str
    registration_time: datetime | None
    preregistration: Mapping[str, object] = field(repr=False)
    registration: Mapping[str, object] = field(repr=False)


@dataclass(frozen=True)
class Paths:
    repository: Path
    preregistration: Path
    registration: Path
    auth: Path
    work: Path
    seed: Path
    output: Path


@dataclass(frozen=True)
class ImageIdentity:
    image_id: str
    reference: str
    revision: str
    source_revision: str
    platform: str


@dataclass
class ResourcePeak:
    cpu_percent: float | None = None
    rss_bytes: int | None = None
    pids: int | None = None
    oom_killed: bool | None = None
    samples: int = 0
    coverage_started_at: float | None = None
    coverage_ended_at: float | None = None
    last_observed_at: float | None = None
    max_observed_gap_seconds: float | None = None

    def start_coverage(self, observed_at: float) -> None:
        self.coverage_started_at = observed_at

    def _record_gap(self, observed_at: float) -> None:
        previous = self.last_observed_at
        if previous is None:
            previous = self.coverage_started_at
        if previous is not None and observed_at >= previous:
            gap = observed_at - previous
            self.max_observed_gap_seconds = max(self.max_observed_gap_seconds or 0.0, gap)

    def observe(self, row: Mapping[str, object], observed_at: float | None = None) -> None:
        cpu = _percent(row.get("CPUPerc"))
        rss = _memory_bytes(row.get("MemUsage"))
        pids = _integer(row.get("PIDs"))
        if cpu is not None:
            self.cpu_percent = max(self.cpu_percent or 0.0, cpu)
        if rss is not None:
            self.rss_bytes = max(self.rss_bytes or 0, rss)
        if pids is not None:
            self.pids = max(self.pids or 0, pids)
        self.samples += 1
        if observed_at is not None:
            self._record_gap(observed_at)
            self.last_observed_at = observed_at

    def end_coverage(self, observed_at: float) -> None:
        if self.coverage_ended_at is not None:
            return
        self.coverage_ended_at = observed_at
        if self.last_observed_at is not None:
            self._record_gap(observed_at)

    def coverage_complete(self) -> bool:
        return (
            self.coverage_started_at is not None
            and self.coverage_ended_at is not None
            and self.last_observed_at is not None
            and self.max_observed_gap_seconds is not None
        )

    def observation_status(self) -> str:
        values = (self.cpu_percent, self.rss_bytes, self.pids, self.oom_killed)
        if self.coverage_complete() and all(value is not None for value in values):
            return "observed"
        if all(value is None for value in values) and self.max_observed_gap_seconds is None:
            return "unavailable"
        return "partial"

    def public(self) -> dict[str, object]:
        return {
            "samples": self.samples,
            "peak_cpu_percent": self.cpu_percent,
            "peak_rss_bytes": self.rss_bytes,
            "peak_pids": self.pids,
            "oom_killed": self.oom_killed,
            "sample_interval_seconds": self.max_observed_gap_seconds,
            "coverage_complete": self.coverage_complete(),
            "observation_status": self.observation_status(),
        }


@dataclass
class EvaluationState:
    created: set[str] = field(default_factory=set)
    by_role: dict[str, str] = field(default_factory=dict)
    started: set[str] = field(default_factory=set)
    stopped: set[str] = field(default_factory=set)
    removed: set[str] = field(default_factory=set)
    ownership_ambiguous: bool = False
    create_outcome_unresolved: bool = False


@dataclass(frozen=True)
class ContainerIntent:
    name: str
    role: str
    image_id: str
    bind_mounts: tuple[tuple[Path, str, bool], ...]


@dataclass(frozen=True)
class AuthBaseline:
    directory_device: int
    directory_inode: int
    directory_owner: int
    directory_mode: int
    file_owner: int
    file_mode: int
    file_links: int
    required_keys: frozenset[str] = field(repr=False)


class SupervisorError(RuntimeError):
    """Closed supervisor failure; message must not carry private values."""

    def __init__(self, failure_class: str):
        if _CLOSED_ID.fullmatch(failure_class) is None:
            failure_class = "supervisor_failure"
        self.failure_class = failure_class
        super().__init__(failure_class)


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SupervisorError(label)
    return value


def _string(value: object, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise SupervisorError(label)
    return value


def _exact_int(value: object, expected: int, label: str) -> int:
    if type(value) is not int or value != expected:
        raise SupervisorError(label)
    return value


def _resource(value: object, expected: Resources, label: str) -> Resources:
    row = _mapping(value, label)
    if set(row) != {"cpus", "memory_gib", "pids"}:
        raise SupervisorError(label)
    return Resources(
        _exact_int(row.get("cpus"), expected.cpus, label),
        _exact_int(row.get("memory_gib"), expected.memory_gib, label),
        _exact_int(row.get("pids"), expected.pids, label),
    )


def load_protocol(path: Path) -> Protocol:
    """Load the deliberately narrow preregistration adapter.

    If the protocol lane changes its public layout, adapt only this function;
    lifecycle and receipt code consume the normalized Protocol value.
    """
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SupervisorError("preregistration_unreadable") from exc
    row = _mapping(value, "preregistration_invalid")
    try:
        validate_preregistration(row)
    except (TypeError, ValueError) as exc:
        raise SupervisorError("preregistration_invalid") from exc
    if row.get("schema") != PREREGISTRATION_SCHEMA:
        raise SupervisorError("preregistration_invalid")
    return Protocol(
        protocol_id=PREREGISTRATION_SCHEMA,
        source_sha="",
        source_tree_sha="",
        image_reference="",
        image_id="",
        image_revision="",
        image_platform="",
        scoring_seconds=_exact_int(
            row.get("global_scoring_seconds"), SCORING_SECONDS, "preregistration_invalid"
        ),
        barrier_delay_seconds=30,
        h24_name=_H24_NAME,
        soak_name=_SOAK_NAME,
        h24=Resources(10, 20, 256),
        soak=Resources(1, 2, 64),
        cleanup_work=True,
        cleanup_seed=True,
        oracle_id=_ORACLE_ID,
        registration_time=None,
        preregistration=dict(row),
        registration={},
    )


def bind_registration(path: Path, protocol: Protocol) -> Protocol:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SupervisorError("registration_unreadable") from exc
    row = _mapping(value, "registration_invalid")
    try:
        validated = validate_source_image_registration(row, protocol.preregistration)
    except (TypeError, ValueError) as exc:
        raise SupervisorError("registration_invalid") from exc
    source = _mapping(validated.get("source"), "registration_invalid")
    image = _mapping(validated.get("image"), "registration_invalid")
    source_sha = _string(source.get("commit_sha"), _SHA, "registration_invalid")
    source_tree = _string(source.get("tree_sha"), _SHA, "registration_invalid")
    image_id = _string(image.get("id"), _IMAGE_ID, "registration_invalid")
    image_platform = image.get("platform")
    if image_platform not in {"linux/amd64", "linux/arm64"}:
        raise SupervisorError("registration_invalid")
    assert isinstance(image_platform, str)
    registered_at = validated.get("registered_at_utc")
    if type(registered_at) is not str or _RFC3339_UTC.fullmatch(registered_at) is None:
        raise SupervisorError("registration_invalid")
    try:
        registration_time = datetime.fromisoformat(registered_at.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise SupervisorError("registration_invalid") from exc
    return replace(
        protocol,
        source_sha=source_sha,
        source_tree_sha=source_tree,
        image_reference=image_id,
        image_id=image_id,
        image_revision=source_sha,
        image_platform=image_platform,
        registration_time=registration_time,
        registration=dict(validated),
    )


def _run(
    runner: Runner, argv: Sequence[str], failure: str, *, timeout: float = 30
) -> CommandResult:
    result = runner(tuple(argv), timeout=timeout)
    if result.returncode != 0:
        raise SupervisorError(failure)
    return result


def _validate_registration_timing(protocol: Protocol, cutoff_epoch_seconds: float) -> None:
    registration_time = protocol.registration_time
    if (
        registration_time is None
        or registration_time.tzinfo is None
        or registration_time >= datetime.fromtimestamp(cutoff_epoch_seconds, tz=UTC)
    ):
        raise SupervisorError("registration_timing")


def validate_source(
    repository: Path, source_sha: str, source_tree_sha: str, runner: Runner
) -> None:
    head = _run(
        runner,
        ("git", "-C", str(repository), "rev-parse", "HEAD"),
        "source_identity",
    ).stdout.strip()
    if _SHA.fullmatch(head) is None or head != source_sha:
        raise SupervisorError("source_identity")
    tree = _run(
        runner,
        ("git", "-C", str(repository), "rev-parse", "HEAD^{tree}"),
        "source_identity",
    ).stdout.strip()
    if _SHA.fullmatch(tree) is None or tree != source_tree_sha:
        raise SupervisorError("source_identity")
    status = _run(
        runner,
        (
            "git",
            "-C",
            str(repository),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ),
        "source_status",
    ).stdout
    if status.strip():
        raise SupervisorError("source_dirty")


def inspect_image(protocol: Protocol, runner: Runner) -> ImageIdentity:
    result = _run(
        runner,
        (
            "docker",
            "image",
            "inspect",
            "--format={{json .}}",
            protocol.image_reference,
        ),
        "image_unavailable",
    )
    try:
        row = _mapping(json.loads(result.stdout), "image_identity")
    except json.JSONDecodeError as exc:
        raise SupervisorError("image_identity") from exc
    config = _mapping(row.get("Config"), "image_identity")
    labels = _mapping(config.get("Labels"), "image_identity")
    _string(labels.get("io.incypher.rapido.base-reference"), _BASE_REFERENCE, "image_identity")
    image_os = row.get("Os")
    architecture = row.get("Architecture")
    if (
        image_os != "linux"
        or architecture not in {"amd64", "arm64"}
        or config.get("User") != CONTAINER_USER
    ):
        raise SupervisorError("image_identity")
    assert isinstance(architecture, str)
    identity = ImageIdentity(
        _string(row.get("Id"), _IMAGE_ID, "image_identity"),
        protocol.image_reference,
        _string(labels.get("org.opencontainers.image.revision"), _SHA, "image_identity"),
        _string(labels.get("io.incypher.rapido.source-revision"), _SHA, "image_identity"),
        f"{image_os}/{architecture}",
    )
    if (
        identity.image_id != protocol.image_id
        or identity.revision != protocol.image_revision
        or identity.source_revision != protocol.source_sha
        or identity.platform != protocol.image_platform
    ):
        raise SupervisorError("image_identity")
    return identity


def _ownership_token() -> str:
    return secrets.token_hex(32)


def _validate_ownership_token(value: str) -> str:
    if _OWNER_TOKEN.fullmatch(value) is None:
        raise SupervisorError("container_identity")
    return value


def _owned_container_ids(ownership_token: str, runner: Runner, *, timeout: float = 30) -> set[str]:
    token = _validate_ownership_token(ownership_token)
    result = runner(
        (
            "docker",
            "ps",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"label={_OWNER_LABEL}={token}",
        ),
        timeout=timeout,
    )
    if result.returncode != 0:
        raise SupervisorError("docker_inventory")
    values = result.stdout.split()
    if len(values) != len(set(values)) or any(
        _CONTAINER_ID.fullmatch(value) is None for value in values
    ):
        raise SupervisorError("docker_inventory")
    return set(values)


def _inspect_container_intent(
    container_id: str,
    intent: ContainerIntent,
    ownership_token: str,
    runner: Runner,
    *,
    timeout: float = 30,
) -> None:
    if _CONTAINER_ID.fullmatch(container_id) is None:
        raise SupervisorError("container_identity")
    result = _run(
        runner,
        (
            "docker",
            "container",
            "inspect",
            "--format={{json .}}",
            container_id,
        ),
        "container_identity",
        timeout=timeout,
    )
    try:
        row = _mapping(json.loads(result.stdout), "container_identity")
    except json.JSONDecodeError as exc:
        raise SupervisorError("container_identity") from exc
    config = _mapping(row.get("Config"), "container_identity")
    labels = _mapping(config.get("Labels"), "container_identity")
    state = _mapping(row.get("State"), "container_identity")
    if (
        row.get("Id") != container_id
        or row.get("Name") != f"/{intent.name}"
        or row.get("Image") != intent.image_id
        or config.get("User") != CONTAINER_USER
        or labels.get(_OWNER_LABEL) != ownership_token
        or labels.get(_ROLE_LABEL) != intent.role
        or state.get("Running") is not False
    ):
        raise SupervisorError("container_identity")
    mounts = row.get("Mounts")
    if not isinstance(mounts, list):
        raise SupervisorError("container_identity")
    actual: dict[str, tuple[Path, bool]] = {}
    for value in mounts:
        mount = _mapping(value, "container_identity")
        if mount.get("Type") != "bind":
            raise SupervisorError("container_identity")
        source = mount.get("Source")
        destination = mount.get("Destination")
        writable = mount.get("RW")
        if type(source) is not str or type(destination) is not str or type(writable) is not bool:
            raise SupervisorError("container_identity")
        if destination in actual:
            raise SupervisorError("container_identity")
        actual[destination] = (Path(source), not writable)
    expected = {
        destination: (source, readonly) for source, destination, readonly in intent.bind_mounts
    }
    if actual != expected:
        raise SupervisorError("container_identity")


def _create_owned_container(
    argv: Sequence[str],
    intent: ContainerIntent,
    ownership_token: str,
    runner: Runner,
    state: EvaluationState,
    *,
    failure: str,
    timeout: float = 120,
    clock: Clock | None = None,
    deadline: float | None = None,
) -> str:
    clock = clock or SystemClock()
    operation_deadline = clock.monotonic() + timeout
    if deadline is not None:
        operation_deadline = min(operation_deadline, deadline)
    available = operation_deadline - clock.monotonic()
    reconciliation_reserve = min(CREATE_RECONCILIATION_SECONDS, available / 2)
    command_timeout = available - reconciliation_reserve
    if command_timeout <= 0:
        raise SupervisorError(failure)
    known = set(state.created)
    state.create_outcome_unresolved = True
    result = runner(tuple(argv), timeout=command_timeout)
    if clock.monotonic() >= operation_deadline:
        raise SupervisorError(failure)
    reconciliation_deadline = min(
        operation_deadline,
        clock.monotonic() + CREATE_RECONCILIATION_SECONDS,
    )
    inventory = _owned_container_ids(
        ownership_token,
        runner,
        timeout=min(30, max(reconciliation_deadline - clock.monotonic(), 0.001)),
    )
    new_ids = inventory - known
    while result.returncode != 0 and not new_ids and clock.monotonic() < reconciliation_deadline:
        remaining = reconciliation_deadline - clock.monotonic()
        if remaining <= 0:
            break
        clock.sleep(min(OWNER_POLL_SECONDS, remaining))
        inventory = _owned_container_ids(
            ownership_token,
            runner,
            timeout=min(30, max(reconciliation_deadline - clock.monotonic(), 0.001)),
        )
        new_ids = inventory - known
    state.created.update(new_ids)
    if len(new_ids) == 1:
        state.create_outcome_unresolved = False
    if clock.monotonic() >= operation_deadline:
        raise SupervisorError(failure)
    returned_id = result.stdout.strip()
    if len(new_ids) != 1:
        state.ownership_ambiguous = len(new_ids) > 1
        raise SupervisorError(failure if not new_ids else f"{failure}_ambiguous")
    container_id = next(iter(new_ids))
    if (
        result.returncode == 0
        and _CONTAINER_ID.fullmatch(returned_id) is not None
        and returned_id != container_id
    ):
        state.ownership_ambiguous = True
        raise SupervisorError(f"{failure}_ambiguous")
    _inspect_container_intent(
        container_id,
        intent,
        ownership_token,
        runner,
        timeout=min(30, operation_deadline - clock.monotonic()),
    )
    if clock.monotonic() >= operation_deadline:
        raise SupervisorError(failure)
    state.by_role[intent.role] = container_id
    return container_id


def _tracked_python_sources(repository: Path, runner: Runner) -> tuple[dict[str, bytes], set[str]]:
    result = _run(
        runner,
        ("git", "-C", str(repository), "ls-files", "-z", "--", "rapido"),
        "image_source_mismatch",
    )
    sources: dict[str, bytes] = {}
    directories = {""}
    try:
        for value in result.stdout.split("\0"):
            if not value:
                continue
            relative = Path(value)
            if relative.suffix != ".py":
                continue
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or relative.parts[:1] != ("rapido",)
            ):
                raise SupervisorError("image_source_mismatch")
            package_relative = Path(*relative.parts[1:])
            source = repository / relative
            metadata = source.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise SupervisorError("image_source_mismatch")
            key = package_relative.as_posix()
            sources[key] = source.read_bytes()
            parent = package_relative.parent
            while parent != Path("."):
                directories.add(parent.as_posix())
                parent = parent.parent
    except OSError as exc:
        raise SupervisorError("image_source_mismatch") from exc
    if not sources:
        raise SupervisorError("image_source_mismatch")
    return sources, directories


def _installed_python_sources(
    root: Path, expected_files: set[str], expected_directories: set[str]
) -> dict[str, bytes]:
    sources: dict[str, bytes] = {}
    seen_directories = {""}
    stack = [root]
    try:
        root_metadata = root.lstat()
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
            raise SupervisorError("image_source_mismatch")
        while stack:
            current = stack.pop()
            with os.scandir(current) as entries:
                for entry in entries:
                    metadata = entry.stat(follow_symlinks=False)
                    path = Path(entry.path)
                    relative = path.relative_to(root).as_posix()
                    if stat.S_ISLNK(metadata.st_mode):
                        raise SupervisorError("image_source_mismatch")
                    if stat.S_ISDIR(metadata.st_mode):
                        if relative not in expected_directories:
                            raise SupervisorError("image_source_mismatch")
                        seen_directories.add(relative)
                        stack.append(path)
                        continue
                    if not stat.S_ISREG(metadata.st_mode) or relative not in expected_files:
                        raise SupervisorError("image_source_mismatch")
                    sources[relative] = path.read_bytes()
    except OSError as exc:
        raise SupervisorError("image_source_mismatch") from exc
    if set(sources) != expected_files or seen_directories != expected_directories:
        raise SupervisorError("image_source_mismatch")
    return sources


def verify_image_source(
    protocol: Protocol,
    repository: Path,
    output: Path,
    runner: Runner,
    *,
    clock: Clock | None = None,
) -> None:
    """Compare installed image sources without executing image-provided code."""
    clock = clock or SystemClock()
    ownership_token = _ownership_token()
    state = EvaluationState()
    owned_container_id: str | None = None
    probe_root = Path(tempfile.mkdtemp(prefix=".rapido-image-source-", dir=output))
    probe_root.chmod(0o700)
    try:
        if not _container_absent(_SOURCE_PROBE_NAME, runner):
            raise SupervisorError("image_source_probe_in_use")
        argv = (
            "docker",
            "create",
            "--name",
            _SOURCE_PROBE_NAME,
            "--label",
            f"{_OWNER_LABEL}={ownership_token}",
            "--label",
            f"{_ROLE_LABEL}=source_probe",
            "--network",
            "none",
            "--read-only",
            "--user",
            CONTAINER_USER,
            "--entrypoint",
            "/bin/false",
            protocol.image_reference,
        )
        owned_container_id = _create_owned_container(
            argv,
            ContainerIntent(
                _SOURCE_PROBE_NAME,
                "source_probe",
                protocol.image_id,
                (),
            ),
            ownership_token,
            runner,
            state,
            failure="image_source_probe_create",
            clock=clock,
        )
        installed = probe_root / "rapido"
        _run(
            runner,
            ("docker", "cp", f"{owned_container_id}:{_INSTALLED_RAPIDO}", str(installed)),
            "image_source_probe_copy",
            timeout=120,
        )
        wrapper = probe_root / "wrapper"
        wrapper.mkdir(mode=0o700)
        for name in _WRAPPER_SOURCES:
            _run(
                runner,
                (
                    "docker",
                    "cp",
                    f"{owned_container_id}:/opt/rapido-eval/{name}",
                    str(wrapper / name),
                ),
                "image_source_probe_copy",
                timeout=30,
            )
        expected_sources, expected_directories = _tracked_python_sources(repository, runner)
        installed_sources = _installed_python_sources(
            installed,
            set(expected_sources),
            expected_directories,
        )
        if installed_sources != expected_sources:
            raise SupervisorError("image_source_mismatch")
        for name, relative in _WRAPPER_SOURCES.items():
            copied = wrapper / name
            metadata = copied.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or copied.read_bytes() != (repository / relative).read_bytes()
            ):
                raise SupervisorError("image_source_mismatch")
    except OSError as exc:
        raise SupervisorError("image_source_mismatch") from exc
    finally:
        cleanup_failed = not _cleanup_owned_containers(
            ownership_token,
            state,
            runner,
            clock,
            clock.monotonic() + OWNER_CLEANUP_SECONDS,
        )
        try:
            shutil.rmtree(probe_root)
        except OSError:
            cleanup_failed = True
        if cleanup_failed and not state.create_outcome_unresolved:
            raise SupervisorError("image_source_probe_cleanup")
    if state.ownership_ambiguous:
        raise SupervisorError("container_ownership_ambiguous")


def validate_host_budget(runner: Runner) -> None:
    result = _run(
        runner,
        ("docker", "info", "--format={{json .}}"),
        "host_budget_unavailable",
    )
    try:
        row = _mapping(json.loads(result.stdout), "host_budget_invalid")
    except json.JSONDecodeError as exc:
        raise SupervisorError("host_budget_invalid") from exc
    cpus = row.get("NCPU")
    memory = row.get("MemTotal")
    if type(cpus) is not int or cpus < 12 or type(memory) is not int or memory < 24 * 1024**3:
        raise SupervisorError("host_budget_invalid")


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        result = path.lstat()
    except OSError as exc:
        raise SupervisorError(label) from exc
    if stat.S_ISLNK(result.st_mode):
        raise SupervisorError(label)
    return result


def _private_directory(path: Path, label: str, owner_uid: int) -> Path:
    metadata = _lstat(path, label)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SupervisorError(label)
    if metadata.st_uid != owner_uid:
        raise SupervisorError(label)
    return path.resolve(strict=True)


def _private_file(path: Path, label: str, owner_uid: int) -> Path:
    metadata = _lstat(path, label)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SupervisorError(label)
    if metadata.st_uid != owner_uid or metadata.st_nlink != 1:
        raise SupervisorError(label)
    return path.resolve(strict=True)


def _auth_baseline(auth: Path) -> AuthBaseline:
    directory_fd: int | None = None
    auth_fd: int | None = None
    try:
        directory_fd = os.open(
            auth,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        directory = os.fstat(directory_fd)
        auth_fd = os.open(
            "auth.json",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        file_metadata = os.fstat(auth_fd)
        for name in _CAPABILITY_FILES:
            try:
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise SupervisorError("auth_integrity")
        with os.fdopen(auth_fd, encoding="utf-8") as stream:
            auth_fd = None
            document = json.load(stream)
        path_file_metadata = os.stat("auth.json", dir_fd=directory_fd, follow_symlinks=False)
        path_directory_metadata = os.stat(auth, follow_symlinks=False)
        for name in _CAPABILITY_FILES:
            try:
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise SupervisorError("auth_integrity")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SupervisorError("auth_integrity") from exc
    finally:
        if auth_fd is not None:
            os.close(auth_fd)
        if directory_fd is not None:
            os.close(directory_fd)
    if (
        not stat.S_ISDIR(directory.st_mode)
        or stat.S_IMODE(directory.st_mode) != 0o700
        or not stat.S_ISREG(file_metadata.st_mode)
        or stat.S_IMODE(file_metadata.st_mode) != 0o600
        or file_metadata.st_uid != directory.st_uid
        or file_metadata.st_nlink != 1
        or (path_file_metadata.st_dev, path_file_metadata.st_ino)
        != (file_metadata.st_dev, file_metadata.st_ino)
        or (path_directory_metadata.st_dev, path_directory_metadata.st_ino)
        != (directory.st_dev, directory.st_ino)
        or not isinstance(document, Mapping)
        or not document
        or any(type(key) is not str for key in document)
    ):
        raise SupervisorError("auth_integrity")
    return AuthBaseline(
        directory.st_dev,
        directory.st_ino,
        directory.st_uid,
        stat.S_IMODE(directory.st_mode),
        file_metadata.st_uid,
        stat.S_IMODE(file_metadata.st_mode),
        file_metadata.st_nlink,
        frozenset(document),
    )


def _auth_matches_baseline(auth: Path, baseline: AuthBaseline) -> bool:
    try:
        observed = _auth_baseline(auth)
    except SupervisorError:
        return False
    return (
        observed.directory_device == baseline.directory_device
        and observed.directory_inode == baseline.directory_inode
        and observed.directory_owner == baseline.directory_owner
        and observed.directory_mode == baseline.directory_mode
        and observed.file_owner == baseline.file_owner
        and observed.file_mode == baseline.file_mode
        and observed.file_links == baseline.file_links
        and observed.required_keys >= baseline.required_keys
    )


def _public_contract_file(path: Path, label: str, *, immutable: bool) -> Path:
    metadata = _lstat(path, label)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= 128 * 1024
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or (immutable and stat.S_IMODE(metadata.st_mode) & 0o222)
    ):
        raise SupervisorError(label)
    return path.resolve(strict=True)


def _overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def validate_paths(
    paths: Paths,
    *,
    owner_uid: int = CONTAINER_UID,
    allowed_output_names: frozenset[str] = frozenset(),
    require_seed: bool = True,
) -> Paths:
    repository = paths.repository.resolve(strict=True)
    preregistration = _public_contract_file(
        paths.preregistration, "preregistration_file_invalid", immutable=False
    )
    registration = _public_contract_file(
        paths.registration, "registration_file_invalid", immutable=True
    )
    auth = _private_directory(paths.auth, "auth_invalid", owner_uid)
    work = _private_directory(paths.work, "work_invalid", owner_uid)
    output = _private_directory(paths.output, "output_invalid", owner_uid)
    seed = _private_file(paths.seed, "seed_invalid", owner_uid) if require_seed else paths.seed
    auth_file = _private_file(auth / "auth.json", "auth_invalid", owner_uid)
    del auth_file
    for name in _CAPABILITY_FILES:
        if (auth / name).exists() or (auth / name).is_symlink():
            raise SupervisorError("auth_capability_file")
    private = (auth, work, output, *((seed,) if require_seed else ()))
    for index, first in enumerate(private):
        for second in private[index + 1 :]:
            if _overlap(first, second):
                raise SupervisorError("private_path_overlap")
    if any(_overlap(repository, path) for path in private):
        raise SupervisorError("repository_path_overlap")
    if require_seed and (seed.stat().st_size < 32 or seed.stat().st_size > 4096):
        raise SupervisorError("seed_invalid")
    output_names = {item.name for item in output.iterdir()}
    if any(work.iterdir()) or not output_names <= allowed_output_names:
        raise SupervisorError("fresh_directory_required")
    return Paths(repository, preregistration, registration, auth, work, seed, output)


def validate_environment(environment: Mapping[str, str]) -> None:
    if any(name in environment for name in _FORBIDDEN_ENV):
        raise SupervisorError("board_environment_present")


def _mount(source: Path, target: str, *, readonly: bool = False) -> str:
    fields = ["type=bind", f"src={source}", f"dst={target}"]
    if readonly:
        fields.append("readonly")
    return ",".join(fields)


def _hardened_create_prefix(
    name: str, resource: Resources, *, ownership_token: str, role: str
) -> list[str]:
    token = _validate_ownership_token(ownership_token)
    if _CLOSED_ID.fullmatch(role) is None:
        raise SupervisorError("container_identity")
    return [
        "docker",
        "create",
        "--name",
        name,
        "--label",
        f"{_OWNER_LABEL}={token}",
        "--label",
        f"{_ROLE_LABEL}={role}",
        "--stop-timeout",
        str(CLEANUP_SECONDS),
        "--cpus",
        str(resource.cpus),
        "--memory",
        f"{resource.memory_gib}g",
        "--pids-limit",
        str(resource.pids),
        "--user",
        CONTAINER_USER,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
    ]


def descriptor_preflight_argv(
    protocol: Protocol, paths: Paths, *, ownership_token: str
) -> tuple[str, ...]:
    name = f"{protocol.h24_name}-descriptor"
    argv = _hardened_create_prefix(
        name, protocol.h24, ownership_token=ownership_token, role="descriptor"
    )
    argv.extend(
        [
            "--mount",
            _mount(paths.auth, "/auth/codex"),
            "--mount",
            _mount(paths.work, "/work"),
            "--mount",
            _mount(paths.output, "/output"),
            "--mount",
            _mount(
                paths.preregistration, "/run/rapido-protocol/preregistration.json", readonly=True
            ),
            "--env",
            f"RAPIDO_IMAGE_ID={protocol.image_id}",
            "--entrypoint",
            "/opt/venv/bin/python",
            protocol.image_reference,
            "/opt/rapido-eval/offline_oracle_pilot.py",
            "--experiment",
            "h24",
            "--descriptor-preflight",
            "--h24-preregistration-file",
            "/run/rapido-protocol/preregistration.json",
            "--codex-binary",
            "codex",
            "--codex-home",
            "/auth/codex",
            "--work-root",
            "/work",
            "--source-sha",
            protocol.source_sha,
            "--image-id",
            protocol.image_id,
            "--output-file",
            f"/output/{DESCRIPTOR_RECEIPT}",
        ]
    )
    return tuple(argv)


def h24_create_argv(
    protocol: Protocol,
    paths: Paths,
    *,
    ownership_token: str,
    start_wall_epoch_milliseconds: int | None = None,
) -> tuple[str, ...]:
    argv = _hardened_create_prefix(
        protocol.h24_name, protocol.h24, ownership_token=ownership_token, role="h24"
    )
    argv.extend(
        [
            "--mount",
            _mount(paths.auth, "/auth/codex"),
            "--mount",
            _mount(paths.work, "/work"),
            "--mount",
            _mount(paths.output, "/output"),
            "--mount",
            _mount(paths.seed, "/seed/oracle.key", readonly=True),
            "--mount",
            _mount(
                paths.preregistration, "/run/rapido-protocol/preregistration.json", readonly=True
            ),
            "--env",
            f"RAPIDO_IMAGE_ID={protocol.image_id}",
            "--entrypoint",
            "/opt/venv/bin/python",
            protocol.image_reference,
            "/opt/rapido-eval/offline_oracle_pilot.py",
            "--experiment",
            "h24",
            "--h24-preregistration-file",
            "/run/rapido-protocol/preregistration.json",
            "--codex-binary",
            "codex",
            "--codex-home",
            "/auth/codex",
            "--work-root",
            "/work",
            "--oracle-key-file",
            "/seed/oracle.key",
            "--oracle-id",
            protocol.oracle_id,
            "--source-sha",
            protocol.source_sha,
            "--image-id",
            protocol.image_id,
            "--output-file",
            f"/output/{H24_RECEIPT}",
        ]
    )
    if start_wall_epoch_milliseconds is not None:
        argv.extend(
            [
                "--start-at-unix-ms",
                str(start_wall_epoch_milliseconds),
            ]
        )
    return tuple(argv)


def soak_create_argv(
    protocol: Protocol,
    paths: Paths,
    *,
    ownership_token: str,
    start_wall_epoch_milliseconds: int | None = None,
) -> tuple[str, ...]:
    argv = _hardened_create_prefix(
        protocol.soak_name, protocol.soak, ownership_token=ownership_token, role="soak"
    )
    argv.extend(
        [
            "--network",
            "none",
            "--mount",
            _mount(paths.output, "/output"),
            "--mount",
            _mount(
                paths.preregistration, "/run/rapido-protocol/preregistration.json", readonly=True
            ),
            "--entrypoint",
            "/opt/venv/bin/python",
            protocol.image_reference,
            "/opt/rapido-eval/board_contract_soak.py",
            "--duration-seconds",
            str(protocol.scoring_seconds),
            "--output",
            f"/output/{SOAK_RECEIPT}",
        ]
    )
    if start_wall_epoch_milliseconds is not None:
        argv.extend(
            [
                "--start-at-unix-ms",
                str(start_wall_epoch_milliseconds),
            ]
        )
    return tuple(argv)


def _container_absent(name: str, runner: Runner, *, timeout: float = 30) -> bool:
    result = runner(
        (
            "docker",
            "ps",
            "--all",
            "--filter",
            f"name=^/{name}$",
            "--format={{.Names}}",
        ),
        timeout=timeout,
    )
    if result.returncode != 0:
        raise SupervisorError("docker_inventory")
    return not result.stdout.strip()


def _container_id_absent(container_id: str, runner: Runner, *, timeout: float = 30) -> bool:
    if _CONTAINER_ID.fullmatch(container_id) is None:
        raise SupervisorError("image_source_probe_identity")
    result = runner(
        (
            "docker",
            "ps",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"id={container_id}",
        ),
        timeout=timeout,
    )
    if result.returncode != 0:
        raise SupervisorError("docker_inventory")
    values = result.stdout.split()
    if any(value != container_id for value in values):
        raise SupervisorError("docker_inventory")
    return not values


def _validate_container_absence(protocol: Protocol, runner: Runner) -> None:
    for name in (
        protocol.h24_name,
        protocol.soak_name,
        f"{protocol.h24_name}-descriptor",
        _SOURCE_PROBE_NAME,
    ):
        if not _container_absent(name, runner):
            raise SupervisorError("container_name_in_use")


def _validate_auth_unmounted(auth: Path, runner: Runner) -> None:
    inventory = _run(
        runner,
        ("docker", "ps", "--all", "--quiet"),
        "docker_inventory",
    ).stdout.split()
    for container_id in inventory:
        if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            raise SupervisorError("docker_inventory")
        result = _run(
            runner,
            ("docker", "container", "inspect", "--format={{json .Mounts}}", container_id),
            "docker_inventory",
        )
        try:
            mounts = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SupervisorError("docker_inventory") from exc
        if not isinstance(mounts, list):
            raise SupervisorError("docker_inventory")
        for mount in mounts:
            if isinstance(mount, Mapping) and mount.get("Source") == str(auth):
                raise SupervisorError("auth_already_mounted")


@contextlib.contextmanager
def auth_lease(auth: Path) -> Iterator[None]:
    name = ".offline-h24-supervisor.lock"
    directory_descriptor: int | None = None
    descriptor: int | None = None
    lock_metadata: os.stat_result | None = None
    acquired = False
    remove_created = False
    integrity_failed = False
    try:
        try:
            directory_descriptor = os.open(
                auth,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            directory_metadata = os.fstat(directory_descriptor)
            if (
                not stat.S_ISDIR(directory_metadata.st_mode)
                or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            ):
                raise SupervisorError("auth_lease_invalid")
            try:
                descriptor = os.open(
                    name,
                    os.O_CREAT
                    | os.O_EXCL
                    | os.O_CLOEXEC
                    | os.O_RDWR
                    | os.O_NOFOLLOW
                    | os.O_NONBLOCK,
                    0o600,
                    dir_fd=directory_descriptor,
                )
                remove_created = True
            except FileExistsError:
                descriptor = os.open(
                    name,
                    os.O_CLOEXEC | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=directory_descriptor,
                )
            lock_metadata = os.fstat(descriptor)
            path_metadata = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except SupervisorError:
            raise
        except OSError as exc:
            raise SupervisorError("auth_lease_invalid") from exc
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or stat.S_IMODE(lock_metadata.st_mode) != 0o600
            or lock_metadata.st_uid != directory_metadata.st_uid
            or lock_metadata.st_nlink != 1
            or (path_metadata.st_dev, path_metadata.st_ino)
            != (lock_metadata.st_dev, lock_metadata.st_ino)
        ):
            raise SupervisorError("auth_lease_invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            remove_created = False
            raise SupervisorError("auth_lease_busy") from exc
        except OSError as exc:
            remove_created = False
            raise SupervisorError("auth_lease_invalid") from exc
        acquired = True
        remove_created = False
        yield
    finally:
        if (
            (acquired or remove_created)
            and directory_descriptor is not None
            and lock_metadata is not None
        ):
            try:
                observed = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                current = os.fstat(descriptor) if descriptor is not None else lock_metadata
                if (
                    not stat.S_ISREG(observed.st_mode)
                    or stat.S_IMODE(observed.st_mode) != 0o600
                    or observed.st_uid != lock_metadata.st_uid
                    or observed.st_nlink != 1
                    or current.st_nlink != 1
                    or (observed.st_dev, observed.st_ino)
                    != (lock_metadata.st_dev, lock_metadata.st_ino)
                ):
                    integrity_failed = True
                else:
                    os.unlink(name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                integrity_failed = True
            except OSError:
                integrity_failed = True
        if acquired and descriptor is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        if integrity_failed:
            raise SupervisorError("auth_lease_integrity")


def _container_state(name: str, runner: Runner, *, timeout: float = 30) -> dict[str, object]:
    result = _run(
        runner,
        (
            "docker",
            "container",
            "inspect",
            "--format={{json .State}}",
            name,
        ),
        "container_inspect",
        timeout=timeout,
    )
    try:
        row = _mapping(json.loads(result.stdout), "container_inspect")
    except json.JSONDecodeError as exc:
        raise SupervisorError("container_inspect") from exc
    return dict(row)


def _sample(
    containers: Mapping[str, str],
    runner: Runner,
    peaks: Mapping[str, ResourcePeak],
    *,
    clock: Clock | None = None,
    deadline: float | None = None,
    timeout: float = 30,
) -> None:
    if not containers:
        return
    result = runner(
        (
            "docker",
            "stats",
            "--no-stream",
            "--no-trunc",
            "--format={{json .}}",
            *containers,
        ),
        timeout=timeout,
    )
    if result.returncode != 0:
        return
    observed_at = clock.monotonic() if clock is not None else None
    if deadline is not None and observed_at is not None and observed_at > deadline:
        return
    for line in result.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, Mapping):
            continue
        container_id = row.get("ID")
        name = containers.get(container_id) if isinstance(container_id, str) else None
        if name is not None:
            peaks[name].observe(row, observed_at)


def _percent(value: object) -> float | None:
    if not isinstance(value, str) or not value.endswith("%"):
        return None
    try:
        parsed = float(value[:-1])
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) and parsed >= 0 else None


def _memory_bytes(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    first = value.split("/", 1)[0].strip()
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?i?B)", first, re.IGNORECASE)
    if match is None:
        return None
    units = {
        "B": 1,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
        "KIB": 1024,
        "MIB": 1024**2,
        "GIB": 1024**3,
        "TIB": 1024**4,
    }
    return int(float(match.group(1)) * units[match.group(2).upper()])


def _integer(value: object) -> int | None:
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _atomic_private_write(path: Path, data: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def _retain_logs(
    name: str, role: str, output: Path, runner: Runner, *, timeout: float = 30
) -> None:
    result = runner(("docker", "logs", name), timeout=timeout)
    _atomic_private_write(
        output / f"{role}.docker.log",
        result.stdout + ("\n[stderr]\n" + result.stderr if result.stderr else ""),
    )


def _receipt_projection(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"present": False, "schema": None, "parse_status": "missing"}
    try:
        metadata = path.lstat()
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"present": True, "schema": None, "parse_status": "invalid"}
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not isinstance(value, Mapping)
    ):
        return {"present": True, "schema": None, "parse_status": "invalid"}
    schema = value.get("schema")
    if type(schema) is not str or _CLOSED_ID.fullmatch(schema) is None:
        schema = None
    return {"present": True, "schema": schema, "parse_status": "parsed" if schema else "invalid"}


def _load_private_json(path: Path, label: str) -> Mapping[str, object]:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        with os.fdopen(descriptor, encoding="utf-8") as stream:
            descriptor = None
            value = json.load(stream)
        path_metadata = path.lstat()
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SupervisorError(label) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or (path_metadata.st_dev, path_metadata.st_ino) != (metadata.st_dev, metadata.st_ino)
        or not isinstance(value, Mapping)
    ):
        raise SupervisorError(label)
    return value


def validate_descriptor_receipt(protocol: Protocol, path: Path) -> list[dict[str, object]]:
    row = _load_private_json(path, "preflight_receipt")
    expected_source = {
        "observed": {
            "head_sha": protocol.source_sha,
            "worktree": "packaged_source",
            "tracked_change_count": None,
            "untracked_file_count": None,
        },
        "declared": {"sha": protocol.source_sha},
        "declared_matches_head": True,
        "identity_basis": "sealed_metadata_file",
    }
    expected_image = {
        "observed": {"id": protocol.image_id},
        "declared": {"id": protocol.image_id},
        "declared_matches_observed": True,
    }
    expected_fields = {
        "schema",
        "preregistration_sha256",
        "source",
        "image",
        "descriptors",
        "matched",
    }
    descriptors = row.get("descriptors")
    if (
        set(row) != expected_fields
        or row.get("schema") != DESCRIPTOR_SCHEMA
        or row.get("preregistration_sha256") != preregistration_sha256(protocol.preregistration)
        or row.get("source") != expected_source
        or row.get("image") != expected_image
        or row.get("matched") is not True
        or descriptors != protocol.preregistration.get("descriptor_preflight")
        or not isinstance(descriptors, list)
        or len(descriptors) != 2
    ):
        raise SupervisorError("preflight_receipt")
    allowed = {
        "arm",
        "returned_model",
        "returned_effort",
        "revision",
        "revision_status",
    }
    closed: list[dict[str, object]] = []
    for descriptor in descriptors:
        item = _mapping(descriptor, "preflight_receipt")
        if set(item) != allowed:
            raise SupervisorError("preflight_receipt")
        closed.append({key: item[key] for key in sorted(allowed)})
    return closed


def _runtime_resources(peak: ResourcePeak) -> dict[str, object]:
    return {
        "observation_status": peak.observation_status(),
        "sample_interval_seconds": peak.max_observed_gap_seconds,
        "peak_cpu_percent": peak.cpu_percent,
        "peak_rss_bytes": peak.rss_bytes,
        "peak_pids": peak.pids,
        "oom_killed": peak.oom_killed,
    }


def _soak_cleanup_facts(soak: Mapping[str, object]) -> tuple[int, int, int]:
    scenarios = soak.get("scenarios")
    if not isinstance(scenarios, list):
        raise SupervisorError("soak_receipt_invalid")
    for value in scenarios:
        if isinstance(value, Mapping) and value.get("scenario_id") == "deadline_cancel_cleanup":
            facts = value.get("facts")
            if not isinstance(facts, Mapping):
                break
            owned = _integer(facts.get("owned_instances"))
            pending = _integer(facts.get("pending_writes"))
            workspace = _integer(facts.get("workspace_entries"))
            if owned is None or pending is None or workspace is None:
                break
            return owned, pending, workspace
    raise SupervisorError("soak_receipt_invalid")


def _utc_from_unix_milliseconds(value: int) -> str:
    return (
        datetime.fromtimestamp(value / 1000, tz=UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def finalize_evaluation(
    protocol: Protocol,
    paths: Paths,
    *,
    barrier: Mapping[str, object],
    h24_peak: ResourcePeak,
    cleanup_started_offset_milliseconds: int,
    cleanup_elapsed_milliseconds: int,
    containers_absent: bool,
    cleanup_completed: bool,
    workspace_residue_bytes: int,
) -> tuple[dict[str, object], dict[str, object]]:
    """Join only sanitized receipts, validate the exact envelope, and persist it privately."""
    raw_h24 = _load_private_json(paths.output / H24_RECEIPT, "h24_receipt_invalid")
    soak = _load_private_json(paths.output / SOAK_RECEIPT, "soak_receipt_invalid")
    registration = protocol.registration
    owned, pending, workspace_entries = _soak_cleanup_facts(soak)
    if workspace_entries != 0:
        raise SupervisorError("cleanup_observation_incomplete")
    cleanup = {
        "started_offset_milliseconds": max(0, cleanup_started_offset_milliseconds),
        "elapsed_milliseconds": max(0, cleanup_elapsed_milliseconds),
        "completed": cleanup_completed,
        "orphan_process_count": 0 if containers_absent else 1,
        "fake_instance_count": owned,
        "pending_write_count": pending,
        "workspace_residue_bytes": workspace_residue_bytes,
        "privacy_scan_passed": False,
        "source_database_mutation_detected": False,
    }
    start = barrier.get("start_wall_epoch_milliseconds")
    if not isinstance(start, int):
        raise SupervisorError("start_barrier_invalid")
    arguments = {
        "preregistration": protocol.preregistration,
        "registration": registration,
        "raw_h24": raw_h24,
        "soak": soak,
        "barrier": barrier,
        "runtime_resources": _runtime_resources(h24_peak),
        "cleanup": cleanup,
        "run_started_at_utc": _utc_from_unix_milliseconds(start),
        "scoring_elapsed_milliseconds": protocol.scoring_seconds * 1000,
    }
    try:
        preliminary = build_evaluation_receipt(**arguments)
    except (TypeError, ValueError) as exc:
        raise SupervisorError("evaluation_assembly") from exc
    encoded = json.dumps(preliminary, sort_keys=True, separators=(",", ":"))
    forbidden = [str(paths.repository), str(paths.auth), str(paths.work), str(paths.seed)]
    forbidden.extend(
        value
        for key, value in os.environ.items()
        if key in _FORBIDDEN_ENV and isinstance(value, str) and value
    )
    if any(value in encoded for value in forbidden):
        raise SupervisorError("privacy_scan")
    cleanup["privacy_scan_passed"] = True
    arguments["cleanup"] = cleanup
    try:
        final = build_evaluation_receipt(**arguments)
        evaluation = evaluate_h24_receipt(protocol.preregistration, final)
    except (TypeError, ValueError) as exc:
        raise SupervisorError("evaluation_assembly") from exc
    if final.get("schema") != EVALUATION_RECEIPT_SCHEMA:
        raise SupervisorError("evaluation_assembly")
    try:
        _atomic_private_write(
            paths.output / FINAL_RECEIPT,
            json.dumps(final, sort_keys=True, separators=(",", ":")) + "\n",
        )
        _atomic_private_write(
            paths.output / EVALUATION_RESULT,
            json.dumps(evaluation, sort_keys=True, separators=(",", ":")) + "\n",
        )
    except OSError as exc:
        raise SupervisorError("evaluation_persistence") from exc
    return final, evaluation


def _remaining_timeout(clock: Clock, deadline: float, maximum: float = 30) -> float | None:
    remaining = deadline - clock.monotonic()
    return min(maximum, remaining) if remaining > 0 else None


def _remove_container(
    container_id: str,
    runner: Runner,
    state: EvaluationState,
    *,
    clock: Clock | None = None,
    deadline: float | None = None,
) -> None:
    timeout = (
        _remaining_timeout(clock, deadline) if clock is not None and deadline is not None else 30
    )
    if timeout is None:
        raise SupervisorError("cleanup_timeout")
    result = runner(("docker", "rm", "--volumes", container_id), timeout=timeout)
    if result.returncode == 0:
        state.removed.add(container_id)
        return
    timeout = (
        _remaining_timeout(clock, deadline) if clock is not None and deadline is not None else 30
    )
    if timeout is not None and _container_id_absent(container_id, runner, timeout=timeout):
        state.removed.add(container_id)
        return
    raise SupervisorError("container_remove")


def _cleanup_owned_containers(
    ownership_token: str,
    state: EvaluationState,
    runner: Runner,
    clock: Clock,
    deadline: float,
) -> bool:
    cleanup_deadline = deadline
    if state.create_outcome_unresolved:
        # An empty inventory cannot prove a timed-out create never reached the daemon.
        # Exhaust the bounded owner window and refuse a clean attestation even if empty.
        cleanup_deadline = min(deadline, clock.monotonic() + OWNER_CLEANUP_SECONDS)
    cleanup_failed = False
    quiet_since: float | None = None
    while clock.monotonic() < cleanup_deadline:
        timeout = _remaining_timeout(clock, cleanup_deadline)
        if timeout is None:
            break
        try:
            inventory = _owned_container_ids(ownership_token, runner, timeout=timeout)
        except SupervisorError:
            cleanup_failed = True
            inventory = set()
        if clock.monotonic() > cleanup_deadline:
            return False
        discovered = inventory - state.created
        if discovered:
            state.created.update(discovered)
            state.ownership_ambiguous = True
        if inventory:
            quiet_since = None
            iteration_failed = False
            for container_id in sorted(inventory):
                try:
                    timeout = _remaining_timeout(clock, cleanup_deadline)
                    if timeout is None:
                        cleanup_failed = True
                        iteration_failed = True
                        break
                    container = _container_state(container_id, runner, timeout=timeout)
                    if container.get("Running") is True:
                        timeout = _remaining_timeout(clock, cleanup_deadline)
                        if timeout is None:
                            cleanup_failed = True
                            iteration_failed = True
                            break
                        result = runner(
                            ("docker", "stop", "--time", "0", container_id),
                            timeout=timeout,
                        )
                        if result.returncode != 0:
                            cleanup_failed = True
                            iteration_failed = True
                        else:
                            state.stopped.add(container_id)
                    _remove_container(
                        container_id,
                        runner,
                        state,
                        clock=clock,
                        deadline=cleanup_deadline,
                    )
                except SupervisorError:
                    cleanup_failed = True
                    iteration_failed = True
            if not iteration_failed:
                quiet_since = clock.monotonic()
        else:
            observed_at = clock.monotonic()
            quiet_since = observed_at if quiet_since is None else quiet_since
            if (
                not state.create_outcome_unresolved
                and observed_at - quiet_since >= OWNER_QUIET_SECONDS
            ):
                return not cleanup_failed
        remaining = cleanup_deadline - clock.monotonic()
        if remaining <= 0:
            break
        clock.sleep(min(OWNER_POLL_SECONDS, remaining))
    return False


def _cleanup_private(paths: Paths, protocol: Protocol) -> None:
    if protocol.cleanup_work:
        shutil.rmtree(paths.work)
    if protocol.cleanup_seed:
        paths.seed.unlink()


def _workspace_residue_bytes(path: Path) -> int:
    """Measure residue without following links or reading private contents."""
    if not path.exists():
        return 0
    total = 0
    stack = [path]
    try:
        while stack:
            current = stack.pop()
            with os.scandir(current) as entries:
                for entry in entries:
                    metadata = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(metadata.st_mode):
                        stack.append(Path(entry.path))
                    elif stat.S_ISREG(metadata.st_mode):
                        total += metadata.st_size
                    else:
                        raise SupervisorError("workspace_residue_invalid")
    except OSError as exc:
        raise SupervisorError("workspace_residue_invalid") from exc
    return total


def _public_receipt(
    protocol: Protocol,
    status: str,
    failure_class: str | None,
    elapsed: float,
    exits: Mapping[str, int | None],
    receipts: Mapping[str, Mapping[str, object]],
    peaks: Mapping[str, ResourcePeak],
    barrier: Mapping[str, object],
    cleanup: Mapping[str, bool],
) -> dict[str, object]:
    return {
        "schema": SUPERVISOR_SCHEMA,
        "status": status,
        "failure_class": failure_class,
        "protocol": {
            "protocol_id": protocol.protocol_id,
            "source_sha": protocol.source_sha,
            "image_reference": protocol.image_reference,
            "image_id": protocol.image_id,
            "image_revision": protocol.image_revision,
            "image_platform": protocol.image_platform,
            "external_registration_validated": True,
            "common_start_barrier": True,
            "scoring_seconds": protocol.scoring_seconds,
            "cleanup_grace_seconds": CLEANUP_SECONDS,
            "worker_drain_seconds": WORKER_DRAIN_SECONDS,
            "h24_target_network_authorized": False,
            "h24_provider_transport": "ordinary",
            "soak_network": "none",
            "post_h24_model_filler": False,
        },
        "barrier": dict(barrier),
        "elapsed_seconds": round(max(0.0, elapsed), 3),
        "containers": {
            "h24": {
                "exit_code": exits.get("h24"),
                "receipt": dict(receipts["h24"]),
                "resources": peaks[protocol.h24_name].public(),
            },
            "soak": {
                "exit_code": exits.get("soak"),
                "receipt": dict(receipts["soak"]),
                "resources": peaks[protocol.soak_name].public(),
            },
        },
        "artifacts": {
            "final_receipt": dict(
                receipts.get("final", {"present": False, "schema": None, "parse_status": "missing"})
            ),
            "evaluation_result": dict(
                receipts.get(
                    "evaluation", {"present": False, "schema": None, "parse_status": "missing"}
                )
            ),
        },
        "cleanup": dict(cleanup),
    }


def run_evaluation(
    protocol: Protocol,
    paths: Paths,
    *,
    runner: Runner = subprocess_runner,
    clock: Clock | None = None,
    finalize: bool = True,
) -> dict[str, object]:
    clock = clock or SystemClock()
    validate_descriptor_receipt(protocol, paths.output / DESCRIPTOR_RECEIPT)
    auth_baseline = _auth_baseline(paths.auth)
    ownership_token = _ownership_token()
    state = EvaluationState()
    peaks = {
        protocol.h24_name: ResourcePeak(),
        protocol.soak_name: ResourcePeak(),
    }
    exits: dict[str, int | None] = {"h24": None, "soak": None}
    failure_class: str | None = None
    started_at = clock.monotonic()
    barrier_origin_wall = clock.time()
    barrier_wall_milliseconds = math.ceil(
        (barrier_origin_wall + protocol.barrier_delay_seconds) * 1000
    )
    _validate_registration_timing(protocol, barrier_wall_milliseconds / 1000)
    barrier_mono: float | None = started_at + (
        barrier_wall_milliseconds / 1000 - barrier_origin_wall
    )
    scoring_deadline_mono: float | None = barrier_mono + protocol.scoring_seconds
    cleanup_started_mono: float | None = None
    worker_drain_deadline_mono: float | None = scoring_deadline_mono + WORKER_DRAIN_SECONDS
    cleanup_deadline_mono: float | None = scoring_deadline_mono + CLEANUP_SECONDS
    cleanup_finished_mono: float | None = None
    running: dict[str, str] = {}
    cleanup = {
        "containers_absent": False,
        "auth_preserved": False,
        "work_removed": False,
        "seed_removed": False,
        "private_receipts_preserved": False,
        "no_orphan_containers": False,
    }
    deadline_wall_milliseconds = barrier_wall_milliseconds + protocol.scoring_seconds * 1000
    barrier_receipt: dict[str, object] = {
        "start_wall_epoch_milliseconds": barrier_wall_milliseconds,
        "global_deadline_wall_epoch_milliseconds": deadline_wall_milliseconds,
        "creation_before_barrier": False,
    }
    with auth_lease(paths.auth):
        try:
            _validate_container_absence(protocol, runner)
            _validate_auth_unmounted(paths.auth, runner)
            for name, argv in (
                (
                    protocol.h24_name,
                    h24_create_argv(
                        protocol,
                        paths,
                        ownership_token=ownership_token,
                        start_wall_epoch_milliseconds=barrier_wall_milliseconds,
                    ),
                ),
                (
                    protocol.soak_name,
                    soak_create_argv(
                        protocol,
                        paths,
                        ownership_token=ownership_token,
                        start_wall_epoch_milliseconds=barrier_wall_milliseconds,
                    ),
                ),
            ):
                if name == protocol.h24_name:
                    intent = ContainerIntent(
                        name,
                        "h24",
                        protocol.image_id,
                        (
                            (paths.auth, "/auth/codex", False),
                            (paths.work, "/work", False),
                            (paths.output, "/output", False),
                            (paths.seed, "/seed/oracle.key", True),
                            (
                                paths.preregistration,
                                "/run/rapido-protocol/preregistration.json",
                                True,
                            ),
                        ),
                    )
                else:
                    intent = ContainerIntent(
                        name,
                        "soak",
                        protocol.image_id,
                        (
                            (paths.output, "/output", False),
                            (
                                paths.preregistration,
                                "/run/rapido-protocol/preregistration.json",
                                True,
                            ),
                        ),
                    )
                _create_owned_container(
                    argv,
                    intent,
                    ownership_token,
                    runner,
                    state,
                    failure="container_create",
                    clock=clock,
                    deadline=barrier_mono,
                )

            if clock.monotonic() >= barrier_mono:
                raise SupervisorError("start_barrier_missed")
            barrier_receipt["creation_before_barrier"] = True
            h24_id = state.by_role["h24"]
            soak_id = state.by_role["soak"]
            _run(
                runner,
                ("docker", "start", h24_id, soak_id),
                "container_start",
                timeout=60,
            )
            state.started.update((h24_id, soak_id))
            remaining = barrier_mono - clock.monotonic()
            if remaining > 0:
                clock.sleep(remaining)

            running = {h24_id: protocol.h24_name, soak_id: protocol.soak_name}
            for peak in peaks.values():
                peak.start_coverage(barrier_mono)
            next_sample_mono = barrier_mono
            while clock.monotonic() < scoring_deadline_mono:
                if not running:
                    remaining = scoring_deadline_mono - clock.monotonic()
                    if remaining > 0:
                        clock.sleep(remaining)
                    break
                until_sample = next_sample_mono - clock.monotonic()
                if until_sample > 0:
                    remaining = scoring_deadline_mono - clock.monotonic()
                    if remaining > 0:
                        clock.sleep(min(until_sample, remaining))
                    continue
                timeout = _remaining_timeout(clock, scoring_deadline_mono)
                if timeout is None:
                    break
                _sample(
                    running,
                    runner,
                    peaks,
                    clock=clock,
                    deadline=scoring_deadline_mono,
                    timeout=timeout,
                )
                next_sample_mono += SAMPLE_TARGET_SECONDS
                for container_id, name in tuple(running.items()):
                    timeout = _remaining_timeout(clock, scoring_deadline_mono)
                    if timeout is None:
                        break
                    container = _container_state(container_id, runner, timeout=timeout)
                    if container.get("Running") is not True:
                        peaks[name].end_coverage(min(clock.monotonic(), scoring_deadline_mono))
                        running.pop(container_id)
            for peak in peaks.values():
                peak.end_coverage(scoring_deadline_mono)

            cleanup_started_mono = scoring_deadline_mono
            # The registered outer grace reserves its final ten seconds for
            # forced stop, inspection, removal, and evidence persistence.
            while running and clock.monotonic() < worker_drain_deadline_mono:
                for container_id in tuple(running):
                    timeout = _remaining_timeout(clock, worker_drain_deadline_mono)
                    if timeout is None:
                        break
                    container = _container_state(container_id, runner, timeout=timeout)
                    if container.get("Running") is not True:
                        running.pop(container_id)
                remaining = worker_drain_deadline_mono - clock.monotonic()
                if running and remaining > 0:
                    clock.sleep(min(CLEANUP_POLL_SECONDS, remaining))
            if running:
                timeout = _remaining_timeout(clock, cleanup_deadline_mono)
                if timeout is None:
                    raise SupervisorError("cleanup_timeout")
                _run(
                    runner,
                    ("docker", "stop", "--time", "0", *sorted(running)),
                    "container_stop",
                    timeout=timeout,
                )
                state.stopped.update(running)
                running.clear()

            for role, name in (("h24", protocol.h24_name), ("soak", protocol.soak_name)):
                container_id = state.by_role[role]
                timeout = _remaining_timeout(clock, cleanup_deadline_mono)
                if timeout is None:
                    raise SupervisorError("cleanup_timeout")
                container = _container_state(container_id, runner, timeout=timeout)
                exits[role] = _integer(container.get("ExitCode"))
                peaks[name].oom_killed = (
                    container.get("OOMKilled") if type(container.get("OOMKilled")) is bool else None
                )
                timeout = _remaining_timeout(clock, cleanup_deadline_mono)
                if timeout is None:
                    raise SupervisorError("cleanup_timeout")
                _retain_logs(container_id, role, paths.output, runner, timeout=timeout)
        except SupervisorError as exc:
            failure_class = exc.failure_class
        finally:
            operation_deadline = cleanup_deadline_mono or clock.monotonic() + CLEANUP_SECONDS
            cleanup["containers_absent"] = _cleanup_owned_containers(
                ownership_token,
                state,
                runner,
                clock,
                operation_deadline,
            )
            cleanup["no_orphan_containers"] = cleanup["containers_absent"]
            cleanup["auth_preserved"] = _auth_matches_baseline(paths.auth, auth_baseline)

    receipts = {
        "h24": _receipt_projection(paths.output / H24_RECEIPT),
        "soak": _receipt_projection(paths.output / SOAK_RECEIPT),
    }
    if not cleanup["auth_preserved"]:
        failure_class = failure_class or "auth_integrity"
    if state.ownership_ambiguous:
        failure_class = failure_class or "container_ownership_ambiguous"
    cleanup["private_receipts_preserved"] = all(row["present"] for row in receipts.values())
    if finalize:
        try:
            if (
                barrier_mono is None
                or scoring_deadline_mono is None
                or cleanup_started_mono is None
                or cleanup_deadline_mono is None
            ):
                raise SupervisorError("evaluation_assembly")
            cleanup_start_offset = protocol.scoring_seconds * 1000
            # Persist and validate a sanitized provisional envelope before
            # deleting its private source material. Failed assembly or privacy
            # checks therefore leave the inputs intact for diagnosis.
            provisional_finish = clock.monotonic()
            finalize_evaluation(
                protocol,
                paths,
                barrier=barrier_receipt,
                h24_peak=peaks[protocol.h24_name],
                cleanup_started_offset_milliseconds=cleanup_start_offset,
                cleanup_elapsed_milliseconds=max(
                    0, int((provisional_finish - cleanup_started_mono) * 1000)
                ),
                containers_absent=cleanup["containers_absent"],
                cleanup_completed=False,
                workspace_residue_bytes=_workspace_residue_bytes(paths.work),
            )
            try:
                _cleanup_private(paths, protocol)
            except OSError:
                failure_class = failure_class or "private_cleanup"
            cleanup["work_removed"] = not paths.work.exists()
            cleanup["seed_removed"] = not paths.seed.exists()

            # The second pass records deletion. The third records the first
            # completed persistence pass, avoiding a claim based only on work
            # performed after the recorded timestamp.
            for _ in range(2):
                observed_finish = clock.monotonic()
                finalize_evaluation(
                    protocol,
                    paths,
                    barrier=barrier_receipt,
                    h24_peak=peaks[protocol.h24_name],
                    cleanup_started_offset_milliseconds=cleanup_start_offset,
                    cleanup_elapsed_milliseconds=max(
                        0, int((observed_finish - cleanup_started_mono) * 1000)
                    ),
                    containers_absent=cleanup["containers_absent"],
                    cleanup_completed=all(cleanup.values()),
                    workspace_residue_bytes=_workspace_residue_bytes(paths.work),
                )
            cleanup_finished_mono = clock.monotonic()
            if cleanup_finished_mono > cleanup_deadline_mono:
                # Never leave a passing cleanup envelope if the replacement
                # itself crossed the registered outer grace.
                finalize_evaluation(
                    protocol,
                    paths,
                    barrier=barrier_receipt,
                    h24_peak=peaks[protocol.h24_name],
                    cleanup_started_offset_milliseconds=cleanup_start_offset,
                    cleanup_elapsed_milliseconds=max(
                        0, int((cleanup_finished_mono - cleanup_started_mono) * 1000)
                    ),
                    containers_absent=cleanup["containers_absent"],
                    cleanup_completed=all(cleanup.values()),
                    workspace_residue_bytes=_workspace_residue_bytes(paths.work),
                )
                cleanup_finished_mono = clock.monotonic()
        except SupervisorError as exc:
            failure_class = failure_class or exc.failure_class
            cleanup_finished_mono = clock.monotonic()
    else:
        try:
            _cleanup_private(paths, protocol)
        except OSError:
            failure_class = failure_class or "private_cleanup"
        cleanup["work_removed"] = not paths.work.exists()
        cleanup["seed_removed"] = not paths.seed.exists()
        cleanup_finished_mono = clock.monotonic()
    if cleanup_deadline_mono is not None and cleanup_finished_mono > cleanup_deadline_mono:
        failure_class = failure_class or "cleanup_timeout"
    receipts["final"] = _receipt_projection(paths.output / FINAL_RECEIPT)
    receipts["evaluation"] = _receipt_projection(paths.output / EVALUATION_RESULT)
    if finalize and any(
        receipts[name]["parse_status"] != "parsed" for name in ("final", "evaluation")
    ):
        failure_class = failure_class or "evaluation_assembly"
    if any(value is None for value in exits.values()) or not cleanup["private_receipts_preserved"]:
        failure_class = failure_class or "receipt_incomplete"
    if any(peak.oom_killed is True for peak in peaks.values()):
        failure_class = failure_class or "container_oom"
    if not all(cleanup.values()):
        failure_class = failure_class or "cleanup_incomplete"
    if any(code != 0 for code in exits.values() if code is not None):
        failure_class = failure_class or "child_exit"
    status = "completed" if failure_class is None else "failed"
    receipt = _public_receipt(
        protocol,
        status,
        failure_class,
        clock.monotonic() - started_at,
        exits,
        receipts,
        peaks,
        barrier_receipt,
        cleanup,
    )
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
    _atomic_private_write(paths.output / SUPERVISOR_RECEIPT, encoded)
    return receipt


def run_descriptor_preflight(
    protocol: Protocol,
    paths: Paths,
    *,
    runner: Runner = subprocess_runner,
    clock: Clock | None = None,
) -> dict[str, object]:
    clock = clock or SystemClock()
    _validate_registration_timing(protocol, clock.time())
    name = f"{protocol.h24_name}-descriptor"
    ownership_token = _ownership_token()
    state = EvaluationState()
    auth_baseline = _auth_baseline(paths.auth)
    with auth_lease(paths.auth):
        _validate_container_absence(protocol, runner)
        _validate_auth_unmounted(paths.auth, runner)
        container_id: str | None = None
        create_deadline = clock.monotonic() + 120
        try:
            container_id = _create_owned_container(
                descriptor_preflight_argv(
                    protocol,
                    paths,
                    ownership_token=ownership_token,
                ),
                ContainerIntent(
                    name,
                    "descriptor",
                    protocol.image_id,
                    (
                        (paths.auth, "/auth/codex", False),
                        (paths.work, "/work", False),
                        (paths.output, "/output", False),
                        (
                            paths.preregistration,
                            "/run/rapido-protocol/preregistration.json",
                            True,
                        ),
                    ),
                ),
                ownership_token,
                runner,
                state,
                failure="preflight_create",
                clock=clock,
                deadline=create_deadline,
            )
            result = runner(
                ("docker", "start", "--attach", container_id),
                timeout=600,
            )
            _atomic_private_write(
                paths.output / "descriptor.docker.log", result.stdout + result.stderr
            )
            if result.returncode != 0:
                raise SupervisorError("preflight_run")
        finally:
            cleanup_attested = _cleanup_owned_containers(
                ownership_token,
                state,
                runner,
                clock,
                clock.monotonic() + OWNER_CLEANUP_SECONDS,
            )
            if not cleanup_attested and not state.create_outcome_unresolved:
                raise SupervisorError("preflight_cleanup")
        if state.ownership_ambiguous:
            raise SupervisorError("container_ownership_ambiguous")
        if not _auth_matches_baseline(paths.auth, auth_baseline):
            raise SupervisorError("auth_integrity")
    projection = _receipt_projection(paths.output / DESCRIPTOR_RECEIPT)
    if projection["parse_status"] != "parsed":
        raise SupervisorError("preflight_receipt")
    closed = validate_descriptor_receipt(protocol, paths.output / DESCRIPTOR_RECEIPT)
    return {
        "schema": DESCRIPTOR_SCHEMA,
        "protocol_id": protocol.protocol_id,
        "status": "matched",
        "descriptors": closed,
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("descriptor-preflight", "execute"))
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--preregistration", required=True, type=Path)
    parser.add_argument("--registration", required=True, type=Path)
    parser.add_argument("--auth", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--seed", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    if arguments.mode == "execute" and arguments.seed is None:
        raise SystemExit("--seed is required for execute")
    paths = validate_paths(
        Paths(
            arguments.repository,
            arguments.preregistration,
            arguments.registration,
            arguments.auth,
            arguments.work,
            arguments.seed or Path("/dev/null"),
            arguments.output,
        ),
        allowed_output_names=(
            frozenset({DESCRIPTOR_RECEIPT, "descriptor.docker.log"})
            if arguments.mode == "execute"
            else frozenset()
        ),
        require_seed=arguments.mode == "execute",
    )
    protocol = load_protocol(paths.preregistration)
    protocol = bind_registration(paths.registration, protocol)
    validate_environment(os.environ)
    _validate_registration_timing(protocol, time.time())
    validate_source(
        paths.repository,
        protocol.source_sha,
        protocol.source_tree_sha,
        subprocess_runner,
    )
    inspect_image(protocol, subprocess_runner)
    verify_image_source(protocol, paths.repository, paths.output, subprocess_runner)
    validate_host_budget(subprocess_runner)
    if arguments.mode == "descriptor-preflight":
        receipt = run_descriptor_preflight(protocol, paths)
    else:
        receipt = run_evaluation(protocol, paths)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("status") != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
