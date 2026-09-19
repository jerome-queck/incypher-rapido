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
SAMPLE_SECONDS = 10.0
CONTAINER_UID = 10_001
H24_RECEIPT = "h24-receipt.json"
SOAK_RECEIPT = "soak-receipt.json"
DESCRIPTOR_RECEIPT = "descriptor-preflight.json"
SUPERVISOR_RECEIPT = "supervisor-receipt.json"
FINAL_RECEIPT = "h24-evaluation-receipt.json"
EVALUATION_RESULT = "h24-evaluation-result.json"
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IMAGE_REFERENCE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
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

    def observe(self, row: Mapping[str, object]) -> None:
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

    def public(self) -> dict[str, object]:
        return {
            "samples": self.samples,
            "peak_cpu_percent": self.cpu_percent,
            "peak_rss_bytes": self.rss_bytes,
            "peak_pids": self.pids,
            "oom_killed": self.oom_killed,
        }


@dataclass
class EvaluationState:
    created: set[str] = field(default_factory=set)
    started: set[str] = field(default_factory=set)
    stopped: set[str] = field(default_factory=set)
    removed: set[str] = field(default_factory=set)


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
    return replace(
        protocol,
        source_sha=source_sha,
        source_tree_sha=source_tree,
        image_reference=image_id,
        image_id=image_id,
        image_revision=source_sha,
        image_platform=image_platform,
        registration=dict(validated),
    )


def _run(
    runner: Runner, argv: Sequence[str], failure: str, *, timeout: float = 30
) -> CommandResult:
    result = runner(tuple(argv), timeout=timeout)
    if result.returncode != 0:
        raise SupervisorError(failure)
    return result


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
    labels = _mapping(_mapping(row.get("Config"), "image_identity").get("Labels"), "image_identity")
    image_os = row.get("Os")
    architecture = row.get("Architecture")
    if image_os != "linux" or architecture not in {"amd64", "arm64"}:
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


def _regular_python_sources(root: Path) -> dict[str, bytes]:
    sources: dict[str, bytes] = {}
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
                    if stat.S_ISLNK(metadata.st_mode):
                        raise SupervisorError("image_source_mismatch")
                    if stat.S_ISDIR(metadata.st_mode):
                        stack.append(path)
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        raise SupervisorError("image_source_mismatch")
                    if path.suffix == ".py":
                        sources[path.relative_to(root).as_posix()] = path.read_bytes()
    except OSError as exc:
        raise SupervisorError("image_source_mismatch") from exc
    return sources


def verify_image_source(
    protocol: Protocol,
    repository: Path,
    output: Path,
    runner: Runner,
) -> None:
    """Compare installed image sources without executing image-provided code."""
    ownership_confirmed = False
    cleanup_failed = False
    probe_root = Path(tempfile.mkdtemp(prefix=".rapido-image-source-", dir=output))
    probe_root.chmod(0o700)
    try:
        if not _container_absent(_SOURCE_PROBE_NAME, runner):
            raise SupervisorError("image_source_probe_in_use")
        ownership_confirmed = True
        _run(
            runner,
            (
                "docker",
                "create",
                "--name",
                _SOURCE_PROBE_NAME,
                "--network",
                "none",
                "--read-only",
                "--entrypoint",
                "/bin/false",
                protocol.image_reference,
            ),
            "image_source_probe_create",
            timeout=120,
        )
        installed = probe_root / "rapido"
        _run(
            runner,
            ("docker", "cp", f"{_SOURCE_PROBE_NAME}:{_INSTALLED_RAPIDO}", str(installed)),
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
                    f"{_SOURCE_PROBE_NAME}:/opt/rapido-eval/{name}",
                    str(wrapper / name),
                ),
                "image_source_probe_copy",
                timeout=30,
            )
        if _regular_python_sources(installed) != _regular_python_sources(repository / "rapido"):
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
        if ownership_confirmed:
            try:
                if not _container_absent(_SOURCE_PROBE_NAME, runner):
                    result = runner(("docker", "rm", "--volumes", _SOURCE_PROBE_NAME), timeout=30)
                    cleanup_failed = result.returncode != 0
                cleanup_failed = cleanup_failed or not _container_absent(_SOURCE_PROBE_NAME, runner)
            except SupervisorError:
                cleanup_failed = True
        try:
            shutil.rmtree(probe_root)
        except OSError:
            cleanup_failed = True
        if cleanup_failed:
            raise SupervisorError("image_source_probe_cleanup")


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


def _hardened_create_prefix(name: str, resource: Resources) -> list[str]:
    return [
        "docker",
        "create",
        "--name",
        name,
        "--stop-timeout",
        str(CLEANUP_SECONDS),
        "--cpus",
        str(resource.cpus),
        "--memory",
        f"{resource.memory_gib}g",
        "--pids-limit",
        str(resource.pids),
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
    ]


def descriptor_preflight_argv(protocol: Protocol, paths: Paths) -> tuple[str, ...]:
    name = f"{protocol.h24_name}-descriptor"
    argv = _hardened_create_prefix(name, protocol.h24)
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
    start_wall_epoch_milliseconds: int | None = None,
) -> tuple[str, ...]:
    argv = _hardened_create_prefix(protocol.h24_name, protocol.h24)
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
    start_wall_epoch_milliseconds: int | None = None,
) -> tuple[str, ...]:
    argv = _hardened_create_prefix(protocol.soak_name, protocol.soak)
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
    path = auth / ".offline-h24-supervisor.lock"
    descriptor = os.open(path, os.O_CREAT | os.O_CLOEXEC | os.O_RDWR, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SupervisorError("auth_lease_busy") from exc
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
        with contextlib.suppress(OSError):
            path.unlink()


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
    names: Sequence[str],
    runner: Runner,
    peaks: Mapping[str, ResourcePeak],
    *,
    timeout: float = 30,
) -> None:
    if not names:
        return
    result = runner(
        (
            "docker",
            "stats",
            "--no-stream",
            "--format={{json .}}",
            *names,
        ),
        timeout=timeout,
    )
    if result.returncode != 0:
        return
    for line in result.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, Mapping):
            continue
        name = row.get("Name")
        if isinstance(name, str) and name in peaks:
            peaks[name].observe(row)


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
    try:
        metadata = path.lstat()
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SupervisorError(label) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not isinstance(value, Mapping)
    ):
        raise SupervisorError(label)
    return value


def _runtime_resources(peak: ResourcePeak) -> dict[str, object]:
    values = (peak.cpu_percent, peak.rss_bytes, peak.pids, peak.oom_killed)
    status = (
        "observed"
        if peak.samples and all(value is not None for value in values)
        else "unavailable"
        if all(value is None for value in values)
        else "partial"
    )
    return {
        "observation_status": status,
        "sample_interval_seconds": SAMPLE_SECONDS if peak.samples else None,
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
    name: str,
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
    result = runner(("docker", "rm", name), timeout=timeout)
    if result.returncode == 0:
        state.removed.add(name)
        return
    timeout = (
        _remaining_timeout(clock, deadline) if clock is not None and deadline is not None else 30
    )
    if timeout is not None and _container_absent(name, runner, timeout=timeout):
        state.removed.add(name)
        return
    raise SupervisorError("container_remove")


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
    state = EvaluationState()
    peaks = {
        protocol.h24_name: ResourcePeak(),
        protocol.soak_name: ResourcePeak(),
    }
    exits: dict[str, int | None] = {"h24": None, "soak": None}
    failure_class: str | None = None
    started_at = clock.monotonic()
    barrier_mono: float | None = None
    scoring_deadline_mono: float | None = None
    cleanup_started_mono: float | None = None
    worker_drain_deadline_mono: float | None = None
    cleanup_deadline_mono: float | None = None
    cleanup_finished_mono: float | None = None
    running: set[str] = set()
    cleanup = {
        "containers_absent": False,
        "auth_preserved": False,
        "work_removed": False,
        "seed_removed": False,
        "private_receipts_preserved": False,
        "no_orphan_containers": False,
    }
    barrier_receipt: dict[str, object] = {
        "start_wall_epoch_milliseconds": None,
        "global_deadline_wall_epoch_milliseconds": None,
        "creation_before_barrier": False,
    }
    with auth_lease(paths.auth):
        try:
            _validate_container_absence(protocol, runner)
            _validate_auth_unmounted(paths.auth, runner)
            barrier_origin_mono = clock.monotonic()
            barrier_origin_wall = clock.time()
            barrier_wall_milliseconds = math.ceil(
                (barrier_origin_wall + protocol.barrier_delay_seconds) * 1000
            )
            barrier_mono = barrier_origin_mono + (
                barrier_wall_milliseconds / 1000 - barrier_origin_wall
            )
            scoring_deadline_mono = barrier_mono + protocol.scoring_seconds
            worker_drain_deadline_mono = scoring_deadline_mono + WORKER_DRAIN_SECONDS
            cleanup_deadline_mono = scoring_deadline_mono + CLEANUP_SECONDS
            deadline_wall_milliseconds = barrier_wall_milliseconds + protocol.scoring_seconds * 1000
            barrier_receipt = {
                "start_wall_epoch_milliseconds": barrier_wall_milliseconds,
                "global_deadline_wall_epoch_milliseconds": deadline_wall_milliseconds,
                "creation_before_barrier": False,
            }
            for name, argv in (
                (
                    protocol.h24_name,
                    h24_create_argv(
                        protocol,
                        paths,
                        start_wall_epoch_milliseconds=barrier_wall_milliseconds,
                    ),
                ),
                (
                    protocol.soak_name,
                    soak_create_argv(
                        protocol,
                        paths,
                        start_wall_epoch_milliseconds=barrier_wall_milliseconds,
                    ),
                ),
            ):
                _run(runner, argv, "container_create", timeout=120)
                state.created.add(name)

            if clock.monotonic() >= barrier_mono:
                raise SupervisorError("start_barrier_missed")
            barrier_receipt["creation_before_barrier"] = True
            _run(
                runner,
                ("docker", "start", protocol.h24_name, protocol.soak_name),
                "container_start",
                timeout=60,
            )
            state.started.update((protocol.h24_name, protocol.soak_name))
            remaining = barrier_mono - clock.monotonic()
            if remaining > 0:
                clock.sleep(remaining)

            running = {protocol.h24_name, protocol.soak_name}
            while clock.monotonic() < scoring_deadline_mono:
                if running:
                    timeout = _remaining_timeout(clock, scoring_deadline_mono)
                    if timeout is None:
                        break
                    _sample(sorted(running), runner, peaks, timeout=timeout)
                    for name in tuple(running):
                        timeout = _remaining_timeout(clock, scoring_deadline_mono)
                        if timeout is None:
                            break
                        container = _container_state(name, runner, timeout=timeout)
                        if container.get("Running") is not True:
                            running.remove(name)
                remaining = scoring_deadline_mono - clock.monotonic()
                if remaining > 0:
                    clock.sleep(min(SAMPLE_SECONDS, remaining) if running else remaining)

            cleanup_started_mono = scoring_deadline_mono
            # The registered outer grace reserves its final ten seconds for
            # forced stop, inspection, removal, and evidence persistence.
            while running and clock.monotonic() < worker_drain_deadline_mono:
                for name in tuple(running):
                    timeout = _remaining_timeout(clock, worker_drain_deadline_mono)
                    if timeout is None:
                        break
                    container = _container_state(name, runner, timeout=timeout)
                    if container.get("Running") is not True:
                        running.remove(name)
                remaining = worker_drain_deadline_mono - clock.monotonic()
                if running and remaining > 0:
                    clock.sleep(min(SAMPLE_SECONDS, remaining))
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
                timeout = _remaining_timeout(clock, cleanup_deadline_mono)
                if timeout is None:
                    raise SupervisorError("cleanup_timeout")
                container = _container_state(name, runner, timeout=timeout)
                exits[role] = _integer(container.get("ExitCode"))
                peaks[name].oom_killed = (
                    container.get("OOMKilled") if type(container.get("OOMKilled")) is bool else None
                )
                timeout = _remaining_timeout(clock, cleanup_deadline_mono)
                if timeout is None:
                    raise SupervisorError("cleanup_timeout")
                _retain_logs(name, role, paths.output, runner, timeout=timeout)
        except SupervisorError as exc:
            failure_class = exc.failure_class
        finally:
            operation_deadline = cleanup_deadline_mono or clock.monotonic() + CLEANUP_SECONDS
            for name in sorted(state.created):
                if name not in state.removed:
                    with contextlib.suppress(SupervisorError):
                        timeout = _remaining_timeout(clock, operation_deadline)
                        if timeout is None:
                            break
                        if not _container_absent(name, runner, timeout=timeout):
                            timeout = _remaining_timeout(clock, operation_deadline)
                            if timeout is None:
                                break
                            container = _container_state(name, runner, timeout=timeout)
                            if container.get("Running") is True:
                                timeout = _remaining_timeout(clock, operation_deadline)
                                if timeout is None:
                                    break
                                result = runner(
                                    ("docker", "stop", "--time", "0", name), timeout=timeout
                                )
                                if result.returncode == 0:
                                    state.stopped.add(name)
                        _remove_container(
                            name,
                            runner,
                            state,
                            clock=clock,
                            deadline=operation_deadline,
                        )
            absent: list[bool] = []
            for name in (protocol.h24_name, protocol.soak_name):
                timeout = _remaining_timeout(clock, operation_deadline)
                if timeout is None:
                    absent.append(False)
                    continue
                with contextlib.suppress(SupervisorError):
                    absent.append(_container_absent(name, runner, timeout=timeout))
            cleanup["containers_absent"] = len(absent) == 2 and all(absent)
            cleanup["no_orphan_containers"] = cleanup["containers_absent"]
            cleanup["auth_preserved"] = paths.auth.is_dir() and (paths.auth / "auth.json").is_file()

    receipts = {
        "h24": _receipt_projection(paths.output / H24_RECEIPT),
        "soak": _receipt_projection(paths.output / SOAK_RECEIPT),
    }
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
) -> dict[str, object]:
    name = f"{protocol.h24_name}-descriptor"
    with auth_lease(paths.auth):
        _validate_container_absence(protocol, runner)
        _validate_auth_unmounted(paths.auth, runner)
        _run(runner, descriptor_preflight_argv(protocol, paths), "preflight_create", timeout=120)
        try:
            result = runner(
                ("docker", "start", "--attach", name),
                timeout=600,
            )
            _atomic_private_write(
                paths.output / "descriptor.docker.log", result.stdout + result.stderr
            )
            if result.returncode != 0:
                raise SupervisorError("preflight_run")
        finally:
            _remove_container(name, runner, EvaluationState(created={name}))
    projection = _receipt_projection(paths.output / DESCRIPTOR_RECEIPT)
    if projection["parse_status"] != "parsed":
        raise SupervisorError("preflight_receipt")
    try:
        raw = json.loads((paths.output / DESCRIPTOR_RECEIPT).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SupervisorError("preflight_receipt") from exc
    row = _mapping(raw, "preflight_receipt")
    if (
        row.get("schema") != DESCRIPTOR_SCHEMA
        or row.get("matched") is not True
        or row.get("descriptors") != protocol.preregistration.get("descriptor_preflight")
    ):
        raise SupervisorError("preflight_receipt")
    descriptors = row.get("descriptors")
    if not isinstance(descriptors, list) or len(descriptors) != 2:
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
