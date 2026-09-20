"""Dedicated direct-injection runner for private offline capability banks."""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import re
import secrets
import shutil
import signal
import stat
import sys
import tarfile
import tempfile
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, BinaryIO

from .board import BoardLike
from .codex_app import CodexAppClient
from .config import ConfigError, validate_codex_home
from .control import DurableJobControl
from .offline_profile import (
    OfflineRuntimeConfig,
    assert_offline_environment,
    offline_child_env,
)
from .orchestrator import NativeRuntime, RunReport

OFFLINE_ACCEPTANCE_SCHEMA = "rapido-offline-board-acceptance-v1"
OFFLINE_STAGE_ACCEPTANCE_SCHEMA = "rapido-offline-board-stage-acceptance-v1"
_OFFLINE_CONTAINER_UID = 10001
_RUN_REPORT_FIELDS = frozenset(field.name for field in fields(RunReport))
_FORBIDDEN_PUBLIC_TEXT = re.compile(
    r"(?:INCYPHER\{|flag\{|https?://|(?<![A-Za-z0-9])[A-Za-z]:[\\/]|"
    r"(?<![A-Za-z0-9])(?:\\\\|//)[^\s]+|(?<![A-Za-z0-9])/(?!\s)[^\s,;]*|"
    r"\b[0-9a-f]{40,64}\b|\b[A-Za-z0-9.-]+:[0-9]{2,5}\b)",
    re.IGNORECASE,
)
_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "authority",
        "board_url",
        "candidate",
        "candidate_bytes",
        "candidate_digest",
        "candidate_hash",
        "candidate_sha256",
        "checker_detail",
        "expected",
        "oracle",
        "oracle_key",
        "path",
        "private_payload",
        "raw_output",
        "target",
        "token",
    }
)


@dataclass(frozen=True)
class OfflineRunRegistration:
    """Private factory output accepted by the public offline entry point."""

    config: OfflineRuntimeConfig
    board_factory: Callable[[], BoardLike]
    run_root: Path
    receipt_path: Path
    private_roots: tuple[Path, ...]
    isolation_backend: str


@dataclass(frozen=True)
class OfflineRunPlan(OfflineRunRegistration):
    """Executable plan; direct runtime injection remains available for focused tests."""

    runtime: NativeRuntime
    isolation_probe: Callable[[], Awaitable[bool] | bool]
    runtime_cleanup_probe: Callable[[], Awaitable[Mapping[str, object]] | Mapping[str, object]]


class _ContainerProcess:
    """Delegate app-server pipes while retaining its exact owned container identity."""

    def __init__(self, process: Any, container_name: str) -> None:
        self._process = process
        self.pid = process.pid
        self.container_name = container_name

    def __getattr__(self, name: str) -> Any:
        return getattr(self._process, name)

    @property
    def returncode(self) -> int | None:
        return self._process.returncode

    def terminate(self) -> None:
        try:
            os.killpg(self.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            return

    def kill(self) -> None:
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            return


class _DockerRuntimeBoundary:
    """Run the scored native client in an exact, private-root-free container."""

    def __init__(
        self,
        *,
        workspace_root: Path,
        codex_home: Path,
        private_roots: tuple[Path, ...],
        binary: str,
        image: str,
        max_workspace_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        docker = shutil.which("docker")
        if docker is None:
            raise ConfigError("the registered offline container backend is unavailable")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise ConfigError("offline runner image must be an exact digest")
        if not binary or len(binary) > 256 or any(ord(character) < 32 for character in binary):
            raise ConfigError("offline native client binary is invalid")
        self.docker = docker
        self.workspace_root = workspace_root
        self.codex_home = codex_home
        self.private_roots = private_roots
        self.binary = binary
        self.image = image
        self.max_workspace_bytes = max_workspace_bytes
        self.run_token = secrets.token_hex(16)
        self.stable_label = "rapido.offline.native=capability-v1"
        self.run_label = f"rapido.offline.native.run={self.run_token}"
        self.workspace_volume = f"rapido-offline-work-{self.run_token}"
        self.codex_volume = f"rapido-offline-codex-{self.run_token}"
        self._volumes_ready = False
        self._workspace_descriptor = -1
        self._workspace_identity: tuple[int, int] | None = None
        self._codex_descriptor = -1
        self._codex_identity: tuple[int, int] | None = None
        self._auth_descriptor = -1
        self._auth_identity: tuple[int, int] | None = None
        self._processes: list[_ContainerProcess] = []
        self._helpers: list[asyncio.subprocess.Process] = []
        self._sync_lock = asyncio.Lock()
        self._sync_count = 0
        host_home = os.environ.get("HOME")
        if not host_home:
            raise ConfigError("offline container client HOME is unavailable")
        self._host_env = {
            "HOME": host_home,
            "PATH": f"{Path(docker).parent}:/usr/local/bin:/usr/bin:/bin",
        }
        try:
            self._codex_descriptor = os.open(
                self.codex_home,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            )
            codex_metadata = os.fstat(self._codex_descriptor)
            if not stat.S_ISDIR(codex_metadata.st_mode) or codex_metadata.st_uid != os.geteuid():
                raise OSError("unsafe codex home")
            self._codex_identity = (codex_metadata.st_dev, codex_metadata.st_ino)
            self._auth_descriptor = os.open(
                "auth.json",
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._codex_descriptor,
            )
            auth_metadata = os.fstat(self._auth_descriptor)
            if (
                not stat.S_ISREG(auth_metadata.st_mode)
                or auth_metadata.st_uid != os.geteuid()
                or auth_metadata.st_nlink != 1
                or auth_metadata.st_size > 1024 * 1024
            ):
                raise OSError("unsafe auth file")
            self._auth_identity = (auth_metadata.st_dev, auth_metadata.st_ino)
        except OSError:
            if self._auth_descriptor >= 0:
                os.close(self._auth_descriptor)
                self._auth_descriptor = -1
            if self._codex_descriptor >= 0:
                os.close(self._codex_descriptor)
                self._codex_descriptor = -1
            raise ConfigError("offline native codex home cannot be pinned") from None

    def _container_args(self, name: str) -> list[str]:
        return [
            self.docker,
            "run",
            "--rm",
            "--interactive",
            "--pull",
            "never",
            "--name",
            name,
            "--label",
            self.stable_label,
            "--label",
            self.run_label,
            "--read-only",
            "--pids-limit",
            "256",
            "--cpus",
            "12",
            "--memory",
            "24g",
            "--shm-size",
            "64m",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=512m",
            "--tmpfs",
            "/auth/codex:rw,nosuid,nodev,noexec,size=16m",
            "--tmpfs",
            "/state:rw,nosuid,nodev,noexec,size=16m",
            "--user",
            f"{_OFFLINE_CONTAINER_UID}:{_OFFLINE_CONTAINER_UID}",
            "--mount",
            f"type=volume,src={self.workspace_volume},dst={self.workspace_root},readonly",
            "--mount",
            f"type=volume,src={self.codex_volume},dst={self.codex_home}",
            "--env",
            f"CODEX_HOME={self.codex_home}",
            "--env",
            f"HOME={self.codex_home}",
            "--env",
            "TERM=dumb",
            "--env",
            "NO_COLOR=1",
            "--workdir",
            str(self.workspace_root),
        ]

    @staticmethod
    async def _drain_helper(
        communication: asyncio.Task[Any],
    ) -> Any:
        while True:
            try:
                return await asyncio.shield(communication)
            except asyncio.CancelledError:
                current = asyncio.current_task()
                if current is not None and hasattr(current, "uncancel"):
                    current.uncancel()

    @staticmethod
    def _kill_process_group(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    async def _docker_run(
        self,
        args: tuple[str, ...],
        *,
        payload: bytes | None,
        input_file: BinaryIO | None = None,
        timeout: float,
    ) -> tuple[int, bytes]:
        if payload is not None and input_file is not None:
            raise ValueError("docker input must have one source")
        process = await asyncio.create_subprocess_exec(
            self.docker,
            *args,
            stdin=(
                input_file
                if input_file is not None
                else asyncio.subprocess.DEVNULL
                if payload is None
                else asyncio.subprocess.PIPE
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=self._host_env,
            start_new_session=True,
        )
        self._helpers.append(process)
        communication = asyncio.create_task(process.communicate(payload))
        try:
            stdout, _ = await asyncio.wait_for(asyncio.shield(communication), timeout=timeout)
        except TimeoutError:
            self._kill_process_group(process)
            await self._drain_helper(communication)
            return 124, b""
        except asyncio.CancelledError:
            self._kill_process_group(process)
            await self._drain_helper(communication)
            raise
        finally:
            if communication.done() and process.returncode is not None and process in self._helpers:
                self._helpers.remove(process)
        if len(stdout) > 65536:
            return 125, b""
        return process.returncode or 0, stdout

    async def _docker_command(self, *args: str, timeout: float = 10.0) -> tuple[int, bytes]:
        return await self._docker_run(tuple(args), payload=None, timeout=timeout)

    async def _docker_input(
        self, *args: str, payload: bytes, timeout: float = 20.0
    ) -> tuple[int, bytes]:
        return await self._docker_run(tuple(args), payload=payload, timeout=timeout)

    async def _docker_file(
        self, *args: str, payload: BinaryIO, timeout: float = 20.0
    ) -> tuple[int, bytes]:
        return await self._docker_run(
            tuple(args), payload=None, input_file=payload, timeout=timeout
        )

    async def _inventory(self, label: str) -> tuple[str, ...] | None:
        names: list[str] = []
        for command in (
            ("ps", "-a", "--filter", f"label={label}", "--format", "{{.Names}}"),
            ("volume", "ls", "--filter", f"label={label}", "--format", "{{.Name}}"),
        ):
            code, output = await self._docker_command(*command)
            if code != 0:
                return None
            names.extend(line for line in output.decode("utf-8", "replace").splitlines() if line)
        return tuple(names)

    def _pin_workspace(self) -> bool:
        if self._workspace_descriptor >= 0:
            return True
        descriptor = -1
        try:
            descriptor = os.open(
                self.workspace_root,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
                return False
            self._workspace_descriptor = descriptor
            self._workspace_identity = (metadata.st_dev, metadata.st_ino)
            return True
        except OSError:
            return False
        finally:
            if descriptor >= 0 and self._workspace_descriptor != descriptor:
                os.close(descriptor)

    async def _initialize_volumes(self) -> bool:
        if self._volumes_ready:
            return True
        if (
            self._codex_descriptor < 0
            or self._codex_identity is None
            or self._auth_descriptor < 0
            or self._auth_identity is None
        ):
            return False
        descriptor = -1
        try:
            current_home = self.codex_home.lstat()
            if (
                not stat.S_ISDIR(current_home.st_mode)
                or (current_home.st_dev, current_home.st_ino) != self._codex_identity
            ):
                return False
            current_auth = os.stat(
                "auth.json", dir_fd=self._codex_descriptor, follow_symlinks=False
            )
            if (current_auth.st_dev, current_auth.st_ino) != self._auth_identity:
                return False
            descriptor = os.dup(self._auth_descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > 1024 * 1024
            ):
                return False
            chunks: list[bytes] = []
            remaining = before.st_size + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            auth = b"".join(chunks)
            after = os.fstat(descriptor)
            if len(auth) != before.st_size or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                return False
        except OSError:
            return False
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        for volume in (self.workspace_volume, self.codex_volume):
            code, _ = await self._docker_command(
                "volume",
                "create",
                "--label",
                self.stable_label,
                "--label",
                self.run_label,
                volume,
            )
            if code != 0:
                return False
        setup_name = f"rapido-offline-{self.run_token}-volume-setup"
        script = (
            'umask 077; mkdir -p "$1" "$2"; '
            ': > "$1/.rapido-volume"; '
            'cat > "$2/auth.json"; '
            f'chown -R {_OFFLINE_CONTAINER_UID}:{_OFFLINE_CONTAINER_UID} "$1" "$2"; '
            'chmod 700 "$1" "$2"; chmod 600 "$2/auth.json"'
        )
        code, _ = await self._docker_input(
            "run",
            "--rm",
            "--interactive",
            "--pull",
            "never",
            "--name",
            setup_name,
            "--label",
            self.stable_label,
            "--label",
            self.run_label,
            "--network",
            "none",
            "--shm-size",
            "16m",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=32m",
            "--tmpfs",
            "/auth/codex:rw,nosuid,nodev,noexec,size=8m",
            "--tmpfs",
            "/state:rw,nosuid,nodev,noexec,size=8m",
            "--user",
            "0:0",
            "--mount",
            f"type=volume,src={self.workspace_volume},dst=/workspace",
            "--mount",
            f"type=volume,src={self.codex_volume},dst=/codex",
            "--entrypoint",
            "/bin/sh",
            self.image,
            "-c",
            script,
            "sh",
            "/workspace",
            "/codex",
            payload=auth,
        )
        self._volumes_ready = code == 0
        return self._volumes_ready

    def _workspace_archive(self, workspace: Path) -> tuple[str, BinaryIO]:
        try:
            relative = workspace.relative_to(self.workspace_root)
        except ValueError:
            raise ConfigError("offline lane workspace is outside the run root") from None
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise ConfigError("offline lane workspace must be below the work root")
        if self._workspace_descriptor < 0 or self._workspace_identity is None:
            raise ConfigError("offline work root is not pinned")
        try:
            current_root = self.workspace_root.lstat()
        except OSError:
            raise ConfigError("offline work root changed identity") from None
        if (
            not stat.S_ISDIR(current_root.st_mode)
            or (current_root.st_dev, current_root.st_ino) != self._workspace_identity
        ):
            raise ConfigError("offline work root changed identity")
        payload = tempfile.TemporaryFile(  # noqa: SIM115 - caller owns streamed archive
            mode="w+b", dir=self.workspace_root.parent
        )
        total = 0
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        entry_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)

        def checked_directory(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise ConfigError("offline lane workspace contains an unsafe directory")

        def add_directory(archive: tarfile.TarFile, descriptor: int, archive_path: Path) -> None:
            nonlocal total
            checked_directory(descriptor)
            info = tarfile.TarInfo(archive_path.as_posix())
            info.type = tarfile.DIRTYPE
            info.mode = 0o700
            info.uid = _OFFLINE_CONTAINER_UID
            info.gid = _OFFLINE_CONTAINER_UID
            info.mtime = 0
            archive.addfile(info)
            try:
                names = sorted(os.listdir(descriptor))
            except OSError:
                raise ConfigError("offline lane workspace changed during capture") from None
            for name in names:
                if not name or name in {".", ".."} or "/" in name:
                    raise ConfigError("offline lane workspace contains an unsafe entry")
                child = -1
                try:
                    child = os.open(name, entry_flags, dir_fd=descriptor)
                    before = os.fstat(child)
                    child_path = archive_path / name
                    if stat.S_ISDIR(before.st_mode):
                        add_directory(archive, child, child_path)
                        continue
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or before.st_uid != os.geteuid()
                        or before.st_nlink != 1
                        or before.st_size > self.max_workspace_bytes - total
                    ):
                        raise ConfigError("offline lane workspace contains an unsafe file")
                    os.lseek(child, 0, os.SEEK_SET)
                    source = os.fdopen(os.dup(child), "rb")
                    info = tarfile.TarInfo(child_path.as_posix())
                    info.size = before.st_size
                    info.mode = 0o600
                    info.uid = _OFFLINE_CONTAINER_UID
                    info.gid = _OFFLINE_CONTAINER_UID
                    info.mtime = 0
                    try:
                        archive.addfile(info, source)
                    finally:
                        source.close()
                    after = os.fstat(child)
                    if (
                        before.st_dev,
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                    ) != (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                    ):
                        raise ConfigError("offline lane workspace changed during capture")
                    total += before.st_size
                except OSError:
                    raise ConfigError("offline lane workspace capture failed") from None
                finally:
                    if child >= 0:
                        os.close(child)
            try:
                if sorted(os.listdir(descriptor)) != names:
                    raise ConfigError("offline lane workspace changed during capture")
            except OSError:
                raise ConfigError("offline lane workspace changed during capture") from None

        selected_descriptor = -1
        try:
            selected_descriptor = os.dup(self._workspace_descriptor)
            checked_directory(selected_descriptor)
            for part in relative.parts:
                child = os.open(part, directory_flags, dir_fd=selected_descriptor)
                os.close(selected_descriptor)
                selected_descriptor = child
                checked_directory(selected_descriptor)
            with tarfile.open(fileobj=payload, mode="w") as archive:
                add_directory(archive, selected_descriptor, relative)
        except OSError:
            payload.close()
            raise ConfigError("offline lane workspace capture failed") from None
        except BaseException:
            payload.close()
            raise
        finally:
            if selected_descriptor >= 0:
                os.close(selected_descriptor)
        payload.seek(0)
        return relative.as_posix(), payload

    async def sync_workspace(self, workspace: Path) -> None:
        """Copy one verified host lane into the already-mounted private volume."""
        if not self._volumes_ready:
            raise ConfigError("offline native volumes are not initialized")
        relative, archive = await asyncio.to_thread(self._workspace_archive, workspace)
        script = r"""import os, pathlib, shutil, stat, sys, tarfile
root = pathlib.Path("/workspace")
parts = pathlib.PurePosixPath(sys.argv[1]).parts
if not parts or any(part in {"", ".", ".."} for part in parts):
    raise SystemExit(2)
target = root.joinpath(*parts)
shutil.rmtree(target, ignore_errors=True)
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as stream:
    for member in stream:
        member_parts = pathlib.PurePosixPath(member.name).parts
        if not member_parts or any(part in {"", ".", ".."} for part in member_parts):
            raise SystemExit(3)
        destination = root.joinpath(*member_parts)
        if member.isdir():
            destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        elif member.isfile():
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = stream.extractfile(member)
            if source is None:
                raise SystemExit(4)
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                shutil.copyfileobj(source, output, 65536)
        else:
            raise SystemExit(5)
"""
        async with self._sync_lock:
            self._sync_count += 1
            name = f"rapido-offline-{self.run_token}-workspace-sync-{self._sync_count}"
            try:
                code, _ = await self._docker_file(
                    "run",
                    "--rm",
                    "--interactive",
                    "--pull",
                    "never",
                    "--name",
                    name,
                    "--label",
                    self.stable_label,
                    "--label",
                    self.run_label,
                    "--network",
                    "none",
                    "--shm-size",
                    "16m",
                    "--tmpfs",
                    "/tmp:rw,nosuid,nodev,noexec,size=32m",
                    "--tmpfs",
                    "/auth/codex:rw,nosuid,nodev,noexec,size=8m",
                    "--tmpfs",
                    "/state:rw,nosuid,nodev,noexec,size=8m",
                    "--user",
                    f"{_OFFLINE_CONTAINER_UID}:{_OFFLINE_CONTAINER_UID}",
                    "--mount",
                    f"type=volume,src={self.workspace_volume},dst=/workspace",
                    "--entrypoint",
                    "/opt/venv/bin/python3",
                    self.image,
                    "-c",
                    script,
                    relative,
                    payload=archive,
                )
            finally:
                archive.close()
        if code != 0:
            raise ConfigError("offline lane workspace synchronization failed")

    async def process_factory(
        self, _binary: str, *args: str, **kwargs: object
    ) -> _ContainerProcess:
        if not self._volumes_ready:
            raise ConfigError("offline native volumes are not initialized")
        name = f"rapido-offline-{self.run_token}-{len(self._processes) + 1}"
        host_kwargs = dict(kwargs)
        host_kwargs["env"] = self._host_env
        process = await asyncio.create_subprocess_exec(
            *self._container_args(name),
            "--entrypoint",
            self.binary,
            self.image,
            *args,
            start_new_session=True,
            **host_kwargs,
        )
        tracked = _ContainerProcess(process, name)
        self._processes.append(tracked)
        return tracked

    async def verify(self) -> bool:
        stale = await self._inventory(self.stable_label)
        if stale is None or stale:
            return False
        code, output = await self._docker_command(
            "image", "inspect", "--format", "{{.Id}}", self.image
        )
        if code != 0 or output.decode("utf-8", "replace").strip() != self.image:
            return False
        if not self._pin_workspace():
            return False
        if not await self._initialize_volumes():
            return False
        private_probes: list[Path] = []
        name = f"rapido-offline-{self.run_token}-preflight"
        try:
            for root in self.private_roots:
                probe = root / f".rapido-private-probe-{secrets.token_hex(12)}"
                probe.write_bytes(b"private\n")
                probe.chmod(0o600)
                private_probes.append(probe)
            command = (
                'test -r "$1/auth.json" || exit 2; test -d "$2" || exit 3; '
                '(: > "$2/.write-probe") 2>/dev/null && exit 3; shift 2; '
                'for private_path do test ! -e "$private_path" || exit 3; done'
            )
            code, output = await self._docker_command(
                *self._container_args(name)[1:],
                "--entrypoint",
                "/bin/sh",
                self.image,
                "-c",
                command,
                "sh",
                str(self.codex_home),
                str(self.workspace_root),
                *(str(path) for path in private_probes),
                timeout=20.0,
            )
            return code == 0 and output == b""
        except OSError:
            return False
        finally:
            await self._docker_command("rm", "-f", name)
            for path in private_probes:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

    @staticmethod
    def _group_alive(process_group: int) -> bool:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    async def cleanup_record(self) -> Mapping[str, object]:
        for helper in tuple(self._helpers):
            self._kill_process_group(helper)
        for helper in tuple(self._helpers):
            try:
                await asyncio.wait_for(helper.wait(), timeout=4.0)
            except TimeoutError:
                continue
            if helper.returncode is not None and helper in self._helpers:
                self._helpers.remove(helper)
        for process in self._processes:
            if self._group_alive(process.pid):
                process.terminate()
        for process in self._processes:
            await self._docker_command("rm", "-f", process.container_name)
        deadline = asyncio.get_running_loop().time() + 4.0
        while any(self._group_alive(process.pid) for process in self._processes):
            if asyncio.get_running_loop().time() >= deadline:
                break
            await asyncio.sleep(0.02)
        for process in self._processes:
            if self._group_alive(process.pid):
                process.kill()
        inventory = await self._inventory(self.run_label)
        containers = () if inventory is None else inventory
        for name in containers:
            if name in {self.workspace_volume, self.codex_volume}:
                await self._docker_command("volume", "rm", "-f", name)
            else:
                await self._docker_command("rm", "-f", name)
        inventory = await self._inventory(self.run_label)
        containers = ("inventory-failed",) if inventory is None else inventory
        client_groups = sum(self._group_alive(process.pid) for process in self._processes)
        helper_groups = sum(self._group_alive(process.pid) for process in self._helpers)
        active = len(containers) + client_groups + helper_groups
        if self._workspace_descriptor >= 0:
            os.close(self._workspace_descriptor)
            self._workspace_descriptor = -1
        if self._auth_descriptor >= 0:
            os.close(self._auth_descriptor)
            self._auth_descriptor = -1
        if self._codex_descriptor >= 0:
            os.close(self._codex_descriptor)
            self._codex_descriptor = -1
        return {"process_absent": active == 0, "active_process_count": active}


class _OfflineCodexClient(CodexAppClient):
    """Synchronize a verified host lane before exposing its path to app-server."""

    def __init__(self, *, boundary: _DockerRuntimeBoundary, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._offline_boundary = boundary

    async def start_thread(self, **kwargs: Any) -> str:
        selected = Path(kwargs.get("cwd") or self.cwd or Path.cwd())
        await self._offline_boundary.sync_workspace(selected)
        return await super().start_thread(**kwargs)


def build_native_offline_plan(registration: OfflineRunRegistration) -> OfflineRunPlan:
    """Construct the scored native runtime with a fixed credential-free child environment."""
    if type(registration) is not OfflineRunRegistration:
        raise ConfigError("offline entry point requires an offline run registration")
    config = registration.config
    if registration.isolation_backend != "docker-container-v1":
        raise ConfigError("offline native runner requires the registered isolation backend")
    child_env = offline_child_env(config)
    boundary = _DockerRuntimeBoundary(
        workspace_root=config.work_root,
        codex_home=config.codex_home,
        private_roots=registration.private_roots,
        binary=config.codex_binary,
        image=config.runner_image,
        max_workspace_bytes=config.max_lane_workspace_bytes,
    )
    runtime = _OfflineCodexClient(
        boundary=boundary,
        env=child_env,
        binary=config.codex_binary,
        model=config.model,
        reasoning_effort=config.reasoning_effort,
        cwd=config.work_root,
        max_workspace_bytes=config.max_lane_workspace_bytes,
        process_factory=boundary.process_factory,
    )
    return OfflineRunPlan(
        config=config,
        board_factory=registration.board_factory,
        run_root=registration.run_root,
        receipt_path=registration.receipt_path,
        private_roots=registration.private_roots,
        isolation_backend=registration.isolation_backend,
        runtime=runtime,
        isolation_probe=boundary.verify,
        runtime_cleanup_probe=boundary.cleanup_record,
    )


def _private_directory(path: Path, label: str) -> None:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o077
        or not os.access(path, os.R_OK | os.W_OK | os.X_OK)
    ):
        raise ConfigError(f"{label} must be owner-only, owned, and writable")


def _prove_removable_parent(path: Path) -> None:
    probe = path / f".rapido-removal-probe-{secrets.token_hex(12)}"
    try:
        probe.mkdir(mode=0o700)
        probe.rmdir()
    except OSError:
        try:
            probe.rmdir()
        except OSError:
            pass
        raise ConfigError("offline run parent failed the removability probe") from None


def preflight_offline_plan(plan: OfflineRunPlan) -> None:
    """Prove fresh/removable local state before constructing any solver work."""
    assert_offline_environment()
    if type(plan.config) is not OfflineRuntimeConfig:
        raise ConfigError("offline runner requires the explicit offline config adapter")
    if not callable(plan.board_factory):
        raise ConfigError("offline Board factory is unavailable")
    if plan.isolation_backend not in {
        "docker-container-v1",
        "synthetic-container-controller-v1",
        "synthetic-controller-v1",
    }:
        raise ConfigError("offline isolation backend is not registered")
    if not callable(plan.isolation_probe) or not callable(plan.runtime_cleanup_probe):
        raise ConfigError("offline isolation and cleanup probes are required")
    if not plan.run_root.is_absolute() or not plan.receipt_path.is_absolute():
        raise ConfigError("offline run and receipt paths must be absolute")
    if plan.run_root == plan.receipt_path or plan.run_root in plan.receipt_path.parents:
        raise ConfigError("offline receipt must survive outside the removable run root")
    if plan.run_root.exists() or plan.run_root.is_symlink():
        raise ConfigError("offline run root must begin absent")
    parent = plan.run_root.parent
    receipt_parent = plan.receipt_path.parent
    _private_directory(parent, "offline run parent")
    _private_directory(receipt_parent, "offline receipt parent")
    _prove_removable_parent(parent)
    if not plan.private_roots:
        raise ConfigError("offline private roots must be registered")
    normalized_private: set[Path] = set()
    for root in plan.private_roots:
        if not isinstance(root, Path) or not root.is_absolute():
            raise ConfigError("offline private roots must be absolute Path values")
        _private_directory(root, "offline private root")
        resolved = root.resolve(strict=True)
        if resolved in normalized_private:
            raise ConfigError("offline private roots must be unique")
        normalized_private.add(resolved)
        if (
            resolved == plan.run_root
            or resolved in plan.run_root.parents
            or plan.run_root in resolved.parents
            or resolved == plan.config.codex_home
            or resolved in plan.config.codex_home.parents
            or plan.config.codex_home in resolved.parents
        ):
            raise ConfigError("offline private roots overlap scored runtime paths")
    expected_state = plan.run_root / "state.sqlite3"
    expected_work = plan.run_root / "work"
    if plan.config.state_path != expected_state or plan.config.work_root != expected_work:
        raise ConfigError("offline state and work paths must be exact run-owned children")
    if plan.receipt_path.exists() or plan.receipt_path.is_symlink():
        raise ConfigError("offline receipt path must begin absent")
    validate_codex_home(plan.config.codex_home)
    supervisor_lock = plan.config.codex_home / ".rapido-supervisor.lock"
    if supervisor_lock.exists() or supervisor_lock.is_symlink():
        raise ConfigError("offline native supervisor lock must begin absent")


def _assert_public(value: object, *, key: str = "") -> None:
    normalized_key = key.lower()
    if normalized_key in _FORBIDDEN_PUBLIC_KEYS:
        raise ValueError("offline public receipt contains a forbidden field")
    if value is None or type(value) in {bool, int, float}:
        return
    if isinstance(value, str):
        if normalized_key == "runner_image" and re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            return
        if normalized_key in {"base_git_commit", "implementation_git_commit"} and re.fullmatch(
            r"[0-9a-f]{40}", value
        ):
            return
        if len(value) > 4096 or _FORBIDDEN_PUBLIC_TEXT.search(value):
            raise ValueError("offline public receipt contains forbidden text")
        return
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            if type(child_key) is not str:
                raise ValueError("offline public receipt has a non-text field")
            _assert_public(child, key=child_key)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            _assert_public(child, key=key)
        return
    raise ValueError("offline public receipt contains an unsupported value")


def validate_offline_acceptance_receipt(receipt: object) -> None:
    """Validate the closed, candidate-free stage receipt."""
    if not isinstance(receipt, Mapping) or set(receipt) != {
        "schema",
        "status",
        "effective_config",
        "run_report",
        "board",
        "cleanup",
    }:
        raise ValueError("offline receipt shape is invalid")
    if receipt.get("schema") != OFFLINE_ACCEPTANCE_SCHEMA:
        raise ValueError("offline receipt schema is invalid")
    if receipt.get("status") not in {"completed", "deadline", "failed", "interrupted"}:
        raise ValueError("offline receipt status is invalid")
    cleanup = receipt.get("cleanup")
    if not isinstance(cleanup, Mapping) or set(cleanup) != {
        "board_closed",
        "model_isolation_verified",
        "native_lock_absent",
        "native_process_absent",
        "native_active_process_count",
        "run_root_absent",
        "exact_cleanup",
    }:
        raise ValueError("offline cleanup receipt is invalid")
    if (
        any(
            type(cleanup[name]) is not bool
            for name in (
                "board_closed",
                "model_isolation_verified",
                "native_lock_absent",
                "native_process_absent",
                "run_root_absent",
                "exact_cleanup",
            )
        )
        or type(cleanup["native_active_process_count"]) is not int
    ):
        raise ValueError("offline cleanup evidence must be boolean")
    expected_cleanup = (
        cleanup["board_closed"]
        and cleanup["model_isolation_verified"]
        and cleanup["native_lock_absent"]
        and cleanup["native_process_absent"]
        and cleanup["native_active_process_count"] == 0
        and cleanup["run_root_absent"]
    )
    if cleanup["exact_cleanup"] is not expected_cleanup:
        raise ValueError("offline cleanup summary is inconsistent")
    if receipt.get("status") in {"completed", "deadline", "interrupted"} and not cleanup.get(
        "exact_cleanup"
    ):
        raise ValueError("offline terminal receipt lacks exact cleanup")
    effective = receipt.get("effective_config")
    board = receipt.get("board")
    if not isinstance(effective, Mapping) or not isinstance(board, Mapping):
        raise TypeError("offline receipt registration records are invalid")
    expected_effective_keys = {
        "schema",
        "offline_profile_id",
        "catalogue_version",
        "board_implementation_version",
        "runner_image",
        "task_registrations",
        "service_runtime",
        "model",
        "reasoning_effort",
        "specialist_model",
        "specialist_reasoning_efforts",
        "lead_lanes",
        "peer_profile",
        "concurrency",
        "active_challenges",
        "episodes_per_challenge",
        "dynamic_concurrency",
        "attempts_per_challenge",
        "attempt_seconds",
        "board_timeout_seconds",
        "instance_ready_seconds",
        "instance_cleanup_seconds",
        "run_seconds",
        "max_artifact_bytes",
        "max_challenge_bytes",
        "max_workspace_bytes",
        "max_challenge_workspace_bytes",
        "max_lane_workspace_bytes",
        "memory_arm",
        "selected_challenge_count",
        "submit_candidates",
        "manage_dynamic_instances",
        "watch_board",
    }
    if set(effective) != expected_effective_keys:
        raise ValueError("offline effective config shape is invalid")
    expected_board_keys = {
        "offline_profile_id",
        "catalogue_version",
        "implementation_version",
        "task_registrations",
        "selected_task_count",
        "solved_task_count",
        "unique_candidate_count",
        "repeat_candidate_count",
        "checker_call_count",
        "attempt_counts",
        "candidates",
        "active_service_count",
        "cleanup_pending_service_count",
        "service_counts",
        "service_runtime",
    }
    if board and set(board) != expected_board_keys:
        raise ValueError("offline Board receipt shape is invalid")
    registrations = effective.get("task_registrations")
    if not isinstance(registrations, list) or not registrations:
        raise ValueError("offline receipt has no frozen task denominator")
    registration_keys = {
        "board_id",
        "task_id",
        "generator_version",
        "checker_version",
        "service_version",
    }
    if any(not isinstance(row, Mapping) or set(row) != registration_keys for row in registrations):
        raise ValueError("offline task registration shape is invalid")
    task_ids = [row["task_id"] for row in registrations]
    if any(not isinstance(task_id, str) or not task_id for task_id in task_ids) or len(
        set(task_ids)
    ) != len(task_ids):
        raise ValueError("offline task registration identity is invalid")
    selected = len(registrations)
    if board:
        candidates = board.get("candidates")
        attempts = board.get("attempt_counts")
        service_counts = board.get("service_counts")
        unique = board.get("unique_candidate_count")
        repeats = board.get("repeat_candidate_count")
        checker_calls = board.get("checker_call_count")
        solved = board.get("solved_task_count")
        if (
            type(unique) is not int
            or unique < 0
            or type(repeats) is not int
            or repeats < 0
            or type(checker_calls) is not int
            or checker_calls != unique
            or type(solved) is not int
            or not 0 <= solved <= selected
            or not isinstance(candidates, list)
            or len(candidates) != unique
        ):
            raise ValueError("offline Board candidate accounting is invalid")
        candidate_keys = {"task_id", "candidate_ordinal", "outcome", "repeat_count"}
        if any(
            not isinstance(row, Mapping)
            or set(row) != candidate_keys
            or row.get("task_id") not in task_ids
            or type(row.get("candidate_ordinal")) is not int
            or row["candidate_ordinal"] <= 0
            or row.get("outcome") not in {"correct", "incorrect", "oracle_inconclusive"}
            or type(row.get("repeat_count")) is not int
            or row["repeat_count"] < 0
            for row in candidates
        ):
            raise ValueError("offline Board candidate rows are invalid")
        ordinals_by_task = {
            task_id: sorted(
                row["candidate_ordinal"] for row in candidates if row["task_id"] == task_id
            )
            for task_id in task_ids
        }
        if (
            any(
                ordinals != list(range(1, len(ordinals) + 1))
                for ordinals in ordinals_by_task.values()
            )
            or sum(row["repeat_count"] for row in candidates) != repeats
            or len({row["task_id"] for row in candidates if row["outcome"] == "correct"}) != solved
        ):
            raise ValueError("offline Board candidate rows are inconsistent")
        if (
            not isinstance(attempts, list)
            or len(attempts) != selected
            or {row.get("task_id") for row in attempts if isinstance(row, Mapping)} != set(task_ids)
            or any(
                not isinstance(row, Mapping)
                or set(row) != {"task_id", "attempts"}
                or type(row.get("attempts")) is not int
                or row["attempts"] < 0
                for row in attempts
            )
            or any(
                row["attempts"]
                != sum(candidate["task_id"] == row["task_id"] for candidate in candidates)
                for row in attempts
            )
        ):
            raise ValueError("offline Board attempt accounting is invalid")
        if (
            not isinstance(service_counts, Mapping)
            or set(service_counts) != {"create", "renew", "delete", "absence"}
            or any(type(value) is not int or value < 0 for value in service_counts.values())
        ):
            raise ValueError("offline Board service accounting is invalid")
        expected_registration = {
            "offline_profile_id": effective.get("offline_profile_id"),
            "catalogue_version": effective.get("catalogue_version"),
            "implementation_version": effective.get("board_implementation_version"),
            "task_registrations": registrations,
            "service_runtime": effective.get("service_runtime"),
        }
        if {key: board.get(key) for key in expected_registration} != expected_registration:
            raise ValueError("offline receipt Board registration is not bound to config")
    clean_terminal = receipt.get("status") in {"completed", "deadline", "interrupted"}
    if clean_terminal:
        required_board = {
            "offline_profile_id",
            "catalogue_version",
            "implementation_version",
            "task_registrations",
            "service_runtime",
            "selected_task_count",
            "unique_candidate_count",
            "checker_call_count",
            "active_service_count",
            "cleanup_pending_service_count",
        }
        if not required_board <= set(board):
            raise ValueError("offline terminal receipt Board evidence is incomplete")
        board_selected = board.get("selected_task_count")
        if type(board_selected) is not int or board_selected != selected or board_selected <= 0:
            raise ValueError("offline receipt selected denominator is inconsistent")
        for name in (
            "unique_candidate_count",
            "checker_call_count",
            "active_service_count",
            "cleanup_pending_service_count",
        ):
            if type(board.get(name)) is not int or board[name] < 0:
                raise ValueError("offline terminal receipt Board counts are invalid")
        if board["unique_candidate_count"] != board["checker_call_count"]:
            raise ValueError("offline unique-candidate checker economy is inconsistent")
        if board["active_service_count"] != 0 or board["cleanup_pending_service_count"] != 0:
            raise ValueError("offline terminal receipt retains an owned service")
    run_report = receipt.get("run_report")
    if receipt.get("status") == "interrupted" and run_report is not None:
        raise ValueError("offline interrupted receipt must not retain a run report")
    if run_report is not None:
        if not isinstance(run_report, Mapping) or set(run_report) != _RUN_REPORT_FIELDS:
            raise ValueError("offline terminal receipt run report is invalid")
        if receipt.get("status") in {"completed", "deadline"} and run_report.get(
            "status"
        ) != receipt.get("status"):
            raise ValueError("offline receipt status contradicts the run report")
        if run_report.get("challenge_count") != selected:
            raise ValueError("offline run report denominator is inconsistent")
        terminal_counts = tuple(
            run_report.get(name) for name in ("solved", "unsolved", "unsupported", "errors")
        )
        if (
            any(type(value) is not int or value < 0 for value in terminal_counts)
            or sum(terminal_counts) != selected
        ):
            raise ValueError("offline run report terminal counts are inconsistent")
        if board and (
            run_report.get("solved") != board.get("solved_task_count")
            or run_report.get("submission_correct") != board.get("solved_task_count")
            or run_report.get("submission_http_200_correct") != board.get("solved_task_count")
            or run_report.get("run_local_verified") != board.get("solved_task_count")
        ):
            raise ValueError("offline run report contradicts Board outcomes")
    elif receipt.get("status") in {"completed", "deadline"}:
        raise ValueError("offline terminal receipt run report is missing")
    _assert_public(receipt)


def validate_offline_stage_receipt(receipt: object) -> None:
    """Validate the immutable CAP02 aggregate against derived pass conditions."""
    expected_keys = {
        "schema",
        "evidence_level",
        "source",
        "sentinel_ids",
        "method_results",
        "sentinel_results",
        "candidate_economy",
        "fresh_second_run",
        "owned_lifecycle",
        "existing_board_scenarios",
        "offline_cases",
        "resource_maxima",
        "privacy",
        "limitations",
        "evidence_runs",
        "passed",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != expected_keys:
        raise ValueError("offline stage receipt shape is invalid")
    if receipt["schema"] != OFFLINE_STAGE_ACCEPTANCE_SCHEMA:
        raise ValueError("offline stage receipt schema is invalid")
    if receipt["evidence_level"] != "synthetic_controller_acceptance":
        raise ValueError("offline stage evidence level is invalid")
    source = receipt["source"]
    if not isinstance(source, Mapping) or set(source) != {
        "base_git_commit",
        "implementation_git_commit",
        "implementation_version",
        "production_authority_logic_changed",
        "production_cli_changed",
        "production_container_entrypoint_changed",
    }:
        raise ValueError("offline stage source identity is invalid")
    commits = (source["base_git_commit"], source["implementation_git_commit"])
    if (
        any(
            not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None
            for commit in commits
        )
        or commits[0] == commits[1]
    ):
        raise ValueError("offline stage source commits are invalid")
    if source["implementation_version"] != "offline-board-v1" or any(
        source[name] is not False
        for name in (
            "production_authority_logic_changed",
            "production_cli_changed",
            "production_container_entrypoint_changed",
        )
    ):
        raise ValueError("offline stage source invariants are invalid")
    if receipt["sentinel_ids"] != ["EAS-005", "EAS-006"]:
        raise ValueError("offline stage sentinel denominator is invalid")
    methods = receipt["method_results"]
    if (
        not isinstance(methods, Mapping)
        or set(methods)
        != {
            "identity",
            "negative_identity",
            "list",
            "detail",
            "download",
            "submit",
            "instance",
        }
        or any(result != "passed" for result in methods.values())
    ):
        raise ValueError("offline stage method evidence is incomplete")
    sentinels = receipt["sentinel_results"]
    if not isinstance(sentinels, list) or len(sentinels) != 2:
        raise ValueError("offline stage sentinel results are invalid")
    by_id = {
        row.get("sentinel_id"): row
        for row in sentinels
        if isinstance(row, Mapping) and isinstance(row.get("sentinel_id"), str)
    }
    if set(by_id) != {"EAS-005", "EAS-006"}:
        raise ValueError("offline stage sentinel results are incomplete")
    static = by_id["EAS-005"]
    dynamic = by_id["EAS-006"]
    if set(static) != {
        "sentinel_id",
        "unchanged_control",
        "source_bound_correct",
        "submission_http_200_correct",
        "run_local_verified",
        "exact_cleanup",
    } or set(dynamic) != {
        "sentinel_id",
        "unchanged_control",
        "assigned_target_observations",
        "fresh_service_generations",
        "submission_http_200_correct",
        "run_local_verified",
        "exact_cleanup",
    }:
        raise ValueError("offline stage sentinel result shape is invalid")
    for row in (static, dynamic):
        if (
            row.get("unchanged_control") is not True
            or row.get("submission_http_200_correct") != 1
            or row.get("run_local_verified") != 1
            or row.get("exact_cleanup") is not True
        ):
            raise ValueError("offline stage sentinel acceptance failed")
    if static.get("source_bound_correct") is not True or (
        dynamic.get("assigned_target_observations", 0) < 2
        or dynamic.get("fresh_service_generations", 0) < 2
    ):
        raise ValueError("offline stage sentinel evidence is insufficient")
    economy = receipt["candidate_economy"]
    if (
        not isinstance(economy, Mapping)
        or set(economy)
        != {
            "unique_candidate_count",
            "repeat_candidate_count",
            "checker_call_count",
            "exact_repeat_checker_once_test",
            "public_candidate_values",
            "public_candidate_digests",
        }
        or (
            economy.get("unique_candidate_count") != 2
            or economy.get("repeat_candidate_count") != 0
            or economy.get("checker_call_count") != 2
            or economy.get("exact_repeat_checker_once_test") is not True
            or economy.get("public_candidate_values") != 0
            or economy.get("public_candidate_digests") != 0
        )
    ):
        raise ValueError("offline stage candidate economy failed")
    freshness = receipt["fresh_second_run"]
    if (
        not isinstance(freshness, Mapping)
        or set(freshness)
        != {
            "new_synthetic_identity",
            "zero_initial_solved_state",
            "zero_initial_candidate_cache",
            "zero_initial_service_state",
            "old_run_root_absent",
            "fresh_dynamic_private_state",
            "second_dynamic_run_exact_cleanup",
        }
        or any(value is not True for value in freshness.values())
    ):
        raise ValueError("offline stage fresh-run evidence failed")
    lifecycle = receipt["owned_lifecycle"]
    if not isinstance(lifecycle, Mapping) or set(lifecycle) != {
        "peak_dynamic_leases",
        "sentinel_service_create_count",
        "sentinel_service_delete_count",
        "sentinel_post_delete_absence_count",
        "cancellation_service_create_count",
        "cancellation_service_delete_count",
        "owned_process_create_count",
        "owned_process_delete_count",
        "run_root_create_count",
        "run_root_delete_count",
        "state_create_count",
        "state_delete_count",
        "final_owned_service_count",
        "final_owned_process_count",
        "final_workspace_count",
        "final_state_count",
        "exact_cleanup",
    }:
        raise TypeError("offline stage lifecycle evidence is invalid")
    for name in (
        "final_owned_service_count",
        "final_owned_process_count",
        "final_workspace_count",
        "final_state_count",
    ):
        if lifecycle.get(name) != 0:
            raise ValueError("offline stage final inventory is not empty")
    if (
        lifecycle.get("exact_cleanup") is not True
        or lifecycle.get("peak_dynamic_leases") != 1
        or lifecycle.get("sentinel_service_create_count")
        != lifecycle.get("sentinel_service_delete_count")
        or lifecycle.get("owned_process_create_count")
        != lifecycle.get("owned_process_delete_count")
        or lifecycle.get("run_root_create_count") != lifecycle.get("run_root_delete_count")
        or lifecycle.get("state_create_count") != lifecycle.get("state_delete_count")
    ):
        raise ValueError("offline stage lifecycle accounting failed")
    expected_scenarios = {
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
    }
    scenarios = receipt["existing_board_scenarios"]
    if (
        not isinstance(scenarios, list)
        or {row.get("scenario_id") for row in scenarios if isinstance(row, Mapping)}
        != expected_scenarios
        or any(
            not isinstance(row, Mapping)
            or set(row) != {"scenario_id", "passed"}
            or row.get("passed") is not True
            for row in scenarios
        )
    ):
        raise ValueError("offline stage Board scenario evidence failed")
    cases = receipt["offline_cases"]
    if (
        not isinstance(cases, list)
        or [row.get("case_id") for row in cases if isinstance(row, Mapping)]
        != [f"OB-{index:02d}" for index in range(1, 11)]
        or any(
            not isinstance(row, Mapping)
            or set(row) != {"case_id", "passed"}
            or row.get("passed") is not True
            for row in cases
        )
    ):
        raise ValueError("offline stage focused cases failed")
    resources = receipt["resource_maxima"]
    expected_resources = {
        "dynamic_leases": 1,
        "service_cpu_limit_cores": 1.0,
        "service_memory_limit_bytes": 256 * 1024 * 1024,
        "service_pids_limit": 64,
        "service_writable_storage_limit_bytes": 64 * 1024 * 1024,
        "service_hard_lifetime_seconds": 900,
        "service_internal_network": True,
        "service_arbitrary_egress_denied": True,
        "service_published_loopback_only": True,
    }
    if not isinstance(resources, Mapping) or dict(resources) != expected_resources:
        raise ValueError("offline stage resource evidence is invalid")
    privacy = receipt["privacy"]
    privacy_keys = {
        "candidate_values_absent",
        "candidate_digests_absent",
        "private_paths_absent",
        "target_authorities_absent",
        "credentials_absent",
        "raw_model_output_absent",
        "raw_tool_output_absent",
    }
    if (
        not isinstance(privacy, Mapping)
        or set(privacy) != privacy_keys
        or any(value is not True for value in privacy.values())
    ):
        raise ValueError("offline stage privacy evidence failed")
    evidence = receipt["evidence_runs"]
    expected_suites = {
        "offline-focused",
        "board-contract",
        "authority-container",
        "full-suite",
    }
    if (
        not isinstance(evidence, list)
        or {row.get("suite_id") for row in evidence if isinstance(row, Mapping)} != expected_suites
        or any(
            not isinstance(row, Mapping)
            or set(row) != {"suite_id", "passed", "failed", "skipped"}
            or row.get("failed") != 0
            or type(row.get("passed")) is not int
            or row["passed"] <= 0
            or type(row.get("skipped")) is not int
            or row["skipped"] < 0
            for row in evidence
        )
    ):
        raise ValueError("offline stage executable evidence is incomplete")
    limitations = receipt["limitations"]
    if not isinstance(limitations, list) or set(limitations) != {
        "synthetic_sentinels_only",
        "no_official_board_access",
        "no_scored_model_task",
        "model_resource_sampling_deferred_to_cap_05",
    }:
        raise ValueError("offline stage limitations are incomplete")
    if receipt["passed"] is not True:
        raise ValueError("offline stage did not pass")
    _assert_public(receipt)


def _atomic_receipt(path: Path, receipt: Mapping[str, object]) -> None:
    payload = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


async def _drain_despite_cancellation(awaitable: Awaitable[Any]) -> tuple[Any, bool]:
    """Finish one bounded cleanup operation even if cancellation repeats."""
    task = asyncio.create_task(awaitable)
    interrupted = False
    while True:
        try:
            return await asyncio.shield(task), interrupted
        except asyncio.CancelledError:
            interrupted = True
            current = asyncio.current_task()
            if current is not None and hasattr(current, "uncancel"):
                current.uncancel()


async def _close_offline_board(close: Callable[[], object]) -> None:
    result = await asyncio.to_thread(close)
    if asyncio.iscoroutine(result):
        await result


async def _run_cleanup_probe(
    probe: Callable[[], Awaitable[Mapping[str, object]] | Mapping[str, object]],
) -> Mapping[str, object]:
    result = probe()
    if asyncio.iscoroutine(result):
        result = await result
    return result


def _descriptor_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise OSError("offline owned directory changed type")
    return metadata.st_dev, metadata.st_ino


def _directory_descriptor_path(descriptor: int) -> str | None:
    """Return the kernel's path for an open directory, where supported."""
    try:
        if sys.platform == "darwin":
            raw = fcntl.fcntl(descriptor, 50, b"\0" * 1024)  # F_GETPATH
            return raw.split(b"\0", 1)[0].decode("utf-8")
        if sys.platform.startswith("linux"):
            return os.readlink(f"/proc/self/fd/{descriptor}")
    except (OSError, UnicodeError, ValueError):
        return None
    return None


def _directory_descriptor_was_removed(descriptor: int, original_path: str | None) -> bool:
    """Prove the pinned directory, rather than a substituted pathname, was removed."""
    current_path = _directory_descriptor_path(descriptor)
    if sys.platform == "darwin":
        return original_path is not None and current_path == original_path
    if sys.platform.startswith("linux") and original_path is not None:
        return os.fstat(descriptor).st_nlink == 0 or current_path in {
            original_path,
            f"{original_path} (deleted)",
        }
    return os.fstat(descriptor).st_nlink == 0


def _remove_owned_tree(descriptor: int) -> None:
    """Remove children relative to one pinned, already-proven owned directory."""
    for name in sorted(os.listdir(descriptor)):
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                identity = _descriptor_identity(child)
                original_path = _directory_descriptor_path(child)
                if identity != (metadata.st_dev, metadata.st_ino):
                    raise OSError("offline owned directory changed identity")
                _remove_owned_tree(child)
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != identity:
                    raise OSError("offline owned directory changed before removal")
                os.rmdir(name, dir_fd=descriptor)
                try:
                    os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise OSError("offline owned directory removal was not exact")
                if not _directory_descriptor_was_removed(child, original_path):
                    raise OSError("offline owned directory removal was not exact")
            finally:
                os.close(child)
        elif stat.S_ISREG(metadata.st_mode):
            child = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                dir_fd=descriptor,
            )
            try:
                pinned = os.fstat(child)
                if (pinned.st_dev, pinned.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise OSError("offline owned file changed identity")
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise OSError("offline owned file changed before removal")
                os.unlink(name, dir_fd=descriptor)
                if os.fstat(child).st_nlink != 0:
                    raise OSError("offline owned file removal was not exact")
            finally:
                os.close(child)
        elif stat.S_ISLNK(metadata.st_mode):
            raise OSError("offline owned tree contains a symbolic link")
        else:
            raise OSError("offline owned tree contains an unsupported entry")
    if os.listdir(descriptor):
        raise OSError("offline owned directory changed during removal")


async def execute_offline_plan(plan: OfflineRunPlan) -> dict[str, object]:
    """Run unchanged durable control, sanitize evidence, then delete exact run state."""
    preflight_offline_plan(plan)
    parent_descriptor = os.open(
        plan.run_root.parent,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    run_descriptor = -1
    try:
        os.mkdir(plan.run_root.name, mode=0o700, dir_fd=parent_descriptor)
        run_descriptor = os.open(
            plan.run_root.name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        run_identity = _descriptor_identity(run_descriptor)
        run_descriptor_path = _directory_descriptor_path(run_descriptor)
        os.mkdir("work", mode=0o700, dir_fd=run_descriptor)
    except BaseException:
        if run_descriptor >= 0:
            os.close(run_descriptor)
        os.close(parent_descriptor)
        raise
    report: dict[str, object] | None = None
    status = "failed"
    board_closed = False
    isolation_verified = False
    runtime_cleanup: Mapping[str, object] = {
        "process_absent": False,
        "active_process_count": 1,
    }
    board: BoardLike | None = None
    try:
        board = plan.board_factory()
        if (
            getattr(board, "timeout", None) != float(plan.config.board_timeout_seconds)
            or getattr(board, "instance_ready_timeout", None)
            != float(plan.config.instance_ready_seconds)
            or getattr(board, "instance_cleanup_timeout", None)
            != float(plan.config.instance_cleanup_seconds)
        ):
            raise ConfigError("offline Board lifecycle budgets do not match the frozen config")
        registration = getattr(board, "registration_record", None)
        if not callable(registration) or registration() != plan.config.offline_board_registration():
            raise ConfigError("offline Board does not match the frozen registration")
        isolation_roots = getattr(board, "isolation_roots", None)
        if not callable(isolation_roots):
            raise ConfigError("offline Board does not expose its private isolation roots")
        observed_roots = {Path(path).resolve(strict=True) for path in isolation_roots()}
        registered_roots = {path.resolve(strict=True) for path in plan.private_roots}
        if not observed_roots or not observed_roots <= registered_roots:
            raise ConfigError("offline Board private roots are not fully isolated")
        isolated = getattr(board, "is_process_isolated", None)
        if plan.isolation_backend in {
            "docker-container-v1",
            "synthetic-container-controller-v1",
        } and (not callable(isolated) or isolated() is not True):
            raise ConfigError("offline native run requires process-isolated callbacks")
        board_preflight = getattr(board, "preflight", None)
        if not callable(board_preflight):
            raise ConfigError("offline Board has no closed preflight")
        preflight_result = board_preflight()
        if asyncio.iscoroutine(preflight_result):
            preflight_result = await preflight_result
        if preflight_result is not True:
            raise ConfigError("offline Board preflight did not close")
        probe_result = plan.isolation_probe()
        if asyncio.iscoroutine(probe_result):
            probe_result = await probe_result
        isolation_verified = probe_result is True
        if not isolation_verified:
            raise ConfigError("scored runtime private-root isolation was not proven")
        result = await DurableJobControl.drive(
            plan.config,
            board=board,
            runtime=plan.runtime,
        )
        report = asdict(result)
        status = result.status if result.status in {"completed", "deadline"} else "failed"
    except asyncio.CancelledError:
        status = "interrupted"
    except (KeyboardInterrupt, SystemExit):
        status = "interrupted"
    except Exception:  # noqa: BLE001 - outer boundary emits only a closed label
        status = "failed"
    finally:
        close = getattr(board, "close", None)
        try:
            if callable(close):
                _result, cleanup_interrupted = await _drain_despite_cancellation(
                    _close_offline_board(close)
                )
                if cleanup_interrupted:
                    status = "interrupted"
                board_closed = True
            else:
                board_closed = False
        except Exception:  # noqa: BLE001 - cleanup failure is projected as one boolean
            board_closed = False
        try:
            cleanup_result, cleanup_interrupted = await _drain_despite_cancellation(
                _run_cleanup_probe(plan.runtime_cleanup_probe)
            )
            if cleanup_interrupted:
                status = "interrupted"
            if isinstance(cleanup_result, Mapping):
                runtime_cleanup = cleanup_result
        except Exception:  # noqa: BLE001 - cleanup proof fails closed
            runtime_cleanup = {"process_absent": False, "active_process_count": 1}

    snapshot = getattr(board, "public_snapshot", None)
    board_record = snapshot() if callable(snapshot) else {}
    if not isinstance(board_record, Mapping):
        board_record = {}
        status = "failed"

    supervisor_lock = plan.config.codex_home / ".rapido-supervisor.lock"
    process_absent = runtime_cleanup.get("process_absent") is True
    active_process_count = runtime_cleanup.get("active_process_count")
    if type(active_process_count) is not int or active_process_count < 0:
        process_absent = False
        active_process_count = 1
    safe_to_erase = board_closed and process_absent and active_process_count == 0
    run_root_removed = False
    if safe_to_erase:
        try:
            if supervisor_lock.exists() or supervisor_lock.is_symlink():
                supervisor_lock.unlink()
            current = os.stat(
                plan.run_root.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (current.st_dev, current.st_ino) != run_identity:
                raise OSError("offline run root changed identity")
            _remove_owned_tree(run_descriptor)
            current = os.stat(
                plan.run_root.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (current.st_dev, current.st_ino) != run_identity:
                raise OSError("offline run root changed before removal")
            os.rmdir(plan.run_root.name, dir_fd=parent_descriptor)
            try:
                os.stat(
                    plan.run_root.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise OSError("offline run root removal was not exact")
            if not _directory_descriptor_was_removed(run_descriptor, run_descriptor_path):
                raise OSError("offline run root removal was not exact")
            run_root_removed = True
        except OSError:
            status = "failed"
    else:
        status = "failed"
    os.close(run_descriptor)
    os.close(parent_descriptor)

    cleanup = {
        "board_closed": board_closed,
        "model_isolation_verified": isolation_verified,
        "native_lock_absent": not supervisor_lock.exists() and not supervisor_lock.is_symlink(),
        "native_process_absent": process_absent,
        "native_active_process_count": active_process_count,
        "run_root_absent": run_root_removed
        and not plan.run_root.exists()
        and not plan.run_root.is_symlink(),
    }
    cleanup["exact_cleanup"] = (
        cleanup["board_closed"]
        and cleanup["model_isolation_verified"]
        and cleanup["native_lock_absent"]
        and cleanup["native_process_absent"]
        and cleanup["native_active_process_count"] == 0
        and cleanup["run_root_absent"]
    )
    if cleanup["exact_cleanup"] is not True:
        status = "failed"
    if status == "interrupted":
        report = None
    receipt: dict[str, object] = {
        "schema": OFFLINE_ACCEPTANCE_SCHEMA,
        "status": status,
        "effective_config": plan.config.public_record(),
        "run_report": report,
        "board": dict(board_record),
        "cleanup": cleanup,
    }
    validate_offline_acceptance_receipt(receipt)
    _atomic_receipt(plan.receipt_path, receipt)
    return receipt
