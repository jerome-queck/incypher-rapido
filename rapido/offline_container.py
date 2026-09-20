"""Resource-bounded Docker boundaries for private offline callbacks.

The model never receives these objects.  Candidate bytes cross only an attached stdin pipe;
private worker output stays inside this controller and is projected to closed public shapes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import selectors
import signal
import socket
import stat
import struct
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .offline_process import (
    CHECKER_REQUEST_SCHEMA,
    CHECKER_RESPONSE_SCHEMA,
    SERVICE_REQUEST_SCHEMA,
    SERVICE_RESPONSE_SCHEMA,
    CleanupProof,
    OfflineProcessError,
)

_IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_MAX_CANDIDATE_BYTES = 4096
_MAX_OUTPUT_BYTES = 16 * 1024
_MAX_STDERR_BYTES = 4096
_CONTAINER_UID = 10001
_PROXY_WRITABLE_BYTES = 8 * 1024 * 1024
_PROXY_CPU_CORES = 0.25
_PROXY_MEMORY_BYTES = 64 * 1024 * 1024
_PROXY_PIDS = 16


def _writable_allocations(total: int) -> tuple[int, int, int, int]:
    """Split the declared writable ceiling across tmp, image volumes, and shm."""
    auxiliary = total // 8
    shared_memory = total // 4
    temporary = total - (2 * auxiliary) - shared_memory
    return temporary, auxiliary, auxiliary, shared_memory


@dataclass(frozen=True)
class ServiceResourceProfile:
    """Frozen limits for one offline-owned dynamic service."""

    profile_id: str = "small-v1"
    cpu_cores: float = 1.0
    memory_bytes: int = 256 * 1024 * 1024
    pids_limit: int = 64
    writable_tmpfs_bytes: int = 64 * 1024 * 1024
    internal_port: int = 8080
    hard_lifetime_seconds: int = 900

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.profile_id) is None:
            raise OfflineProcessError("resource_profile_invalid")
        if not 0.5 <= self.cpu_cores <= 4.0:
            raise OfflineProcessError("resource_profile_invalid")
        if not 128 * 1024 * 1024 <= self.memory_bytes <= 2 * 1024 * 1024 * 1024:
            raise OfflineProcessError("resource_profile_invalid")
        if not 32 <= self.pids_limit <= 256:
            raise OfflineProcessError("resource_profile_invalid")
        if not 16 * 1024 * 1024 <= self.writable_tmpfs_bytes <= 512 * 1024 * 1024:
            raise OfflineProcessError("resource_profile_invalid")
        if not 1024 <= self.internal_port <= 65535:
            raise OfflineProcessError("resource_profile_invalid")
        if not 5 <= self.hard_lifetime_seconds <= 7200:
            raise OfflineProcessError("resource_profile_invalid")

    def public_record(self, image: str, source_version: str) -> dict[str, object]:
        return {
            "backend": "docker-service-v1",
            "runner_image": image,
            "source_version": source_version,
            "profile_id": self.profile_id,
            "cpu_cores": self.cpu_cores,
            "memory_bytes": self.memory_bytes,
            "pids_limit": self.pids_limit,
            "writable_tmpfs_bytes": self.writable_tmpfs_bytes,
            "internal_port": self.internal_port,
            "hard_lifetime_seconds": self.hard_lifetime_seconds,
            "internal_network": True,
            "arbitrary_egress": False,
            "published_loopback_only": True,
        }


def _closed_identifier(value: str, code: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise OfflineProcessError(code)
    return value


def _remaining(deadline_ns: int) -> float:
    return max(0.0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)


def _deadline(value: int) -> int:
    if type(value) is not int or value <= time.monotonic_ns():
        raise OfflineProcessError("deadline_expired")
    return value


def _private_source(
    path: Path,
    roots: tuple[Path, ...],
    expected_sha256: str,
    expected_identity: tuple[int, int] | None = None,
) -> tuple[tuple[int, int], bytes]:
    if not path.is_absolute() or not roots:
        raise OfflineProcessError("worker_entrypoint_invalid")
    descriptor = -1
    try:
        resolved = path.resolve(strict=True)
        descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        payload = bytearray()
        while len(payload) <= 1024 * 1024:
            chunk = os.read(descriptor, min(64 * 1024, 1024 * 1024 + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
    except OSError:
        raise OfflineProcessError("worker_entrypoint_invalid") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity = (metadata.st_dev, metadata.st_ino)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or len(payload) > 1024 * 1024
        or not any(resolved == root or root in resolved.parents for root in roots)
        or hashlib.sha256(payload).hexdigest() != expected_sha256
        or (expected_identity is not None and identity != expected_identity)
    ):
        raise OfflineProcessError("worker_entrypoint_invalid")
    return identity, bytes(payload)


class _DockerOwner:
    process_isolated = True
    descendant_confined = True

    def __init__(
        self,
        *,
        worker_entrypoint: Path,
        private_roots: tuple[Path, ...],
        worker_sha256: str,
        image: str,
        role: str,
        ownership_scope: str,
    ) -> None:
        docker = subprocess.run(
            ["/usr/bin/which", "docker"],
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not docker:
            raise OfflineProcessError("docker_unavailable")
        if _IMAGE.fullmatch(image) is None or re.fullmatch(r"[0-9a-f]{64}", worker_sha256) is None:
            raise OfflineProcessError("worker_registration_invalid")
        roots = tuple(Path(root).resolve(strict=True) for root in private_roots)
        for root in roots:
            metadata = root.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
            ):
                raise OfflineProcessError("private_roots_invalid")
        self.worker_entrypoint = Path(worker_entrypoint).resolve(strict=True)
        self.private_roots = roots
        self.worker_sha256 = worker_sha256
        self._source_identity, _payload = _private_source(
            self.worker_entrypoint, self.private_roots, worker_sha256
        )
        self.image = image
        self.docker = docker
        self.role = _closed_identifier(role, "role_invalid")
        self.ownership_scope = _closed_identifier(ownership_scope, "ownership_scope_invalid")
        self.run_token = secrets.token_hex(16)
        self.stable_label = f"rapido.offline.{self.role}.owner={self.ownership_scope}"
        self.run_label = f"rapido.offline.{self.role}.run={self.run_token}"
        self.worker_volume = f"rapido-offline-{self.role}-worker-{self.run_token}"
        self._worker_volume_ready = False
        self._worker_volume_created = False
        self._host_env = {
            "HOME": os.environ.get("HOME", "/tmp"),
            "PATH": f"{Path(docker).parent}:/usr/local/bin:/usr/bin:/bin",
        }
        self._lock = threading.RLock()
        self.spawn_count = 0
        self.reaped_count = 0
        self.peak_active_processes = 0
        self.last_cleanup_proof = CleanupProof(0, 0, 0, 0, 0, True)

    def _capture_source(self) -> bytes | None:
        try:
            _identity, payload = _private_source(
                self.worker_entrypoint,
                self.private_roots,
                self.worker_sha256,
                self._source_identity,
            )
            return payload
        except OfflineProcessError:
            return None

    def _command(
        self,
        *args: str,
        input_bytes: bytes | None = None,
        timeout: float = 10.0,
    ) -> tuple[int, bytes]:
        if timeout <= 0:
            raise OfflineProcessError("deadline_expired")
        try:
            result = subprocess.run(
                (self.docker, *args),
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self._host_env,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise OfflineProcessError("docker_command_failed") from None
        if len(result.stdout) > 64 * 1024:
            raise OfflineProcessError("docker_output_limit")
        return result.returncode, result.stdout

    def _command_input(
        self,
        *args: str,
        payload: bytes,
        timeout: float = 20.0,
    ) -> tuple[int, bytes]:
        return self._command(*args, input_bytes=payload, timeout=timeout)

    def _owned_objects(
        self, label: str, deadline_ns: int
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        deadline = _deadline(deadline_ns)
        groups: list[tuple[str, ...]] = []
        for command in (
            ("ps", "-a", "--filter", f"label={label}", "--format", "{{.Names}}"),
            ("network", "ls", "--filter", f"label={label}", "--format", "{{.Name}}"),
            ("volume", "ls", "--filter", f"label={label}", "--format", "{{.Name}}"),
        ):
            code, output = self._command(*command, timeout=_remaining(deadline))
            if code != 0:
                raise OfflineProcessError("docker_inventory_failed")
            groups.append(
                tuple(line for line in output.decode("utf-8", "replace").splitlines() if line)
            )
        return groups[0], groups[1], groups[2]

    def _object_names(self, label: str, deadline_ns: int) -> tuple[str, ...]:
        containers, networks, volumes = self._owned_objects(label, deadline_ns)
        return (*containers, *networks, *volumes)

    def inventory(self, deadline_ns: int) -> int:
        deadline = _deadline(deadline_ns)
        names = set(self._object_names(self.stable_label, deadline))
        if self._worker_volume_ready:
            names.discard(self.worker_volume)
        return len(names)

    def _ensure_worker_volume(self, deadline_ns: int, payload: bytes) -> bool:
        if self._worker_volume_ready:
            return True
        if self.inventory(deadline_ns) != 0:
            return False
        code, _ = self._command(
            "volume",
            "create",
            "--label",
            self.stable_label,
            "--label",
            self.run_label,
            self.worker_volume,
            timeout=_remaining(deadline_ns),
        )
        if code != 0:
            return False
        self._worker_volume_created = True
        setup = f"rapido-offline-{self.role}-setup-{self.run_token}"
        temporary, auth, state, shared_memory = _writable_allocations(64 * 1024 * 1024)
        script = (
            "umask 077; cat > /worker/private-worker.py; "
            f"chown {_CONTAINER_UID}:{_CONTAINER_UID} /worker/private-worker.py; "
            "chmod 600 /worker/private-worker.py"
        )
        code, _ = self._command_input(
            "run",
            "--rm",
            "--interactive",
            "--pull",
            "never",
            "--name",
            setup,
            "--label",
            self.stable_label,
            "--label",
            self.run_label,
            "--network",
            "none",
            "--shm-size",
            str(shared_memory),
            "--tmpfs",
            f"/tmp:rw,nosuid,nodev,noexec,size={temporary}",
            "--tmpfs",
            f"/auth/codex:rw,nosuid,nodev,noexec,size={auth}",
            "--tmpfs",
            f"/state:rw,nosuid,nodev,noexec,size={state}",
            "--user",
            "0:0",
            "--mount",
            f"type=volume,src={self.worker_volume},dst=/worker",
            "--entrypoint",
            "/bin/sh",
            self.image,
            "-c",
            script,
            payload=payload,
            timeout=_remaining(deadline_ns),
        )
        self._worker_volume_ready = code == 0
        return self._worker_volume_ready

    def _common_preflight(self, deadline_ns: int) -> bool:
        deadline = _deadline(deadline_ns)
        if self.inventory(deadline) != 0:
            return False
        payload = self._capture_source()
        if payload is None:
            return False
        code, output = self._command(
            "image", "inspect", "--format", "{{.Id}}", self.image, timeout=_remaining(deadline)
        )
        return (
            code == 0
            and output.decode("utf-8", "replace").strip() == self.image
            and self._ensure_worker_volume(deadline, payload)
        )

    def _base_container_args(
        self, name: str, *, writable_bytes: int = 64 * 1024 * 1024
    ) -> list[str]:
        _temporary, auth, state, shared_memory = _writable_allocations(writable_bytes)
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
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--log-driver",
            "none",
            "--shm-size",
            str(shared_memory),
            "--tmpfs",
            f"/auth/codex:rw,nosuid,nodev,noexec,size={auth}",
            "--tmpfs",
            f"/state:rw,nosuid,nodev,noexec,size={state}",
            "--user",
            f"{_CONTAINER_UID}:{_CONTAINER_UID}",
            "--mount",
            f"type=volume,src={self.worker_volume},dst=/opt/rapido,readonly",
            "--entrypoint",
            "/opt/venv/bin/python3",
        ]

    @staticmethod
    def _read_line(process: subprocess.Popen[bytes], deadline_ns: int) -> bytes:
        if process.stdout is None or process.stderr is None:
            raise OfflineProcessError("worker_pipe_failed")
        selector = selectors.DefaultSelector()
        output = bytearray()
        errors = bytearray()
        for pipe, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe.fileno(), selectors.EVENT_READ, label)
        try:
            while b"\n" not in output:
                if time.monotonic_ns() >= deadline_ns:
                    raise OfflineProcessError("worker_timeout")
                for key, _ in selector.select(min(0.05, _remaining(deadline_ns))):
                    target = output if key.data == "stdout" else errors
                    limit = _MAX_OUTPUT_BYTES if key.data == "stdout" else _MAX_STDERR_BYTES
                    chunk = os.read(int(key.fd), min(4096, max(1, limit - len(target) + 1)))
                    if not chunk:
                        raise OfflineProcessError("worker_crash")
                    target.extend(chunk)
                    if len(target) > limit:
                        raise OfflineProcessError("worker_output_limit")
                if errors:
                    raise OfflineProcessError("worker_stderr")
            line, remainder = output.split(b"\n", 1)
            if remainder:
                raise OfflineProcessError("worker_protocol")
            return bytes(line)
        finally:
            selector.close()

    @staticmethod
    def _write_line(process: subprocess.Popen[bytes], payload: bytes) -> None:
        if process.stdin is None:
            raise OfflineProcessError("worker_pipe_failed")
        try:
            process.stdin.write(payload)
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            raise OfflineProcessError("worker_pipe_failed") from None

    def _remove_owned(
        self,
        *,
        container: str | None,
        network: str | None,
        process: subprocess.Popen[bytes] | None,
        deadline_ns: int,
        remove_worker_volume: bool = False,
    ) -> CleanupProof:
        term_sent = 0
        kill_sent = 0
        reaped = 0
        if container is not None:
            try:
                self._command("rm", "-f", "-v", container, timeout=_remaining(deadline_ns))
            except OfflineProcessError:
                pass
        if network is not None:
            try:
                self._command("network", "rm", network, timeout=_remaining(deadline_ns))
            except OfflineProcessError:
                pass
        if process is not None:
            process.poll()
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    term_sent = 1
                except (ProcessLookupError, PermissionError):
                    pass
            try:
                process.wait(timeout=max(0.0, min(0.5, _remaining(deadline_ns))))
                reaped = 1
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    kill_sent = 1
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    process.wait(timeout=max(0.0, _remaining(deadline_ns)))
                    reaped = 1
                except subprocess.TimeoutExpired:
                    pass
        if remove_worker_volume and self._worker_volume_created:
            try:
                self._command(
                    "volume",
                    "rm",
                    "-f",
                    self.worker_volume,
                    timeout=_remaining(deadline_ns),
                )
            except OfflineProcessError:
                pass
        try:
            containers, networks, volumes = self._owned_objects(self.run_label, deadline_ns)
            for name in containers:
                self._command("rm", "-f", "-v", name, timeout=_remaining(deadline_ns))
            for name in networks:
                self._command("network", "rm", name, timeout=_remaining(deadline_ns))
            for name in volumes:
                if name != self.worker_volume or remove_worker_volume:
                    self._command("volume", "rm", "-f", name, timeout=_remaining(deadline_ns))
        except OfflineProcessError:
            pass
        try:
            names = set(self._object_names(self.run_label, deadline_ns))
            if self._worker_volume_ready and not remove_worker_volume:
                names.discard(self.worker_volume)
            remaining = len(names)
        except OfflineProcessError:
            remaining = 1
        if process is not None and reaped != 1:
            remaining += 1
        proof = CleanupProof(
            term_sent=term_sent,
            kill_sent=kill_sent,
            reaped=reaped,
            groups_absent=int(remaining == 0),
            remaining=remaining,
            exact_cleanup=remaining == 0,
        )
        self.last_cleanup_proof = proof
        if remove_worker_volume and proof.exact_cleanup:
            self._worker_volume_ready = False
            self._worker_volume_created = False
        if proof.exact_cleanup and process is not None:
            self.reaped_count += 1
        return proof


class DockerChecker(_DockerOwner):
    """One exact, resource-bounded, networkless checker container per candidate."""

    def __init__(
        self,
        *,
        worker_entrypoint: Path,
        private_roots: tuple[Path, ...],
        worker_sha256: str,
        image: str,
        checker_version: str,
        ownership_scope: str = "cap02-v1",
    ) -> None:
        super().__init__(
            worker_entrypoint=worker_entrypoint,
            private_roots=private_roots,
            worker_sha256=worker_sha256,
            image=image,
            role="checker",
            ownership_scope=ownership_scope,
        )
        self.checker_version = _closed_identifier(checker_version, "checker_version_invalid")

    def preflight(self, task_id: str, checker_version: str, deadline_ns: int) -> bool:
        _closed_identifier(task_id, "task_id_invalid")
        return checker_version == self.checker_version and self._common_preflight(deadline_ns)

    def check(self, task_id: str, candidate: bytes, deadline_ns: int) -> bool:
        task = _closed_identifier(task_id, "task_id_invalid")
        deadline = _deadline(deadline_ns)
        if (
            not isinstance(candidate, bytes)
            or not candidate
            or len(candidate) > _MAX_CANDIDATE_BYTES
        ):
            raise OfflineProcessError("candidate_invalid")
        with self._lock:
            if not self._common_preflight(deadline):
                raise OfflineProcessError("checker_preflight_failed")
            name = f"rapido-offline-checker-{self.run_token}-{self.spawn_count + 1}"
            header = json.dumps(
                {
                    "schema": CHECKER_REQUEST_SCHEMA,
                    "task_id": task,
                    "candidate_bytes": len(candidate),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            payload = struct.pack(">I", len(header)) + header + candidate
            process: subprocess.Popen[bytes] | None = None
            failure: OfflineProcessError | None = None
            output = b""
            return_code = -1
            try:
                temporary, _auth, _state, _shared_memory = _writable_allocations(64 * 1024 * 1024)
                process = subprocess.Popen(
                    (
                        *self._base_container_args(name),
                        "--network",
                        "none",
                        "--cpus",
                        "1",
                        "--memory",
                        "256m",
                        "--memory-swap",
                        "256m",
                        "--pids-limit",
                        "64",
                        "--tmpfs",
                        f"/tmp:rw,nosuid,nodev,noexec,size={temporary}",
                        self.image,
                        "/opt/rapido/private-worker.py",
                    ),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=self._host_env,
                    start_new_session=True,
                )
                self.spawn_count += 1
                self.peak_active_processes = max(self.peak_active_processes, 1)
                try:
                    output, errors = process.communicate(
                        payload, timeout=max(0.05, _remaining(deadline) - 0.5)
                    )
                    return_code = process.returncode or 0
                    if len(output) > _MAX_OUTPUT_BYTES:
                        raise OfflineProcessError("worker_output_limit")
                    if errors:
                        raise OfflineProcessError("worker_stderr")
                except subprocess.TimeoutExpired:
                    failure = OfflineProcessError("worker_timeout")
            except (OSError, OfflineProcessError) as exc:
                failure = (
                    exc
                    if isinstance(exc, OfflineProcessError)
                    else OfflineProcessError("worker_start_failed")
                )
            proof = self._remove_owned(
                container=name,
                network=None,
                process=process,
                deadline_ns=deadline,
            )
            if not proof.exact_cleanup:
                raise OfflineProcessError("checker_cleanup_failed")
            if failure is not None:
                raise failure
            if return_code != 0:
                raise OfflineProcessError("checker_crash")
            try:
                document = json.loads(output)
            except (UnicodeError, ValueError):
                raise OfflineProcessError("worker_protocol") from None
            if not isinstance(document, dict) or set(document) != {"schema", "result"}:
                raise OfflineProcessError("worker_protocol")
            if document.get("schema") != CHECKER_RESPONSE_SCHEMA or document.get("result") not in {
                "correct",
                "incorrect",
            }:
                raise OfflineProcessError("worker_protocol")
            return document["result"] == "correct"

    def abort_and_reap(self, deadline_ns: int) -> CleanupProof:
        deadline = _deadline(deadline_ns)
        with self._lock:
            return self._remove_owned(
                container=None,
                network=None,
                process=None,
                deadline_ns=deadline,
                remove_worker_volume=True,
            )

    close = abort_and_reap


class DockerServiceController(_DockerOwner):
    """One bounded service container on a fresh internal no-egress network."""

    def __init__(
        self,
        *,
        worker_entrypoint: Path,
        private_roots: tuple[Path, ...],
        worker_sha256: str,
        image: str,
        source_version: str,
        profile: ServiceResourceProfile | None = None,
        ownership_scope: str = "cap02-v1",
    ) -> None:
        super().__init__(
            worker_entrypoint=worker_entrypoint,
            private_roots=private_roots,
            worker_sha256=worker_sha256,
            image=image,
            role="service",
            ownership_scope=ownership_scope,
        )
        self.source_version = _closed_identifier(source_version, "source_version_invalid")
        self.profile = profile or ServiceResourceProfile()
        self._container: str | None = None
        self._proxy: str | None = None
        self._network: str | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._task_id: str | None = None
        self._watchdog: threading.Timer | None = None
        self.private_generation_nonces: list[str] = []

    def registration_record(self) -> dict[str, object]:
        return self.profile.public_record(self.image, self.source_version)

    def preflight(self, task_id: str, resource_profile_id: str, deadline_ns: int) -> bool:
        _closed_identifier(task_id, "task_id_invalid")
        if resource_profile_id != self.profile.profile_id:
            return False
        return self._common_preflight(deadline_ns)

    def _network_create(self, name: str, deadline_ns: int) -> None:
        code, output = self._command(
            "network",
            "create",
            "--internal",
            "--label",
            self.stable_label,
            "--label",
            self.run_label,
            name,
            timeout=_remaining(deadline_ns),
        )
        if code != 0 or not output.strip():
            raise OfflineProcessError("service_network_failed")
        code, output = self._command(
            "network",
            "inspect",
            "--format",
            "{{.Internal}}",
            name,
            timeout=_remaining(deadline_ns),
        )
        if code != 0 or output.strip() != b"true":
            raise OfflineProcessError("service_network_failed")

    def _service_document(self, payload: bytes) -> tuple[dict[str, object], str]:
        try:
            document = json.loads(payload)
        except (UnicodeError, ValueError):
            raise OfflineProcessError("worker_protocol") from None
        expected = {"schema", "ready", "connection_info", "since", "until", "generation_nonce"}
        if not isinstance(document, dict) or set(document) != expected:
            raise OfflineProcessError("worker_protocol")
        nonce = document.get("generation_nonce")
        if (
            document.get("schema") != SERVICE_RESPONSE_SCHEMA
            or document.get("ready") is not True
            or not isinstance(nonce, str)
            or re.fullmatch(r"[0-9a-f]{64}", nonce) is None
        ):
            raise OfflineProcessError("worker_protocol")
        for key in ("since", "until"):
            value = document[key]
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, (str, int, float))
            ):
                raise OfflineProcessError("worker_protocol")
        return document, nonce

    def _host_port(self, container: str, deadline_ns: int) -> int:
        code, output = self._command(
            "port",
            container,
            f"{self.profile.internal_port}/tcp",
            timeout=_remaining(deadline_ns),
        )
        if code != 0:
            raise OfflineProcessError("service_endpoint_invalid")
        value = output.decode("utf-8", "replace").strip()
        match = re.fullmatch(r"127\.0\.0\.1:(\d{1,5})", value)
        if match is None or not 1 <= int(match.group(1)) <= 65535:
            raise OfflineProcessError("service_endpoint_invalid")
        return int(match.group(1))

    def _verify_service_container(self, container: str, network: str, deadline_ns: int) -> None:
        code, output = self._command("inspect", container, timeout=_remaining(deadline_ns))
        try:
            inspected = json.loads(output)[0] if code == 0 else None
            host = inspected["HostConfig"]
            config = inspected["Config"]
            mounts = inspected["Mounts"]
            networks = inspected["NetworkSettings"]["Networks"]
        except (IndexError, KeyError, TypeError, ValueError):
            raise OfflineProcessError("service_limits_unverified") from None
        service_writable = self.profile.writable_tmpfs_bytes - _PROXY_WRITABLE_BYTES
        service_cpu = self.profile.cpu_cores - _PROXY_CPU_CORES
        service_memory = self.profile.memory_bytes - _PROXY_MEMORY_BYTES
        service_pids = self.profile.pids_limit - _PROXY_PIDS
        temporary, auth, state, shared_memory = _writable_allocations(service_writable)
        expected_tmpfs = {
            "/tmp": f"rw,nosuid,nodev,noexec,size={temporary}",
            "/auth/codex": f"rw,nosuid,nodev,noexec,size={auth}",
            "/state": f"rw,nosuid,nodev,noexec,size={state}",
        }
        environment = config.get("Env") or []
        if (
            inspected.get("Image") != self.image
            or config.get("User") != f"{_CONTAINER_UID}:{_CONTAINER_UID}"
            or host.get("NanoCpus") != int(service_cpu * 1_000_000_000)
            or host.get("Memory") != service_memory
            or host.get("MemorySwap") != service_memory
            or host.get("PidsLimit") != service_pids
            or host.get("ReadonlyRootfs") is not True
            or host.get("NetworkMode") != network
            or host.get("PortBindings") not in ({}, None)
            or host.get("LogConfig", {}).get("Type") != "none"
            or "ALL" not in (host.get("CapDrop") or [])
            or "no-new-privileges" not in (host.get("SecurityOpt") or [])
            or host.get("Tmpfs") != expected_tmpfs
            or host.get("ShmSize") != shared_memory
            or set(networks) != {network}
            or len(mounts) != 1
            or mounts[0].get("Type") != "volume"
            or mounts[0].get("Name") != self.worker_volume
            or mounts[0].get("RW") is not False
            or any(
                str(item).split("=", 1)[0] in {"CTFD_API_TOKEN", "TEAM_KEY", "OPENAI_API_KEY"}
                for item in environment
            )
        ):
            raise OfflineProcessError("service_limits_unverified")

    def _verify_proxy_container(self, container: str, network: str, deadline_ns: int) -> None:
        code, output = self._command("inspect", container, timeout=_remaining(deadline_ns))
        try:
            inspected = json.loads(output)[0] if code == 0 else None
            host = inspected["HostConfig"]
            config = inspected["Config"]
            mounts = inspected["Mounts"]
            networks = inspected["NetworkSettings"]["Networks"]
        except (IndexError, KeyError, TypeError, ValueError):
            raise OfflineProcessError("service_proxy_unverified") from None
        temporary, auth, state, shared_memory = _writable_allocations(_PROXY_WRITABLE_BYTES)
        expected_tmpfs = {
            "/tmp": f"rw,nosuid,nodev,noexec,size={temporary}",
            "/auth/codex": f"rw,nosuid,nodev,noexec,size={auth}",
            "/state": f"rw,nosuid,nodev,noexec,size={state}",
        }
        binding = (host.get("PortBindings") or {}).get(f"{self.profile.internal_port}/tcp")
        environment = config.get("Env") or []
        if (
            inspected.get("Image") != self.image
            or config.get("User") != f"{_CONTAINER_UID}:{_CONTAINER_UID}"
            or host.get("NanoCpus") != int(_PROXY_CPU_CORES * 1_000_000_000)
            or host.get("Memory") != _PROXY_MEMORY_BYTES
            or host.get("MemorySwap") != _PROXY_MEMORY_BYTES
            or host.get("PidsLimit") != _PROXY_PIDS
            or host.get("ReadonlyRootfs") is not True
            or host.get("LogConfig", {}).get("Type") != "none"
            or "ALL" not in (host.get("CapDrop") or [])
            or "no-new-privileges" not in (host.get("SecurityOpt") or [])
            or host.get("Tmpfs") != expected_tmpfs
            or host.get("ShmSize") != shared_memory
            or mounts
            or set(networks) != {"bridge", network}
            or not isinstance(binding, list)
            or len(binding) != 1
            or binding[0].get("HostIp") != "127.0.0.1"
            or binding[0].get("HostPort") != ""
            or any(
                str(item).split("=", 1)[0] in {"CTFD_API_TOKEN", "TEAM_KEY", "OPENAI_API_KEY"}
                for item in environment
            )
        ):
            raise OfflineProcessError("service_proxy_unverified")

    @staticmethod
    def _wait_loopback(port: int, deadline_ns: int) -> None:
        while time.monotonic_ns() < deadline_ns:
            try:
                with socket.create_connection(
                    ("127.0.0.1", port),
                    timeout=min(0.2, _remaining(deadline_ns)),
                ) as probe:
                    probe.settimeout(min(0.2, _remaining(deadline_ns)))
                    probe.sendall(b"GET / HTTP/1.0\r\nHost: offline\r\n\r\n")
                    response = probe.recv(64)
                if response.startswith(b"HTTP/1."):
                    return
            except OSError:
                pass
            time.sleep(min(0.02, _remaining(deadline_ns)))
        raise OfflineProcessError("service_proxy_failed")

    def _watchdog_expired(self, token: str) -> None:
        with self._lock:
            if token != self._container:
                return
            deadline = time.monotonic_ns() + 5_000_000_000
            self._cleanup_current(deadline)

    def start(self, task_id: str, resource_profile_id: str, deadline_ns: int) -> Mapping[str, Any]:
        task = _closed_identifier(task_id, "task_id_invalid")
        deadline = _deadline(deadline_ns)
        if resource_profile_id != self.profile.profile_id:
            raise OfflineProcessError("resource_profile_invalid")
        with self._lock:
            if self._container is not None or self.inventory(deadline) != 0:
                raise OfflineProcessError("service_already_owned")
            ordinal = self.spawn_count + 1
            container = f"rapido-offline-service-{self.run_token}-{ordinal}"
            proxy = f"rapido-offline-proxy-{self.run_token}-{ordinal}"
            network = f"rapido-offline-network-{self.run_token}-{ordinal}"
            process: subprocess.Popen[bytes] | None = None
            service_writable = self.profile.writable_tmpfs_bytes - _PROXY_WRITABLE_BYTES
            service_cpu = self.profile.cpu_cores - _PROXY_CPU_CORES
            service_memory = self.profile.memory_bytes - _PROXY_MEMORY_BYTES
            service_pids = self.profile.pids_limit - _PROXY_PIDS
            temporary, _auth, _state, _shared_memory = _writable_allocations(service_writable)
            proxy_tmp, proxy_auth, proxy_state, proxy_shm = _writable_allocations(
                _PROXY_WRITABLE_BYTES
            )
            self._container = container
            self._proxy = proxy
            self._network = network
            self._task_id = task
            try:
                self._network_create(network, deadline)
                process = subprocess.Popen(
                    (
                        *self._base_container_args(container, writable_bytes=service_writable),
                        "--network",
                        network,
                        "--network-alias",
                        "service",
                        "--cpus",
                        str(service_cpu),
                        "--memory",
                        str(service_memory),
                        "--memory-swap",
                        str(service_memory),
                        "--pids-limit",
                        str(service_pids),
                        "--tmpfs",
                        f"/tmp:rw,nosuid,nodev,noexec,size={temporary}",
                        self.image,
                        "/opt/rapido/private-worker.py",
                        str(self.profile.internal_port),
                    ),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=self._host_env,
                    start_new_session=True,
                )
                self._process = process
                self.spawn_count += 1
                self.peak_active_processes = max(self.peak_active_processes, 1)
                request = (
                    json.dumps(
                        {
                            "schema": SERVICE_REQUEST_SCHEMA,
                            "operation": "start",
                            "task_id": task,
                            "resource_profile_id": resource_profile_id,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                    + b"\n"
                )
                self._write_line(process, request)
                document, nonce = self._service_document(self._read_line(process, deadline))
                self._verify_service_container(container, network, deadline)
                proxy_source = (
                    "import socket,sys,threading;"
                    "host=sys.argv[1];port=int(sys.argv[2]);"
                    "listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
                    "listener.bind(('0.0.0.0',port));listener.listen();"
                    "relay=lambda source,target:"
                    "[target.sendall(chunk) for chunk in iter(lambda:source.recv(65536),b'')];"
                    "\nwhile True:\n"
                    " client,_=listener.accept(); upstream=socket.create_connection((host,port),2);"
                    " threading.Thread(target=relay,args=(client,upstream),daemon=True).start();"
                    " threading.Thread(target=relay,args=(upstream,client),daemon=True).start()"
                )
                code, _ = self._command(
                    "run",
                    "--detach",
                    "--rm",
                    "--pull",
                    "never",
                    "--name",
                    proxy,
                    "--label",
                    self.stable_label,
                    "--label",
                    self.run_label,
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--log-driver",
                    "none",
                    "--cpus",
                    str(_PROXY_CPU_CORES),
                    "--memory",
                    str(_PROXY_MEMORY_BYTES),
                    "--memory-swap",
                    str(_PROXY_MEMORY_BYTES),
                    "--pids-limit",
                    str(_PROXY_PIDS),
                    "--shm-size",
                    str(proxy_shm),
                    "--tmpfs",
                    f"/tmp:rw,nosuid,nodev,noexec,size={proxy_tmp}",
                    "--tmpfs",
                    f"/auth/codex:rw,nosuid,nodev,noexec,size={proxy_auth}",
                    "--tmpfs",
                    f"/state:rw,nosuid,nodev,noexec,size={proxy_state}",
                    "--user",
                    f"{_CONTAINER_UID}:{_CONTAINER_UID}",
                    "--publish",
                    f"127.0.0.1::{self.profile.internal_port}",
                    "--entrypoint",
                    "/opt/venv/bin/python3",
                    self.image,
                    "-c",
                    proxy_source,
                    "service",
                    str(self.profile.internal_port),
                    timeout=_remaining(deadline),
                )
                if code != 0:
                    raise OfflineProcessError("service_proxy_failed")
                code, _ = self._command(
                    "network",
                    "connect",
                    network,
                    proxy,
                    timeout=_remaining(deadline),
                )
                if code != 0:
                    raise OfflineProcessError("service_proxy_failed")
                self._verify_proxy_container(proxy, network, deadline)
                port = self._host_port(proxy, deadline)
                self._wait_loopback(port, deadline)
            except (OSError, OfflineProcessError):
                cleanup_deadline = max(
                    deadline,
                    time.monotonic_ns() + 3_000_000_000,
                )
                proof = self._cleanup_current(cleanup_deadline)
                if not proof.exact_cleanup:
                    raise OfflineProcessError("service_cleanup_failed") from None
                raise
            self.private_generation_nonces.append(nonce)
            self._watchdog = threading.Timer(
                self.profile.hard_lifetime_seconds,
                self._watchdog_expired,
                args=(container,),
            )
            self._watchdog.daemon = True
            self._watchdog.start()
            return {
                "connection_info": f"http://127.0.0.1:{port}/",
                "since": document["since"],
                "until": document["until"],
            }

    def renew(self, task_id: str, deadline_ns: int) -> Mapping[str, Any]:
        task = _closed_identifier(task_id, "task_id_invalid")
        deadline = _deadline(deadline_ns)
        with self._lock:
            if (
                self._container is None
                or self._proxy is None
                or self._process is None
                or self._task_id != task
            ):
                raise OfflineProcessError("service_not_owned")
            request = (
                json.dumps(
                    {
                        "schema": SERVICE_REQUEST_SCHEMA,
                        "operation": "renew",
                        "task_id": task,
                        "resource_profile_id": self.profile.profile_id,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                + b"\n"
            )
            try:
                self._write_line(self._process, request)
                document, _nonce = self._service_document(self._read_line(self._process, deadline))
                port = self._host_port(self._proxy, deadline)
            except OfflineProcessError:
                self._cleanup_current(deadline)
                raise
            return {
                "connection_info": f"http://127.0.0.1:{port}/",
                "since": document["since"],
                "until": document["until"],
            }

    def _cleanup_current(self, deadline_ns: int) -> CleanupProof:
        if self._watchdog is not None:
            self._watchdog.cancel()
            self._watchdog = None
        if self._proxy is not None:
            try:
                self._command(
                    "rm",
                    "-f",
                    "-v",
                    self._proxy,
                    timeout=_remaining(deadline_ns),
                )
            except OfflineProcessError:
                pass
        proof = self._remove_owned(
            container=self._container,
            network=self._network,
            process=self._process,
            deadline_ns=deadline_ns,
        )
        if proof.exact_cleanup:
            self._container = None
            self._proxy = None
            self._network = None
            self._process = None
            self._task_id = None
        return proof

    def stop(self, task_id: str, deadline_ns: int) -> CleanupProof:
        task = _closed_identifier(task_id, "task_id_invalid")
        deadline = _deadline(deadline_ns)
        with self._lock:
            if self._container is None or self._task_id != task:
                raise OfflineProcessError("service_not_owned")
            return self._cleanup_current(deadline)

    def abort_and_reap(self, deadline_ns: int) -> CleanupProof:
        deadline = _deadline(deadline_ns)
        with self._lock:
            if (
                self._container is not None
                or self._proxy is not None
                or self._network is not None
                or self._process is not None
            ):
                proof = self._cleanup_current(deadline)
                if not proof.exact_cleanup:
                    return proof
            return self._remove_owned(
                container=None,
                network=None,
                process=None,
                deadline_ns=deadline,
                remove_worker_volume=True,
            )

    close = abort_and_reap
