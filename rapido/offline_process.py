"""Process-isolated private checker and owned offline service controllers.

All worker input uses private pipes.  Worker output and failures are normalized before crossing
the controller boundary; candidate bytes never enter argv, the environment, or exceptions.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import selectors
import signal
import stat
import struct
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .target import parse_connection_info

CHECKER_REQUEST_SCHEMA = "rapido-checker-request-v1"
CHECKER_RESPONSE_SCHEMA = "rapido-checker-response-v1"
SERVICE_REQUEST_SCHEMA = "rapido-service-request-v1"
SERVICE_RESPONSE_SCHEMA = "rapido-service-response-v1"
_MAX_CANDIDATE_BYTES = 4096
_MAX_REQUEST_BYTES = 16 * 1024
_MAX_OUTPUT_BYTES = 16 * 1024
_MAX_STDERR_BYTES = 4096
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_ENV_KEYS = frozenset({"PATH", "LANG", "LC_ALL", "PYTHONUNBUFFERED"})


class OfflineProcessError(RuntimeError):
    """A closed process-port failure with no private worker detail."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class CleanupProof:
    term_sent: int
    kill_sent: int
    reaped: int
    groups_absent: int
    remaining: int
    exact_cleanup: bool


class CheckerProcessPort(Protocol):
    process_isolated: bool
    private_roots: tuple[Path, ...]

    def check(self, task_id: str, candidate: bytes, deadline_ns: int) -> bool: ...

    def abort_and_reap(self, deadline_ns: int) -> CleanupProof: ...

    def close(self, deadline_ns: int) -> CleanupProof: ...


class ServiceProcessPort(Protocol):
    process_isolated: bool
    private_roots: tuple[Path, ...]

    def preflight(self, task_id: str, resource_profile_id: str, deadline_ns: int) -> bool: ...

    def start(
        self, task_id: str, resource_profile_id: str, deadline_ns: int
    ) -> Mapping[str, Any]: ...

    def renew(self, task_id: str, deadline_ns: int) -> Mapping[str, Any]: ...

    def stop(self, task_id: str, deadline_ns: int) -> CleanupProof: ...

    def inventory(self, deadline_ns: int) -> int: ...

    def abort_and_reap(self, deadline_ns: int) -> CleanupProof: ...

    def close(self, deadline_ns: int) -> CleanupProof: ...


@dataclass
class _TrackedProcess:
    process: subprocess.Popen[bytes]
    group_id: int


def _identifier(value: str, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise OfflineProcessError(f"{label}_invalid")
    return value


def _deadline(value: int) -> int:
    if type(value) is not int or value <= time.monotonic_ns():
        raise OfflineProcessError("deadline_expired")
    return value


def _remaining_seconds(deadline_ns: int) -> float:
    return max(0.0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)


def _private_roots(values: Sequence[Path]) -> tuple[Path, ...]:
    if any(not Path(value).is_absolute() for value in values):
        raise OfflineProcessError("private_roots_invalid")
    roots = tuple(Path(value).absolute() for value in values)
    if not roots:
        raise OfflineProcessError("private_roots_invalid")
    for root in roots:
        try:
            metadata = root.lstat()
        except OSError:
            raise OfflineProcessError("private_roots_invalid") from None
        if (
            not root.is_absolute()
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise OfflineProcessError("private_roots_invalid")
    return roots


def _worker_argv(values: Sequence[str]) -> tuple[str, ...]:
    argv = tuple(values)
    if not argv or not Path(argv[0]).is_absolute():
        raise OfflineProcessError("worker_argv_invalid")
    for value in argv:
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise OfflineProcessError("worker_argv_invalid")
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise OfflineProcessError("worker_argv_invalid") from None
        if "\x00" in value or "\n" in value or "\r" in value:
            raise OfflineProcessError("worker_argv_invalid")
    return argv


def _worker_env(values: Mapping[str, str] | None) -> dict[str, str]:
    source = (
        {
            "PATH": os.defpath,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONUNBUFFERED": "1",
        }
        if values is None
        else dict(values)
    )
    if not source or any(key not in _ENV_KEYS for key in source):
        raise OfflineProcessError("worker_env_invalid")
    for key, value in source.items():
        if type(key) is not str or type(value) is not str or "\x00" in value:
            raise OfflineProcessError("worker_env_invalid")
        if len(value) > 4096:
            raise OfflineProcessError("worker_env_invalid")
    return source


def _group_exists(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _close_pipes(process: subprocess.Popen[bytes]) -> None:
    for pipe in (process.stdin, process.stdout, process.stderr):
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass


class _ProcessOwner:
    process_isolated = True
    descendant_confined = False

    def __init__(
        self,
        worker_argv: Sequence[str],
        private_roots: Sequence[Path],
        *,
        worker_env: Mapping[str, str] | None = None,
        term_grace_ns: int = 100_000_000,
        cleanup_reserve_ns: int = 500_000_000,
    ) -> None:
        if type(term_grace_ns) is not int or not 1_000_000 <= term_grace_ns <= 5_000_000_000:
            raise OfflineProcessError("term_grace_invalid")
        if (
            type(cleanup_reserve_ns) is not int
            or cleanup_reserve_ns < term_grace_ns + 50_000_000
            or cleanup_reserve_ns > 10_000_000_000
        ):
            raise OfflineProcessError("cleanup_reserve_invalid")
        self.worker_argv = _worker_argv(worker_argv)
        self.private_roots = _private_roots(private_roots)
        if len(self.worker_argv) < 2:
            raise OfflineProcessError("worker_entrypoint_invalid")
        try:
            entrypoint = Path(self.worker_argv[1]).resolve(strict=True)
        except OSError:
            raise OfflineProcessError("worker_entrypoint_invalid") from None
        if not entrypoint.is_file() or not any(
            entrypoint == root or root in entrypoint.parents for root in self.private_roots
        ):
            raise OfflineProcessError("worker_entrypoint_invalid")
        self._entrypoint = entrypoint
        for argument in self.worker_argv[2:]:
            if _IDENTIFIER.fullmatch(argument) is None:
                raise OfflineProcessError("worker_argument_invalid")
        self._env = _worker_env(worker_env)
        self._term_grace_ns = term_grace_ns
        self._cleanup_reserve_ns = cleanup_reserve_ns
        self._lock = threading.RLock()
        self._tracked: dict[int, _TrackedProcess] = {}
        self.spawn_count = 0
        self.reaped_count = 0
        self.peak_active_processes = 0
        self.last_cleanup_proof = CleanupProof(0, 0, 0, 0, 0, True)

    def _spawn(self) -> _TrackedProcess:
        descriptor = -1
        try:
            descriptor = os.open(
                self._entrypoint,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError("invalid worker entrypoint")
            process = subprocess.Popen(
                (
                    self.worker_argv[0],
                    f"/dev/fd/{descriptor}",
                    *self.worker_argv[2:],
                ),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.private_roots[0],
                env=self._env,
                start_new_session=True,
                close_fds=True,
                pass_fds=(descriptor,),
            )
        except OSError:
            raise OfflineProcessError("worker_start_failed") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        tracked = _TrackedProcess(process, process.pid)
        self._tracked[process.pid] = tracked
        self.spawn_count += 1
        self.peak_active_processes = max(self.peak_active_processes, len(self._tracked))
        return tracked

    def _cleanup_one(self, tracked: _TrackedProcess, deadline_ns: int) -> CleanupProof:
        process = tracked.process
        group_id = tracked.group_id
        term_sent = 0
        kill_sent = 0
        reaped = 0
        process.poll()
        if _group_exists(group_id):
            try:
                os.killpg(group_id, signal.SIGTERM)
                term_sent = 1
            except ProcessLookupError:
                pass
            except PermissionError:
                pass
            term_deadline = min(deadline_ns, time.monotonic_ns() + self._term_grace_ns)
            while _group_exists(group_id) and time.monotonic_ns() < term_deadline:
                process.poll()
                time.sleep(min(0.005, _remaining_seconds(term_deadline)))
        if _group_exists(group_id):
            try:
                os.killpg(group_id, signal.SIGKILL)
                kill_sent = 1
            except ProcessLookupError:
                pass
            except PermissionError:
                pass
        while _group_exists(group_id) and time.monotonic_ns() < deadline_ns:
            process.poll()
            time.sleep(min(0.005, _remaining_seconds(deadline_ns)))
        try:
            process.wait(timeout=_remaining_seconds(deadline_ns))
            reaped = 1
        except subprocess.TimeoutExpired:
            pass
        absent = not _group_exists(group_id)
        if absent and reaped:
            if self._tracked.pop(process.pid, None) is not None:
                self.reaped_count += 1
            _close_pipes(process)
        remaining = int(not (absent and reaped))
        proof = CleanupProof(
            term_sent=term_sent,
            kill_sent=kill_sent,
            reaped=reaped,
            groups_absent=int(absent),
            remaining=remaining,
            exact_cleanup=remaining == 0,
        )
        self.last_cleanup_proof = proof
        return proof

    @staticmethod
    def _merge_proofs(proofs: Sequence[CleanupProof]) -> CleanupProof:
        return CleanupProof(
            term_sent=sum(proof.term_sent for proof in proofs),
            kill_sent=sum(proof.kill_sent for proof in proofs),
            reaped=sum(proof.reaped for proof in proofs),
            groups_absent=sum(proof.groups_absent for proof in proofs),
            remaining=sum(proof.remaining for proof in proofs),
            exact_cleanup=all(proof.exact_cleanup for proof in proofs),
        )

    def abort_and_reap(self, deadline_ns: int) -> CleanupProof:
        deadline = _deadline(deadline_ns)
        with self._lock:
            proofs = [self._cleanup_one(item, deadline) for item in list(self._tracked.values())]
            proof = self._merge_proofs(proofs)
            self.last_cleanup_proof = proof
            return proof

    def close(self, deadline_ns: int) -> CleanupProof:
        return self.abort_and_reap(deadline_ns)

    def _io_deadline(self, deadline_ns: int) -> int:
        deadline = _deadline(deadline_ns)
        io_deadline = deadline - self._cleanup_reserve_ns
        if io_deadline <= time.monotonic_ns():
            raise OfflineProcessError("deadline_too_short")
        return io_deadline

    def _exchange(
        self,
        tracked: _TrackedProcess,
        payload: bytes,
        io_deadline_ns: int,
    ) -> tuple[bytes, int]:
        if len(payload) > _MAX_REQUEST_BYTES:
            raise OfflineProcessError("request_too_large")
        process = tracked.process
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise OfflineProcessError("worker_pipe_failed")
        input_fd = process.stdin.fileno()
        output_fd = process.stdout.fileno()
        error_fd = process.stderr.fileno()
        for descriptor in (input_fd, output_fd, error_fd):
            os.set_blocking(descriptor, False)
        selector = selectors.DefaultSelector()
        selector.register(input_fd, selectors.EVENT_WRITE, "stdin")
        selector.register(output_fd, selectors.EVENT_READ, "stdout")
        selector.register(error_fd, selectors.EVENT_READ, "stderr")
        written = 0
        output = bytearray()
        errors = bytearray()
        open_streams = {"stdin", "stdout", "stderr"}
        try:
            while open_streams:
                if time.monotonic_ns() >= io_deadline_ns:
                    raise OfflineProcessError("worker_timeout")
                events = selector.select(min(0.05, _remaining_seconds(io_deadline_ns)))
                for key, _mask in events:
                    kind = str(key.data)
                    descriptor = int(key.fd)
                    if kind == "stdin":
                        try:
                            count = os.write(descriptor, payload[written:])
                        except BrokenPipeError:
                            count = 0
                        written += count
                        if count == 0 or written == len(payload):
                            selector.unregister(descriptor)
                            process.stdin.close()
                            open_streams.discard("stdin")
                    else:
                        target = output if kind == "stdout" else errors
                        limit = _MAX_OUTPUT_BYTES if kind == "stdout" else _MAX_STDERR_BYTES
                        try:
                            chunk = os.read(
                                descriptor,
                                min(64 * 1024, max(1, limit - len(target) + 1)),
                            )
                        except BlockingIOError:
                            continue
                        if chunk:
                            target.extend(chunk)
                            if len(target) > limit:
                                raise OfflineProcessError("worker_output_limit")
                        else:
                            selector.unregister(descriptor)
                            open_streams.discard(kind)
                if process.poll() is not None and open_streams == {"stdin"}:
                    open_streams.clear()
            try:
                return_code = process.wait(timeout=_remaining_seconds(io_deadline_ns))
            except subprocess.TimeoutExpired:
                raise OfflineProcessError("worker_timeout") from None
            if errors:
                raise OfflineProcessError("worker_stderr")
            return bytes(output), return_code
        finally:
            selector.close()

    @staticmethod
    def _write_pipe(pipe: Any, payload: bytes, deadline_ns: int) -> None:
        if len(payload) > _MAX_REQUEST_BYTES:
            raise OfflineProcessError("request_too_large")
        descriptor = pipe.fileno()
        os.set_blocking(descriptor, False)
        selector = selectors.DefaultSelector()
        selector.register(descriptor, selectors.EVENT_WRITE)
        written = 0
        try:
            while written < len(payload):
                if time.monotonic_ns() >= deadline_ns:
                    raise OfflineProcessError("worker_timeout")
                if not selector.select(min(0.05, _remaining_seconds(deadline_ns))):
                    continue
                try:
                    count = os.write(descriptor, payload[written:])
                except BrokenPipeError:
                    raise OfflineProcessError("worker_pipe_failed") from None
                if count <= 0:
                    raise OfflineProcessError("worker_pipe_failed")
                written += count
        finally:
            selector.close()

    @staticmethod
    def _read_service_line(process: subprocess.Popen[bytes], deadline_ns: int) -> bytes:
        if process.stdout is None or process.stderr is None:
            raise OfflineProcessError("worker_pipe_failed")
        output_fd = process.stdout.fileno()
        error_fd = process.stderr.fileno()
        os.set_blocking(output_fd, False)
        os.set_blocking(error_fd, False)
        selector = selectors.DefaultSelector()
        selector.register(output_fd, selectors.EVENT_READ, "stdout")
        selector.register(error_fd, selectors.EVENT_READ, "stderr")
        output = bytearray()
        errors = bytearray()
        try:
            while True:
                if time.monotonic_ns() >= deadline_ns:
                    raise OfflineProcessError("worker_timeout")
                if process.poll() is not None and not _group_exists(process.pid):
                    raise OfflineProcessError("worker_crash")
                for key, _mask in selector.select(min(0.05, _remaining_seconds(deadline_ns))):
                    target = output if key.data == "stdout" else errors
                    limit = _MAX_OUTPUT_BYTES if key.data == "stdout" else _MAX_STDERR_BYTES
                    try:
                        chunk = os.read(
                            int(key.fd),
                            min(64 * 1024, max(1, limit - len(target) + 1)),
                        )
                    except BlockingIOError:
                        continue
                    if not chunk:
                        raise OfflineProcessError("worker_crash")
                    target.extend(chunk)
                    if len(target) > limit:
                        raise OfflineProcessError("worker_output_limit")
                if errors:
                    raise OfflineProcessError("worker_stderr")
                if b"\n" in output:
                    line, remainder = output.split(b"\n", 1)
                    if remainder:
                        raise OfflineProcessError("worker_protocol")
                    return bytes(line)
        finally:
            selector.close()


def _json_line(document: Mapping[str, Any]) -> bytes:
    try:
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, UnicodeError, ValueError):
        raise OfflineProcessError("request_invalid") from None
    if len(payload) + 1 > _MAX_REQUEST_BYTES:
        raise OfflineProcessError("request_too_large")
    return payload + b"\n"


def _document(payload: bytes, expected_keys: set[str], schema: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeError, ValueError, RecursionError):
        raise OfflineProcessError("worker_protocol") from None
    if not isinstance(value, dict) or set(value) != expected_keys or value.get("schema") != schema:
        raise OfflineProcessError("worker_protocol")
    return value


class ProcessChecker(_ProcessOwner):
    """One fresh, killable worker per deterministic checker invocation."""

    def check(self, task_id: str, candidate: bytes, deadline_ns: int) -> bool:
        task = _identifier(task_id, "task_id")
        if (
            not isinstance(candidate, bytes)
            or not candidate
            or len(candidate) > _MAX_CANDIDATE_BYTES
        ):
            raise OfflineProcessError("candidate_invalid")
        for value in (*self.worker_argv, *self._env.values()):
            if candidate in value.encode("utf-8"):
                raise OfflineProcessError("candidate_boundary")
        deadline = _deadline(deadline_ns)
        io_deadline = self._io_deadline(deadline)
        header = json.dumps(
            {
                "schema": CHECKER_REQUEST_SCHEMA,
                "task_id": task,
                "candidate_bytes": len(candidate),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        payload = struct.pack(">I", len(header)) + header + candidate
        with self._lock:
            tracked = self._spawn()
            failure: OfflineProcessError | None = None
            output = b""
            return_code = -1
            try:
                output, return_code = self._exchange(tracked, payload, io_deadline)
            except OfflineProcessError as exc:
                failure = exc
            proof = self._cleanup_one(tracked, deadline)
            if not proof.exact_cleanup:
                raise OfflineProcessError("checker_cleanup_failed")
            if failure is not None:
                raise failure
            if return_code != 0:
                raise OfflineProcessError("checker_crash")
            document = _document(
                output,
                {"schema", "result"},
                CHECKER_RESPONSE_SCHEMA,
            )
            if document["result"] not in {"correct", "incorrect"}:
                raise OfflineProcessError("worker_protocol")
            return document["result"] == "correct"


class ProcessServiceController(_ProcessOwner):
    """One globally owned long-lived service process with structured pipe control."""

    def __init__(
        self,
        worker_argv: Sequence[str],
        private_roots: Sequence[Path],
        *,
        worker_env: Mapping[str, str] | None = None,
        term_grace_ns: int = 100_000_000,
        cleanup_reserve_ns: int = 500_000_000,
    ) -> None:
        super().__init__(
            worker_argv,
            private_roots,
            worker_env=worker_env,
            term_grace_ns=term_grace_ns,
            cleanup_reserve_ns=cleanup_reserve_ns,
        )
        self._service: _TrackedProcess | None = None
        self._task_id: str | None = None
        self._resource_profile_id: str | None = None

    @staticmethod
    def _service_record(payload: bytes) -> dict[str, Any]:
        document = _document(
            payload,
            {"schema", "ready", "connection_info", "since", "until"},
            SERVICE_RESPONSE_SCHEMA,
        )
        if document["ready"] is not True:
            raise OfflineProcessError("service_not_ready")
        connection_info = document["connection_info"]
        if (
            not isinstance(connection_info, str)
            or not connection_info
            or len(connection_info) > 4096
        ):
            raise OfflineProcessError("worker_protocol")
        try:
            endpoints = parse_connection_info(connection_info)
            if any(not ipaddress.ip_address(endpoint.host).is_loopback for endpoint in endpoints):
                raise ValueError("non-loopback endpoint")
        except ValueError:
            raise OfflineProcessError("service_endpoint_invalid") from None
        for key in ("since", "until"):
            value = document[key]
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (str, int, float))
                or len(str(value)) > 256
            ):
                raise OfflineProcessError("worker_protocol")
        return {
            "connection_info": connection_info,
            "since": document["since"],
            "until": document["until"],
        }

    def preflight(self, task_id: str, resource_profile_id: str, deadline_ns: int) -> bool:
        task = _identifier(task_id, "task_id")
        profile = _identifier(resource_profile_id, "resource_profile_id")
        deadline = _deadline(deadline_ns)
        io_deadline = self._io_deadline(deadline)
        payload = _json_line(
            {
                "schema": SERVICE_REQUEST_SCHEMA,
                "operation": "preflight",
                "task_id": task,
                "resource_profile_id": profile,
            }
        )
        with self._lock:
            tracked = self._spawn()
            failure: OfflineProcessError | None = None
            output = b""
            return_code = -1
            try:
                output, return_code = self._exchange(tracked, payload, io_deadline)
            except OfflineProcessError as exc:
                failure = exc
            proof = self._cleanup_one(tracked, deadline)
            if not proof.exact_cleanup:
                raise OfflineProcessError("service_cleanup_failed")
            if failure is not None:
                raise failure
            if return_code != 0:
                raise OfflineProcessError("worker_crash")
            document = _document(output, {"schema", "ok"}, SERVICE_RESPONSE_SCHEMA)
            if type(document["ok"]) is not bool:
                raise OfflineProcessError("worker_protocol")
            return document["ok"]

    def start(self, task_id: str, resource_profile_id: str, deadline_ns: int) -> Mapping[str, Any]:
        task = _identifier(task_id, "task_id")
        profile = _identifier(resource_profile_id, "resource_profile_id")
        deadline = _deadline(deadline_ns)
        io_deadline = self._io_deadline(deadline)
        with self._lock:
            if self._service is not None or self._tracked:
                raise OfflineProcessError("service_already_owned")
            tracked = self._spawn()
            try:
                if tracked.process.stdin is None:
                    raise OfflineProcessError("worker_pipe_failed")
                self._write_pipe(
                    tracked.process.stdin,
                    _json_line(
                        {
                            "schema": SERVICE_REQUEST_SCHEMA,
                            "operation": "start",
                            "task_id": task,
                            "resource_profile_id": profile,
                        }
                    ),
                    io_deadline,
                )
                record = self._service_record(self._read_service_line(tracked.process, io_deadline))
            except OfflineProcessError:
                proof = self._cleanup_one(tracked, deadline)
                if not proof.exact_cleanup:
                    raise OfflineProcessError("service_cleanup_failed") from None
                raise
            self._service = tracked
            self._task_id = task
            self._resource_profile_id = profile
            return record

    def renew(self, task_id: str, deadline_ns: int) -> Mapping[str, Any]:
        task = _identifier(task_id, "task_id")
        deadline = _deadline(deadline_ns)
        io_deadline = self._io_deadline(deadline)
        with self._lock:
            tracked = self._service
            if tracked is None or self._task_id != task or tracked.process.stdin is None:
                raise OfflineProcessError("service_not_owned")
            try:
                self._write_pipe(
                    tracked.process.stdin,
                    _json_line(
                        {
                            "schema": SERVICE_REQUEST_SCHEMA,
                            "operation": "renew",
                            "task_id": task,
                            "resource_profile_id": self._resource_profile_id,
                        }
                    ),
                    io_deadline,
                )
                return self._service_record(self._read_service_line(tracked.process, io_deadline))
            except OfflineProcessError:
                proof = self._cleanup_one(tracked, deadline)
                if proof.exact_cleanup:
                    self._service = None
                    self._task_id = None
                    self._resource_profile_id = None
                if not proof.exact_cleanup:
                    raise OfflineProcessError("service_cleanup_failed") from None
                raise

    def stop(self, task_id: str, deadline_ns: int) -> CleanupProof:
        task = _identifier(task_id, "task_id")
        deadline = _deadline(deadline_ns)
        with self._lock:
            tracked = self._service
            if tracked is None or self._task_id != task:
                raise OfflineProcessError("service_not_owned")
            proof = self._cleanup_one(tracked, deadline)
            if proof.exact_cleanup:
                self._service = None
                self._task_id = None
                self._resource_profile_id = None
            return proof

    def inventory(self, deadline_ns: int) -> int:
        _deadline(deadline_ns)
        with self._lock:
            return sum(int(_group_exists(item.group_id)) for item in self._tracked.values())

    def abort_and_reap(self, deadline_ns: int) -> CleanupProof:
        proof = super().abort_and_reap(deadline_ns)
        with self._lock:
            if proof.exact_cleanup:
                self._service = None
                self._task_id = None
                self._resource_profile_id = None
        return proof
