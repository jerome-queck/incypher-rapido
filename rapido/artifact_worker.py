"""Killable, descriptor-only isolation for optional artifact parsers.

The public entry point accepts an already-confined regular-file descriptor. It
never accepts an executable or source path: both the Python worker and its JSON
protocol are fixed here. The child starts a new process group; Linux confinement
prevents it or descendants from changing groups, so cleanup kills the full tree.
"""

from __future__ import annotations

import json
import os
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 130 * 1024
MAX_DIAGNOSTIC_BYTES = 8 * 1024
WORKER_TIMEOUT_SECONDS = 3.0
WORKER_DRAIN_SECONDS = 1.0
_SCRATCH_ROOT = "/tmp"
_SCRATCH_PREFIX = "rapido-artifact-"

_WORKER_SCRIPT = str(Path(__file__).with_name("artifact_worker_main.py").resolve())
_PYTHON_EXECUTABLE = os.path.abspath(sys.executable)
_SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
_OPERATIONS = frozenset({"disassembly", "image", "pcap", "pdf", "pe", "tar"})
_REMOTE_ERROR_CODES = frozenset(
    """dependency_unavailable input_too_large internal_error invalid_argument invalid_artifact
    invalid_cursor invalid_encoding limit_exceeded not_a_file output_too_large read_failed
    resource_limit source_changed stale_cursor tool_cleanup_failed tool_failed tool_unavailable
    unsupported_format unsupported_platform""".split()  # noqa: SIM905
)


def _require_linux_sandbox() -> None:
    if sys.platform != "linux":
        raise _error(
            "tool_unavailable",
            "artifact worker requires Linux Landlock and seccomp confinement",
        )


def _error(code: str, message: str) -> Exception:
    from .tools import ToolError

    return ToolError(code, message)


def _worker_command(
    descriptor: int, scratch_descriptor: int, worker_script: str = _WORKER_SCRIPT
) -> tuple[str, ...]:
    return (
        _PYTHON_EXECUTABLE,
        "-I",
        "-B",
        worker_script,
        "--source-fd",
        str(descriptor),
        "--scratch-fd",
        str(scratch_descriptor),
    )


def _create_scratch() -> tuple[str, int]:
    path = tempfile.mkdtemp(prefix=_SCRATCH_PREFIX, dir=_SCRATCH_ROOT)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        shutil.rmtree(path, ignore_errors=True)
        raise
    return path, descriptor


def _remove_scratch(path: str, descriptor: int) -> None:
    try:
        os.fchmod(descriptor, 0o700)
    except OSError:
        pass
    os.close(descriptor)

    def retry(function: Any, target: str, _error: Any) -> None:
        os.chmod(target, 0o700, follow_symlinks=False)
        function(target)

    shutil.rmtree(path, onerror=retry)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _request_bytes(operation: str, parameters: Mapping[str, Any]) -> bytes:
    request = {
        "protocol": PROTOCOL_VERSION,
        "operation": operation,
        "parameters": dict(parameters),
    }
    try:
        encoded = json.dumps(request, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _error("invalid_argument", "artifact-worker parameters must be bounded JSON") from exc
    if len(encoded) > MAX_REQUEST_BYTES:
        raise _error("limit_exceeded", "artifact-worker request exceeds the byte limit")
    return encoded


def _read_protocol_response(raw: bytes) -> Any:
    try:
        response = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error("tool_failed", "artifact worker returned an invalid response") from exc
    if not isinstance(response, dict) or response.get("protocol") != PROTOCOL_VERSION:
        raise _error("tool_failed", "artifact worker returned an invalid protocol version")
    if response.get("ok") is True and set(response) == {"protocol", "ok", "result"}:
        return response["result"]
    if response.get("ok") is False and set(response) == {"protocol", "ok", "error"}:
        remote = response["error"]
        if (
            not isinstance(remote, dict)
            or set(remote) != {"code", "message"}
            or not isinstance(remote.get("code"), str)
            or not isinstance(remote.get("message"), str)
        ):
            raise _error("tool_failed", "artifact worker returned an invalid error")
        code = remote["code"] if remote["code"] in _REMOTE_ERROR_CODES else "tool_failed"
        message = remote["message"] if code == remote["code"] else "artifact worker failed safely"
        if not message.isascii() or not 1 <= len(message) <= 256:
            message = "artifact worker failed safely"
        raise _error(code, message)
    raise _error("tool_failed", "artifact worker returned an invalid response shape")


def _run_worker(
    descriptor: int,
    request: bytes,
    *,
    timeout_seconds: float = WORKER_TIMEOUT_SECONDS,
    drain_seconds: float = WORKER_DRAIN_SECONDS,
    worker_script: str = _WORKER_SCRIPT,
) -> Any:
    """Run the fixed protocol.  Private overrides exist only for failure fixtures."""
    try:
        scratch_path, scratch_descriptor = _create_scratch()
    except OSError as exc:
        raise _error("tool_unavailable", "private artifact scratch could not be created") from exc
    try:
        process = subprocess.Popen(
            _worker_command(descriptor, scratch_descriptor, worker_script),
            cwd="/",
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            pass_fds=(descriptor, scratch_descriptor),
            close_fds=True,
            start_new_session=True,
            env=_SAFE_ENV,
        )
    except OSError as exc:
        _remove_scratch(scratch_path, scratch_descriptor)
        raise _error("tool_unavailable", "fixed artifact worker could not start") from exc
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    output = bytearray()
    diagnostic = bytearray()
    selector = selectors.DefaultSelector()
    reason: str | None = None
    deadline = time.monotonic() + timeout_seconds
    try:
        try:
            process.stdin.write(request)
            process.stdin.close()
        except (BrokenPipeError, OSError):
            process.stdin.close()
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream.fileno(), selectors.EVENT_READ, stream is process.stdout)
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "deadline"
                break
            for key, _ in selector.select(min(0.05, remaining)):
                try:
                    chunk = os.read(key.fd, 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                destination = output if key.data else diagnostic
                limit = MAX_RESPONSE_BYTES if key.data else MAX_DIAGNOSTIC_BYTES
                capacity = limit - len(destination)
                destination.extend(chunk[: max(0, capacity)])
                if len(chunk) > capacity:
                    reason = "response_limit" if key.data else "diagnostic_limit"
                    break
            if reason is not None:
                break
        if reason is not None:
            _kill_process_group(process)
        try:
            returncode = process.wait(timeout=drain_seconds)
        except subprocess.TimeoutExpired as exc:
            _kill_process_group(process)
            raise _error(
                "tool_cleanup_failed", "artifact worker did not confirm termination"
            ) from exc
        if reason == "deadline":
            raise _error("deadline_exceeded", "artifact worker exceeded the wall-time limit")
        if reason in {"response_limit", "diagnostic_limit"}:
            raise _error("output_too_large", "artifact worker exceeded the output byte limit")
        if returncode < 0 and -returncode in {
            getattr(signal, "SIGXCPU", signal.SIGKILL),
            getattr(signal, "SIGXFSZ", signal.SIGKILL),
            signal.SIGKILL,
        }:
            raise _error("resource_limit", "artifact worker exceeded a resource limit")
        if returncode != 0:
            raise _error("tool_failed", "artifact worker exited without a valid result")
        return _read_protocol_response(bytes(output))
    finally:
        # A successful worker may still have a same-group descendant holding no
        # pipe. Linux confinement prevents descendants from escaping this group.
        _kill_process_group(process)
        selector.close()
        for stream in (process.stdout, process.stderr):
            stream.close()
        if not process.stdin.closed:
            process.stdin.close()
        if process.poll() is None:
            try:
                process.wait(timeout=drain_seconds)
            except subprocess.TimeoutExpired:
                _kill_process_group(process)
        _remove_scratch(scratch_path, scratch_descriptor)


def run_artifact_worker(
    descriptor: int,
    operation: str,
    *,
    size: int,
    cursor: str | None,
    base: Mapping[str, Any],
) -> Any:
    """Run one allowlisted parser against an already-confined regular descriptor."""
    _require_linux_sandbox()
    if type(descriptor) is not int or descriptor < 0:
        raise _error("invalid_argument", "artifact worker requires an open file descriptor")
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise _error("read_failed", "artifact descriptor is not readable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise _error("not_a_file", "artifact worker requires a regular file descriptor")
    if type(size) is not int or size != metadata.st_size:
        raise _error("source_changed", "artifact size differs from the opened source")
    if operation not in _OPERATIONS:
        raise _error("invalid_argument", "artifact-worker operation is not allowlisted")
    display_path = base.get("path")
    if not isinstance(display_path, str):
        raise _error("invalid_argument", "artifact-worker base path is invalid")
    worker_base = {**base, "path": "[artifact]"}
    parameters = {"size": size, "cursor": cursor, "base": worker_base}
    result = _run_worker(descriptor, _request_bytes(operation, parameters))
    if isinstance(result, dict) and result.get("path") == "[artifact]":
        result["path"] = display_path
    return result


__all__ = ["run_artifact_worker"]
