"""Fixed worker for a network-denied Python target script."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import traceback
from typing import Any

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 8 * 1024
MAX_SCRIPT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 128 * 1024


class WorkerError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _BoundedBinary(io.RawIOBase):
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.truncated = False

    def writable(self) -> bool:
        return True

    def write(self, value: bytes | bytearray) -> int:
        raw = bytes(value)
        capacity = max(0, self.limit - len(self.data))
        self.data.extend(raw[:capacity])
        self.truncated = self.truncated or len(raw) > capacity
        return len(raw)


class _BoundedText(io.TextIOBase):
    def __init__(self, limit: int) -> None:
        self.buffer = _BoundedBinary(limit)

    def writable(self) -> bool:
        return True

    def write(self, value: str) -> int:
        if not isinstance(value, str):
            raise TypeError("text output must be str")
        self.buffer.write(value.encode("utf-8", "replace"))
        return len(value)

    def flush(self) -> None:
        return None

    def value(self) -> str:
        return bytes(self.buffer.data).decode("utf-8", "replace")


def _fail(code: str, message: str) -> WorkerError:
    return WorkerError(code, message)


def _descriptors() -> tuple[int, int, int, int, int, int]:
    expected = (
        "--workspace-fd",
        "--analysis-fd",
        "--ephemeral-fd",
        "--script-fd",
        "--broker-fd",
        "--result-fd",
    )
    if len(sys.argv) != 13:
        raise _fail("invalid_argument", "target-script descriptors are invalid")
    values: list[int] = []
    for offset, name in enumerate(expected, 1):
        index = offset * 2 - 1
        if sys.argv[index] != name or not sys.argv[index + 1].isdigit():
            raise _fail("invalid_argument", "target-script descriptors are invalid")
        values.append(int(sys.argv[index + 1]))
    workspace_fd, analysis_fd, ephemeral_fd, script_fd, broker_fd, result_fd = values
    for descriptor in (workspace_fd, analysis_fd, ephemeral_fd):
        try:
            metadata = os.fstat(descriptor)
        except OSError as exc:
            raise _fail("invalid_argument", "target-script directory is unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise _fail("invalid_argument", "target-script directory is invalid")
    try:
        script = os.fstat(script_fd)
    except OSError as exc:
        raise _fail("invalid_argument", "target script is unavailable") from exc
    if (
        not stat.S_ISREG(script.st_mode)
        or script.st_nlink != 1
        or not 0 < script.st_size <= MAX_SCRIPT_BYTES
    ):
        raise _fail("invalid_argument", "target script must be a bounded single-link file")
    for descriptor in (broker_fd, result_fd):
        try:
            os.fstat(descriptor)
        except OSError as exc:
            raise _fail("invalid_argument", "target-script channel is unavailable") from exc
    return workspace_fd, analysis_fd, ephemeral_fd, script_fd, broker_fd, result_fd


def _request() -> tuple[str, str, int]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise _fail("limit_exceeded", "target-script request exceeds its limit")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _fail("invalid_argument", "target-script request is invalid") from exc
    if not isinstance(value, dict) or set(value) != {
        "protocol",
        "generation",
        "path",
        "timeout_seconds",
    }:
        raise _fail("invalid_argument", "target-script request shape is invalid")
    generation = value.get("generation")
    path = value.get("path")
    timeout_seconds = value.get("timeout_seconds")
    if (
        value.get("protocol") != PROTOCOL_VERSION
        or not isinstance(generation, str)
        or not 16 <= len(generation) <= 128
        or not generation.isascii()
        or not isinstance(path, str)
        or not path.startswith("rapido-analysis/")
        or not path.endswith(".py")
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 120
    ):
        raise _fail("invalid_argument", "target-script request values are invalid")
    return generation, path, timeout_seconds


def _script_bytes(descriptor: int) -> bytes:
    raw = os.pread(descriptor, MAX_SCRIPT_BYTES + 1, 0)
    if not raw or len(raw) > MAX_SCRIPT_BYTES:
        raise _fail("invalid_argument", "target script exceeds its limit")
    return raw


def _emit(descriptor: int, value: dict[str, Any]) -> None:
    raw = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
    if len(raw) > MAX_RESPONSE_BYTES:
        value = {
            "protocol": PROTOCOL_VERSION,
            "ok": False,
            "error": {"code": "output_too_large", "message": "target script output is too large"},
        }
        raw = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("target-script result channel closed")
        view = view[written:]


def _run(script: bytes, path: str, broker_fd: int, generation: str) -> dict[str, Any]:
    from rapido.target_script_client import TargetClient

    output = _BoundedText(MAX_OUTPUT_BYTES // 2)
    diagnostic = _BoundedText(MAX_OUTPUT_BYTES // 2)
    previous_stdout, previous_stderr, previous_argv = sys.stdout, sys.stderr, sys.argv
    returncode = 0
    TargetClient._install(broker_fd, generation)
    try:
        sys.stdout = output
        sys.stderr = diagnostic
        sys.argv = [path]
        namespace = {
            "__builtins__": __builtins__,
            "__file__": path,
            "__name__": "__main__",
            "__package__": None,
        }
        try:
            exec(compile(script, path, "exec"), namespace, namespace)  # noqa: S102
        except SystemExit as exc:
            returncode = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
            if exc.code not in (None, 0) and not isinstance(exc.code, int):
                diagnostic.write(str(exc.code))
        except BaseException as exc:  # noqa: BLE001 - script failures are tool results
            returncode = 1
            traceback.print_exception(type(exc), exc, exc.__traceback__, limit=8, file=diagnostic)
    finally:
        TargetClient._uninstall()
        sys.stdout, sys.stderr, sys.argv = previous_stdout, previous_stderr, previous_argv
    return {
        "returncode": returncode,
        "stdout": output.value(),
        "stderr": diagnostic.value(),
        "truncated": output.buffer.truncated or diagnostic.buffer.truncated,
    }


def main() -> int:
    result_fd = -1
    try:
        workspace_fd, analysis_fd, ephemeral_fd, script_fd, broker_fd, result_fd = _descriptors()
        generation, path, timeout_seconds = _request()
        script = _script_bytes(script_fd)
        from rapido.analysis_worker_main import _apply_limits
        from rapido.artifact_sandbox import SandboxUnavailable, apply_analysis_sandbox

        _apply_limits(timeout_seconds)
        try:
            sandbox = apply_analysis_sandbox(workspace_fd, analysis_fd, ephemeral_fd)
        except SandboxUnavailable as exc:
            raise _fail("tool_unavailable", "required analysis sandbox is unavailable") from exc
        os.fchdir(analysis_fd)
        os.umask(0o077)
        result = _run(script, path, broker_fd, generation)
        result["sandbox"] = sandbox
        result["cwd"] = "rapido-analysis"
        response = {"protocol": PROTOCOL_VERSION, "ok": True, "result": result}
    except MemoryError:
        response = {
            "protocol": PROTOCOL_VERSION,
            "ok": False,
            "error": {"code": "resource_limit", "message": "target script exceeded memory limit"},
        }
    except WorkerError as exc:
        response = {
            "protocol": PROTOCOL_VERSION,
            "ok": False,
            "error": {"code": exc.code, "message": exc.message},
        }
    except Exception:  # noqa: BLE001 - hide sandbox and worker internals
        response = {
            "protocol": PROTOCOL_VERSION,
            "ok": False,
            "error": {"code": "tool_failed", "message": "target script failed safely"},
        }
    if result_fd < 0:
        return 70
    try:
        _emit(result_fd, response)
        return 0
    except Exception:  # noqa: BLE001 - result emission cannot recurse
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
