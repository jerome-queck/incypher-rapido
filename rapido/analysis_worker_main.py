"""Fixed Linux worker that runs Bash inside the challenge-local analysis directory."""

from __future__ import annotations

import json
import os
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Any

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 66 * 1024
MAX_COMMAND_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 128 * 1024
MAX_TIMEOUT_SECONDS = 180
FILE_LIMIT_BYTES = 512 * 1024 * 1024
FILE_DESCRIPTOR_LIMIT = 1024

_SAFE_ENV = {
    "PATH": (
        "/opt/venv/bin:/opt/angr/bin:/opt/java/openjdk/bin:/opt/ghidra/support:"
        "/opt/jadx/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    ),
    "JAVA_HOME": "/opt/java/openjdk",
    "GHIDRA_HEADLESS_MAXMEM": "768m",
    "GHIDRA_MAXMEM": "768m",
    "JAVA_TOOL_OPTIONS": (
        "-Xmx768m -XX:MaxRAM=1536m -XX:CompressedClassSpaceSize=128m "
        "-XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=128m "
        "-XX:ActiveProcessorCount=2 -XX:+UseSerialGC"
    ),
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "LOGNAME": "rapido",
    "MKL_NUM_THREADS": "2",
    "NUMEXPR_NUM_THREADS": "2",
    "OMP_NUM_THREADS": "2",
    "OPENBLAS_NUM_THREADS": "2",
    "POCL_CPU_MAX_CU_COUNT": "2",
    "USER": "rapido",
    "PYTHONDONTWRITEBYTECODE": "1",
}


class WorkerError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> WorkerError:
    return WorkerError(code, message)


def _set_limit(kind: int, soft: int, hard: int | None = None) -> None:
    old_soft, old_hard = resource.getrlimit(kind)

    def bounded(old: int, wanted: int) -> int:
        return wanted if old == resource.RLIM_INFINITY else min(old, wanted)

    new_hard = bounded(old_hard, soft if hard is None else hard)
    resource.setrlimit(kind, (min(bounded(old_soft, soft), new_hard), new_hard))


def _apply_limits(timeout_seconds: int) -> None:
    if hasattr(signal, "pthread_sigmask"):
        signals = {
            value
            for name in ("SIGXCPU", "SIGXFSZ")
            if isinstance((value := getattr(signal, name, None)), signal.Signals)
        }
        if signals:
            signal.pthread_sigmask(signal.SIG_UNBLOCK, signals)
    _set_limit(resource.RLIMIT_CORE, 0)
    _set_limit(resource.RLIMIT_FSIZE, FILE_LIMIT_BYTES)
    _set_limit(resource.RLIMIT_NOFILE, FILE_DESCRIPTOR_LIMIT)
    if hasattr(resource, "RLIMIT_NPROC"):
        _set_limit(resource.RLIMIT_NPROC, 192)
    _set_limit(resource.RLIMIT_CPU, timeout_seconds, timeout_seconds + 2)


def _descriptors() -> tuple[int, int, int]:
    if (
        len(sys.argv) != 7
        or sys.argv[1] != "--workspace-fd"
        or not sys.argv[2].isdigit()
        or sys.argv[3] != "--analysis-fd"
        or not sys.argv[4].isdigit()
        or sys.argv[5] != "--ephemeral-fd"
        or not sys.argv[6].isdigit()
    ):
        raise _fail("invalid_argument", "analysis worker descriptors are invalid")
    workspace_fd, analysis_fd, ephemeral_fd = (
        int(sys.argv[2]),
        int(sys.argv[4]),
        int(sys.argv[6]),
    )
    for descriptor in (workspace_fd, analysis_fd, ephemeral_fd):
        try:
            metadata = os.fstat(descriptor)
        except OSError as exc:
            raise _fail("invalid_argument", "analysis worker descriptor is unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise _fail("invalid_argument", "analysis worker descriptor is not a directory")
    return workspace_fd, analysis_fd, ephemeral_fd


def _request() -> tuple[str, int]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise _fail("limit_exceeded", "analysis request exceeds the byte limit")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _fail("invalid_argument", "analysis request is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"protocol", "command", "timeout_seconds"}:
        raise _fail("invalid_argument", "analysis request shape is invalid")
    command = value.get("command")
    timeout_seconds = value.get("timeout_seconds")
    if (
        value.get("protocol") != PROTOCOL_VERSION
        or not isinstance(command, str)
        or not command.strip()
        or len(command.encode("utf-8")) > MAX_COMMAND_BYTES
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        raise _fail("invalid_argument", "analysis request values are invalid")
    return command, timeout_seconds


def _run(command: str, timeout_seconds: int, ephemeral: str) -> dict[str, Any]:
    scratch = os.getcwd()
    environment = {
        **_SAFE_ENV,
        "HOME": scratch,
        "TMPDIR": scratch,
        "XDG_CACHE_HOME": os.path.join(scratch, ".cache"),
        "XDG_CONFIG_HOME": os.path.join(scratch, ".config"),
        "XDG_DATA_HOME": os.path.join(scratch, ".local", "share"),
    }
    environment["JAVA_TOOL_OPTIONS"] += (
        f" -Djava.io.tmpdir={ephemeral}"
        f" -Dapplication.cachedir={ephemeral}/cache"
        f" -Dapplication.settingsdir={ephemeral}/config"
        f" -Dapplication.tempdir={ephemeral}/temp"
    )
    try:
        process = subprocess.Popen(
            ("/bin/bash", "--noprofile", "--norc", "-c", command),
            cwd=".",
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env=environment,
        )
    except OSError as exc:
        raise _fail("tool_unavailable", "analysis shell could not start") from exc
    assert process.stdout is not None and process.stderr is not None
    streams = (process.stdout, process.stderr)
    buffers = {stream.fileno(): bytearray() for stream in streams}
    selector = selectors.DefaultSelector()
    retained = 0
    stop_reason: str | None = None
    deadline = time.monotonic() + timeout_seconds
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream.fileno(), selectors.EVENT_READ)
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_reason = "deadline"
                break
            for key, _ in selector.select(min(0.05, remaining)):
                try:
                    chunk = os.read(key.fd, 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                capacity = MAX_OUTPUT_BYTES - retained
                buffers[key.fd].extend(chunk[: max(0, capacity)])
                retained += min(len(chunk), max(0, capacity))
                if len(chunk) > capacity:
                    stop_reason = "output_limit"
                    break
            if stop_reason is not None:
                break
        if stop_reason is not None:
            # Signal syscalls are denied inside the arbitrary-code boundary so
            # challenge code cannot kill the supervisor or Board owner.  Return
            # immediately; the fixed outer parent kills this entire process group.
            return {
                "returncode": None,
                "stdout": bytes(buffers[process.stdout.fileno()]).decode("utf-8", "replace"),
                "stderr": bytes(buffers[process.stderr.fileno()]).decode("utf-8", "replace"),
                "stop_reason": stop_reason,
            }
        try:
            returncode = process.wait(timeout=1.0)
        except subprocess.TimeoutExpired as exc:
            raise _fail("tool_cleanup_failed", "analysis command did not terminate") from exc
        if (
            returncode < 0
            and -returncode
            in {
                int(getattr(signal, "SIGXCPU", signal.SIGKILL)),
                int(getattr(signal, "SIGXFSZ", signal.SIGKILL)),
                int(signal.SIGKILL),
            }
            and stop_reason is None
        ):
            raise _fail("resource_limit", "analysis command exceeded a resource limit")
        return {
            "returncode": returncode,
            "stdout": bytes(buffers[process.stdout.fileno()]).decode("utf-8", "replace"),
            "stderr": bytes(buffers[process.stderr.fileno()]).decode("utf-8", "replace"),
            "stop_reason": stop_reason,
        }
    finally:
        selector.close()
        for stream in streams:
            stream.close()


def _emit(value: dict[str, Any]) -> None:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise _fail("output_too_large", "analysis response exceeds the byte limit")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def main() -> int:
    try:
        workspace_fd, analysis_fd, ephemeral_fd = _descriptors()
        ephemeral = os.path.realpath(f"/proc/self/fd/{ephemeral_fd}")
        command, timeout_seconds = _request()
        _apply_limits(timeout_seconds)
        from rapido.artifact_sandbox import SandboxUnavailable, apply_analysis_sandbox

        try:
            sandbox = apply_analysis_sandbox(workspace_fd, analysis_fd, ephemeral_fd)
        except SandboxUnavailable as exc:
            raise _fail("tool_unavailable", "required analysis sandbox is unavailable") from exc
        os.fchdir(analysis_fd)
        os.umask(0o077)
        result = _run(command, timeout_seconds, ephemeral)
        result["sandbox"] = sandbox
        result["cwd"] = "rapido-analysis"
        _emit({"protocol": PROTOCOL_VERSION, "ok": True, "result": result})
        return 0
    except MemoryError:
        error = {"code": "resource_limit", "message": "analysis worker exceeded memory limit"}
    except WorkerError as exc:
        error = {"code": exc.code, "message": exc.message}
    except Exception:  # noqa: BLE001 - hide sandbox and child internals
        error = {"code": "tool_failed", "message": "analysis worker failed safely"}
    try:
        _emit({"protocol": PROTOCOL_VERSION, "ok": False, "error": error})
        return 0
    except Exception:  # noqa: BLE001 - error emission cannot recurse
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
