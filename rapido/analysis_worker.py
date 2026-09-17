"""Credential-blind, network-denied shell execution inside one challenge workspace."""

from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = 1
MAX_COMMAND_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 128 * 1024
MAX_DIAGNOSTIC_BYTES = 8 * 1024
MAX_TIMEOUT_SECONDS = 180
WORKER_DRAIN_SECONDS = 2.0
ANALYSIS_DIRECTORY = "rapido-analysis"
GROUP_RSS_LIMIT_BYTES = 2 * 1024 * 1024 * 1024
GROUP_TASK_LIMIT = 48
CGROUP_MEMORY_ADMISSION_BYTES = 18 * 1024 * 1024 * 1024
CGROUP_PID_ADMISSION = 192
WATCHDOG_INTERVAL_SECONDS = 0.05
_PTRACE_SCOPE = Path("/proc/sys/kernel/yama/ptrace_scope")

_WORKER_SCRIPT = str(Path(__file__).with_name("analysis_worker_main.py").resolve())
_PYTHON_EXECUTABLE = os.path.abspath(sys.executable)
_SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
_ANALYSIS_SLOTS = threading.BoundedSemaphore(8)
_REMOTE_ERROR_CODES = frozenset(
    {
        "deadline_exceeded",
        "internal_error",
        "invalid_argument",
        "limit_exceeded",
        "output_too_large",
        "resource_limit",
        "tool_cleanup_failed",
        "tool_failed",
        "tool_unavailable",
        "unsupported_platform",
    }
)


def _error(code: str, message: str) -> Exception:
    from .tools import ToolError

    return ToolError(code, message)


def _directory_fd(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def _analysis_directory(workspace: Path) -> Path:
    target = workspace / ANALYSIS_DIRECTORY
    try:
        target.mkdir(mode=0o700)
    except FileExistsError:
        metadata = target.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise _error("tool_unavailable", "analysis workspace path is not a real directory")
    try:
        metadata = target.stat(follow_symlinks=False)
    except OSError as exc:
        raise _error("tool_unavailable", "analysis workspace is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise _error("tool_unavailable", "analysis workspace ownership is invalid")
    return target


def _request_bytes(command: str, timeout_seconds: int) -> bytes:
    if not isinstance(command, str) or not command.strip():
        raise _error("invalid_argument", "shell command must be non-empty text")
    try:
        command_bytes = command.encode("utf-8")
    except UnicodeError as exc:
        raise _error("invalid_argument", "shell command must be valid UTF-8") from exc
    if len(command_bytes) > MAX_COMMAND_BYTES:
        raise _error("limit_exceeded", "shell command exceeds the byte limit")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise _error("invalid_argument", "shell timeout is outside the permitted range")
    return json.dumps(
        {
            "protocol": PROTOCOL_VERSION,
            "command": command,
            "timeout_seconds": timeout_seconds,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode()


def _response(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error("tool_failed", "analysis worker returned invalid JSON") from exc
    if not isinstance(value, dict) or value.get("protocol") != PROTOCOL_VERSION:
        raise _error("tool_failed", "analysis worker returned an invalid protocol version")
    if value.get("ok") is True and set(value) == {"protocol", "ok", "result"}:
        result = value["result"]
        if not isinstance(result, dict):
            raise _error("tool_failed", "analysis worker result is invalid")
        return result
    if value.get("ok") is False and set(value) == {"protocol", "ok", "error"}:
        remote = value["error"]
        if not isinstance(remote, dict) or set(remote) != {"code", "message"}:
            raise _error("tool_failed", "analysis worker error is invalid")
        code = remote.get("code")
        message = remote.get("message")
        if code not in _REMOTE_ERROR_CODES or not isinstance(message, str):
            raise _error("tool_failed", "analysis worker failed safely")
        raise _error(
            code,
            message
            if 1 <= len(message) <= 256 and message.isascii()
            else "analysis worker failed safely",
        )
    raise _error("tool_failed", "analysis worker returned an invalid response shape")


def _cgroup_value(name: str) -> int | None:
    try:
        raw = (Path("/sys/fs/cgroup") / name).read_text(encoding="ascii").strip()
        return int(raw)
    except (FileNotFoundError, OSError, UnicodeError, ValueError):
        return None


def _require_resource_headroom() -> None:
    memory = _cgroup_value("memory.current")
    tasks = _cgroup_value("pids.current")
    if (memory is not None and memory >= CGROUP_MEMORY_ADMISSION_BYTES) or (
        tasks is not None and tasks >= CGROUP_PID_ADMISSION
    ):
        raise _error("resource_limit", "analysis capacity is temporarily exhausted")


def _require_ptrace_isolation() -> None:
    """Keep child debugging while fail-closing parent/sibling process inspection."""
    try:
        scope = int(_PTRACE_SCOPE.read_text(encoding="ascii").strip())
    except (FileNotFoundError, OSError, UnicodeError, ValueError) as exc:
        raise _error(
            "tool_unavailable", "required process-inspection isolation is unavailable"
        ) from exc
    if scope < 1:
        raise _error("tool_unavailable", "required process-inspection isolation is disabled")


def _process_group_usage(process_group: int) -> tuple[int, int, int]:
    resident_pages = 0
    tasks = 0
    processes = 0
    try:
        entries = os.scandir("/proc")
    except OSError:
        return 0, 0, 0
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                raw = Path(entry.path, "stat").read_text(encoding="ascii")
                fields = raw[raw.rfind(") ") + 2 :].split()
                if len(fields) < 22 or int(fields[2]) != process_group:
                    continue
                tasks += max(1, int(fields[17]))
                resident_pages += max(0, int(fields[21]))
                processes += 1
            except (FileNotFoundError, OSError, UnicodeError, ValueError):
                continue
    return resident_pages * os.sysconf("SC_PAGE_SIZE"), tasks, processes


def _watch_process_group(
    process: subprocess.Popen[bytes], stop: threading.Event, state: dict[str, int | str]
) -> None:
    while not stop.wait(WATCHDOG_INTERVAL_SECONDS):
        if process.poll() is not None:
            return
        resident, tasks, processes = _process_group_usage(process.pid)
        state["peak_rss_bytes"] = max(int(state["peak_rss_bytes"]), resident)
        state["peak_tasks"] = max(int(state["peak_tasks"]), tasks)
        state["peak_processes"] = max(int(state["peak_processes"]), processes)
        if resident <= GROUP_RSS_LIMIT_BYTES and tasks <= GROUP_TASK_LIMIT:
            continue
        state["breach"] = "memory" if resident > GROUP_RSS_LIMIT_BYTES else "tasks"
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return


def _run_analysis_worker(workspace: Path, command: str, timeout_seconds: int) -> dict[str, Any]:
    if sys.platform != "linux":
        raise _error("tool_unavailable", "analysis shell requires Linux confinement")
    analysis = _analysis_directory(workspace)
    workspace_fd: int | None = None
    analysis_fd: int | None = None
    ephemeral_fd: int | None = None
    ephemeral: Path | None = None
    try:
        workspace_fd = _directory_fd(workspace)
        analysis_fd = _directory_fd(analysis)
        ephemeral = Path(tempfile.mkdtemp(prefix="rapido-analysis-", dir="/tmp"))
        ephemeral_fd = _directory_fd(ephemeral)
    except OSError as exc:
        if workspace_fd is not None:
            os.close(workspace_fd)
        if analysis_fd is not None:
            os.close(analysis_fd)
        if ephemeral_fd is not None:
            os.close(ephemeral_fd)
        if ephemeral is not None:
            shutil.rmtree(ephemeral, ignore_errors=True)
        raise _error("tool_unavailable", "analysis workspace descriptors are unavailable") from exc
    request = _request_bytes(command, timeout_seconds)
    process: subprocess.Popen[bytes] | None = None
    watchdog_stop = threading.Event()
    watchdog: threading.Thread | None = None
    usage: dict[str, int | str] = {
        "peak_rss_bytes": 0,
        "peak_tasks": 0,
        "peak_processes": 0,
    }
    try:
        try:
            process = subprocess.Popen(
                (
                    _PYTHON_EXECUTABLE,
                    "-I",
                    "-B",
                    _WORKER_SCRIPT,
                    "--workspace-fd",
                    str(workspace_fd),
                    "--analysis-fd",
                    str(analysis_fd),
                    "--ephemeral-fd",
                    str(ephemeral_fd),
                ),
                cwd="/",
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=(workspace_fd, analysis_fd, ephemeral_fd),
                close_fds=True,
                start_new_session=True,
                env=_SAFE_ENV,
            )
        except OSError as exc:
            raise _error("tool_unavailable", "fixed analysis worker could not start") from exc
        watchdog = threading.Thread(
            target=_watch_process_group,
            args=(process, watchdog_stop, usage),
            name="rapido-analysis-watchdog",
            daemon=True,
        )
        watchdog.start()
        try:
            stdout, stderr = process.communicate(
                request,
                timeout=timeout_seconds + WORKER_DRAIN_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=WORKER_DRAIN_SECONDS)
            raise _error(
                "tool_cleanup_failed", "analysis worker exceeded its outer deadline"
            ) from exc
        if "breach" in usage:
            raise _error("resource_limit", "analysis process tree exceeded its resource limit")
        if len(stdout) > MAX_RESPONSE_BYTES or len(stderr) > MAX_DIAGNOSTIC_BYTES:
            raise _error("output_too_large", "analysis worker exceeded its protocol output limit")
        if process.returncode != 0:
            raise _error("tool_failed", "analysis worker exited without a valid result")
        result = _response(stdout)
        result["peak_group_rss_bytes"] = int(usage["peak_rss_bytes"])
        result["peak_group_tasks"] = int(usage["peak_tasks"])
        result["peak_group_processes"] = int(usage["peak_processes"])
        return result
    finally:
        watchdog_stop.set()
        if watchdog is not None:
            watchdog.join(timeout=WORKER_DRAIN_SECONDS)
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.poll() is None:
                try:
                    process.wait(timeout=WORKER_DRAIN_SECONDS)
                except subprocess.TimeoutExpired:
                    pass
        os.close(ephemeral_fd)
        os.close(analysis_fd)
        os.close(workspace_fd)
        try:
            shutil.rmtree(ephemeral)
        except OSError as exc:
            raise _error(
                "tool_cleanup_failed", "ephemeral analysis scratch was not removed"
            ) from exc


def run_analysis_worker(workspace: Path, command: str, timeout_seconds: int) -> dict[str, Any]:
    """Run arbitrary Bash in a persisted subdirectory with no auth/state sibling visibility."""
    _require_ptrace_isolation()
    _require_resource_headroom()
    if not _ANALYSIS_SLOTS.acquire(timeout=min(10, timeout_seconds)):
        raise _error("tool_busy", "all eight analysis workers are busy")
    try:
        return _run_analysis_worker(workspace, command, timeout_seconds)
    finally:
        _ANALYSIS_SLOTS.release()


__all__ = ["ANALYSIS_DIRECTORY", "MAX_TIMEOUT_SECONDS", "run_analysis_worker"]
