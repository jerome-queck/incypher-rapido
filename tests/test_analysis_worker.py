from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from rapido import analysis_worker, analysis_worker_main
from rapido.analysis_worker import (
    MAX_COMMAND_BYTES,
    MAX_TIMEOUT_SECONDS,
    PROTOCOL_VERSION,
    _analysis_directory,
    _request_bytes,
    _response,
)
from rapido.tools import ToolError


def test_request_protocol_is_bounded_and_exact() -> None:
    request = json.loads(_request_bytes("printf test", MAX_TIMEOUT_SECONDS))
    assert request == {
        "protocol": PROTOCOL_VERSION,
        "command": "printf test",
        "timeout_seconds": MAX_TIMEOUT_SECONDS,
    }
    with pytest.raises(ToolError, match="non-empty"):
        _request_bytes(" ", 1)
    with pytest.raises(ToolError, match="byte limit"):
        _request_bytes("x" * (MAX_COMMAND_BYTES + 1), 1)
    with pytest.raises(ToolError, match="permitted range"):
        _request_bytes("true", MAX_TIMEOUT_SECONDS + 1)


def test_analysis_fd_limit_supports_large_toolchains() -> None:
    assert analysis_worker_main.FILE_DESCRIPTOR_LIMIT == 1024


def test_response_protocol_rejects_unrecognized_remote_errors() -> None:
    assert _response(
        json.dumps(
            {
                "protocol": PROTOCOL_VERSION,
                "ok": True,
                "result": {"returncode": 0},
            }
        ).encode()
    ) == {"returncode": 0}
    with pytest.raises(ToolError) as caught:
        _response(
            json.dumps(
                {
                    "protocol": PROTOCOL_VERSION,
                    "ok": False,
                    "error": {"code": "invented", "message": "unsafe detail"},
                }
            ).encode()
        )
    assert caught.value.code == "tool_failed"


def test_analysis_directory_rejects_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "rapido-analysis").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ToolError) as caught:
        _analysis_directory(tmp_path)
    assert caught.value.code == "tool_unavailable"


def test_resource_headroom_rejects_saturated_cgroup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        analysis_worker,
        "_cgroup_value",
        lambda name: analysis_worker.CGROUP_PID_ADMISSION if name == "pids.current" else 0,
    )
    with pytest.raises(ToolError) as caught:
        analysis_worker._require_resource_headroom()
    assert caught.value.code == "resource_limit"


def test_ptrace_isolation_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Disabled:
        @staticmethod
        def read_text(*, encoding: str) -> str:
            assert encoding == "ascii"
            return "0\n"

    monkeypatch.setattr(analysis_worker, "_PTRACE_SCOPE", Disabled())
    with pytest.raises(ToolError) as caught:
        analysis_worker._require_ptrace_isolation()
    assert caught.value.code == "tool_unavailable"


def test_watchdog_kills_oversized_process_group(monkeypatch: pytest.MonkeyPatch) -> None:
    class Process:
        pid = 42

        @staticmethod
        def poll() -> None:
            return None

    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(analysis_worker, "WATCHDOG_INTERVAL_SECONDS", 0.001)
    monkeypatch.setattr(
        analysis_worker,
        "_process_group_usage",
        lambda _process_group: (analysis_worker.GROUP_RSS_LIMIT_BYTES + 1, 3, 2),
    )
    monkeypatch.setattr(
        analysis_worker.os,
        "killpg",
        lambda process_group, signal_number: killed.append((process_group, signal_number)),
    )
    state: dict[str, int | str] = {
        "peak_rss_bytes": 0,
        "peak_tasks": 0,
        "peak_processes": 0,
    }
    analysis_worker._watch_process_group(Process(), threading.Event(), state)  # type: ignore[arg-type]
    assert state["breach"] == "memory"
    assert state["peak_tasks"] == 3
    assert killed == [(42, analysis_worker.signal.SIGKILL)]
