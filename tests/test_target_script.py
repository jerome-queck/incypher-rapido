from __future__ import annotations

import inspect
import os
import socket
import threading
from pathlib import Path
from unittest import mock

import pytest

from rapido.target import (
    MAX_TARGET_SCRIPT_CONNECTIONS,
    MAX_TARGET_SCRIPT_LIVE_CONNECTIONS,
    MAX_TARGET_SCRIPT_OPERATIONS,
    MAX_TARGET_SCRIPT_TIMEOUT_SECONDS,
    TargetEndpoint,
    TargetToolRegistry,
    _open_target_script,
    _TargetScriptBroker,
)
from rapido.target_script_client import TargetClient, TargetError
from rapido.tools import ToolError, Workspace


class WireSocket:
    def __init__(self, responses: list[bytes], *, send_barrier: threading.Barrier | None = None):
        self.responses = list(responses)
        self.sent: list[bytes] = []
        self.closed = False
        self.send_barrier = send_barrier

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def send(self, data) -> int:
        self.sendall(bytes(data))
        return len(data)

    def sendall(self, data: bytes) -> None:
        raw = bytes(data)
        self.sent.append(raw)
        if self.send_barrier is not None and raw.startswith(b"PING"):
            self.send_barrier.wait(timeout=1)

    def recv(self, limit: int) -> bytes:
        if not self.responses:
            raise TimeoutError
        value = self.responses.pop(0)
        return value[:limit]

    def shutdown(self, _direction: int) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def _broker(
    tmp_path: Path,
    endpoints: tuple[TargetEndpoint, ...],
    connector,
) -> tuple[TargetToolRegistry, _TargetScriptBroker, socket.socket]:
    registry = TargetToolRegistry(tmp_path, endpoints, connector=connector)
    parent, child = socket.socketpair()
    return registry, _TargetScriptBroker(registry, parent, "a" * 32, 120), child


def test_model_surface_is_one_saved_script_without_authority_or_inline_code(tmp_path: Path) -> None:
    registry = TargetToolRegistry(tmp_path, (TargetEndpoint("tcp", "192.0.2.5", 31337),))
    spec = {item["name"]: item for item in registry.dynamic_tools()}["run_target_script"]
    schema = spec["inputSchema"]
    assert schema["required"] == ["path", "source_paths"]
    assert set(schema["properties"]) == {"path", "source_paths", "timeout_seconds"}
    assert schema["additionalProperties"] is False
    assert not {"code", "argv", "env", "host", "port", "url"} & set(schema["properties"])


def test_target_script_path_is_anchored_single_link_python_and_64k(tmp_path: Path) -> None:
    analysis = tmp_path / "rapido-analysis"
    analysis.mkdir()
    script = analysis / "solve.py"
    script.write_text("print('ok')\n")
    workspace = Workspace(tmp_path)
    directory_fd = os.open(analysis, os.O_RDONLY | os.O_DIRECTORY)
    try:
        descriptor, normalized = _open_target_script(
            directory_fd, workspace, "rapido-analysis/solve.py"
        )
        assert normalized == "rapido-analysis/solve.py"
        os.close(descriptor)
        with pytest.raises(ToolError, match="below rapido-analysis"):
            _open_target_script(directory_fd, workspace, "solve.py")
        with pytest.raises(ToolError, match=".py file"):
            _open_target_script(directory_fd, workspace, "rapido-analysis/solve.sh")
        hardlink = analysis / "linked.py"
        os.link(script, hardlink)
        with pytest.raises(ToolError, match="single-link"):
            _open_target_script(directory_fd, workspace, "rapido-analysis/linked.py")
        large = analysis / "large.py"
        large.write_bytes(b"x" * (64 * 1024 + 1))
        with pytest.raises(ToolError, match="64 KiB"):
            _open_target_script(directory_fd, workspace, "rapido-analysis/large.py")
    finally:
        os.close(directory_fd)


def test_registry_validates_sources_and_invokes_isolated_worker(tmp_path: Path) -> None:
    analysis = tmp_path / "rapido-analysis"
    analysis.mkdir()
    (analysis / "solve.py").write_text("print('ok')\n")
    (tmp_path / "input.bin").write_bytes(b"challenge")
    registry = TargetToolRegistry(tmp_path, (TargetEndpoint("tcp", "192.0.2.5", 31337),))
    worker_result = {
        "returncode": 0,
        "stdout": "ok\n",
        "stderr": "",
        "sandbox": {"network": "denied"},
        "broker": {"operations": 0},
    }
    with mock.patch("rapido.target._run_target_script_worker", return_value=worker_result) as run:
        result = registry.dispatch(
            "run_target_script",
            {
                "path": "rapido-analysis/solve.py",
                "source_paths": ["input.bin"],
                "timeout_seconds": 120,
            },
        )
    assert result["stdout"] == "ok\n"
    assert result["analysis_directory"] == "rapido-analysis"
    assert run.call_args.args[2][0]["sha256"]
    with pytest.raises(ToolError, match="source_paths"):
        registry.dispatch(
            "run_target_script",
            {
                "path": "rapido-analysis/solve.py",
                "source_paths": ["rapido-analysis/solve.py"],
            },
        )


def test_client_protocol_exposes_only_sanitized_endpoint_metadata(tmp_path: Path) -> None:
    registry, broker, child = _broker(
        tmp_path,
        (TargetEndpoint("tcp", "private.example", 31337),),
        lambda _address, timeout: WireSocket([b"banner"]),
    )
    thread = threading.Thread(target=broker.serve)
    thread.start()
    client = TargetClient(child.fileno(), "a" * 32)
    try:
        endpoints = client.endpoints()
        assert endpoints[0]["protocol"] == "tcp"
        assert "private.example" not in str(endpoints)
        with pytest.raises(TargetError, match="invalid"):
            client._call("tcp_open", host="elsewhere.example")
    finally:
        child.close()
        broker.close()
        thread.join(timeout=1)
        registry.close()


def test_saved_script_imports_current_client_and_uses_inherited_ipc(tmp_path: Path) -> None:
    from rapido.target_script_worker_main import _run

    registry, broker, child = _broker(
        tmp_path,
        (TargetEndpoint("tcp", "private.example", 31337),),
        lambda _address, timeout: WireSocket([b"banner"]),
    )
    thread = threading.Thread(target=broker.serve)
    thread.start()
    try:
        result = _run(
            b"from rapido.target_script_client import TargetClient\n"
            b"print(TargetClient.current().endpoints()[0]['protocol'])\n",
            "rapido-analysis/solve.py",
            child.fileno(),
            "a" * 32,
        )
        assert result["returncode"] == 0
        assert result["stdout"] == "tcp\n"
    finally:
        child.close()
        broker.close()
        thread.join(timeout=1)
        registry.close()


def test_http_session_replays_cookie_but_cannot_change_authority(tmp_path: Path) -> None:
    created = [
        WireSocket(
            [b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=test; Path=/\r\nContent-Length: 2\r\n\r\nok"]
        ),
        WireSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"]),
    ]
    sockets = list(created)
    registry, broker, child = _broker(
        tmp_path,
        (TargetEndpoint("http", "assigned.example", 8080),),
        lambda _address, timeout: sockets.pop(0),
    )
    session = broker.dispatch("http_session_open", {"endpoint_index": 0})["session"]
    broker.dispatch("http_request", {"session": session, "path": "/one"})
    second = broker.dispatch("http_request", {"session": session, "path": "/two"})
    assert second["text"] == "done"
    used = broker.summary()
    assert used["connects"] == 2
    assert b"Cookie: sid=test\r\n" in created[1].sent[0]
    with pytest.raises(ToolError, match="assigned authority"):
        broker.dispatch("http_request", {"path": "http://elsewhere.example/"})
    broker.close()
    child.close()
    registry.close()


def test_exchange_many_uses_distinct_live_handles_concurrently(tmp_path: Path) -> None:
    barrier = threading.Barrier(2)
    created: list[WireSocket] = []

    def connect(_address, timeout):
        wire = WireSocket([b"ready"], send_barrier=barrier)
        created.append(wire)
        return wire

    registry, broker, child = _broker(
        tmp_path, (TargetEndpoint("tcp", "192.0.2.8", 31337),), connect
    )
    first = broker.dispatch("tcp_open", {})["handle"]
    second = broker.dispatch("tcp_open", {})["handle"]
    created[0].responses.append(b"first")
    created[1].responses.append(b"second")
    result = broker.dispatch(
        "exchange_many",
        {
            "requests": [
                {"handle": first, "data": "PING1", "encoding": "utf8"},
                {"handle": second, "data": "PING2", "encoding": "utf8"},
            ],
            "timeout_seconds": 2,
        },
    )
    assert [item["text"] for item in result["results"]] == ["first", "second"]
    assert broker.summary()["operations"] == 4
    broker.close()
    child.close()
    registry.close()
    assert all(wire.closed for wire in created)


def test_caps_and_generation_revocation_fail_closed(tmp_path: Path) -> None:
    registry, broker, child = _broker(
        tmp_path,
        (TargetEndpoint("tcp", "192.0.2.9", 31337),),
        lambda _address, timeout: WireSocket([b"ready"]),
    )
    assert MAX_TARGET_SCRIPT_TIMEOUT_SECONDS == 120
    assert MAX_TARGET_SCRIPT_LIVE_CONNECTIONS == 4
    assert MAX_TARGET_SCRIPT_CONNECTIONS == 64
    assert MAX_TARGET_SCRIPT_OPERATIONS == 2048
    broker._operations = MAX_TARGET_SCRIPT_OPERATIONS
    with pytest.raises(ToolError, match="operation limit"):
        broker.dispatch("target_info", {})
    broker._operations = 0
    registry._target_revoked.set()
    with pytest.raises(ToolError, match="no longer active"):
        broker.dispatch("target_info", {})
    broker.close()
    child.close()
    registry.close()


def test_fixed_worker_installs_existing_network_denied_analysis_sandbox() -> None:
    import rapido.target_script_worker_main as worker

    source = inspect.getsource(worker.main)
    assert "apply_analysis_sandbox" in source
    assert "TargetClient" not in source  # installed only inside the bounded runner
