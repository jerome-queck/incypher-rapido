from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar
from unittest import mock

import pytest

from rapido.target import (
    TargetEndpoint,
    TargetToolRegistry,
    _connect_target,
    _DeadlineReader,
    _parse_http_response,
    _wire_result,
    parse_connection_info,
    solve_team_pow,
)
from rapido.tools import ToolError


def test_parses_only_explicit_board_endpoint_shapes() -> None:
    endpoints = parse_connection_info(
        '<a href="http://target.example:8135/">open</a> or nc 192.0.2.4 30081'
    )
    assert endpoints == (
        TargetEndpoint("http", "target.example", 8135),
        TargetEndpoint("tcp", "192.0.2.4", 30081),
    )
    with pytest.raises(ValueError, match="no supported endpoint"):
        parse_connection_info("host target.example port 80")
    with pytest.raises(ValueError, match="authority"):
        parse_connection_info("https://user:password@target.example/")


def test_pow_matches_observed_team_key_bound_decimal_ascii_contract() -> None:
    key = b"private-team-key"
    nonce = b"0011223344556677"
    solution, attempts = solve_team_pow(key, nonce, 8, timeout=2)
    prefix = hmac.new(key, nonce, hashlib.sha256).digest()
    assert hashlib.sha256(prefix + str(solution).encode()).digest()[0] == 0
    assert attempts == solution + 1


class FakeHTTPWireSocket:
    instances: ClassVar[list[FakeHTTPWireSocket]] = []

    def __init__(self) -> None:
        self.queue = [
            (
                b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n"
                b"Set-Cookie: session=test\r\nContent-Length: 27\r\n\r\n"
                b"flag{bounded-target-result}"
            )
        ]
        self.sent = bytearray()
        self.closed = False
        self.instances.append(self)

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def send(self, data) -> int:
        self.sent.extend(data)
        return len(data)

    def recv(self, limit: int) -> bytes:
        if not self.queue:
            return b""
        return self.queue.pop(0)[:limit]

    def close(self) -> None:
        self.closed = True


def test_http_tool_cannot_override_assigned_authority(tmp_path: Path) -> None:
    fake = FakeHTTPWireSocket()
    registry = TargetToolRegistry(
        tmp_path,
        (TargetEndpoint("http", "assigned.example", 8080, "/base"),),
        connector=lambda address, timeout: fake,
    )
    result = registry.dispatch("http_request", {"path": "/status?full=1"})
    assert b"GET /base/status?full=1 HTTP/1.1\r\n" in fake.sent
    assert b"Host: assigned.example:8080\r\n" in fake.sent
    assert result["status"] == 404
    assert "flag{bounded-target-result}" in result["text"]
    assert fake.closed
    with pytest.raises(ToolError, match="assigned authority"):
        registry.dispatch("http_request", {"path": "http://elsewhere.example/"})
    with pytest.raises(ToolError, match="transport authority"):
        registry.dispatch("http_request", {"headers": {"Host": "elsewhere.example"}})


def test_http_method_type_failure_is_structurally_attributed(tmp_path: Path) -> None:
    registry = TargetToolRegistry(
        tmp_path,
        (TargetEndpoint("http", "assigned.example", 8080),),
    )

    with pytest.raises(ToolError) as caught:
        registry.dispatch("http_request", {"method": []})

    assert caught.value.code == "invalid_argument"
    assert caught.value.details == {
        "schema_version": 1,
        "contract_version": 1,
        "failure_stage": "arguments",
        "constraint": "enum",
        "field_path": "method",
        "actual_kind": "array",
    }


def test_http_encoding_type_failure_is_structurally_attributed(tmp_path: Path) -> None:
    registry = TargetToolRegistry(
        tmp_path,
        (TargetEndpoint("http", "assigned.example", 8080),),
    )

    with pytest.raises(ToolError) as caught:
        registry.dispatch("http_request", {"encoding": [], "data": ""})

    assert caught.value.code == "invalid_argument"
    assert caught.value.details["field_path"] == "encoding"
    assert caught.value.details["constraint"] == "enum"
    assert caught.value.details["actual_kind"] == "array"


def test_http_reader_uses_one_decreasing_absolute_deadline() -> None:
    sock = FakeHTTPWireSocket()
    sock.queue = [b"HTTP/1.1 200"]
    reader = _DeadlineReader(sock, 1.0)
    with (
        mock.patch("rapido.target.time.monotonic", side_effect=[0.25, 1.01]),
        pytest.raises(TimeoutError),
    ):
        reader.until(b"\r\n\r\n", 1024)
    assert sock.timeout == pytest.approx(0.75)


def test_chunked_http_response_is_bounded_and_consumes_trailers() -> None:
    sock = FakeHTTPWireSocket()
    sock.queue = [
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\nDigest: ignored\r\n\r\n"
        )
    ]
    status, reason, headers, body, truncated = _parse_http_response(
        sock, time.monotonic() + 1, "GET"
    )
    assert (status, reason, body, truncated) == (200, "OK", b"hello", False)
    assert headers == [["Transfer-Encoding", "chunked"]]


def test_chunked_response_at_exact_limit_plus_one_is_truncated() -> None:
    sock = FakeHTTPWireSocket()
    sock.queue = [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nabcdef\r\n0\r\n\r\n"]
    _, _, _, body, truncated = _parse_http_response(
        sock, time.monotonic() + 1, "GET", response_limit=5
    )
    assert body == b"abcde"
    assert truncated


def test_informational_http_response_is_consumed_before_final_response() -> None:
    sock = FakeHTTPWireSocket()
    sock.queue = [b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]
    status, reason, headers, body, truncated = _parse_http_response(
        sock, time.monotonic() + 1, "POST"
    )
    assert (status, reason, headers, body, truncated) == (
        200,
        "OK",
        [["Content-Length", "2"]],
        b"ok",
        False,
    )


@pytest.mark.parametrize("payload", (b"a" * (64 * 1024), b"\xff" * (64 * 1024)))
def test_wire_result_fits_app_server_result_budget(payload: bytes) -> None:
    result = {
        "headers": [["X-Hostile", "\x01" * (8 * 1024)]],
        **_wire_result(payload, eof=True),
    }
    assert len(json.dumps(result).encode()) < 128 * 1024
    assert ("text" in result) != ("data_base64" in result)


class FakeConnectSocket:
    def __init__(self, failure: bool) -> None:
        self.failure = failure
        self.timeout = 0.0
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def connect(self, address) -> None:
        if self.failure:
            raise OSError("first address failed")

    def close(self) -> None:
        self.closed = True


def test_dns_and_multi_address_connect_share_one_absolute_deadline() -> None:
    first = FakeConnectSocket(True)
    second = FakeConnectSocket(False)
    resolution = SimpleNamespace(
        stdout=b"192.0.2.1 STREAM target\n192.0.2.2 STREAM target\n",
        returncode=0,
    )
    with (
        mock.patch("rapido.target.os.path.isfile", return_value=True),
        mock.patch("rapido.target.subprocess.run", return_value=resolution) as resolver,
        mock.patch("rapido.target.socket.socket", side_effect=[first, second]),
        mock.patch("rapido.target.time.monotonic", side_effect=[0.0, 0.1, 0.2, 0.4]),
    ):
        assert _connect_target(("assigned.example", 80), 1.0) is second
    assert resolver.call_args.kwargs["timeout"] == pytest.approx(0.9)
    assert first.timeout == pytest.approx(0.8)
    assert second.timeout == pytest.approx(0.6)
    assert first.closed


class FakeSocket:
    def __init__(self, banner: bytes) -> None:
        self.queue = [banner]
        self.sent: list[bytes] = []
        self.closed = False
        self.timeout = 0.0

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, limit: int) -> bytes:
        if not self.queue:
            raise TimeoutError
        return self.queue.pop(0)[:limit]

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)
        if len(self.sent) == 1:
            self.queue.append(b"SERVICE READY\n")

    def shutdown(self, how: int) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def test_tcp_tool_auto_solves_gate_and_keeps_one_bounded_session(tmp_path: Path) -> None:
    fake = FakeSocket(
        b"IN-CYPHER instance\nproof-of-work required (team-key bound)\n"
        b"nonce=0011223344556677 bits=8\n"
        b"send X such that sha256(hmac_sha256(team_key, nonce) || X) has 8 leading zero bits:\n"
    )
    registry = TargetToolRegistry(
        tmp_path,
        (TargetEndpoint("tcp", "192.0.2.7", 30081),),
        team_key="private-team-key",
        connector=lambda address, timeout: fake,
    )
    opened = registry.dispatch("tcp_open", {})
    assert opened["pow"]["required"] is True
    assert opened["text"] == "SERVICE READY\n"
    assert fake.sent[0].strip().isdigit()
    assert b"private-team-key" not in fake.sent[0]

    fake.queue.append(b"REPLY\n")
    exchange = registry.dispatch("tcp_exchange", {"data": "PING", "append_newline": True})
    assert fake.sent[-1] == b"PING\n"
    assert exchange["text"] == "REPLY\n"
    assert registry.dispatch("tcp_close", {}) == {"closed": True}
    assert fake.closed


def test_registry_exposes_sanitized_endpoint_metadata_only(tmp_path: Path) -> None:
    registry = TargetToolRegistry(
        tmp_path,
        (TargetEndpoint("https", "private-target.example", 443),),
    )
    report = registry.dispatch("target_info", {})
    assert report["endpoints"][0]["protocol"] == "https"
    assert "private-target.example" not in str(report)
    assert "authority_sha256" in report["endpoints"][0]
    names = {item["name"] for item in registry.dynamic_tools()}
    assert {"inspect_artifact", "target_info", "http_request", "tcp_open"} <= names
    assert "inspect_file" not in names
