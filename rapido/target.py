"""Board-issued target endpoints and bounded protocol tools.

Only ``parse_connection_info`` can create endpoint authorities.  Dynamic tool
arguments never contain a host or port, so a model cannot turn these helpers into
a scanner or a general network client.
"""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .tools import (
    MAX_INPUT_BYTES,
    ToolError,
    ToolRegistry,
    Workspace,
    _bounded_int,
    _bounded_text,
    _error,
    _value_kind,
    inspect_file,
)

MAX_CONNECTION_INFO_BYTES = 32 * 1024
MAX_TARGET_RESPONSE_BYTES = 8 * 1024
MAX_TARGET_HEADER_BYTES = 8 * 1024
MAX_TARGET_REQUEST_BYTES = 64 * 1024
MAX_TARGET_CALLS = 512
MAX_POW_BITS = 24
MAX_TARGET_SCRIPT_BYTES = 64 * 1024
MAX_TARGET_SCRIPT_OPERATIONS = 2048
MAX_TARGET_SCRIPT_CONNECTIONS = 64
MAX_TARGET_SCRIPT_LIVE_CONNECTIONS = 4
MAX_TARGET_SCRIPT_TRANSFER_BYTES = 16 * 1024 * 1024
MAX_TARGET_SCRIPT_TIMEOUT_SECONDS = 120
MAX_TARGET_SCRIPT_FRAME_BYTES = 256 * 1024
MAX_TARGET_SCRIPT_OBSERVATION_BYTES = 64 * 1024
TARGET_TOOL_NAMES = frozenset(
    {
        "target_info",
        "http_request",
        "tcp_open",
        "tcp_exchange",
        "tcp_close",
        "run_target_script",
    }
)

_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_TCP = re.compile(
    r"(?:^|\s)(?:nc\s+|tcp://)(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)[\s:]+(\d{1,5})(?=\s|$|[/<])",
    re.IGNORECASE,
)
_DNS = re.compile(r"(?=.{1,253}\.?$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.?")
_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}")
_POW = re.compile(
    rb"nonce=([0-9a-fA-F]{8,256})\s+bits=(\d{1,2}).*?send X .*?:\s*\n",
    re.DOTALL,
)


@dataclass(frozen=True)
class TargetEndpoint:
    """One immutable authority obtained from Board connection information."""

    scheme: str
    host: str
    port: int
    base_path: str = "/"

    def __post_init__(self) -> None:
        if self.scheme not in {"http", "https", "tcp"}:
            raise ValueError("unsupported target protocol")
        if not 0 < self.port <= 65_535:
            raise ValueError("target port is outside the valid range")
        _validate_host(self.host)
        if not self.base_path.startswith("/") or self.base_path.startswith("//"):
            raise ValueError("target base path is invalid")

    def public_record(self, index: int) -> dict[str, Any]:
        try:
            ipaddress.ip_address(self.host)
            host_kind = "ip"
        except ValueError:
            host_kind = "dns"
        return {
            "index": index,
            "protocol": self.scheme,
            "port": self.port,
            "host_kind": host_kind,
            "base_path_present": self.base_path != "/",
            "authority_sha256": hashlib.sha256(
                f"{self.scheme}://{self.host}:{self.port}".encode()
            ).hexdigest(),
        }


def _validate_host(host: str) -> None:
    if not isinstance(host, str) or not host or len(host) > 253 or any(c.isspace() for c in host):
        raise ValueError("target host is invalid")
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    if not host.isascii() or not _DNS.fullmatch(host):
        raise ValueError("target host is invalid")
    if any(not label or len(label) > 63 for label in host.rstrip(".").split(".")):
        raise ValueError("target host is invalid")


def parse_connection_info(value: str) -> tuple[TargetEndpoint, ...]:
    """Parse only explicit HTTP(S), ``tcp://``, and ``nc HOST PORT`` authorities."""
    if not isinstance(value, str) or not value:
        raise ValueError("connection information is missing")
    if len(value.encode("utf-8", "replace")) > MAX_CONNECTION_INFO_BYTES:
        raise ValueError("connection information exceeds the limit")
    decoded = html.unescape(value)
    endpoints: list[TargetEndpoint] = []
    for match in _URL.finditer(decoded):
        raw = match.group(0).rstrip(".,;)")
        parsed = urllib.parse.urlsplit(raw)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("target URL port is invalid") from exc
        if parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
            raise ValueError("target URL authority is invalid")
        base_path = parsed.path or "/"
        if parsed.query:
            base_path += "?" + parsed.query
        endpoints.append(
            TargetEndpoint(
                parsed.scheme.lower(),
                parsed.hostname,
                port or (443 if parsed.scheme.lower() == "https" else 80),
                base_path,
            )
        )
    for match in _TCP.finditer(decoded):
        host = match.group(1)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        endpoints.append(TargetEndpoint("tcp", host, int(match.group(2))))
    unique: list[TargetEndpoint] = []
    for endpoint in endpoints:
        if endpoint not in unique:
            unique.append(endpoint)
    if not unique:
        raise ValueError("connection information carried no supported endpoint")
    if len(unique) > 8:
        raise ValueError("connection information carried too many endpoints")
    return tuple(unique)


def _leading_zero_bits(digest: bytes, bits: int) -> bool:
    whole, remainder = divmod(bits, 8)
    return digest[:whole] == b"\0" * whole and (
        remainder == 0 or digest[whole] >> (8 - remainder) == 0
    )


def solve_team_pow(
    team_key: bytes, nonce: bytes, bits: int, *, timeout: float = 25.0
) -> tuple[int, int]:
    """Solve the observed decimal-ASCII, team-key-bound proof of work."""
    if not team_key or len(team_key) > 1024:
        raise _error("team_key_unavailable", "TCP target requires a bounded team key")
    if not re.fullmatch(rb"[0-9a-fA-F]{8,256}", nonce):
        raise _error("pow_protocol", "target supplied an invalid proof-of-work nonce")
    if not 1 <= bits <= MAX_POW_BITS:
        raise _error("pow_limit", "target proof-of-work difficulty exceeds the supported bound")
    prefix = hmac.new(team_key, nonce, hashlib.sha256).digest()
    deadline = time.monotonic() + timeout
    for counter in range(1 << (bits + 3)):
        encoded = str(counter).encode()
        if _leading_zero_bits(hashlib.sha256(prefix + encoded).digest(), bits):
            return counter, counter + 1
        if counter % 65_536 == 0 and time.monotonic() >= deadline:
            raise _error("pow_timeout", "target proof-of-work exceeded its time bound")
    raise _error("pow_exhausted", "target proof-of-work search bound was exhausted")


def _encoded_payload(arguments: Mapping[str, Any]) -> bytes:
    encoding = arguments.get("encoding", "utf8")
    if encoding not in {"utf8", "hex", "base64"}:
        raise _error("invalid_argument", "encoding must be utf8, hex, or base64")
    value = _bounded_text(arguments.get("data", ""), "data", MAX_TARGET_REQUEST_BYTES * 2)
    try:
        if encoding == "utf8":
            payload = value.encode()
        elif encoding == "hex":
            payload = bytes.fromhex(value)
        else:
            payload = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise _error("invalid_encoding", "target payload encoding is invalid") from exc
    if len(payload) > MAX_TARGET_REQUEST_BYTES:
        raise _error("input_too_large", "target payload exceeds the request limit")
    return payload


def _wire_result(data: bytes, *, eof: bool, truncated: bool = False) -> dict[str, Any]:
    if len(data) > MAX_TARGET_RESPONSE_BYTES:
        data = data[:MAX_TARGET_RESPONSE_BYTES]
        truncated = True
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    binary_controls = sum(byte < 32 and byte not in b"\t\n\r" for byte in data)
    result: dict[str, Any] = {
        "bytes": len(data),
        "eof": eof,
        "truncated": truncated,
    }
    if text is not None and binary_controls <= max(2, len(data) // 100):
        result.update({"encoding": "utf8", "text": text})
    else:
        result.update({"encoding": "base64", "data_base64": base64.b64encode(data).decode()})
    return result


def _recv_available(sock: socket.socket, *, timeout: float, limit: int) -> tuple[bytes, bool, bool]:
    deadline = time.monotonic() + timeout
    chunks: list[bytes] = []
    total = 0
    eof = False
    while total <= limit and time.monotonic() < deadline:
        sock.settimeout(max(0.05, min(0.5, deadline - time.monotonic())))
        try:
            chunk = sock.recv(min(16_384, limit + 1 - total))
        except TimeoutError:
            if chunks:
                break
            continue
        if not chunk:
            eof = True
            break
        chunks.append(chunk)
        total += len(chunk)
    data = b"".join(chunks)
    return data[:limit], eof, len(data) > limit


class _DeadlineReader:
    """Socket reader whose timeout shrinks against one absolute deadline."""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self.sock = sock
        self.deadline = deadline
        self.buffer = bytearray()
        self.eof = False

    def _fill(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.sock.settimeout(remaining)
        chunk = self.sock.recv(16_384)
        if not chunk:
            self.eof = True
        else:
            self.buffer.extend(chunk)

    def until(self, marker: bytes, limit: int) -> bytes:
        while marker not in self.buffer:
            if len(self.buffer) > limit or self.eof:
                raise ValueError("bounded HTTP delimiter was absent")
            self._fill()
        end = self.buffer.index(marker) + len(marker)
        if end > limit:
            raise ValueError("bounded HTTP section exceeded its limit")
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def exact(self, count: int) -> bytes:
        while len(self.buffer) < count and not self.eof:
            self._fill()
        if len(self.buffer) < count:
            raise ValueError("HTTP body ended unexpectedly")
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def to_eof(self, limit: int) -> tuple[bytes, bool]:
        while not self.eof and len(self.buffer) <= limit:
            self._fill()
        data = bytes(self.buffer)
        self.buffer.clear()
        return data[:limit], len(data) > limit


def _send_before(sock: socket.socket, payload: bytes, deadline: float) -> None:
    view = memoryview(payload)
    while view:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        sock.settimeout(remaining)
        sent = sock.send(view)
        if sent <= 0:
            raise OSError("target socket closed during request")
        view = view[sent:]


def _read_chunked(reader: _DeadlineReader, limit: int) -> tuple[bytes, bool]:
    body = bytearray()
    while True:
        line = reader.until(b"\r\n", 1024)
        try:
            size = int(line[:-2].split(b";", 1)[0], 16)
        except ValueError as exc:
            raise ValueError("HTTP chunk size is invalid") from exc
        if size < 0:
            raise ValueError("HTTP chunk size is invalid")
        if size == 0:
            trailer_bytes = 0
            while True:
                trailer = reader.until(b"\r\n", 64 * 1024)
                trailer_bytes += len(trailer)
                if trailer_bytes > 64 * 1024:
                    raise ValueError("HTTP trailers exceeded their limit")
                if trailer == b"\r\n":
                    break
            return bytes(body[:limit]), len(body) > limit
        remaining = limit + 1 - len(body)
        if size > remaining:
            body.extend(reader.exact(remaining))
            return bytes(body[:limit]), True
        body.extend(reader.exact(size))
        if reader.exact(2) != b"\r\n":
            raise ValueError("HTTP chunk terminator is invalid")


def _parse_http_response(
    sock: socket.socket,
    deadline: float,
    method: str,
    *,
    response_limit: int = MAX_TARGET_RESPONSE_BYTES,
    header_limit: int = MAX_TARGET_HEADER_BYTES,
    returned_header_limit: int = 40,
    header_value_limit: int = 2048,
) -> tuple[int, str, list[list[str]], bytes, bool]:
    reader = _DeadlineReader(sock, deadline)
    for _ in range(6):
        header_block = reader.until(b"\r\n\r\n", header_limit)
        lines = header_block[:-4].split(b"\r\n")
        if not lines:
            raise ValueError("HTTP response had no status line")
        status_parts = lines[0].decode("latin-1").split(" ", 2)
        if len(status_parts) < 2 or not status_parts[0].startswith("HTTP/"):
            raise ValueError("HTTP status line is invalid")
        status = int(status_parts[1])
        if not 100 <= status <= 599:
            raise ValueError("HTTP status code is invalid")
        reason = status_parts[2] if len(status_parts) == 3 else ""
        headers = []
        by_name: dict[str, list[str]] = {}
        for raw in lines[1:]:
            if raw[:1] in b" \t" or b":" not in raw:
                raise ValueError("HTTP response header is invalid")
            name_raw, value_raw = raw.split(b":", 1)
            name = name_raw.decode("ascii")
            if not _HEADER.fullmatch(name):
                raise ValueError("HTTP response header name is invalid")
            value = value_raw.strip().decode("latin-1")
            headers.append([name[:100], value[:header_value_limit]])
            by_name.setdefault(name.lower(), []).append(value)
            if len(headers) > 100:
                raise ValueError("HTTP response carried too many headers")
        if status == 101:
            raise ValueError("HTTP protocol upgrades are unsupported")
        if status >= 200:
            break
    else:
        raise ValueError("HTTP response carried too many informational messages")
    no_body = method == "HEAD" or status in {204, 304} or 100 <= status < 200
    if no_body:
        return status, reason, headers[:returned_header_limit], b"", False
    transfer = ",".join(by_name.get("transfer-encoding", [])).lower()
    if transfer:
        if transfer.split(",")[-1].strip() != "chunked":
            raise ValueError("HTTP transfer encoding is unsupported")
        body, truncated = _read_chunked(reader, response_limit)
    elif "content-length" in by_name:
        values = by_name["content-length"]
        if len(set(values)) != 1:
            raise ValueError("HTTP content length is ambiguous")
        length = int(values[0])
        if length < 0:
            raise ValueError("HTTP content length is invalid")
        wanted = min(length, response_limit + 1)
        body = reader.exact(wanted)
        truncated = length > response_limit
        body = body[:response_limit]
    else:
        body, truncated = reader.to_eof(response_limit)
    return status, reason, headers[:returned_header_limit], body, truncated


def _connect_target(address: tuple[str, int], timeout: float) -> socket.socket:
    """Resolve in a killable helper and connect all addresses against one deadline."""
    host, port = address
    deadline = time.monotonic() + timeout
    try:
        parsed = ipaddress.ip_address(host)
        resolved = [parsed]
    except ValueError:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        if os.path.isfile("/usr/bin/getent"):
            command = ["/usr/bin/getent", "ahosts", host]
            resolver_kind = "getent"
        elif os.path.isfile("/usr/bin/dscacheutil"):
            command = ["/usr/bin/dscacheutil", "-q", "host", "-a", "name", host]
            resolver_kind = "dscacheutil"
        else:
            raise OSError("no killable target DNS resolver is installed")
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=remaining,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OSError("bounded target DNS resolution failed") from exc
        resolved = []
        for line in result.stdout.splitlines()[:64]:
            token = line.split(maxsplit=1)[0] if resolver_kind == "getent" else b""
            if resolver_kind == "dscacheutil" and b":" in line:
                name, _, value = line.partition(b":")
                if name.strip() in {b"ip_address", b"ipv6_address"}:
                    token = value.strip()
            try:
                candidate = ipaddress.ip_address(token.decode("ascii"))
            except (UnicodeError, ValueError):
                continue
            if candidate not in resolved:
                resolved.append(candidate)
        if result.returncode != 0 or not resolved:
            raise OSError("bounded target DNS resolution returned no address")
    last_error: OSError | None = None
    for candidate in resolved[:16]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError from last_error
        family = socket.AF_INET6 if candidate.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(remaining)
            sockaddr = (
                (str(candidate), port, 0, 0)
                if family == socket.AF_INET6
                else (str(candidate), port)
            )
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise OSError("assigned target connection failed") from last_error


def _script_wire_result(data: bytes, *, eof: bool, truncated: bool = False) -> dict[str, Any]:
    if len(data) > MAX_TARGET_REQUEST_BYTES:
        data = data[:MAX_TARGET_REQUEST_BYTES]
        truncated = True
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    binary_controls = sum(byte < 32 and byte not in b"\t\n\r" for byte in data)
    result: dict[str, Any] = {"bytes": len(data), "eof": eof, "truncated": truncated}
    if text is not None and binary_controls <= max(2, len(data) // 100):
        result.update({"encoding": "utf8", "text": text})
    else:
        result.update({"encoding": "base64", "data_base64": base64.b64encode(data).decode()})
    return result


def _socket_read_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class _TargetScriptBroker:
    """Supervisor-side authority broker for one bounded target script."""

    _OPERATIONS = frozenset(
        {
            "target_info",
            "http_session_open",
            "http_session_close",
            "http_request",
            "tcp_open",
            "tcp_exchange",
            "exchange_many",
            "tcp_close",
        }
    )

    def __init__(
        self,
        registry: TargetToolRegistry,
        channel: socket.socket,
        generation: str,
        timeout_seconds: int,
    ) -> None:
        self.registry = registry
        self.channel = channel
        self.generation = generation
        self.deadline = time.monotonic() + timeout_seconds
        self._lock = threading.RLock()
        self._closed = threading.Event()
        self._tcp: dict[str, tuple[int, socket.socket]] = {}
        self._http_sessions: dict[str, dict[str, Any]] = {}
        self._transient_sockets: set[socket.socket] = set()
        self._operations = 0
        self._connects = 0
        self._sent_bytes = 0
        self._received_bytes = 0
        self._reserved_receive_bytes = 0
        self._observations: deque[tuple[int, dict[str, Any]]] = deque()
        self._observation_bytes = 0

    def _active(self) -> None:
        if self._closed.is_set() or self.registry._target_revoked.is_set():
            raise _error("generation_revoked", "target generation is no longer active")
        if time.monotonic() >= self.deadline:
            raise _error("deadline_exceeded", "target script deadline expired")

    def _operation(self, count: int = 1) -> None:
        self._active()
        with self._lock:
            if self._operations + count > MAX_TARGET_SCRIPT_OPERATIONS:
                raise _error("tool_call_limit", "target script operation limit reached")
            self._operations += count

    def _timeout(self, value: Any, default: int = 15) -> float:
        requested = _bounded_int(
            value, "timeout_seconds", 1, MAX_TARGET_SCRIPT_TIMEOUT_SECONDS, default
        )
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise _error("deadline_exceeded", "target script deadline expired")
        return min(float(requested), remaining)

    def _endpoint(self, value: Any, protocols: set[str]) -> tuple[int, TargetEndpoint]:
        index = _bounded_int(value, "endpoint_index", 0, 7, 0)
        if index >= len(self.registry.endpoints):
            raise _error("invalid_argument", "endpoint index is not assigned")
        endpoint = self.registry.endpoints[index]
        if endpoint.scheme not in protocols:
            raise _error("protocol_mismatch", "assigned endpoint does not support this operation")
        return index, endpoint

    def _connect(self, endpoint: TargetEndpoint, timeout: float) -> socket.socket:
        self._active()
        with self._lock:
            if self._connects >= MAX_TARGET_SCRIPT_CONNECTIONS:
                raise _error("connection_limit", "target script connection limit reached")
            self._connects += 1
        try:
            sock = self.registry._connector((endpoint.host, endpoint.port), timeout=timeout)
        except (OSError, TimeoutError) as exc:
            raise _error("target_transport", "assigned target connection failed") from exc
        with self._lock:
            self._transient_sockets.add(sock)
        return sock

    def _replace_transient(self, old: socket.socket, new: socket.socket) -> None:
        with self._lock:
            self._transient_sockets.discard(old)
            self._transient_sockets.add(new)

    def _untrack(self, sock: socket.socket) -> None:
        with self._lock:
            self._transient_sockets.discard(sock)

    def _account(self, *, sent: int = 0, received: int = 0) -> None:
        with self._lock:
            if (
                self._sent_bytes + sent > MAX_TARGET_SCRIPT_TRANSFER_BYTES
                or self._received_bytes + received > MAX_TARGET_SCRIPT_TRANSFER_BYTES
            ):
                raise _error("transfer_limit", "target script transfer limit reached")
            self._sent_bytes += sent
            self._received_bytes += received

    def _reserve_receive(self) -> int:
        with self._lock:
            remaining = (
                MAX_TARGET_SCRIPT_TRANSFER_BYTES
                - self._received_bytes
                - self._reserved_receive_bytes
            )
            if remaining <= 0:
                raise _error("transfer_limit", "target script receive limit reached")
            reserved = min(MAX_TARGET_REQUEST_BYTES, remaining)
            self._reserved_receive_bytes += reserved
            return reserved

    def _finish_receive(self, reserved: int, actual: int) -> None:
        with self._lock:
            self._reserved_receive_bytes -= reserved
            self._received_bytes += actual

    def _record(self, kind: str, endpoint_index: int, result: Mapping[str, Any]) -> None:
        public_result = {key: value for key, value in result.items() if key != "handle"}
        record = {"kind": kind, "endpoint_index": endpoint_index, **public_result}
        raw = json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode()
        if len(raw) > MAX_TARGET_SCRIPT_OBSERVATION_BYTES:
            if isinstance(result.get("text"), str):
                value = result["text"]
                public_result.pop("text", None)
                public_result["text"] = value[: 24 * 1024] + value[-24 * 1024 :]
            elif isinstance(result.get("data_base64"), str):
                try:
                    value = base64.b64decode(result["data_base64"], validate=True)
                except ValueError:
                    value = b""
                public_result.pop("data_base64", None)
                public_result.update(
                    _script_wire_result(
                        value[: 18 * 1024] + value[-18 * 1024 :],
                        eof=bool(result.get("eof")),
                        truncated=True,
                    )
                )
            public_result["observation_sliced"] = True
            record = {"kind": kind, "endpoint_index": endpoint_index, **public_result}
            raw = json.dumps(record, separators=(",", ":")).encode()
            if len(raw) > MAX_TARGET_SCRIPT_OBSERVATION_BYTES:
                record = {
                    "kind": kind,
                    "endpoint_index": endpoint_index,
                    "bytes": result.get("bytes", 0),
                    "observation_sliced": True,
                }
                raw = json.dumps(record, separators=(",", ":")).encode()
        with self._lock:
            self._observations.append((len(raw), record))
            self._observation_bytes += len(raw)
            while self._observation_bytes > MAX_TARGET_SCRIPT_OBSERVATION_BYTES:
                size, _ = self._observations.popleft()
                self._observation_bytes -= size

    @staticmethod
    def _strict(
        arguments: Mapping[str, Any],
        allowed: set[str],
        required: frozenset[str] = frozenset(),
    ) -> None:
        if not isinstance(arguments, Mapping):
            raise _error(
                "invalid_argument",
                "target broker arguments must be an object",
                field_path="arguments",
                constraint="type",
                actual_kind=_value_kind(arguments),
            )
        fields = set(arguments)
        if fields - allowed:
            raise _error(
                "invalid_argument",
                "target broker arguments are invalid: unsupported fields",
                field_path="arguments",
                constraint="additional_properties",
                actual_kind="object",
            )
        if not required <= fields:
            raise _error(
                "invalid_argument",
                "target broker arguments are invalid: required field omitted",
                field_path="arguments",
                constraint="required",
                actual_kind="object",
            )

    def _http_session_open(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self._strict(arguments, {"endpoint_index"})
        index, _ = self._endpoint(arguments.get("endpoint_index"), {"http", "https"})
        with self._lock:
            if len(self._http_sessions) >= 16:
                raise _error("session_limit", "HTTP session limit reached")
            handle = secrets.token_urlsafe(18)
            self._http_sessions[handle] = {"endpoint_index": index, "cookies": {}}
        return {"session": handle, "endpoint_index": index}

    def _http_session_close(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self._strict(arguments, {"session"}, {"session"})
        handle = arguments.get("session")
        if not isinstance(handle, str):
            raise _error("invalid_argument", "HTTP session handle is invalid")
        with self._lock:
            return {"closed": self._http_sessions.pop(handle, None) is not None}

    def _http_request(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self._strict(
            arguments,
            {
                "endpoint_index",
                "session",
                "method",
                "path",
                "headers",
                "data",
                "encoding",
                "timeout_seconds",
            },
        )
        session: dict[str, Any] | None = None
        session_handle = arguments.get("session")
        if session_handle is not None:
            if not isinstance(session_handle, str):
                raise _error("invalid_argument", "HTTP session handle is invalid")
            with self._lock:
                session = self._http_sessions.get(session_handle)
            if session is None:
                raise _error("invalid_argument", "HTTP session handle is not active")
            endpoint_value = session["endpoint_index"]
            if "endpoint_index" in arguments and arguments["endpoint_index"] != endpoint_value:
                raise _error("invalid_argument", "HTTP session endpoint cannot change")
        else:
            endpoint_value = arguments.get("endpoint_index")
        index, endpoint = self._endpoint(endpoint_value, {"http", "https"})
        method = arguments.get("method", "GET")
        if not isinstance(method, str) or method not in {
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            raise _error(
                "invalid_argument",
                "HTTP method is not permitted",
                field_path="method",
                constraint="enum",
                actual_kind=_value_kind(method),
            )
        path = self.registry._http_path(endpoint, arguments.get("path", "/"))
        headers_arg = arguments.get("headers", {})
        if not isinstance(headers_arg, Mapping) or len(headers_arg) > 20:
            raise _error("invalid_argument", "HTTP headers must be a bounded object")
        headers = {
            "User-Agent": "incypher-rapido/0.1",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        }
        forbidden = {"host", "connection", "content-length", "transfer-encoding", "upgrade"}
        for raw_name, raw_value in headers_arg.items():
            if not isinstance(raw_name, str) or not _HEADER.fullmatch(raw_name):
                raise _error("invalid_argument", "HTTP header name is invalid")
            if raw_name.lower() in forbidden or raw_name.lower().startswith("proxy-"):
                raise _error("invalid_argument", "HTTP header cannot override target authority")
            value = _bounded_text(raw_value, "header value", 4096)
            if (
                "\r" in value
                or "\n" in value
                or any(ord(char) < 32 and char != "\t" for char in value)
            ):
                raise _error("invalid_argument", "HTTP header value is invalid")
            headers[raw_name] = value
        if (
            session is not None
            and session["cookies"]
            and not any(name.lower() == "cookie" for name in headers)
        ):
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in session["cookies"].items()
            )
        body = _encoded_payload(arguments) if "data" in arguments else b""
        timeout = self._timeout(arguments.get("timeout_seconds"))
        try:
            path_bytes = path.encode("ascii")
            encoded_headers = [
                (name.encode("ascii"), value.encode("latin-1")) for name, value in headers.items()
            ]
        except UnicodeError as exc:
            raise _error("invalid_argument", "HTTP request encoding is invalid") from exc
        host_header = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
        default_port = 443 if endpoint.scheme == "https" else 80
        if endpoint.port != default_port:
            host_header += f":{endpoint.port}"
        request = bytearray(method.encode() + b" " + path_bytes + b" HTTP/1.1\r\n")
        request.extend(b"Host: " + host_header.encode("ascii") + b"\r\n")
        for name, value in encoded_headers:
            request.extend(name + b": " + value + b"\r\n")
        request.extend(b"Connection: close\r\n")
        if body:
            request.extend(f"Content-Length: {len(body)}\r\n".encode())
        request.extend(b"\r\n")
        request.extend(body)
        if len(request) > MAX_TARGET_REQUEST_BYTES:
            raise _error("input_too_large", "HTTP request exceeds 64 KiB")
        deadline = min(self.deadline, time.monotonic() + timeout)
        sock: socket.socket | None = None
        response_reservation = 0
        try:
            sock = self._connect(endpoint, timeout)
            if endpoint.scheme == "https":
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                sock.settimeout(remaining)
                wrapped = ssl.create_default_context().wrap_socket(
                    sock, server_hostname=endpoint.host
                )
                self._replace_transient(sock, wrapped)
                sock = wrapped
            self._account(sent=len(request))
            _send_before(sock, bytes(request), deadline)
            response_reservation = self._reserve_receive()
            status, reason, header_rows, data, truncated = _parse_http_response(
                sock,
                deadline,
                method,
                response_limit=response_reservation,
                header_limit=MAX_TARGET_REQUEST_BYTES,
            )
            self._finish_receive(response_reservation, len(data))
            response_reservation = 0
            if session is not None:
                for name, value in header_rows:
                    if name.lower() != "set-cookie":
                        continue
                    pair = value.split(";", 1)[0]
                    cookie_name, separator, cookie_value = pair.partition("=")
                    if separator and _HEADER.fullmatch(cookie_name) and len(cookie_value) <= 4096:
                        session["cookies"][cookie_name] = cookie_value
            result = {
                "endpoint_index": index,
                "status": status,
                "reason": reason[:200],
                "headers": header_rows,
                **_script_wire_result(data, eof=True, truncated=truncated),
            }
            self._record("http", index, result)
            return result
        except ToolError:
            raise
        except (OSError, TimeoutError, UnicodeError, ValueError, ssl.SSLError) as exc:
            raise _error("target_transport", "assigned HTTP target request failed") from exc
        finally:
            if response_reservation:
                self._finish_receive(response_reservation, 0)
            if sock is not None:
                self._untrack(sock)
                try:
                    sock.close()
                except OSError:
                    pass

    def _tcp_open(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self._strict(arguments, {"endpoint_index", "timeout_seconds"})
        index, endpoint = self._endpoint(arguments.get("endpoint_index"), {"tcp"})
        timeout = self._timeout(arguments.get("timeout_seconds"))
        with self._lock:
            if len(self._tcp) >= MAX_TARGET_SCRIPT_LIVE_CONNECTIONS:
                raise _error("connection_limit", "four target connections are already open")
        sock: socket.socket | None = None
        receive_reservation = 0
        try:
            sock = self._connect(endpoint, timeout)
            receive_reservation = self._reserve_receive()
            banner, eof, truncated = _recv_available(
                sock, timeout=timeout, limit=receive_reservation
            )
            self._finish_receive(receive_reservation, len(banner))
            receive_reservation = 0
            received = len(banner)
            pow_match = _POW.search(banner)
            pow_record: dict[str, Any] = {"required": False}
            service = banner
            if pow_match is not None:
                bits = int(pow_match.group(2))
                started = time.monotonic()
                solution, attempts = solve_team_pow(
                    self.registry._team_key, pow_match.group(1), bits, timeout=timeout
                )
                answer = str(solution).encode() + b"\n"
                self._account(sent=len(answer))
                sock.sendall(answer)
                response_capacity = MAX_TARGET_REQUEST_BYTES - received
                if response_capacity <= 0:
                    raise _error("transfer_limit", "TCP open response exceeds 64 KiB")
                receive_reservation = self._reserve_receive()
                service, eof, truncated = _recv_available(
                    sock,
                    timeout=timeout,
                    limit=min(receive_reservation, response_capacity),
                )
                self._finish_receive(receive_reservation, len(service))
                receive_reservation = 0
                received += len(service)
                pow_record = {
                    "required": True,
                    "bits": bits,
                    "attempts": attempts,
                    "seconds": round(time.monotonic() - started, 3),
                }
            handle = secrets.token_urlsafe(18)
            self._untrack(sock)
            with self._lock:
                self._tcp[handle] = (index, sock)
            result = {
                "handle": handle,
                "endpoint_index": index,
                "pow": pow_record,
                **_script_wire_result(service, eof=eof, truncated=truncated),
            }
            self._record("tcp_open", index, result)
            if eof:
                self._tcp_close({"handle": handle})
            return result
        except ToolError:
            if receive_reservation:
                self._finish_receive(receive_reservation, 0)
            if sock is not None:
                self._untrack(sock)
                try:
                    sock.close()
                except OSError:
                    pass
            raise
        except (OSError, TimeoutError) as exc:
            if receive_reservation:
                self._finish_receive(receive_reservation, 0)
            if sock is not None:
                self._untrack(sock)
                try:
                    sock.close()
                except OSError:
                    pass
            raise _error("target_transport", "assigned TCP target connection failed") from exc

    def _tcp_exchange(
        self, arguments: Mapping[str, Any], *, shared_timeout: float | None = None
    ) -> dict[str, Any]:
        self._strict(
            arguments,
            {"handle", "data", "encoding", "append_newline", "shutdown_write", "timeout_seconds"},
            {"handle"},
        )
        handle = arguments.get("handle")
        if not isinstance(handle, str):
            raise _error("invalid_argument", "TCP handle is invalid")
        with self._lock:
            session = self._tcp.get(handle)
        if session is None:
            raise _error("tcp_session", "TCP handle is not active")
        index, sock = session
        payload = _encoded_payload(arguments)
        if arguments.get("append_newline", False):
            payload += b"\n"
        if len(payload) > MAX_TARGET_REQUEST_BYTES:
            raise _error("input_too_large", "TCP payload exceeds 64 KiB")
        timeout = shared_timeout or self._timeout(arguments.get("timeout_seconds"))
        receive_reservation = 0
        try:
            if payload:
                self._account(sent=len(payload))
                sock.sendall(payload)
            if arguments.get("shutdown_write", False):
                sock.shutdown(socket.SHUT_WR)
            receive_reservation = self._reserve_receive()
            data, eof, truncated = _recv_available(sock, timeout=timeout, limit=receive_reservation)
            self._finish_receive(receive_reservation, len(data))
            receive_reservation = 0
            result = {
                "handle": handle,
                "endpoint_index": index,
                "sent_bytes": len(payload),
                **_script_wire_result(data, eof=eof, truncated=truncated),
            }
            self._record("tcp_exchange", index, result)
            if eof:
                self._tcp_close({"handle": handle})
            return result
        except ToolError:
            if receive_reservation:
                self._finish_receive(receive_reservation, 0)
            raise
        except (OSError, TimeoutError) as exc:
            if receive_reservation:
                self._finish_receive(receive_reservation, 0)
            self._tcp_close({"handle": handle})
            raise _error("target_transport", "assigned TCP target exchange failed") from exc

    def _exchange_many(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self._strict(arguments, {"requests", "timeout_seconds"}, {"requests"})
        requests = arguments.get("requests")
        if not isinstance(requests, list) or not 2 <= len(requests) <= 4:
            raise _error("invalid_argument", "exchange_many requires two to four requests")
        if any(not isinstance(request, Mapping) for request in requests):
            raise _error("invalid_argument", "exchange_many requests are invalid")
        handles = [request.get("handle") for request in requests]
        if any(not isinstance(handle, str) for handle in handles) or len(set(handles)) != len(
            handles
        ):
            raise _error("invalid_argument", "exchange_many requires distinct active handles")
        timeout = self._timeout(arguments.get("timeout_seconds"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(requests)) as executor:
            futures = [
                executor.submit(self._tcp_exchange, request, shared_timeout=timeout)
                for request in requests
            ]
            return {"results": [future.result() for future in futures]}

    def _tcp_close(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self._strict(arguments, {"handle"}, {"handle"})
        handle = arguments.get("handle")
        if not isinstance(handle, str):
            raise _error("invalid_argument", "TCP handle is invalid")
        with self._lock:
            session = self._tcp.pop(handle, None)
        if session is None:
            return {"closed": False}
        try:
            session[1].close()
        except OSError:
            pass
        return {"closed": True}

    def dispatch(self, operation: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if operation not in self._OPERATIONS:
            raise _error("invalid_argument", "target broker operation is invalid")
        cost = len(arguments.get("requests", [])) if operation == "exchange_many" else 1
        self._operation(max(1, cost))
        if operation == "target_info":
            self._strict(arguments, set())
            return {
                "endpoints": [
                    endpoint.public_record(index)
                    for index, endpoint in enumerate(self.registry.endpoints)
                ]
            }
        if operation == "http_session_open":
            return self._http_session_open(arguments)
        if operation == "http_session_close":
            return self._http_session_close(arguments)
        if operation == "http_request":
            return self._http_request(arguments)
        if operation == "tcp_open":
            return self._tcp_open(arguments)
        if operation == "tcp_exchange":
            return self._tcp_exchange(arguments)
        if operation == "exchange_many":
            return self._exchange_many(arguments)
        return self._tcp_close(arguments)

    def serve(self) -> None:
        try:
            while not self._closed.is_set():
                try:
                    length = int.from_bytes(_socket_read_exact(self.channel, 4), "big")
                    if not 1 <= length <= MAX_TARGET_SCRIPT_FRAME_BYTES:
                        raise ValueError
                    raw = _socket_read_exact(self.channel, length)
                    request = json.loads(raw)
                    if (
                        not isinstance(request, dict)
                        or set(request) != {"protocol", "generation", "operation", "arguments"}
                        or request.get("protocol") != 1
                        or request.get("generation") != self.generation
                        or not isinstance(request.get("operation"), str)
                        or not isinstance(request.get("arguments"), Mapping)
                    ):
                        raise ValueError
                    result = self.dispatch(request["operation"], request["arguments"])
                    response = {"protocol": 1, "ok": True, "result": result}
                except EOFError:
                    return
                except ToolError as exc:
                    response = {
                        "protocol": 1,
                        "ok": False,
                        "error": {"code": exc.code, "message": exc.message},
                    }
                except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
                    response = {
                        "protocol": 1,
                        "ok": False,
                        "error": {
                            "code": "broker_protocol",
                            "message": "target broker request is invalid",
                        },
                    }
                raw_response = json.dumps(
                    response, ensure_ascii=True, separators=(",", ":")
                ).encode()
                if len(raw_response) > MAX_TARGET_SCRIPT_FRAME_BYTES:
                    raw_response = json.dumps(
                        {
                            "protocol": 1,
                            "ok": False,
                            "error": {
                                "code": "output_too_large",
                                "message": "target broker response is too large",
                            },
                        },
                        separators=(",", ":"),
                    ).encode()
                self.channel.sendall(len(raw_response).to_bytes(4, "big") + raw_response)
        except (BrokenPipeError, ConnectionError, OSError):
            return

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "operations": self._operations,
                "connects": self._connects,
                "sent_bytes": self._sent_bytes,
                "received_bytes": self._received_bytes,
                "open_connections": len(self._tcp),
                "open_http_sessions": len(self._http_sessions),
                "target_observations": [record for _, record in self._observations],
            }

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        with self._lock:
            sockets = [sock for _, sock in self._tcp.values()]
            sockets.extend(self._transient_sockets)
            self._tcp.clear()
            self._transient_sockets.clear()
            self._http_sessions.clear()
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass
        try:
            self.channel.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.channel.close()
        except OSError:
            pass


def _target_script_sources(workspace: Workspace, raw_sources: Any) -> list[dict[str, Any]]:
    if (
        not isinstance(raw_sources, list)
        or not 1 <= len(raw_sources) <= 16
        or any(not isinstance(path, str) for path in raw_sources)
    ):
        raise _error("invalid_argument", "source_paths must contain 1 to 16 workspace files")
    sources: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_path in raw_sources:
        path = _bounded_text(raw_path, "source path")
        parts = workspace._parts(path)
        if not parts or parts[0] == "rapido-analysis":
            raise _error(
                "invalid_argument",
                "source_paths must identify controller-provided or derived challenge inputs",
            )
        normalized = "/".join(parts)
        if normalized in seen:
            continue
        seen.add(normalized)
        manifest = inspect_file(workspace, {"path": normalized, "algorithms": ["sha256"]})
        sources.append(
            {
                "path": normalized,
                "bytes": manifest["size"],
                "sha256": manifest["hashes"]["sha256"],
            }
        )
    if not sources:
        raise _error("invalid_argument", "source_paths must contain a unique challenge input")
    return sources


def _open_target_script(analysis_fd: int, workspace: Workspace, raw_path: Any) -> tuple[int, str]:
    path = _bounded_text(raw_path, "path", MAX_INPUT_BYTES)
    parts = workspace._parts(path)
    if len(parts) < 2 or parts[0] != "rapido-analysis" or not parts[-1].endswith(".py"):
        raise _error("invalid_argument", "path must name a .py file below rapido-analysis")
    if len(parts) > 128:
        raise _error("limit_exceeded", "target script path has too many components")
    descriptors: list[int] = []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        parent = analysis_fd
        for part in parts[1:-1]:
            descriptor = os.open(part, flags, dir_fd=parent)
            descriptors.append(descriptor)
            parent = descriptor
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= MAX_TARGET_SCRIPT_BYTES
        ):
            os.close(descriptor)
            raise _error(
                "invalid_argument", "target script must be a non-empty single-link file <=64 KiB"
            )
        return descriptor, "/".join(parts)
    except ToolError:
        raise
    except FileNotFoundError as exc:
        raise _error("not_found", "target script does not exist") from exc
    except OSError as exc:
        raise _error("symlink_or_invalid_path", "target script path is unavailable") from exc
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def _target_worker_response(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _error("tool_failed", "target-script worker returned invalid JSON") from exc
    if not isinstance(value, dict) or value.get("protocol") != 1:
        raise _error("tool_failed", "target-script worker protocol is invalid")
    if value.get("ok") is True and set(value) == {"protocol", "ok", "result"}:
        result = value["result"]
        if isinstance(result, dict):
            return result
    if value.get("ok") is False and set(value) == {"protocol", "ok", "error"}:
        error = value["error"]
        if (
            isinstance(error, dict)
            and error.get("code")
            in {
                "invalid_argument",
                "limit_exceeded",
                "output_too_large",
                "resource_limit",
                "tool_failed",
                "tool_unavailable",
            }
            and isinstance(error.get("message"), str)
        ):
            raise _error(error["code"], error["message"])
    raise _error("tool_failed", "target-script worker failed safely")


def _run_target_script_worker(
    registry: TargetToolRegistry,
    path: str,
    sources: list[dict[str, Any]],
    timeout_seconds: int,
) -> dict[str, Any]:
    from . import analysis_worker

    if sys.platform != "linux":
        raise _error("tool_unavailable", "target scripts require Linux confinement")
    analysis_worker._require_ptrace_isolation()
    analysis_worker._require_resource_headroom()
    if not analysis_worker._ANALYSIS_SLOTS.acquire(timeout=min(10, timeout_seconds)):
        raise _error("tool_busy", "all eight analysis workers are busy")
    analysis = analysis_worker._analysis_directory(registry.workspace.root)
    workspace_fd: int | None = None
    analysis_fd: int | None = None
    ephemeral_fd: int | None = None
    script_fd: int | None = None
    result_fd: int | None = None
    ephemeral: Path | None = None
    parent_channel: socket.socket | None = None
    child_channel: socket.socket | None = None
    process: subprocess.Popen[bytes] | None = None
    broker: _TargetScriptBroker | None = None
    broker_thread: threading.Thread | None = None
    watchdog: threading.Thread | None = None
    watchdog_stop = threading.Event()
    usage: dict[str, int | str] = {
        "peak_rss_bytes": 0,
        "peak_tasks": 0,
        "peak_processes": 0,
    }
    generation = secrets.token_hex(24)
    try:
        workspace_fd = analysis_worker._directory_fd(registry.workspace.root)
        analysis_fd = analysis_worker._directory_fd(analysis)
        script_fd, normalized_path = _open_target_script(analysis_fd, registry.workspace, path)
        script_sha256 = hashlib.sha256(os.pread(script_fd, MAX_TARGET_SCRIPT_BYTES, 0)).hexdigest()
        ephemeral = Path(tempfile.mkdtemp(prefix="rapido-target-script-", dir="/tmp"))
        ephemeral_fd = analysis_worker._directory_fd(ephemeral)
        result_fd = os.open(
            ephemeral / "result.json",
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        parent_channel, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        broker = _TargetScriptBroker(registry, parent_channel, generation, timeout_seconds)
        with registry._target_brokers_lock:
            registry._target_brokers.add(broker)
        worker_script = str(Path(__file__).with_name("target_script_worker_main.py").resolve())
        try:
            process = subprocess.Popen(
                (
                    os.path.abspath(sys.executable),
                    "-I",
                    "-B",
                    worker_script,
                    "--workspace-fd",
                    str(workspace_fd),
                    "--analysis-fd",
                    str(analysis_fd),
                    "--ephemeral-fd",
                    str(ephemeral_fd),
                    "--script-fd",
                    str(script_fd),
                    "--broker-fd",
                    str(child_channel.fileno()),
                    "--result-fd",
                    str(result_fd),
                ),
                cwd="/",
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                pass_fds=(
                    workspace_fd,
                    analysis_fd,
                    ephemeral_fd,
                    script_fd,
                    child_channel.fileno(),
                    result_fd,
                ),
                close_fds=True,
                start_new_session=True,
                env=analysis_worker._SAFE_ENV,
            )
        except OSError as exc:
            raise _error("tool_unavailable", "target-script worker could not start") from exc
        child_channel.close()
        child_channel = None
        broker_thread = threading.Thread(
            target=broker.serve, name="rapido-target-broker", daemon=True
        )
        broker_thread.start()
        watchdog = threading.Thread(
            target=analysis_worker._watch_process_group,
            args=(process, watchdog_stop, usage),
            name="rapido-target-script-watchdog",
            daemon=True,
        )
        watchdog.start()
        request = json.dumps(
            {
                "protocol": 1,
                "generation": generation,
                "path": normalized_path,
                "timeout_seconds": timeout_seconds,
            },
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode()
        try:
            process.communicate(
                request, timeout=timeout_seconds + analysis_worker.WORKER_DRAIN_SECONDS
            )
        except subprocess.TimeoutExpired as exc:
            broker.close()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=analysis_worker.WORKER_DRAIN_SECONDS)
            raise _error(
                "tool_cleanup_failed", "target-script worker exceeded its outer deadline"
            ) from exc
        if "breach" in usage:
            raise _error("resource_limit", "target-script process tree exceeded its resource limit")
        if process.returncode != 0:
            raise _error("tool_failed", "target-script worker exited without a valid result")
        raw = os.pread(result_fd, 128 * 1024 + 1, 0)
        if len(raw) > 128 * 1024:
            raise _error("output_too_large", "target-script worker response is too large")
        result = _target_worker_response(raw)
        broker_summary = broker.summary()
        broker.close()
        broker_thread.join(timeout=analysis_worker.WORKER_DRAIN_SECONDS)
        broker_summary["cleanup_closed_connections"] = broker_summary["open_connections"]
        broker_summary["cleanup_closed_http_sessions"] = broker_summary["open_http_sessions"]
        broker_summary["open_connections"] = 0
        broker_summary["open_http_sessions"] = 0
        return {
            **result,
            "script_sha256": script_sha256,
            "sources": sources,
            "broker": broker_summary,
            "peak_group_rss_bytes": int(usage["peak_rss_bytes"]),
            "peak_group_tasks": int(usage["peak_tasks"]),
            "peak_group_processes": int(usage["peak_processes"]),
        }
    finally:
        watchdog_stop.set()
        if broker is not None:
            broker.close()
            with registry._target_brokers_lock:
                registry._target_brokers.discard(broker)
        if broker_thread is not None:
            broker_thread.join(timeout=analysis_worker.WORKER_DRAIN_SECONDS)
        if watchdog is not None:
            watchdog.join(timeout=analysis_worker.WORKER_DRAIN_SECONDS)
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.poll() is None:
                try:
                    process.wait(timeout=analysis_worker.WORKER_DRAIN_SECONDS)
                except subprocess.TimeoutExpired:
                    pass
        for channel in (child_channel, parent_channel):
            if channel is not None:
                try:
                    channel.close()
                except OSError:
                    pass
        for descriptor in (result_fd, script_fd, ephemeral_fd, analysis_fd, workspace_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if ephemeral is not None:
            try:
                shutil.rmtree(ephemeral)
            except OSError as exc:
                raise _error(
                    "tool_cleanup_failed", "target-script scratch was not removed"
                ) from exc
        analysis_worker._ANALYSIS_SLOTS.release()


class TargetToolRegistry(ToolRegistry):
    """Workspace tools plus protocol clients bound to Board-issued authorities."""

    def __init__(
        self,
        workspace: Workspace | str | os.PathLike[str],
        endpoints: tuple[TargetEndpoint, ...],
        *,
        team_key: str = "",
        max_workspace_bytes: int | None = None,
        connector: Callable[..., socket.socket] | None = None,
    ) -> None:
        super().__init__(workspace, max_workspace_bytes=max_workspace_bytes)
        if not endpoints or not all(isinstance(item, TargetEndpoint) for item in endpoints):
            raise ValueError("target registry requires parsed endpoints")
        self.endpoints = endpoints
        self._team_key = team_key.encode()
        self._connector = connector or _connect_target
        self._socket: socket.socket | None = None
        self._socket_endpoint: int | None = None
        self._target_calls = 0
        self._target_revoked = threading.Event()
        self._target_brokers_lock = threading.Lock()
        self._target_brokers: set[_TargetScriptBroker] = set()

    @staticmethod
    def _target_specs() -> list[dict[str, Any]]:
        schemas: dict[str, dict[str, Any]] = {
            "target_info": {},
            "http_request": {
                "endpoint_index": {"type": "integer", "minimum": 0, "maximum": 7},
                "method": {
                    "type": "string",
                    "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
                },
                "path": {
                    "type": "string",
                    "description": "Absolute path on the assigned authority; host and port are fixed.",
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "maxProperties": 20,
                },
                "data": {"type": "string", "maxLength": MAX_TARGET_REQUEST_BYTES},
                "encoding": {"type": "string", "enum": ["utf8", "hex", "base64"]},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 15},
            },
            "tcp_open": {
                "endpoint_index": {"type": "integer", "minimum": 0, "maximum": 7},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 15},
            },
            "tcp_exchange": {
                "data": {"type": "string", "maxLength": MAX_INPUT_BYTES},
                "encoding": {"type": "string", "enum": ["utf8", "hex", "base64"]},
                "append_newline": {"type": "boolean"},
                "shutdown_write": {"type": "boolean"},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 15},
            },
            "tcp_close": {},
            "run_target_script": {
                "path": {
                    "type": "string",
                    "description": "A .py script below rapido-analysis; the supervisor fixes all target authorities.",
                },
                "source_paths": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 16,
                    "items": {"type": "string"},
                    "description": "Controller-provided challenge inputs used by the script.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_TARGET_SCRIPT_TIMEOUT_SECONDS,
                },
            },
        }
        descriptions = {
            "target_info": "List sanitized Board-issued endpoint metadata; authority values are never exposed.",
            "http_request": "Send one bounded request to an assigned HTTP(S) endpoint without following redirects.",
            "tcp_open": "Open one assigned TCP endpoint, automatically complete its team-key proof of work, and read initial bytes.",
            "tcp_exchange": "Send and receive bounded bytes on the currently open assigned TCP session.",
            "tcp_close": "Close the currently open assigned TCP session.",
            "run_target_script": (
                "Run one saved Python exploit against assigned endpoints through a bounded "
                "supervisor broker. Import TargetClient from rapido.target_script_client; "
                "direct networking remains denied."
            ),
        }
        result = []
        for name in (
            "target_info",
            "http_request",
            "tcp_open",
            "tcp_exchange",
            "tcp_close",
            "run_target_script",
        ):
            input_schema: dict[str, Any] = {
                "type": "object",
                "properties": schemas[name],
                "additionalProperties": False,
            }
            if name == "run_target_script":
                input_schema["required"] = ["path", "source_paths"]
            result.append(
                {
                    "name": name,
                    "description": descriptions[name],
                    "inputSchema": input_schema,
                }
            )
        return result

    def dynamic_tools(self) -> list[dict[str, Any]]:
        return [*super().dynamic_tools(), *self._target_specs()]

    def _endpoint(
        self, arguments: Mapping[str, Any], protocols: set[str]
    ) -> tuple[int, TargetEndpoint]:
        index = _bounded_int(arguments.get("endpoint_index"), "endpoint_index", 0, 7, 0)
        if index >= len(self.endpoints):
            raise _error("invalid_argument", "endpoint index is not assigned")
        endpoint = self.endpoints[index]
        if endpoint.scheme not in protocols:
            raise _error("protocol_mismatch", "assigned endpoint does not support this tool")
        return index, endpoint

    @staticmethod
    def _http_path(endpoint: TargetEndpoint, value: Any) -> str:
        requested = _bounded_text(value if value is not None else "/", "path", 8192)
        parsed = urllib.parse.urlsplit(requested)
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.fragment
            or not parsed.path.startswith("/")
            or parsed.path.startswith("//")
            or any(part == ".." for part in parsed.path.split("/"))
        ):
            raise _error("path_outside_target", "HTTP path must stay on the assigned authority")
        base = urllib.parse.urlsplit(endpoint.base_path)
        prefix = base.path.rstrip("/")
        path = (prefix + parsed.path) if prefix else parsed.path
        query = parsed.query or (base.query if parsed.path == "/" else "")
        return path + ("?" + query if query else "")

    def _http_request(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        index, endpoint = self._endpoint(arguments, {"http", "https"})
        method = arguments.get("method", "GET")
        if not isinstance(method, str) or method not in {
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            raise _error(
                "invalid_argument",
                "HTTP method is not permitted",
                field_path="method",
                constraint="enum",
                actual_kind=_value_kind(method),
            )
        path = self._http_path(endpoint, arguments.get("path", "/"))
        headers_arg = arguments.get("headers", {})
        if not isinstance(headers_arg, Mapping) or len(headers_arg) > 20:
            raise _error("invalid_argument", "HTTP headers must be a bounded object")
        headers = {
            "User-Agent": "incypher-rapido/0.1",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        }
        forbidden = {"host", "connection", "content-length", "transfer-encoding", "upgrade"}
        for raw_name, raw_value in headers_arg.items():
            if not isinstance(raw_name, str) or not _HEADER.fullmatch(raw_name):
                raise _error("invalid_argument", "HTTP header name is invalid")
            if raw_name.lower() in forbidden or raw_name.lower().startswith("proxy-"):
                raise _error("invalid_argument", "HTTP header cannot override transport authority")
            value = _bounded_text(raw_value, "header value", 4096)
            if (
                any(ord(char) < 32 and char != "\t" for char in value)
                or "\r" in value
                or "\n" in value
            ):
                raise _error("invalid_argument", "HTTP header value is invalid")
            headers[raw_name] = value
        body = _encoded_payload(arguments) if "data" in arguments else b""
        timeout = float(_bounded_int(arguments.get("timeout_seconds"), "timeout_seconds", 1, 15, 8))
        try:
            path_bytes = path.encode("ascii")
            encoded_headers = [
                (name.encode("ascii"), value.encode("latin-1")) for name, value in headers.items()
            ]
        except UnicodeError as exc:
            raise _error(
                "invalid_argument", "HTTP path must be percent-encoded and headers must be Latin-1"
            ) from exc
        host_header = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
        default_port = 443 if endpoint.scheme == "https" else 80
        if endpoint.port != default_port:
            host_header += f":{endpoint.port}"
        request = bytearray(method.encode() + b" " + path_bytes + b" HTTP/1.1\r\n")
        request.extend(b"Host: " + host_header.encode("ascii") + b"\r\n")
        for name, value in encoded_headers:
            request.extend(name + b": " + value + b"\r\n")
        request.extend(b"Connection: close\r\n")
        if body:
            request.extend(f"Content-Length: {len(body)}\r\n".encode())
        request.extend(b"\r\n")
        request.extend(body)
        deadline = time.monotonic() + timeout
        sock: socket.socket | None = None
        try:
            sock = self._connector((endpoint.host, endpoint.port), timeout=timeout)
            if endpoint.scheme == "https":
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                sock.settimeout(remaining)
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=endpoint.host)
            _send_before(sock, bytes(request), deadline)
            status, reason, header_rows, data, truncated = _parse_http_response(
                sock, deadline, method
            )
            return {
                "endpoint_index": index,
                "status": status,
                "reason": reason[:200],
                "headers": header_rows,
                **_wire_result(data, eof=True, truncated=truncated),
            }
        except (OSError, TimeoutError, UnicodeError, ValueError, ssl.SSLError) as exc:
            raise _error("target_transport", "assigned HTTP target request failed") from exc
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _close_socket(self) -> bool:
        existed = self._socket is not None
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        self._socket = None
        self._socket_endpoint = None
        return existed

    def _tcp_open(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        index, endpoint = self._endpoint(arguments, {"tcp"})
        timeout = float(_bounded_int(arguments.get("timeout_seconds"), "timeout_seconds", 1, 15, 8))
        self._close_socket()
        try:
            sock = self._connector((endpoint.host, endpoint.port), timeout=timeout)
            self._socket = sock
            self._socket_endpoint = index
            banner, eof, truncated = _recv_available(
                sock, timeout=timeout, limit=MAX_TARGET_RESPONSE_BYTES
            )
            pow_match = _POW.search(banner)
            pow_record: dict[str, Any] = {"required": False}
            service = banner
            if pow_match is not None:
                bits = int(pow_match.group(2))
                started = time.monotonic()
                solution, attempts = solve_team_pow(self._team_key, pow_match.group(1), bits)
                sock.sendall(str(solution).encode() + b"\n")
                service, eof, truncated = _recv_available(
                    sock, timeout=timeout, limit=MAX_TARGET_RESPONSE_BYTES
                )
                pow_record = {
                    "required": True,
                    "bits": bits,
                    "attempts": attempts,
                    "seconds": round(time.monotonic() - started, 3),
                }
            return {
                "endpoint_index": index,
                "pow": pow_record,
                **_wire_result(service, eof=eof, truncated=truncated),
            }
        except ToolError:
            self._close_socket()
            raise
        except (OSError, TimeoutError) as exc:
            self._close_socket()
            raise _error("target_transport", "assigned TCP target connection failed") from exc

    def _tcp_exchange(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if self._socket is None or self._socket_endpoint is None:
            raise _error("tcp_session", "no assigned TCP session is open")
        payload = _encoded_payload(arguments)
        if arguments.get("append_newline", False):
            payload += b"\n"
        timeout = float(_bounded_int(arguments.get("timeout_seconds"), "timeout_seconds", 1, 15, 8))
        try:
            if payload:
                self._socket.sendall(payload)
            if arguments.get("shutdown_write", False):
                self._socket.shutdown(socket.SHUT_WR)
            data, eof, truncated = _recv_available(
                self._socket, timeout=timeout, limit=MAX_TARGET_RESPONSE_BYTES
            )
            result = {
                "endpoint_index": self._socket_endpoint,
                "sent_bytes": len(payload),
                **_wire_result(data, eof=eof, truncated=truncated),
            }
            if eof:
                self._close_socket()
            return result
        except (OSError, TimeoutError) as exc:
            self._close_socket()
            raise _error("target_transport", "assigned TCP target exchange failed") from exc

    def _run_target_script(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if set(arguments) - {"path", "source_paths", "timeout_seconds"}:
            raise _error("invalid_argument", "target-script arguments are invalid")
        timeout_seconds = _bounded_int(
            arguments.get("timeout_seconds"),
            "timeout_seconds",
            1,
            MAX_TARGET_SCRIPT_TIMEOUT_SECONDS,
            60,
        )
        path = _bounded_text(arguments.get("path"), "path", MAX_INPUT_BYTES)
        sources = _target_script_sources(self.workspace, arguments.get("source_paths"))
        entries, _ = self.workspace.snapshot()
        before = self._rollback_manifest(entries)
        try:
            result = _run_target_script_worker(self, path, sources, timeout_seconds)
            self.workspace.ensure_capacity()
            return {
                **result,
                "path": path,
                "analysis_directory": "rapido-analysis",
            }
        except BaseException as exc:
            try:
                self._restore_run_shell_capacity(before)
            except ToolError as cleanup:
                raise cleanup from exc
            raise

    def dispatch(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if name not in TARGET_TOOL_NAMES:
            return super().dispatch(name, arguments)
        arguments = {} if arguments is None else arguments
        if not isinstance(arguments, Mapping):
            raise _error(
                "invalid_argument",
                "tool arguments must be an object",
                field_path="arguments",
                constraint="type",
                actual_kind=_value_kind(arguments),
            )
        with self._dispatch_lock:
            if self._target_revoked.is_set():
                raise _error("generation_revoked", "target generation is no longer active")
            self._target_calls += 1
            if self._target_calls > MAX_TARGET_CALLS:
                raise _error("tool_call_limit", "target tool call limit reached")
            if name == "target_info":
                return {
                    "endpoints": [item.public_record(i) for i, item in enumerate(self.endpoints)]
                }
            if name == "http_request":
                return self._http_request(arguments)
            if name == "tcp_open":
                return self._tcp_open(arguments)
            if name == "tcp_exchange":
                return self._tcp_exchange(arguments)
            if name == "tcp_close":
                return {"closed": self._close_socket()}
            if name == "run_target_script":
                return self._run_target_script(arguments)
        raise _error("unknown_tool", "unknown target tool")

    def close(self) -> None:
        self._target_revoked.set()
        with self._target_brokers_lock:
            brokers = tuple(self._target_brokers)
        for broker in brokers:
            broker.close()
        with self._dispatch_lock:
            self._close_socket()


__all__ = [
    "MAX_POW_BITS",
    "TARGET_TOOL_NAMES",
    "TargetEndpoint",
    "TargetToolRegistry",
    "parse_connection_info",
    "solve_team_pow",
]
