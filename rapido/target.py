"""Board-issued target endpoints and bounded protocol tools.

Only ``parse_connection_info`` can create endpoint authorities.  Dynamic tool
arguments never contain a host or port, so a model cannot turn these helpers into
a scanner or a general network client.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import ipaddress
import os
import re
import socket
import ssl
import subprocess
import time
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .tools import (
    MAX_INPUT_BYTES,
    ToolError,
    ToolRegistry,
    Workspace,
    _bounded_int,
    _bounded_text,
    _error,
)

MAX_CONNECTION_INFO_BYTES = 32 * 1024
MAX_TARGET_RESPONSE_BYTES = 8 * 1024
MAX_TARGET_HEADER_BYTES = 8 * 1024
MAX_TARGET_REQUEST_BYTES = 64 * 1024
MAX_TARGET_CALLS = 80
MAX_POW_BITS = 24
TARGET_TOOL_NAMES = frozenset(
    {"target_info", "http_request", "tcp_open", "tcp_exchange", "tcp_close"}
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
        }
        descriptions = {
            "target_info": "List sanitized Board-issued endpoint metadata; authority values are never exposed.",
            "http_request": "Send one bounded request to an assigned HTTP(S) endpoint without following redirects.",
            "tcp_open": "Open one assigned TCP endpoint, automatically complete its team-key proof of work, and read initial bytes.",
            "tcp_exchange": "Send and receive bounded bytes on the currently open assigned TCP session.",
            "tcp_close": "Close the currently open assigned TCP session.",
        }
        return [
            {
                "name": name,
                "description": descriptions[name],
                "inputSchema": {
                    "type": "object",
                    "properties": schemas[name],
                    "additionalProperties": False,
                },
            }
            for name in ("target_info", "http_request", "tcp_open", "tcp_exchange", "tcp_close")
        ]

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
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
            raise _error("invalid_argument", "HTTP method is not permitted")
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

    def dispatch(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if name not in TARGET_TOOL_NAMES:
            return super().dispatch(name, arguments)
        arguments = {} if arguments is None else arguments
        if not isinstance(arguments, Mapping):
            raise _error("invalid_argument", "tool arguments must be an object")
        with self._dispatch_lock:
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
        raise _error("unknown_tool", "unknown target tool")

    def close(self) -> None:
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
