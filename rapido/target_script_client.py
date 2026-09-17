"""Client available only inside a supervisor-launched target-script worker."""

from __future__ import annotations

import base64
import json
import os
import threading
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 256 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024


class TargetError(RuntimeError):
    """Safe broker failure returned to a target script."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise TargetError("broker_unavailable", "target broker closed")
        view = view[written:]


def _read_exact(descriptor: int, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            raise TargetError("broker_unavailable", "target broker closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _payload(value: str | bytes | bytearray | memoryview) -> tuple[str, str]:
    if isinstance(value, str):
        raw = value.encode()
        encoding = "utf8"
        encoded = value
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        encoding = "base64"
        encoded = base64.b64encode(raw).decode("ascii")
    else:
        raise TypeError("target data must be str or bytes")
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ValueError("target data exceeds 64 KiB")
    return encoding, encoded


class TargetClient:
    """Endpoint-index/opaque-handle API backed by the supervisor."""

    _current: ClassVar[TargetClient | None] = None

    def __init__(self, descriptor: int, generation: str) -> None:
        self._descriptor = descriptor
        self._generation = generation
        self._lock = threading.Lock()

    @classmethod
    def current(cls) -> TargetClient:
        current = cls._current
        if current is None:
            raise TargetError("broker_unavailable", "no target broker is installed")
        return current

    @classmethod
    def _install(cls, descriptor: int, generation: str) -> TargetClient:
        if cls._current is not None:
            raise TargetError("broker_unavailable", "target broker is already installed")
        cls._current = cls(descriptor, generation)
        return cls._current

    @classmethod
    def _uninstall(cls) -> None:
        cls._current = None

    def _call(self, operation: str, **arguments: Any) -> dict[str, Any]:
        request = {
            "protocol": PROTOCOL_VERSION,
            "generation": self._generation,
            "operation": operation,
            "arguments": arguments,
        }
        raw = json.dumps(request, ensure_ascii=True, separators=(",", ":")).encode()
        if len(raw) > MAX_FRAME_BYTES:
            raise ValueError("target broker request is too large")
        with self._lock:
            _write_all(self._descriptor, len(raw).to_bytes(4, "big") + raw)
            length = int.from_bytes(_read_exact(self._descriptor, 4), "big")
            if not 1 <= length <= MAX_FRAME_BYTES:
                raise TargetError("broker_protocol", "target broker response is invalid")
            response_raw = _read_exact(self._descriptor, length)
        try:
            response = json.loads(response_raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise TargetError("broker_protocol", "target broker response is invalid") from exc
        if not isinstance(response, dict) or response.get("protocol") != PROTOCOL_VERSION:
            raise TargetError("broker_protocol", "target broker response is invalid")
        if response.get("ok") is True and set(response) == {"protocol", "ok", "result"}:
            result = response["result"]
            if not isinstance(result, dict):
                raise TargetError("broker_protocol", "target broker result is invalid")
            return result
        if response.get("ok") is False and set(response) == {"protocol", "ok", "error"}:
            error = response["error"]
            if (
                isinstance(error, dict)
                and isinstance(error.get("code"), str)
                and isinstance(error.get("message"), str)
            ):
                raise TargetError(error["code"], error["message"])
        raise TargetError("broker_protocol", "target broker response is invalid")

    def endpoints(self) -> list[dict[str, Any]]:
        return list(self._call("target_info")["endpoints"])

    def http_session(self, endpoint_index: int = 0) -> str:
        return str(self._call("http_session_open", endpoint_index=endpoint_index)["session"])

    def http_close(self, session: str) -> bool:
        return bool(self._call("http_session_close", session=session)["closed"])

    def http_request(
        self,
        *,
        endpoint_index: int | None = None,
        session: str | None = None,
        method: str = "GET",
        path: str = "/",
        headers: Mapping[str, str] | None = None,
        data: str | bytes | bytearray | memoryview = b"",
        timeout_seconds: int = 15,
    ) -> dict[str, Any]:
        encoding, encoded = _payload(data)
        arguments: dict[str, Any] = {
            "method": method,
            "path": path,
            "headers": dict(headers or {}),
            "data": encoded,
            "encoding": encoding,
            "timeout_seconds": timeout_seconds,
        }
        if endpoint_index is not None or session is None:
            arguments["endpoint_index"] = 0 if endpoint_index is None else endpoint_index
        if session is not None:
            arguments["session"] = session
        return self._call("http_request", **arguments)

    def tcp_open(self, endpoint_index: int = 0, *, timeout_seconds: int = 15) -> dict[str, Any]:
        return self._call(
            "tcp_open", endpoint_index=endpoint_index, timeout_seconds=timeout_seconds
        )

    def tcp_exchange(
        self,
        handle: str,
        data: str | bytes | bytearray | memoryview = b"",
        *,
        append_newline: bool = False,
        shutdown_write: bool = False,
        timeout_seconds: int = 15,
    ) -> dict[str, Any]:
        encoding, encoded = _payload(data)
        return self._call(
            "tcp_exchange",
            handle=handle,
            data=encoded,
            encoding=encoding,
            append_newline=append_newline,
            shutdown_write=shutdown_write,
            timeout_seconds=timeout_seconds,
        )

    def exchange_many(
        self,
        requests: Sequence[Mapping[str, Any]],
        *,
        timeout_seconds: int = 15,
    ) -> list[dict[str, Any]]:
        if not 2 <= len(requests) <= 4:
            raise ValueError("exchange_many requires two to four requests")
        encoded_requests: list[dict[str, Any]] = []
        for request in requests:
            if not isinstance(request, Mapping):
                raise TypeError("exchange_many entries must be mappings")
            encoding, encoded = _payload(request.get("data", b""))
            encoded_requests.append(
                {
                    "handle": request.get("handle"),
                    "data": encoded,
                    "encoding": encoding,
                    "append_newline": request.get("append_newline", False),
                    "shutdown_write": request.get("shutdown_write", False),
                }
            )
        return list(
            self._call(
                "exchange_many",
                requests=encoded_requests,
                timeout_seconds=timeout_seconds,
            )["results"]
        )

    def tcp_close(self, handle: str) -> bool:
        return bool(self._call("tcp_close", handle=handle)["closed"])


__all__ = ["TargetClient", "TargetError"]
