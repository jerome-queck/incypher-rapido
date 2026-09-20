"""Bounded CTFd/IN-CYPHER Board transport.

Challenge targets never pass through this client. API redirects are refused; only challenge-file
downloads may follow a small number of same-origin HTTPS redirects.
"""

from __future__ import annotations

import json
import re
import ssl
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .target import _connect_target, _parse_http_response, _send_before

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0 Safari/537.36"
)
FLAG_RE = re.compile(r"(?:INCYPHER|flag)\{[^{}\r\n]{1,512}\}")
API_RESPONSE_LIMIT = 4 * 1024 * 1024
MAX_CHALLENGE_DESCRIPTION_BYTES = 256 * 1024


class BoardError(RuntimeError):
    """A deliberately sanitized Board failure."""


class BoardTransportError(BoardError):
    """A retryable failure that occurred before a readable Board response."""


class BoardTemporaryResponseError(BoardError):
    """A retryable server response to an idempotent Board read."""


_TEMPORARY_READ_STATUSES = frozenset({500, 502, 503, 504})


def _raise_temporary_read_response(response: HttpResponse, operation: str) -> None:
    if response.status in _TEMPORARY_READ_STATUSES:
        raise BoardTemporaryResponseError(f"{operation} returned HTTP {response.status}")


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    location: str = ""
    content_type: str = ""


@dataclass(frozen=True)
class Challenge:
    id: int
    name: str
    category: str
    type: str
    description: str
    value: int
    files: tuple[str, ...]
    solved: bool
    max_attempts: int | None
    attempts: int
    timeout: int | None
    shared: bool | None


@dataclass(frozen=True)
class Verdict:
    outcome: str
    message: str
    http_status: int

    @property
    def correct(self) -> bool:
        return self.outcome == "correct"

    @property
    def settled(self) -> bool:
        return self.outcome in {"correct", "incorrect", "already_solved"}


class BoardLike(Protocol):
    """Narrow structural Board surface consumed by orchestration.

    Production authority remains entirely in :class:`BoardClient`.  This
    protocol documents the existing dependency-injection seam without making
    either adapter inherit from, register with, or trust the other.
    """

    timeout: float

    def identity(self) -> dict[str, Any]: ...

    def anonymous_identity_is_rejected(self) -> bool: ...

    def list_challenges(self) -> list[dict[str, Any]]: ...

    def challenge(self, challenge_id: int) -> Challenge: ...

    def download(
        self,
        file_ref: str,
        destination: Path,
        *,
        byte_limit: int | None = None,
    ) -> dict[str, Any]: ...

    def submit(self, challenge_id: int, candidate: str) -> Verdict: ...

    def instance(self, method: str, challenge_id: int) -> dict[str, Any]: ...


Transport = Callable[[urllib.request.Request, float, int], HttpResponse]


def _challenge_id(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise BoardError("challenge id must be a positive integer")
    return value


def _https_url(value: str, *, origin_only: bool = False) -> urllib.parse.SplitResult:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as exc:
        raise BoardError("Board URL is malformed") from exc
    try:
        port = parsed.port
    except ValueError as exc:
        raise BoardError("Board URL contains an invalid port") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or (
            origin_only
            and (
                parsed.hostname != "hackathon.in-cypher.com"
                or port not in (None, 443)
                or parsed.path not in ("", "/")
                or parsed.query
                or parsed.fragment
            )
        )
    ):
        label = "origin" if origin_only else "request URL"
        raise BoardError(f"Board {label} is not permitted")
    return parsed


def _default_transport(
    request: urllib.request.Request, timeout: float, byte_limit: int
) -> HttpResponse:
    parsed = _https_url(request.full_url)
    deadline = time.monotonic() + timeout
    raw_sock = None
    sock = None
    try:
        raw_sock = _connect_target((parsed.hostname or "", parsed.port or 443), timeout)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        raw_sock.settimeout(remaining)
        sock = ssl.create_default_context().wrap_socket(raw_sock, server_hostname=parsed.hostname)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        method = request.get_method()
        body = request.data or b""
        headers = dict(request.header_items())
        headers["Host"] = parsed.hostname or ""
        headers["Accept-Encoding"] = "identity"
        headers["Connection"] = "close"
        if request.data is not None:
            headers["Content-Length"] = str(len(body))
        request_bytes = bytearray(f"{method} {path} HTTP/1.1\r\n".encode("ascii"))
        for name, value in headers.items():
            if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
                raise ValueError("HTTP header contains a line break")
            request_bytes.extend(f"{name}: {value}\r\n".encode("latin-1"))
        request_bytes.extend(b"\r\n")
        request_bytes.extend(body)
        _send_before(sock, bytes(request_bytes), deadline)
        status, _, response_headers, response_body, truncated = _parse_http_response(
            sock,
            deadline,
            method,
            response_limit=byte_limit,
            header_limit=64 * 1024,
            returned_header_limit=100,
            header_value_limit=64 * 1024,
        )
        if truncated:
            raise BoardError("Board response exceeded the configured byte limit")
        by_name = {name.lower(): value for name, value in response_headers}
        return HttpResponse(
            status=status,
            body=response_body,
            location=by_name.get("location", ""),
            content_type=by_name.get("content-type", ""),
        )
    except BoardError:
        raise
    except (OSError, TimeoutError, UnicodeError, ValueError, ssl.SSLError) as exc:
        raise BoardTransportError("Board transport failed") from exc
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if raw_sock is not None and raw_sock is not sock:
            try:
                raw_sock.close()
            except OSError:
                pass


class BoardClient:
    """Fixed-origin Board API plus explicit file-download redirects."""

    def __init__(
        self,
        origin: str,
        token: str,
        *,
        timeout: float = 15.0,
        response_limit: int = API_RESPONSE_LIMIT,
        artifact_limit: int = 128 * 1024 * 1024,
        transport: Transport = _default_transport,
    ) -> None:
        _https_url(origin, origin_only=True)
        if token and (not token.isascii() or any(c.isspace() for c in token) or len(token) > 1024):
            raise BoardError("Board token is invalid")
        if not 0 < timeout <= 120:
            raise BoardError("Board timeout is out of bounds")
        self.origin = origin.rstrip("/")
        self._origin_parts = urllib.parse.urlsplit(self.origin)
        self._token = token
        self.timeout = timeout
        self.response_limit = response_limit
        self.artifact_limit = artifact_limit
        self._transport = transport

    def _same_origin(self, url: str) -> bool:
        parsed = urllib.parse.urlsplit(url)
        left = (parsed.scheme, parsed.hostname, parsed.port or 443)
        right = (
            self._origin_parts.scheme,
            self._origin_parts.hostname,
            self._origin_parts.port or 443,
        )
        return left == right

    def _request(
        self,
        method: str,
        path_or_url: str,
        body: dict[str, Any] | None = None,
        *,
        byte_limit: int | None = None,
    ) -> HttpResponse:
        if path_or_url.startswith("/"):
            url = self.origin + path_or_url
        else:
            url = path_or_url
        _https_url(url)
        payload = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        request = urllib.request.Request(url, data=payload, method=method)
        request.add_header("User-Agent", BROWSER_USER_AGENT)
        request.add_header("Accept", "application/json")
        if self._same_origin(url):
            request.add_header("Content-Type", "application/json")
        if self._token and self._same_origin(url):
            request.add_header("Authorization", f"Token {self._token}")
        return self._transport(request, self.timeout, byte_limit or self.response_limit)

    @staticmethod
    def _document(response: HttpResponse, operation: str) -> Any:
        _raise_temporary_read_response(response, operation)
        if response.status != 200:
            raise BoardError(f"{operation} returned HTTP {response.status}")
        try:
            document = json.loads(response.body)
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise BoardError(f"{operation} returned malformed JSON") from exc
        if (
            not isinstance(document, dict)
            or document.get("success") is not True
            or "data" not in document
        ):
            raise BoardError(f"{operation} returned an unsuccessful API envelope")
        return document["data"]

    def identity(self) -> dict[str, Any]:
        value = self._document(self._request("GET", "/api/v1/users/me"), "identity")
        if not isinstance(value, dict) or type(value.get("id")) is not int or value["id"] <= 0:
            raise BoardError("identity returned an invalid shape")
        return value

    def anonymous_identity_is_rejected(self) -> bool:
        """Negative auth control using the same origin/transport without credentials."""
        request = urllib.request.Request(
            self.origin + "/api/v1/users/me",
            method="GET",
            headers={
                "User-Agent": BROWSER_USER_AGENT,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        response = self._transport(request, self.timeout, self.response_limit)
        _raise_temporary_read_response(response, "anonymous identity")
        return response.status in {401, 403}

    def list_challenges(self) -> list[dict[str, Any]]:
        value = self._document(self._request("GET", "/api/v1/challenges"), "challenge list")
        if not isinstance(value, list):
            raise BoardError("challenge list returned an invalid shape")
        rows = [row for row in value if isinstance(row, dict)]
        if len(rows) != len(value) or len(rows) > 1000:
            raise BoardError("challenge list contains invalid rows or exceeds the limit")
        return rows

    def challenge(self, challenge_id: int) -> Challenge:
        _challenge_id(challenge_id)
        raw = self._document(
            self._request("GET", f"/api/v1/challenges/{challenge_id}"), "challenge detail"
        )
        if not isinstance(raw, dict) or type(raw.get("id")) is not int or raw["id"] != challenge_id:
            raise BoardError("challenge detail returned an invalid shape")

        def text(name: str, default: str = "") -> str:
            value = raw.get(name, default)
            limit = MAX_CHALLENGE_DESCRIPTION_BYTES if name == "description" else 4096
            if not isinstance(value, str):
                raise BoardError(f"challenge {name} is invalid")
            try:
                encoded = value.encode("utf-8")
            except UnicodeError as exc:
                raise BoardError(f"challenge {name} is invalid") from exc
            if len(encoded) > limit:
                raise BoardError(f"challenge {name} is invalid")
            return value

        files = raw.get("files", [])
        if (
            not isinstance(files, list)
            or len(files) > 100
            or not all(isinstance(v, str) for v in files)
        ):
            raise BoardError("challenge files are invalid")
        value = raw.get("value", 0)
        attempts = raw.get("attempts", 0)
        max_attempts = raw.get("max_attempts")
        timeout = raw.get("timeout")
        for name, number in (("value", value), ("attempts", attempts)):
            if type(number) is not int or number < 0:
                raise BoardError(f"challenge {name} is invalid")
        for name, number in (("max_attempts", max_attempts), ("timeout", timeout)):
            if number is not None and (type(number) is not int or number < 0):
                raise BoardError(f"challenge {name} is invalid")
        shared = raw.get("shared")
        if shared is not None and type(shared) is not bool:
            raise BoardError("challenge shared value is invalid")
        solved = raw.get("solved_by_me", raw.get("solved", False))
        if type(solved) is not bool:
            raise BoardError("challenge solved value is invalid")
        return Challenge(
            id=challenge_id,
            name=text("name"),
            category=text("category", "unknown"),
            type=text("type", "unknown"),
            description=text("description"),
            value=value,
            files=tuple(files),
            solved=solved,
            max_attempts=max_attempts,
            attempts=attempts,
            timeout=timeout,
            shared=shared,
        )

    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        _challenge_id(challenge_id)
        if (
            not isinstance(candidate, str)
            or not FLAG_RE.fullmatch(candidate)
            or len(candidate) > 600
        ):
            raise BoardError("candidate does not match a supported flag shape")
        response = self._request(
            "POST",
            "/api/v1/challenges/attempt",
            {"challenge_id": challenge_id, "submission": candidate},
        )
        try:
            document = json.loads(response.body)
        except (UnicodeError, ValueError, RecursionError):
            return Verdict("unread", "submission response was not readable JSON", response.status)
        data = (
            document.get("data")
            if isinstance(document, dict) and document.get("success") is True
            else None
        )
        if not isinstance(data, dict) or not isinstance(data.get("status"), str):
            return Verdict("unread", "submission response carried no verdict", response.status)
        outcome = data["status"][:64]
        expected_statuses = {
            200: {"correct", "incorrect", "already_solved"},
            403: {"paused"},
            429: {"ratelimited"},
        }
        if outcome not in expected_statuses.get(response.status, set()):
            return Verdict(
                "unread", "submission response status and verdict disagreed", response.status
            )
        message = data.get("message", "")
        return Verdict(
            outcome,
            message[:512] if isinstance(message, str) else "",
            response.status,
        )

    def instance(self, method: str, challenge_id: int) -> dict[str, Any]:
        if method not in {"GET", "POST", "PATCH", "DELETE"}:
            raise BoardError("unsupported instance method")
        _challenge_id(challenge_id)
        query = urllib.parse.urlencode({"challengeId": challenge_id})
        body = None if method == "GET" else {"challengeId": challenge_id}
        response = self._request(
            method, f"/api/v1/plugins/ctfd-chall-manager/instance?{query}", body
        )
        if method == "GET":
            _raise_temporary_read_response(response, "instance operation")
        if response.status not in {200, 403, 404, 429}:
            raise BoardError(f"instance operation returned HTTP {response.status}")
        try:
            document = json.loads(response.body) if response.body else {}
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise BoardError("instance operation returned malformed JSON") from exc
        if not isinstance(document, dict):
            raise BoardError("instance operation returned an invalid shape")
        data = document.get("data", {})
        if not isinstance(data, dict):
            raise BoardError("instance operation returned invalid data")
        connection_info = data.get("connectionInfo", "")
        if connection_info is None:
            connection_info = ""
        try:
            connection_info_bytes = (
                connection_info.encode("utf-8") if isinstance(connection_info, str) else b""
            )
        except UnicodeError as exc:
            raise BoardError("instance connection information is invalid") from exc
        if not isinstance(connection_info, str) or len(connection_info_bytes) > 32 * 1024:
            raise BoardError("instance connection information is invalid")
        until = data.get("until")
        since = data.get("since")
        for name, value in (("until", until), ("since", since)):
            if value is not None and (
                not isinstance(value, (str, int, float))
                or isinstance(value, bool)
                or len(str(value)) > 256
            ):
                raise BoardError(f"instance {name} is invalid")
        return {
            "success": document.get("success") is True,
            "status": response.status,
            "connection_info": connection_info,
            "until": until,
            "since": since,
            "message": str(document.get("message", ""))[:512],
        }

    def download(
        self, file_ref: str, destination: Path, *, byte_limit: int | None = None
    ) -> dict[str, Any]:
        if not isinstance(file_ref, str) or not file_ref or len(file_ref) > 8192:
            raise BoardError("challenge file reference is invalid")
        try:
            url = urllib.parse.urljoin(self.origin + "/", file_ref)
        except ValueError as exc:
            raise BoardError("challenge file reference is invalid") from exc
        _https_url(url)
        if not self._same_origin(url):
            raise BoardError("initial challenge file URL must use the Board origin")
        limit = self.artifact_limit if byte_limit is None else byte_limit
        if not 0 < limit <= self.artifact_limit:
            raise BoardError("challenge file byte limit is invalid")
        chain: list[str] = []
        for _ in range(5):
            response = self._request("GET", url, byte_limit=limit)
            _raise_temporary_read_response(response, "challenge file")
            host = urllib.parse.urlsplit(url).hostname or ""
            chain.append(host)
            if response.status in {301, 302, 303, 307, 308}:
                if not response.location:
                    raise BoardError("challenge file redirect lacked a destination")
                try:
                    url = urllib.parse.urljoin(url, response.location)
                except ValueError as exc:
                    raise BoardError("challenge file redirect is invalid") from exc
                _https_url(url)
                if not self._same_origin(url):
                    raise BoardError("off-origin challenge file redirect is not permitted")
                continue
            if response.status != 200:
                raise BoardError(f"challenge file returned HTTP {response.status}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(destination.name + ".partial")
            temporary.write_bytes(response.body)
            temporary.replace(destination)
            return {"bytes": len(response.body), "redirect_hosts": chain}
        raise BoardError("challenge file exceeded the redirect limit")
