"""Bounded CTFd/IN-CYPHER Board transport.

Challenge targets never pass through this client. API redirects are refused; only challenge-file
downloads may follow a small number of HTTPS redirects, and the Board token never leaves its origin.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0 Safari/537.36"
)
FLAG_RE = re.compile(r"(?:INCYPHER|flag)\{[^{}\r\n]{1,512}\}")
API_RESPONSE_LIMIT = 4 * 1024 * 1024


class BoardError(RuntimeError):
    """A deliberately sanitized Board failure."""


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


Transport = Callable[[urllib.request.Request, float, int], HttpResponse]


def _challenge_id(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise BoardError("challenge id must be a positive integer")
    return value


def _https_url(value: str, *, origin_only: bool = False) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(value)
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _default_transport(
    request: urllib.request.Request, timeout: float, byte_limit: int
) -> HttpResponse:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(byte_limit + 1)
            if len(body) > byte_limit:
                raise BoardError("Board response exceeded the configured byte limit")
            return HttpResponse(
                status=int(response.code),
                body=body,
                location=response.headers.get("Location", ""),
                content_type=response.headers.get("Content-Type", ""),
            )
    except BoardError:
        raise
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise BoardError("Board transport failed") from exc


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
        if not isinstance(value, dict) or type(value.get("id")) is not int:
            raise BoardError("identity returned an invalid shape")
        return value

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
        if not isinstance(raw, dict) or raw.get("id") != challenge_id:
            raise BoardError("challenge detail returned an invalid shape")

        def text(name: str, default: str = "") -> str:
            value = raw.get(name, default)
            if not isinstance(value, str) or len(value) > 2_000_000:
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
        return Challenge(
            id=challenge_id,
            name=text("name"),
            category=text("category", "unknown"),
            type=text("type", "unknown"),
            description=text("description"),
            value=value,
            files=tuple(files),
            solved=bool(raw.get("solved_by_me", raw.get("solved", False))),
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
        if response.status not in {200, 403, 404, 429}:
            raise BoardError(f"instance operation returned HTTP {response.status}")
        try:
            document = json.loads(response.body) if response.body else {}
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise BoardError("instance operation returned malformed JSON") from exc
        if not isinstance(document, dict):
            raise BoardError("instance operation returned an invalid shape")
        data = document.get("data", {})
        return {
            "success": document.get("success") is True,
            "status": response.status,
            "connection_info": data.get("connectionInfo", "") if isinstance(data, dict) else "",
            "until": data.get("until") if isinstance(data, dict) else None,
            "message": str(document.get("message", ""))[:512],
        }

    def download(self, file_ref: str, destination: Path) -> dict[str, Any]:
        if not isinstance(file_ref, str) or not file_ref or len(file_ref) > 8192:
            raise BoardError("challenge file reference is invalid")
        url = urllib.parse.urljoin(self.origin + "/", file_ref)
        _https_url(url)
        if not self._same_origin(url):
            raise BoardError("initial challenge file URL must use the Board origin")
        chain: list[str] = []
        for _ in range(5):
            response = self._request("GET", url, byte_limit=self.artifact_limit)
            host = urllib.parse.urlsplit(url).hostname or ""
            chain.append(host)
            if response.status in {301, 302, 303, 307, 308}:
                if not response.location:
                    raise BoardError("challenge file redirect lacked a destination")
                url = urllib.parse.urljoin(url, response.location)
                _https_url(url)
                continue
            if response.status != 200:
                raise BoardError(f"challenge file returned HTTP {response.status}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(destination.name + ".partial")
            temporary.write_bytes(response.body)
            temporary.replace(destination)
            return {"bytes": len(response.body), "redirect_hosts": chain}
        raise BoardError("challenge file exceeded the redirect limit")
