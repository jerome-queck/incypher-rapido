"""Read-only, metadata-only CTFd diagnostic. Never contacts a challenge target."""
from __future__ import annotations

import json
import math
import re
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

ORIGIN = "https://hackathon.in-cypher.com"
MAX_RESPONSE = 2 * 1024 * 1024
MAX_CHALLENGES = 200
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0 Safari/537.36"
)
ALLOWED_PATH = re.compile(
    r"/api/v1/(?:users/me|challenges(?:/[1-9][0-9]*)?|"
    r"plugins/ctfd-chall-manager/mana)\Z"
)


class ContractError(ValueError):
    """A safe static explanation, never a raw HTTP body or credential."""


@dataclass(frozen=True)
class Reply:
    status: int
    content_type: str
    body: bytes


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def transport(request: urllib.request.Request, timeout: float) -> Reply:
    """Bound each request. System proxy variables are deliberately not inherited.

    The deadline is checked between reads; an in-progress read can consume one
    additional socket timeout. This is not a hard real-time guarantee.
    """
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect()
    )
    began = time.monotonic()
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as response_error:
            response = response_error
        with response:
            status = response.code
            content_type = response.headers.get_content_type()
            if status != 200:
                return Reply(status, content_type, b"")
            data = bytearray()
            while True:
                if time.monotonic() - began > timeout:
                    raise ContractError("response read budget exceeded")
                # read1 avoids waiting to fill a large buffer when data trickles.
                chunk = response.read1(min(65536, MAX_RESPONSE + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_RESPONSE:
                    raise ContractError("response exceeds byte limit")
            return Reply(status, content_type, bytes(data))
    except ContractError:
        raise
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise ContractError("Board transport failed; inspect connectivity locally") from exc


class ReadOnlyBoard:
    """Fixed official origin, fixed GET endpoints, no generic request or write API."""

    def __init__(
        self, token: str, *,
        send: Callable[[urllib.request.Request, float], Reply] = transport,
        timeout: float = 5.0,
        budget_seconds: float = 60.0,
    ) -> None:
        if (not isinstance(token, str) or not token or len(token) > 512
                or not token.isascii() or any(c.isspace() for c in token)):
            raise ContractError("set a nonempty ASCII CTFD_API_TOKEN without whitespace")
        if not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ContractError("request timeout must be finite and in (0, 30]")
        if not math.isfinite(budget_seconds) or not 0 < budget_seconds <= 300:
            raise ContractError("preflight budget must be finite and in (0, 300]")
        self._token = token
        self._send = send
        self._timeout = timeout
        self._budget = budget_seconds
        self._deadline = 0.0
        self.requests = 0

    def _get(self, path: str):
        if not ALLOWED_PATH.fullmatch(path):
            raise ContractError("endpoint is not in the read-only allowlist")
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise ContractError("preflight budget exhausted")
        request = urllib.request.Request(
            ORIGIN + path, method="GET",
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": "Token " + self._token,
            },
        )
        self.requests += 1
        reply = self._send(request, min(self._timeout, remaining))
        if reply.status != 200:
            # No retrying a rate limit and no leaking Location/body/header contents.
            raise ContractError(f"Board HTTP {reply.status}; no redirect or retry performed")
        if reply.content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise ContractError("Board returned non-JSON content")
        if len(reply.body) > MAX_RESPONSE:
            raise ContractError("response exceeds byte limit")
        try:
            document = json.loads(reply.body)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ContractError("Board returned malformed JSON") from exc
        if not isinstance(document, dict) or document.get("success") is not True:
            raise ContractError("Board response is not a successful API envelope")
        if "data" not in document:
            raise ContractError("Board response lacks data")
        return document["data"]

    def _label(self, value: object) -> str:
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ContractError("metadata label is absent, invalid, or too long")
        value = value.replace(self._token, "[redacted]")
        value = re.sub(r"(?i)(?:INCYPHER|flag)\{[^}]*\}", "[redacted]", value)
        value = re.sub(r"ctfd_[A-Za-z0-9]+", "[redacted]", value)
        value = re.sub(r"\b[0-9a-fA-F]{64}\b", "[redacted]", value)
        return "".join(c if c.isprintable() else "?" for c in value)

    @staticmethod
    def _id(row: object) -> int:
        if not isinstance(row, dict) or type(row.get("id")) is not int or row["id"] <= 0:
            raise ContractError("invalid participant or challenge id")
        return row["id"]

    def snapshot(self) -> dict:
        self._deadline = time.monotonic() + self._budget
        self.requests = 0
        identity = self._get("/api/v1/users/me")
        self._id(identity)
        team_joined = type(identity.get("team_id")) is int and identity["team_id"] > 0
        listed = self._get("/api/v1/challenges")
        if not isinstance(listed, list) or len(listed) > MAX_CHALLENGES:
            raise ContractError("challenge collection has invalid shape or exceeds limit")
        if not listed:
            raise ContractError("empty collection is unverified, not proof of no challenges")
        ids = [self._id(row) for row in listed]
        if len(set(ids)) != len(ids):
            raise ContractError("duplicate challenge ids in collection")
        categories: Counter = Counter()
        types: Counter = Counter()
        terms: list[dict] = []
        file_count = 0
        for challenge_id in sorted(ids):
            detail = self._get(f"/api/v1/challenges/{challenge_id}")
            if self._id(detail) != challenge_id:
                raise ContractError("challenge detail id does not match request")
            categories[self._label(detail.get("category"))] += 1
            challenge_type = self._label(detail.get("type"))
            types[challenge_type] += 1
            files = detail.get("files", [])
            if not isinstance(files, list):
                raise ContractError("invalid attachment metadata")
            file_count += len(files)
            term = {"challenge_id": challenge_id, "type": challenge_type}
            for key in ("timeout", "mana_cost", "max_attempts"):
                value = detail.get(key)
                if value is not None and (type(value) is not int or value < 0):
                    raise ContractError("invalid numeric challenge terms")
                term[key] = value
            for key in ("shared", "destroy_on_flag"):
                value = detail.get(key)
                if value is not None and type(value) is not bool:
                    raise ContractError("invalid boolean challenge terms")
                term[key] = value
            terms.append(term)
        mana: dict = {"status": "unverified"}
        try:
            raw = self._get("/api/v1/plugins/ctfd-chall-manager/mana")
            if (isinstance(raw, dict) and all(
                type(raw.get(k)) is int and raw[k] >= 0 for k in ("used", "total")
            )):
                mana = {"status": "observed", "used": raw["used"], "total": raw["total"]}
        except ContractError:
            pass  # Optional plugin failure does not invalidate verified core reads.
        return {
            "mode": "read_only_preflight",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "competition_ready": False,
            "authentication_verified": True,
            "team_membership_observed": team_joined,
            "challenge_count": len(ids),
            "category_counts": dict(sorted(categories.items())),
            "type_counts": dict(sorted(types.items())),
            "attachment_count": file_count,
            "challenge_terms": terms,
            "mana": mana,
            "requests": self.requests,
            "writes": 0,
            "target_connections": 0,
            "warnings": [
                "Snapshot only: no lifecycle, attachment download, ADK, or submission verification.",
                "Current practice terms do not establish hidden competition terms.",
                "This is not a challenge solver or competition-ready submission.",
            ],
        }
