"""Pure typed same-run memory projection.

The persistence adapter supplies typed records.  This module only applies scope,
privacy, ordering, deduplication, and byte-budget rules; it owns no effects or
cache. Candidate context is private and is never accepted by the public projector.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import unicodedata
import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, TypeAlias

PROTOCOL_SHA256 = "4605399b8ff84acef4ecbcd30bd1856a86b8e3792d94f03fd525db4d70cd8a6e"
PROJECTION_BYTES = 64 * 1024

MemoryArm = Literal["lane_local_v1", "typed_challenge_v1"]
MemoryRole = Literal["recovery", "specialist", "verifier"]
MemoryKind = Literal["analysis_claim", "host_observation", "tactic_outcome", "failure"]
JSONScalar: TypeAlias = None | bool | int | float | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]

MEMORY_ARMS = frozenset({"lane_local_v1", "typed_challenge_v1"})
MEMORY_ROLES = frozenset({"recovery", "specialist", "verifier"})
PUBLIC_RECORD_FIELDS: Mapping[str, tuple[str, ...]] = {
    "analysis_claim": (
        "kind",
        "record_id",
        "source_episode",
        "source_lane",
        "status",
        "summary",
        "evidence",
        "next_steps",
        "tool_count",
    ),
    "host_observation": (
        "kind",
        "record_id",
        "source_episode",
        "source_lane",
        "complete",
        "gap",
        "tool",
        "success",
        "source_bound",
        "facts",
    ),
    "tactic_outcome": (
        "kind",
        "record_id",
        "source_episode",
        "source_lane",
        "role",
        "tactic",
        "tool_profile",
        "status",
    ),
    "failure": (
        "record_id",
        "source_episode",
        "source_lane",
        "kind",
        "failure_kind",
        "subreason",
    ),
}

_KIND_ORDER = {
    "host_observation": 0,
    "tactic_outcome": 1,
    "failure": 2,
    "analysis_claim": 3,
}
_FAILURE_KINDS = frozenset(
    {"board", "container", "disagreement", "policy", "provenance", "quota", "timeout", "tool"}
)
_FORBIDDEN_FIELD_FRAGMENTS = (
    "authority",
    "candidate",
    "credential",
    "digest",
    "endpoint",
    "key",
    "password",
    "path",
    "receipt",
    "secret",
    "token",
)
_LOWER_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_CANDIDATE = re.compile(r"(?:INCYPHER|flag)\{[^{}\r\n]{1,512}\}", re.IGNORECASE)
_CREDENTIAL_MARKER = re.compile(
    r"(?:^|[_:=\-\s])(?:credential|password|secret|token)(?:[_:=\-\s]|$)",
    re.IGNORECASE,
)
_REJECTED = object()


def _json_copy(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _json_copy(child) for key, child in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_copy(child) for child in value]
    if value is None or type(value) in {bool, int, float, str}:
        return value
    raise TypeError("memory value is not JSON data")


def canonical_bytes(value: object) -> bytes:
    """Return protocol canonical compact JSON bytes."""
    return json.dumps(
        _json_copy(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _bounded_text(value: object, label: str, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 for character in value)
        or _unsafe_text(value, frozenset())
    ):
        raise ValueError(f"memory {label} is invalid")
    return value


def _nonnegative(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"memory {label} is invalid")
    return value


def _optional_text(value: object, label: str, *, maximum: int = 4096) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, label, maximum=maximum)


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(child) for child in value)
    return value


def _sensitive_forms(values: Iterable[str | bytes]) -> frozenset[str]:
    forms: set[str] = set()
    for value in values:
        if not isinstance(value, (str, bytes)):
            raise TypeError("memory sensitive value is invalid")
        raw = value if isinstance(value, bytes) else value.encode("utf-8")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        encoded = base64.b64encode(raw).decode("ascii")
        urlsafe = base64.urlsafe_b64encode(raw).decode("ascii")
        generated = {
            text,
            raw.hex(),
            raw.hex().upper(),
            encoded,
            encoded.rstrip("="),
            urlsafe,
            urlsafe.rstrip("="),
            urllib.parse.quote_from_bytes(raw),
            hashlib.sha256(raw).hexdigest(),
        }
        forms.update(unicodedata.normalize("NFKC", item) for item in generated if item)
    return frozenset(forms)


def _decoded_candidate(value: str) -> bool:
    payloads: list[bytes] = []
    if "%" in value:
        try:
            payloads.append(urllib.parse.unquote_to_bytes(value))
        except (UnicodeEncodeError, ValueError):
            pass
    if len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", value):
        try:
            payloads.append(bytes.fromhex(value))
        except ValueError:
            pass
    if re.fullmatch(r"[A-Za-z0-9_+/=-]+", value):
        padded = value + "=" * (-len(value) % 4)
        for altchars in (None, b"-_"):
            try:
                payloads.append(base64.b64decode(padded, altchars=altchars, validate=True))
            except (ValueError, base64.binascii.Error):
                pass
    for payload in payloads:
        try:
            decoded = unicodedata.normalize("NFKC", payload.decode("utf-8"))
        except UnicodeDecodeError:
            continue
        if _CANDIDATE.search(decoded) is not None:
            return True
    return False


def _discover_sensitive_values(
    value: object,
    *,
    active: set[int] | None = None,
    depth: int = 0,
) -> set[str]:
    """Find raw candidate and credential values before encoded siblings are sanitized."""
    if depth > 64:
        return set()
    if active is None:
        active = set()
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return set()
    if isinstance(value, str):
        normalized = unicodedata.normalize("NFKC", value)
        found = {match.group(0) for match in _CANDIDATE.finditer(normalized)}
        if _CREDENTIAL_MARKER.search(normalized) is not None:
            found.add(normalized)
        return found
    if not isinstance(value, (Mapping, Sequence)):
        return set()
    identity = id(value)
    if identity in active:
        return set()
    active.add(identity)
    found: set[str] = set()
    try:
        children: Iterable[object]
        if isinstance(value, Mapping):
            children = (*value.keys(), *value.values())
        else:
            children = value
        for child in children:
            found.update(_discover_sensitive_values(child, active=active, depth=depth + 1))
    finally:
        active.remove(identity)
    return found


def _unsafe_text(value: str, sensitive_forms: frozenset[str]) -> bool:
    normalized = unicodedata.normalize("NFKC", value)
    if (
        normalized in sensitive_forms
        or _CANDIDATE.search(normalized) is not None
        or _CREDENTIAL_MARKER.search(normalized) is not None
        or _decoded_candidate(normalized)
        or _LOWER_HEX_SHA256.fullmatch(normalized) is not None
        or normalized.startswith("/")
    ):
        return True
    try:
        return bool(urllib.parse.urlsplit(normalized).netloc)
    except ValueError:
        return True


def _sanitize(
    value: object,
    sensitive_forms: frozenset[str],
    *,
    active: set[int],
    depth: int,
) -> object:
    if depth > 64:
        return _REJECTED
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return _REJECTED
    if isinstance(value, str):
        return _REJECTED if _unsafe_text(value, sensitive_forms) else value
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        return value if math.isfinite(value) else _REJECTED
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            return _REJECTED
        active.add(identity)
        output: dict[str, JSONValue] = {}
        try:
            keys = sorted(key for key in value if isinstance(key, str))
            for key in keys:
                normalized_key = unicodedata.normalize("NFKC", key).casefold()
                if any(
                    fragment in normalized_key for fragment in _FORBIDDEN_FIELD_FRAGMENTS
                ) or _unsafe_text(key, sensitive_forms):
                    continue
                child = _sanitize(value[key], sensitive_forms, active=active, depth=depth + 1)
                if child is not _REJECTED:
                    output[key] = child  # type: ignore[assignment]
        finally:
            active.remove(identity)
        return output
    if isinstance(value, Sequence):
        identity = id(value)
        if identity in active:
            return _REJECTED
        active.add(identity)
        output_list: list[JSONValue] = []
        try:
            for item in value:
                child = _sanitize(item, sensitive_forms, active=active, depth=depth + 1)
                if child is not _REJECTED:
                    output_list.append(child)  # type: ignore[arg-type]
        finally:
            active.remove(identity)
        return output_list
    return _REJECTED


def sanitize_public_value(
    value: object,
    *,
    sensitive_values: Iterable[str | bytes] = (),
) -> JSONValue | None:
    """Recursively remove protocol-forbidden fields, elements, and scalar values."""
    explicit = tuple(sensitive_values)
    discovered = _discover_sensitive_values(value)
    sanitized = _sanitize(
        value,
        _sensitive_forms((*explicit, *discovered)),
        active=set(),
        depth=0,
    )
    return None if sanitized is _REJECTED else sanitized  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class MemoryTarget:
    run_id: str
    challenge_id: int
    episode: int
    lane: int
    role: MemoryRole

    def __post_init__(self) -> None:
        _bounded_text(self.run_id, "target run id", maximum=200)
        _nonnegative(self.challenge_id, "target challenge id")
        _nonnegative(self.episode, "target episode")
        _nonnegative(self.lane, "target lane")
        if self.role not in MEMORY_ROLES:
            raise ValueError("memory target role is invalid")


@dataclass(frozen=True, slots=True)
class _RecordScope:
    record_id: str
    run_id: str
    challenge_id: int
    source_episode: int
    source_lane: int
    source_attempt_id: str

    def __post_init__(self) -> None:
        _bounded_text(self.record_id, "record id", maximum=200)
        _bounded_text(self.run_id, "record run id", maximum=200)
        _nonnegative(self.challenge_id, "record challenge id")
        _nonnegative(self.source_episode, "record source episode")
        _nonnegative(self.source_lane, "record source lane")
        _bounded_text(self.source_attempt_id, "record source attempt id", maximum=200)


@dataclass(frozen=True, slots=True)
class AnalysisClaim(_RecordScope):
    status: str
    summary: str
    evidence: tuple[str, ...]
    next_steps: tuple[str, ...]
    tool_count: int
    kind: Literal["analysis_claim"] = field(default="analysis_claim", init=False)

    def __post_init__(self) -> None:
        super(AnalysisClaim, self).__post_init__()
        _bounded_text(self.status, "analysis status", maximum=100)
        if not isinstance(self.summary, str):
            raise TypeError("memory analysis summary is invalid")
        if any(not isinstance(item, str) for item in (*self.evidence, *self.next_steps)):
            raise TypeError("memory analysis items are invalid")
        _nonnegative(self.tool_count, "analysis tool count")
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "next_steps", tuple(self.next_steps))

    def public_record(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "record_id": self.record_id,
            "source_episode": self.source_episode,
            "source_lane": self.source_lane,
            "status": self.status,
            "summary": self.summary,
            "evidence": list(self.evidence),
            "next_steps": list(self.next_steps),
            "tool_count": self.tool_count,
        }


@dataclass(frozen=True, slots=True)
class HostObservation(_RecordScope):
    complete: bool
    gap: str | None
    tool: str
    success: bool | None
    source_bound: bool
    facts: Mapping[str, Any]
    kind: Literal["host_observation"] = field(default="host_observation", init=False)

    def __post_init__(self) -> None:
        super(HostObservation, self).__post_init__()
        if type(self.complete) is not bool or type(self.source_bound) is not bool:
            raise TypeError("memory observation flags are invalid")
        if self.success is not None and type(self.success) is not bool:
            raise TypeError("memory observation success is invalid")
        _optional_text(self.gap, "observation gap", maximum=100)
        _bounded_text(self.tool, "observation tool", maximum=100)
        if not isinstance(self.facts, Mapping):
            raise TypeError("memory observation facts are invalid")
        object.__setattr__(self, "facts", _freeze(self.facts))

    def public_record(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "record_id": self.record_id,
            "source_episode": self.source_episode,
            "source_lane": self.source_lane,
            "complete": self.complete,
            "gap": self.gap,
            "tool": self.tool,
            "success": self.success,
            "source_bound": self.source_bound,
            "facts": self.facts,
        }


@dataclass(frozen=True, slots=True)
class TacticOutcome(_RecordScope):
    role: MemoryRole
    tactic: str
    tool_profile: str
    status: str
    kind: Literal["tactic_outcome"] = field(default="tactic_outcome", init=False)

    def __post_init__(self) -> None:
        super(TacticOutcome, self).__post_init__()
        if self.role not in MEMORY_ROLES:
            raise ValueError("memory tactic role is invalid")
        _bounded_text(self.tactic, "tactic", maximum=200)
        _bounded_text(self.tool_profile, "tactic tool profile", maximum=200)
        _bounded_text(self.status, "tactic status", maximum=100)

    def public_record(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "record_id": self.record_id,
            "source_episode": self.source_episode,
            "source_lane": self.source_lane,
            "role": self.role,
            "tactic": self.tactic,
            "tool_profile": self.tool_profile,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class FailureRecord(_RecordScope):
    failure_kind: str
    subreason: str
    kind: Literal["failure"] = field(default="failure", init=False)

    def __post_init__(self) -> None:
        super(FailureRecord, self).__post_init__()
        if self.failure_kind not in _FAILURE_KINDS:
            raise ValueError("memory failure kind is invalid")
        _bounded_text(self.subreason, "failure subreason", maximum=200)

    def public_record(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "source_episode": self.source_episode,
            "source_lane": self.source_lane,
            "kind": self.kind,
            "failure_kind": self.failure_kind,
            "subreason": self.subreason,
        }


PublicMemoryRecord: TypeAlias = AnalysisClaim | HostObservation | TacticOutcome | FailureRecord


def record_order(record: PublicMemoryRecord) -> tuple[int, int, str, int, str]:
    """Protocol order independent of insertion order."""
    return (
        -record.source_episode,
        record.source_lane,
        record.source_attempt_id,
        _KIND_ORDER[record.kind],
        record.record_id,
    )


def repeated_fingerprint(public_record: Mapping[str, object]) -> str | None:
    """Return the exact per-kind deduplication key, encoded canonically."""
    kind = public_record.get("kind")
    fields = {
        "host_observation": (
            "kind",
            "complete",
            "gap",
            "tool",
            "source_bound",
            "success",
            "facts",
        ),
        "tactic_outcome": ("kind", "role", "tactic", "tool_profile", "status"),
        "failure": ("kind", "failure_kind", "subreason"),
        "analysis_claim": (
            "kind",
            "status",
            "summary",
            "evidence",
            "next_steps",
            "tool_count",
        ),
    }.get(kind)
    if fields is None or any(name not in public_record for name in fields):
        return None
    return canonical_bytes([public_record[name] for name in fields]).decode("ascii")


@dataclass(frozen=True, slots=True)
class CandidateEvidence:
    """Narrow private view of one candidate-matching source observation."""

    run_id: str
    challenge_id: int
    source_episode: int
    source_lane: int
    source_attempt_id: str
    role: MemoryRole
    recipe_kind: str
    manifest_complete: bool
    manifest_gap: str | None
    candidate_observed: bool = field(repr=False)
    candidate_supplied: bool = field(repr=False)

    def __post_init__(self) -> None:
        _bounded_text(self.run_id, "candidate evidence run id", maximum=200)
        _nonnegative(self.challenge_id, "candidate evidence challenge id")
        _nonnegative(self.source_episode, "candidate evidence source episode")
        _nonnegative(self.source_lane, "candidate evidence source lane")
        _bounded_text(self.source_attempt_id, "candidate evidence attempt id", maximum=200)
        if self.role not in MEMORY_ROLES:
            raise ValueError("memory candidate evidence role is invalid")
        _bounded_text(self.recipe_kind, "candidate evidence recipe", maximum=200)
        if (
            type(self.manifest_complete) is not bool
            or type(self.candidate_observed) is not bool
            or type(self.candidate_supplied) is not bool
        ):
            raise TypeError("memory candidate evidence status is invalid")
        _optional_text(self.manifest_gap, "candidate manifest gap", maximum=100)
        expected_recipe = (
            "fresh_source_reobservation_v1"
            if self.role == "verifier"
            else "source_bound_tool_observation_v1"
        )
        if self.recipe_kind != expected_recipe:
            raise ValueError("memory candidate evidence recipe is invalid")

    @property
    def complete(self) -> bool:
        return (
            self.manifest_complete
            and self.manifest_gap is None
            and self.candidate_observed
            and not self.candidate_supplied
        )


@dataclass(frozen=True, slots=True)
class CandidateVerification:
    """Controller-private exact verification join; candidate is never serialised."""

    run_id: str
    challenge_id: int
    producer_attempt_id: str
    verifier_attempt_id: str
    recipe_kind: str
    candidate: str = field(repr=False)
    evidence: CandidateEvidence = field(repr=False)

    def __post_init__(self) -> None:
        _bounded_text(self.run_id, "verification run id", maximum=200)
        _nonnegative(self.challenge_id, "verification challenge id")
        _bounded_text(self.producer_attempt_id, "verification producer attempt id", maximum=200)
        _bounded_text(self.verifier_attempt_id, "verification verifier attempt id", maximum=200)
        _bounded_text(self.recipe_kind, "verification recipe", maximum=200)
        if self.producer_attempt_id == self.verifier_attempt_id:
            raise ValueError("memory verification attempts are not independent")
        if not isinstance(self.candidate, str) or _CANDIDATE.fullmatch(self.candidate) is None:
            raise ValueError("memory private verification candidate is invalid")
        if not isinstance(self.evidence, CandidateEvidence):
            raise TypeError("memory verification evidence is invalid")
        if (
            self.evidence.role != "verifier"
            or self.recipe_kind != self.evidence.recipe_kind
            or self.evidence.run_id != self.run_id
            or self.evidence.challenge_id != self.challenge_id
            or self.evidence.source_attempt_id != self.verifier_attempt_id
        ):
            raise ValueError("memory verification evidence does not match")


@dataclass(frozen=True, slots=True)
class CandidateContext:
    """Controller-private producer context; candidate has no public output surface."""

    run_id: str
    challenge_id: int
    source_episode: int
    source_lane: int
    source_attempt_id: str
    role: Literal["recovery", "specialist"]
    recipe_kind: str
    candidate: str = field(repr=False)
    evidence: CandidateEvidence = field(repr=False)
    verification: CandidateVerification | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _bounded_text(self.run_id, "candidate run id", maximum=200)
        _nonnegative(self.challenge_id, "candidate challenge id")
        _nonnegative(self.source_episode, "candidate source episode")
        _nonnegative(self.source_lane, "candidate source lane")
        _bounded_text(self.source_attempt_id, "candidate source attempt id", maximum=200)
        if self.role not in {"specialist", "recovery"}:
            raise ValueError("memory candidate role is invalid")
        _bounded_text(self.recipe_kind, "candidate recipe", maximum=200)
        if not isinstance(self.candidate, str) or _CANDIDATE.fullmatch(self.candidate) is None:
            raise ValueError("memory private candidate is invalid")
        if not isinstance(self.evidence, CandidateEvidence):
            raise TypeError("memory candidate evidence is invalid")
        if (
            self.evidence.role != self.role
            or self.evidence.recipe_kind != self.recipe_kind
            or self.evidence.run_id != self.run_id
            or self.evidence.challenge_id != self.challenge_id
            or self.evidence.source_episode != self.source_episode
            or self.evidence.source_lane != self.source_lane
            or self.evidence.source_attempt_id != self.source_attempt_id
        ):
            raise ValueError("memory candidate evidence does not match")
        if self.verification is not None and not isinstance(
            self.verification, CandidateVerification
        ):
            raise TypeError("memory candidate verification is invalid")

    @property
    def complete(self) -> bool:
        return self.evidence.complete

    @property
    def verified(self) -> bool:
        verification = self.verification
        return bool(
            self.complete
            and verification is not None
            and verification.evidence.complete
            and verification.run_id == self.run_id
            and verification.challenge_id == self.challenge_id
            and verification.producer_attempt_id == self.source_attempt_id
            and verification.evidence.source_episode > self.source_episode
            and verification.candidate == self.candidate
        )


@dataclass(frozen=True, slots=True)
class CandidateMemoryAggregate:
    """Private contexts plus the only public candidate-memory surface: five counters."""

    contexts: tuple[CandidateContext, ...] = field(default=(), repr=False)
    invalid_context_count: int = 0
    rejected_context_count: int = 0

    def __post_init__(self) -> None:
        if any(not isinstance(context, CandidateContext) for context in self.contexts):
            raise TypeError("memory candidate aggregate contains an invalid context")
        _nonnegative(self.invalid_context_count, "invalid candidate context count")
        _nonnegative(self.rejected_context_count, "rejected candidate context count")
        contexts = tuple(self.contexts)
        object.__setattr__(self, "contexts", contexts)
        object.__setattr__(
            self,
            "invalid_context_count",
            self.invalid_context_count
            + sum(
                context.verification is not None and not context.verified for context in contexts
            ),
        )
        object.__setattr__(
            self,
            "rejected_context_count",
            self.rejected_context_count + sum(not context.complete for context in contexts),
        )

    @classmethod
    def from_contexts(
        cls,
        contexts: Iterable[CandidateContext],
        *,
        invalid_context_count: int = 0,
        rejected_context_count: int = 0,
    ) -> CandidateMemoryAggregate:
        return cls(tuple(contexts), invalid_context_count, rejected_context_count)

    @property
    def complete_context_count(self) -> int:
        return sum(context.complete for context in self.contexts)

    @property
    def pending_count(self) -> int:
        return sum(context.complete and context.verification is None for context in self.contexts)

    @property
    def verified_count(self) -> int:
        return sum(context.complete and context.verified for context in self.contexts)

    def public_counts(self) -> dict[str, int]:
        return {
            "complete_context_count": self.complete_context_count,
            "invalid_context_count": self.invalid_context_count,
            "rejected_context_count": self.rejected_context_count,
            "pending_count": self.pending_count,
            "verified_count": self.verified_count,
        }

    def _sensitive_values(self) -> tuple[str, ...]:
        values: list[str] = []
        for context in self.contexts:
            values.append(context.candidate)
            if context.verification is not None:
                values.append(context.verification.candidate)
        return tuple(values)


@dataclass(frozen=True, slots=True, init=False)
class MemoryProjection:
    deduplicated_record_count: int
    omitted_record_count: int
    _target: MemoryTarget = field(repr=False)
    _arm: MemoryArm = field(repr=False)
    _encoded: bytes = field(repr=False)

    @classmethod
    def _create(
        cls,
        records: Sequence[Mapping[str, JSONValue]],
        deduplicated_record_count: int,
        omitted_record_count: int,
        target: MemoryTarget,
        arm: MemoryArm,
    ) -> MemoryProjection:
        if any(
            type(value) is not int or value < 0
            for value in (deduplicated_record_count, omitted_record_count)
        ):
            raise ValueError("memory projection counts are invalid")
        if not isinstance(target, MemoryTarget) or arm not in MEMORY_ARMS:
            raise ValueError("memory projection scope is invalid")
        instance = object.__new__(cls)
        object.__setattr__(instance, "deduplicated_record_count", deduplicated_record_count)
        object.__setattr__(instance, "omitted_record_count", omitted_record_count)
        object.__setattr__(instance, "_target", target)
        object.__setattr__(instance, "_arm", arm)
        object.__setattr__(instance, "_encoded", canonical_bytes(records))
        return instance

    @property
    def target(self) -> MemoryTarget:
        return self._target

    @property
    def arm(self) -> MemoryArm:
        return self._arm

    @property
    def records(self) -> tuple[Mapping[str, JSONValue], ...]:
        return tuple(json.loads(self._encoded))

    @property
    def encoded_bytes(self) -> int:
        return len(self._encoded)

    @property
    def record_ids(self) -> tuple[str, ...]:
        return tuple(str(record["record_id"]) for record in self.records)

    def as_public(self) -> list[dict[str, JSONValue]]:
        return json.loads(self._encoded)

    def canonical_bytes(self) -> bytes:
        return self._encoded


def _in_scope(record: PublicMemoryRecord, target: MemoryTarget, arm: MemoryArm) -> bool:
    if (
        record.run_id != target.run_id
        or record.challenge_id != target.challenge_id
        or record.source_episode >= target.episode
    ):
        return False
    if record.source_lane == target.lane:
        return True
    return arm == "typed_challenge_v1" and record.kind != "analysis_claim"


def project_memory(
    records: Iterable[PublicMemoryRecord],
    target: MemoryTarget,
    *,
    arm: MemoryArm = "typed_challenge_v1",
    candidate_memory: CandidateMemoryAggregate | None = None,
    sensitive_values: Iterable[str | bytes] = (),
    projection_bytes: int = PROJECTION_BYTES,
) -> MemoryProjection:
    """Build the deterministic public projection for one target engagement."""
    if not isinstance(target, MemoryTarget):
        raise TypeError("memory target is invalid")
    if arm not in MEMORY_ARMS:
        raise ValueError("memory arm is invalid")
    if (
        type(projection_bytes) is not int
        or projection_bytes < 2
        or projection_bytes > PROJECTION_BYTES
    ):
        raise ValueError("memory projection byte budget is invalid")
    if candidate_memory is not None and not isinstance(candidate_memory, CandidateMemoryAggregate):
        raise TypeError("memory private aggregate is invalid")
    if target.role == "verifier":
        return MemoryProjection._create((), 0, 0, target, arm)

    materialized = tuple(records)
    if any(
        not isinstance(record, (AnalysisClaim, HostObservation, TacticOutcome, FailureRecord))
        for record in materialized
    ):
        raise TypeError("memory records contain an invalid type")
    raw_public = tuple(record.public_record() for record in materialized)
    private_values = candidate_memory._sensitive_values() if candidate_memory is not None else ()
    discovered: set[str] = set()
    for public_record in raw_public:
        discovered.update(_discover_sensitive_values(public_record))
    forms = _sensitive_forms((*private_values, *tuple(sensitive_values), *discovered))

    eligible: list[tuple[PublicMemoryRecord, dict[str, JSONValue]]] = []
    public_by_identity = {id(record): public for record, public in zip(materialized, raw_public)}
    for record in sorted(materialized, key=record_order):
        if not _in_scope(record, target, arm):
            continue
        sanitized = _sanitize(public_by_identity[id(record)], forms, active=set(), depth=0)
        if not isinstance(sanitized, dict):
            continue
        if record.kind == "analysis_claim" and "summary" not in sanitized:
            sanitized["summary"] = ""
        eligible.append((record, sanitized))

    unique: list[dict[str, JSONValue]] = []
    seen: set[str] = set()
    deduplicated = 0
    for _, public_record in eligible:
        fingerprint = repeated_fingerprint(public_record)
        if fingerprint is not None and fingerprint in seen:
            deduplicated += 1
            continue
        if fingerprint is not None:
            seen.add(fingerprint)
        unique.append(public_record)

    selected: list[Mapping[str, JSONValue]] = []
    omitted = 0
    for index, public_record in enumerate(unique):
        proposed = [*selected, public_record]
        if len(canonical_bytes(proposed)) > projection_bytes:
            omitted = len(unique) - index
            break
        selected.append(public_record)
    return MemoryProjection._create(selected, deduplicated, omitted, target, arm)


__all__ = [
    "MEMORY_ARMS",
    "MEMORY_ROLES",
    "PROJECTION_BYTES",
    "PROTOCOL_SHA256",
    "PUBLIC_RECORD_FIELDS",
    "AnalysisClaim",
    "CandidateContext",
    "CandidateEvidence",
    "CandidateMemoryAggregate",
    "CandidateVerification",
    "FailureRecord",
    "HostObservation",
    "MemoryArm",
    "MemoryProjection",
    "MemoryRole",
    "MemoryTarget",
    "PublicMemoryRecord",
    "TacticOutcome",
    "canonical_bytes",
    "project_memory",
    "record_order",
    "repeated_fingerprint",
    "sanitize_public_value",
]
