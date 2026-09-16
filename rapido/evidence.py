"""Run-scoped, immutable, content-addressed host evidence.

This module deliberately has no orchestration or tool-registry dependency.  The
caller supplies already host-observed tool results, and later integration can
place that call immediately after bounded tool dispatch.  Model prose is never
an evidence input.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sqlite3
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, TypeAlias

from .board import FLAG_RE
from .state import StateStore

_SCHEMA_VERSION = 3
_OBJECT_DOMAIN = b"rapido-host-evidence-object-v1\0"
_MANIFEST_DOMAIN = b"rapido-host-evidence-manifest-v1\0"
_CONFIG_DOMAIN = b"rapido-host-evidence-config-v1\0"
_TARGET_PAYLOAD_DOMAIN_LABEL = "rapido-target-response-payload-v1"
_TARGET_PAYLOAD_DOMAIN = _TARGET_PAYLOAD_DOMAIN_LABEL.encode() + b"\0"
_MANIFEST_DOCUMENT_KEYS = frozenset(
    {
        "attempt_id",
        "candidate_sensitive",
        "challenge_id",
        "committed_count",
        "complete",
        "episode",
        "gap",
        "item_bytes",
        "items",
        "lane",
        "observation_count",
        "omissions",
        "omitted_count",
        "run_id",
        "schema_version",
    }
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DIGEST_VALUE = re.compile(r"[0-9a-fA-F]{32,128}")
_TOKEN = re.compile(r"[A-Za-z0-9_.:+-]{1,96}")
_TOOL = re.compile(r"[a-z0-9_]{1,96}")
_MAX_HOST_RESULT_BYTES = 128 * 1024
_MAX_BATCH_OBSERVATIONS = 1_000

_GAPS = frozenset(
    {
        "process_interrupted",
        "turn_timeout",
        "turn_no_progress",
        "turn_cancelled",
        "turn_failed",
        "provenance_incomplete",
        "quota_omitted",
        "legacy_unavailable",
    }
)

_PATH_KEYS = frozenset({"path", "destination", "member", "filename", "cwd"})
_INTEGER_KEYS = frozenset(
    {
        "bits",
        "bytes",
        "channels",
        "count",
        "entry_count",
        "frame_count",
        "height",
        "index",
        "length",
        "machine",
        "offset",
        "page_count",
        "sample_rate",
        "samples",
        "size",
        "width",
    }
)
_BOOLEAN_KEYS = frozenset(
    {
        "complete",
        "dynamic",
        "eof",
        "executable",
        "limited",
        "linked",
        "partial",
        "readable",
        "signed",
        "slow",
        "supported",
        "timed_out",
        "truncated",
        "unsafe",
        "writable",
    }
)
_TOKEN_KEYS = frozenset(
    {
        "action",
        "address",
        "architecture",
        "byte_order",
        "command",
        "compression",
        "coverage",
        "decoder",
        "endianness",
        "encoding",
        "format",
        "inspector",
        "kind",
        "library",
        "mnemonic",
        "mode",
        "name",
        "operation",
        "protocol",
        "status",
        "stop_reason",
        "symbol",
        "type",
        "view",
    }
)
_TOKEN_LIST_KEYS = frozenset({"addresses", "libraries", "mnemonics", "names", "symbols"})
_CONTAINER_KEYS = frozenset(
    {
        "channels",
        "entries",
        "exports",
        "fields",
        "imports",
        "instructions",
        "libraries",
        "metadata",
        "pages",
        "pixel_signals",
        "records",
        "regions",
        "sections",
        "segments",
        "statistics",
        "streams",
        "symbols",
        "tables",
        "tags",
    }
)
_HASH_KEYS = frozenset(
    {
        "sha256",
        "source_sha256",
        "source_range_sha256",
        "payload_sha256",
    }
)
_RAW_DIGEST_KEYS = frozenset(
    {
        "body",
        "content",
        "data",
        "data_base64",
        "decoded",
        "matches",
        "output",
        "result",
        "strings",
        "text",
        "value",
    }
)
_NEVER_RETAIN_KEYS = frozenset(
    {
        "authority",
        "candidate",
        "connection_info",
        "credential",
        "endpoint",
        "headers",
        "host",
        "password",
        "secret",
        "token",
        "transcript",
        "url",
    }
)
_SENSITIVE_TEXT = re.compile(
    r"(?:secret|credential|password|bearer|authorization|api[_-]?key|team[_-]?key|"
    r"https?://|tcp://|(?:^|\s)/(?:[^\s/]+/)+[^\s]*)",
    re.IGNORECASE,
)

_METADATA_TOOLS = frozenset(
    {
        "audio_metadata",
        "dicom_metadata",
        "disassemble_elf",
        "elf_symbols",
        "image_metadata",
        "inspect_artifact",
        "inspect_binary",
        "inspect_elf",
        "inspect_file",
        "inspect_filesystem",
        "list_tar",
        "list_workspace",
        "list_zip",
        "search_text",
        "wav_analyze",
    }
)
_DERIVATION_TOOLS = frozenset(
    {
        "compute_exact",
        "decode_base64",
        "decode_hex",
        "decode_url",
        "decompress_gzip",
        "derive_artifact",
        "extract_archive",
        "extract_strings",
        "read_bytes",
        "read_text",
    }
)
_TARGET_TOOLS = frozenset({"http_request", "target_info", "tcp_close", "tcp_exchange", "tcp_open"})
_KNOWN_TOOLS = _METADATA_TOOLS | _DERIVATION_TOOLS | _TARGET_TOOLS


class EvidenceError(RuntimeError):
    """Base error for durable evidence operations."""


class EvidenceConflictError(EvidenceError):
    """An immutable identity was recommitted with different content."""


class EvidenceTamperError(EvidenceError):
    """Stored content failed canonical, digest, or relational verification."""


CanonicalScalar: TypeAlias = None | bool | int | str
CanonicalValue: TypeAlias = (
    CanonicalScalar
    | Mapping[str, "CanonicalValue"]
    | tuple["CanonicalValue", ...]
    | list["CanonicalValue"]
)


@dataclass(frozen=True)
class EvidenceLimits:
    max_observations: int = 100
    max_object_bytes: int = 16 * 1024
    max_attempt_bytes: int = 512 * 1024
    max_carry_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        for name, value in (
            ("max_observations", self.max_observations),
            ("max_object_bytes", self.max_object_bytes),
            ("max_attempt_bytes", self.max_attempt_bytes),
            ("max_carry_bytes", self.max_carry_bytes),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_observations > 100:
            raise ValueError("max_observations exceeds 100")
        if self.max_object_bytes > 16 * 1024:
            raise ValueError("max_object_bytes exceeds 16 KiB")
        if self.max_attempt_bytes > 512 * 1024:
            raise ValueError("max_attempt_bytes exceeds 512 KiB")
        if self.max_carry_bytes > 64 * 1024:
            raise ValueError("max_carry_bytes exceeds 64 KiB")

    def as_dict(self) -> dict[str, int]:
        return {
            "max_attempt_bytes": self.max_attempt_bytes,
            "max_carry_bytes": self.max_carry_bytes,
            "max_object_bytes": self.max_object_bytes,
            "max_observations": self.max_observations,
        }


def _valid_text(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def _freeze_json(value: Any, *, depth: int = 0) -> Any:
    if depth > 32:
        raise ValueError("host observation exceeds the nesting limit")
    if value is None or type(value) in {bool, int}:
        return value
    if isinstance(value, float):
        raise TypeError("host observation floats are not canonical evidence")
    if isinstance(value, str):
        if not _valid_text(value):
            raise ValueError("host observation contains invalid Unicode")
        return value
    if isinstance(value, Mapping):
        if len(value) > 512 or any(not isinstance(key, str) for key in value):
            raise ValueError("host observation contains invalid object keys")
        return MappingProxyType(
            {key: _freeze_json(child, depth=depth + 1) for key, child in value.items()}
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > 2_000:
            raise ValueError("host observation contains an oversized sequence")
        return tuple(_freeze_json(child, depth=depth + 1) for child in value)
    raise ValueError("host observation is not strict JSON data")


_OMIT_MEMORY_VALUE = object()


def _digest_free_memory_value(value: Any, *, depth: int = 0) -> Any:
    """Remove digest-bearing fields and values from the public memory seam."""
    if depth > 32:
        raise ValueError("memory observation exceeds the nesting limit")
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for key, child in value.items():
            lowered = key.lower()
            if re.search(
                r"(?:^|_)(?:sha(?:1|224|256|384|512)|hash(?:es)?|digest|checksum)(?:_|$)",
                lowered,
            ):
                continue
            projected = _digest_free_memory_value(child, depth=depth + 1)
            if projected is not _OMIT_MEMORY_VALUE:
                cleaned[key] = projected
        return cleaned
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        cleaned_items = []
        for child in value:
            projected = _digest_free_memory_value(child, depth=depth + 1)
            if projected is not _OMIT_MEMORY_VALUE:
                cleaned_items.append(projected)
        return cleaned_items
    if isinstance(value, str) and _DIGEST_VALUE.fullmatch(value):
        return _OMIT_MEMORY_VALUE
    return value


def _canonical_value(value: Any) -> Any:
    if value is None or type(value) in {bool, int, str}:
        return value
    if isinstance(value, float):
        raise TypeError("floats are not canonical evidence")
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) or not _valid_text(key) for key in value):
            raise ValueError("canonical evidence keys must be valid strings")
        return {key: _canonical_value(value[key]) for key in sorted(value)}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_canonical_value(child) for child in value]
    raise ValueError("value is not canonical evidence data")


def _canonical_bytes(value: Any) -> bytes:
    encoded = json.dumps(
        _canonical_value(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return encoded.encode("utf-8")


def _digest(domain: bytes, payload: bytes) -> str:
    return hashlib.sha256(domain + payload).hexdigest()


@dataclass(frozen=True)
class HostObservation:
    """One host-produced tool result; never model prose or a raw transcript."""

    tool: str
    success: bool | None
    source_bound: bool
    facts: Mapping[str, CanonicalValue] = field(default_factory=lambda: MappingProxyType({}))
    candidate_sha256s: tuple[str, ...] = ()
    supplied_candidate_sha256s: tuple[str, ...] = ()
    candidate_sensitive: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.tool, str) or _TOOL.fullmatch(self.tool) is None:
            raise ValueError("host observation tool name is invalid")
        if self.success is not None and type(self.success) is not bool:
            raise ValueError("host observation success must be boolean or null")
        if type(self.source_bound) is not bool:
            raise ValueError("host observation source_bound must be boolean")
        if type(self.candidate_sensitive) is not bool:
            raise ValueError("host observation candidate sensitivity must be boolean")
        if not isinstance(self.facts, Mapping):
            raise TypeError("host observation facts must be a mapping")
        frozen = _freeze_json(self.facts)
        if len(_canonical_bytes(frozen)) > _MAX_HOST_RESULT_BYTES:
            raise ValueError("host observation facts exceed the bounded result limit")
        for name, hashes in (
            ("candidate_sha256s", self.candidate_sha256s),
            ("supplied_candidate_sha256s", self.supplied_candidate_sha256s),
        ):
            if (
                isinstance(hashes, (str, bytes))
                or len(hashes) > 20
                or any(
                    not isinstance(value, str) or _SHA256.fullmatch(value) is None
                    for value in hashes
                )
            ):
                raise ValueError(f"{name} must contain at most 20 lowercase SHA-256 digests")
            object.__setattr__(self, name, tuple(hashes))
        object.__setattr__(
            self,
            "candidate_sensitive",
            self.candidate_sensitive
            or bool(self.candidate_sha256s)
            or bool(self.supplied_candidate_sha256s),
        )
        object.__setattr__(self, "facts", frozen)


@dataclass(frozen=True)
class EvidenceBatch:
    observations: tuple[HostObservation, ...] = ()
    complete: bool = True
    gap: str | None = None

    def __post_init__(self) -> None:
        if type(self.complete) is not bool:
            raise ValueError("evidence batch completeness must be boolean")
        if self.complete and self.gap is not None:
            raise ValueError("complete evidence batch cannot have a gap")
        if not self.complete and self.gap not in _GAPS:
            raise ValueError("incomplete evidence batch requires one closed gap")
        if isinstance(self.observations, (str, bytes)):
            raise TypeError("evidence batch observations must be typed observations")
        observations = tuple(self.observations)
        if len(observations) > _MAX_BATCH_OBSERVATIONS or any(
            not isinstance(item, HostObservation) for item in observations
        ):
            raise ValueError("evidence batch observations are invalid or unbounded")
        object.__setattr__(self, "observations", observations)


def _strip_payload_digests(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _strip_payload_digests(child)
            for key, child in value.items()
            if isinstance(key, str)
            and key.lower() != "hashes"
            and "digest" not in key.lower()
            and not key.lower().endswith("sha256")
        }
    if isinstance(value, list):
        return [_strip_payload_digests(child) for child in value]
    return value


@dataclass(frozen=True)
class EvidenceItem:
    ordinal: int
    digest: str
    tool: str
    byte_count: int
    payload_json: str
    carry_redact_digests: bool = False

    def _is_candidate_sensitive(self) -> bool:
        return json.loads(self.payload_json).get("candidate_sensitive") is True

    def as_dict(self) -> dict[str, Any]:
        payload = json.loads(self.payload_json)
        payload.pop("candidate_sha256s", None)
        payload.pop("supplied_candidate_sha256s", None)
        payload.pop("candidate_sensitive", None)
        if self.carry_redact_digests:
            payload = _strip_payload_digests(payload)
        public = {
            "byte_count": self.byte_count,
            "ordinal": self.ordinal,
            "payload": payload,
            "tool": self.tool,
        }
        if not self.carry_redact_digests:
            public["digest"] = self.digest
        return public


@dataclass(frozen=True)
class MemoryEvidenceObservation:
    """Digest-free typed host observation for the memory projector."""

    ordinal: int
    tool: str
    success: bool | None
    source_bound: bool
    facts: Mapping[str, CanonicalValue]


@dataclass(frozen=True)
class MemoryEvidenceSource:
    """Narrow verified evidence view; candidate identity stays a private boolean join."""

    run_id: str
    attempt_id: str
    challenge_id: int
    episode: int
    lane: int
    complete: bool
    gap: str | None
    observations: tuple[MemoryEvidenceObservation, ...]
    candidate_observed: bool
    candidate_supplied: bool


@dataclass(frozen=True)
class EvidenceManifest:
    run_id: str
    attempt_id: str
    digest: str
    challenge_id: int
    episode: int
    lane: int
    complete: bool
    gap: str | None
    observation_count: int
    committed_count: int
    omitted_count: int
    item_bytes: int
    omissions: tuple[tuple[str, int], ...]
    items: tuple[EvidenceItem, ...]
    candidate_sensitive: bool = False
    carry_omitted_items: int = 0
    carry_redact_digests: bool = False

    def as_dict(self) -> dict[str, Any]:
        public = {
            "attempt_id": self.attempt_id,
            "challenge_id": self.challenge_id,
            "committed_count": self.committed_count,
            "complete": self.complete,
            "gap": self.gap,
            "episode": self.episode,
            "item_bytes": self.item_bytes,
            "items": [item.as_dict() for item in self.items],
            "lane": self.lane,
            "observation_count": self.observation_count,
            "omissions": dict(self.omissions),
            "omitted_count": self.omitted_count,
            "carry_omitted_items": self.carry_omitted_items,
        }
        if not self.carry_redact_digests:
            public["digest"] = self.digest
        return public


@dataclass(frozen=True)
class EvidenceBundle:
    run_id: str
    challenge_id: int
    lane: int
    before_episode: int
    manifests: tuple[EvidenceManifest, ...]
    omitted_manifests: int
    omitted_items: int
    encoded_bytes: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "before_episode": self.before_episode,
            "challenge_id": self.challenge_id,
            "encoded_bytes": self.encoded_bytes,
            "lane": self.lane,
            "manifests": [manifest.as_dict() for manifest in self.manifests],
            "omitted_items": self.omitted_items,
            "omitted_manifests": self.omitted_manifests,
            "run_id": self.run_id,
        }


def _raw_digest(value: Any) -> tuple[str, int] | None:
    try:
        encoded = _canonical_bytes(value)
    except (TypeError, ValueError, UnicodeError):
        return None
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def _safe_token(value: object) -> str | None:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None or not _valid_text(value):
        return None
    normalized = unicodedata.normalize("NFKC", value)
    if FLAG_RE.search(normalized) or _SENSITIVE_TEXT.search(normalized):
        return None
    if value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", value):
        return None
    return value


def _safe_label(value: object) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 160 or not _valid_text(value):
        return None
    normalized = unicodedata.normalize("NFKC", value)
    if normalized != value or FLAG_RE.search(normalized) or _SENSITIVE_TEXT.search(normalized):
        return None
    if re.fullmatch(r"[A-Za-z0-9_.:+,; -]+", value) is None:
        return None
    return value


def _safe_structural_label(value: object) -> str | None:
    return _safe_token(value) or _safe_label(value)


def _recursive_facts(value: Any, *, depth: int = 0) -> Any | None:
    """Conservatively retain typed metadata, never paths or raw result material."""
    if depth > 8:
        return None
    if isinstance(value, Mapping):
        projected: dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str) or re.fullmatch(r"[A-Za-z0-9_]{1,64}", key) is None:
                continue
            lowered = key.lower()
            child = value[key]
            if lowered in _NEVER_RETAIN_KEYS or lowered in _PATH_KEYS:
                continue
            if lowered in _RAW_DIGEST_KEYS:
                digest = _raw_digest(child)
                if digest is not None:
                    projected[f"{lowered}_sha256"] = digest[0]
                    projected[f"{lowered}_bytes"] = digest[1]
                continue
            if (
                (
                    lowered in _INTEGER_KEYS
                    or lowered.endswith(("_bytes", "_count", "_length", "_offset", "_port"))
                )
                and type(child) is int
                and child >= 0
            ):
                projected[lowered] = child
                continue
            if lowered == "returncode" and type(child) is int:
                projected[lowered] = child
                continue
            if lowered in _BOOLEAN_KEYS and type(child) is bool:
                projected[lowered] = child
                continue
            if lowered in _TOKEN_KEYS or lowered.endswith(
                ("_address", "_encoding", "_format", "_kind", "_name", "_reason", "_type")
            ):
                token = _safe_structural_label(child)
                if token is not None:
                    projected[lowered] = token
                continue
            if (
                (lowered in _HASH_KEYS or lowered.endswith("_sha256"))
                and isinstance(child, str)
                and _SHA256.fullmatch(child)
            ):
                projected[lowered] = child
                continue
            if lowered == "hashes" and isinstance(child, Mapping):
                hashes = {
                    name: digest
                    for name, digest in sorted(child.items())
                    if isinstance(name, str)
                    and _TOKEN.fullmatch(name)
                    and isinstance(digest, str)
                    and re.fullmatch(r"[0-9a-f]{32,128}", digest)
                }
                if hashes:
                    projected["hashes"] = hashes
                continue
            if (
                lowered in _TOKEN_LIST_KEYS
                and isinstance(child, Sequence)
                and not isinstance(child, (str, bytes, bytearray))
            ):
                labels = [
                    label
                    for item in child[:64]
                    if (label := _safe_structural_label(item)) is not None
                ]
                if labels:
                    projected[lowered] = labels
                    continue
            if (
                lowered in _CONTAINER_KEYS
                and isinstance(child, (Mapping, Sequence))
                and not isinstance(child, (str, bytes, bytearray))
            ):
                nested = _recursive_facts(child, depth=depth + 1)
                if nested not in (None, {}, []):
                    projected[lowered] = nested
        return projected
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        projected_items = []
        for child in value[:64]:
            projected = _recursive_facts(child, depth=depth + 1)
            if projected not in (None, {}, []):
                projected_items.append(projected)
        return projected_items
    if type(value) is bool:
        return value
    if type(value) is int and value >= 0:
        return value
    return None


def _metadata_facts(result: Mapping[str, Any]) -> dict[str, Any]:
    """Unwrap exactly one structural result container; nested raw data stays opaque."""
    top = _recursive_facts({key: value for key, value in result.items() if key != "data"})
    projected = top if isinstance(top, dict) else {}
    data = result.get("data")
    if isinstance(data, (Mapping, Sequence)) and not isinstance(data, (str, bytes, bytearray)):
        nested = _recursive_facts(data, depth=1)
        if nested not in (None, {}, []):
            projected["data"] = nested
    return projected


def _safe_shape_field(value: object) -> str | None:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", value) is None:
        return None
    lowered = value.lower()
    if lowered in _NEVER_RETAIN_KEYS or lowered in _PATH_KEYS:
        return None
    return lowered


def _payload_shape(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        fields = sorted({field for key in value if (field := _safe_shape_field(key)) is not None})[
            :64
        ]
        return {"field_count": len(value), "fields": fields, "kind": "object"}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return {"item_count": len(value), "kind": "array"}
    if value is None:
        return {"kind": "null"}
    if type(value) is bool:
        return {"kind": "boolean"}
    if type(value) is int:
        return {"kind": "integer"}
    if isinstance(value, str):
        return {"kind": "string"}
    return {"kind": "bytes"}


def _validated_payload_shape(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) - {
        "field_count",
        "fields",
        "item_count",
        "kind",
    }:
        return None
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in {
        "array",
        "boolean",
        "bytes",
        "integer",
        "null",
        "object",
        "string",
        "text",
    }:
        return None
    shape: dict[str, Any] = {"kind": kind}
    if kind == "object":
        count = value.get("field_count")
        fields = value.get("fields")
        if (
            type(count) is not int
            or count < 0
            or not isinstance(fields, Sequence)
            or isinstance(fields, (str, bytes, bytearray))
        ):
            return None
        safe_fields = [_safe_shape_field(field) for field in fields]
        if any(field is None for field in safe_fields) or list(fields) != sorted(set(fields)):
            return None
        shape.update({"field_count": count, "fields": list(fields)})
    elif kind == "array":
        count = value.get("item_count")
        if type(count) is not int or count < 0:
            return None
        shape["item_count"] = count
    elif len(value) != 1:
        return None
    return shape


def _target_payload(result: Mapping[str, Any]) -> tuple[bytes, str, dict[str, Any]] | None:
    if isinstance(result.get("text"), str):
        text = result["text"]
        if not _valid_text(text):
            return None
        payload = text.encode()
        try:
            decoded = json.loads(text)
        except (ValueError, RecursionError):
            shape = {"kind": "text"}
        else:
            shape = _payload_shape(decoded)
        return payload, "utf8", shape
    encoded = result.get("data_base64")
    if isinstance(encoded, str):
        try:
            payload = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError, UnicodeError):
            return None
        return payload, "base64-decoded", {"kind": "bytes"}
    for name in ("body", "content", "data", "output", "result"):
        if name not in result:
            continue
        value = result[name]
        if isinstance(value, str) and _valid_text(value):
            return value.encode(), "utf8", {"kind": "text"}
        try:
            payload = _canonical_bytes(value)
        except (TypeError, ValueError, UnicodeError):
            return None
        return payload, "canonical-json", _payload_shape(value)
    return None


def _target_metadata(result: Mapping[str, Any]) -> dict[str, Any]:
    """Retain target outcome/shape and a domain-bound payload fingerprint, never payload."""
    projected: dict[str, Any] = {}
    for key in sorted(key for key in result if isinstance(key, str)):
        lowered = key.lower()
        value = result[key]
        if lowered in _NEVER_RETAIN_KEYS or lowered in _PATH_KEYS:
            continue
        if (
            (
                lowered in _INTEGER_KEYS
                or lowered == "status"
                or lowered.endswith(("_bytes", "_count", "_index", "_length"))
            )
            and type(value) is int
            and value >= 0
            or lowered in _BOOLEAN_KEYS
            and type(value) is bool
        ):
            projected[lowered] = value
        elif lowered in {"encoding", "status", "type"}:
            token = _safe_token(value)
            if token is not None:
                projected[lowered] = token
        elif (
            lowered == "payload_sha256"
            and isinstance(value, str)
            and _SHA256.fullmatch(value)
            or lowered == "payload_digest_domain"
            and value == _TARGET_PAYLOAD_DOMAIN_LABEL
            or lowered == "payload_representation"
            and isinstance(value, str)
            and value in {"base64-decoded", "canonical-json", "utf8"}
        ):
            projected[lowered] = value
        elif lowered == "payload_shape":
            shape = _validated_payload_shape(value)
            if shape is not None:
                projected[lowered] = shape
        elif (
            lowered == "response_fields"
            and isinstance(value, Sequence)
            and not isinstance(value, (str, bytes, bytearray))
        ):
            fields = [_safe_shape_field(field) for field in value]
            if not any(field is None for field in fields) and list(value) == sorted(set(value)):
                projected[lowered] = list(value)

    if "response_fields" not in projected:
        response_fields = sorted(
            {field for key in result if (field := _safe_shape_field(key)) is not None}
        )[:64]
        if response_fields:
            projected["response_fields"] = response_fields

    fingerprint = _target_payload(result)
    if fingerprint is not None:
        payload, representation, shape = fingerprint
        projected.update(
            {
                "payload_bytes": len(payload),
                "payload_digest_domain": _TARGET_PAYLOAD_DOMAIN_LABEL,
                "payload_representation": representation,
                "payload_sha256": _digest(_TARGET_PAYLOAD_DOMAIN, payload),
                "payload_shape": shape,
            }
        )
    return projected


def _contains_candidate(value: Any) -> bool:
    strings: list[str] = []

    def visit(child: Any) -> None:
        if isinstance(child, str):
            strings.append(child)
        elif isinstance(child, Mapping):
            for key in sorted(child):
                visit(child[key])
        elif isinstance(child, Sequence) and not isinstance(child, (str, bytes, bytearray)):
            for item in child:
                visit(item)

    visit(value)
    return FLAG_RE.search(unicodedata.normalize("NFKC", "".join(strings))) is not None


def _facts_for_tool(tool: str, facts: Mapping[str, Any]) -> dict[str, Any]:
    if tool == "unknown_tool":
        return {}
    if tool in _TARGET_TOOLS:
        return _target_metadata(facts)
    if tool in _METADATA_TOOLS:
        return _metadata_facts(facts)
    projected = _recursive_facts(facts)
    return projected if isinstance(projected, dict) else {}


def _validated_facts(observation: HostObservation) -> dict[str, Any]:
    canonical_tool = observation.tool if observation.tool in _KNOWN_TOOLS else "unknown_tool"
    facts = _facts_for_tool(canonical_tool, observation.facts)
    if _contains_candidate(facts):
        return {}
    return facts


def project_tool_observation(
    name: str,
    *,
    success: bool | None,
    source_bound: bool,
    result: Mapping[str, Any] | None = None,
    candidate_sha256s: tuple[str, ...] = (),
    supplied_candidate_sha256s: tuple[str, ...] = (),
    candidate_sensitive: bool = False,
) -> HostObservation:
    """Project one dispatcher result into the closed durable HostObservation seam."""
    if not isinstance(name, str) or _TOOL.fullmatch(name) is None:
        raise ValueError("tool name is invalid")
    if success is not None and type(success) is not bool:
        raise ValueError("success must be boolean or null")
    if type(source_bound) is not bool:
        raise ValueError("source_bound must be boolean")
    if result is not None and not isinstance(result, Mapping):
        raise ValueError("tool result must be a mapping or null")
    canonical_tool = name if name in _KNOWN_TOOLS else "unknown_tool"
    facts: dict[str, Any] = {}
    if success is True and source_bound and result is not None:
        if canonical_tool in _TARGET_TOOLS:
            facts = _target_metadata(result)
        elif canonical_tool in _METADATA_TOOLS:
            facts = _metadata_facts(result)
            if _contains_candidate(facts):
                facts = {}
        elif canonical_tool in _DERIVATION_TOOLS:
            projected = _recursive_facts(result)
            facts = projected if isinstance(projected, dict) else {}
            if _contains_candidate(facts):
                facts = {}
    return HostObservation(
        tool=canonical_tool,
        success=success,
        source_bound=source_bound,
        facts=facts,
        candidate_sha256s=candidate_sha256s,
        supplied_candidate_sha256s=supplied_candidate_sha256s,
        candidate_sensitive=candidate_sensitive,
    )


def _project_observation(observation: HostObservation) -> tuple[str, bytes]:
    canonical_tool = observation.tool if observation.tool in _KNOWN_TOOLS else "unknown_tool"
    payload: dict[str, Any] = {
        "candidate_sha256s": list(observation.candidate_sha256s),
        "candidate_sensitive": observation.candidate_sensitive,
        "facts": {},
        "schema_version": _SCHEMA_VERSION,
        "source_bound": observation.source_bound,
        "supplied_candidate_sha256s": list(observation.supplied_candidate_sha256s),
        "success": observation.success,
        "tool": canonical_tool,
    }
    if observation.success is True and observation.source_bound:
        payload["facts"] = _validated_facts(observation)
    encoded = _canonical_bytes(payload)
    return canonical_tool, encoded


_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS evidence_schema (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL
);
INSERT OR IGNORE INTO evidence_schema(singleton, schema_version) VALUES (1, {_SCHEMA_VERSION});
CREATE TABLE IF NOT EXISTS evidence_runs (
    run_id TEXT PRIMARY KEY REFERENCES runs(id),
    schema_version INTEGER NOT NULL,
    limits_digest TEXT NOT NULL,
    limits_json BLOB NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_objects (
    run_id TEXT NOT NULL REFERENCES evidence_runs(run_id),
    digest TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    tool TEXT NOT NULL,
    byte_count INTEGER NOT NULL,
    payload_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(run_id, digest)
);
CREATE TABLE IF NOT EXISTS evidence_manifests (
    run_id TEXT NOT NULL REFERENCES evidence_runs(run_id),
    attempt_id TEXT NOT NULL REFERENCES attempts(id),
    digest TEXT NOT NULL,
    challenge_id INTEGER NOT NULL,
    episode INTEGER NOT NULL,
    lane INTEGER NOT NULL,
    complete INTEGER NOT NULL,
    gap TEXT,
    observation_count INTEGER NOT NULL,
    committed_count INTEGER NOT NULL,
    omitted_count INTEGER NOT NULL,
    item_bytes INTEGER NOT NULL,
    payload_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(run_id, attempt_id),
    UNIQUE(run_id, digest)
);
CREATE TABLE IF NOT EXISTS evidence_items (
    run_id TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    object_digest TEXT NOT NULL,
    PRIMARY KEY(run_id, manifest_digest, ordinal),
    FOREIGN KEY(run_id, manifest_digest) REFERENCES evidence_manifests(run_id, digest),
    FOREIGN KEY(run_id, object_digest) REFERENCES evidence_objects(run_id, digest)
);
CREATE TRIGGER IF NOT EXISTS evidence_schema_no_update
BEFORE UPDATE ON evidence_schema BEGIN SELECT RAISE(ABORT, 'evidence rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_schema_no_delete
BEFORE DELETE ON evidence_schema BEGIN SELECT RAISE(ABORT, 'evidence rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_runs_no_update
BEFORE UPDATE ON evidence_runs BEGIN SELECT RAISE(ABORT, 'evidence rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_runs_no_delete
BEFORE DELETE ON evidence_runs BEGIN SELECT RAISE(ABORT, 'evidence rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_objects_no_update
BEFORE UPDATE ON evidence_objects BEGIN SELECT RAISE(ABORT, 'evidence rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_objects_no_delete
BEFORE DELETE ON evidence_objects BEGIN SELECT RAISE(ABORT, 'evidence rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_manifests_no_update
BEFORE UPDATE ON evidence_manifests BEGIN SELECT RAISE(ABORT, 'evidence rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_manifests_no_delete
BEFORE DELETE ON evidence_manifests BEGIN SELECT RAISE(ABORT, 'evidence rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_items_no_update
BEFORE UPDATE ON evidence_items BEGIN SELECT RAISE(ABORT, 'evidence rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_items_no_delete
BEFORE DELETE ON evidence_items BEGIN SELECT RAISE(ABORT, 'evidence rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_manifests_attempt_identity
BEFORE INSERT ON evidence_manifests
WHEN NOT EXISTS (
    SELECT 1 FROM attempts
    WHERE id=NEW.attempt_id
      AND run_id=NEW.run_id
      AND challenge_id=NEW.challenge_id
      AND episode=NEW.episode
      AND lane=NEW.lane
)
BEGIN SELECT RAISE(ABORT, 'evidence attempt identity mismatch'); END;
CREATE TRIGGER IF NOT EXISTS evidence_attempt_identity_no_update
BEFORE UPDATE OF run_id, challenge_id, episode, lane ON attempts
WHEN EXISTS (
    SELECT 1 FROM evidence_manifests
    WHERE attempt_id=OLD.id AND run_id=OLD.run_id
)
AND (
    NEW.run_id!=OLD.run_id
    OR NEW.challenge_id!=OLD.challenge_id
    OR NEW.episode!=OLD.episode
    OR NEW.lane!=OLD.lane
)
BEGIN SELECT RAISE(ABORT, 'committed evidence attempt identity is immutable'); END;
"""

_SCHEMA_COLUMNS = {
    "evidence_schema": ("singleton", "schema_version"),
    "evidence_runs": (
        "run_id",
        "schema_version",
        "limits_digest",
        "limits_json",
        "created_at",
    ),
    "evidence_objects": (
        "run_id",
        "digest",
        "schema_version",
        "tool",
        "byte_count",
        "payload_json",
        "created_at",
    ),
    "evidence_manifests": (
        "run_id",
        "attempt_id",
        "digest",
        "challenge_id",
        "episode",
        "lane",
        "complete",
        "gap",
        "observation_count",
        "committed_count",
        "omitted_count",
        "item_bytes",
        "payload_json",
        "created_at",
    ),
    "evidence_items": ("run_id", "manifest_digest", "ordinal", "object_digest"),
}

_EMPTY_SCHEMA_STUB_SQL = """
CREATE TABLE evidence_schema (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL
)
"""


def _normalized_sql(value: str) -> str:
    return " ".join(value.lower().split())


def _owned_schema_objects(connection: sqlite3.Connection) -> dict[tuple[str, str], str]:
    rows = connection.execute(
        """
        SELECT type, name, sql
        FROM sqlite_master
        WHERE type IN ('table', 'index', 'trigger')
          AND sql IS NOT NULL
          AND (name GLOB 'evidence_*' OR tbl_name GLOB 'evidence_*')
        """
    ).fetchall()
    return {
        (row["type"], row["name"]): _normalized_sql(row["sql"])
        for row in rows
        if isinstance(row["sql"], str)
    }


def _expected_schema_objects() -> dict[tuple[str, str], str]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(
            """
            CREATE TABLE runs (id TEXT PRIMARY KEY);
            CREATE TABLE attempts (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                challenge_id INTEGER NOT NULL,
                episode INTEGER NOT NULL,
                lane INTEGER NOT NULL
            );
            """
        )
        connection.executescript(_SCHEMA)
        return _owned_schema_objects(connection)
    finally:
        connection.close()


_EXPECTED_SCHEMA_OBJECTS = _expected_schema_objects()


def ensure_evidence_schema(state: StateStore) -> None:
    """Crash-atomically install evidence tables; recover only an exact empty first stub."""
    if not isinstance(state, StateStore):
        raise TypeError("state must be a StateStore")
    with state._lock:
        connection = state._connection
        schema_objects = _owned_schema_objects(connection)
        unknown_objects = set(schema_objects) - set(_EXPECTED_SCHEMA_OBJECTS)
        changed_objects = {
            identity
            for identity, sql in schema_objects.items()
            if _EXPECTED_SCHEMA_OBJECTS.get(identity) != sql
        }
        if unknown_objects or changed_objects:
            raise EvidenceConflictError("evidence schema object definition conflicts")
        missing_objects = set(_EXPECTED_SCHEMA_OBJECTS) - set(schema_objects)
        evidence_tables = {name for (kind, name) in schema_objects if kind == "table"}
        unknown_tables = evidence_tables - set(_SCHEMA_COLUMNS)
        if unknown_tables:
            raise EvidenceConflictError("unknown evidence schema objects are present")
        if "evidence_schema" not in evidence_tables and evidence_tables:
            raise EvidenceConflictError("unversioned evidence schema is present")
        for table in evidence_tables:
            actual = tuple(row["name"] for row in connection.execute(f"PRAGMA table_info({table})"))
            if actual != _SCHEMA_COLUMNS[table]:
                raise EvidenceConflictError(f"{table} shape conflicts with schema version")
        if "evidence_schema" in evidence_tables:
            try:
                versions = connection.execute(
                    "SELECT singleton, schema_version FROM evidence_schema"
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise EvidenceConflictError("evidence schema version is unreadable") from exc
            if not versions:
                schema_sql_row = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='evidence_schema'"
                ).fetchone()
                if (
                    evidence_tables != {"evidence_schema"}
                    or schema_sql_row is None
                    or not isinstance(schema_sql_row["sql"], str)
                    or _normalized_sql(schema_sql_row["sql"])
                    != _normalized_sql(_EMPTY_SCHEMA_STUB_SQL)
                ):
                    raise EvidenceConflictError("evidence schema version is invalid")
            else:
                if len(versions) != 1 or versions[0]["singleton"] != 1:
                    raise EvidenceConflictError("evidence schema version is invalid")
                if versions[0]["schema_version"] != _SCHEMA_VERSION:
                    raise EvidenceConflictError("evidence schema version conflict")
                if missing_objects:
                    for table in evidence_tables - {"evidence_schema"}:
                        if (
                            connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
                            is not None
                        ):
                            raise EvidenceConflictError(
                                "nonempty partial evidence schema is present"
                            )
        try:
            connection.executescript(f"BEGIN IMMEDIATE;\n{_SCHEMA}\nCOMMIT;")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        for table, expected in _SCHEMA_COLUMNS.items():
            actual = tuple(row["name"] for row in connection.execute(f"PRAGMA table_info({table})"))
            if actual != expected:
                raise EvidenceConflictError(f"{table} shape conflicts with schema version")
        if _owned_schema_objects(connection) != _EXPECTED_SCHEMA_OBJECTS:
            raise EvidenceConflictError("evidence schema object inventory is incomplete")


def _limits_record(limits: EvidenceLimits) -> tuple[str, bytes]:
    payload = _canonical_bytes({"schema_version": _SCHEMA_VERSION, "limits": limits.as_dict()})
    return _digest(_CONFIG_DOMAIN, payload), payload


def seal_unavailable_attempt_evidence(state: StateStore) -> int:
    """Seal terminal legacy/recovered attempts without inventing observations."""
    ensure_evidence_schema(state)
    limits_digest, limits_payload = _limits_record(EvidenceLimits())
    with state.transaction() as connection:
        rows = connection.execute(
            """
            SELECT attempt.id, attempt.run_id, attempt.challenge_id,
                   attempt.episode, attempt.lane, attempt.status
            FROM attempts AS attempt
            LEFT JOIN evidence_manifests AS manifest
              ON manifest.run_id=attempt.run_id AND manifest.attempt_id=attempt.id
            WHERE attempt.status!='running' AND manifest.attempt_id IS NULL
            ORDER BY attempt.run_id, attempt.id
            """
        ).fetchall()
        for attempt in rows:
            connection.execute(
                """
                INSERT OR IGNORE INTO evidence_runs(
                    run_id, schema_version, limits_digest, limits_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    attempt["run_id"],
                    _SCHEMA_VERSION,
                    limits_digest,
                    limits_payload,
                    state._now(),
                ),
            )
            gap = (
                "process_interrupted"
                if attempt["status"] == "interrupted"
                else "legacy_unavailable"
            )
            document = {
                "attempt_id": attempt["id"],
                "candidate_sensitive": False,
                "challenge_id": attempt["challenge_id"],
                "committed_count": 0,
                "complete": False,
                "episode": attempt["episode"],
                "gap": gap,
                "item_bytes": 0,
                "items": [],
                "lane": attempt["lane"],
                "observation_count": 0,
                "omissions": {
                    "attempt_bytes": 0,
                    "object_bytes": 0,
                    "observation_limit": 0,
                },
                "omitted_count": 0,
                "run_id": attempt["run_id"],
                "schema_version": _SCHEMA_VERSION,
            }
            payload = _canonical_bytes(document)
            connection.execute(
                """
                INSERT INTO evidence_manifests(
                    run_id, attempt_id, digest, challenge_id, episode, lane,
                    complete, gap, observation_count, committed_count, omitted_count,
                    item_bytes, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0, 0, 0, 0, ?, ?)
                """,
                (
                    attempt["run_id"],
                    attempt["id"],
                    _digest(_MANIFEST_DOMAIN, payload),
                    attempt["challenge_id"],
                    attempt["episode"],
                    attempt["lane"],
                    gap,
                    payload,
                    state._now(),
                ),
            )
    return len(rows)


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8")
    raise EvidenceTamperError("evidence payload has an invalid SQLite representation")


def _verify_canonical(payload: bytes, domain: bytes, expected_digest: str) -> dict[str, Any]:
    try:
        decoded = json.loads(payload)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise EvidenceTamperError("evidence payload is not valid JSON") from exc
    try:
        canonical = _canonical_bytes(decoded)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise EvidenceTamperError("evidence payload is not canonicalizable") from exc
    if canonical != payload or _digest(domain, payload) != expected_digest:
        raise EvidenceTamperError("evidence payload digest or canonical form changed")
    if not isinstance(decoded, dict):
        raise EvidenceTamperError("evidence payload is not an object")
    return decoded


class RunEvidence:
    """Evidence operations bound to one immutable run namespace and limit set."""

    def __init__(self, state: StateStore, run_id: str, limits: EvidenceLimits) -> None:
        self._state = state
        self.run_id = run_id
        self.limits = limits

    @classmethod
    def open(
        cls,
        state: StateStore,
        run_id: str,
        limits: EvidenceLimits | None = None,
    ) -> RunEvidence:
        if not isinstance(state, StateStore):
            raise TypeError("state must be a StateStore")
        if (
            not isinstance(run_id, str)
            or not run_id
            or len(run_id) > 256
            or not _valid_text(run_id)
        ):
            raise ValueError("run_id is invalid")
        selected = limits or EvidenceLimits()
        if not isinstance(selected, EvidenceLimits):
            raise TypeError("limits must be EvidenceLimits")
        ensure_evidence_schema(state)
        limits_digest, limits_bytes = _limits_record(selected)
        with state.transaction() as connection:
            if connection.execute("SELECT 1 FROM runs WHERE id=?", (run_id,)).fetchone() is None:
                raise ValueError("run is absent")
            row = connection.execute(
                "SELECT * FROM evidence_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO evidence_runs(
                        run_id, schema_version, limits_digest, limits_json, created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (run_id, _SCHEMA_VERSION, limits_digest, limits_bytes, state._now()),
                )
            elif (
                row["schema_version"] != _SCHEMA_VERSION
                or row["limits_digest"] != limits_digest
                or _blob(row["limits_json"]) != limits_bytes
            ):
                raise EvidenceConflictError("run evidence limits or schema conflict")
        return cls(state, run_id, selected)

    def _verify_run(self) -> None:
        expected = _canonical_bytes(
            {"schema_version": _SCHEMA_VERSION, "limits": self.limits.as_dict()}
        )
        with self._state._lock:
            row = self._state._connection.execute(
                "SELECT * FROM evidence_runs WHERE run_id=?", (self.run_id,)
            ).fetchone()
        if (
            row is None
            or row["schema_version"] != _SCHEMA_VERSION
            or row["limits_digest"] != _digest(_CONFIG_DOMAIN, expected)
            or _blob(row["limits_json"]) != expected
        ):
            raise EvidenceTamperError("run evidence configuration changed")

    def _attempt(self, attempt_id: str) -> dict[str, Any]:
        if not isinstance(attempt_id, str) or not attempt_id or len(attempt_id) > 512:
            raise ValueError("attempt_id is invalid")
        with self._state._lock:
            row = self._state._connection.execute(
                """
                SELECT id, run_id, challenge_id, episode, lane, status
                FROM attempts WHERE id=?
                """,
                (attempt_id,),
            ).fetchone()
        if row is None or row["run_id"] != self.run_id:
            raise ValueError("attempt is absent or belongs to another run")
        return dict(row)

    def commit(self, attempt_id: str, batch: EvidenceBatch) -> EvidenceManifest:
        if not isinstance(batch, EvidenceBatch):
            raise TypeError("batch must be EvidenceBatch")
        self._verify_run()
        attempt = self._attempt(attempt_id)
        objects: list[tuple[int, str, str, bytes]] = []
        omissions = {"attempt_bytes": 0, "object_bytes": 0, "observation_limit": 0}
        candidate_sensitive = any(
            observation.candidate_sensitive for observation in batch.observations
        )
        item_bytes = 0
        for ordinal, observation in enumerate(batch.observations):
            if ordinal >= self.limits.max_observations:
                omissions["observation_limit"] += 1
                continue
            tool, payload = _project_observation(observation)
            if len(payload) > self.limits.max_object_bytes:
                omissions["object_bytes"] += 1
                continue
            if item_bytes + len(payload) > self.limits.max_attempt_bytes:
                omissions["attempt_bytes"] += 1
                continue
            digest = _digest(_OBJECT_DOMAIN, payload)
            objects.append((ordinal, digest, tool, payload))
            item_bytes += len(payload)

        manifest_document = {
            "attempt_id": attempt_id,
            "candidate_sensitive": candidate_sensitive,
            "challenge_id": attempt["challenge_id"],
            "committed_count": len(objects),
            "complete": batch.complete and not any(omissions.values()),
            "episode": attempt["episode"],
            "gap": batch.gap or ("quota_omitted" if any(omissions.values()) else None),
            "item_bytes": item_bytes,
            "items": [
                {"object_digest": digest, "ordinal": ordinal}
                for ordinal, digest, _tool, _payload in objects
            ],
            "lane": attempt["lane"],
            "observation_count": len(batch.observations),
            "omissions": omissions,
            "omitted_count": sum(omissions.values()),
            "run_id": self.run_id,
            "schema_version": _SCHEMA_VERSION,
        }
        manifest_payload = _canonical_bytes(manifest_document)
        manifest_digest = _digest(_MANIFEST_DOMAIN, manifest_payload)

        with self._state.transaction() as connection:
            locked_attempt = connection.execute(
                """
                SELECT id, run_id, challenge_id, episode, lane, status
                FROM attempts WHERE id=?
                """,
                (attempt_id,),
            ).fetchone()
            if locked_attempt is None or any(
                locked_attempt[key] != attempt[key]
                for key in ("id", "run_id", "challenge_id", "episode", "lane")
            ):
                raise EvidenceConflictError("attempt identity changed during evidence commit")
            current = connection.execute(
                "SELECT digest, payload_json FROM evidence_manifests WHERE run_id=? AND attempt_id=?",
                (self.run_id, attempt_id),
            ).fetchone()
            if current is not None:
                if (
                    current["digest"] != manifest_digest
                    or _blob(current["payload_json"]) != manifest_payload
                ):
                    raise EvidenceConflictError(
                        "attempt evidence was already committed differently"
                    )
            else:
                if locked_attempt["status"] != "running":
                    raise ValueError("first evidence commit requires a running attempt")
                for _ordinal, digest, tool, payload in objects:
                    existing = connection.execute(
                        "SELECT * FROM evidence_objects WHERE run_id=? AND digest=?",
                        (self.run_id, digest),
                    ).fetchone()
                    if existing is None:
                        connection.execute(
                            """
                            INSERT INTO evidence_objects(
                                run_id, digest, schema_version, tool, byte_count,
                                payload_json, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                self.run_id,
                                digest,
                                _SCHEMA_VERSION,
                                tool,
                                len(payload),
                                payload,
                                self._state._now(),
                            ),
                        )
                    else:
                        self._verify_object_row(existing)
                        if _blob(existing["payload_json"]) != payload or existing["tool"] != tool:
                            raise EvidenceTamperError(
                                "content-addressed object collision or tamper"
                            )
                connection.execute(
                    """
                    INSERT INTO evidence_manifests(
                        run_id, attempt_id, digest, challenge_id, episode, lane,
                        complete, observation_count, committed_count,
                        gap, omitted_count, item_bytes, payload_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.run_id,
                        attempt_id,
                        manifest_digest,
                        attempt["challenge_id"],
                        attempt["episode"],
                        attempt["lane"],
                        int(manifest_document["complete"]),
                        len(batch.observations),
                        len(objects),
                        manifest_document["gap"],
                        sum(omissions.values()),
                        item_bytes,
                        manifest_payload,
                        self._state._now(),
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO evidence_items(run_id, manifest_digest, ordinal, object_digest)
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        (self.run_id, manifest_digest, ordinal, digest)
                        for ordinal, digest, _tool, _payload in objects
                    ],
                )
        return self._load_manifest(attempt_id)

    def _verify_object_row(self, row: Mapping[str, Any]) -> dict[str, Any]:
        payload = _blob(row["payload_json"])
        if (
            row["schema_version"] != _SCHEMA_VERSION
            or row["byte_count"] != len(payload)
            or not isinstance(row["tool"], str)
        ):
            raise EvidenceTamperError("evidence object metadata changed")
        decoded = _verify_canonical(payload, _OBJECT_DOMAIN, row["digest"])
        hashes_valid = all(
            isinstance(values, list)
            and len(values) <= 20
            and all(isinstance(value, str) and _SHA256.fullmatch(value) for value in values)
            for values in (
                decoded.get("candidate_sha256s"),
                decoded.get("supplied_candidate_sha256s"),
            )
        )
        facts = decoded.get("facts")
        validated_facts = (
            _facts_for_tool(decoded.get("tool"), facts)
            if isinstance(decoded.get("tool"), str) and isinstance(facts, dict)
            else None
        )
        if (
            set(decoded)
            != {
                "candidate_sha256s",
                "candidate_sensitive",
                "facts",
                "schema_version",
                "source_bound",
                "success",
                "supplied_candidate_sha256s",
                "tool",
            }
            or decoded.get("tool") != row["tool"]
            or decoded.get("schema_version") != _SCHEMA_VERSION
            or decoded.get("success") not in {True, False, None}
            or type(decoded.get("source_bound")) is not bool
            or type(decoded.get("candidate_sensitive")) is not bool
            or bool(decoded.get("candidate_sha256s") or decoded.get("supplied_candidate_sha256s"))
            and decoded.get("candidate_sensitive") is not True
            or not hashes_valid
            or not isinstance(facts, dict)
            or validated_facts != facts
            or _contains_candidate(facts)
        ):
            raise EvidenceTamperError("evidence object columns disagree with payload")
        return decoded

    def _load_manifest(self, attempt_id: str) -> EvidenceManifest:
        with self._state._lock:
            row = self._state._connection.execute(
                "SELECT * FROM evidence_manifests WHERE run_id=? AND attempt_id=?",
                (self.run_id, attempt_id),
            ).fetchone()
        if row is None:
            raise EvidenceTamperError("committed evidence manifest is missing")
        payload = _blob(row["payload_json"])
        document = _verify_canonical(payload, _MANIFEST_DOMAIN, row["digest"])
        integer_fields = (
            "challenge_id",
            "committed_count",
            "episode",
            "item_bytes",
            "lane",
            "observation_count",
            "omitted_count",
        )
        if (
            set(document) != _MANIFEST_DOCUMENT_KEYS
            or type(document.get("schema_version")) is not int
            or document["schema_version"] != _SCHEMA_VERSION
            or not isinstance(document.get("attempt_id"), str)
            or not isinstance(document.get("run_id"), str)
            or type(document.get("candidate_sensitive")) is not bool
            or type(document.get("complete")) is not bool
            or any(
                type(document.get(key)) is not int or document[key] < 0 for key in integer_fields
            )
            or document.get("challenge_id") == 0
            or row["complete"] not in {0, 1}
        ):
            raise EvidenceTamperError("manifest document shape or schema version changed")
        complete = document["complete"]
        gap = document["gap"]
        if (
            complete
            and gap is not None
            or not complete
            and (not isinstance(gap, str) or gap not in _GAPS)
        ):
            raise EvidenceTamperError("manifest completeness and gap disagree")
        scalar_columns = {
            "attempt_id": row["attempt_id"],
            "challenge_id": row["challenge_id"],
            "committed_count": row["committed_count"],
            "complete": bool(row["complete"]),
            "episode": row["episode"],
            "gap": row["gap"],
            "item_bytes": row["item_bytes"],
            "lane": row["lane"],
            "observation_count": row["observation_count"],
            "omitted_count": row["omitted_count"],
            "run_id": row["run_id"],
        }
        if any(document.get(key) != value for key, value in scalar_columns.items()):
            raise EvidenceTamperError("manifest columns disagree with payload")
        omissions = document.get("omissions")
        declared_items = document.get("items")
        if (
            not isinstance(omissions, dict)
            or set(omissions) != {"attempt_bytes", "object_bytes", "observation_limit"}
            or any(type(value) is not int or value < 0 for value in omissions.values())
            or sum(omissions.values()) != row["omitted_count"]
            or not isinstance(declared_items, list)
            or len(declared_items) != row["committed_count"]
            or document["observation_count"]
            != document["committed_count"] + document["omitted_count"]
            or any(
                not isinstance(item, dict)
                or set(item) != {"object_digest", "ordinal"}
                or type(item.get("ordinal")) is not int
                or item["ordinal"] < 0
                or not isinstance(item.get("object_digest"), str)
                or _SHA256.fullmatch(item["object_digest"]) is None
                for item in declared_items
            )
        ):
            raise EvidenceTamperError("manifest counts or item declaration changed")

        with self._state._lock:
            item_rows = self._state._connection.execute(
                """
                SELECT ordinal, object_digest FROM evidence_items
                WHERE run_id=? AND manifest_digest=? ORDER BY ordinal
                """,
                (self.run_id, row["digest"]),
            ).fetchall()
        expected_items = [
            (item.get("ordinal"), item.get("object_digest"))
            for item in declared_items
            if isinstance(item, dict)
        ]
        actual_items = [(item["ordinal"], item["object_digest"]) for item in item_rows]
        if len(expected_items) != len(declared_items) or actual_items != expected_items:
            raise EvidenceTamperError("manifest item rows disagree with payload")

        items: list[EvidenceItem] = []
        item_bytes = 0
        with self._state._lock:
            for ordinal, object_digest in actual_items:
                object_row = self._state._connection.execute(
                    "SELECT * FROM evidence_objects WHERE run_id=? AND digest=?",
                    (self.run_id, object_digest),
                ).fetchone()
                if object_row is None:
                    raise EvidenceTamperError("manifest references a missing evidence object")
                self._verify_object_row(object_row)
                object_payload = _blob(object_row["payload_json"])
                item_bytes += len(object_payload)
                items.append(
                    EvidenceItem(
                        ordinal=ordinal,
                        digest=object_digest,
                        tool=object_row["tool"],
                        byte_count=object_row["byte_count"],
                        payload_json=object_payload.decode("utf-8"),
                    )
                )
        if item_bytes != row["item_bytes"]:
            raise EvidenceTamperError("manifest item byte accounting changed")
        attempt = self._attempt(attempt_id)
        if (
            attempt["run_id"] != row["run_id"]
            or attempt["challenge_id"] != row["challenge_id"]
            or attempt["episode"] != row["episode"]
            or attempt["lane"] != row["lane"]
        ):
            raise EvidenceTamperError("attempt identity changed after evidence commit")
        return EvidenceManifest(
            run_id=self.run_id,
            attempt_id=attempt_id,
            digest=row["digest"],
            challenge_id=row["challenge_id"],
            episode=row["episode"],
            lane=row["lane"],
            complete=bool(row["complete"]),
            gap=row["gap"],
            observation_count=row["observation_count"],
            committed_count=row["committed_count"],
            omitted_count=row["omitted_count"],
            item_bytes=row["item_bytes"],
            omissions=tuple(sorted((key, int(value)) for key, value in omissions.items())),
            items=tuple(items),
            candidate_sensitive=document["candidate_sensitive"],
        )

    def memory_source(
        self,
        attempt_id: str,
        *,
        candidate_sha256: str | None = None,
    ) -> MemoryEvidenceSource:
        """Load a verified digest-free view for typed same-run memory."""
        if not isinstance(attempt_id, str) or not attempt_id:
            raise ValueError("attempt_id must be nonempty")
        if candidate_sha256 is not None and _SHA256.fullmatch(candidate_sha256) is None:
            raise ValueError("candidate_sha256 must be lowercase SHA-256")
        self._verify_run()
        manifest = self._load_manifest(attempt_id)
        observations: list[MemoryEvidenceObservation] = []
        candidate_observed = False
        candidate_supplied = False
        for item in manifest.items:
            payload = json.loads(item.payload_json)
            if candidate_sha256 is not None:
                candidate_supplied |= candidate_sha256 in payload["supplied_candidate_sha256s"]
                candidate_observed |= (
                    payload["success"] is True
                    and payload["source_bound"] is True
                    and candidate_sha256 in payload["candidate_sha256s"]
                )
            observations.append(
                MemoryEvidenceObservation(
                    ordinal=item.ordinal,
                    tool=item.tool,
                    success=payload["success"],
                    source_bound=payload["source_bound"],
                    facts=_freeze_json(_digest_free_memory_value(payload["facts"])),
                )
            )
        return MemoryEvidenceSource(
            run_id=self.run_id,
            attempt_id=manifest.attempt_id,
            challenge_id=manifest.challenge_id,
            episode=manifest.episode,
            lane=manifest.lane,
            complete=manifest.complete,
            gap=manifest.gap,
            observations=tuple(observations),
            candidate_observed=candidate_observed,
            candidate_supplied=candidate_supplied,
        )

    @staticmethod
    def _bundle_size(bundle: EvidenceBundle) -> tuple[EvidenceBundle, int]:
        current = bundle
        size = -1
        for _ in range(8):
            measured = len(_canonical_bytes(current.as_dict()))
            if measured == size and current.encoded_bytes == measured:
                return current, measured
            size = measured
            current = replace(current, encoded_bytes=measured)
        measured = len(_canonical_bytes(current.as_dict()))
        return replace(current, encoded_bytes=measured), measured

    def carry(self, challenge_id: int, lane: int, before_episode: int) -> EvidenceBundle:
        self._verify_run()
        for name, value in (
            ("challenge_id", challenge_id),
            ("lane", lane),
            ("before_episode", before_episode),
        ):
            if type(value) is not int or value < 0 or (name == "challenge_id" and value == 0):
                raise ValueError(f"{name} must be a valid nonnegative integer")
        with self._state._lock:
            rows = self._state._connection.execute(
                """
                SELECT manifest.attempt_id, attempt.status
                FROM evidence_manifests AS manifest
                JOIN attempts AS attempt
                  ON attempt.id=manifest.attempt_id AND attempt.run_id=manifest.run_id
                WHERE manifest.run_id=? AND manifest.challenge_id=?
                  AND manifest.lane=? AND manifest.episode<?
                  AND attempt.status IN (
                      'candidate', 'unsolved', 'timeout', 'cancelled', 'interrupted',
                      'failed', 'unsupported'
                  )
                ORDER BY manifest.episode DESC, manifest.attempt_id DESC
                """,
                (self.run_id, challenge_id, lane, before_episode),
            ).fetchall()
        available = []
        for row in rows:
            manifest = self._load_manifest(row["attempt_id"])
            if (
                row["status"] == "candidate"
                or manifest.candidate_sensitive
                or any(item._is_candidate_sensitive() for item in manifest.items)
            ):
                manifest = replace(
                    manifest,
                    items=tuple(
                        replace(item, carry_redact_digests=True) for item in manifest.items
                    ),
                    carry_redact_digests=True,
                )
            available.append(manifest)
        total_items = sum(len(manifest.items) for manifest in available)
        selected: list[EvidenceManifest] = []

        def candidate_bundle(manifests: list[EvidenceManifest]) -> EvidenceBundle:
            selected_items = sum(len(manifest.items) for manifest in manifests)
            bundle = EvidenceBundle(
                run_id=self.run_id,
                challenge_id=challenge_id,
                lane=lane,
                before_episode=before_episode,
                manifests=tuple(manifests),
                omitted_manifests=len(available) - len(manifests),
                omitted_items=total_items - selected_items,
                encoded_bytes=0,
            )
            return self._bundle_size(bundle)[0]

        for manifest in available:
            base = replace(manifest, items=(), carry_omitted_items=len(manifest.items))
            trial = candidate_bundle([*selected, base])
            if trial.encoded_bytes > self.limits.max_carry_bytes:
                continue
            selected.append(base)
            index = len(selected) - 1
            admitted: list[EvidenceItem] = []
            for item in manifest.items:
                proposed = replace(
                    manifest,
                    items=(*admitted, item),
                    carry_omitted_items=len(manifest.items) - len(admitted) - 1,
                )
                trial_selected = [*selected]
                trial_selected[index] = proposed
                trial = candidate_bundle(trial_selected)
                if trial.encoded_bytes <= self.limits.max_carry_bytes:
                    selected[index] = proposed
                    admitted.append(item)

        bundle = candidate_bundle(selected)
        if bundle.encoded_bytes > self.limits.max_carry_bytes:
            raise EvidenceTamperError("empty evidence bundle exceeds its configured carry limit")
        return bundle


__all__ = [
    "CanonicalValue",
    "EvidenceBatch",
    "EvidenceBundle",
    "EvidenceConflictError",
    "EvidenceError",
    "EvidenceItem",
    "EvidenceLimits",
    "EvidenceManifest",
    "EvidenceTamperError",
    "HostObservation",
    "MemoryEvidenceObservation",
    "MemoryEvidenceSource",
    "RunEvidence",
    "ensure_evidence_schema",
    "project_tool_observation",
    "seal_unavailable_attempt_evidence",
]
