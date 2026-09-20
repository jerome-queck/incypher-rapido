"""Generic C-to-R capsule exporter for private offline capability banks.

The caller owns generator, seed, checker, reference-method, and provenance data.  This module sees
only an allowlisted visible file set plus closed admission attestations.  It writes a private Board
bank and a path-free public readiness manifest; it never writes source paths, seeds, candidates,
checker material, or content-derived digests.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import hmac
import io
import json
import lzma
import os
import re
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import time
import unicodedata
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final

CAPSULE_EXPORT_SCHEMA: Final = "rapido-offline-capsule-export-v1"
CAPSULE_EXPORTER_VERSION: Final = "offline-capsule-v1"
CAPSULE_SCAN_WORKER_VERSION: Final = "offline-capsule-scan-worker-v1"

EXCLUSION_CODES: Final = frozenset(
    {
        "bytes_absent",
        "source_or_generator_absent",
        "license_or_ownership_unresolved",
        "checker_absent_or_ambiguous",
        "unsafe_or_unowned_service",
        "public_internet_required",
        "answer_or_solution_exposed",
        "identity_or_fingerprint_exposed",
        "generator_unstable",
        "trivialized_by_transformation",
        "mechanic_destroyed",
        "dependency_unavailable",
        "resource_unbounded",
        "cleanup_unprovable",
    }
)

_ASSIGNMENTS = frozenset(
    {"sentinel", "calibration", "focused-sibling", "routing", "heldout", "capacity-reserve"}
)
_CATEGORIES = frozenset(
    {
        "archive",
        "binary",
        "crypto",
        "dynamic",
        "forensics",
        "misc",
        "proof",
        "pwn",
        "reverse",
        "structured",
        "text",
        "web",
    }
)
_FORMS = frozenset({"static", "dynamic", "hybrid"})
_TIERS = frozenset({"A", "B", "C", "D", "sentinel"})
_TASK_ID = re.compile(r"[A-Z0-9][A-Z0-9-]{2,79}\Z")
_FAMILY_ID = re.compile(r"[A-Z0-9][A-Z0-9-]{2,79}\Z")
_VERSION = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_DIGEST_VERSION = re.compile(r"(?:sha256[.:-]?)?[0-9a-f]{40,64}\Z")
_FORBIDDEN_COMPONENTS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".ssh",
        "__pycache__",
        "attempt",
        "attempts",
        "solution",
        "solutions",
        "solved",
        "writeup",
        "writeups",
    }
)
_FORBIDDEN_BYTES = re.compile(
    rb"(?:"
    rb"(?:INCYPHER|flag)\{[^{}\r\n]{1,512}\}|"
    rb"(?:https?|wss?|ssh|git)://|git@[A-Za-z0-9.-]+:|"
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    rb"(?<![A-Za-z0-9])/(?:Users|home|root|Volumes|private)/[^\x00\r\n ]+|"
    rb"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\x00\r\n ]+|"
    rb"(?:refs/heads/|objects/pack/|\.git/(?:config|HEAD|objects))"
    rb")",
    re.IGNORECASE,
)
_PUBLIC_FORBIDDEN = re.compile(
    r"(?:https?://|wss?://|(?<![A-Za-z0-9])/(?:Users|home|root|Volumes|private|var|etc|opt)/|"
    r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]|(?:INCYPHER|flag)\{|"
    r"(?<![0-9a-f])[0-9a-f]{40,64}(?![0-9a-f]))",
    re.IGNORECASE,
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_COPY_CHUNK = 1024 * 1024
_SCAN_WORKER_ARGUMENT = "--offline-capsule-scan-worker-v1"
_SCAN_WORKER_DEADLINE_SECONDS = 5.0
_SCAN_WORKER_MAX_OUTPUT = 4096
_SCAN_WORKER_MAX_HEADER = 1024 * 1024
_SCAN_WORKER_CPU_SECONDS = 3
_SCAN_WORKER_MEMORY_BYTES = 1024 * 1024 * 1024
_SCAN_WORKER_PIDS = 1
_OCI_COMMAND_DEADLINE_SECONDS = 8.0
_OCI_SCAN_DEADLINE_SECONDS = 8.0
_OCI_OUTPUT_LIMIT = 4096
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PLACEHOLDER_VERSION = re.compile(
    r"(?:^|[._-])(?:none|unknown|unassigned|placeholder|unset|unspecified|todo|tbd)"
    r"(?:[0-9]+)?(?:$|[._-])"
)
_SINGLE_STREAM_ARCHIVE_SIGNATURES = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")
_TAR_CHECKSUM = re.compile(rb"[0-7 ]{6}(?:\x00 |\x00\x00|  )")
_UNSUPPORTED_ARCHIVE_SIGNATURES = (
    b"7z\xbc\xaf'\x1c",
    b"Rar!\x1a\x07",
    b"MSCF",
    b"MSWIM\x00\x00\x00",
    b"!<arch>\n",
    b"070701",
    b"070702",
    b"070707",
    b"xar!",
)


class CapsuleContractError(ValueError):
    """Closed failure at the private capsule boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class CapsuleLimits:
    """Resource bounds applied before any capsule becomes runner-visible."""

    max_files: int = 100
    max_file_bytes: int = 128 * 1024 * 1024
    max_total_bytes: int = 1024 * 1024 * 1024
    max_archive_members: int = 4096
    max_archive_unpacked_bytes: int = 1024 * 1024 * 1024
    max_archive_depth: int = 4
    max_archive_ratio: int = 256

    def validate(self) -> None:
        values = (
            self.max_files,
            self.max_file_bytes,
            self.max_total_bytes,
            self.max_archive_members,
            self.max_archive_unpacked_bytes,
            self.max_archive_depth,
            self.max_archive_ratio,
        )
        if any(type(value) is not int or value <= 0 for value in values):
            raise CapsuleContractError("capsule_limit_invalid")
        if (
            self.max_files > 1000
            or self.max_file_bytes > 128 * 1024 * 1024
            or self.max_total_bytes > 1024 * 1024 * 1024
            or self.max_archive_members > 10_000
            or self.max_archive_unpacked_bytes > 1024 * 1024 * 1024
            or self.max_file_bytes > self.max_total_bytes
            or self.max_archive_depth > 8
            or self.max_archive_ratio > 1024
        ):
            raise CapsuleContractError("capsule_limit_invalid")


@dataclass(frozen=True)
class AdmissionAttestation:
    """Closed private evidence gates; raw evidence remains in Zone C/O."""

    validation_seed_count: int
    reference_success: bool
    negative_rejection: bool
    semantic_stability: bool
    provenance_recorded: bool
    assignment_frozen: bool
    checker_isolated: bool
    cleanup_registered: bool
    private_full_scan_attested: bool

    def validate(self) -> None:
        booleans = (
            self.reference_success,
            self.negative_rejection,
            self.semantic_stability,
            self.provenance_recorded,
            self.assignment_frozen,
            self.checker_isolated,
            self.cleanup_registered,
            self.private_full_scan_attested,
        )
        if type(self.validation_seed_count) is not int or self.validation_seed_count != 3:
            raise CapsuleContractError("admission_incomplete")
        if any(type(value) is not bool or value is not True for value in booleans):
            raise CapsuleContractError("admission_incomplete")


@dataclass(frozen=True)
class CapsuleTask:
    """Runner-visible registration.  Source paths live only in :class:`CapsuleInput`."""

    board_id: int
    task_id: str
    family_id: str
    category: str
    assignment: str
    tier: str
    form: str
    description: str
    files: tuple[str, ...]
    generator_version: str
    checker_version: str
    private_scan_version: str
    service_version: str
    resource_profile_id: str
    service_required: bool
    admission: AdmissionAttestation


@dataclass(frozen=True)
class PrivateTaskCommitments:
    """Opaque fixed-size private bindings.  Values never enter either public projection."""

    namespace: str
    assignment: bytes
    semantic: bytes
    full_scan: bytes

    def validate(self) -> None:
        try:
            namespace = _version(self.namespace)
        except CapsuleContractError:
            _fail("private_attestation_invalid")
        if namespace in {"none", "unknown", "unassigned"}:
            _fail("private_attestation_invalid")
        values = (self.assignment, self.semantic, self.full_scan)
        if any(type(value) is not bytes or len(value) != 32 for value in values):
            _fail("private_attestation_invalid")
        if len(set(values)) != len(values):
            _fail("private_attestation_invalid")


@dataclass(frozen=True)
class RegisteredPrivateBinding:
    """Frozen opaque registry row supplied from the private curator trust zone."""

    namespace: str
    assignment_commitment: bytes
    semantic_commitment: bytes
    full_scan_commitment: bytes
    board_id: int
    task_id: str
    family_id: str
    category: str
    tier: str
    assignment: str
    form: str
    description_commitment: bytes
    files_commitment: bytes
    generator_version: str
    checker_version: str
    private_scan_version: str
    service_version: str
    resource_profile_id: str
    service_required: bool
    validation_seed_count: int


@dataclass(frozen=True)
class CapsuleOciAdapter:
    """Exact-image Docker isolation and frozen opaque-registry adapter."""

    docker_path: Path
    image_id: str
    source_sha256: str
    registry: tuple[RegisteredPrivateBinding, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.docker_path, Path)
            or not self.docker_path.is_absolute()
            or type(self.image_id) is not str
            or _IMAGE_ID.fullmatch(self.image_id) is None
            or type(self.source_sha256) is not str
            or _SOURCE_SHA256.fullmatch(self.source_sha256) is None
            or type(self.registry) is not tuple
            or not self.registry
            or any(type(value) is not RegisteredPrivateBinding for value in self.registry)
        ):
            _fail("isolation_adapter_invalid")
        keys = [(value.namespace, value.task_id) for value in self.registry]
        if len(set(keys)) != len(keys):
            _fail("isolation_adapter_invalid")

    def verify_binding(self, value: CapsuleInput) -> None:
        task = value.task
        matching = [
            row
            for row in self.registry
            if row.namespace == value.commitments.namespace and row.task_id == task.task_id
        ]
        if len(matching) != 1:
            _fail("private_attestation_failed")
        row = matching[0]
        if any(
            type(commitment) is not bytes or len(commitment) != 32
            for commitment in (
                row.assignment_commitment,
                row.semantic_commitment,
                row.full_scan_commitment,
                row.description_commitment,
                row.files_commitment,
            )
        ):
            _fail("private_attestation_failed")
        exact = (
            hmac.compare_digest(row.assignment_commitment, value.commitments.assignment)
            and hmac.compare_digest(row.semantic_commitment, value.commitments.semantic)
            and hmac.compare_digest(row.full_scan_commitment, value.commitments.full_scan)
            and type(row.board_id) is int
            and row.board_id == task.board_id
            and row.family_id == task.family_id
            and row.category == task.category
            and row.tier == task.tier
            and row.assignment == task.assignment
            and row.form == task.form
            and hmac.compare_digest(
                row.description_commitment,
                _private_field_commitment("description", task.description),
            )
            and hmac.compare_digest(
                row.files_commitment,
                _private_field_commitment("files", task.files),
            )
            and row.generator_version == task.generator_version
            and row.checker_version == task.checker_version
            and row.private_scan_version == task.private_scan_version
            and row.service_version == task.service_version
            and row.resource_profile_id == task.resource_profile_id
            and type(row.service_required) is bool
            and row.service_required is task.service_required
            and type(row.validation_seed_count) is int
            and row.validation_seed_count == task.admission.validation_seed_count
        )
        if not exact:
            _fail("private_attestation_failed")


@dataclass(frozen=True)
class CapsuleInput:
    """Zone-C input.  ``source_root`` is never serialized or copied into a public record."""

    task: CapsuleTask
    source_root: Path
    commitments: PrivateTaskCommitments


@dataclass(frozen=True)
class CapsuleExclusion:
    """Candidate-free closed readiness row for an ineligible task."""

    task_id: str
    family_id: str
    category: str
    assignment: str
    tier: str
    code: str


@dataclass
class _ScanState:
    limits: CapsuleLimits
    marker_pattern: re.Pattern[bytes]
    direct_bytes: int = 0
    archive_bytes: int = 0
    archive_members: int = 0


@dataclass(frozen=True)
class _Identity:
    dev: int
    ino: int
    mode: int
    uid: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _Identity:
        return cls(
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )


@dataclass
class _PinnedDirectory:
    path: Path
    descriptors: tuple[int, ...]
    names: tuple[str, ...]
    identities: tuple[_Identity, ...]

    @property
    def descriptor(self) -> int:
        return self.descriptors[-1]

    @property
    def identity(self) -> _Identity:
        return self.identities[-1]

    def revalidate(self, *, strict_final: bool = False) -> bool:
        try:
            for index, name in enumerate(self.names, start=1):
                named = os.stat(name, dir_fd=self.descriptors[index - 1], follow_symlinks=False)
                opened = os.fstat(self.descriptors[index])
                expected = self.identities[index]
                if (
                    not _same_inode(named, expected)
                    or not _same_inode(opened, expected)
                    or named.st_mode != expected.mode
                    or opened.st_mode != expected.mode
                    or named.st_uid != expected.uid
                    or opened.st_uid != expected.uid
                ):
                    return False
            return (
                not strict_final or _Identity.from_stat(os.fstat(self.descriptor)) == self.identity
            )
        except OSError:
            return False

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _fail(code: str) -> None:
    raise CapsuleContractError(code)


def _identifier(value: Any, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail("registration_invalid")
    return value


def _version(value: Any) -> str:
    if (
        type(value) is not str
        or _VERSION.fullmatch(value) is None
        or _DIGEST_VERSION.fullmatch(value) is not None
        or _PLACEHOLDER_VERSION.search(value) is not None
    ):
        _fail("registration_invalid")
    return value


def _private_field_commitment(label: str, value: Any) -> bytes:
    """Bind large registration fields inside the private registry only."""

    try:
        encoded = json.dumps(
            {"field": label, "value": value},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("private_attestation_invalid")
    return hashlib.sha256(b"rapido-private-registration-v1\x00" + encoded).digest()


def _relative_path(value: Any) -> tuple[str, ...]:
    if type(value) is not str or not value:
        _fail("capsule_path_invalid")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        _fail("capsule_path_invalid")
    if len(encoded) > 4096 or unicodedata.normalize("NFC", value) != value:
        _fail("capsule_path_invalid")
    if value.startswith(("/", "\\")) or "\\" in value or ":" in value:
        _fail("capsule_path_invalid")
    if any(
        ord(character) < 32
        or ord(character) == 127
        or unicodedata.category(character).startswith("C")
        for character in value
    ):
        _fail("capsule_path_invalid")
    parts = tuple(value.split("/"))
    if (
        not parts
        or any(not part or part in {".", ".."} for part in parts)
        or PurePosixPath(*parts).as_posix() != value
        or any(part.casefold() in _FORBIDDEN_COMPONENTS for part in parts)
    ):
        _fail("capsule_path_invalid")
    return parts


def _pin_absolute_directory(path: Path, failure_code: str) -> _PinnedDirectory:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(failure_code)
    parts = path.parts[1:]
    descriptors: list[int] = []
    identities: list[_Identity] = []
    try:
        root = os.open("/", os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
        descriptors.append(root)
        identities.append(_Identity.from_stat(os.fstat(root)))
        for name in parts:
            before = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                _fail(failure_code)
            child = os.open(
                name,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                dir_fd=descriptors[-1],
            )
            after = os.fstat(child)
            if _Identity.from_stat(before) != _Identity.from_stat(after):
                os.close(child)
                _fail(failure_code)
            descriptors.append(child)
            identities.append(_Identity.from_stat(after))
    except CapsuleContractError:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise
    except OSError:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        _fail(failure_code)
    final = identities[-1]
    if final.uid != os.geteuid() or final.mode & 0o077:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        _fail(failure_code)
    return _PinnedDirectory(path, tuple(descriptors), tuple(parts), tuple(identities))


def _same_inode(left: os.stat_result | _Identity, right: os.stat_result | _Identity) -> bool:
    def key(value: os.stat_result | _Identity) -> tuple[int, int]:
        if isinstance(value, _Identity):
            return value.dev, value.ino
        return value.st_dev, value.st_ino

    return key(left) == key(right)


def _directory_descriptor_is_unlinked(descriptor: int) -> bool:
    links = os.fstat(descriptor).st_nlink
    # Darwin retains the pre-unlink directory link count on an open descriptor.  Callers also
    # require the pinned name to be absent, so Linux's zero-link proof is supplemented by that
    # inode/name proof on Darwin.
    return links == 0 or sys.platform == "darwin"


def _prove_removable_parent(path: Path) -> _PinnedDirectory:
    """Actually unlink and recreate one empty owner-only destination parent."""
    old_parent: _PinnedDirectory | None = None
    grandparent: _PinnedDirectory | None = None
    removed = False
    try:
        old_parent = _pin_absolute_directory(path, "capsule_destination_invalid")
        grandparent = _pin_absolute_directory(path.parent, "capsule_destination_invalid")
        if os.listdir(old_parent.descriptor):
            _fail("capsule_destination_invalid")
        _quarantine_remove_entry(
            grandparent.descriptor,
            path.name,
            old_parent.descriptor,
            directory=True,
            failure_code="capsule_destination_invalid",
        )
        removed = True
        os.mkdir(path.name, mode=0o700, dir_fd=grandparent.descriptor)
        removed = False
        captured = _open_child_directory(grandparent.descriptor, path.name)
        recreated = _pin_absolute_directory(path, "capsule_destination_invalid")
        if not _same_inode(os.fstat(captured), recreated.identity):
            os.close(captured)
            recreated.close()
            _fail("capsule_destination_invalid")
        os.close(captured)
        if _same_inode(recreated.identity, old_parent.identity) or not grandparent.revalidate():
            recreated.close()
            _fail("capsule_destination_invalid")
        return recreated
    except CapsuleContractError:
        raise
    except OSError:
        _fail("capsule_destination_invalid")
    finally:
        if removed and grandparent is not None:
            try:
                os.mkdir(path.name, mode=0o700, dir_fd=grandparent.descriptor)
            except OSError:
                pass
        if old_parent is not None:
            old_parent.close()
        if grandparent is not None:
            grandparent.close()


def _open_child_directory(parent: int, name: str, *, create: bool = False) -> int:
    descriptor = -1
    try:
        if create:
            os.mkdir(name, mode=0o700, dir_fd=parent)
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o077
        ):
            _fail("capsule_destination_invalid" if create else "capsule_source_invalid")
        descriptor = os.open(name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC, dir_fd=parent)
        after = os.fstat(descriptor)
    except (FileExistsError, OSError):
        if descriptor >= 0:
            os.close(descriptor)
        _fail("capsule_destination_invalid" if create else "capsule_source_invalid")
    if (
        not stat.S_ISDIR(after.st_mode)
        or after.st_uid != os.geteuid()
        or after.st_mode & 0o077
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        os.close(descriptor)
        _fail("capsule_destination_invalid" if create else "capsule_source_invalid")
    return descriptor


def _ensure_child_directory(parent: int, name: str) -> int:
    try:
        return _open_child_directory(parent, name)
    except CapsuleContractError:
        try:
            return _open_child_directory(parent, name, create=True)
        except CapsuleContractError:
            _fail("capsule_destination_invalid")


def _marker_pattern(
    canaries: Sequence[bytes], forbidden_markers: Sequence[bytes]
) -> re.Pattern[bytes]:
    selected: list[bytes] = []
    for values, minimum in ((canaries, 8), (forbidden_markers, 3)):
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
            _fail("scanner_registration_invalid")
        for value in values:
            if type(value) is not bytes or not minimum <= len(value) <= 4096:
                _fail("scanner_registration_invalid")
            selected.append(value)
    if (
        not canaries
        or not forbidden_markers
        or len(selected) > 1024
        or sum(map(len, selected)) > 256 * 1024
        or len(set(selected)) != len(selected)
    ):
        _fail("scanner_registration_invalid")
    return re.compile(b"|".join(re.escape(value) for value in selected), re.IGNORECASE)


def _scan_bytes(value: bytes, state: _ScanState) -> None:
    if _FORBIDDEN_BYTES.search(value) is not None or state.marker_pattern.search(value) is not None:
        _fail("capsule_contaminated")


def _archive_name(value: str, state: _ScanState) -> tuple[str, ...]:
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        _fail("capsule_archive_invalid")
    _scan_bytes(encoded, state)
    try:
        return _relative_path(value.rstrip("/"))
    except CapsuleContractError:
        _fail("capsule_archive_invalid")


def _read_bounded(stream: Any, size: int, limit: int) -> bytes:
    if type(size) is not int or size < 0 or size > limit:
        _fail("capsule_limit_exceeded")
    try:
        value = stream.read(size + 1)
    except (OSError, EOFError, RuntimeError, ValueError, zipfile.BadZipFile, lzma.LZMAError):
        _fail("capsule_archive_invalid")
    if len(value) != size:
        _fail("capsule_archive_invalid")
    return value


def _account_archive(size: int, state: _ScanState, *, compressed_size: int | None = None) -> None:
    if (
        compressed_size is not None
        and size > max(1, compressed_size) * state.limits.max_archive_ratio
    ):
        _fail("capsule_limit_exceeded")
    state.archive_members += 1
    state.archive_bytes += size
    if (
        state.archive_members > state.limits.max_archive_members
        or size > state.limits.max_file_bytes
        or state.archive_bytes > state.limits.max_archive_unpacked_bytes
    ):
        _fail("capsule_limit_exceeded")


def _zip_eocd(payload: bytes) -> int:
    signature = b"PK\x05\x06"
    positions: list[int] = []
    offset = 0
    while True:
        offset = payload.find(signature, offset)
        if offset < 0:
            break
        positions.append(offset)
        offset += 1
    if len(positions) != 1:
        return -1
    eocd = positions[0]
    if eocd < max(0, len(payload) - 65_557) or eocd + 22 > len(payload):
        return -1
    try:
        comment_size = struct.unpack_from("<H", payload, eocd + 20)[0]
    except struct.error:
        return -1
    return eocd if eocd + 22 + comment_size == len(payload) else -1


def _scan_zip(payload: bytes, state: _ScanState, depth: int) -> None:
    eocd = _zip_eocd(payload)
    if eocd < 0:
        _fail("capsule_archive_invalid")
    try:
        disk, central_disk, disk_count, member_count, central_size, central_offset, comment_size = (
            struct.unpack_from("<4H2LH", payload, eocd + 4)
        )
    except struct.error:
        _fail("capsule_archive_invalid")
    if (
        disk != 0
        or central_disk != 0
        or disk_count != member_count
        or member_count > state.limits.max_archive_members
        or member_count == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
        or central_offset + central_size > eocd
        or eocd + 22 + comment_size != len(payload)
    ):
        _fail(
            "capsule_limit_exceeded"
            if member_count > state.limits.max_archive_members
            else "capsule_archive_invalid"
        )
    zip_start = eocd - central_size - central_offset
    if zip_start < 0:
        _fail("capsule_archive_invalid")
    prefix = payload[:zip_start]
    if prefix and any(
        signature in prefix for signature in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    ):
        _fail("capsule_archive_invalid")
    embedded_offset = _embedded_supported_archive_offset(prefix)
    if embedded_offset is not None:
        _scan_payload(
            prefix[embedded_offset:],
            "zip-prefix.archive",
            state,
            depth + 1,
        )
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            _scan_bytes(archive.comment, state)
            names: set[str] = set()
            members = archive.infolist()
            if len(members) != member_count:
                _fail("capsule_archive_invalid")
            for member in members:
                normalized = "/".join(_archive_name(member.filename, state)).casefold()
                if normalized in names:
                    _fail("capsule_archive_invalid")
                names.add(normalized)
                _scan_bytes(member.comment + member.extra, state)
                if member.flag_bits & 1:
                    _fail("capsule_archive_invalid")
                mode = (member.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if file_type and file_type not in {stat.S_IFREG, stat.S_IFDIR}:
                    _fail("capsule_archive_invalid")
                if member.is_dir():
                    _account_archive(0, state)
                    continue
                _account_archive(
                    member.file_size,
                    state,
                    compressed_size=member.compress_size,
                )
                with archive.open(member) as source:
                    child = _read_bounded(source, member.file_size, state.limits.max_file_bytes)
                _scan_payload(child, member.filename, state, depth + 1)
    except CapsuleContractError:
        raise
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, NotImplementedError):
        _fail("capsule_archive_invalid")


def _scan_tar(payload: bytes, state: _ScanState, depth: int) -> bool:
    opened = False
    unpacked_total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            opened = True
            names: set[str] = set()
            for member in archive:
                normalized = "/".join(_archive_name(member.name, state)).casefold()
                if normalized in names:
                    _fail("capsule_archive_invalid")
                names.add(normalized)
                metadata = "\n".join(
                    (
                        member.uname,
                        member.gname,
                        member.linkname,
                        *member.pax_headers.keys(),
                        *member.pax_headers.values(),
                    )
                ).encode("utf-8", "strict")
                _scan_bytes(metadata, state)
                if member.isdir():
                    _account_archive(0, state)
                    continue
                if not member.isreg():
                    _fail("capsule_archive_invalid")
                unpacked_total += member.size
                if unpacked_total > max(1, len(payload)) * state.limits.max_archive_ratio:
                    _fail("capsule_limit_exceeded")
                _account_archive(member.size, state, compressed_size=len(payload))
                source = archive.extractfile(member)
                if source is None:
                    _fail("capsule_archive_invalid")
                with source:
                    child = _read_bounded(source, member.size, state.limits.max_file_bytes)
                _scan_payload(child, member.name, state, depth + 1)
            return True
    except CapsuleContractError:
        raise
    except (UnicodeError, tarfile.TarError, OSError, EOFError, lzma.LZMAError):
        if not opened:
            return False
        _fail("capsule_archive_invalid")


def _decompress_single(payload: bytes, name: str, state: _ScanState, depth: int) -> bool:
    factories: tuple[tuple[bool, Any], ...] = (
        (payload.startswith(b"\x1f\x8b"), gzip.GzipFile),
        (payload.startswith(b"BZh"), None),
        (payload.startswith(b"\xfd7zXZ\x00"), None),
    )
    matched = next((factory for condition, factory in factories if condition), False)
    if matched is False:
        return False
    try:
        if matched is gzip.GzipFile:
            with gzip.GzipFile(fileobj=io.BytesIO(payload)) as source:
                child = source.read(state.limits.max_file_bytes + 1)
        elif payload.startswith(b"BZh"):
            decompressor = bz2.BZ2Decompressor()
            child = decompressor.decompress(payload, max_length=state.limits.max_file_bytes + 1)
            if len(child) > state.limits.max_file_bytes:
                _fail("capsule_limit_exceeded")
            if not decompressor.eof or decompressor.unused_data:
                _fail("capsule_archive_invalid")
        else:
            decompressor = lzma.LZMADecompressor(
                format=lzma.FORMAT_AUTO,
                memlimit=min(
                    _SCAN_WORKER_MEMORY_BYTES // 2,
                    max(16 * 1024 * 1024, state.limits.max_file_bytes * 2),
                ),
            )
            child = decompressor.decompress(payload, max_length=state.limits.max_file_bytes + 1)
            if len(child) > state.limits.max_file_bytes:
                _fail("capsule_limit_exceeded")
            if not decompressor.eof or decompressor.unused_data:
                _fail("capsule_archive_invalid")
    except (OSError, EOFError, ValueError, lzma.LZMAError):
        _fail("capsule_archive_invalid")
    if len(child) > state.limits.max_file_bytes:
        _fail("capsule_limit_exceeded")
    _account_archive(len(child), state, compressed_size=len(payload))
    _scan_payload(child, name.rsplit(".", 1)[0], state, depth + 1)
    return True


def _looks_like_tar_at(payload: bytes, offset: int = 0) -> bool:
    if offset < 0 or len(payload) - offset < 512:
        return False
    header = payload[offset : offset + 512]
    if header == b"\x00" * 512:
        return False
    try:
        recorded = int(header[148:156].rstrip(b"\x00 ") or b"0", 8)
    except ValueError:
        return False
    calculated = sum(header[:148]) + (8 * 32) + sum(header[156:])
    return recorded == calculated


def _looks_like_tar(payload: bytes) -> bool:
    return _looks_like_tar_at(payload)


def _embedded_supported_archive_offset(payload: bytes) -> int | None:
    """Find a supported archive hidden behind an arbitrary bounded prefix."""

    offsets = [
        offset
        for signature in _SINGLE_STREAM_ARCHIVE_SIGNATURES
        if (offset := payload.find(signature)) >= 0
    ]
    for match in _TAR_CHECKSUM.finditer(payload):
        offset = match.start() - 148
        if offset >= 0 and _looks_like_tar_at(payload, offset):
            offsets.append(offset)
            break
    return min(offsets) if offsets else None


def _has_unsupported_archive_signature(payload: bytes) -> bool:
    if any(signature in payload for signature in _UNSUPPORTED_ARCHIVE_SIGNATURES):
        return True
    return len(payload) >= 32_774 and payload[32_769:32_774] == b"CD001"


def _scan_payload(payload: bytes, name: str, state: _ScanState, depth: int = 0) -> None:
    _scan_bytes(name.encode("utf-8", "strict"), state)
    _scan_bytes(payload, state)
    if _has_unsupported_archive_signature(payload):
        _fail("capsule_archive_invalid")
    archive_extensions = (
        ".zip",
        ".tar",
        ".tgz",
        ".tbz",
        ".tbz2",
        ".txz",
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".cab",
        ".wim",
        ".cpio",
        ".xar",
        ".iso",
    )
    zip_eocd = _zip_eocd(payload)
    zip_signature = any(
        signature in payload for signature in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    )
    embedded_offset = _embedded_supported_archive_offset(payload)
    compressed = payload.startswith(_SINGLE_STREAM_ARCHIVE_SIGNATURES)
    archive_like = (
        zip_signature
        or _looks_like_tar(payload)
        or compressed
        or name.casefold().endswith(archive_extensions)
    )
    if not archive_like:
        if embedded_offset is not None and embedded_offset > 0:
            if depth >= state.limits.max_archive_depth:
                _fail("capsule_limit_exceeded")
            _scan_payload(payload[embedded_offset:], f"{name}.embedded", state, depth + 1)
        return
    if depth >= state.limits.max_archive_depth:
        _fail("capsule_limit_exceeded")
    if zip_signature and zip_eocd < 0:
        _fail("capsule_archive_invalid")
    if zip_eocd >= 0:
        _scan_zip(payload, state, depth)
        return
    if not compressed and _scan_tar(payload, state, depth):
        return
    if _decompress_single(payload, name, state, depth):
        return
    _fail("capsule_archive_invalid")


def _scan_request(
    payload: bytes,
    name: str,
    state: _ScanState,
    canaries: Sequence[bytes],
    forbidden_markers: Sequence[bytes],
) -> bytes:
    header = {
        "worker_version": CAPSULE_SCAN_WORKER_VERSION,
        "name": name,
        "canaries": [value.hex() for value in canaries],
        "forbidden_markers": [value.hex() for value in forbidden_markers],
        "limits": {
            "max_files": state.limits.max_files,
            "max_file_bytes": state.limits.max_file_bytes,
            "max_total_bytes": state.limits.max_total_bytes,
            "max_archive_members": state.limits.max_archive_members,
            "max_archive_unpacked_bytes": state.limits.max_archive_unpacked_bytes,
            "max_archive_depth": state.limits.max_archive_depth,
            "max_archive_ratio": state.limits.max_archive_ratio,
        },
    }
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(header_bytes) > _SCAN_WORKER_MAX_HEADER:
        _fail("scanner_registration_invalid")
    return struct.pack(">Q", len(header_bytes)) + header_bytes + payload


def _bounded_process(
    argv: Sequence[str],
    *,
    input_data: bytes = b"",
    deadline_seconds: float = _OCI_COMMAND_DEADLINE_SECONDS,
    output_limit: int = _OCI_OUTPUT_LIMIT,
) -> tuple[int, bytes]:
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    output = bytearray()
    deadline = time.monotonic() + deadline_seconds
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            close_fds=True,
            start_new_session=True,
        )
        if process.stdin is None or process.stdout is None:
            _fail("isolation_adapter_failed")
        stdin_fd = process.stdin.fileno()
        stdout_fd = process.stdout.fileno()
        os.set_blocking(stdin_fd, False)
        os.set_blocking(stdout_fd, False)
        selector.register(stdout_fd, selectors.EVENT_READ)
        if input_data:
            selector.register(stdin_fd, selectors.EVENT_WRITE)
        else:
            process.stdin.close()
        offset = 0
        stdout_open = True
        while stdout_open or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("isolation_adapter_failed")
            for key, mask in selector.select(min(remaining, 0.1)):
                if key.fd == stdin_fd and mask & selectors.EVENT_WRITE:
                    try:
                        written = os.write(stdin_fd, input_data[offset : offset + 64 * 1024])
                    except BrokenPipeError:
                        selector.unregister(stdin_fd)
                        process.stdin.close()
                    else:
                        offset += written
                        if offset == len(input_data):
                            selector.unregister(stdin_fd)
                            process.stdin.close()
                elif key.fd == stdout_fd and mask & selectors.EVENT_READ:
                    chunk = os.read(stdout_fd, min(64 * 1024, output_limit + 1 - len(output)))
                    if chunk:
                        output.extend(chunk)
                        if len(output) > output_limit:
                            _fail("isolation_adapter_failed")
                    else:
                        selector.unregister(stdout_fd)
                        stdout_open = False
            if process.poll() is not None and stdout_open:
                chunk = os.read(stdout_fd, output_limit + 1 - len(output))
                if chunk:
                    output.extend(chunk)
                    if len(output) > output_limit:
                        _fail("isolation_adapter_failed")
                else:
                    selector.unregister(stdout_fd)
                    stdout_open = False
        return process.returncode, bytes(output)
    except CapsuleContractError:
        raise
    except (OSError, ValueError, subprocess.SubprocessError):
        _fail("isolation_adapter_failed")
    finally:
        selector.close()
        reaped = True
        if process is not None:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    try:
                        process.kill()
                    except OSError:
                        pass
            try:
                process.wait(timeout=1.0)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                    process.wait(timeout=1.0)
                except (OSError, subprocess.TimeoutExpired):
                    reaped = False
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        if not reaped:
            _fail("isolation_adapter_failed")


def _validate_docker_binary(path: Path) -> None:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError:
        _fail("isolation_adapter_invalid")
    if (
        path.name != "docker"
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o022
        or not metadata.st_mode & 0o111
    ):
        _fail("isolation_adapter_invalid")


def _docker(
    adapter: CapsuleOciAdapter, *arguments: str, input_data: bytes = b"", scan: bool = False
) -> tuple[int, bytes]:
    return _bounded_process(
        (str(adapter.docker_path), *arguments),
        input_data=input_data,
        deadline_seconds=_OCI_SCAN_DEADLINE_SECONDS if scan else _OCI_COMMAND_DEADLINE_SECONDS,
        output_limit=_SCAN_WORKER_MAX_OUTPUT if scan else _OCI_OUTPUT_LIMIT,
    )


def _inspect_owned_oci_scanner(
    adapter: CapsuleOciAdapter,
    container_id: str,
    *,
    container_name: str,
    operation_id: str,
) -> bool:
    format_value = (
        "{{.Id}}|"
        '{{index .Config.Labels "rapido.offline-capsule"}}|'
        '{{index .Config.Labels "rapido.offline-capsule-source"}}|'
        '{{index .Config.Labels "rapido.offline-capsule-operation"}}|'
        "{{.Image}}|{{.Name}}|{{json .HostConfig.Tmpfs}}|{{json .Mounts}}"
    )
    inspect_code, inspect_output = _docker(
        adapter, "container", "inspect", "--format", format_value, container_id
    )
    try:
        observed = inspect_output.strip().decode("ascii", "strict")
        (
            inspected_id,
            owner,
            source,
            operation,
            image,
            observed_name,
            tmpfs_json,
            mounts_json,
        ) = observed.split("|", 7)
        tmpfs = json.loads(tmpfs_json)
        mounts = json.loads(mounts_json)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return False
    expected_tmpfs = {
        "/tmp": "rw,noexec,nosuid,nodev,size=16m",
        "/state": "rw,noexec,nosuid,nodev,size=1m,mode=0700",
        "/auth/codex": "rw,noexec,nosuid,nodev,size=1m,mode=0700",
    }
    return (
        inspect_code == 0
        and inspected_id == container_id
        and owner == "scan-v1"
        and source == adapter.source_sha256
        and operation == operation_id
        and image == adapter.image_id
        and observed_name == f"/{container_name}"
        and isinstance(mounts, list)
        and not mounts
        and tmpfs == expected_tmpfs
    )


def _enumerate_oci_scanners(
    adapter: CapsuleOciAdapter,
    *,
    owner_label: str,
    source_label: str,
    operation_label: str,
) -> tuple[bool, tuple[str, ...]]:
    code, output = _docker(
        adapter,
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--filter",
        f"label={owner_label}",
        "--filter",
        f"label={source_label}",
        "--filter",
        f"label={operation_label}",
        "--format",
        "{{.ID}}",
    )
    try:
        ids = tuple(line for line in output.decode("ascii", "strict").splitlines() if line)
    except UnicodeDecodeError:
        return False, ()
    return code == 0 and len(ids) == len(set(ids)) and all(
        _CONTAINER_ID.fullmatch(i) for i in ids
    ), ids


def _scan_in_oci(
    adapter: CapsuleOciAdapter,
    payload: bytes,
    name: str,
    state: _ScanState,
    canaries: Sequence[bytes],
    forbidden_markers: Sequence[bytes],
) -> None:
    _validate_docker_binary(adapter.docker_path)
    returncode, output = _docker(
        adapter, "image", "inspect", "--format", "{{.Id}}", adapter.image_id
    )
    try:
        inspected_image = output.strip().decode("ascii", "strict")
    except UnicodeDecodeError:
        _fail("isolation_adapter_failed")
    if returncode != 0 or inspected_image != adapter.image_id:
        _fail("isolation_adapter_failed")
    container_name = f"rapido-capsule-scan-{secrets.token_hex(12)}"
    owner_label = "rapido.offline-capsule=scan-v1"
    source_label = f"rapido.offline-capsule-source={adapter.source_sha256}"
    operation_id = secrets.token_hex(16)
    operation_label = f"rapido.offline-capsule-operation={operation_id}"
    create_attempted = False
    container_id: str | None = None
    cleanup_failed = False
    result: dict[str, Any] | None = None
    try:
        create_argv = (
            "container",
            "create",
            "--name",
            container_name,
            "--interactive",
            "--label",
            owner_label,
            "--label",
            source_label,
            "--label",
            operation_label,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--memory",
            "1g",
            "--memory-swap",
            "1g",
            "--cpus",
            "1",
            "--pids-limit",
            "8",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "--tmpfs",
            "/state:rw,noexec,nosuid,nodev,size=1m,mode=0700",
            "--tmpfs",
            "/auth/codex:rw,noexec,nosuid,nodev,size=1m,mode=0700",
            "--ulimit",
            "cpu=3:3",
            "--ulimit",
            "nofile=32:32",
            "--user",
            "65534:65534",
            "--stop-timeout",
            "1",
            "--entrypoint",
            "/opt/venv/bin/python",
            adapter.image_id,
            "-I",
            "-B",
            "-m",
            "rapido.offline_capsule",
            _SCAN_WORKER_ARGUMENT,
        )
        create_attempted = True
        returncode, created_output = _docker(adapter, *create_argv)
        if returncode != 0:
            _fail("isolation_adapter_failed")
        try:
            observed_id = created_output.strip().decode("ascii", "strict")
        except UnicodeDecodeError:
            _fail("isolation_adapter_failed")
        if _CONTAINER_ID.fullmatch(observed_id) is None:
            _fail("isolation_adapter_failed")
        container_id = observed_id
        request = _scan_request(payload, name, state, canaries, forbidden_markers)
        returncode, output = _docker(
            adapter,
            "container",
            "start",
            "--attach",
            "--interactive",
            container_id,
            input_data=request,
            scan=True,
        )
        if returncode != 0:
            _fail("capsule_scan_worker_failed")
        if len(output) > _SCAN_WORKER_MAX_OUTPUT:
            _fail("capsule_scan_worker_failed")
        try:
            parsed = json.loads(output)
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("capsule_scan_worker_failed")
        if isinstance(parsed, dict):
            result = parsed
        else:
            _fail("capsule_scan_worker_failed")
    finally:
        if create_attempted:
            enumeration_ok, enumerated_ids = _enumerate_oci_scanners(
                adapter,
                owner_label=owner_label,
                source_label=source_label,
                operation_label=operation_label,
            )
            if not enumeration_ok:
                cleanup_failed = True
            candidate_ids = set(enumerated_ids)
            if container_id is not None:
                candidate_ids.add(container_id)
            for selected_id in sorted(candidate_ids):
                owned = _inspect_owned_oci_scanner(
                    adapter,
                    selected_id,
                    container_name=container_name,
                    operation_id=operation_id,
                )
                if owned:
                    _docker(adapter, "container", "kill", selected_id)
                    remove_code, _remove_output = _docker(
                        adapter, "container", "rm", "--force", "--volumes", selected_id
                    )
                    if remove_code != 0:
                        cleanup_failed = True
                else:
                    cleanup_failed = True
                id_absent_code, id_absent_output = _docker(
                    adapter,
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--filter",
                    f"id={selected_id}",
                    "--format",
                    "{{.ID}}",
                )
                if id_absent_code != 0 or id_absent_output.strip():
                    cleanup_failed = True
            labels_absent_ok, remaining_ids = _enumerate_oci_scanners(
                adapter,
                owner_label=owner_label,
                source_label=source_label,
                operation_label=operation_label,
            )
            if not labels_absent_ok or remaining_ids:
                cleanup_failed = True
            name_absent_code, name_absent_output = _docker(
                adapter,
                "container",
                "ls",
                "--all",
                "--filter",
                f"name=^{container_name}$",
                "--format",
                "{{.Names}}",
            )
            if name_absent_code != 0 or name_absent_output.strip():
                cleanup_failed = True
        if cleanup_failed:
            _fail("capsule_cleanup_failed")
    if result is None:
        _fail("capsule_scan_worker_failed")
    if set(result) not in (
        {"status", "code"},
        {
            "status",
            "worker_version",
            "source_sha256",
            "archive_members",
            "archive_bytes",
        },
    ):
        _fail("capsule_scan_worker_failed")
    if result.get("status") == "failed":
        code = result.get("code")
        if code in {
            "capsule_archive_invalid",
            "capsule_contaminated",
            "capsule_limit_exceeded",
            "capsule_path_invalid",
        }:
            _fail(code)
        _fail("capsule_scan_worker_failed")
    if (
        result.get("status") != "passed"
        or result.get("worker_version") != CAPSULE_SCAN_WORKER_VERSION
        or result.get("source_sha256") != adapter.source_sha256
        or type(result.get("archive_members")) is not int
        or type(result.get("archive_bytes")) is not int
        or result["archive_members"] < 0
        or result["archive_bytes"] < 0
    ):
        _fail("capsule_scan_worker_failed")
    state.archive_members += result["archive_members"]
    state.archive_bytes += result["archive_bytes"]
    if (
        state.archive_members > state.limits.max_archive_members
        or state.archive_bytes > state.limits.max_archive_unpacked_bytes
    ):
        _fail("capsule_limit_exceeded")


def _worker_apply_limits() -> bool:
    try:
        import resource

        resource.setrlimit(
            resource.RLIMIT_CPU, (_SCAN_WORKER_CPU_SECONDS, _SCAN_WORKER_CPU_SECONDS)
        )
        resource.setrlimit(
            resource.RLIMIT_AS, (_SCAN_WORKER_MEMORY_BYTES, _SCAN_WORKER_MEMORY_BYTES)
        )
        resource.setrlimit(resource.RLIMIT_NPROC, (_SCAN_WORKER_PIDS, _SCAN_WORKER_PIDS))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (AttributeError, OSError, ValueError):
        return False
    return True


def _scan_worker_main() -> int:
    limits_applied = _worker_apply_limits()
    try:
        source_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        prefix = sys.stdin.buffer.read(8)
        if len(prefix) != 8:
            _fail("capsule_scan_worker_failed")
        header_size = struct.unpack(">Q", prefix)[0]
        if header_size > _SCAN_WORKER_MAX_HEADER:
            _fail("capsule_scan_worker_failed")
        header_bytes = sys.stdin.buffer.read(header_size)
        if len(header_bytes) != header_size:
            _fail("capsule_scan_worker_failed")
        header = json.loads(header_bytes)
        expected = {"worker_version", "name", "canaries", "forbidden_markers", "limits"}
        if not isinstance(header, dict) or set(header) != expected:
            _fail("capsule_scan_worker_failed")
        if header.get("worker_version") != CAPSULE_SCAN_WORKER_VERSION:
            _fail("capsule_scan_worker_failed")
        limit_values = header.get("limits")
        if not isinstance(limit_values, dict) or set(limit_values) != {
            "max_files",
            "max_file_bytes",
            "max_total_bytes",
            "max_archive_members",
            "max_archive_unpacked_bytes",
            "max_archive_depth",
            "max_archive_ratio",
        }:
            _fail("capsule_scan_worker_failed")
        limits = CapsuleLimits(**limit_values)
        limits.validate()
        payload = sys.stdin.buffer.read(limits.max_file_bytes + 1)
        if len(payload) > limits.max_file_bytes:
            _fail("capsule_limit_exceeded")
        if not limits_applied:
            _fail("capsule_scan_worker_failed")
        canaries = tuple(bytes.fromhex(value) for value in header["canaries"])
        forbidden_markers = tuple(bytes.fromhex(value) for value in header["forbidden_markers"])
        marker_pattern = _marker_pattern(canaries, forbidden_markers)
        state = _ScanState(limits, marker_pattern)
        name = header.get("name")
        if type(name) is not str:
            _fail("capsule_scan_worker_failed")
        _scan_payload(payload, name, state)
        result = {
            "status": "passed",
            "worker_version": CAPSULE_SCAN_WORKER_VERSION,
            "source_sha256": source_sha256,
            "archive_members": state.archive_members,
            "archive_bytes": state.archive_bytes,
        }
    except CapsuleContractError as error:
        result = {"status": "failed", "code": error.code}
    except BaseException:  # noqa: BLE001 - worker must emit only a closed status
        result = {"status": "failed", "code": "capsule_scan_worker_failed"}
    output = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(output) > _SCAN_WORKER_MAX_OUTPUT:
        return 1
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    return 0


def _validate_task(task: CapsuleTask, state: _ScanState) -> None:
    if type(task) is not CapsuleTask:
        _fail("registration_invalid")
    if type(task.board_id) is not int or not 0 < task.board_id <= 2**31 - 1:
        _fail("registration_invalid")
    _identifier(task.task_id, _TASK_ID)
    _identifier(task.family_id, _FAMILY_ID)
    if (
        type(task.category) is not str
        or type(task.assignment) is not str
        or task.category not in _CATEGORIES
        or task.assignment not in _ASSIGNMENTS
    ):
        _fail("registration_invalid")
    if (
        type(task.tier) is not str
        or type(task.form) is not str
        or task.tier not in {"A", "sentinel"}
        or task.form not in _FORMS
    ):
        _fail("registration_invalid")
    if task.assignment == "sentinel" and task.tier != "sentinel":
        _fail("registration_invalid")
    if task.assignment != "sentinel" and task.tier != "A":
        _fail("registration_invalid")
    if (
        type(task.description) is not str
        or not task.description
        or unicodedata.normalize("NFC", task.description) != task.description
        or any(
            unicodedata.category(character).startswith("C") and character not in {"\n", "\r", "\t"}
            for character in task.description
        )
    ):
        _fail("registration_invalid")
    try:
        description = task.description.encode("utf-8", "strict")
    except UnicodeError:
        _fail("registration_invalid")
    if len(description) > 256 * 1024:
        _fail("registration_invalid")
    _scan_bytes(description, state)
    if type(task.files) is not tuple or len(task.files) > state.limits.max_files:
        _fail("registration_invalid")
    normalized = tuple("/".join(_relative_path(value)) for value in task.files)
    if len(set(normalized)) != len(normalized):
        _fail("registration_invalid")
    for value in (
        task.generator_version,
        task.checker_version,
        task.private_scan_version,
        task.resource_profile_id,
    ):
        _version(value)
    if type(task.service_version) is not str:
        _fail("registration_invalid")
    if task.form == "static":
        if task.service_version != "none" or task.service_required is not False:
            _fail("registration_invalid")
    else:
        _version(task.service_version)
        if task.service_required is not True:
            _fail("registration_invalid")
    if task.service_version != "none" and _PLACEHOLDER_VERSION.search(task.service_version):
        _fail("registration_invalid")
    _scan_bytes(
        (
            f"{task.task_id}\n{task.family_id}\n{task.category}\n{task.assignment}\n"
            f"{task.tier}\n{task.form}\n{task.generator_version}\n{task.checker_version}\n"
            f"{task.private_scan_version}\n"
            f"{task.service_version}\n{task.resource_profile_id}"
        ).encode(),
        state,
    )
    if type(task.service_required) is not bool:
        _fail("registration_invalid")
    if type(task.admission) is not AdmissionAttestation:
        _fail("admission_incomplete")
    task.admission.validate()


def _validate_exclusion(value: CapsuleExclusion, state: _ScanState) -> None:
    _identifier(value.task_id, _TASK_ID)
    _identifier(value.family_id, _FAMILY_ID)
    if (
        type(value.category) is not str
        or type(value.assignment) is not str
        or type(value.tier) is not str
        or type(value.code) is not str
        or value.category not in _CATEGORIES
        or value.assignment not in _ASSIGNMENTS
        or value.tier not in _TIERS
        or value.code not in EXCLUSION_CODES
    ):
        _fail("registration_invalid")
    _scan_bytes(
        (
            f"{value.task_id}\n{value.family_id}\n{value.category}\n{value.assignment}\n"
            f"{value.tier}\n{value.code}"
        ).encode("ascii"),
        state,
    )


def _read_source(root: int, file_ref: str, limit: int) -> bytes:
    descriptor = os.dup(root)
    try:
        parts = _relative_path(file_ref)
        for part in parts[:-1]:
            child = _open_child_directory(descriptor, part)
            os.close(descriptor)
            descriptor = child
        source = -1
        try:
            before = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or before.st_mode & 0o077
            ):
                _fail("capsule_source_invalid")
            if before.st_size > limit:
                _fail("capsule_limit_exceeded")
            source = os.open(
                parts[-1],
                os.O_RDONLY | _NOFOLLOW | _NONBLOCK | _CLOEXEC,
                dir_fd=descriptor,
            )
            after_open = os.fstat(source)
        except OSError:
            if source >= 0:
                os.close(source)
            _fail("capsule_source_invalid")
        try:
            if (
                _Identity.from_stat(before) != _Identity.from_stat(after_open)
                or not stat.S_ISREG(after_open.st_mode)
                or after_open.st_uid != os.geteuid()
                or after_open.st_nlink != 1
            ):
                _fail("capsule_source_invalid")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(source, min(_COPY_CHUNK, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            final = os.fstat(source)
        finally:
            os.close(source)
        payload = b"".join(chunks)
        if len(payload) > limit:
            _fail("capsule_limit_exceeded")
        if (
            _Identity.from_stat(after_open) != _Identity.from_stat(final)
            or len(payload) != final.st_size
        ):
            _fail("capsule_source_invalid")
        return payload
    finally:
        os.close(descriptor)


def _write_file(root: int, file_ref: str, payload: bytes) -> None:
    descriptor = os.dup(root)
    try:
        parts = _relative_path(file_ref)
        for part in parts[:-1]:
            child = _ensure_child_directory(descriptor, part)
            os.close(descriptor)
            descriptor = child
        try:
            target = os.open(
                parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
                0o600,
                dir_fd=descriptor,
            )
            offset = 0
            while offset < len(payload):
                written = os.write(target, payload[offset : offset + _COPY_CHUNK])
                if written <= 0:
                    _fail("capsule_destination_invalid")
                offset += written
            os.fsync(target)
            metadata = os.fstat(target)
        except OSError:
            _fail("capsule_destination_invalid")
        finally:
            if "target" in locals():
                os.close(target)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
        ):
            _fail("capsule_destination_invalid")
    finally:
        os.close(descriptor)


def _write_json(root: int, name: str, value: Mapping[str, Any]) -> None:
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    _write_file(root, name, payload)


def _quarantine_remove_entry(
    parent: int,
    name: str,
    descriptor: int,
    *,
    directory: bool,
    failure_code: str = "capsule_cleanup_failed",
) -> None:
    """Move one pinned entry into an unpredictable private quarantine before removal.

    POSIX removal remains name-based.  This boundary assumes no untrusted same-EUID host code;
    every observable substitution before the final syscall is detected after the atomic move and
    preserved inside the quarantine.
    """

    quarantine = -1
    quarantine_name = f".rapido-delete-{secrets.token_hex(12)}"
    try:
        os.mkdir(quarantine_name, mode=0o700, dir_fd=parent)
        quarantine_before = os.stat(quarantine_name, dir_fd=parent, follow_symlinks=False)
        quarantine = os.open(
            quarantine_name,
            os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
            dir_fd=parent,
        )
        quarantine_after = os.fstat(quarantine)
        if (
            not stat.S_ISDIR(quarantine_before.st_mode)
            or quarantine_before.st_uid != os.geteuid()
            or quarantine_before.st_mode & 0o077
            or _Identity.from_stat(quarantine_before) != _Identity.from_stat(quarantine_after)
        ):
            _fail(failure_code)
        quarantine_identity = _Identity.from_stat(quarantine_after)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        current = os.fstat(descriptor)
        if _Identity.from_stat(named) != _Identity.from_stat(current):
            _fail(failure_code)
        os.rename(name, "victim", src_dir_fd=parent, dst_dir_fd=quarantine)
        moved = os.stat("victim", dir_fd=quarantine, follow_symlinks=False)
        current = os.fstat(descriptor)
        if _Identity.from_stat(moved) != _Identity.from_stat(current):
            _fail(failure_code)
        if directory:
            if os.listdir(descriptor):
                _fail(failure_code)
            final_named = os.stat("victim", dir_fd=quarantine, follow_symlinks=False)
            final_current = os.fstat(descriptor)
            if _Identity.from_stat(final_named) != _Identity.from_stat(final_current):
                _fail(failure_code)
            os.rmdir("victim", dir_fd=quarantine)
            if not _directory_descriptor_is_unlinked(descriptor):
                _fail(failure_code)
        else:
            final_named = os.stat("victim", dir_fd=quarantine, follow_symlinks=False)
            final_current = os.fstat(descriptor)
            if _Identity.from_stat(final_named) != _Identity.from_stat(final_current):
                _fail(failure_code)
            os.unlink("victim", dir_fd=quarantine)
            if os.fstat(descriptor).st_nlink != 0:
                _fail(failure_code)
        if os.listdir(quarantine):
            _fail(failure_code)
        named_quarantine = os.stat(quarantine_name, dir_fd=parent, follow_symlinks=False)
        current_quarantine = os.fstat(quarantine)
        if (
            not _same_inode(named_quarantine, quarantine_identity)
            or not _same_inode(current_quarantine, quarantine_identity)
            or named_quarantine.st_mode != quarantine_identity.mode
            or current_quarantine.st_mode != quarantine_identity.mode
            or named_quarantine.st_uid != quarantine_identity.uid
            or current_quarantine.st_uid != quarantine_identity.uid
        ):
            _fail(failure_code)
        os.rmdir(quarantine_name, dir_fd=parent)
        if not _directory_descriptor_is_unlinked(quarantine):
            _fail(failure_code)
    except CapsuleContractError:
        raise
    except OSError:
        _fail(failure_code)
    finally:
        if quarantine >= 0:
            os.close(quarantine)


def _remove_tree(descriptor: int) -> None:
    for name in os.listdir(descriptor):
        try:
            before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            _fail("capsule_cleanup_failed")
        if stat.S_ISDIR(before.st_mode):
            if before.st_uid != os.geteuid() or before.st_mode & 0o077:
                _fail("capsule_cleanup_failed")
            child = -1
            try:
                child = os.open(
                    name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC, dir_fd=descriptor
                )
                opened = os.fstat(child)
                if _Identity.from_stat(before) != _Identity.from_stat(opened):
                    _fail("capsule_cleanup_failed")
                _remove_tree(child)
                _quarantine_remove_entry(descriptor, name, child, directory=True)
            except CapsuleContractError:
                raise
            except OSError:
                _fail("capsule_cleanup_failed")
            finally:
                if child >= 0:
                    os.close(child)
        elif stat.S_ISREG(before.st_mode):
            if before.st_uid != os.geteuid() or before.st_nlink != 1 or before.st_mode & 0o077:
                _fail("capsule_cleanup_failed")
            child = -1
            try:
                child = os.open(
                    name, os.O_RDONLY | _NOFOLLOW | _NONBLOCK | _CLOEXEC, dir_fd=descriptor
                )
                opened = os.fstat(child)
                if _Identity.from_stat(before) != _Identity.from_stat(opened):
                    _fail("capsule_cleanup_failed")
                named = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if _Identity.from_stat(named) != _Identity.from_stat(opened):
                    _fail("capsule_cleanup_failed")
                _quarantine_remove_entry(descriptor, name, child, directory=False)
            except CapsuleContractError:
                raise
            except OSError:
                _fail("capsule_cleanup_failed")
            finally:
                if child >= 0:
                    os.close(child)
        else:
            _fail("capsule_cleanup_failed")


def remove_capsule_bank(bank_root: Path) -> None:
    """Remove one pinned owned bank; substitutions after pinning fail closed."""
    if (
        not isinstance(bank_root, Path)
        or not bank_root.is_absolute()
        or bank_root.name in {"", ".", ".."}
    ):
        _fail("capsule_cleanup_failed")
    parent = _pin_absolute_directory(bank_root.parent, "capsule_cleanup_failed")
    root = -1
    try:
        before = os.stat(bank_root.name, dir_fd=parent.descriptor, follow_symlinks=False)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o077
        ):
            _fail("capsule_cleanup_failed")
        root = os.open(
            bank_root.name,
            os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
            dir_fd=parent.descriptor,
        )
        opened = os.fstat(root)
        if _Identity.from_stat(before) != _Identity.from_stat(opened):
            _fail("capsule_cleanup_failed")
        if not parent.revalidate():
            _fail("capsule_cleanup_failed")
        after = os.stat(bank_root.name, dir_fd=parent.descriptor, follow_symlinks=False)
        if not _same_inode(after, opened):
            _fail("capsule_cleanup_failed")
        _remove_tree(root)
        if not parent.revalidate():
            _fail("capsule_cleanup_failed")
        _quarantine_remove_entry(
            parent.descriptor,
            bank_root.name,
            root,
            directory=True,
        )
        try:
            os.stat(bank_root.name, dir_fd=parent.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        _fail("capsule_cleanup_failed")
    except CapsuleContractError:
        raise
    except OSError:
        _fail("capsule_cleanup_failed")
    finally:
        if root >= 0:
            os.close(root)
        parent.close()


def validate_public_capsule_manifest(value: Any) -> None:
    """Reject path/payload/digest additions to the candidate-free public projection."""
    if not isinstance(value, Mapping):
        _fail("public_manifest_invalid")
    expected = {
        "schema",
        "exporter_version",
        "catalogue_version",
        "trust_zones",
        "admitted_task_count",
        "excluded_task_count",
        "admitted",
        "excluded",
    }
    if set(value) != expected:
        _fail("public_manifest_invalid")
    if (
        value.get("schema") != CAPSULE_EXPORT_SCHEMA
        or value.get("exporter_version") != CAPSULE_EXPORTER_VERSION
    ):
        _fail("public_manifest_invalid")
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        _fail("public_manifest_invalid")
    forbidden_keys = {
        "answer",
        "candidate",
        "candidate_digest",
        "checker_path",
        "description",
        "digest",
        "file",
        "files",
        "host_path",
        "oracle",
        "path",
        "payload",
        "seed",
        "source",
    }

    def walk(node: Any) -> None:
        if isinstance(node, Mapping):
            if any(key.casefold() in forbidden_keys for key in node if isinstance(key, str)):
                _fail("public_manifest_invalid")
            for item in node.values():
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str) and _PUBLIC_FORBIDDEN.search(node) is not None:
            _fail("public_manifest_invalid")

    walk(value)
    if _PUBLIC_FORBIDDEN.search(encoded) is not None:
        _fail("public_manifest_invalid")
    admitted = value.get("admitted")
    excluded = value.get("excluded")
    if not isinstance(admitted, list) or not isinstance(excluded, list):
        _fail("public_manifest_invalid")
    if (
        type(value.get("admitted_task_count")) is not int
        or type(value.get("excluded_task_count")) is not int
        or value.get("admitted_task_count") != len(admitted)
        or value.get("excluded_task_count") != len(excluded)
    ):
        _fail("public_manifest_invalid")
    if value.get("trust_zones") != {
        "curator_export": "allowlisted_only",
        "scored_runner_private_roots": "excluded",
        "controller_oracle": "excluded_from_capsule_export",
        "assignment_binding": "frozen_opaque_registry_exact_match",
        "private_full_scan": "frozen_opaque_registry_exact_match",
        "literal_scanner": "kernel_isolated_disposable_oci_worker_v1",
    }:
        _fail("public_manifest_invalid")
    if type(value.get("catalogue_version")) is not str:
        _fail("public_manifest_invalid")
    if (
        _VERSION.fullmatch(value["catalogue_version"]) is None
        or _DIGEST_VERSION.fullmatch(value["catalogue_version"]) is not None
        or _PLACEHOLDER_VERSION.search(value["catalogue_version"]) is not None
    ):
        _fail("public_manifest_invalid")
    admitted_fields = {
        "task_id",
        "family_id",
        "category",
        "assignment",
        "tier",
        "form",
        "status",
        "generator_version",
        "checker_version",
        "private_scan_version",
        "service_version",
        "resource_profile_id",
        "validation_seed_count",
        "reference_success",
        "negative_rejection",
        "semantic_stability",
        "provenance_recorded",
        "assignment_frozen",
        "checker_isolated",
        "cleanup_registered",
        "literal_scan_passed",
        "private_full_scan_attested",
    }
    exclusion_fields = {
        "task_id",
        "family_id",
        "category",
        "assignment",
        "tier",
        "status",
        "exclusion_code",
    }
    observed_ids: set[str] = set()
    for row in admitted:
        if not isinstance(row, Mapping) or set(row) != admitted_fields:
            _fail("public_manifest_invalid")
        task_id = row.get("task_id")
        family_id = row.get("family_id")
        if (
            type(task_id) is not str
            or _TASK_ID.fullmatch(task_id) is None
            or type(family_id) is not str
            or _FAMILY_ID.fullmatch(family_id) is None
            or task_id in observed_ids
            or row.get("category") not in _CATEGORIES
            or row.get("assignment") not in _ASSIGNMENTS
            or row.get("tier") not in {"A", "sentinel"}
            or row.get("form") not in _FORMS
            or row.get("status") != "admitted"
            or type(row.get("validation_seed_count")) is not int
            or row.get("validation_seed_count") != 3
            or (row.get("assignment") == "sentinel") != (row.get("tier") == "sentinel")
        ):
            _fail("public_manifest_invalid")
        observed_ids.add(task_id)
        for field in (
            "generator_version",
            "checker_version",
            "private_scan_version",
            "resource_profile_id",
        ):
            selected_version = row.get(field)
            if (
                type(selected_version) is not str
                or _VERSION.fullmatch(selected_version) is None
                or _DIGEST_VERSION.fullmatch(selected_version) is not None
                or _PLACEHOLDER_VERSION.search(selected_version) is not None
            ):
                _fail("public_manifest_invalid")
        if (
            type(row.get("service_version")) is not str
            or (row.get("form") == "static" and row.get("service_version") != "none")
            or (
                row.get("form") != "static"
                and (
                    _VERSION.fullmatch(row.get("service_version", "")) is None
                    or _DIGEST_VERSION.fullmatch(row.get("service_version", "")) is not None
                    or _PLACEHOLDER_VERSION.search(row.get("service_version", "")) is not None
                )
            )
        ):
            _fail("public_manifest_invalid")
        for field in (
            "reference_success",
            "negative_rejection",
            "semantic_stability",
            "provenance_recorded",
            "assignment_frozen",
            "checker_isolated",
            "cleanup_registered",
            "literal_scan_passed",
            "private_full_scan_attested",
        ):
            if type(row.get(field)) is not bool or row.get(field) is not True:
                _fail("public_manifest_invalid")
    for row in excluded:
        if not isinstance(row, Mapping) or set(row) != exclusion_fields:
            _fail("public_manifest_invalid")
        task_id = row.get("task_id")
        family_id = row.get("family_id")
        if (
            type(task_id) is not str
            or _TASK_ID.fullmatch(task_id) is None
            or type(family_id) is not str
            or _FAMILY_ID.fullmatch(family_id) is None
            or task_id in observed_ids
            or row.get("category") not in _CATEGORIES
            or row.get("assignment") not in _ASSIGNMENTS
            or row.get("tier") not in _TIERS
            or row.get("status") != "excluded"
            or row.get("exclusion_code") not in EXCLUSION_CODES
        ):
            _fail("public_manifest_invalid")
        observed_ids.add(task_id)


def export_capsule_bank(
    bank_root: Path,
    *,
    catalogue_version: str,
    tasks: Sequence[CapsuleInput],
    exclusions: Sequence[CapsuleExclusion] = (),
    canaries: Sequence[bytes],
    forbidden_markers: Sequence[bytes],
    isolation: CapsuleOciAdapter,
    limits: CapsuleLimits | None = None,
) -> dict[str, Any]:
    """Export one new private bank and return its candidate-free public manifest.

    ``canaries`` and ``forbidden_markers`` are private inputs and never appear in the return value.
    The destination must not exist and its parent must be an empty owner-only removable directory.
    Literal scanning runs only in the exact registered OCI image.  Private acceptance is an exact
    match against the adapter's frozen opaque registry; no caller isolation booleans are trusted.
    """
    if limits is None:
        limits = CapsuleLimits()
    if type(limits) is not CapsuleLimits:
        _fail("capsule_limit_invalid")
    if type(isolation) is not CapsuleOciAdapter:
        _fail("isolation_adapter_invalid")
    limits.validate()
    catalogue = _version(catalogue_version)
    if catalogue == "none":
        _fail("registration_invalid")
    if not isinstance(tasks, Sequence) or isinstance(tasks, (str, bytes, bytearray)) or not tasks:
        _fail("registration_invalid")
    if not isinstance(exclusions, Sequence) or isinstance(exclusions, (str, bytes, bytearray)):
        _fail("registration_invalid")
    selected = tuple(tasks)
    rejected = tuple(exclusions)
    if any(type(value) is not CapsuleInput for value in selected) or any(
        type(value) is not CapsuleExclusion for value in rejected
    ):
        _fail("registration_invalid")
    if len(selected) > 128:
        _fail("registration_invalid")
    _marker_pattern(canaries, forbidden_markers)
    base_forbidden_markers = tuple(forbidden_markers)
    commitment_values: list[bytes] = []
    namespace_values: set[bytes] = set()
    for value in selected:
        if type(value.commitments) is not PrivateTaskCommitments:
            _fail("private_attestation_invalid")
        value.commitments.validate()
        namespace_values.add(value.commitments.namespace.encode("ascii"))
        commitment_values.extend(
            (
                value.commitments.assignment,
                value.commitments.semantic,
                value.commitments.full_scan,
            )
        )
    if len(set(commitment_values)) != len(commitment_values):
        _fail("private_attestation_invalid")
    scan_forbidden_markers = (
        base_forbidden_markers
        + tuple(
            value.hex().encode("ascii") for value in (*tuple(canaries), *base_forbidden_markers)
        )
        + tuple(commitment_values)
        + tuple(value.hex().encode("ascii") for value in commitment_values)
        + tuple(sorted(namespace_values))
    )
    marker_pattern = _marker_pattern(canaries, scan_forbidden_markers)
    state = _ScanState(limits, marker_pattern)
    _scan_bytes(catalogue.encode("ascii"), state)
    for value in selected:
        _validate_task(value.task, state)
    for value in rejected:
        _validate_exclusion(value, state)
    task_ids = [value.task.task_id for value in selected] + [value.task_id for value in rejected]
    board_ids = [value.task.board_id for value in selected]
    if len(set(task_ids)) != len(task_ids) or len(set(board_ids)) != len(board_ids):
        _fail("registration_invalid")
    if (
        not isinstance(bank_root, Path)
        or not bank_root.is_absolute()
        or bank_root.name in {"", ".", ".."}
        or bank_root.exists()
    ):
        _fail("capsule_destination_invalid")
    try:
        unresolved_bank = bank_root.resolve(strict=False)
    except (OSError, RuntimeError):
        _fail("capsule_destination_invalid")
    for value in selected:
        try:
            source = value.source_root.resolve(strict=True)
        except (OSError, RuntimeError):
            _fail("private_boundary_invalid")
        if (
            source == unresolved_bank
            or source in unresolved_bank.parents
            or unresolved_bank in source.parents
        ):
            _fail("private_boundary_invalid")
    pinned_sources: list[_PinnedDirectory] = []
    prepared: list[tuple[CapsuleInput, tuple[tuple[str, bytes], ...]]] = []
    try:
        for value in selected:
            pinned_sources.append(
                _pin_absolute_directory(value.source_root, "private_boundary_invalid")
            )
        for value, pinned in zip(selected, pinned_sources, strict=True):
            payloads: list[tuple[str, bytes]] = []
            for file_ref in value.task.files:
                payload = _read_source(pinned.descriptor, file_ref, limits.max_file_bytes)
                state.direct_bytes += len(payload)
                if state.direct_bytes > limits.max_total_bytes:
                    _fail("capsule_limit_exceeded")
                _scan_in_oci(
                    isolation,
                    payload,
                    file_ref,
                    state,
                    canaries,
                    scan_forbidden_markers,
                )
                payloads.append((file_ref, payload))
            prepared.append((value, tuple(payloads)))
            isolation.verify_binding(value)
        for pinned in pinned_sources:
            if not pinned.revalidate(strict_final=True):
                _fail("capsule_source_invalid")
    except CapsuleContractError:
        for pinned in pinned_sources:
            pinned.close()
        raise
    except OSError:
        for pinned in pinned_sources:
            pinned.close()
        _fail("capsule_source_invalid")

    parent: _PinnedDirectory | None = None
    root = -1
    complete = False
    cleanup_failed = False
    try:
        parent = _prove_removable_parent(bank_root.parent)
        os.mkdir(bank_root.name, mode=0o700, dir_fd=parent.descriptor)
        root = _open_child_directory(parent.descriptor, bank_root.name)
        capsules = _open_child_directory(root, "capsules", create=True)
        catalogue_rows: list[dict[str, Any]] = []
        admitted_rows: list[dict[str, Any]] = []
        try:
            for value, payloads in prepared:
                task = value.task
                task_root = _open_child_directory(capsules, task.task_id, create=True)
                visible = _open_child_directory(task_root, "visible", create=True)
                try:
                    for file_ref, payload in payloads:
                        _write_file(visible, file_ref, payload)
                finally:
                    os.close(visible)
                    os.close(task_root)
                catalogue_rows.append(
                    {
                        "board_id": task.board_id,
                        "task_id": task.task_id,
                        "name": task.task_id,
                        "category": task.category,
                        "type": "dynamic_iac" if task.service_required else "standard",
                        "description": task.description,
                        "value": 100,
                        "files": list(task.files),
                        "solved": False,
                        "attempts": 0,
                        "max_attempts": None,
                        "timeout": None,
                        "shared": False,
                        "service_required": task.service_required,
                        "resource_profile_id": task.resource_profile_id,
                        "generator_version": task.generator_version,
                        "checker_version": task.checker_version,
                        "service_version": task.service_version,
                    }
                )
                admitted_rows.append(
                    {
                        "task_id": task.task_id,
                        "family_id": task.family_id,
                        "category": task.category,
                        "assignment": task.assignment,
                        "tier": task.tier,
                        "form": task.form,
                        "status": "admitted",
                        "generator_version": task.generator_version,
                        "checker_version": task.checker_version,
                        "private_scan_version": task.private_scan_version,
                        "service_version": task.service_version,
                        "resource_profile_id": task.resource_profile_id,
                        "validation_seed_count": task.admission.validation_seed_count,
                        "reference_success": True,
                        "negative_rejection": True,
                        "semantic_stability": True,
                        "provenance_recorded": True,
                        "assignment_frozen": True,
                        "checker_isolated": True,
                        "cleanup_registered": True,
                        "literal_scan_passed": True,
                        "private_full_scan_attested": True,
                    }
                )
        finally:
            os.close(capsules)
        excluded_rows = [
            {
                "task_id": value.task_id,
                "family_id": value.family_id,
                "category": value.category,
                "assignment": value.assignment,
                "tier": value.tier,
                "status": "excluded",
                "exclusion_code": value.code,
            }
            for value in rejected
        ]
        manifest: dict[str, Any] = {
            "schema": CAPSULE_EXPORT_SCHEMA,
            "exporter_version": CAPSULE_EXPORTER_VERSION,
            "catalogue_version": catalogue,
            "trust_zones": {
                "curator_export": "allowlisted_only",
                "scored_runner_private_roots": "excluded",
                "controller_oracle": "excluded_from_capsule_export",
                "assignment_binding": "frozen_opaque_registry_exact_match",
                "private_full_scan": "frozen_opaque_registry_exact_match",
                "literal_scanner": "kernel_isolated_disposable_oci_worker_v1",
            },
            "admitted_task_count": len(admitted_rows),
            "excluded_task_count": len(excluded_rows),
            "admitted": admitted_rows,
            "excluded": excluded_rows,
        }
        catalogue_projection = {"catalogue_version": catalogue, "tasks": catalogue_rows}
        for projection in (manifest, catalogue_projection):
            _scan_bytes(
                json.dumps(projection, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                state,
            )
        validate_public_capsule_manifest(manifest)
        for pinned in pinned_sources:
            if not pinned.revalidate(strict_final=True):
                _fail("capsule_source_invalid")
        _write_json(root, "public-readiness.json", manifest)
        _write_json(
            root,
            "public-catalogue.json",
            catalogue_projection,
        )
        if not parent.revalidate():
            _fail("capsule_destination_invalid")
        named = os.stat(bank_root.name, dir_fd=parent.descriptor, follow_symlinks=False)
        opened = os.fstat(root)
        if not _same_inode(named, opened):
            _fail("capsule_destination_invalid")
        complete = True
        return manifest
    except CapsuleContractError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        _fail("capsule_destination_invalid")
    finally:
        if root >= 0 and parent is not None:
            if not complete:
                try:
                    if not parent.revalidate():
                        _fail("capsule_cleanup_failed")
                    named = os.stat(
                        bank_root.name,
                        dir_fd=parent.descriptor,
                        follow_symlinks=False,
                    )
                    opened = os.fstat(root)
                    if not _same_inode(named, opened):
                        _fail("capsule_cleanup_failed")
                    _remove_tree(root)
                    if not parent.revalidate():
                        _fail("capsule_cleanup_failed")
                    _quarantine_remove_entry(
                        parent.descriptor,
                        bank_root.name,
                        root,
                        directory=True,
                    )
                    try:
                        os.stat(
                            bank_root.name,
                            dir_fd=parent.descriptor,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        _fail("capsule_cleanup_failed")
                except (OSError, CapsuleContractError):
                    cleanup_failed = True
            os.close(root)
        if parent is not None:
            parent.close()
        for pinned in pinned_sources:
            pinned.close()
        if cleanup_failed:
            _fail("capsule_cleanup_failed")


if __name__ == "__main__" and sys.argv[1:] == [_SCAN_WORKER_ARGUMENT]:
    raise SystemExit(_scan_worker_main())
