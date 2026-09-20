"""Small, workspace-confined tools exposed through native Codex dynamic tools.

Every operation takes a workspace root and workspace-relative paths; optional format
adapters are pinned by the runtime image. Paths are checked before use and sensitive
operations use descriptor-confined no-follow access. The limits below are part of the
interface, rather than merely implementation details: callers can rely on a request
failing instead of causing an unbounded read, archive expansion, or process.
"""

from __future__ import annotations

import base64
import binascii
import errno
import gzip
import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import stat
import struct
import subprocess
import tarfile
import threading
import time
import urllib.parse
import warnings
import wave
import zipfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO

from .artifact_inspector import artifact_tool_spec, inspect_artifact
from .binary_tools import binary_tool_specs, disassemble_elf, elf_symbols, inspect_elf
from .derive_tools import derive_artifact, derive_tool_spec
from .exact_tools import compute_exact, exact_tool_spec
from .media_tools import dicom_metadata, media_tool_specs, wav_analyze

try:  # aifc was removed from Python 3.13; WAV remains universally available.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import aifc
except ImportError:  # pragma: no cover - depends on interpreter version
    aifc = None  # type: ignore[assignment]

_AIFF_ERRORS: tuple[type[BaseException], ...] = (aifc.Error,) if aifc is not None else ()
_AUDIO_ERRORS: tuple[type[BaseException], ...] = (OSError, EOFError, wave.Error) + _AIFF_ERRORS


# Conservative limits. Files may be larger than the amount ever loaded into memory:
# range reads and streaming hashes keep ordinary challenge artifacts usable without
# making resident memory scale with artifact size.
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_SCAN_BYTES = 16 * 1024 * 1024
MAX_HEADER_BYTES = 4 * 1024 * 1024
MAX_INPUT_BYTES = 1 * 1024 * 1024
MAX_OUTPUT_BYTES = 128 * 1024
MAX_LIST_ENTRIES = 500
MAX_LIST_OUTPUT_ENTRIES = 200
MAX_ARCHIVE_ENTRIES = 1_000
MAX_ARCHIVE_LIST_OUTPUT = 200
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_METADATA_BYTES = 8 * 1024 * 1024
MAX_SEARCH_RESULTS = 200
MAX_STRING_LENGTH = 512
COMMAND_TIMEOUT_SECONDS = 3.0
MAX_COMMAND_OUTPUT_BYTES = 8 * 1024
MAX_WORKSPACE_ENTRIES = 10_000


class ToolError(Exception):
    """A safe, user-facing failure with a stable error code."""

    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})


def _error(code: str, message: str, **details: Any) -> ToolError:
    stage = (
        "arguments"
        if code
        in {
            "invalid_argument",
            "invalid_cursor",
            "stale_cursor",
            "input_too_large",
            "limit_exceeded",
        }
        else "result"
        if code in {"invalid_result", "output_too_large"}
        else "execution"
    )
    diagnostic = {
        "schema_version": 1,
        "contract_version": 1,
        "failure_stage": stage,
        "constraint": code,
        **details,
    }
    return ToolError(code, message, details=diagnostic)


def _value_kind(value: Any) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, (list, tuple)):
        return "array"
    if isinstance(value, (bytes, bytearray)):
        return "bytes"
    return "other"


def _bounded_text(value: Any, name: str, limit: int = MAX_INPUT_BYTES) -> str:
    if not isinstance(value, str):
        raise _error(
            "invalid_argument",
            f"{name} must be a string",
            field_path=name,
            constraint="type",
            actual_kind=_value_kind(value),
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _error(
            "invalid_argument",
            f"{name} must contain valid Unicode text",
            field_path=name,
            constraint="unicode",
            actual_kind="string",
        ) from exc
    if "\x00" in value:
        raise _error(
            "invalid_argument",
            f"{name} contains a NUL byte",
            field_path=name,
            constraint="nul_forbidden",
            actual_kind="string",
            actual_size=len(encoded),
        )
    if len(encoded) > limit:
        raise _error(
            "input_too_large",
            f"{name} exceeds the input limit",
            field_path=name,
            constraint="max_bytes",
            actual_kind="string",
            actual_size=len(encoded),
            limit=limit,
        )
    return value


def _bounded_int(value: Any, name: str, low: int, high: int, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error(
            "invalid_argument",
            f"{name} must be an integer",
            field_path=name,
            constraint="type",
            actual_kind=_value_kind(value),
        )
    if not low <= value <= high:
        raise _error(
            "limit_exceeded",
            f"{name} must be between {low} and {high}",
            field_path=name,
            constraint="range",
            actual_kind="integer",
        )
    return value


class Workspace:
    """Resolve and inspect only paths below a non-symlink workspace directory."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        max_workspace_bytes: int | None = None,
    ):
        try:
            candidate = Path(root)
        except TypeError as exc:
            raise _error("invalid_workspace", "workspace must be a path") from exc
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        # Resolve the root itself, but refuse a symlink root.  This allows a normal
        # path containing a symlink in an ancestor while preventing a mutable root.
        try:
            if candidate.is_symlink() or not candidate.is_dir():
                raise _error("invalid_workspace", "workspace must be a real directory")
            self.root = candidate.resolve(strict=True)
        except OSError as exc:
            raise _error("invalid_workspace", "workspace is not accessible") from exc
        if max_workspace_bytes is not None and max_workspace_bytes <= 0:
            raise _error("invalid_workspace", "workspace byte limit must be positive")
        self.max_workspace_bytes = max_workspace_bytes

    def snapshot(self) -> tuple[set[str], int]:
        """Return bounded, non-following entry names and regular-file bytes."""
        entries: set[str] = set()
        total = 0
        try:
            for directory, directories, files in os.walk(
                self.root, topdown=True, followlinks=False
            ):
                base = Path(directory)
                for name in [*directories, *files]:
                    path = base / name
                    relative = path.relative_to(self.root).as_posix()
                    st = path.lstat()
                    if stat.S_ISLNK(st.st_mode):
                        raise _error(
                            "symlink_or_invalid_path",
                            "workspace accounting refuses symlinks",
                        )
                    entries.add(relative)
                    if len(entries) > MAX_WORKSPACE_ENTRIES:
                        raise _error(
                            "workspace_quota",
                            "workspace exceeds the entry limit",
                            limit=MAX_WORKSPACE_ENTRIES,
                        )
                    if stat.S_ISREG(st.st_mode):
                        total += st.st_size
        except ToolError:
            raise
        except OSError as exc:
            raise _error("path_unavailable", "workspace cannot be accounted") from exc
        return entries, total

    def ensure_capacity(self, additional_bytes: int = 0) -> None:
        if additional_bytes < 0:
            raise _error("invalid_argument", "additional workspace bytes cannot be negative")
        _, current = self.snapshot()
        if self.max_workspace_bytes is None:
            return
        if current + additional_bytes > self.max_workspace_bytes:
            raise _error(
                "workspace_quota",
                "operation would exceed the cumulative workspace byte limit",
                current=current,
                additional=additional_bytes,
                limit=self.max_workspace_bytes,
            )

    def ensure_entry_capacity(self, relative: str, *, temporary_entries: int = 0) -> None:
        """Reserve path components plus bounded transient entries before writing."""
        if temporary_entries < 0:
            raise _error("invalid_argument", "temporary entry count cannot be negative")
        parts = self._parts(relative)
        if not parts:
            raise _error("invalid_argument", "destination must name a new file")
        entries, _ = self.snapshot()
        prefixes = ["/".join(parts[: index + 1]) for index in range(len(parts))]
        additional = sum(prefix not in entries for prefix in prefixes) + temporary_entries
        if len(entries) + additional > MAX_WORKSPACE_ENTRIES:
            raise _error(
                "workspace_quota",
                "operation would exceed the cumulative workspace entry limit",
                current=len(entries),
                additional=additional,
                limit=MAX_WORKSPACE_ENTRIES,
            )

    @staticmethod
    def _parts(relative: str) -> tuple[str, ...]:
        relative = _bounded_text(relative, "path", MAX_INPUT_BYTES)
        if not relative or relative in (".", "./"):
            return ()
        # Treat both separators as separators.  This is stricter on POSIX and avoids
        # accepting a Windows traversal string when a request is replayed elsewhere.
        relative = relative.replace("\\", "/")
        if relative.startswith("/") or (len(relative) > 1 and relative[1] == ":"):
            raise _error("path_outside_workspace", "absolute paths are not allowed")
        parts = tuple(p for p in relative.split("/") if p not in ("", "."))
        if any(p == ".." for p in parts):
            raise _error("path_outside_workspace", "path traversal is not allowed")
        return parts

    def _check_components(self, parts: tuple[str, ...], *, must_exist: bool = True) -> Path:
        current = self.root
        for index, part in enumerate(parts):
            current = current / part
            try:
                current.lstat()
            except FileNotFoundError:
                if must_exist:
                    raise _error("not_found", "path does not exist")
                return current.joinpath(*parts[index + 1 :])
            except OSError as exc:
                raise _error("path_unavailable", "path cannot be inspected") from exc
            if os.path.islink(current) or (index < len(parts) - 1 and not os.path.isdir(current)):
                raise _error(
                    "symlink_or_invalid_path",
                    "symlinks and invalid path components are not allowed",
                )
        if must_exist:
            try:
                # A second realpath check closes the common symlink-swap case for
                # ordinary local use; operations still use no follow-link APIs.
                resolved = current.resolve(strict=True)
                resolved.relative_to(self.root)
            except (OSError, ValueError):
                raise _error("path_outside_workspace", "path resolves outside workspace")
        return current

    def path(self, relative: str, *, must_exist: bool = True) -> Path:
        parts = self._parts(relative)
        if not parts:
            return self.root
        return self._check_components(parts, must_exist=must_exist)

    def relative(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix() or "."
        except ValueError:
            return "[outside-workspace]"

    def ensure_directory(self, relative: str) -> Path:
        path = self.path(relative, must_exist=False)
        if path.exists():
            if path.is_symlink() or not path.is_dir():
                raise _error("symlink_or_invalid_path", "destination must be a real directory")
            # Re-run component checks after a caller-created directory appeared.
            return self.path(relative)
        parts = self._parts(relative)
        current = self.root
        for part in parts:
            current = current / part
            if current.exists():
                if current.is_symlink() or not current.is_dir():
                    raise _error(
                        "symlink_or_invalid_path", "destination contains an invalid component"
                    )
            else:
                try:
                    current.mkdir()
                except OSError as exc:
                    raise _error("write_failed", "cannot create destination directory") from exc
        return self.path(relative)


@contextmanager
def _workspace_regular_fd(
    workspace: Workspace, relative: str, *, limit: int = MAX_FILE_BYTES
) -> Iterator[tuple[int, os.stat_result]]:
    """Open a regular input through anchored no-follow directory descriptors."""
    parts = workspace._parts(relative)
    if not parts:
        raise _error("not_a_file", "path must name a regular file")
    if len(parts) > 128:
        raise _error("limit_exceeded", "path has too many components")
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    if any(not hasattr(os, name) for name in required) or os.open not in os.supports_dir_fd:
        raise _error("unsupported_platform", "descriptor-confined file access is unavailable")
    descriptors: list[int] = []
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptors.append(os.open(workspace.root, directory_flags))
        for part in parts[:-1]:
            descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=descriptors[-1],
        )
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise _error("not_a_file", "path must name a regular file")
        if metadata.st_nlink > 1:
            raise _error("symlink_or_invalid_path", "multiply linked inputs are not allowed")
        _check_file_size(metadata, limit=limit)
        yield descriptor, metadata
    except ToolError:
        raise
    except FileNotFoundError as exc:
        raise _error("not_found", "file does not exist") from exc
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise _error(
                "symlink_or_invalid_path", "symlinks and invalid components are not allowed"
            ) from exc
        raise _error("read_failed", "file could not be opened safely") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


@contextmanager
def _workspace_exclusive_output_fd(workspace: Workspace, relative: str) -> Iterator[int]:
    """Write privately, then atomically publish a complete output without overwriting."""
    parts = workspace._parts(relative)
    if not parts:
        raise _error("invalid_argument", "destination must name a new file")
    if len(parts) > 128:
        raise _error("limit_exceeded", "destination has too many components")
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    if (
        any(not hasattr(os, name) for name in required)
        or os.open not in os.supports_dir_fd
        or os.link not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
    ):
        raise _error("unsupported_platform", "descriptor-confined file access is unavailable")
    descriptors: list[int] = []
    output_descriptor: int | None = None
    owned: os.stat_result | None = None
    temporary_name: str | None = None
    created_directories: list[tuple[int, str, int, int]] = []
    published = False
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptors.append(os.open(workspace.root, directory_flags))
        for part in parts[:-1]:
            try:
                descriptor = os.open(part, directory_flags, dir_fd=descriptors[-1])
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptors[-1])
                    created = os.stat(part, dir_fd=descriptors[-1], follow_symlinks=False)
                    created_directories.append(
                        (descriptors[-1], part, created.st_dev, created.st_ino)
                    )
                except FileExistsError:
                    pass
                descriptor = os.open(part, directory_flags, dir_fd=descriptors[-1])
            descriptors.append(descriptor)
        for _ in range(8):
            candidate = f".rapido-part-{secrets.token_hex(16)}"
            try:
                output_descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=descriptors[-1],
                )
                temporary_name = candidate
                break
            except FileExistsError:
                continue
        if output_descriptor is None or temporary_name is None:
            raise _error("write_conflict", "could not allocate a private output name")
        owned = os.fstat(output_descriptor)
        if not stat.S_ISREG(owned.st_mode):
            raise _error("write_failed", "private output is not a regular file")
        yield output_descriptor
        try:
            os.fsync(output_descriptor)
            os.link(
                temporary_name,
                parts[-1],
                src_dir_fd=descriptors[-1],
                dst_dir_fd=descriptors[-1],
                follow_symlinks=False,
            )
            published = True
        except FileExistsError as exc:
            raise _error("write_conflict", "destination already exists") from exc
        except OSError as exc:
            raise _error("write_failed", "completed output could not be published") from exc
    except ToolError:
        raise
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise _error(
                "symlink_or_invalid_path", "destination contains an invalid component"
            ) from exc
        raise _error("write_failed", "destination could not be created safely") from exc
    finally:
        if temporary_name is not None and owned is not None and descriptors:
            try:
                current = os.stat(temporary_name, dir_fd=descriptors[-1], follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
                    os.unlink(temporary_name, dir_fd=descriptors[-1])
            except OSError:
                pass
        if output_descriptor is not None:
            os.close(output_descriptor)
        if not published:
            for parent_descriptor, name, device, inode in reversed(created_directories):
                try:
                    current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (device, inode):
                        os.rmdir(name, dir_fd=parent_descriptor)
                except OSError:
                    pass
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _ensure_regular(path: Path) -> os.stat_result:
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise _error("not_found", "file does not exist") from exc
    except OSError as exc:
        raise _error("path_unavailable", "file cannot be inspected") from exc
    if os.path.islink(path):
        raise _error("symlink_or_invalid_path", "symlinks are not allowed")
    if not os.path.isfile(path):
        raise _error("not_a_file", "path is not a regular file")
    return st


def _check_file_size(st: os.stat_result, *, limit: int = MAX_FILE_BYTES) -> None:
    if st.st_size > limit:
        raise _error(
            "input_too_large", "file exceeds the bounded read limit", size=st.st_size, limit=limit
        )


def _read_file(path: Path, *, limit: int = MAX_FILE_BYTES) -> bytes:
    st = _ensure_regular(path)
    _check_file_size(st, limit=limit)
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise _error("read_failed", "file could not be read") from exc
    if len(data) > limit:
        raise _error("input_too_large", "file exceeds the bounded read limit", limit=limit)
    return data


def _read_range(
    path: Path, *, offset: int = 0, length: int = MAX_OUTPUT_BYTES
) -> tuple[bytes, os.stat_result]:
    st = _ensure_regular(path)
    _check_file_size(st)
    try:
        with path.open("rb") as handle:
            handle.seek(offset)
            return handle.read(length), st
    except OSError as exc:
        raise _error("read_failed", "file could not be read") from exc


def _truncate_text(text: str, limit: int = MAX_OUTPUT_BYTES) -> tuple[str, bool]:
    raw = text.encode("utf-8", "replace")
    if len(raw) <= limit:
        return text, False
    return raw[:limit].decode("utf-8", "ignore"), True


def _cap_bytes(data: bytes, limit: int = MAX_OUTPUT_BYTES) -> tuple[bytes, bool]:
    return (data[:limit], len(data) > limit)


def _result(data: Mapping[str, Any]) -> dict[str, Any]:
    """Make a normal dict while avoiding accidental non-JSON return values."""
    try:
        json.dumps(data)
    except (TypeError, ValueError) as exc:
        raise _error("internal_error", "tool returned non-serializable data") from exc
    return dict(data)


def list_workspace(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    path_arg = _bounded_text(arguments.get("path", "."), "path")
    root = workspace.path(path_arg)
    if root.is_symlink():
        raise _error("symlink_or_invalid_path", "symlinks are not allowed")
    if not root.is_dir():
        raise _error("not_a_directory", "path is not a directory")
    recursive = arguments.get("recursive", False)
    if not isinstance(recursive, bool):
        raise _error("invalid_argument", "recursive must be a boolean")
    max_depth = _bounded_int(arguments.get("max_depth"), "max_depth", 0, 8, 2)
    max_entries = _bounded_int(
        arguments.get("max_entries"), "max_entries", 1, MAX_LIST_ENTRIES, 200
    )
    entries: list[dict[str, Any]] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack and len(entries) < min(max_entries, MAX_LIST_OUTPUT_ENTRIES):
        directory, depth = stack.pop(0)
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise _error("read_failed", "directory could not be listed") from exc
        for child in children:
            if len(entries) >= min(max_entries, MAX_LIST_OUTPUT_ENTRIES):
                break
            # Do not reveal symlink targets; an omitted entry is safer than metadata
            # that can be used to probe outside the workspace.
            try:
                st = child.lstat()
            except OSError:
                continue
            if os.path.islink(child):
                continue
            is_dir = stat_is_dir(st)
            item = {"path": workspace.relative(child), "type": "directory" if is_dir else "file"}
            if not is_dir:
                item["size"] = st.st_size
            entries.append(item)
            if recursive and is_dir and depth < max_depth:
                stack.append((child, depth + 1))
    return _result(
        {
            "path": workspace.relative(root),
            "entries": entries,
            "truncated": bool(stack) or len(entries) >= min(max_entries, MAX_LIST_OUTPUT_ENTRIES),
        }
    )


def stat_is_dir(st: os.stat_result) -> bool:
    return (st.st_mode & 0o170000) == 0o040000


def inspect_file(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    path_arg = _bounded_text(arguments.get("path"), "path")
    path = workspace.path(path_arg)
    st = _ensure_regular(path)
    _check_file_size(st)
    algorithms = arguments.get("algorithms", ["sha256"])
    if isinstance(algorithms, str):
        algorithms = [algorithms]
    if (
        not isinstance(algorithms, list)
        or len(algorithms) > 5
        or any(not isinstance(x, str) for x in algorithms)
    ):
        raise _error("invalid_argument", "algorithms must be a list of at most five names")
    allowed = {"sha256", "sha1", "md5", "blake2b", "blake2s"}
    if any(name not in allowed for name in algorithms):
        raise _error("invalid_argument", "unsupported hash algorithm")
    hashers = {name: hashlib.new(name) for name in algorithms}
    try:
        with path.open("rb") as handle:
            while block := handle.read(1024 * 1024):
                for digest in hashers.values():
                    digest.update(block)
    except OSError as exc:
        raise _error("read_failed", "file could not be hashed") from exc
    hashes = {name: digest.hexdigest() for name, digest in hashers.items()}
    return _result(
        {
            "path": workspace.relative(path),
            "size": st.st_size,
            "mode": st.st_mode & 0o777,
            "hashes": hashes,
        }
    )


def read_bytes(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    path_arg = _bounded_text(arguments.get("path"), "path")
    offset = _bounded_int(arguments.get("offset"), "offset", 0, MAX_FILE_BYTES, 0)
    max_bytes = max(1, (MAX_OUTPUT_BYTES - 1024) * 3 // 4)
    length = _bounded_int(arguments.get("length"), "length", 1, max_bytes, 16 * 1024)
    path = workspace.path(path_arg)
    data, st = _read_range(path, offset=offset, length=length)
    return _result(
        {
            "path": workspace.relative(path),
            "offset": offset,
            "length": len(data),
            "data_base64": base64.b64encode(data).decode("ascii"),
            "eof": offset + len(data) >= st.st_size,
        }
    )


def read_text(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    path_arg = _bounded_text(arguments.get("path"), "path")
    offset = _bounded_int(arguments.get("offset"), "offset", 0, MAX_FILE_BYTES, 0)
    length = _bounded_int(arguments.get("length"), "length", 1, MAX_OUTPUT_BYTES - 1024, 64 * 1024)
    path = workspace.path(path_arg)
    chunk, st = _read_range(path, offset=offset, length=length)
    text = chunk.decode(
        _bounded_text(arguments.get("encoding", "utf-8"), "encoding", 64), errors="replace"
    )
    return _result(
        {
            "path": workspace.relative(path),
            "offset": offset,
            "length": len(chunk),
            "text": text,
            "eof": offset + len(chunk) >= st.st_size,
        }
    )


def search_text(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    path_arg = _bounded_text(arguments.get("path"), "path")
    needle = _bounded_text(arguments.get("query"), "query", 4 * 1024)
    if not needle:
        raise _error("invalid_argument", "query must not be empty")
    case_sensitive = arguments.get("case_sensitive", True)
    if not isinstance(case_sensitive, bool):
        raise _error("invalid_argument", "case_sensitive must be a boolean")
    path = workspace.path(path_arg)
    data, st = _read_range(path, length=MAX_SCAN_BYTES)
    text = data.decode("utf-8", errors="replace")
    haystack, query = (text, needle) if case_sensitive else (text.casefold(), needle.casefold())
    lines: list[dict[str, Any]] = []
    original_lines = text.splitlines()
    for line_number, line in enumerate(haystack.splitlines(), 1):
        if query in line:
            original = original_lines[line_number - 1]
            lines.append(
                {"line": line_number, "text": _truncate_text(original, MAX_STRING_LENGTH)[0]}
            )
            if len(lines) >= MAX_SEARCH_RESULTS:
                break
    return _result(
        {
            "path": workspace.relative(path),
            "query": needle,
            "matches": lines,
            "scanned_bytes": len(data),
            "truncated": len(lines) >= MAX_SEARCH_RESULTS or st.st_size > len(data),
        }
    )


def extract_strings(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    path_arg = _bounded_text(arguments.get("path"), "path")
    minimum = _bounded_int(arguments.get("minimum"), "minimum", 3, 128, 4)
    path = workspace.path(path_arg)
    data, st = _read_range(path, length=MAX_SCAN_BYTES)
    found: list[dict[str, Any]] = []
    # ASCII strings are deterministic and avoid locale-dependent output.  Decode a
    # UTF-16LE sequence only when it has a strong printable signal.
    for match in re.finditer(rb"[ -~]{" + str(minimum).encode() + rb",}", data):
        value = _truncate_text(match.group().decode("ascii", "replace"), MAX_STRING_LENGTH)[0]
        found.append({"offset": match.start(), "text": value})
        if len(found) >= MAX_SEARCH_RESULTS:
            break
    return _result(
        {
            "path": workspace.relative(path),
            "strings": found,
            "scanned_bytes": len(data),
            "truncated": len(found) >= MAX_SEARCH_RESULTS or st.st_size > len(data),
        }
    )


def _decode_input(workspace: Workspace, arguments: Mapping[str, Any]) -> bytes:
    has_data = "data" in arguments
    has_path = "path" in arguments
    if has_data == has_path:
        raise _error("invalid_argument", "provide exactly one of data or path")
    if has_data:
        text = _bounded_text(arguments.get("data"), "data")
        return text.encode("utf-8")
    return _read_file(
        workspace.path(_bounded_text(arguments.get("path"), "path")), limit=MAX_INPUT_BYTES
    )


def _decoded_result(data: bytes, *, kind: str) -> dict[str, Any]:
    # Base64 and the small preview both expand the wire representation.  Reserve
    # space for those envelopes so the JSON result remains bounded as well.
    max_data = max(1, (MAX_OUTPUT_BYTES - 2 * MAX_STRING_LENGTH) * 3 // 4)
    if len(data) > max_data:
        raise _error(
            "output_too_large",
            "decoded output exceeds the bounded representation limit",
            size=len(data),
            limit=max_data,
        )
    text = data.decode("utf-8", errors="replace")
    text = _truncate_text(text, MAX_STRING_LENGTH)[0]
    return _result(
        {
            "encoding": kind,
            "size": len(data),
            "data_base64": base64.b64encode(data).decode("ascii"),
            "text": text,
        }
    )


def decode_base64(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    raw = _decode_input(workspace, arguments)
    try:
        data = base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _error("invalid_encoding", "invalid base64 input") from exc
    return _decoded_result(data, kind="base64")


def decode_hex(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    raw = _decode_input(workspace, arguments)
    try:
        data = bytes.fromhex(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise _error("invalid_encoding", "invalid hexadecimal input") from exc
    return _decoded_result(data, kind="hex")


def decode_url(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    raw = _decode_input(workspace, arguments)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _error("invalid_encoding", "URL input must be UTF-8") from exc
    decoded = urllib.parse.unquote_to_bytes(text)
    return _decoded_result(decoded, kind="url")


def _archive_name(name: str) -> str:
    # Archive names are POSIX paths even on Windows.  Reject absolute paths and any
    # parent component instead of normalizing them into a seemingly safe path.
    name = _bounded_text(name, "archive entry", 4096).replace("\\", "/")
    if name.startswith(("/", "~")):
        raise _error("unsafe_archive", "archive contains an absolute entry")
    parts = tuple(part for part in name.split("/") if part not in ("", "."))
    if any(part == ".." for part in parts):
        raise _error("unsafe_archive", "archive contains a traversal entry")
    return "/".join(parts)


def _archive_limit_count(count: int) -> None:
    if count > MAX_ARCHIVE_ENTRIES:
        raise _error("archive_too_large", "archive has too many entries", count=count)


def _zip_declared_entry_count(path: Path) -> int | None:
    """Read the bounded EOCD before ZipFile materializes its central directory."""
    try:
        size = path.stat().st_size
        tail_size = min(size, 65_535 + 22)
        with path.open("rb") as handle:
            handle.seek(size - tail_size)
            tail = handle.read(tail_size)
    except OSError as exc:
        raise _error("path_unavailable", "archive metadata cannot be read") from exc
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or offset + 22 > len(tail):
        return None
    comment_size = struct.unpack_from("<H", tail, offset + 20)[0]
    if offset + 22 + comment_size != len(tail):
        return None
    disk, central_disk, disk_entries, entries = struct.unpack_from("<HHHH", tail, offset + 4)
    central_size, central_offset = struct.unpack_from("<II", tail, offset + 12)
    if (
        disk != 0
        or central_disk != 0
        or disk_entries != entries
        or entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    ):
        raise _error("unsupported_archive", "multi-disk and ZIP64 archives are unsupported")
    _archive_limit_count(entries)
    if central_size > MAX_ARCHIVE_METADATA_BYTES:
        raise _error(
            "archive_too_large",
            "ZIP metadata exceeds the bounded central-directory limit",
            size=central_size,
        )
    return entries


def list_zip(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    path_arg = _bounded_text(arguments.get("path"), "path")
    path = workspace.path(path_arg)
    _check_file_size(_ensure_regular(path))
    try:
        declared_entries = _zip_declared_entry_count(path)
        if declared_entries is None:
            raise _error("invalid_archive", "file is not a readable ZIP archive")
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            _archive_limit_count(len(infos))
            if len(infos) != declared_entries:
                raise _error("invalid_archive", "ZIP entry count does not match its metadata")
            entries = []
            for info in infos[:MAX_ARCHIVE_LIST_OUTPUT]:
                safe_name = _archive_name(info.filename)
                is_symlink = (info.external_attr >> 16) & 0o170000 == 0o120000
                entries.append(
                    {
                        "name": _truncate_text(safe_name, MAX_STRING_LENGTH)[0],
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                        "directory": info.is_dir(),
                        "symlink": is_symlink,
                        "unsafe": not bool(safe_name)
                        or is_symlink
                        or info.file_size > MAX_ARCHIVE_MEMBER_BYTES,
                    }
                )
    except ToolError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise _error("invalid_archive", "file is not a readable ZIP archive") from exc
    return _result(
        {"path": path_arg, "entries": entries, "truncated": len(infos) > MAX_ARCHIVE_LIST_OUTPUT}
    )


def list_tar(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    path_arg = _bounded_text(arguments.get("path"), "path")
    path = workspace.path(path_arg)
    _check_file_size(_ensure_regular(path))
    try:
        with tarfile.open(path, mode="r:*") as archive:
            entries = []
            count = 0
            for member in archive:
                count += 1
                _archive_limit_count(count)
                if count > MAX_ARCHIVE_LIST_OUTPUT:
                    continue
                name = _archive_name(member.name)
                unsupported = (
                    member.issym()
                    or member.islnk()
                    or member.isdev()
                    or member.size > MAX_ARCHIVE_MEMBER_BYTES
                )
                entries.append(
                    {
                        "name": _truncate_text(name, MAX_STRING_LENGTH)[0],
                        "size": member.size,
                        "directory": member.isdir(),
                        "symlink": member.issym() or member.islnk(),
                        "unsafe": not bool(name) or unsupported,
                    }
                )
    except ToolError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise _error("invalid_archive", "file is not a readable TAR archive") from exc
    return _result(
        {"path": path_arg, "entries": entries, "truncated": count > MAX_ARCHIVE_LIST_OUTPUT}
    )


def _prepare_destination(workspace: Workspace, destination: str) -> Path:
    destination = _bounded_text(destination, "destination")
    return workspace.ensure_directory(destination)


def _safe_member_destination(workspace: Workspace, destination: Path, name: str) -> Path:
    clean = _archive_name(name)
    if not clean:
        raise _error("unsafe_archive", "archive has an empty entry")
    target = destination.joinpath(*clean.split("/"))
    try:
        target.relative_to(workspace.root)
    except ValueError as exc:
        raise _error("unsafe_archive", "archive entry leaves workspace") from exc
    # Validate existing parents and target without following links.
    relative = workspace.relative(target)
    workspace.path(relative, must_exist=False)
    current = destination
    for component in clean.split("/"):
        current = current / component
        if current.exists() and current.is_symlink():
            raise _error("unsafe_archive", "archive extraction would use a symlink")
    return target


def _preflight_target(target: Path, seen: set[str], workspace: Workspace) -> None:
    relative = workspace.relative(target)
    if relative in seen:
        raise _error("write_conflict", "archive contains duplicate entries")
    seen.add(relative)
    if target.exists():
        raise _error("write_conflict", "archive extraction will not overwrite an existing path")


def _write_archive_member(target: Path, source: BinaryIO, size: int) -> int:
    if size > MAX_ARCHIVE_MEMBER_BYTES:
        raise _error("archive_too_large", "archive member exceeds the per-file limit", size=size)
    if target.exists():
        raise _error("write_conflict", "archive extraction will not overwrite an existing path")
    target.parent.mkdir(parents=True, exist_ok=True)
    # Ensure mkdir did not encounter a symlink introduced by a prior archive entry.
    cursor = target.parent
    while cursor != cursor.parent:
        if cursor.is_symlink():
            raise _error("unsafe_archive", "archive extraction encountered a symlink")
        if cursor == Path(target.anchor):
            break
        cursor = cursor.parent
    written = 0
    try:
        with target.open("xb") as handle:
            while written <= size:
                block = source.read(min(64 * 1024, size - written + 1))
                if not block:
                    break
                written += len(block)
                if written > size:
                    raise _error("invalid_archive", "archive member exceeded declared size")
                handle.write(block)
    except ToolError:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    except OSError as exc:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise _error("write_failed", "archive member could not be written") from exc
    if written != size:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise _error("invalid_archive", "archive member was truncated")
    return written


def extract_archive(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    path_arg = _bounded_text(arguments.get("path"), "path")
    destination_arg = _bounded_text(arguments.get("destination", "extracted"), "destination")
    fmt = arguments.get("format", "auto")
    if fmt not in ("auto", "zip"):
        raise _error(
            "unsupported_archive",
            "TAR extraction is unavailable; inspect TAR inventory through inspect_artifact",
        )
    password_value = arguments.get("password")
    password = (
        None
        if password_value is None
        else _bounded_text(password_value, "password", 256).encode("utf-8")
    )
    archive_path = workspace.path(path_arg)
    _check_file_size(_ensure_regular(archive_path))
    # Validate without creating anything.  A malformed/traversal archive should be
    # non-mutating; the destination is created only after complete preflight.
    destination = workspace.path(destination_arg, must_exist=False)
    if destination.exists():
        destination = _prepare_destination(workspace, destination_arg)
    total = 0
    extracted: list[str] = []
    # Preflight all names, types, and declared sizes before writing anything.  This
    # makes an archive bomb or traversal failure non-mutating.
    try:
        if fmt in ("auto", "zip"):
            declared_entries = _zip_declared_entry_count(archive_path)
            if declared_entries is None:
                if fmt == "zip":
                    raise _error("invalid_archive", "file is not a ZIP archive")
                archive = None
            else:
                archive = zipfile.ZipFile(archive_path)
                kind = "zip"
            if archive is not None:
                with archive:
                    infos = archive.infolist()
                    _archive_limit_count(len(infos))
                    if len(infos) != declared_entries:
                        raise _error("invalid_archive", "ZIP entry count does not match metadata")
                    preflight: list[tuple[zipfile.ZipInfo, Path]] = []
                    seen_targets: set[str] = set()
                    for info in infos:
                        clean = _archive_name(info.filename)
                        if not clean or info.is_dir():
                            continue
                        if (
                            info.file_size > MAX_ARCHIVE_MEMBER_BYTES
                            or total + info.file_size > MAX_ARCHIVE_BYTES
                        ):
                            raise _error("archive_too_large", "archive exceeds extraction limits")
                        if (info.external_attr >> 16) & 0o170000 == 0o120000:
                            raise _error("unsafe_archive", "symlink entries cannot be extracted")
                        if info.flag_bits & 1:
                            if password is None:
                                raise _error(
                                    "archive_password_required", "ZIP member requires a password"
                                )
                            try:
                                with archive.open(info, "r", pwd=password) as probe:
                                    probe.read(1)
                            except RuntimeError as exc:
                                raise _error(
                                    "archive_password_rejected", "ZIP password was rejected"
                                ) from exc
                        target = _safe_member_destination(workspace, destination, clean)
                        _preflight_target(target, seen_targets, workspace)
                        preflight.append((info, target))
                        total += info.file_size
                    workspace.ensure_capacity(total)
                    destination = _prepare_destination(workspace, destination_arg)
                    for info, target in preflight:
                        try:
                            source = archive.open(info, "r", pwd=password)
                        except RuntimeError as exc:
                            raise _error(
                                "archive_password_rejected", "ZIP password was rejected"
                            ) from exc
                        _write_archive_member(target, source, info.file_size)
                        extracted.append(workspace.relative(target))
                    return _result(
                        {
                            "path": path_arg,
                            "destination": destination_arg,
                            "format": kind,
                            "files": extracted,
                            "bytes": total,
                        }
                    )
    except ToolError:
        raise
    except (OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
        raise _error("invalid_archive", "archive could not be safely extracted") from exc
    raise _error("invalid_archive", "archive could not be identified")


def decompress_gzip(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Decompress one bounded gzip stream without using its embedded filename."""
    source_arg = _bounded_text(arguments.get("path"), "path")
    destination_arg = _bounded_text(arguments.get("destination"), "destination")
    workspace.ensure_capacity(MAX_ARCHIVE_BYTES)
    workspace.ensure_entry_capacity(destination_arg, temporary_entries=1)
    written = 0
    with (
        _workspace_regular_fd(workspace, source_arg) as (source_descriptor, _),
        _workspace_exclusive_output_fd(workspace, destination_arg) as output_descriptor,
        os.fdopen(os.dup(source_descriptor), "rb") as source_stream,
        gzip.GzipFile(fileobj=source_stream, mode="rb") as compressed,
        os.fdopen(os.dup(output_descriptor), "wb") as output,
    ):
        try:
            while written <= MAX_ARCHIVE_BYTES:
                block = compressed.read(min(64 * 1024, MAX_ARCHIVE_BYTES - written + 1))
                if not block:
                    break
                written += len(block)
                if written > MAX_ARCHIVE_BYTES:
                    raise _error("archive_too_large", "gzip output exceeds its byte limit")
                output.write(block)
        except ToolError:
            raise
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            raise _error("invalid_archive", "file is not a readable bounded gzip stream") from exc
    return _result({"path": source_arg, "destination": destination_arg, "bytes": written})


def _u16(data: bytes, offset: int, endian: str = ">") -> int:
    return struct.unpack_from(endian + "H", data, offset)[0]


def image_metadata(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    path_arg = _bounded_text(arguments.get("path"), "path")
    path = workspace.path(path_arg)
    data, st = _read_range(path, length=MAX_HEADER_BYTES)
    result: dict[str, Any] = {
        "path": workspace.relative(path),
        "size": st.st_size,
        "header_bytes": len(data),
        "header_truncated": st.st_size > len(data),
    }
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        width, height = struct.unpack(">II", data[16:24])
        result.update(
            format="png",
            width=width,
            height=height,
            bit_depth=data[24] if len(data) > 24 else None,
            color_type=data[25] if len(data) > 25 else None,
        )
    elif data[:3] == b"GIF" and len(data) >= 10:
        result.update(
            format=data[:6].decode("ascii"), width=_u16(data, 6, "<"), height=_u16(data, 8, "<")
        )
    elif data.startswith(b"BM") and len(data) >= 26:
        width, height = struct.unpack_from("<ii", data, 18)
        result.update(
            format="bmp",
            width=abs(width),
            height=abs(height),
            bits_per_pixel=_u16(data, 28) if len(data) >= 30 else None,
        )
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP" and len(data) >= 30:
        chunk = data[12:16]
        if chunk == b"VP8X":
            width = 1 + int.from_bytes(data[24:27], "little")
            height = 1 + int.from_bytes(data[27:30], "little")
            result.update(format="webp", width=width, height=height)
        else:
            result.update(format="webp")
    elif data.startswith(b"\xff\xd8"):
        # JPEG dimensions live in a SOF marker.  Scan only the bounded input.
        offset = 2
        found = None
        while offset + 9 < len(data):
            if data[offset] != 0xFF:
                offset += 1
                continue
            marker = data[offset + 1]
            offset += 2
            if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                continue
            if offset + 2 > len(data):
                break
            segment_length = _u16(data, offset)
            if segment_length < 2 or offset + segment_length > len(data):
                break
            is_start_of_frame = (
                marker in range(0xC0, 0xC4)
                or marker in range(0xC5, 0xC8)
                or marker in range(0xC9, 0xCC)
                or marker in range(0xCD, 0xD0)
            )
            if is_start_of_frame and segment_length >= 7:
                height = _u16(data, offset + 3)
                width = _u16(data, offset + 5)
                found = (width, height)
                break
            offset += segment_length
        result["format"] = "jpeg"
        if found:
            result.update(width=found[0], height=found[1])
    else:
        raise _error("unsupported_format", "file is not a supported image format")
    return _result(result)


def audio_metadata(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    path_arg = _bounded_text(arguments.get("path"), "path")
    path = workspace.path(path_arg)
    st = _ensure_regular(path)
    _check_file_size(st)
    try:
        header, _ = _read_range(path, length=64)
        if path.suffix.lower() == ".wav" or header[:4] == b"RIFF":
            with wave.open(str(path), "rb") as handle:
                return _result(
                    {
                        "path": path_arg,
                        "format": "wav",
                        "channels": handle.getnchannels(),
                        "sample_width": handle.getsampwidth(),
                        "sample_rate": handle.getframerate(),
                        "frames": handle.getnframes(),
                        "duration_seconds": round(handle.getnframes() / handle.getframerate(), 6)
                        if handle.getframerate()
                        else 0,
                    }
                )
        if path.suffix.lower() in (".aif", ".aiff", ".aifc") and aifc is not None:
            with aifc.open(str(path), "rb") as handle:
                return _result(
                    {
                        "path": path_arg,
                        "format": "aiff",
                        "channels": handle.getnchannels(),
                        "sample_width": handle.getsampwidth(),
                        "sample_rate": handle.getframerate(),
                        "frames": handle.getnframes(),
                        "duration_seconds": round(handle.getnframes() / handle.getframerate(), 6)
                        if handle.getframerate()
                        else 0,
                    }
                )
    except _AUDIO_ERRORS as exc:
        raise _error("invalid_audio", "file is not a readable supported audio file") from exc
    raise _error("unsupported_format", "only WAV and AIFF metadata are supported")


_COMMANDS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("file", (), "file type identification"),
    ("strings", ("-a", "-n", "4"), "printable strings"),
    ("readelf", ("-h", "-S"), "ELF headers and sections"),
    ("objdump", ("-f", "-h"), "object headers"),
    ("otool", ("-hv",), "Mach-O headers"),
    ("nm", ("-a",), "symbol table"),
)


def _binary_kind(data: bytes) -> str:
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data[:2] == b"MZ":
        return "pe"
    if len(data) >= 4 and int.from_bytes(data[:4], "big") in (
        0xFEEDFACE,
        0xFEEDFACF,
        0xCEFAEDFE,
        0xCFFAEDFE,
    ):
        return "mach-o"
    return "unknown"


def _command_output(data: bytes) -> tuple[str, bool]:
    clipped, truncated = _cap_bytes(data, MAX_COMMAND_OUTPUT_BYTES)
    return clipped.decode("utf-8", "replace"), truncated


def _run_bounded_command(
    argv: list[str], cwd: Path, *, pass_fds: tuple[int, ...] = ()
) -> tuple[int, bytes, bytes, bool, bool]:
    """Run fixed argv while draining pipes but retaining only a bounded prefix."""
    process = subprocess.Popen(
        argv,
        cwd=str(cwd),
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        pass_fds=pass_fds,
    )
    selector = selectors.DefaultSelector()
    buffers: dict[int, bytearray] = {}
    truncated = False
    timed_out = False
    assert process.stdout is not None and process.stderr is not None
    streams = (process.stdout, process.stderr)
    try:
        for stream in streams:
            fd = stream.fileno()
            os.set_blocking(fd, False)
            buffers[fd] = bytearray()
            selector.register(fd, selectors.EVENT_READ)
        deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
        hard_deadline = deadline + 1.0
        while selector.get_map():
            now = time.monotonic()
            if process.poll() is None and now >= deadline:
                timed_out = True
                process.kill()
            if now >= hard_deadline:
                truncated = True
                break
            events = selector.select(0.05)
            for key, _ in events:
                try:
                    chunk = os.read(key.fd, 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                retained = buffers[key.fd]
                capacity = max(0, MAX_COMMAND_OUTPUT_BYTES - len(retained))
                retained.extend(chunk[:capacity])
                truncated = truncated or len(chunk) > capacity
        if process.poll() is None:
            process.kill()
        returncode = process.wait(timeout=1.0)
        return (
            returncode,
            bytes(buffers[process.stdout.fileno()]),
            bytes(buffers[process.stderr.fileno()]),
            truncated,
            timed_out,
        )
    finally:
        selector.close()
        for stream in streams:
            stream.close()
        if process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass


def inspect_binary(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    path_arg = _bounded_text(arguments.get("path"), "path")
    path = workspace.path(path_arg)
    data, _ = _read_range(path, length=4096)
    kind = _binary_kind(data)
    results: list[dict[str, Any]] = []
    # The argument surface intentionally has no command/argv field.  Every argv below
    # is fixed, and the path is passed as one argument with shell=False.
    for command, fixed, description in _COMMANDS:
        executable = shutil.which(command, path="/usr/bin:/bin:/usr/sbin:/sbin")
        if not executable:
            results.append({"command": command, "available": False, "description": description})
            continue
        if command == "readelf" and kind != "elf":
            continue
        if command == "otool" and kind != "mach-o":
            continue
        if command == "objdump" and kind == "unknown":
            continue
        # A workspace file may legally begin with a dash.  Prefix only that case
        # so fixed-argv tools cannot interpret a user filename as an option.
        relative_path = workspace.relative(path)
        command_path = "./" + relative_path if relative_path.startswith("-") else relative_path
        argv = [executable, *fixed, command_path]
        try:
            returncode, stdout_raw, stderr_raw, truncated, timed_out = _run_bounded_command(
                argv, workspace.root
            )
            if timed_out:
                results.append(
                    {
                        "command": command,
                        "available": True,
                        "timed_out": True,
                        "error": "command timed out",
                    }
                )
                continue
            stdout, stdout_truncated = _command_output(stdout_raw)
            stderr, stderr_truncated = _command_output(stderr_raw)
            results.append(
                {
                    "command": command,
                    "available": True,
                    "returncode": returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                    "truncated": truncated or stdout_truncated or stderr_truncated,
                }
            )
        except (OSError, ValueError):
            results.append(
                {"command": command, "available": True, "error": "command failed to start"}
            )
    return _result({"path": path_arg, "kind": kind, "commands": results})


_FILESYSTEM_PATH = re.compile(r"/(?:[A-Za-z0-9._+@,:=-]+/?)*")


def inspect_filesystem(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Inspect an ext-family image with fixed read-only debugfs commands."""
    image_arg = _bounded_text(arguments.get("path"), "path")
    action = _bounded_text(arguments.get("action", "superblock"), "action", 32)
    commands = {
        "superblock": "stats",
        "deleted": "lsdel",
    }
    filesystem_path = arguments.get("filesystem_path")
    if action in {"list", "stat", "read"}:
        filesystem_path = _bounded_text(filesystem_path, "filesystem_path", 1024)
        if (
            not filesystem_path.isascii()
            or not _FILESYSTEM_PATH.fullmatch(filesystem_path)
            or ".." in filesystem_path.split("/")
        ):
            raise _error(
                "invalid_argument",
                "filesystem_path must be a strict absolute path without whitespace or traversal",
                field_path="filesystem_path",
                constraint="path_grammar",
                actual_kind="string",
                allowed_values=["strict_absolute_path"],
            )
        commands[action] = {
            "list": "ls -l",
            "stat": "stat",
            "read": "cat",
        }[action] + f" {filesystem_path}"
    elif action not in commands:
        raise _error(
            "invalid_argument",
            "action must be superblock, deleted, list, stat, or read",
            field_path="action",
            constraint="enum",
            actual_kind="string",
            allowed_values=["superblock", "deleted", "list", "stat", "read"],
        )
    executable = shutil.which("debugfs", path="/usr/bin:/bin:/usr/sbin:/sbin")
    if not executable:
        raise _error("tool_unavailable", "read-only filesystem analyzer is unavailable")
    with _workspace_regular_fd(workspace, image_arg) as (descriptor, _):
        returncode, stdout, stderr, truncated, timed_out = _run_bounded_command(
            [executable, "-R", commands[action], f"/proc/self/fd/{descriptor}"],
            workspace.root,
            pass_fds=(descriptor,),
        )
    if timed_out:
        raise _error("tool_timeout", "filesystem analysis exceeded its time bound")
    record: dict[str, Any] = {
        "path": image_arg,
        "action": action,
        "returncode": returncode,
        "truncated": truncated,
    }
    if action == "read":
        record.update(
            {
                "bytes": len(stdout),
                "data_base64": base64.b64encode(stdout).decode(),
                "text_preview": stdout[:MAX_STRING_LENGTH].decode("utf-8", "replace"),
            }
        )
    else:
        record["text"] = stdout.decode("utf-8", "replace")
    if stderr:
        record["diagnostic"] = stderr[:MAX_STRING_LENGTH].decode("utf-8", "replace")
    return _result(record)


def run_shell(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Run arbitrary local analysis without exposing credentials, Board state, or networking."""
    from .analysis_worker import MAX_COMMAND_BYTES, MAX_TIMEOUT_SECONDS, run_analysis_worker

    command = _bounded_text(arguments.get("command"), "command", MAX_COMMAND_BYTES)
    timeout_seconds = _bounded_int(
        arguments.get("timeout_seconds"),
        "timeout_seconds",
        1,
        MAX_TIMEOUT_SECONDS,
        60,
    )
    raw_sources = arguments.get("source_paths")
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
    result = run_analysis_worker(workspace.root, command, timeout_seconds)
    return _result(
        {
            **result,
            "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
            "sources": sources,
            "analysis_directory": "rapido-analysis",
        }
    )


ToolFunction = Callable[[Workspace, Mapping[str, Any]], dict[str, Any]]

TOOLS: dict[str, tuple[ToolFunction, str]] = {
    "list_workspace": (
        list_workspace,
        "List bounded workspace entries without following symlinks.",
    ),
    "inspect_file": (inspect_file, "Inspect a file and compute bounded cryptographic hashes."),
    "inspect_artifact": (
        inspect_artifact,
        "Inspect a content-detected artifact through one bounded passive interface.",
    ),
    "read_bytes": (read_bytes, "Read a bounded byte range as base64."),
    "read_text": (read_text, "Read a bounded text range with replacement decoding."),
    "search_text": (search_text, "Search a bounded UTF-8 file for literal text."),
    "extract_strings": (extract_strings, "Extract bounded printable ASCII strings."),
    "decode_base64": (decode_base64, "Decode bounded base64 data or a workspace file."),
    "decode_hex": (decode_hex, "Decode bounded hexadecimal data or a workspace file."),
    "decode_url": (decode_url, "Decode bounded percent-encoded URL data or a workspace file."),
    "derive_artifact": (
        derive_artifact,
        "Decode one bounded source range into a content-addressed workspace artifact.",
    ),
    "compute_exact": (
        compute_exact,
        "Compute bounded exact arithmetic and byte operations without file or process access.",
    ),
    "list_zip": (list_zip, "List ZIP members and flag unsafe or oversized entries."),
    "list_tar": (list_tar, "List TAR members and flag unsafe or oversized entries."),
    "extract_archive": (extract_archive, "Safely extract a ZIP into the workspace."),
    "decompress_gzip": (
        decompress_gzip,
        "Safely decompress one bounded gzip stream to a new workspace file.",
    ),
    "image_metadata": (image_metadata, "Read dimensions from common image headers."),
    "audio_metadata": (audio_metadata, "Read WAV or AIFF audio metadata."),
    "dicom_metadata": (
        dicom_metadata,
        "Read bounded top-level DICOM Part-10 metadata without pixel payloads.",
    ),
    "wav_analyze": (
        wav_analyze,
        "Analyze bounded integer-PCM WAV statistics and LSB/text previews.",
    ),
    "inspect_binary": (inspect_binary, "Inspect a binary with fixed-argv installed tools."),
    "inspect_elf": (
        inspect_elf,
        "Read bounded ELF headers and a page of section metadata from a workspace file.",
    ),
    "elf_symbols": (
        elf_symbols,
        "Read a bounded static or dynamic ELF symbol-table prefix using installed readelf.",
    ),
    "disassemble_elf": (
        disassemble_elf,
        "Read a bounded ELF instruction window using installed objdump; never execute input.",
    ),
    "inspect_filesystem": (
        inspect_filesystem,
        "Inspect ext-family images with fixed read-only superblock, directory, deleted-file, stat, or read operations.",
    ),
    "run_shell": (
        run_shell,
        "Run arbitrary Bash and create reusable solve scripts in rapido-analysis inside this challenge workspace. The main Python has crypto, algebra/SMT, pwn/ELF/emulation, packet, image, PDF, HTTP, LIEF cross-format binary, YARA signature, pydicom, HL7, and Scapy libraries; use rapido.scapy_offline.summarize_pcap for network-denied capture parsing. /opt/angr/bin/python and /opt/math/bin/python provide isolated symbolic-execution and lattice environments. SageMath, Ghidra headless, JADX, compilers, GDB static inspection, QEMU execution, packet/forensics/archive/media/PDF tools, and CPU hashcat are on PATH. Prefer content triage before deeper tools; keep generated rules/scripts deterministic, cap records and recursion, and parse supplied files offline. Declare challenge input files in source_paths. The shell reads this challenge workspace and writes rapido-analysis, but cannot read credentials or sibling state, signal supervisors, or directly network; use bound target tools for live interaction. A verifier may derive a candidate here, but must also observe that exact candidate through a successful non-run_shell fixed source or target tool before it qualifies.",
    ),
}

# Friendly short aliases are useful for tiny clients, while canonical names remain
# documented and stable.
ALIASES = {
    "list": "list_workspace",
    "inspect": "inspect_file",
    "strings": "extract_strings",
    "search": "search_text",
    "hash": "inspect_file",
    "binary": "inspect_binary",
}

# Keep specialized compatibility operations dispatchable, but show the model one
# compact default surface. The facade covers passive format inspection; only
# semantically distinct search, transform, materialization, symbol, and filesystem
# operations remain separate.
AGENT_TOOL_NAMES = (
    "list_workspace",
    "inspect_artifact",
    "search_text",
    "derive_artifact",
    "decode_base64",
    "decode_hex",
    "decode_url",
    "compute_exact",
    "extract_archive",
    "decompress_gzip",
    "elf_symbols",
    "inspect_filesystem",
    "run_shell",
)


def tool_schemas() -> list[dict[str, Any]]:
    common_path = {
        "type": "string",
        "description": "Workspace-relative path; absolute paths and symlinks are rejected.",
    }
    schemas: dict[str, dict[str, Any]] = {
        "list_workspace": {
            "path": {"type": "string", "default": "."},
            "recursive": {"type": "boolean", "default": False},
            "max_depth": {"type": "integer", "minimum": 0, "maximum": 8},
            "max_entries": {"type": "integer", "minimum": 1, "maximum": MAX_LIST_ENTRIES},
        },
        "inspect_file": {
            "path": common_path,
            "algorithms": {"type": "array", "items": {"type": "string"}, "maxItems": 5},
        },
        "read_bytes": {
            "path": common_path,
            "offset": {"type": "integer", "minimum": 0},
            "length": {
                "type": "integer",
                "minimum": 1,
                "maximum": (MAX_OUTPUT_BYTES - 1024) * 3 // 4,
            },
        },
        "read_text": {
            "path": common_path,
            "offset": {"type": "integer", "minimum": 0},
            "length": {"type": "integer", "minimum": 1, "maximum": MAX_OUTPUT_BYTES - 1024},
            "encoding": {"type": "string"},
        },
        "search_text": {
            "path": common_path,
            "query": {"type": "string", "minLength": 1},
            "case_sensitive": {"type": "boolean"},
        },
        "extract_strings": {
            "path": common_path,
            "minimum": {"type": "integer", "minimum": 3, "maximum": 128},
        },
        "decode_base64": {"data": {"type": "string"}, "path": common_path},
        "decode_hex": {"data": {"type": "string"}, "path": common_path},
        "decode_url": {"data": {"type": "string"}, "path": common_path},
        "list_zip": {"path": common_path},
        "list_tar": {"path": common_path},
        "extract_archive": {
            "path": common_path,
            "destination": {"type": "string"},
            "format": {"type": "string", "enum": ["auto", "zip"]},
            "password": {"type": "string", "maxLength": 256},
        },
        "decompress_gzip": {"path": common_path, "destination": common_path},
        "image_metadata": {"path": common_path},
        "audio_metadata": {"path": common_path},
        "inspect_binary": {"path": common_path},
        "inspect_filesystem": {
            "path": common_path,
            "action": {
                "type": "string",
                "enum": ["superblock", "deleted", "list", "stat", "read"],
            },
            "filesystem_path": {
                "type": "string",
                "pattern": r"^/(?:[A-Za-z0-9._+@,:=-]+/?)*$",
                "description": (
                    "Absolute path inside the filesystem image; ASCII only, without whitespace "
                    "or '..' components."
                ),
            },
        },
        "run_shell": {
            "command": {
                "type": "string",
                "minLength": 1,
                "maxLength": 65536,
                "description": "Bash command. The current directory is persistent rapido-analysis; challenge files are readable as ../<workspace-relative-path>.",
            },
            "source_paths": {
                "type": "array",
                "minItems": 1,
                "maxItems": 16,
                "items": common_path,
                "description": "Controller-provided or derived challenge inputs used by the command; rapido-analysis files are not valid source roots.",
            },
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 180},
        },
    }
    extension_specs = {
        spec["name"]: spec
        for spec in [
            artifact_tool_spec(),
            derive_tool_spec(),
            exact_tool_spec(),
            *binary_tool_specs(),
            *media_tool_specs(),
        ]
    }

    required_fields = {
        "inspect_file": ["path"],
        "read_bytes": ["path"],
        "read_text": ["path"],
        "search_text": ["path", "query"],
        "extract_strings": ["path"],
        "list_zip": ["path"],
        "list_tar": ["path"],
        "extract_archive": ["path"],
        "decompress_gzip": ["path", "destination"],
        "image_metadata": ["path"],
        "audio_metadata": ["path"],
        "inspect_binary": ["path"],
        "inspect_filesystem": ["path"],
        "run_shell": ["command", "source_paths"],
    }

    def generic_spec(name: str, description: str) -> dict[str, Any]:
        input_schema: dict[str, Any] = {
            "type": "object",
            "properties": schemas.get(name, {}),
            "additionalProperties": False,
        }
        if name in required_fields:
            input_schema["required"] = required_fields[name]
        if name in {"decode_base64", "decode_hex", "decode_url"}:
            input_schema["oneOf"] = [{"required": ["data"]}, {"required": ["path"]}]
        if name == "inspect_filesystem":
            input_schema["oneOf"] = [
                {
                    "properties": {"action": {"enum": ["superblock", "deleted"]}},
                },
                {
                    "properties": {"action": {"enum": ["list", "stat", "read"]}},
                    "required": ["action", "filesystem_path"],
                },
            ]
        return {"name": name, "description": description, "inputSchema": input_schema}

    return [
        extension_specs.get(name, generic_spec(name, description))
        for name, (_, description) in TOOLS.items()
    ]


def call_tool(
    workspace: Workspace, name: str, arguments: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    if not isinstance(name, str):
        raise _error(
            "invalid_argument",
            "tool name must be a string",
            field_path="name",
            constraint="type",
            actual_kind=_value_kind(name),
        )
    canonical = ALIASES.get(name, name)
    entry = TOOLS.get(canonical)
    if not entry:
        raise _error("unknown_tool", "unknown tool")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, Mapping):
        raise _error(
            "invalid_argument",
            "tool arguments must be an object",
            field_path="arguments",
            constraint="type",
            actual_kind=_value_kind(arguments),
        )
    started = time.monotonic()
    try:
        result = entry[0](workspace, arguments)
    except ToolError:
        raise
    except Exception as exc:
        # Do not let codec/parser/library exception text disclose host paths or
        # implementation details through a dynamic tool boundary.
        raise _error("internal_error", "tool failed safely") from exc
    if time.monotonic() - started > COMMAND_TIMEOUT_SECONDS * 4:
        # This is informational only: in-process operations cannot be interrupted
        # safely, but clients get truthful evidence that a bounded operation was slow.
        result = dict(result)
        result["slow"] = True
    return result


def dispatch(
    workspace: Workspace, name: str, arguments: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Dispatch one dynamic tool call for the app-server integration.

    This deliberately keeps the workspace as an explicit argument: a caller cannot
    smuggle a new root through tool arguments or ask a long-lived registry to change
    its confinement boundary.
    """
    return call_tool(workspace, name, arguments)


class ToolRegistry:
    """Immutable tool definitions bound to one workspace.

    ``dynamic_tools`` is suitable for the Codex app-server ``dynamicTools`` field;
    the same schemas are valid MCP ``tools/list`` entries.  Registry dispatch never
    accepts executable names, filesystem roots, or network parameters.
    """

    def __init__(
        self,
        workspace: Workspace | str | os.PathLike[str],
        *,
        max_workspace_bytes: int | None = None,
    ):
        if isinstance(workspace, Workspace):
            if max_workspace_bytes is None:
                self.workspace = workspace
            else:
                self.workspace = Workspace(workspace.root, max_workspace_bytes=max_workspace_bytes)
        else:
            self.workspace = Workspace(workspace, max_workspace_bytes=max_workspace_bytes)
        schemas = {spec["name"]: spec for spec in tool_schemas()}
        self._tools = tuple(schemas[name] for name in AGENT_TOOL_NAMES)
        self._dispatch_lock = threading.Lock()

    def _remove_added_entries(self, before: set[str]) -> None:
        try:
            after, _ = self.workspace.snapshot()
        except ToolError:
            return
        for relative in sorted(after - before, key=lambda value: value.count("/"), reverse=True):
            path = self.workspace.root.joinpath(*relative.split("/"))
            try:
                mode = path.lstat().st_mode
                if stat.S_ISDIR(mode):
                    path.rmdir()
                else:
                    path.unlink()
            except OSError:
                # Never recurse through an unexpected entry during error recovery.
                continue

    def _rollback_manifest(self, entries: set[str]) -> dict[str, tuple[int, int]]:
        manifest: dict[str, tuple[int, int]] = {}
        for relative in entries:
            path = self.workspace.root.joinpath(*relative.split("/"))
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise _error("path_unavailable", "workspace rollback state is unavailable") from exc
            manifest[relative] = (
                stat.S_IFMT(metadata.st_mode),
                metadata.st_size if stat.S_ISREG(metadata.st_mode) else 0,
            )
        return manifest

    def _restore_run_shell_capacity(self, before: dict[str, tuple[int, int]]) -> None:
        """Remove new residue and undo file growth without trusting bounded snapshot()."""
        failures = 0
        for directory, directories, files in os.walk(
            self.workspace.root, topdown=False, followlinks=False
        ):
            base = Path(directory)
            for name in [*files, *directories]:
                path = base / name
                relative = path.relative_to(self.workspace.root).as_posix()
                if relative in before:
                    continue
                try:
                    mode = path.lstat().st_mode
                    path.rmdir() if stat.S_ISDIR(mode) else path.unlink()
                except OSError:
                    failures += 1
        for relative, (original_kind, original_size) in before.items():
            path = self.workspace.root.joinpath(*relative.split("/"))
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            except OSError:
                failures += 1
                continue
            current_kind = stat.S_IFMT(metadata.st_mode)
            try:
                if original_kind == stat.S_IFREG and current_kind == stat.S_IFREG:
                    if metadata.st_size > original_size:
                        os.truncate(path, original_size)
                elif original_kind != current_kind:
                    path.rmdir() if stat.S_ISDIR(metadata.st_mode) else path.unlink()
            except OSError:
                failures += 1
        if failures:
            raise _error("tool_cleanup_failed", "analysis quota cleanup was incomplete")
        try:
            self.workspace.snapshot()
            self.workspace.ensure_capacity()
        except ToolError as exc:
            raise _error(
                "tool_cleanup_failed", "analysis quota cleanup did not restore capacity"
            ) from exc

    def dynamic_tools(self) -> list[dict[str, Any]]:
        return [dict(spec) for spec in self._tools]

    @property
    def tools(self) -> list[dict[str, Any]]:
        return self.dynamic_tools()

    @property
    def dynamic_tool_specs(self) -> list[dict[str, Any]]:
        """Property spelling convenient for app-server adapters."""
        return self.dynamic_tools()

    @property
    def specs(self) -> list[dict[str, Any]]:
        return self.dynamic_tools()

    def dispatch(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        canonical = ALIASES.get(name, name) if isinstance(name, str) else name
        with self._dispatch_lock:
            before: set[str] | None = None
            shell_before: dict[str, tuple[int, int]] | None = None
            if canonical == "extract_archive":
                before, _ = self.workspace.snapshot()
            elif canonical == "run_shell":
                entries, _ = self.workspace.snapshot()
                shell_before = self._rollback_manifest(entries)
            try:
                result = dispatch(self.workspace, name, arguments)
                self.workspace.ensure_capacity()
                return result
            except BaseException as exc:
                try:
                    if shell_before is not None:
                        self._restore_run_shell_capacity(shell_before)
                    elif before is not None:
                        self._remove_added_entries(before)
                except ToolError as cleanup:
                    raise cleanup from exc
                raise

    def call(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return self.dispatch(name, arguments)


__all__ = [
    "AGENT_TOOL_NAMES",
    "ALIASES",
    "TOOLS",
    "ToolError",
    "ToolRegistry",
    "Workspace",
    "call_tool",
    "dispatch",
    "tool_schemas",
]
