"""One bounded, source-bound artifact inspection Interface.

The artifact is opened once through descriptor-relative, no-follow operations.  Format
adapters receive that descriptor; none executes the artifact, extracts members, follows
external references, writes files, or accesses the network.  Optional libraries improve
representation depth but are never treated as evidence that an unsupported view succeeded.
"""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import io
import json
import os
import re
import selectors
import signal
import stat
import struct
import subprocess
import tarfile
import time
import zipfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, nullcontext
from typing import TYPE_CHECKING, Any

from . import binary_tools, capstone_tools
from .artifact_worker import run_artifact_worker
from .media_tools import dicom_metadata_from_descriptor, wav_analyze_from_descriptor

if TYPE_CHECKING:
    from .tools import Workspace

# Optional adapters are imported only inside the resource-limited worker. Tests
# inject them when exercising the private in-process parser units directly.
_dpkt: Any = None
_pefile: Any = None
_pypdf: Any = None
_PILImage: Any = None


MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_SCAN_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 128 * 1024
MAX_TEXT_PAGE_BYTES = 32 * 1024
MAX_BYTE_PAGE_BYTES = 32 * 1024
MAX_RECORDS = 100
MAX_ARCHIVE_ENTRIES = 1_000
MAX_ARCHIVE_METADATA_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_DECLARED_BYTES = 512 * 1024 * 1024
MAX_PACKET_BYTES = 1024 * 1024
MAX_PAGES = 256
MAX_PDF_TEXT_PAGES = 2
MAX_PIXELS = 4_000_000
MAX_PIXEL_SCAN = 262_144
MAX_IMAGE_FRAMES = 64
MAX_LSB_BYTES = 4 * 1024
MAX_NATIVE_OUTPUT_BYTES = 32 * 1024
NATIVE_TIMEOUT_SECONDS = 3.0
NATIVE_DRAIN_SECONDS = 1.0

_SELECTION = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
_ASCII_STRING = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16LE_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_UTF16BE_STRING = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")
_SIGNAL = re.compile(r"(?:INCYPHER|flag)\{[^{}\r\n]{1,512}\}")
_TEXT_ENCODINGS = frozenset({"utf-8", "utf-16-le", "utf-16-be", "latin-1", "cp1252"})
_IMAGE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"BM", "bmp"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
)
_FIXED_TESSERACT = (
    "/usr/bin/tesseract",
    "/usr/local/bin/tesseract",
    "/opt/homebrew/bin/tesseract",
)


def _error(code: str, message: str, **details: Any) -> Exception:
    from .tools import ToolError

    stage = (
        "arguments"
        if code in {"invalid_argument", "invalid_cursor", "input_too_large"}
        else ("result" if code in {"output_too_large", "internal_error"} else "execution")
    )
    return ToolError(
        code,
        message,
        details={
            "contract_version": 1,
            "failure_stage": stage,
            "constraint": code,
            **details,
        },
    )


def _value_kind(value: Any) -> str:
    if value is None:
        return "missing"
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
    return "other"


def _json_size(value: Any) -> int:
    return len(json.dumps(value, allow_nan=False, separators=(",", ":")).encode("utf-8"))


def _bounded_result(result: dict[str, Any]) -> dict[str, Any]:
    try:
        size = _json_size(result)
    except (TypeError, ValueError) as exc:
        raise _error("internal_error", "artifact inspector produced an invalid result") from exc
    if size > MAX_OUTPUT_BYTES:
        raise _error("output_too_large", "artifact inspection exceeded the output byte limit")
    return result


def _arguments(arguments: Mapping[str, Any]) -> tuple[str, str, str | None, str | None]:
    if not isinstance(arguments, Mapping) or set(arguments) - {
        "path",
        "view",
        "selection",
        "cursor",
    }:
        raise _error(
            "invalid_argument",
            "unsupported artifact-inspector arguments",
            field_path="arguments",
            constraint="additional_properties",
            actual_kind=_value_kind(arguments),
        )
    path = arguments.get("path")
    if not isinstance(path, str) or not path or "\x00" in path:
        raise _error(
            "invalid_argument",
            "path is required and must be nonempty relative text",
            field_path="path",
            constraint="required_text",
            actual_kind=_value_kind(path),
        )
    try:
        encoded_path = path.encode("utf-8")
    except UnicodeError as exc:
        raise _error(
            "invalid_argument",
            "path must contain valid Unicode text",
            field_path="path",
            constraint="unicode",
            actual_kind="string",
        ) from exc
    if len(encoded_path) > 4096:
        raise _error(
            "input_too_large",
            "path exceeds the input limit",
            field_path="path",
            constraint="max_bytes",
            actual_kind="string",
            actual_size=len(encoded_path),
        )
    view = arguments.get("view", "summary")
    if not isinstance(view, str) or view not in {"summary", "text", "structure", "bytes"}:
        raise _error(
            "invalid_argument",
            "view must be summary, text, structure, or bytes",
            field_path="view",
            constraint="enum",
            actual_kind=_value_kind(view),
        )
    selection = arguments.get("selection")
    if selection is not None and (
        not isinstance(selection, str) or not _SELECTION.fullmatch(selection)
    ):
        raise _error(
            "invalid_argument",
            "selection must be a bounded identifier",
            field_path="selection",
            constraint="bounded_identifier",
            actual_kind=_value_kind(selection),
        )
    cursor = arguments.get("cursor")
    if cursor is not None and (
        not isinstance(cursor, str) or len(cursor) > 1024 or not cursor.isascii()
    ):
        raise _error(
            "invalid_cursor",
            "cursor must be bounded ASCII text",
            field_path="cursor",
            constraint="bounded_ascii",
            actual_kind=_value_kind(cursor),
        )
    if view == "summary" and cursor is not None:
        raise _error(
            "invalid_argument",
            "summary view does not accept a cursor",
            field_path="cursor",
            constraint="forbidden",
            actual_kind="string",
        )
    return path, view, selection, cursor


@contextmanager
def _source(workspace: Workspace, relative: str) -> Iterator[tuple[int, int]]:
    """Open a regular file beneath Workspace using anchored no-follow descriptors."""
    from .tools import Workspace

    if not isinstance(workspace, Workspace):
        raise _error("invalid_workspace", "artifact inspection requires a bound workspace")
    normalized = relative.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        raise _error("path_outside_workspace", "absolute paths are not allowed")
    parts = tuple(part for part in normalized.split("/") if part not in {"", "."})
    if not parts:
        raise _error("not_a_file", "path must name a regular file")
    if ".." in parts:
        raise _error("path_outside_workspace", "path traversal is not allowed")
    if len(parts) > 128:
        raise _error("limit_exceeded", "path has too many components")
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise _error("unsupported_platform", "descriptor-bound no-follow access is unavailable")
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
        if metadata.st_size > MAX_SOURCE_BYTES:
            raise _error("input_too_large", "artifact exceeds the source byte limit")
        yield descriptor, metadata.st_size
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            raise _error("not_found", "artifact input was not found") from exc
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise _error(
                "symlink_or_invalid_path", "symlinks and invalid components are refused"
            ) from exc
        raise _error("read_failed", "artifact input could not be opened") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _pread(descriptor: int, length: int, offset: int, size: int) -> bytes:
    if offset < 0 or length < 0 or offset > size:
        raise _error("invalid_cursor", "artifact cursor is outside the source")
    length = min(length, size - offset)
    try:
        data = os.pread(descriptor, length, offset)
    except OSError as exc:
        raise _error("read_failed", "artifact bytes could not be read") from exc
    if len(data) != length:
        raise _error("source_changed", "artifact changed during inspection")
    return data


def _identity(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    before = os.fstat(descriptor)
    while offset < size:
        block = _pread(descriptor, min(1024 * 1024, size - offset), offset, size)
        digest.update(block)
        offset += len(block)
    after = os.fstat(descriptor)
    facts = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, fact) != getattr(after, fact) for fact in facts):
        raise _error("source_changed", "artifact changed during inspection")
    return digest.hexdigest()


def _source_facts(descriptor: int) -> tuple[int, int, int, int, int]:
    metadata = os.fstat(descriptor)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _encode_cursor(
    offset: int, digest: str, format_name: str, view: str, selection: str | None
) -> str:
    payload = json.dumps(
        {"v": 1, "o": offset, "h": digest, "f": format_name, "w": view, "s": selection},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def _cursor_offset(
    cursor: str | None,
    digest: str,
    format_name: str,
    view: str,
    selection: str | None,
    maximum: int,
) -> int:
    if cursor is None:
        return 0
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        payload = json.loads(raw)
    except (ValueError, UnicodeError, binascii.Error, json.JSONDecodeError) as exc:
        raise _error("invalid_cursor", "cursor is not a valid artifact continuation") from exc
    if not isinstance(payload, dict) or set(payload) != {"v", "o", "h", "f", "w", "s"}:
        raise _error("invalid_cursor", "cursor shape is invalid")
    if (
        payload["v"] != 1
        or payload["h"] != digest
        or payload["f"] != format_name
        or payload["w"] != view
        or payload["s"] != selection
    ):
        raise _error("stale_cursor", "cursor does not match this artifact and view")
    offset = payload["o"]
    if type(offset) is not int or not 0 <= offset <= maximum:
        raise _error("invalid_cursor", "cursor position is outside the bounded view")
    return offset


def _base(
    path: str,
    size: int,
    digest: str,
    format_name: str,
    view: str,
    selection: str | None,
) -> dict[str, Any]:
    return {
        "path": path,
        "source_bytes": size,
        "source_sha256": digest,
        "format": format_name,
        "view": view,
        "selection": selection,
    }


def _finish(
    base: dict[str, Any],
    data: Any,
    coverage: str,
    stop_reason: str,
    *,
    next_offset: int | None = None,
) -> dict[str, Any]:
    if coverage not in {"complete", "partial", "unsupported"}:
        raise _error("internal_error", "invalid artifact coverage state")
    result = {**base, "coverage": coverage, "stop_reason": stop_reason, "data": data}
    if next_offset is not None:
        result["next_cursor"] = _encode_cursor(
            next_offset,
            base["source_sha256"],
            base["format"],
            base["view"],
            base["selection"],
        )
    return _bounded_result(result)


def _detect_text(prefix: bytes) -> tuple[str, int] | None:
    if prefix.startswith(b"\xef\xbb\xbf"):
        return "utf-8", 3
    if prefix.startswith(b"\xff\xfe"):
        return "utf-16-le", 2
    if prefix.startswith(b"\xfe\xff"):
        return "utf-16-be", 2
    if not prefix:
        return "utf-8", 0
    even_nuls = prefix[0::2].count(0)
    odd_nuls = prefix[1::2].count(0)
    pairs = max(1, len(prefix) // 2)
    for encoding, likely, unlikely in (
        ("utf-16-le", odd_nuls, even_nuls),
        ("utf-16-be", even_nuls, odd_nuls),
    ):
        if likely / pairs > 0.35 and unlikely / pairs < 0.05:
            try:
                prefix[: len(prefix) // 2 * 2].decode(encoding)
            except UnicodeDecodeError:
                continue
            return encoding, 0
    try:
        text = prefix.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if text and _printable_fraction(text) >= 0.85:
        return "utf-8", 0
    if b"\x00" not in prefix:
        for encoding in ("cp1252", "latin-1"):
            try:
                text = prefix.decode(encoding)
            except UnicodeDecodeError:
                continue
            if _printable_fraction(text) >= 0.9:
                return encoding, 0
    return None


def _printable_fraction(text: str) -> float:
    if not text:
        return 1.0
    return sum(character.isprintable() or character in "\r\n\t" for character in text) / len(text)


def _detect_format(prefix: bytes, size: int, selection: str | None) -> tuple[str, dict[str, Any]]:
    if prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip", {}
    if prefix.startswith(b"\x1f\x8b"):
        return "gzip", {}
    if prefix.startswith(b"%PDF-"):
        return "pdf", {}
    if prefix.startswith(b"\x7fELF"):
        return "elf", {}
    if prefix.startswith(b"MZ"):
        return "pe", {}
    if prefix[:4] in {
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    }:
        return "pcap", {}
    if prefix.startswith(b"\x0a\x0d\x0d\x0a"):
        return "pcapng", {}
    if len(prefix) >= 132 and prefix[128:132] == b"DICM":
        return "dicom", {}
    if prefix.startswith(b"RIFF") and prefix[8:12] == b"WAVE":
        return "wav", {}
    for signature, name in _IMAGE_SIGNATURES:
        if prefix.startswith(signature):
            return name, {}
    if prefix.startswith(b"RIFF") and prefix[8:12] == b"WEBP":
        return "webp", {}
    if len(prefix) >= 265 and prefix[257:263] in {b"ustar\x00", b"ustar "}:
        return "tar", {}
    forced = _selection_encoding(selection)
    detected = (forced, 0) if forced else _detect_text(prefix)
    if detected:
        return "text", {"encoding": detected[0], "bom_bytes": detected[1]}
    return "binary", {}


def _selection_encoding(selection: str | None) -> str | None:
    if selection is None or not selection.startswith("encoding:"):
        return None
    encoding = selection.removeprefix("encoding:")
    if encoding not in _TEXT_ENCODINGS:
        raise _error("invalid_argument", "selection names an unsupported text encoding")
    return encoding


def _check_selection(selection: str | None, allowed: set[str]) -> None:
    if selection is not None and selection not in allowed:
        raise _error("invalid_argument", "selection is not supported for this format and view")


def _disassembly_address(selection: str | None) -> int | None:
    if selection == "disassembly":
        return None
    match = re.fullmatch(r"disassembly:0x([0-9A-Fa-f]{1,16})", selection or "")
    if match is None:
        raise _error(
            "invalid_argument",
            "disassembly selection must be disassembly or disassembly:0x<address>",
        )
    return int(match.group(1), 16)


def _bytes_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    _check_selection(base["selection"], set())
    offset = _cursor_offset(
        cursor,
        base["source_sha256"],
        base["format"],
        "bytes",
        None,
        size,
    )
    data = _pread(descriptor, MAX_BYTE_PAGE_BYTES, offset, size)
    end = offset + len(data)
    return _finish(
        base,
        {
            "offset": offset,
            "length": len(data),
            "data_base64": base64.b64encode(data).decode(),
            "hex_preview": data[:256].hex(),
        },
        "complete" if end >= size else "partial",
        "end_of_file" if end >= size else "byte_page_limit",
        next_offset=end if end < size else None,
    )


def _decode_page(data: bytes, encoding: str) -> tuple[str, int]:
    if encoding.startswith("utf-16"):
        data = data[: len(data) // 2 * 2]
    if encoding == "utf-8":
        end = len(data)
        while end and end > len(data) - 4:
            try:
                return data[:end].decode(encoding), end
            except UnicodeDecodeError as exc:
                if exc.start < end - 4:
                    break
                end = exc.start
    try:
        return data.decode(encoding), len(data)
    except UnicodeDecodeError:
        return data.decode(encoding, "replace"), len(data)


def _text_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
    encoding: str,
    bom_bytes: int,
) -> dict[str, Any]:
    allowed = {f"encoding:{item}" for item in _TEXT_ENCODINGS}
    _check_selection(base["selection"], allowed)
    offset = _cursor_offset(
        cursor,
        base["source_sha256"],
        "text",
        base["view"],
        base["selection"],
        size,
    )
    if cursor is None:
        offset = bom_bytes
    if encoding.startswith("utf-16") and offset % 2:
        raise _error("invalid_cursor", "UTF-16 continuation is not code-unit aligned")
    raw = _pread(descriptor, MAX_TEXT_PAGE_BYTES + 4, offset, size)
    text, consumed = _decode_page(raw, encoding)
    if not consumed and offset < size:
        raise _error("invalid_encoding", "text page cannot be decoded at this boundary")
    if base["view"] == "summary":
        preview = text[:2048]
        end = offset + consumed
        return _finish(
            base,
            {
                "encoding": encoding,
                "bom_bytes": bom_bytes,
                "preview": preview,
                "preview_truncated": len(text) > len(preview) or end < size,
                "scanned_bytes": consumed,
            },
            "complete" if end >= size else "partial",
            "end_of_file" if end >= size else "summary_preview_limit",
        )
    if base["view"] == "structure":
        lines = text.splitlines(keepends=True)
        selected = lines[:MAX_RECORDS]
        if len(lines) > MAX_RECORDS:
            selected_text = "".join(selected)
            consumed = len(selected_text.encode(encoding, "replace"))
            text = selected_text
        records = []
        character_offset = 0
        for line in selected:
            value = line.rstrip("\r\n")
            records.append(
                {
                    "character_offset": character_offset,
                    "text": value[:1024],
                    "truncated": len(value) > 1024,
                }
            )
            character_offset += len(line)
        data: Any = {
            "encoding": encoding,
            "byte_offset": offset,
            "byte_length": consumed,
            "lines": records,
        }
        reason = "record_limit" if len(lines) > MAX_RECORDS else "text_page_limit"
    else:
        data = {
            "encoding": encoding,
            "byte_offset": offset,
            "byte_length": consumed,
            "text": text,
        }
        reason = "text_page_limit"
    end = offset + consumed
    complete = end >= size
    return _finish(
        base,
        data,
        "complete" if complete else "partial",
        "end_of_file" if complete else reason,
        next_offset=end if not complete else None,
    )


def _safe_archive_name(name: str) -> tuple[str, bool]:
    clipped = name[:512]
    normalized = name.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    unsafe = (
        normalized.startswith(("/", "~"))
        or any(part == ".." for part in parts)
        or len(name.encode("utf-8", "replace")) > 4096
    )
    return clipped, unsafe


def _zip_preflight(descriptor: int, size: int) -> tuple[int, int, int]:
    tail_size = min(size, 65_535 + 22)
    tail = _pread(descriptor, tail_size, size - tail_size, size)
    position = tail.rfind(b"PK\x05\x06")
    if position < 0 or position + 22 > len(tail):
        raise _error("invalid_artifact", "ZIP end-of-directory record is missing")
    comment_size = struct.unpack_from("<H", tail, position + 20)[0]
    if position + 22 + comment_size != len(tail):
        raise _error("invalid_artifact", "ZIP end-of-directory record is inconsistent")
    disk, central_disk, disk_entries, entries = struct.unpack_from("<HHHH", tail, position + 4)
    central_size, central_offset = struct.unpack_from("<II", tail, position + 12)
    if (
        disk
        or central_disk
        or disk_entries != entries
        or entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    ):
        raise _error("unsupported_format", "multi-disk and ZIP64 archives are unsupported")
    if entries > MAX_ARCHIVE_ENTRIES:
        raise _error("limit_exceeded", "ZIP entry count exceeds the inventory limit")
    if central_size > MAX_ARCHIVE_METADATA_BYTES or central_offset + central_size > size:
        raise _error("limit_exceeded", "ZIP central directory exceeds its metadata limit")
    return entries, central_size, central_offset


def _zip_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    _check_selection(base["selection"], {"entries"})
    declared, central_size, _ = _zip_preflight(descriptor, size)
    try:
        with os.fdopen(os.dup(descriptor), "rb") as source, zipfile.ZipFile(source) as archive:
            infos = archive.infolist()
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise _error("invalid_artifact", "ZIP metadata is malformed") from exc
    if len(infos) != declared:
        raise _error("invalid_artifact", "ZIP entry count does not match its directory")
    total_declared = sum(info.file_size for info in infos)
    oversized = total_declared > MAX_ARCHIVE_DECLARED_BYTES
    if base["view"] == "summary":
        records = infos[: min(10, len(infos))]
        start = 0
    else:
        start = _cursor_offset(
            cursor,
            base["source_sha256"],
            "zip",
            base["view"],
            base["selection"],
            len(infos),
        )
        records = infos[start : start + MAX_RECORDS]
    entries = []
    for info in records:
        name, unsafe_name = _safe_archive_name(info.filename)
        mode = info.external_attr >> 16
        linked = stat.S_ISLNK(mode)
        entries.append(
            {
                "name": name,
                "size": info.file_size,
                "compressed_size": info.compress_size,
                "compression": info.compress_type,
                "crc32": f"{info.CRC:08x}",
                "directory": info.is_dir(),
                "linked": linked,
                "unsafe": unsafe_name or linked,
            }
        )
    if base["view"] == "text":
        data: Any = {"entry_names": [entry["name"] for entry in entries]}
    else:
        data = {
            "entry_count": len(infos),
            "central_directory_bytes": central_size,
            "total_declared_bytes": total_declared,
            "declared_bytes_over_inventory_limit": oversized,
            "entries": entries,
            "inventory_only": True,
        }
    end = start + len(records)
    complete = end >= len(infos)
    if base["view"] == "summary" and not complete:
        return _finish(base, data, "partial", "summary_preview_limit")
    return _finish(
        base,
        data,
        "complete" if complete else "partial",
        "end_of_inventory" if complete else "record_limit",
        next_offset=end if not complete else None,
    )


def _tar_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    _check_selection(base["selection"], {"entries"})
    start = 0
    if base["view"] != "summary":
        start = _cursor_offset(
            cursor,
            base["source_sha256"],
            "tar",
            base["view"],
            base["selection"],
            MAX_ARCHIVE_ENTRIES,
        )
    selected = []
    count = 0
    total_declared = 0
    more = False
    try:
        with os.fdopen(os.dup(descriptor), "rb") as source:
            source.seek(0)
            with tarfile.open(fileobj=source, mode="r:") as archive:
                for member in archive:
                    count += 1
                    if count > MAX_ARCHIVE_ENTRIES:
                        raise _error(
                            "limit_exceeded", "TAR entry count exceeds the inventory limit"
                        )
                    total_declared += max(0, member.size)
                    if count <= start:
                        continue
                    page_limit = 10 if base["view"] == "summary" else MAX_RECORDS
                    if len(selected) >= page_limit:
                        more = True
                        continue
                    name, unsafe_name = _safe_archive_name(member.name)
                    linked = member.issym() or member.islnk()
                    selected.append(
                        {
                            "name": name,
                            "size": member.size,
                            "directory": member.isdir(),
                            "linked": linked,
                            "unsafe": unsafe_name or linked or member.isdev(),
                            "type": member.type.decode("ascii", "replace")
                            if isinstance(member.type, bytes)
                            else str(member.type),
                        }
                    )
    except (OSError, tarfile.TarError) as exc:
        raise _error("invalid_artifact", "TAR metadata is malformed") from exc
    data: Any
    if base["view"] == "text":
        data = {"entry_names": [entry["name"] for entry in selected]}
    else:
        data = {
            "entry_count": count,
            "total_declared_bytes": total_declared,
            "declared_bytes_over_inventory_limit": total_declared > MAX_ARCHIVE_DECLARED_BYTES,
            "entries": selected,
            "inventory_only": True,
        }
    end = start + len(selected)
    if more:
        reason = "summary_preview_limit" if base["view"] == "summary" else "record_limit"
        return _finish(
            base,
            data,
            "partial",
            reason,
            next_offset=end if base["view"] != "summary" else None,
        )
    return _finish(base, data, "complete", "end_of_inventory")


def _gzip_metadata(descriptor: int, size: int) -> dict[str, Any]:
    data = _pread(descriptor, min(size, 64 * 1024), 0, size)
    if len(data) < 10 or data[:3] != b"\x1f\x8b\x08":
        raise _error("invalid_artifact", "gzip header is malformed")
    flags = data[3]
    if flags & 0xE0:
        raise _error("invalid_artifact", "gzip reserved flags are set")
    position = 10
    if flags & 4:
        if position + 2 > len(data):
            raise _error("limit_exceeded", "gzip extra header exceeds the scan limit")
        extra = struct.unpack_from("<H", data, position)[0]
        position += 2 + extra
    strings = {}
    for mask, field in ((8, "original_name"), (16, "comment")):
        if flags & mask:
            end = data.find(b"\x00", position)
            if end < 0:
                raise _error("limit_exceeded", "gzip text header exceeds the scan limit")
            strings[field] = data[position:end].decode("latin-1", "replace")[:512]
            position = end + 1
    if flags & 2:
        position += 2
    if position > len(data) or size < position + 8:
        raise _error("invalid_artifact", "gzip header or trailer is incomplete")
    crc32, original_size_mod32 = struct.unpack("<II", _pread(descriptor, 8, size - 8, size))
    return {
        "method": "deflate",
        "header_bytes": position,
        "compressed_bytes": size,
        "crc32": f"{crc32:08x}",
        "original_size_mod32": original_size_mod32,
        **strings,
        "inventory_only": True,
    }


def _gzip_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    _check_selection(base["selection"], {"entries"})
    if cursor is not None:
        raise _error("invalid_argument", "single-stream gzip inventory has no continuation")
    metadata = _gzip_metadata(descriptor, size)
    if base["view"] == "text":
        data: Any = {key: metadata[key] for key in ("original_name", "comment") if key in metadata}
    else:
        data = metadata
    return _finish(base, data, "partial", "inventory_only_no_decompression")


def _pdf_reader(descriptor: int) -> tuple[Any, io.BufferedReader]:
    if _pypdf is None:
        raise _error("tool_unavailable", "pypdf is unavailable")
    source = os.fdopen(os.dup(descriptor), "rb")
    try:
        reader = _pypdf.PdfReader(source, strict=True)
    except Exception as exc:
        source.close()
        raise _error("invalid_artifact", "PDF structure is malformed") from exc
    return reader, source


def _pdf_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    allowed = {"metadata"}
    page_selection = None
    if base["selection"] and base["selection"].startswith("page:"):
        try:
            page_selection = int(base["selection"].removeprefix("page:"))
        except ValueError as exc:
            raise _error("invalid_argument", "PDF page selection is invalid") from exc
    elif base["selection"] is not None and base["selection"] not in allowed:
        raise _error("invalid_argument", "PDF selection must be metadata or page:<index>")
    if _pypdf is None:
        version = (
            _pread(descriptor, min(size, 16), 0, size).splitlines()[0].decode("ascii", "replace")
        )
        return _finish(
            base,
            {"header": version, "dependency": "pypdf unavailable"},
            "unsupported",
            "dependency_unavailable",
        )
    if base["view"] == "text" and not all(
        hasattr(_pypdf, name) for name in ("Configuration", "apply_configuration")
    ):
        return _finish(
            base,
            {"dependency": "pypdf lacks bounded stream configuration"},
            "unsupported",
            "dependency_lacks_resource_limits",
        )
    configuration_context = nullcontext()
    if all(hasattr(_pypdf, name) for name in ("Configuration", "apply_configuration")):
        configuration = _pypdf.Configuration(
            maximum_declared_stream_length=MAX_SCAN_BYTES,
            array_based_stream_maximum_output_length=MAX_SCAN_BYTES,
            jbig2_maximum_output_length=MAX_SCAN_BYTES,
            lzw_maximum_output_length=MAX_SCAN_BYTES,
            run_length_maximum_output_length=MAX_SCAN_BYTES,
            zlib_maximum_output_length=MAX_SCAN_BYTES,
            zlib_maximum_recovery_input_length=min(MAX_SCAN_BYTES, 1024 * 1024),
            flate_maximum_columns=100_000,
            flate_maximum_row_length=1024 * 1024,
            image_maximum_buffer_size=MAX_SCAN_BYTES,
            xmp_maximum_input_length=1024 * 1024,
            xmp_maximum_element_count=10_000,
            outline_maximum_entries=10_000,
            outline_maximum_depth=64,
            page_tree_maximum_entries=MAX_PAGES + 1,
            page_tree_maximum_depth=64,
            xform_maximum_invocations_per_extraction=1_000,
            jbig2dec_binary=None,
        )
        configuration_context = _pypdf.apply_configuration(configuration)
    configuration_context.__enter__()
    source = None
    try:
        reader, source = _pdf_reader(descriptor)
        if reader.is_encrypted:
            return _finish(base, {"encrypted": True}, "unsupported", "encrypted_pdf")
        page_count = len(reader.pages)
        if page_count > MAX_PAGES:
            return _finish(
                base,
                {"page_count": page_count, "page_limit": MAX_PAGES},
                "partial",
                "page_limit",
            )
        metadata = {}
        if reader.metadata:
            for key in ("title", "author", "subject", "creator", "producer"):
                value = getattr(reader.metadata, key, None)
                if value is not None:
                    metadata[key] = str(value)[:512]
        if base["view"] == "summary" or base["selection"] == "metadata":
            return _finish(
                base,
                {"page_count": page_count, "encrypted": False, "metadata": metadata},
                "complete",
                "metadata_complete",
            )
        if page_selection is not None:
            if not 0 <= page_selection < page_count:
                raise _error("invalid_argument", "selected PDF page is outside the document")
            start, stop = page_selection, page_selection + 1
        else:
            start = _cursor_offset(
                cursor,
                base["source_sha256"],
                "pdf",
                base["view"],
                base["selection"],
                page_count,
            )
            stop = min(page_count, start + (MAX_PDF_TEXT_PAGES if base["view"] == "text" else 16))
        pages = []
        output_used = 0
        reason = "page_window_limit"
        for index in range(start, stop):
            page = reader.pages[index]
            width = float(page.mediabox.width)
            height = float(page.mediabox.height)
            record: dict[str, Any] = {
                "index": index,
                "width_points": round(width, 3),
                "height_points": round(height, 3),
                "rotation": int(page.rotation or 0),
            }
            if base["view"] == "text":
                try:
                    extracted = page.extract_text() or ""
                except Exception as exc:
                    raise _error("invalid_artifact", "PDF page text cannot be decoded") from exc
                available = max(0, MAX_TEXT_PAGE_BYTES - output_used)
                encoded = extracted.encode("utf-8", "replace")
                clipped = encoded[:available].decode("utf-8", "ignore")
                record["text"] = clipped
                record["text_truncated"] = len(encoded) > available
                output_used += len(clipped.encode())
                if record["text_truncated"]:
                    pages.append(record)
                    reason = "output_limit"
                    stop = index + 1
                    break
            pages.append(record)
        end = stop
        complete = page_selection is not None or end >= page_count
        if reason == "output_limit":
            complete = False
        return _finish(
            base,
            {"page_count": page_count, "pages": pages},
            "complete" if complete else "partial",
            "selected_page_complete"
            if page_selection is not None and reason != "output_limit"
            else "end_of_document"
            if complete
            else reason,
            next_offset=end if not complete and reason != "output_limit" else None,
        )
    finally:
        if source is not None:
            source.close()
        configuration_context.__exit__(None, None, None)


def _network_summary(packet: bytes, linktype: int) -> dict[str, Any] | None:
    if _dpkt is None:
        return None
    try:
        decoded: Any
        if linktype == getattr(_dpkt.pcap, "DLT_EN10MB", 1):
            ethernet = _dpkt.ethernet.Ethernet(packet)
            record: dict[str, Any] = {
                "ethernet_source": ethernet.src.hex(":"),
                "ethernet_destination": ethernet.dst.hex(":"),
                "ether_type": ethernet.type,
            }
            decoded = ethernet.data
        else:
            return None
        if isinstance(decoded, (_dpkt.ip.IP, _dpkt.ip6.IP6)):
            import socket

            family = socket.AF_INET if isinstance(decoded, _dpkt.ip.IP) else socket.AF_INET6
            record.update(
                {
                    "ip_source": socket.inet_ntop(family, decoded.src),
                    "ip_destination": socket.inet_ntop(family, decoded.dst),
                    "ip_protocol": decoded.p,
                }
            )
            transport = decoded.data
            if isinstance(transport, (_dpkt.tcp.TCP, _dpkt.udp.UDP)):
                record.update(source_port=transport.sport, destination_port=transport.dport)
        return record
    except (ValueError, TypeError, IndexError, struct.error, _dpkt.Error):
        return None


def _pcap_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    _check_selection(base["selection"], {"packets"})
    header = _pread(descriptor, 24, 0, size)
    magic = header[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        endian = "<"
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        endian = ">"
    else:
        raise _error("invalid_artifact", "PCAP byte order is invalid")
    nanosecond = magic in {b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
    major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack(endian + "HHiIII", header[4:])
    if major != 2 or minor != 4 or not 1 <= snaplen <= MAX_PACKET_BYTES:
        raise _error("unsupported_format", "PCAP version or snapshot length is unsupported")
    if base["view"] == "summary":
        return _finish(
            base,
            {
                "version": f"{major}.{minor}",
                "nanosecond_timestamps": nanosecond,
                "snapshot_length": snaplen,
                "linktype": linktype,
                "packet_decode": "dpkt" if _dpkt is not None else "unavailable",
            },
            "partial",
            "packet_inventory_not_scanned",
        )
    position = _cursor_offset(
        cursor,
        base["source_sha256"],
        "pcap",
        base["view"],
        base["selection"],
        size,
    )
    if cursor is None:
        position = 24
    records = []
    scanned = 0
    while position < size and len(records) < MAX_RECORDS and scanned + 16 <= MAX_SCAN_BYTES:
        record_header = _pread(descriptor, 16, position, size)
        seconds, fraction, captured, original = struct.unpack(endian + "IIII", record_header)
        if captured > snaplen or captured > MAX_PACKET_BYTES or captured > original:
            raise _error("invalid_artifact", "PCAP packet length is invalid")
        if position + 16 + captured > size:
            raise _error("invalid_artifact", "PCAP packet extends outside the source")
        if 16 + captured > MAX_SCAN_BYTES - scanned:
            break
        packet = _pread(descriptor, captured, position + 16, size)
        row = {
            "offset": position,
            "timestamp_seconds": seconds,
            "timestamp_fraction": fraction,
            "captured_length": captured,
            "original_length": original,
            "data_hex_preview": packet[:64].hex(),
        }
        decoded = _network_summary(packet, linktype)
        if decoded:
            row["decoded"] = decoded
        records.append(row)
        consumed = 16 + captured
        position += consumed
        scanned += consumed
    complete = position >= size
    if base["view"] == "text":
        data: Any = {
            "packets": [record.get("decoded", {}) for record in records if record.get("decoded")]
        }
    else:
        data = {"linktype": linktype, "records": records, "scanned_bytes": scanned}
    reason = (
        "end_of_capture"
        if complete
        else ("record_limit" if len(records) >= MAX_RECORDS else "scan_limit")
    )
    return _finish(
        base,
        data,
        "complete" if complete else "partial",
        reason,
        next_offset=position if not complete else None,
    )


def _pcapng_section_endian(header: bytes) -> str:
    if header[8:12] == b"\x4d\x3c\x2b\x1a":
        return "<"
    if header[8:12] == b"\x1a\x2b\x3c\x4d":
        return ">"
    raise _error("invalid_artifact", "PCAPNG section byte order is invalid")


def _encode_pcapng_cursor(
    offset: int,
    section_offset: int,
    endian: str,
    base: Mapping[str, Any],
) -> str:
    payload = json.dumps(
        {
            "v": 1,
            "o": offset,
            "h": base["source_sha256"],
            "f": "pcapng",
            "w": base["view"],
            "s": base["selection"],
            "e": endian,
            "q": section_offset,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def _pcapng_cursor_position(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: Mapping[str, Any],
    initial_endian: str,
) -> tuple[int, str, int]:
    if cursor is None:
        return 0, initial_endian, 0
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        payload = json.loads(raw)
    except (ValueError, UnicodeError, binascii.Error, json.JSONDecodeError) as exc:
        raise _error("invalid_cursor", "cursor is not a valid artifact continuation") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "v",
        "o",
        "h",
        "f",
        "w",
        "s",
        "e",
        "q",
    }:
        raise _error("invalid_cursor", "PCAPNG cursor shape is invalid")
    if (
        payload["v"] != 1
        or payload["h"] != base["source_sha256"]
        or payload["f"] != "pcapng"
        or payload["w"] != base["view"]
        or payload["s"] != base["selection"]
    ):
        raise _error("stale_cursor", "cursor does not match this artifact and view")
    position, section_offset, endian = payload["o"], payload["q"], payload["e"]
    if (
        type(position) is not int
        or type(section_offset) is not int
        or type(endian) is not str
        or endian not in {"<", ">"}
        or not 0 <= section_offset < position < size
    ):
        raise _error("invalid_cursor", "PCAPNG cursor position is invalid")
    section = _pread(descriptor, 12, section_offset, size)
    if section[:4] != b"\x0a\x0d\x0d\x0a" or _pcapng_section_endian(section) != endian:
        raise _error("invalid_cursor", "PCAPNG cursor section binding is invalid")
    section_length = struct.unpack_from(endian + "I", section, 4)[0]
    if (
        section_length < 28
        or section_length % 4
        or section_offset + section_length > position
        or section_offset + section_length > size
    ):
        raise _error("invalid_cursor", "PCAPNG cursor section is invalid")
    trailer = _pread(descriptor, 4, section_offset + section_length - 4, size)
    if struct.unpack(endian + "I", trailer)[0] != section_length:
        raise _error("invalid_cursor", "PCAPNG cursor section trailer is invalid")
    return position, endian, section_offset


def _pcapng_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    _check_selection(base["selection"], {"packets", "blocks"})
    first = _pread(descriptor, 12, 0, size)
    endian = _pcapng_section_endian(first)
    if base["view"] == "summary":
        block_length = struct.unpack_from(endian + "I", first, 4)[0]
        if block_length < 28 or block_length > size:
            raise _error("invalid_artifact", "PCAPNG section header is invalid")
        return _finish(
            base,
            {
                "byte_order": "little" if endian == "<" else "big",
                "section_header_bytes": block_length,
                "packet_decode": "dpkt available" if _dpkt is not None else "unavailable",
            },
            "partial",
            "block_inventory_not_scanned",
        )
    position, endian, section_offset = _pcapng_cursor_position(
        descriptor,
        size,
        cursor,
        base,
        endian,
    )
    records = []
    scanned = 0
    while position < size and len(records) < MAX_RECORDS and scanned < MAX_SCAN_BYTES:
        header = _pread(descriptor, 12, position, size)
        section_header = header[:4] == b"\x0a\x0d\x0d\x0a"
        block_endian = _pcapng_section_endian(header) if section_header else endian
        block_type = struct.unpack_from(block_endian + "I", header, 0)[0]
        block_length = struct.unpack_from(block_endian + "I", header, 4)[0]
        minimum_length = 28 if section_header else 12
        if (
            block_length < minimum_length
            or block_length % 4
            or block_length > MAX_SCAN_BYTES
            or position + block_length > size
        ):
            raise _error("invalid_artifact", "PCAPNG block length is invalid")
        if scanned + block_length > MAX_SCAN_BYTES:
            break
        trailer = _pread(descriptor, 4, position + block_length - 4, size)
        if struct.unpack(block_endian + "I", trailer)[0] != block_length:
            raise _error("invalid_artifact", "PCAPNG block length trailer is inconsistent")
        retained = _pread(descriptor, min(block_length - 4, 28 + 64), position, size)
        row: dict[str, Any] = {
            "offset": position,
            "block_type": f"0x{block_type:08x}",
            "block_length": block_length,
        }
        if block_type == 6 and block_length >= 32:
            interface, high, low, captured, original = struct.unpack_from(
                block_endian + "IIIII", retained, 8
            )
            if (
                captured > MAX_PACKET_BYTES
                or captured > original
                or 28 + captured > block_length - 4
            ):
                raise _error("invalid_artifact", "PCAPNG enhanced packet length is invalid")
            row.update(
                interface_id=interface,
                timestamp=(high << 32) | low,
                captured_length=captured,
                original_length=original,
                data_hex_preview=retained[28 : 28 + min(captured, 64)].hex(),
            )
        records.append(row)
        if section_header:
            endian = block_endian
            section_offset = position
        position += block_length
        scanned += block_length
    complete = position >= size
    data: Any = {"records": records, "scanned_bytes": scanned}
    if base["view"] == "text":
        data = {"packet_blocks": [row for row in records if "captured_length" in row]}
    reason = (
        "end_of_capture"
        if complete
        else ("record_limit" if len(records) >= MAX_RECORDS else "scan_limit")
    )
    result = _finish(
        base,
        data,
        "complete" if complete else "partial",
        reason,
    )
    if not complete:
        result["next_cursor"] = _encode_pcapng_cursor(position, section_offset, endian, base)
        return _bounded_result(result)
    return result


def _elf_metadata(descriptor: int, size: int, start: int, limit: int) -> dict[str, Any]:
    header = binary_tools._header(descriptor, size)
    names = b""
    if header["shstrndx"]:
        name_section = binary_tools._section(descriptor, size, header, header["shstrndx"])
        if name_section[1] != 3:
            raise _error("invalid_artifact", "ELF section names are not a string table")
        names = binary_tools._read(descriptor, name_section[4], name_section[5], size)
    sections = []
    for index in range(start, min(start + limit, header["shnum"])):
        fields = binary_tools._section(descriptor, size, header, index)
        name_offset, kind, flags, address, file_offset, byte_size, link, _, alignment, _ = fields
        if kind not in {0, 8} and file_offset + byte_size > size:
            raise _error("invalid_artifact", "ELF section extends outside the source")
        if name_offset and (not names or name_offset >= len(names)):
            raise _error("invalid_artifact", "ELF section-name offset is invalid")
        raw_name = names[name_offset : name_offset + 129].split(b"\x00", 1)[0] if names else b""
        sections.append(
            {
                "index": index,
                "name": raw_name.decode("utf-8", "replace")[:128],
                "type": kind,
                "flags": hex(flags),
                "address": hex(address),
                "offset": file_offset,
                "size": byte_size,
                "link": link,
                "alignment": alignment,
            }
        )
    return {
        "class_bits": header["bits"],
        "byte_order": "little" if header["endian"] == "<" else "big",
        "type": header["type"],
        "machine": header["machine"],
        "entry_address": hex(header["entry"]),
        "program_header_count": header["phnum"],
        "section_count": header["shnum"],
        "sections": sections,
    }


def _elf_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    if isinstance(base["selection"], str) and (
        base["selection"] == "disassembly" or base["selection"].startswith("disassembly:")
    ):
        if base["view"] not in {"text", "structure"}:
            raise _error("invalid_argument", "ELF disassembly requires text or structure view")
        return _disassembly_view(descriptor, size, cursor, base)
    section_selection = None
    if base["selection"] and base["selection"].startswith("section:"):
        try:
            section_selection = int(base["selection"].removeprefix("section:"))
        except ValueError as exc:
            raise _error("invalid_argument", "ELF section selection is invalid") from exc
    elif base["selection"] is not None:
        raise _error("invalid_argument", "ELF selection must be section:<index> or disassembly")
    if base["view"] == "text":
        return _binary_strings(descriptor, size, cursor, base)
    header = binary_tools._header(descriptor, size)
    maximum = header["shnum"]
    if section_selection is not None:
        if not 0 <= section_selection < maximum:
            raise _error("invalid_argument", "selected ELF section is outside the table")
        start, limit = section_selection, 1
    elif base["view"] == "summary":
        start, limit = 0, min(10, MAX_RECORDS)
    else:
        start = _cursor_offset(
            cursor,
            base["source_sha256"],
            "elf",
            base["view"],
            base["selection"],
            maximum,
        )
        limit = MAX_RECORDS
    data = _elf_metadata(descriptor, size, start, limit)
    end = start + len(data["sections"])
    complete = section_selection is not None or end >= maximum
    reason = (
        "selected_section_complete"
        if section_selection is not None
        else ("end_of_sections" if complete else "record_limit")
    )
    return _finish(
        base,
        data,
        "complete" if complete else "partial",
        reason,
        next_offset=end if not complete and base["view"] != "summary" else None,
    )


def _pe_headers(descriptor: int, size: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if size < 64:
        raise _error("invalid_artifact", "PE DOS header is incomplete")
    pe_offset = struct.unpack("<I", _pread(descriptor, 4, 0x3C, size))[0]
    if pe_offset > size - 24 or pe_offset > MAX_SCAN_BYTES:
        raise _error("invalid_artifact", "PE header offset is invalid")
    header = _pread(descriptor, 24, pe_offset, size)
    if header[:4] != b"PE\x00\x00":
        raise _error("invalid_artifact", "PE signature is missing")
    machine, section_count, timestamp, _, _, optional_size, characteristics = struct.unpack(
        "<HHIIIHH", header[4:]
    )
    if section_count > MAX_RECORDS:
        raise _error("limit_exceeded", "PE section count exceeds the structure limit")
    if pe_offset + 24 + optional_size > size:
        raise _error("invalid_artifact", "PE optional header extends outside the source")
    optional = _pread(descriptor, optional_size, pe_offset + 24, size)
    magic = struct.unpack_from("<H", optional)[0] if len(optional) >= 2 else 0
    if magic not in {0x10B, 0x20B}:
        raise _error("unsupported_format", "PE optional-header format is unsupported")
    required_optional_size = 96 if magic == 0x10B else 112
    if optional_size < required_optional_size:
        raise _error("invalid_artifact", "PE optional header is incomplete")
    entry = struct.unpack_from("<I", optional, 16)[0] if len(optional) >= 20 else 0
    if magic == 0x10B and len(optional) >= 32:
        image_base = struct.unpack_from("<I", optional, 28)[0]
    elif magic == 0x20B and len(optional) >= 32:
        image_base = struct.unpack_from("<Q", optional, 24)[0]
    else:
        image_base = 0
    section_offset = pe_offset + 24 + optional_size
    rows = []
    for index in range(section_count):
        raw = _pread(descriptor, 40, section_offset + index * 40, size)
        name = raw[:8].split(b"\x00", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", raw, 8)
        flags = struct.unpack_from("<I", raw, 36)[0]
        if raw_size and raw_offset + raw_size > size:
            raise _error("invalid_artifact", "PE section extends outside the source")
        rows.append(
            {
                "index": index,
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": hex(virtual_address),
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "characteristics": hex(flags),
                "executable": bool(flags & 0x20000000),
                "writable": bool(flags & 0x80000000),
            }
        )
    return (
        {
            "machine": machine,
            "section_count": section_count,
            "timestamp": timestamp,
            "optional_header_magic": hex(magic),
            "entry_rva": hex(entry),
            "image_base": hex(image_base),
            "characteristics": hex(characteristics),
        },
        rows,
    )


def _pe_symbols(descriptor: int, size: int, selection: str) -> tuple[list[Any], bool, bool]:
    if _pefile is None:
        return [], False, False
    if size > 64 * 1024 * 1024:
        raise _error("limit_exceeded", "PE deep parsing exceeds its source byte limit")
    data = _pread(descriptor, size, 0, size)
    try:
        pe = _pefile.PE(data=data, fast_load=True)
        if selection == "imports":
            pe.parse_data_directories(
                directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            libraries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            limited = len(libraries) > MAX_RECORDS
            rows = []
            for library in libraries[:MAX_RECORDS]:
                imports = library.imports
                limited = limited or len(imports) > MAX_RECORDS
                rows.append(
                    {
                        "library": bytes(library.dll).decode("ascii", "replace")[:256],
                        "symbols": [
                            (bytes(item.name).decode("ascii", "replace")[:256])
                            if item.name
                            else f"ordinal:{item.ordinal}"
                            for item in imports[:MAX_RECORDS]
                        ],
                    }
                )
            return rows, True, limited
        pe.parse_data_directories(
            directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
        exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        symbols = exports.symbols if exports else []
        return (
            [
                {
                    "name": bytes(item.name).decode("ascii", "replace")[:256]
                    if item.name
                    else None,
                    "ordinal": item.ordinal,
                    "address": hex(item.address),
                }
                for item in symbols[:MAX_RECORDS]
            ],
            True,
            len(symbols) > MAX_RECORDS,
        )
    except Exception as exc:
        raise _error("invalid_artifact", "PE directory metadata is malformed") from exc


def _pe_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    if isinstance(base["selection"], str) and (
        base["selection"] == "disassembly" or base["selection"].startswith("disassembly:")
    ):
        if base["view"] not in {"text", "structure"}:
            raise _error("invalid_argument", "PE disassembly requires text or structure view")
        return _disassembly_view(descriptor, size, cursor, base)
    if base["selection"] in {"imports", "exports"}:
        if cursor is not None or base["view"] == "summary":
            raise _error("invalid_argument", "PE directory selection is one structure/text request")
        rows, available, limited = _pe_symbols(descriptor, size, base["selection"])
        return _finish(
            base,
            {base["selection"]: rows, "dependency": "pefile" if available else "unavailable"},
            "partial" if limited else "complete" if available else "unsupported",
            "record_limit"
            if limited
            else "directory_complete"
            if available
            else "dependency_unavailable",
        )
    if base["selection"] is not None:
        raise _error("invalid_argument", "PE selection must be imports, exports, or disassembly")
    if base["view"] == "text":
        return _binary_strings(descriptor, size, cursor, base)
    headers, sections = _pe_headers(descriptor, size)
    data = {**headers, "sections": sections, "pefile_available": _pefile is not None}
    return _finish(base, data, "complete", "headers_and_sections_complete")


def _binary_strings(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    position = _cursor_offset(
        cursor,
        base["source_sha256"],
        base["format"],
        base["view"],
        base["selection"],
        size,
    )
    raw = _pread(descriptor, min(MAX_SCAN_BYTES, size - position), position, size)
    found = []
    deferred_start: int | None = None
    for encoding, pattern in (
        ("ascii", _ASCII_STRING),
        ("utf-16-le", _UTF16LE_STRING),
        ("utf-16-be", _UTF16BE_STRING),
    ):
        for match in pattern.finditer(raw):
            span_complete = match.end() < len(raw) or position + len(raw) >= size
            absolute_start = position + match.start()
            if not span_complete and match.start() > 0:
                deferred_start = (
                    absolute_start
                    if deferred_start is None
                    else min(deferred_start, absolute_start)
                )
                continue
            decoded = match.group().decode(encoding)
            found.append(
                {
                    "offset": absolute_start,
                    "encoding": encoding,
                    "text": decoded[:512],
                    "truncated": len(decoded) > 512 or not span_complete,
                    "span_complete": span_complete,
                    "end_offset": position + match.end(),
                }
            )
    if deferred_start is not None:
        found = [row for row in found if row["offset"] < deferred_start]
    found.sort(key=lambda row: (row["offset"], row["encoding"]))
    limited = found[:MAX_RECORDS]
    if len(found) > MAX_RECORDS:
        next_position = max(position + 1, found[MAX_RECORDS]["offset"])
        reason = "record_limit"
    elif deferred_start is not None:
        next_position = deferred_start
        reason = "string_boundary"
    else:
        next_position = position + len(raw)
        reason = "scan_limit"
    for row in limited:
        row.pop("end_offset")
    complete = next_position >= size
    return _finish(
        base,
        {"strings": limited, "scanned_bytes": len(raw)},
        "complete" if complete else "partial",
        "end_of_file" if complete else reason,
        next_offset=next_position if not complete else None,
    )


def _fixed_executable(candidates: tuple[str, ...]) -> str | None:
    for candidate in candidates:
        try:
            metadata = os.stat(candidate)
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _run_fixed(argv: list[str], descriptor: int) -> dict[str, Any]:
    standard_input: int | Any = (
        descriptor if len(argv) > 1 and argv[1] == "stdin" else subprocess.DEVNULL
    )
    working_directory = (
        "/usr/share/tesseract-ocr"
        if len(argv) > 1 and argv[1] == "stdin" and os.path.isdir("/usr/share/tesseract-ocr")
        else "/"
    )
    try:
        process = subprocess.Popen(
            argv,
            cwd=working_directory,
            shell=False,
            stdin=standard_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            pass_fds=(descriptor,),
            close_fds=True,
            start_new_session=True,
            env={},
        )
    except OSError as exc:
        raise _error("tool_unavailable", "fixed artifact inspector could not start") from exc
    assert process.stdout is not None and process.stderr is not None
    streams = (process.stdout, process.stderr)
    buffers = {stream.fileno(): bytearray() for stream in streams}
    retained = 0
    reason = None
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + NATIVE_TIMEOUT_SECONDS
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream.fileno(), selectors.EVENT_READ)
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "timeout"
                break
            for key, _ in selector.select(min(0.05, remaining)):
                try:
                    chunk = os.read(key.fd, 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                capacity = MAX_NATIVE_OUTPUT_BYTES - retained
                buffers[key.fd].extend(chunk[:capacity])
                retained += min(len(chunk), capacity)
                if len(chunk) > capacity:
                    reason = "output_limit"
                    break
            if reason:
                break
        if reason:
            _terminate(process)
        try:
            returncode = process.wait(timeout=NATIVE_DRAIN_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise _error("tool_cleanup_failed", "native inspector did not terminate") from exc
        if (
            reason is None
            and returncode < 0
            and -returncode
            in {
                getattr(signal, "SIGXCPU", signal.SIGKILL),
                getattr(signal, "SIGXFSZ", signal.SIGKILL),
                signal.SIGKILL,
            }
        ):
            raise _error("resource_limit", "native inspector exceeded a resource limit")
        output = [bytes(buffers[stream.fileno()]) for stream in streams]
        return {
            "returncode": returncode,
            "stdout": output[0],
            "stderr": output[1],
            "stop_reason": reason,
        }
    finally:
        _terminate(process)
        selector.close()
        for stream in streams:
            stream.close()
        if process.poll() is None:
            try:
                process.wait(timeout=NATIVE_DRAIN_SECONDS)
            except subprocess.TimeoutExpired:
                pass


def _disassembly_view(
    descriptor: int, size: int, cursor: str | None, base: dict[str, Any]
) -> dict[str, Any]:
    selected_address = _disassembly_address(base["selection"])
    address = (
        _cursor_offset(
            cursor,
            base["source_sha256"],
            base["format"],
            base["view"],
            base["selection"],
            (1 << 64) - 1,
        )
        if cursor is not None
        else selected_address
    )
    result = capstone_tools.disassemble(descriptor, size, address)
    data: Any = result
    if base["view"] == "text":
        lines = [
            " ".join(
                part
                for part in (
                    row["address"],
                    row["bytes"],
                    row["mnemonic"],
                    row["operands"],
                )
                if part
            )
            for row in result["instructions"]
        ]
        data = {**result, "text": "\n".join(lines)}
    return _finish(
        base,
        data,
        result["coverage"],
        result["stop_reason"],
        next_offset=result.get("next_address"),
    )


def _pack_bits(bits: bytearray, offset: int, msb_first: bool) -> bytes:
    count = min(MAX_LSB_BYTES, max(0, len(bits) - offset) // 8)
    return bytes(
        sum(bits[offset + index * 8 + bit] << ((7 - bit) if msb_first else bit) for bit in range(8))
        for index in range(count)
    )


def _bit_signals(bits: bytearray) -> dict[str, Any]:
    signals = []
    previews = []
    seen = set()
    for offset in range(min(8, len(bits))):
        for order, msb_first in (("msb_first", True), ("lsb_first", False)):
            packed = _pack_bits(bits, offset, msb_first)
            text = "".join(chr(value) if 32 <= value < 127 else "." for value in packed)
            for match in _SIGNAL.finditer(packed.decode("latin-1")):
                value = match.group()
                if value not in seen and len(signals) < 16:
                    seen.add(value)
                    signals.append({"bit_offset": offset, "bit_order": order, "text": value})
            if offset == 0:
                previews.append(
                    {
                        "bit_order": order,
                        "data_base64": base64.b64encode(packed[:256]).decode(),
                        "text_preview": text[:256],
                    }
                )
    return {
        "complete_bytes_considered": min(MAX_LSB_BYTES, len(bits) // 8),
        "previews": previews,
        "candidate_signals": signals,
    }


def _image_basic(prefix: bytes, format_name: str) -> dict[str, Any]:
    if format_name == "png" and len(prefix) >= 24:
        width, height = struct.unpack(">II", prefix[16:24])
        return {"width": width, "height": height}
    if format_name == "gif" and len(prefix) >= 10:
        width, height = struct.unpack("<HH", prefix[6:10])
        return {"width": width, "height": height}
    if format_name == "bmp" and len(prefix) >= 26:
        width, height = struct.unpack("<ii", prefix[18:26])
        return {"width": width, "height": abs(height)}
    return {}


def _image_pixels(image: Any, selection: str | None) -> dict[str, Any]:
    width, height = image.size
    total = width * height
    if total > MAX_PIXELS:
        return {"pixel_count": total, "pixel_limit": MAX_PIXELS, "limited": True}
    converted = image.convert("RGBA")
    scan = min(total, MAX_PIXEL_SCAN)
    channels = {name: bytearray() for name in "RGBA"}
    sums = {name: 0 for name in channels}
    minima = {name: 255 for name in channels}
    maxima = {name: 0 for name in channels}
    histograms = {name: [0] * 256 for name in channels}
    pixels = (
        converted.get_flattened_data()
        if hasattr(converted, "get_flattened_data")
        else converted.getdata()
    )
    for index, pixel in enumerate(pixels):
        if index >= scan:
            break
        for channel, value in zip("RGBA", pixel, strict=True):
            sums[channel] += value
            minima[channel] = min(minima[channel], value)
            maxima[channel] = max(maxima[channel], value)
            histograms[channel][value] += 1
            if len(channels[channel]) < MAX_LSB_BYTES * 8 + 7:
                channels[channel].append(value & 1)
    channel_selection = None
    plane_selection = None
    if selection and selection.startswith("channel:"):
        channel_selection = selection.removeprefix("channel:").upper()
        if channel_selection not in channels:
            raise _error("invalid_argument", "image channel selection must be R, G, B, or A")
    if selection and selection.startswith("bitplane:"):
        parts = selection.split(":")
        if (
            len(parts) != 3
            or parts[1].upper() not in channels
            or parts[2] not in {str(bit) for bit in range(8)}
        ):
            raise _error("invalid_argument", "image bitplane selection is invalid")
        plane_selection = (parts[1].upper(), int(parts[2]))
        channel = plane_selection[0]
        bit = plane_selection[1]
        values = bytearray()
        pixels = (
            converted.get_flattened_data()
            if hasattr(converted, "get_flattened_data")
            else converted.getdata()
        )
        for index, pixel in enumerate(pixels):
            if index >= scan or len(values) >= MAX_LSB_BYTES * 8 + 7:
                break
            values.append((pixel["RGBA".index(channel)] >> bit) & 1)
        return {
            "pixel_count": total,
            "scanned_pixels": scan,
            "channel": channel,
            "bitplane": bit,
            "signals": _bit_signals(values),
            "limited": scan < total,
        }
    rows = {}
    selected_channels = [channel_selection] if channel_selection else list(channels)
    for channel in selected_channels:
        row: dict[str, Any] = {
            "minimum": minima[channel] if scan else None,
            "maximum": maxima[channel] if scan else None,
            "mean": round(sums[channel] / scan, 6) if scan else 0.0,
            "lsb_one_fraction": round(sum(channels[channel]) / len(channels[channel]), 6)
            if channels[channel]
            else 0.0,
            "lsb_signals": _bit_signals(channels[channel]),
        }
        if channel_selection:
            row["histogram"] = histograms[channel]
        rows[channel] = row
    return {
        "pixel_count": total,
        "scanned_pixels": scan,
        "channels": rows,
        "limited": scan < total,
    }


def _ocr_view(descriptor: int, base: dict[str, Any]) -> dict[str, Any]:
    executable = _fixed_executable(_FIXED_TESSERACT)
    if executable is None:
        return _finish(base, {"inspector": "tesseract"}, "unsupported", "dependency_unavailable")
    result = _run_fixed([executable, "stdin", "stdout", "--psm", "6"], descriptor)
    text = result["stdout"].decode("utf-8", "replace")
    diagnostic = result["stderr"].decode("utf-8", "replace")
    if result["stop_reason"]:
        coverage, reason = "partial", result["stop_reason"]
    elif result["returncode"]:
        coverage, reason = "unsupported", "ocr_failed"
    else:
        coverage, reason = "complete", "ocr_complete"
    return _finish(
        base,
        {"text": text, "diagnostic": diagnostic[:512], "inspector": os.path.basename(executable)},
        coverage,
        reason,
    )


def _image_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    if cursor is not None:
        raise _error("invalid_argument", "image views do not use continuation cursors")
    if base["selection"] == "ocr":
        if base["view"] != "text":
            raise _error("invalid_argument", "OCR selection requires text view")
    elif base["selection"] is not None and not (
        base["selection"].startswith("channel:")
        or base["selection"].startswith("bitplane:")
        or base["selection"] == "metadata"
    ):
        raise _error("invalid_argument", "image selection is unsupported")
    prefix = _pread(descriptor, min(size, 4096), 0, size)
    if _PILImage is None:
        return _finish(
            base,
            {**_image_basic(prefix, base["format"]), "dependency": "Pillow unavailable"},
            "unsupported",
            "dependency_unavailable",
        )
    try:
        with os.fdopen(os.dup(descriptor), "rb") as source, _PILImage.open(source) as image:
            width, height = image.size
            frames = int(getattr(image, "n_frames", 1))
            metadata = {
                "width": width,
                "height": height,
                "mode": image.mode,
                "image_format": image.format,
                "frame_count": frames,
            }
            info = {}
            for key, value in list(image.info.items())[:MAX_RECORDS]:
                if isinstance(value, bytes):
                    info[str(key)[:128]] = {"byte_length": len(value)}
                elif isinstance(value, (str, int, float, bool)) or value is None:
                    info[str(key)[:128]] = str(value)[:512]
            metadata["metadata"] = info
            if width <= 0 or height <= 0:
                raise _error("invalid_artifact", "image dimensions are invalid")
            if frames > MAX_IMAGE_FRAMES:
                return _finish(
                    base,
                    {**metadata, "frame_limit": MAX_IMAGE_FRAMES},
                    "partial",
                    "frame_limit",
                )
            if base["selection"] == "ocr":
                if width * height > MAX_PIXELS:
                    return _finish(
                        base,
                        {**metadata, "pixel_limit": MAX_PIXELS},
                        "unsupported",
                        "pixel_limit",
                    )
                return _ocr_view(descriptor, base)
            if base["view"] == "summary" or base["selection"] == "metadata":
                if width * height > MAX_PIXELS:
                    return _finish(base, metadata, "partial", "pixel_limit_metadata_only")
                pixels = _image_pixels(image, None)
                return _finish(
                    base,
                    {**metadata, "pixel_signals": pixels},
                    "complete" if not pixels["limited"] and frames == 1 else "partial",
                    "image_complete"
                    if not pixels["limited"] and frames == 1
                    else "pixel_or_frame_scan_limit",
                )
            pixels = _image_pixels(image, base["selection"])
            return _finish(
                base,
                {**metadata, "pixel_signals": pixels},
                "complete" if not pixels["limited"] and frames == 1 else "partial",
                "image_complete"
                if not pixels["limited"] and frames == 1
                else "pixel_or_frame_scan_limit",
            )
    except (OSError, SyntaxError, ValueError, TypeError, struct.error) as exc:
        raise _error("invalid_artifact", "raster image is malformed or unsupported") from exc


def _media_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    if cursor is not None:
        raise _error("invalid_argument", "media metadata views do not use continuations")
    if base["format"] == "wav":
        _check_selection(base["selection"], {"metadata", "signals"})
        result = wav_analyze_from_descriptor(descriptor, size, {"path": base["path"]})
        if base["view"] == "text":
            data: Any = {
                "lsb_candidate_signals": result["lsb_candidate_signals"],
                "pcm_text_signals": result["pcm_text_signals"],
            }
        elif base["view"] == "summary":
            data = {
                key: result[key]
                for key in (
                    "encoding",
                    "channels",
                    "sample_rate",
                    "bits_per_sample",
                    "frames",
                    "duration_seconds",
                    "analyzed_frames",
                    "lsb_candidate_signals",
                )
            }
        else:
            data = result
        complete = not result["truncated"]
        return _finish(
            base,
            data,
            "complete" if complete else "partial",
            "wav_complete" if complete else "media_scan_limit",
        )
    _check_selection(base["selection"], {"metadata"})
    result = dicom_metadata_from_descriptor(descriptor, size, {"path": base["path"]})
    if base["view"] == "text":
        lines = []
        for row in result["tags"]:
            value = row.get("text_preview", row.get("values_preview", row.get("hex_preview")))
            if value is not None:
                lines.append({"tag": row["tag"], "name": row["name"], "value": value})
        data = {"tags": lines}
    elif base["view"] == "summary":
        data = {
            "transfer_syntax_uid": result["transfer_syntax_uid"],
            "dataset_encoding": result["dataset_encoding"],
            "tag_count": result["tag_count"],
            "pixel_data_omitted": result["pixel_data_omitted"],
        }
    else:
        data = result
    return _finish(base, data, "partial", result["stop_reason"])


def _unsupported_view(
    descriptor: int,
    size: int,
    cursor: str | None,
    base: dict[str, Any],
) -> dict[str, Any]:
    if base["view"] == "text":
        _check_selection(base["selection"], set())
        return _binary_strings(descriptor, size, cursor, base)
    _check_selection(base["selection"], set())
    if cursor is not None:
        raise _error("invalid_argument", "unsupported summary has no continuation")
    prefix = _pread(descriptor, min(size, 256), 0, size)
    return _finish(
        base,
        {
            "magic_hex": prefix[:32].hex(),
            "printable_fraction": round(
                sum(32 <= value < 127 or value in {9, 10, 13} for value in prefix)
                / max(1, len(prefix)),
                6,
            ),
        },
        "unsupported",
        "unrecognized_format",
    )


def _inspect_artifact(
    workspace: Workspace, arguments: Mapping[str, Any], *, isolate_optional: bool
) -> dict[str, Any]:
    from .tools import ToolError

    path, view, selection, cursor = _arguments(arguments)
    try:
        with _source(workspace, path) as (descriptor, size):
            original_facts = _source_facts(descriptor)
            digest = _identity(descriptor, size)
            prefix = _pread(descriptor, min(size, 64 * 1024), 0, size)
            format_name, detection = _detect_format(prefix, size, selection)
            base = _base(path, size, digest, format_name, view, selection)
            if view == "bytes":
                return _bytes_view(descriptor, size, cursor, base)
            operation = None
            if format_name == "tar":
                operation = "tar"
            elif format_name == "pdf":
                operation = "pdf"
            elif format_name == "pcap":
                operation = "pcap"
            elif format_name in {"png", "jpeg", "gif", "bmp", "tiff", "webp"}:
                operation = "image"
            elif format_name == "pe" and selection in {"imports", "exports"}:
                operation = "pe"
            elif format_name in {"elf", "pe"} and (
                selection == "disassembly"
                or (isinstance(selection, str) and selection.startswith("disassembly:"))
            ):
                operation = "disassembly"
            if isolate_optional and operation is not None:
                result = run_artifact_worker(
                    descriptor,
                    operation,
                    size=size,
                    cursor=cursor,
                    base=base,
                )
                if _source_facts(descriptor) != original_facts:
                    raise _error("source_changed", "artifact changed during isolated inspection")
                return result
            if format_name == "text":
                return _text_view(
                    descriptor,
                    size,
                    cursor,
                    base,
                    detection["encoding"],
                    detection["bom_bytes"],
                )
            if format_name == "zip":
                return _zip_view(descriptor, size, cursor, base)
            if format_name == "tar":
                return _tar_view(descriptor, size, cursor, base)
            if format_name == "gzip":
                return _gzip_view(descriptor, size, cursor, base)
            if format_name == "pdf":
                return _pdf_view(descriptor, size, cursor, base)
            if format_name == "pcap":
                return _pcap_view(descriptor, size, cursor, base)
            if format_name == "pcapng":
                return _pcapng_view(descriptor, size, cursor, base)
            if format_name == "elf":
                return _elf_view(descriptor, size, cursor, base)
            if format_name == "pe":
                return _pe_view(descriptor, size, cursor, base)
            if format_name in {"png", "jpeg", "gif", "bmp", "tiff", "webp"}:
                return _image_view(descriptor, size, cursor, base)
            if format_name in {"wav", "dicom"}:
                result = _media_view(descriptor, size, cursor, base)
                if _source_facts(descriptor) != original_facts:
                    raise _error("source_changed", "media changed during artifact inspection")
                return result
            return _unsupported_view(descriptor, size, cursor, base)
    except ToolError:
        raise
    except (struct.error, EOFError, UnicodeError, OverflowError) as exc:
        raise _error("invalid_artifact", "artifact structure is malformed") from exc


def _inspect_artifact_local(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Exercise parser units in-process; production callers use ``inspect_artifact``."""
    return _inspect_artifact(workspace, arguments, isolate_optional=False)


def inspect_artifact(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Inspect one artifact while isolating optional/native parsers in a killable worker."""
    return _inspect_artifact(workspace, arguments, isolate_optional=True)


def artifact_tool_spec() -> dict[str, Any]:
    """Return the single opt-in dynamic-tool schema for the artifact Interface."""
    spec = {
        "name": "inspect_artifact",
        "description": (
            "Inspect one bounded source-bound summary, text, structure, or byte view; "
            "never execute or extract the artifact."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 4096,
                    "description": "Workspace-relative regular-file path; symlinks are refused.",
                },
                "view": {
                    "type": "string",
                    "enum": ["summary", "text", "structure", "bytes"],
                    "default": "summary",
                },
                "selection": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 64,
                    "pattern": "^[A-Za-z0-9_.:-]+$",
                    "description": (
                        "Optional format selector: encoding:<name>, entries, metadata, "
                        "page:<index>, packets, blocks, section:<index>, imports, exports, "
                        "disassembly, disassembly:0x<address>, channel:<RGBA>, "
                        "bitplane:<RGBA>:<0-7>, ocr, or signals."
                    ),
                },
                "cursor": {"type": "string", "minLength": 1, "maxLength": 1024},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    }
    json.dumps(spec)
    return spec


__all__ = ["artifact_tool_spec", "inspect_artifact"]
