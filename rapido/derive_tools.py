"""Bounded source-range transforms that publish inert derived artifacts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import urllib.parse
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .tools import Workspace

MAX_DERIVE_INPUT_BYTES = 1024 * 1024
MAX_DERIVE_OUTPUT_BYTES = 1024 * 1024
_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _error(code: str, message: str, **details: Any) -> Exception:
    from .tools import _error as tool_error

    return tool_error(code, message, **details)


def _integer(value: Any, name: str, low: int, high: int, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error("invalid_argument", f"{name} must be an integer")
    if not low <= value <= high:
        raise _error("limit_exceeded", f"{name} must be between {low} and {high}")
    return value


def _decode(kind: str, raw: bytes) -> bytes:
    try:
        if kind == "base64":
            return base64.b64decode(raw.strip(), validate=True)
        if kind == "hex":
            return bytes.fromhex(raw.decode("ascii"))
        if kind == "url":
            text = raw.decode("utf-8")
            if _PERCENT_ESCAPE.search(text):
                raise ValueError
            return urllib.parse.unquote_to_bytes(text)
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise _error("invalid_encoding", f"invalid {kind} input") from exc
    raise _error("invalid_argument", "encoding must be base64, hex, or url")


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise _error("write_failed", "derived artifact write made no progress")
        view = view[written:]


def derive_artifact(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Decode one bounded source range and publish it under a content-addressed path."""
    from .tools import (
        MAX_FILE_BYTES,
        _bounded_text,
        _result,
        _workspace_exclusive_output_fd,
        _workspace_regular_fd,
    )

    allowed = {"path", "encoding", "offset", "length"}
    if set(arguments) - allowed:
        raise _error("invalid_argument", "derive_artifact received unknown arguments")
    path_arg = _bounded_text(arguments.get("path"), "path")
    kind = _bounded_text(arguments.get("encoding"), "encoding", 16)
    offset = _integer(arguments.get("offset"), "offset", 0, MAX_FILE_BYTES, 0)
    requested_length = arguments.get("length")
    with _workspace_regular_fd(workspace, path_arg) as (descriptor, metadata):
        source_size = metadata.st_size
        if offset > metadata.st_size:
            raise _error("invalid_argument", "offset exceeds source size")
        remaining = metadata.st_size - offset
        default_length = min(remaining, MAX_DERIVE_INPUT_BYTES)
        length = _integer(
            requested_length,
            "length",
            1,
            MAX_DERIVE_INPUT_BYTES,
            default_length,
        )
        if length == 0:
            raise _error("invalid_argument", "source range is empty")
        if offset + length > metadata.st_size:
            raise _error("invalid_argument", "source range exceeds source size")
        try:
            raw = os.pread(descriptor, length, offset)
        except OSError as exc:
            raise _error("read_failed", "source range could not be read") from exc
        if len(raw) != length:
            raise _error("source_changed", "source changed during range read")
    decoded = _decode(kind, raw)
    if len(decoded) > MAX_DERIVE_OUTPUT_BYTES:
        raise _error("output_too_large", "decoded artifact exceeds the output limit")
    digest = hashlib.sha256(decoded).hexdigest()
    destination = f"derived/{digest}.bin"
    destination_path = workspace.path(destination, must_exist=False)
    if destination_path.exists():
        with _workspace_regular_fd(workspace, destination) as (descriptor, metadata):
            existing = os.pread(descriptor, metadata.st_size, 0)
        if existing != decoded:
            raise _error("write_conflict", "content-addressed destination is inconsistent")
    else:
        workspace.ensure_capacity(len(decoded))
        workspace.ensure_entry_capacity(destination, temporary_entries=1)
        with _workspace_exclusive_output_fd(workspace, destination) as descriptor:
            _write_all(descriptor, decoded)
    preview = decoded[:512].decode("utf-8", "replace")
    return _result(
        {
            "path": destination,
            "encoding": kind,
            "bytes": len(decoded),
            "sha256": digest,
            "source_path": path_arg,
            "source_bytes": source_size,
            "source_offset": offset,
            "source_length": length,
            "source_range_sha256": hashlib.sha256(raw).hexdigest(),
            "source_truncated": requested_length is None and length < remaining,
            "text_preview": preview,
            "preview_truncated": len(decoded) > 512,
        }
    )


def derive_tool_spec() -> dict[str, Any]:
    """Return the native dynamic-tool schema for durable decoding."""
    return {
        "name": "derive_artifact",
        "description": (
            "Decode one bounded range of a workspace file into a new content-addressed "
            "artifact for later inspection."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 4096},
                "encoding": {"type": "string", "enum": ["base64", "hex", "url"]},
                "offset": {"type": "integer", "minimum": 0},
                "length": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_DERIVE_INPUT_BYTES,
                },
            },
            "required": ["path", "encoding"],
            "additionalProperties": False,
        },
    }


__all__ = ["derive_artifact", "derive_tool_spec"]
