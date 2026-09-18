"""Bounded static ELF tools; input binaries are never executed.

The public functions match ``ToolRegistry``'s ``(Workspace, arguments)`` contract.
They are deliberately not registered here. Imports from ``tools`` are deferred so
the registry can import these functions without creating an import cycle.

Metadata uses a small ELF parser. Symbols and disassembly use only installed
readelf/objdump programs from fixed system directories, with no shell, source
lookup, inherited credentials, or an arbitrary command/argv surface. A file
descriptor opened through no-follow directory handles remains the input even if
its original path is replaced. Child processes get an absolute wall-clock budget
and a combined stdout/stderr prefix budget.
"""

from __future__ import annotations

import errno
import json
import os
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .tools import Workspace

MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_SECTIONS = 128
MAX_STRING_TABLE_BYTES = 1024 * 1024
MAX_DISASSEMBLY_BYTES = 4096
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024
COMMAND_TIMEOUT_SECONDS = 3.0
COMMAND_SHUTDOWN_SECONDS = 1.0
_SYSTEM_PATH = "/usr/bin:/bin"
_ADDRESS_LIMIT = (1 << 64) - 1
_SECTION_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_MACHINES = {3: "x86", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}


def _error(code: str, message: str, **details: Any) -> Exception:
    from .tools import _error as tool_error

    return tool_error(code, message, **details)


def _arguments(arguments: Mapping[str, Any], allowed: set[str]) -> str:
    from .tools import _value_kind

    if not isinstance(arguments, Mapping):
        raise _error(
            "invalid_argument",
            "binary-tool arguments must be an object",
            field_path="arguments",
            constraint="type",
            actual_kind=_value_kind(arguments),
        )
    if set(arguments) - allowed:
        raise _error(
            "invalid_argument",
            "unsupported binary-tool argument",
            field_path="arguments",
            constraint="additional_properties",
            actual_kind="object",
        )
    value = arguments.get("path")
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _error(
            "invalid_argument",
            "path must be a nonempty string without NUL bytes",
            field_path="path",
            constraint="nonempty_text",
            actual_kind=_value_kind(value),
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise _error("invalid_argument", "path must contain valid Unicode text") from exc
    if len(encoded) > 4096:
        raise _error("input_too_large", "path exceeds the input limit")
    return value


def _integer(value: Any, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        from .tools import _value_kind

        raise _error(
            "invalid_argument",
            f"{name} must be an integer between {low} and {high}",
            field_path=name,
            constraint="range" if type(value) is int else "type",
            actual_kind=_value_kind(value),
        )
    return value


@contextmanager
def _input(workspace: Workspace, relative: str) -> Iterator[tuple[int, int]]:
    """Anchor every input component to open directory descriptors, never symlinks."""
    from .tools import Workspace

    if not isinstance(workspace, Workspace):
        raise _error("invalid_workspace", "binary tools require a bound workspace")
    normalized = relative.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        raise _error("path_outside_workspace", "absolute paths are not allowed")
    parts = tuple(part for part in normalized.split("/") if part not in {"", "."})
    if ".." in parts:
        raise _error("path_outside_workspace", "path traversal is not allowed")
    if not parts:
        raise _error("not_a_file", "path must name a regular file")
    if len(parts) > 128:
        raise _error("limit_exceeded", "path has too many components")
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise _error("unsupported_platform", "no-follow descriptor access is unavailable")
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
        if metadata.st_size > MAX_BINARY_BYTES:
            raise _error("input_too_large", "binary exceeds the input byte limit")
        yield descriptor, metadata.st_size
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            raise _error("not_found", "binary input was not found") from exc
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise _error(
                "symlink_or_invalid_path", "symlinks and invalid components are refused"
            ) from exc
        raise _error("read_failed", "binary input could not be inspected") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read(descriptor: int, offset: int, length: int, size: int) -> bytes:
    if offset < 0 or length < 0 or offset + length > size:
        raise _error("invalid_elf", "ELF data extends beyond the input file")
    if length > MAX_STRING_TABLE_BYTES:
        raise _error("limit_exceeded", "ELF metadata read exceeds the byte limit")
    data = os.pread(descriptor, length, offset)
    if len(data) != length:
        raise _error("invalid_elf", "ELF input changed or contains truncated metadata")
    return data


def _header(descriptor: int, size: int) -> dict[str, Any]:
    ident = _read(descriptor, 0, 16, size)
    if ident[:4] != b"\x7fELF":
        raise _error("unsupported_format", "only ELF inputs are supported")
    if ident[4] not in {1, 2} or ident[5] not in {1, 2} or ident[6] != 1:
        raise _error("invalid_elf", "ELF class, byte order, or version is invalid")
    bits = 32 if ident[4] == 1 else 64
    endian = "<" if ident[5] == 1 else ">"
    layout = "HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"
    fields = struct.unpack(endian + layout, _read(descriptor, 16, struct.calcsize(layout), size))
    names = (
        "type",
        "machine",
        "version",
        "entry",
        "phoff",
        "shoff",
        "flags",
        "ehsize",
        "phentsize",
        "phnum",
        "shentsize",
        "shnum",
        "shstrndx",
    )
    result = dict(zip(names, fields, strict=True))
    result.update(bits=bits, endian=endian, osabi=ident[7])
    if result["version"] != 1 or result["ehsize"] != (52 if bits == 32 else 64):
        raise _error("invalid_elf", "ELF header size or version is invalid")
    section_size = 40 if bits == 32 else 64
    if result["shoff"]:
        if result["shentsize"] != section_size:
            raise _error("invalid_elf", "ELF section entry size is invalid")
        first = _section(descriptor, size, result, 0)
        if result["shnum"] == 0:
            result["shnum"] = first[5]
        if result["shstrndx"] == 0xFFFF:
            result["shstrndx"] = first[6]
        if result["phnum"] == 0xFFFF:
            result["phnum"] = first[7]
    elif result["shnum"] or result["shstrndx"] or result["phnum"] == 0xFFFF:
        raise _error("invalid_elf", "ELF section table is missing")
    for offset, entry_size, count, expected in (
        (result["shoff"], result["shentsize"], result["shnum"], section_size),
        (result["phoff"], result["phentsize"], result["phnum"], 32 if bits == 32 else 56),
    ):
        if count and (not offset or entry_size != expected or offset + entry_size * count > size):
            raise _error("invalid_elf", "ELF table bounds or entry size is invalid")
    if result["shstrndx"] and result["shstrndx"] >= result["shnum"]:
        raise _error("invalid_elf", "ELF section-name table index is invalid")
    if result["shnum"] > 65536:
        raise _error("limit_exceeded", "ELF section count exceeds the metadata limit")
    return result


def _section(descriptor: int, size: int, header: Mapping[str, Any], index: int) -> tuple[int, ...]:
    layout = "IIIIIIIIII" if header["bits"] == 32 else "IIQQQQIIQQ"
    return struct.unpack(
        header["endian"] + layout,
        _read(
            descriptor, header["shoff"] + header["shentsize"] * index, struct.calcsize(layout), size
        ),
    )


def inspect_elf(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Read ELF32/ELF64 headers and a bounded page of section metadata, without tools."""
    path = _arguments(arguments, {"path", "section_offset", "max_sections"})
    offset = _integer(arguments.get("section_offset", 0), "section_offset", 0, 65535)
    maximum = _integer(arguments.get("max_sections", 64), "max_sections", 1, MAX_SECTIONS)
    with _input(workspace, path) as (descriptor, size):
        header = _header(descriptor, size)
        names = b""
        if header["shstrndx"]:
            name_section = _section(descriptor, size, header, header["shstrndx"])
            if name_section[1] != 3:
                raise _error("invalid_elf", "ELF section names are not in a string table")
            names = _read(descriptor, name_section[4], name_section[5], size)
        sections = []
        for index in range(offset, min(offset + maximum, header["shnum"])):
            fields = _section(descriptor, size, header, index)
            name_offset, kind, flags, address, file_offset, byte_size, link, _, alignment, _ = (
                fields
            )
            if kind not in {0, 8} and file_offset + byte_size > size:
                raise _error("invalid_elf", "ELF section extends beyond the input file")
            if name_offset and (not names or name_offset >= len(names)):
                raise _error("invalid_elf", "ELF section name offset is invalid")
            raw_name = names[name_offset : name_offset + 129].split(b"\x00", 1)[0] if names else b""
            name = "".join(
                character if character.isprintable() else "?"
                for character in raw_name.decode("utf-8", "replace")
            )[:128]
            sections.append(
                {
                    "index": index,
                    "name": name,
                    "name_truncated": len(raw_name) > 128,
                    "type": kind,
                    "address": hex(address),
                    "offset": file_offset,
                    "size": byte_size,
                    "flags": hex(flags),
                    "writable": bool(flags & 1),
                    "allocated": bool(flags & 2),
                    "executable": bool(flags & 4),
                    "link": link,
                    "alignment": alignment,
                }
            )
    return {
        "path": path,
        "format": "elf",
        "size": size,
        "class_bits": header["bits"],
        "byte_order": "little" if header["endian"] == "<" else "big",
        "type": header["type"],
        "machine": header["machine"],
        "machine_name": _MACHINES.get(header["machine"], "unknown"),
        "entry_address": hex(header["entry"]),
        "osabi": header["osabi"],
        "program_header_count": header["phnum"],
        "section_count": header["shnum"],
        "section_offset": offset,
        "sections": sections,
        "next_section_offset": offset + len(sections)
        if offset + len(sections) < header["shnum"]
        else None,
    }


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _run_command(
    argv: list[str], descriptor: int, *, deadline: float | None = None
) -> dict[str, Any]:
    """Internal runner; public callers construct argv exclusively from fixed options."""
    if deadline is None:
        deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    if deadline <= time.monotonic():
        return {
            "status": "timeout",
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "truncated": False,
            "timed_out": True,
        }
    process = subprocess.Popen(
        argv,
        # A constant system directory avoids resolving the mutable workspace path
        # again. The sole artifact input is the inherited descriptor below.
        cwd="/",
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        pass_fds=(descriptor,),
        start_new_session=True,
        close_fds=True,
        env={"PATH": _SYSTEM_PATH, "LANG": "C", "LC_ALL": "C", "DEBUGINFOD_URLS": ""},
    )
    assert process.stdout is not None and process.stderr is not None
    streams = (process.stdout, process.stderr)
    buffers: dict[int, bytearray] = {stream.fileno(): bytearray() for stream in streams}
    retained = 0
    reason = None
    selector = selectors.DefaultSelector()
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
                capacity = MAX_COMMAND_OUTPUT_BYTES - retained
                buffers[key.fd].extend(chunk[:capacity])
                retained += min(len(chunk), capacity)
                if len(chunk) > capacity:
                    reason = "output_limit"
                    break
            if reason:
                break
        if reason:
            _terminate(process)
        returncode = process.wait(timeout=COMMAND_SHUTDOWN_SECONDS)
        output = [bytes(buffers[stream.fileno()]).decode("utf-8", "replace") for stream in streams]
        return {
            "status": reason or ("ok" if returncode == 0 else "command_failed"),
            "returncode": returncode,
            "stdout": output[0],
            "stderr": output[1],
            "truncated": reason == "output_limit",
            "timed_out": reason == "timeout",
        }
    except subprocess.TimeoutExpired as exc:
        raise _error(
            "command_cleanup_failed", "binary inspector did not confirm termination"
        ) from exc
    finally:
        _terminate(process)
        selector.close()
        for stream in streams:
            stream.close()
        if process.poll() is None:
            try:
                process.wait(timeout=COMMAND_SHUTDOWN_SECONDS)
            except subprocess.TimeoutExpired:
                pass


def _command(
    path: str,
    descriptor: int,
    names: tuple[str, ...],
    options: list[str],
) -> dict[str, Any]:
    selected = next(
        (
            (name, executable)
            for name in names
            if (executable := shutil.which(name, path=_SYSTEM_PATH))
        ),
        None,
    )
    if selected is None:
        return {"path": path, "format": "elf", "status": "unavailable", "commands": list(names)}
    name, executable = selected
    source = f"/dev/fd/{descriptor}"
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        version = _run_command([executable, "--version"], descriptor, deadline=deadline)
        if version["status"] != "ok":
            return {"path": path, "format": "elf", "command": name, **version}
        if "GNU" in version["stdout"]:
            debug_option = "--debug-dump" if "readelf" in name else "--dwarf"
            safety = [f"{debug_option}=no-follow-links", f"{debug_option}=do-not-use-debuginfod"]
        elif "LLVM" in version["stdout"] and "objdump" in name:
            safety = ["--no-debuginfod"]
        else:
            return {
                "path": path,
                "format": "elf",
                "command": name,
                "status": "unsupported_tool",
                "error": "inspector does not have a supported external-debug-file policy",
            }
        result = _run_command(
            [executable, *safety, *options, source], descriptor, deadline=deadline
        )
    except OSError as exc:
        raise _error("command_failed", "binary inspector could not be started") from exc
    for field in ("stdout", "stderr"):
        result[field] = result[field].replace(source, "[workspace binary]")
    return {"path": path, "format": "elf", "command": name, **result}


def elf_symbols(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Print a bounded symbol-table prefix; this does not load or execute the binary."""
    path = _arguments(arguments, {"path", "dynamic"})
    dynamic = arguments.get("dynamic", False)
    if type(dynamic) is not bool:
        raise _error("invalid_argument", "dynamic must be a boolean")
    with _input(workspace, path) as (descriptor, size):
        _header(descriptor, size)
        return _command(
            path,
            descriptor,
            ("readelf", "llvm-readelf"),
            [
                "--wide",
                "--dyn-syms" if dynamic else "--symbols",
            ],
        )


def disassemble_elf(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Disassemble at most 4096 address bytes from one ELF section using fixed objdump options."""
    path = _arguments(arguments, {"path", "start_address", "byte_count", "section"})
    count = _integer(arguments.get("byte_count", 256), "byte_count", 1, MAX_DISASSEMBLY_BYTES)
    section = arguments.get("section", ".text")
    if not isinstance(section, str) or not _SECTION_NAME.fullmatch(section):
        raise _error("invalid_argument", "section must be a bounded ELF section name")
    with _input(workspace, path) as (descriptor, size):
        header = _header(descriptor, size)
        start = arguments.get("start_address", header["entry"])
        if isinstance(start, str) and re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", start):
            start = int(start, 16)
        start = _integer(start, "start_address", 0, _ADDRESS_LIMIT - count)
        result = _command(
            path,
            descriptor,
            ("objdump", "llvm-objdump"),
            [
                "--disassemble",
                f"--section={section}",
                f"--start-address={hex(start)}",
                f"--stop-address={hex(start + count)}",
            ],
        )
    return {
        **result,
        "section": section,
        "start_address": hex(start),
        "stop_address": hex(start + count),
    }


def binary_tool_specs() -> list[dict[str, Any]]:
    """Return opt-in native dynamic-tool specs; importing this module registers nothing."""
    path = {"type": "string", "minLength": 1, "maxLength": 4096}
    properties = {
        "inspect_elf": {
            "path": path,
            "section_offset": {"type": "integer", "minimum": 0, "maximum": 65535},
            "max_sections": {"type": "integer", "minimum": 1, "maximum": MAX_SECTIONS},
        },
        "elf_symbols": {"path": path, "dynamic": {"type": "boolean"}},
        "disassemble_elf": {
            "path": path,
            "start_address": {
                "anyOf": [
                    {"type": "integer", "minimum": 0, "maximum": _ADDRESS_LIMIT},
                    {"type": "string", "pattern": "^0[xX][0-9a-fA-F]{1,16}$"},
                ]
            },
            "byte_count": {"type": "integer", "minimum": 1, "maximum": MAX_DISASSEMBLY_BYTES},
            "section": {"type": "string", "pattern": _SECTION_NAME.pattern},
        },
    }
    descriptions = {
        "inspect_elf": "Read bounded ELF headers and a page of section metadata from a workspace file.",
        "elf_symbols": "Read a bounded static or dynamic ELF symbol-table prefix using installed readelf.",
        "disassemble_elf": "Read a bounded ELF instruction window using installed objdump; never execute input.",
    }
    specs = [
        {
            "name": name,
            "description": descriptions[name],
            "inputSchema": {
                "type": "object",
                "properties": fields,
                "required": ["path"],
                "additionalProperties": False,
            },
        }
        for name, fields in properties.items()
    ]
    json.dumps(specs)
    return specs


__all__ = ["binary_tool_specs", "disassemble_elf", "elf_symbols", "inspect_elf"]
