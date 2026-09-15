"""Passive entrypoint disassembly from an already-open ELF/PE artifact.

Only bounded headers and one file-backed executable byte window are read. No
paths, debug links, processes, execution, or tool registration are involved.
Instructions are a linear interpretation in the entrypoint's declared mode,
not evidence of reachability or complete code discovery.
"""

from __future__ import annotations

import json
import os
import stat
import struct
from dataclasses import dataclass
from typing import Any

from . import binary_tools

try:
    import capstone as _capstone
except (ImportError, OSError):  # pragma: no cover - depends on runtime packaging
    _capstone = None


MAX_INSTRUCTION_BYTES = 4096
MAX_INSTRUCTIONS = 256
MAX_OUTPUT_BYTES = 32 * 1024
MAX_HEADERS = 128


class _Unsupported(Exception):
    """A recognized input cannot be decoded without guessing."""


@dataclass(frozen=True)
class _Image:
    format: str
    machine: int
    bits: int
    byte_order: str
    architecture: str
    mode: str
    entry: int


@dataclass(frozen=True)
class _Region:
    offset: int
    address: int
    size: int
    kind: str
    index: int


def _error(code: str, message: str) -> Exception:
    from .tools import ToolError

    return ToolError(code, message)


def _read(descriptor: int, size: int, offset: int, length: int) -> bytes:
    if offset < 0 or length < 0 or offset + length > size:
        raise _error("invalid_artifact", "disassembly metadata extends outside the artifact")
    if length > MAX_INSTRUCTION_BYTES:
        raise _error("limit_exceeded", "disassembly read exceeds its byte limit")
    data = os.pread(descriptor, length, offset)
    if len(data) != length:
        raise _error("source_changed", "artifact changed during disassembly")
    return data


def _machine(
    format_name: str, machine: int, bits: int, byte_order: str, entry: int, flags: int = 0
) -> _Image:
    mappings = {
        "elf": {
            3: (32, "x86", "32"),
            62: (64, "x86", "64"),
            40: (32, "arm", "thumb" if entry & 1 else "arm"),
            183: (64, "aarch64", "aarch64"),
        },
        "pe": {
            0x14C: (32, "x86", "32"),
            0x8664: (64, "x86", "64"),
            0x1C0: (32, "arm", "arm"),
            0x1C2: (32, "arm", "thumb"),
            0x1C4: (32, "arm", "thumb"),
            0xAA64: (64, "aarch64", "aarch64"),
        },
    }
    selected = mappings[format_name].get(machine)
    if selected is None or selected[0] != bits:
        raise _Unsupported("unsupported_machine_mode", "machine and bitness are unsupported")
    _, architecture, mode = selected
    if byte_order == "big" and architecture != "arm":
        raise _Unsupported("unsupported_machine_mode", "machine byte order is unsupported")
    # BE8/LE8 ARM encodings require more than the ELF data-byte-order declaration.
    if format_name == "elf" and architecture == "arm" and flags & 0x00C00000:
        raise _Unsupported("unsupported_machine_mode", "ARM mixed-endian flags are unsupported")
    if mode == "thumb":
        entry &= ~1
    alignment = 2 if mode == "thumb" else (4 if architecture != "x86" else 1)
    if entry % alignment:
        raise _Unsupported("unsupported_machine_mode", "entrypoint is not instruction-aligned")
    return _Image(format_name, machine, bits, byte_order, architecture, mode, entry)


def _select(regions: list[_Region], address: int, *, explicit: bool) -> _Region:
    matches = [
        region for region in regions if region.address <= address < region.address + region.size
    ]
    if len(matches) != 1:
        raise _Unsupported(
            ("address_unavailable" if explicit else "entrypoint_unavailable")
            if not matches
            else ("ambiguous_address" if explicit else "ambiguous_entrypoint"),
            "start address must belong to exactly one file-backed executable region",
        )
    return matches[0]


def _start_address(image: _Image, address: int | None) -> int:
    start = image.entry if address is None else address
    if type(start) is not int or not 0 <= start < 1 << image.bits:
        raise _Unsupported("address_unavailable", "start address exceeds the image address space")
    if image.mode == "thumb" and start & 1:
        start &= ~1
    alignment = 2 if image.mode == "thumb" else (4 if image.architecture != "x86" else 1)
    if start % alignment:
        raise _Unsupported("unsupported_machine_mode", "start address is not instruction-aligned")
    return start


def _elf(
    descriptor: int, size: int, requested_address: int | None = None
) -> tuple[_Image, _Region, int]:
    header = binary_tools._header(descriptor, size)
    if header["type"] not in {2, 3}:
        raise _Unsupported(
            "entrypoint_unavailable", "ELF type has no supported executable entrypoint"
        )
    image = _machine(
        "elf",
        header["machine"],
        header["bits"],
        "little" if header["endian"] == "<" else "big",
        header["entry"],
        header["flags"],
    )
    regions = []
    # Program mappings take precedence; section metadata is a fallback only when
    # no program table exists. No section-name or symbol string tables are read.
    count = header["phnum"] or header["shnum"]
    if count > MAX_HEADERS:
        raise _Unsupported("metadata_limit", "executable-region table exceeds its record limit")
    for index in range(count):
        if header["phnum"]:
            layout = "IIIIIIII" if image.bits == 32 else "IIQQQQQQ"
            raw = _read(
                descriptor,
                size,
                header["phoff"] + header["phentsize"] * index,
                struct.calcsize(header["endian"] + layout),
            )
            values = struct.unpack(header["endian"] + layout, raw)
            if image.bits == 32:
                kind, offset, address, _, length, memory_size, flags, _ = values
            else:
                kind, flags, offset, address, _, length, memory_size, _ = values
            if kind != 1:
                continue
            if length > memory_size or address + memory_size > 1 << image.bits:
                raise _error("invalid_artifact", "ELF load-region bounds are invalid")
            executable = bool(flags & 1)
            region_kind = "segment"
        else:
            _, kind, flags, address, offset, length, *_ = binary_tools._section(
                descriptor, size, header, index
            )
            if kind != 1:
                continue
            executable = flags & 6 == 6
            if executable and flags & 0x800:
                raise _Unsupported(
                    "unsupported_encoding", "compressed executable sections are unsupported"
                )
            region_kind = "section"
        if offset + length > size or address + length > 1 << image.bits:
            raise _error("invalid_artifact", "ELF executable-region bounds are invalid")
        if executable and length:
            regions.append(_Region(offset, address, length, region_kind, index))
    start = _start_address(image, requested_address)
    return image, _select(regions, start, explicit=requested_address is not None), start


def _pe(descriptor: int, size: int, address: int | None = None) -> tuple[_Image, _Region, int]:
    dos = _read(descriptor, size, 0, 64)
    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    if pe_offset < 64:
        raise _error("invalid_artifact", "PE header overlaps the DOS header")
    header = _read(descriptor, size, pe_offset, 24)
    if header[:4] != b"PE\0\0":
        raise _error("invalid_artifact", "PE signature is missing")
    machine, count, _, _, _, optional_size, _ = struct.unpack("<HHIIIHH", header[4:])
    if count > MAX_HEADERS:
        raise _Unsupported("metadata_limit", "PE section table exceeds its record limit")
    optional_offset = pe_offset + 24
    if optional_size < 32 or optional_offset + optional_size + count * 40 > size:
        raise _error("invalid_artifact", "PE optional header or section table is truncated")
    optional = _read(descriptor, size, optional_offset, 32)
    magic = struct.unpack_from("<H", optional)[0]
    if magic not in {0x10B, 0x20B}:
        raise _Unsupported("unsupported_format", "PE optional-header format is unsupported")
    bits = 32 if magic == 0x10B else 64
    if optional_size < (96 if bits == 32 else 112):
        raise _error("invalid_artifact", "PE optional header is incomplete")
    entry = struct.unpack_from("<I", optional, 16)[0]
    image_base = struct.unpack_from(
        "<I" if bits == 32 else "<Q", optional, 28 if bits == 32 else 24
    )[0]
    if not entry and address is None:
        raise _Unsupported("entrypoint_unavailable", "PE does not declare an entrypoint")
    if entry and image_base + entry >= 1 << bits:
        raise _error("invalid_artifact", "PE entrypoint address overflows its bitness")
    image = _machine(
        "pe",
        machine,
        bits,
        "little",
        image_base + entry if entry else address or 0,
    )
    regions = []
    for index in range(count):
        raw = _read(descriptor, size, optional_offset + optional_size + index * 40, 40)
        virtual_size, rva, raw_size, offset = struct.unpack_from("<IIII", raw, 8)
        flags = struct.unpack_from("<I", raw, 36)[0]
        mapped_size = virtual_size or raw_size
        if (
            offset + raw_size > size
            or rva + mapped_size > 1 << 32
            or image_base + rva + mapped_size > 1 << bits
        ):
            raise _error("invalid_artifact", "PE section bounds are invalid")
        if flags & 0x20000000 and raw_size:
            regions.append(
                _Region(offset, image_base + rva, min(raw_size, mapped_size), "section", index)
            )
    start = _start_address(image, address)
    return image, _select(regions, start, explicit=address is not None), start


def _decode(
    descriptor: int, size: int, image: _Image, region: _Region, start: int
) -> dict[str, Any]:
    endian = (
        _capstone.CS_MODE_LITTLE_ENDIAN
        if image.byte_order == "little"
        else _capstone.CS_MODE_BIG_ENDIAN
    )
    architectures = {
        "x86": _capstone.CS_ARCH_X86,
        "arm": _capstone.CS_ARCH_ARM,
        "aarch64": _capstone.CS_ARCH_ARM64,
    }
    modes = {
        "32": _capstone.CS_MODE_32,
        "64": _capstone.CS_MODE_64,
        "arm": _capstone.CS_MODE_ARM,
        "thumb": _capstone.CS_MODE_THUMB,
        "aarch64": _capstone.CS_MODE_ARM,
    }
    try:
        decoder = _capstone.Cs(architectures[image.architecture], modes[image.mode] | endian)
        decoder.detail = False
        decoder.skipdata = False
    except _capstone.CsError as exc:
        raise _Unsupported(
            "unsupported_machine_mode", "Capstone rejected the declared machine mode"
        ) from exc
    displacement = start - region.address
    remaining = region.size - displacement
    window_size = min(MAX_INSTRUCTION_BYTES, remaining)
    offset = region.offset + displacement
    data = _read(descriptor, size, offset, window_size)
    result: dict[str, Any] = {
        "decoder": "capstone",
        "format": image.format,
        "machine": image.machine,
        "class_bits": image.bits,
        "byte_order": image.byte_order,
        "architecture": image.architecture,
        "mode": image.mode,
        "status": "ok",
        "coverage": "partial",
        "stop_reason": "undecodable_bytes",
        "interpretation": "linear declared-mode decoding; no control-flow or data classification",
        "region_kind": region.kind,
        "region_index": region.index,
        "start_address": hex(start),
        "file_offset": offset,
        "window_bytes": window_size,
        "decoded_bytes": 0,
        "instruction_count": 0,
        "instructions": [],
    }
    # Reserve room for the longest final reason/counters. The entire result, not
    # just instruction text, stays strictly below the output limit.
    output_bytes = len(json.dumps(result).encode()) + 128
    try:
        for instruction in decoder.disasm(data, start, count=MAX_INSTRUCTIONS):
            row = {
                "address": hex(instruction.address),
                "bytes": bytes(instruction.bytes).hex(),
                "mnemonic": instruction.mnemonic,
                "operands": instruction.op_str,
            }
            row_bytes = len(json.dumps(row).encode()) + 2
            if output_bytes + row_bytes >= MAX_OUTPUT_BYTES:
                result["stop_reason"] = "output_limit"
                break
            output_bytes += row_bytes
            result["instructions"].append(row)
            result["decoded_bytes"] += instruction.size
    except _capstone.CsError:
        result["stop_reason"] = "decoder_error"
    result["instruction_count"] = len(result["instructions"])
    if result["stop_reason"] == "undecodable_bytes":
        if result["decoded_bytes"] == window_size:
            result["stop_reason"] = (
                "byte_window_limit" if window_size < remaining else "end_of_region"
            )
        elif result["instruction_count"] == MAX_INSTRUCTIONS:
            result["stop_reason"] = "instruction_limit"
    if not result["instruction_count"]:
        result["status"] = "unsupported"
        result["coverage"] = "unsupported"
    elif (
        result["stop_reason"] in {"byte_window_limit", "instruction_limit", "output_limit"}
        and result["decoded_bytes"]
        and start + result["decoded_bytes"] < region.address + region.size
    ):
        result["next_address"] = start + result["decoded_bytes"]
    return result


def disassemble(descriptor: int, size: int, address: int | None = None) -> dict[str, Any]:
    """Return at most 256 instructions from an entrypoint or bounded image address.

    The caller owns the open regular-file descriptor and its workspace policy.
    Unsupported inputs return explicit non-success results; malformed metadata,
    invalid descriptors, and source changes raise ToolError. Coverage never
    claims that one linear byte window represents the entire executable.
    """
    if (
        type(descriptor) is not int
        or descriptor < 0
        or type(size) is not int
        or not 0 <= size < 1 << 63
        or (address is not None and (type(address) is not int or not 0 <= address < 1 << 64))
    ):
        raise _error(
            "invalid_argument", "disassembly requires a descriptor and bounded integer size"
        )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise _error("not_a_file", "disassembly requires a regular-file descriptor")
        if before.st_size != size:
            raise _error("source_changed", "artifact size differs from the opened source")
        prefix = _read(descriptor, size, 0, min(size, 4))
        if not prefix.startswith((b"\x7fELF", b"MZ")):
            raise _Unsupported("unsupported_format", "only ELF and PE disassembly are supported")
        if _capstone is None:
            raise _Unsupported("dependency_unavailable", "Capstone is unavailable")
        image, region, start = (
            _elf(descriptor, size, address)
            if prefix == b"\x7fELF"
            else _pe(descriptor, size, address)
        )
        result = _decode(descriptor, size, image, region, start)
        result["window"] = "entrypoint" if address is None else "address"
        after = os.fstat(descriptor)
        if any(
            getattr(before, key) != getattr(after, key)
            for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        ):
            raise _error("source_changed", "artifact changed during disassembly")
        return result
    except _Unsupported as exc:
        reason, message = exc.args
        return {
            "decoder": "capstone",
            "status": "unsupported",
            "coverage": "unsupported",
            "stop_reason": reason,
            "error": message,
            "instruction_count": 0,
            "instructions": [],
        }
    except OSError as exc:
        raise _error("read_failed", "artifact bytes could not be read for disassembly") from exc
