from __future__ import annotations

import json
import os
import struct
from types import SimpleNamespace

import pytest

from rapido import capstone_tools
from rapido.tools import ToolError


def _elf(
    code: bytes = b"\x90\xc3",
    *,
    bits: int = 64,
    machine: int = 62,
    endian: str = "<",
    entry: int = 0x1000,
    address: int = 0x1000,
    flags: int = 0,
    program: bool = False,
    executable: bool = True,
) -> bytes:
    """Inert ELF metadata and instruction bytes, never linked or executed."""
    header_size, section_size, program_size = (64, 64, 56) if bits == 64 else (52, 40, 32)
    header_format = "HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"
    ident = b"\x7fELF" + bytes((2 if bits == 64 else 1, 1 if endian == "<" else 2, 1)) + bytes(9)
    header = struct.pack(
        endian + header_format,
        2,
        machine,
        1,
        entry,
        header_size if program else 0,
        0 if program else header_size,
        flags,
        header_size,
        program_size if program else 0,
        int(program),
        0 if program else section_size,
        0 if program else 2,
        0,
    )
    if program:
        values = (1, 5 if executable else 4, 512, address, 0, len(code), len(code), 1)
        if bits == 32:
            values = (1, 512, address, 0, len(code), len(code), 5 if executable else 4, 1)
        table = struct.pack(endian + ("IIQQQQQQ" if bits == 64 else "IIIIIIII"), *values)
    else:
        table = bytes(section_size) + struct.pack(
            endian + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII"),
            0,
            1,
            6 if executable else 2,
            address,
            512,
            len(code),
            0,
            0,
            1,
            0,
        )
    return (ident + header + table).ljust(512, b"\0") + code


def _pe(
    code: bytes = b"\x90\xc3",
    *,
    bits: int = 64,
    machine: int = 0x8664,
    entry: int = 0x1000,
    virtual_size: int | None = None,
    executable: bool = True,
) -> bytes:
    """Inert PE headers with one executable section and no directories."""
    dos = bytearray(128)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 128)
    optional = bytearray(112 if bits == 64 else 96)
    struct.pack_into("<H", optional, 0, 0x20B if bits == 64 else 0x10B)
    struct.pack_into("<I", optional, 16, entry)
    struct.pack_into("<Q" if bits == 64 else "<I", optional, 24 if bits == 64 else 28, 0x400000)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, len(optional), 2)
    section = bytearray(40)
    section[:8] = b".text\0\0\0"
    struct.pack_into(
        "<IIII",
        section,
        8,
        len(code) if virtual_size is None else virtual_size,
        0x1000,
        len(code),
        512,
    )
    struct.pack_into("<I", section, 36, 0x20000020 if executable else 0x40000040)
    return bytes(dos + coff + optional + section).ljust(512, b"\0") + code


def _run(tmp_path, data: bytes):
    path = tmp_path / "inert"
    path.write_bytes(data)
    with path.open("rb") as source:
        return capstone_tools.disassemble(source.fileno(), len(data))


_CASES = [
    (32, 3, "<", 0x1000, "b80100000090c3", [(0, "mov", "eax, 1"), (5, "nop", ""), (6, "ret", "")]),
    (64, 62, "<", 0x1000, "4889d890c3", [(0, "mov", "rax, rbx"), (3, "nop", ""), (4, "ret", "")]),
    (32, 40, "<", 0x1000, "0100a0e31eff2fe1", [(0, "mov", "r0, #1"), (4, "bx", "lr")]),
    (32, 40, ">", 0x1000, "e3a00001e12fff1e", [(0, "mov", "r0, #1"), (4, "bx", "lr")]),
    (32, 40, "<", 0x1001, "01207047", [(0, "movs", "r0, #1"), (2, "bx", "lr")]),
    (64, 183, "<", 0x1000, "200080d2c0035fd6", [(0, "mov", "x0, #1"), (4, "ret", "")]),
]


@pytest.mark.parametrize("program", [False, True])
@pytest.mark.parametrize("bits,machine,endian,entry,hex_code,expected", _CASES)
def test_elf_declared_modes_and_exact_instructions(
    tmp_path,
    bits,
    machine,
    endian,
    entry,
    hex_code,
    expected,
    program,
):
    result = _run(
        tmp_path,
        _elf(
            bytes.fromhex(hex_code),
            bits=bits,
            machine=machine,
            endian=endian,
            entry=entry,
            program=program,
        ),
    )
    assert result["status"] == "ok"
    assert result["coverage"] == "partial"
    assert result["stop_reason"] == "end_of_region"
    assert result["byte_order"] == ("little" if endian == "<" else "big")
    assert result["region_kind"] == ("segment" if program else "section")
    assert result["file_offset"] == 512
    assert result["decoded_bytes"] == len(bytes.fromhex(hex_code))
    assert [
        (row["address"], row["mnemonic"], row["operands"]) for row in result["instructions"]
    ] == [(hex(0x1000 + offset), mnemonic, operands) for offset, mnemonic, operands in expected]
    assert "".join(row["bytes"] for row in result["instructions"]) == hex_code
    assert "version" not in result


@pytest.mark.parametrize(
    "bits,machine,hex_code,expected",
    [
        (32, 0x14C, _CASES[0][4], _CASES[0][5]),
        (64, 0x8664, _CASES[1][4], _CASES[1][5]),
        (32, 0x1C0, _CASES[2][4], _CASES[2][5]),
        (32, 0x1C2, _CASES[4][4], _CASES[4][5]),
        (32, 0x1C4, _CASES[4][4], _CASES[4][5]),
        (64, 0xAA64, _CASES[5][4], _CASES[5][5]),
    ],
)
def test_pe_declared_modes_and_image_base(tmp_path, bits, machine, hex_code, expected):
    result = _run(tmp_path, _pe(bytes.fromhex(hex_code), bits=bits, machine=machine))
    assert result["status"] == "ok"
    assert result["stop_reason"] == "end_of_region"
    assert result["start_address"] == "0x401000"
    assert [
        (row["address"], row["mnemonic"], row["operands"]) for row in result["instructions"]
    ] == [(hex(0x401000 + offset), mnemonic, operands) for offset, mnemonic, operands in expected]


@pytest.mark.parametrize(
    "data",
    [
        _elf(machine=243),
        _elf(bits=32),
        _elf(endian=">"),
        _elf(machine=183, endian=">"),
        _elf(bits=32, machine=40, flags=0x00800000),
        _elf(bits=32, machine=40, flags=0x00400000),
        _elf(bits=32, machine=40, entry=0x1002),
        _pe(machine=0xA641),
        _pe(machine=0x14C),
        _pe(bits=32, machine=0x1C0, entry=0x1001),
    ],
)
def test_unsupported_machine_mode_never_claims_success(tmp_path, data):
    result = _run(tmp_path, data)
    assert result["status"] == result["coverage"] == "unsupported"
    assert result["stop_reason"] == "unsupported_machine_mode"
    assert result["instructions"] == []


@pytest.mark.parametrize(
    "data",
    [
        _elf(entry=0x2000),
        _elf(executable=False),
        _elf(program=True, executable=False),
        _pe(entry=0),
        _pe(entry=0x2000),
        _pe(executable=False),
        _pe(b"\x90" * 10, entry=0x1008, virtual_size=4),
    ],
)
def test_missing_file_backed_executable_entrypoint_is_explicit(tmp_path, data):
    result = _run(tmp_path, data)
    assert result["status"] == "unsupported"
    assert result["stop_reason"] == "entrypoint_unavailable"


def test_entrypoint_offset_and_virtual_padding_are_respected(tmp_path):
    result = _run(tmp_path, _pe(b"\x00\x00\x90\xc3\xff", entry=0x1002, virtual_size=4))
    assert result["file_offset"] == 514
    assert result["window_bytes"] == result["decoded_bytes"] == 2
    assert [row["mnemonic"] for row in result["instructions"]] == ["nop", "ret"]
    assert result["instructions"][0]["address"] == "0x401002"


@pytest.mark.parametrize(
    "data,address,expected",
    [
        (_elf(b"\x90\xc3"), 0x1001, "ret"),
        (_pe(b"\x90\xc3"), 0x401001, "ret"),
        (_pe(b"\x90\xc3", entry=0), 0x401001, "ret"),
    ],
)
def test_explicit_address_window_within_supported_region(tmp_path, data, address, expected):
    path = tmp_path / "inert"
    path.write_bytes(data)
    with path.open("rb") as source:
        result = capstone_tools.disassemble(source.fileno(), len(data), address)
    assert result["window"] == "address"
    assert result["start_address"] == hex(address)
    assert result["instructions"][0]["mnemonic"] == expected


def test_explicit_address_selects_another_executable_region(tmp_path):
    data = bytearray(_elf(b"\xc3"))
    struct.pack_into("<H", data, 60, 3)
    second_offset = len(data)
    data.extend(b"\x90\xc3")
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        192,
        0,
        1,
        6,
        0x2000,
        second_offset,
        2,
        0,
        0,
        1,
        0,
    )
    path = tmp_path / "inert"
    path.write_bytes(data)
    with path.open("rb") as source:
        result = capstone_tools.disassemble(source.fileno(), len(data), 0x2000)
    assert result["region_index"] == 2
    assert [row["mnemonic"] for row in result["instructions"]] == ["nop", "ret"]


@pytest.mark.parametrize("address", [-1, True, 1 << 64])
def test_invalid_explicit_address_is_refused(tmp_path, address):
    data = _elf()
    path = tmp_path / "inert"
    path.write_bytes(data)
    with path.open("rb") as source, pytest.raises(ToolError) as error:
        capstone_tools.disassemble(source.fileno(), len(data), address)
    assert error.value.code == "invalid_argument"


@pytest.mark.parametrize("data", [b"", b"not an executable"])
def test_unrecognized_format_is_explicit(tmp_path, data):
    assert _run(tmp_path, data)["stop_reason"] == "unsupported_format"


def test_missing_capstone_is_explicit_and_does_not_read_code(tmp_path, monkeypatch):
    monkeypatch.setattr(capstone_tools, "_capstone", None)
    monkeypatch.setattr(capstone_tools, "_elf", lambda *_: pytest.fail("read metadata"))
    result = _run(tmp_path, _elf())
    assert result["status"] == result["coverage"] == "unsupported"
    assert result["stop_reason"] == "dependency_unavailable"


@pytest.mark.parametrize("data", [b"\x7fELF", b"MZ", _elf()[:-1], _pe()[:-1]])
def test_truncated_metadata_or_regions_are_rejected(tmp_path, data):
    with pytest.raises(ToolError) as error:
        _run(tmp_path, data)
    assert error.value.code in {"invalid_artifact", "invalid_elf"}


@pytest.mark.parametrize(
    "case", ["elf_memory", "elf_address", "pe_optional", "pe_signature", "pe_address"]
)
def test_malformed_bounds_and_headers(tmp_path, case):
    data = bytearray(_elf(program=True) if case.startswith("elf") else _pe())
    if case == "elf_memory":
        struct.pack_into("<Q", data, 64 + 40, 1)
    elif case == "elf_address":
        struct.pack_into("<Q", data, 64 + 16, (1 << 64) - 1)
    elif case == "pe_optional":
        struct.pack_into("<H", data, 128 + 20, 32)
    elif case == "pe_signature":
        data[128:132] = b"NOPE"
    else:
        struct.pack_into("<Q", data, 128 + 24 + 24, (1 << 64) - 1)
    with pytest.raises(ToolError) as error:
        _run(tmp_path, bytes(data))
    assert error.value.code == "invalid_artifact"


def test_overlapping_executable_regions_are_not_guessed(tmp_path):
    data = bytearray(_elf())
    struct.pack_into("<H", data, 60, 3)
    data[192:256] = data[128:192]
    result = _run(tmp_path, bytes(data))
    assert result["status"] == "unsupported"
    assert result["stop_reason"] == "ambiguous_entrypoint"


def test_metadata_record_limit_precedes_region_scanning(tmp_path, monkeypatch):
    monkeypatch.setattr(capstone_tools, "MAX_HEADERS", 1)
    result = _run(tmp_path, _elf())
    assert result["stop_reason"] == "metadata_limit"


def test_instruction_and_read_budgets(tmp_path, monkeypatch):
    real_pread = os.pread
    reads = []

    def read(descriptor, length, offset):
        reads.append((length, offset))
        return real_pread(descriptor, length, offset)

    monkeypatch.setattr(capstone_tools.os, "pread", read)
    result = _run(tmp_path, _elf(b"\x90" * 10000))
    assert result["instruction_count"] == 256
    assert result["decoded_bytes"] == 256
    assert result["stop_reason"] == "instruction_limit"
    assert max(length for length, _ in reads) == 4096
    assert [(length, offset) for length, offset in reads if offset >= 512] == [(4096, 512)]
    assert len(json.dumps(result).encode()) < 32 * 1024


def test_byte_window_limit_is_distinct_from_undecodable_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(capstone_tools, "MAX_INSTRUCTION_BYTES", 128)
    result = _run(tmp_path, _elf(b"\x90" * 200))
    assert result["stop_reason"] == "byte_window_limit"
    assert result["instruction_count"] == result["decoded_bytes"] == 128


@pytest.mark.parametrize("code,count,status", [(b"\x90\x0f", 1, "ok"), (b"\x0f", 0, "unsupported")])
def test_undecodable_trailing_bytes_are_not_skipped(tmp_path, code, count, status):
    result = _run(tmp_path, _elf(code))
    assert result["stop_reason"] == "undecodable_bytes"
    assert result["instruction_count"] == count
    assert result["status"] == status


def test_total_output_limit_preserves_whole_instructions(tmp_path, monkeypatch):
    original = capstone_tools._capstone

    class Decoder:
        def disasm(self, data, address, count):
            assert len(data) <= 4096 and count == 256
            for index in range(256):
                yield SimpleNamespace(
                    address=address + index, size=1, bytes=b"\x90", mnemonic="nop", op_str="x" * 200
                )

    monkeypatch.setattr(original, "Cs", lambda *_: Decoder())
    result = _run(tmp_path, _elf(b"\x90" * 256))
    assert result["stop_reason"] == "output_limit"
    assert 0 < result["instruction_count"] < 256
    assert len(json.dumps(result).encode()) < 32 * 1024
    assert all(row["operands"] == "x" * 200 for row in result["instructions"])


def test_decoder_mode_rejection_is_explicit(tmp_path, monkeypatch):
    def reject(*_):
        raise capstone_tools._capstone.CsError(capstone_tools._capstone.CS_ERR_MODE)

    monkeypatch.setattr(capstone_tools._capstone, "Cs", reject)
    assert _run(tmp_path, _elf())["stop_reason"] == "unsupported_machine_mode"


def test_uses_open_descriptor_without_following_replaced_path(tmp_path, monkeypatch):
    data = _elf()
    path = tmp_path / "original"
    path.write_bytes(data)
    outside = tmp_path / "outside"
    outside.write_bytes(b"not an ELF")
    with path.open("rb") as source:
        path.rename(tmp_path / "retained")
        path.symlink_to(outside)
        monkeypatch.setattr(os, "open", lambda *_a, **_k: pytest.fail("opened a path"))
        result = capstone_tools.disassemble(source.fileno(), len(data))
    assert [row["mnemonic"] for row in result["instructions"]] == ["nop", "ret"]


def test_short_read_and_changed_source_are_rejected(tmp_path, monkeypatch):
    real_pread = os.pread

    def read(descriptor, length, offset):
        data = real_pread(descriptor, length, offset)
        return data[:-1] if offset == 512 else data

    monkeypatch.setattr(capstone_tools.os, "pread", read)
    with pytest.raises(ToolError) as error:
        _run(tmp_path, _elf())
    assert error.value.code == "source_changed"


def test_source_change_after_code_read_is_rejected(tmp_path, monkeypatch):
    real_pread = os.pread

    def read(descriptor, length, offset):
        data = real_pread(descriptor, length, offset)
        if offset == 512:
            with (tmp_path / "inert").open("ab") as source:
                source.write(b"changed")
        return data

    monkeypatch.setattr(capstone_tools.os, "pread", read)
    with pytest.raises(ToolError) as error:
        _run(tmp_path, _elf())
    assert error.value.code == "source_changed"


@pytest.mark.parametrize("size", [-1, True, 1 << 63])
def test_invalid_size_is_refused(size):
    with pytest.raises(ToolError) as error:
        capstone_tools.disassemble(0, size)
    assert error.value.code == "invalid_argument"


def test_mismatched_size_is_refused_before_reads(tmp_path):
    path = tmp_path / "inert"
    path.write_bytes(_elf())
    with path.open("rb") as source, pytest.raises(ToolError) as error:
        capstone_tools.disassemble(source.fileno(), 1)
    assert error.value.code == "source_changed"
