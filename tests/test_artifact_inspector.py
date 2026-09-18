from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import struct
import tarfile
import wave
import zipfile
from types import SimpleNamespace

import dpkt
import pefile
import pypdf
import pytest
from PIL import Image

from rapido import artifact_inspector
from rapido.artifact_inspector import (
    MAX_OUTPUT_BYTES,
    MAX_SOURCE_BYTES,
    _inspect_artifact_local,
    artifact_tool_spec,
)
from rapido.artifact_inspector import (
    inspect_artifact as isolated_inspect_artifact,
)
from rapido.tools import ToolError, Workspace

inspect_artifact = _inspect_artifact_local


@pytest.fixture(autouse=True)
def _in_process_optional_adapters(monkeypatch):
    monkeypatch.setattr(artifact_inspector, "_dpkt", dpkt)
    monkeypatch.setattr(artifact_inspector, "_pefile", pefile)
    monkeypatch.setattr(artifact_inspector, "_pypdf", pypdf)
    monkeypatch.setattr(artifact_inspector, "_PILImage", Image)


def _elf_fixture(text: bytes = b"\x90\xc3") -> bytes:
    header_size = section_size = 64
    names = b"\x00.text\x00.shstrtab\x00"
    names_offset = header_size + len(text)
    sections_offset = (names_offset + len(names) + 7) // 8 * 8
    ident = b"\x7fELF" + bytes((2, 1, 1)) + b"\x00" * 9
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        62,
        1,
        0x1000,
        0,
        sections_offset,
        0,
        header_size,
        0,
        0,
        section_size,
        3,
        2,
    )
    sections = (
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 6, 0x1000, header_size, len(text), 0, 0, 1, 0),
        (7, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
    )
    prefix = ident + header + text + names
    return prefix.ljust(sections_offset, b"\x00") + b"".join(
        struct.pack("<IIQQQQIIQQ", *section) for section in sections
    )


def _pe_fixture() -> bytes:
    pe_offset = 0x80
    dos = bytearray(pe_offset)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_offset)
    optional = bytearray(112)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<Q", optional, 24, 0x140000000)
    raw_offset = pe_offset + 24 + len(optional) + 40
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, len(optional), 0x2022)
    section = b".text\x00\x00\x00" + struct.pack(
        "<IIIIIIHHI", 1, 0x1000, 1, raw_offset, 0, 0, 0, 0, 0x60000020
    )
    return bytes(dos) + coff + optional + section + b"\xc3"


def _fake_pefile(*, imports=(), exports=()):
    class PE:
        def __init__(self, **_kwargs):
            self.DIRECTORY_ENTRY_IMPORT = list(imports)
            self.DIRECTORY_ENTRY_EXPORT = SimpleNamespace(symbols=list(exports))

        def parse_data_directories(self, **_kwargs):
            return None

    return SimpleNamespace(
        PE=PE,
        DIRECTORY_ENTRY={
            "IMAGE_DIRECTORY_ENTRY_IMPORT": 1,
            "IMAGE_DIRECTORY_ENTRY_EXPORT": 2,
        },
    )


def _pe_imports(count: int):
    return [SimpleNamespace(name=b"symbol", ordinal=index) for index in range(count)]


def _pe_exports(count: int):
    return [
        SimpleNamespace(name=b"export", ordinal=index, address=0x1000 + index)
        for index in range(count)
    ]


def _dicom_element(group: int, element: int, vr: str, value: bytes) -> bytes:
    if len(value) % 2:
        value += b"\x00" if vr == "UI" else b" "
    if vr in {"OB", "OD", "OF", "OL", "OV", "OW", "SQ", "SV", "UC", "UN", "UR", "UT", "UV"}:
        return struct.pack("<HH2s2xI", group, element, vr.encode(), len(value)) + value
    return struct.pack("<HH2sH", group, element, vr.encode(), len(value)) + value


def _dicom_fixture() -> bytes:
    syntax = _dicom_element(0x0002, 0x0010, "UI", b"1.2.840.10008.1.2.1")
    patient = _dicom_element(0x0010, 0x0010, "PN", b"ALPHA^BETA")
    pixels = _dicom_element(0x7FE0, 0x0010, "OW", b"OMITTED")
    return b"\x00" * 128 + b"DICM" + syntax + patient + pixels


def _pcap_fixture(packets: list[bytes]) -> bytes:
    result = bytearray(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1))
    for index, packet in enumerate(packets):
        result.extend(struct.pack("<IIII", index + 1, 0, len(packet), len(packet)))
        result.extend(packet)
    return bytes(result)


def _pcapng_block(kind: int, body: bytes, endian: str = "<") -> bytes:
    length = 12 + len(body)
    assert length % 4 == 0
    return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)


def _pcapng_fixture() -> bytes:
    section = _pcapng_block(0x0A0D0D0A, b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1))
    interface = _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    packet = b"abcd"
    enhanced = _pcapng_block(6, struct.pack("<IIIII", 0, 0, 1, 4, 4) + packet)
    return section + interface + enhanced


def test_spec_is_one_strict_required_path_interface():
    spec = artifact_tool_spec()
    assert spec["name"] == "inspect_artifact"
    assert spec["inputSchema"]["required"] == ["path"]
    assert spec["inputSchema"]["additionalProperties"] is False
    assert spec["inputSchema"]["properties"]["view"]["enum"] == [
        "summary",
        "text",
        "structure",
        "bytes",
    ]
    json.dumps(spec)


def test_public_inspector_routes_optional_parsers_through_bound_worker(tmp_path, monkeypatch):
    source = tmp_path / "image.png"
    source.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 32)
    calls = []

    def worker(descriptor, operation, *, size, cursor, base):
        calls.append((os.fstat(descriptor).st_size, operation, size, cursor, base))
        return {**base, "coverage": "unsupported", "stop_reason": "fixture", "data": {}}

    monkeypatch.setattr(artifact_inspector, "run_artifact_worker", worker)
    result = isolated_inspect_artifact(Workspace(tmp_path), {"path": "image.png"})
    assert result["stop_reason"] == "fixture"
    assert calls[0][0:4] == (40, "image", 40, None)
    assert calls[0][4]["source_sha256"] == result["source_sha256"]


def test_public_inspector_routes_tar_inventory_through_bound_worker(tmp_path, monkeypatch):
    with tarfile.open(tmp_path / "one.tar", "w") as archive:
        member = tarfile.TarInfo("safe.txt")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    calls = []

    def worker(descriptor, operation, *, size, cursor, base):
        calls.append((os.fstat(descriptor).st_size, operation, size, cursor, base))
        return {**base, "coverage": "complete", "stop_reason": "fixture", "data": {}}

    monkeypatch.setattr(artifact_inspector, "run_artifact_worker", worker)
    monkeypatch.setattr(
        artifact_inspector,
        "_tar_view",
        lambda *_args, **_kwargs: pytest.fail("supervisor parsed TAR inventory"),
    )
    result = isolated_inspect_artifact(
        Workspace(tmp_path), {"path": "one.tar", "view": "structure"}
    )
    assert result["stop_reason"] == "fixture"
    size = (tmp_path / "one.tar").stat().st_size
    assert calls[0][0:4] == (size, "tar", size, None)
    assert calls[0][4]["format"] == "tar"


def test_public_inspector_rejects_same_inode_change_after_worker_result(tmp_path, monkeypatch):
    source = tmp_path / "one.tar"
    with tarfile.open(source, "w") as archive:
        member = tarfile.TarInfo("safe.txt")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    original = source.stat()

    def worker(descriptor, operation, *, size, cursor, base):
        del descriptor, operation, size, cursor
        with source.open("r+b") as stream:
            stream.seek(-1, os.SEEK_END)
            stream.write(b"x")
            stream.flush()
            os.fsync(stream.fileno())
        os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns + 1_000_000_000))
        assert source.stat().st_ino == original.st_ino
        return {**base, "coverage": "complete", "stop_reason": "fixture", "data": {}}

    monkeypatch.setattr(artifact_inspector, "run_artifact_worker", worker)
    with pytest.raises(ToolError) as error:
        isolated_inspect_artifact(Workspace(tmp_path), {"path": "one.tar", "view": "structure"})
    assert error.value.code == "source_changed"


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"path": ""},
        {"path": "a", "view": "execute"},
        {"path": "a", "selection": "../../outside"},
        {"path": "a", "extra": True},
        {"path": "a", "cursor": 1},
        {"path": "\udcff"},
    ],
)
def test_arguments_are_closed_and_bounded(tmp_path, arguments):
    (tmp_path / "a").write_bytes(b"a")
    with pytest.raises(ToolError) as error:
        inspect_artifact(Workspace(tmp_path), arguments)
    assert error.value.code in {"invalid_argument", "invalid_cursor"}


def test_utf8_utf16_and_legacy_text_are_content_detected(tmp_path):
    (tmp_path / "utf8").write_text("alpha\nβeta\n", encoding="utf-8")
    (tmp_path / "utf16").write_text("alpha\nbeta\n", encoding="utf-16")
    (tmp_path / "legacy").write_bytes("café\n".encode("cp1252"))
    workspace = Workspace(tmp_path)
    utf8 = inspect_artifact(workspace, {"path": "utf8", "view": "text"})
    utf16 = inspect_artifact(workspace, {"path": "utf16", "view": "text"})
    legacy = inspect_artifact(workspace, {"path": "legacy", "view": "text"})
    assert utf8["format"] == "text" and "βeta" in utf8["data"]["text"]
    assert utf16["data"]["encoding"] == "utf-16-le"
    assert "beta" in utf16["data"]["text"]
    assert legacy["data"]["encoding"] == "cp1252"
    assert "café" in legacy["data"]["text"]


def test_text_and_bytes_paging_is_source_bound_and_stale_after_change(tmp_path):
    path = tmp_path / "long.txt"
    path.write_text("line\n" * 20_000)
    workspace = Workspace(tmp_path)
    first = inspect_artifact(workspace, {"path": "long.txt", "view": "bytes"})
    assert first["coverage"] == "partial"
    second = inspect_artifact(
        workspace, {"path": "long.txt", "view": "bytes", "cursor": first["next_cursor"]}
    )
    assert second["data"]["offset"] == first["data"]["length"]
    with pytest.raises(ToolError) as wrong_view:
        inspect_artifact(
            workspace, {"path": "long.txt", "view": "text", "cursor": first["next_cursor"]}
        )
    assert wrong_view.value.code == "stale_cursor"
    path.write_text("changed\n" * 20_000)
    with pytest.raises(ToolError) as stale:
        inspect_artifact(
            workspace, {"path": "long.txt", "view": "bytes", "cursor": first["next_cursor"]}
        )
    assert stale.value.code == "stale_cursor"


def test_structure_lines_and_all_results_respect_output_cap(tmp_path):
    (tmp_path / "lines").write_text(("x" * 2000 + "\n") * 300)
    result = inspect_artifact(Workspace(tmp_path), {"path": "lines", "view": "structure"})
    assert result["coverage"] == "partial"
    assert result["stop_reason"] in {"record_limit", "text_page_limit"}
    assert len(json.dumps(result, separators=(",", ":")).encode()) <= MAX_OUTPUT_BYTES


def test_zip_inventory_pages_without_reading_members_or_extracting(tmp_path):
    with zipfile.ZipFile(tmp_path / "many.zip", "w") as archive:
        for index in range(101):
            archive.writestr(f"entry-{index:03}.txt", b"member secret")
        archive.writestr("../outside", b"never extract")
    before = set(os.listdir(tmp_path))
    first = inspect_artifact(Workspace(tmp_path), {"path": "many.zip", "view": "structure"})
    second = inspect_artifact(
        Workspace(tmp_path),
        {"path": "many.zip", "view": "structure", "cursor": first["next_cursor"]},
    )
    assert len(first["data"]["entries"]) == 100
    assert second["coverage"] == "complete"
    assert any(entry["unsafe"] for entry in second["data"]["entries"])
    assert set(os.listdir(tmp_path)) == before
    assert "member secret" not in json.dumps(first)


def test_zip_declared_bomb_is_only_flagged_in_inventory(tmp_path):
    with zipfile.ZipFile(tmp_path / "bomb.zip", "w") as archive:
        archive.writestr("huge.bin", b"")
    raw = bytearray((tmp_path / "bomb.zip").read_bytes())
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<I", raw, central + 24, 600 * 1024 * 1024)
    (tmp_path / "bomb.zip").write_bytes(raw)
    result = inspect_artifact(Workspace(tmp_path), {"path": "bomb.zip", "view": "structure"})
    assert result["data"]["total_declared_bytes"] == 600 * 1024 * 1024
    assert result["data"]["declared_bytes_over_inventory_limit"] is True
    assert not (tmp_path / "huge.bin").exists()


def test_zip_entry_bomb_is_rejected_before_inventory_materialization(tmp_path):
    with zipfile.ZipFile(tmp_path / "many.zip", "w") as archive:
        for index in range(artifact_inspector.MAX_ARCHIVE_ENTRIES + 1):
            archive.writestr(f"{index}.txt", b"")
    with pytest.raises(ToolError) as error:
        inspect_artifact(Workspace(tmp_path), {"path": "many.zip", "view": "structure"})
    assert error.value.code == "limit_exceeded"


def test_tar_inventory_marks_links_and_never_follows_them(tmp_path):
    with tarfile.open(tmp_path / "links.tar", "w") as archive:
        regular = tarfile.TarInfo("safe.txt")
        regular.size = 1
        archive.addfile(regular, io.BytesIO(b"x"))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)
        hard = tarfile.TarInfo("hard")
        hard.type = tarfile.LNKTYPE
        hard.linkname = "safe.txt"
        archive.addfile(hard)
    result = inspect_artifact(Workspace(tmp_path), {"path": "links.tar", "view": "structure"})
    assert [row["linked"] for row in result["data"]["entries"]] == [False, True, True]
    assert not (tmp_path / "link").exists()


def test_gzip_is_inventory_only_and_never_decompresses(tmp_path, monkeypatch):
    (tmp_path / "data.gz").write_bytes(gzip.compress(b"private payload" * 1000))
    monkeypatch.setattr(gzip, "decompress", lambda *_: pytest.fail("decompressed"))
    result = inspect_artifact(Workspace(tmp_path), {"path": "data.gz"})
    assert result["coverage"] == "partial"
    assert result["stop_reason"] == "inventory_only_no_decompression"
    assert "private payload" not in json.dumps(result)


@pytest.mark.parametrize(
    "name,data",
    [
        ("bad.zip", b"PK\x03\x04broken"),
        (
            "bad.pcap",
            b"\xd4\xc3\xb2\xa1"
            + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1, 0, 2 * 1024 * 1024, 2 * 1024 * 1024),
        ),
        ("bad.elf", b"\x7fELF"),
        ("bad.pe", b"MZ"),
    ],
)
def test_malformed_claimed_formats_fail_with_stable_tool_error(tmp_path, name, data):
    (tmp_path / name).write_bytes(data)
    with pytest.raises(ToolError) as error:
        inspect_artifact(Workspace(tmp_path), {"path": name, "view": "structure"})
    assert error.value.code in {"invalid_artifact", "invalid_elf", "limit_exceeded"}


def test_argument_contract_error_has_bounded_structural_attribution(tmp_path):
    with pytest.raises(ToolError) as error:
        inspect_artifact(Workspace(tmp_path), {"path": "fixture", "view": []})
    assert error.value.code == "invalid_argument"
    assert error.value.details == {
        "schema_version": 1,
        "contract_version": 1,
        "failure_stage": "arguments",
        "constraint": "enum",
        "field_path": "view",
        "actual_kind": "array",
    }


def test_pcap_and_pcapng_record_views_are_bounded(tmp_path):
    ethernet = bytes.fromhex("00112233445566778899aabb0800") + b"payload"
    (tmp_path / "capture.pcap").write_bytes(_pcap_fixture([ethernet, ethernet]))
    (tmp_path / "capture.pcapng").write_bytes(_pcapng_fixture())
    pcap = inspect_artifact(Workspace(tmp_path), {"path": "capture.pcap", "view": "structure"})
    pcapng = inspect_artifact(Workspace(tmp_path), {"path": "capture.pcapng", "view": "structure"})
    assert pcap["coverage"] == "complete" and len(pcap["data"]["records"]) == 2
    assert pcap["data"]["records"][0]["captured_length"] == len(ethernet)
    assert pcapng["coverage"] == "complete"
    assert [row["block_type"] for row in pcapng["data"]["records"]] == [
        "0x0a0d0d0a",
        "0x00000001",
        "0x00000006",
    ]


def test_pcapng_pages_never_exceed_scan_budget(tmp_path, monkeypatch):
    (tmp_path / "capture.pcapng").write_bytes(_pcapng_fixture())
    monkeypatch.setattr(artifact_inspector, "MAX_SCAN_BYTES", 40)
    arguments = {"path": "capture.pcapng", "view": "structure"}
    pages = []
    while True:
        page = inspect_artifact(Workspace(tmp_path), arguments)
        pages.append(page)
        assert page["data"]["scanned_bytes"] <= 40
        if "next_cursor" not in page:
            break
        arguments["cursor"] = page["next_cursor"]
    assert sum(len(page["data"]["records"]) for page in pages) == 3


def test_pcapng_pagination_preserves_mixed_section_byte_order(tmp_path):
    def section(endian: str) -> bytes:
        byte_order_magic = b"\x4d\x3c\x2b\x1a" if endian == "<" else b"\x1a\x2b\x3c\x4d"
        body = byte_order_magic + struct.pack(endian + "HHq", 1, 0, -1)
        return _pcapng_block(0x0A0D0D0A, body, endian)

    def interface(endian: str) -> bytes:
        return _pcapng_block(1, struct.pack(endian + "HHI", 1, 0, 65_535), endian)

    path = tmp_path / "mixed-sections.pcapng"
    path.write_bytes(section("<") + interface("<") * 98 + section(">") + interface(">"))
    workspace = Workspace(tmp_path)
    first = isolated_inspect_artifact(workspace, {"path": path.name, "view": "structure"})
    second = isolated_inspect_artifact(
        workspace,
        {"path": path.name, "view": "structure", "cursor": first["next_cursor"]},
    )
    assert first["coverage"] == "partial" and len(first["data"]["records"]) == 100
    assert second["coverage"] == "complete"
    assert second["data"]["records"] == [
        {"offset": 2016, "block_type": "0x00000001", "block_length": 20}
    ]


def test_pcap_still_has_truthful_inventory_when_dpkt_is_unavailable(tmp_path, monkeypatch):
    (tmp_path / "capture").write_bytes(_pcap_fixture([b"packet"]))
    monkeypatch.setattr(artifact_inspector, "_dpkt", None)
    summary = inspect_artifact(Workspace(tmp_path), {"path": "capture"})
    structure = inspect_artifact(Workspace(tmp_path), {"path": "capture", "view": "structure"})
    assert summary["data"]["packet_decode"] == "unavailable"
    assert structure["coverage"] == "complete"
    assert "decoded" not in structure["data"]["records"][0]


def test_pcap_truncated_packet_never_reports_complete(tmp_path):
    header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 0, 100, 100) + b"x"
    (tmp_path / "truncated.pcap").write_bytes(header + record)
    with pytest.raises(ToolError) as error:
        inspect_artifact(Workspace(tmp_path), {"path": "truncated.pcap", "view": "structure"})
    assert error.value.code == "invalid_artifact"


def test_pe_truncated_declared_optional_header_never_reports_complete(tmp_path):
    pe_offset = 0x80
    source = bytearray(pe_offset)
    source[:2] = b"MZ"
    struct.pack_into("<I", source, 0x3C, pe_offset)
    source.extend(b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 112, 0))
    source.extend(b"\x0b\x02" + b"\x00" * 30)
    (tmp_path / "truncated.exe").write_bytes(source)
    with pytest.raises(ToolError) as error:
        inspect_artifact(Workspace(tmp_path), {"path": "truncated.exe", "view": "structure"})
    assert error.value.code == "invalid_artifact"


def test_elf_and_pe_use_passive_bounded_structure_parsers(tmp_path, monkeypatch):
    (tmp_path / "inert.elf").write_bytes(_elf_fixture())
    (tmp_path / "inert.exe").write_bytes(_pe_fixture())
    monkeypatch.setattr(
        artifact_inspector.subprocess, "Popen", lambda *_a, **_k: pytest.fail("ran")
    )
    elf = inspect_artifact(Workspace(tmp_path), {"path": "inert.elf", "view": "structure"})
    pe = inspect_artifact(Workspace(tmp_path), {"path": "inert.exe", "view": "structure"})
    assert elf["data"]["entry_address"] == "0x1000"
    assert elf["data"]["sections"][1]["name"] == ".text"
    assert pe["data"]["machine"] == 0x8664
    assert pe["data"]["sections"][0]["executable"] is True


def test_pefile_deep_view_is_explicitly_unsupported_when_unavailable(tmp_path, monkeypatch):
    (tmp_path / "inert.exe").write_bytes(_pe_fixture())
    monkeypatch.setattr(artifact_inspector, "_pefile", None)
    result = inspect_artifact(
        Workspace(tmp_path),
        {"path": "inert.exe", "view": "structure", "selection": "imports"},
    )
    assert result["coverage"] == "unsupported"
    assert result["stop_reason"] == "dependency_unavailable"


def test_pe_import_library_limit_reports_partial(tmp_path, monkeypatch):
    (tmp_path / "inert.exe").write_bytes(_pe_fixture())
    libraries = [
        SimpleNamespace(dll=f"lib{index}".encode(), imports=[])
        for index in range(artifact_inspector.MAX_RECORDS + 1)
    ]
    monkeypatch.setattr(artifact_inspector, "_pefile", _fake_pefile(imports=libraries))
    result = inspect_artifact(
        Workspace(tmp_path),
        {"path": "inert.exe", "view": "structure", "selection": "imports"},
    )
    assert len(result["data"]["imports"]) == artifact_inspector.MAX_RECORDS
    assert result["coverage"] == "partial"
    assert result["stop_reason"] == "record_limit"


def test_pe_per_library_import_limit_reports_partial(tmp_path, monkeypatch):
    (tmp_path / "inert.exe").write_bytes(_pe_fixture())
    libraries = [
        SimpleNamespace(dll=b"limited.dll", imports=_pe_imports(artifact_inspector.MAX_RECORDS + 1))
    ]
    monkeypatch.setattr(artifact_inspector, "_pefile", _fake_pefile(imports=libraries))
    result = inspect_artifact(
        Workspace(tmp_path),
        {"path": "inert.exe", "view": "structure", "selection": "imports"},
    )
    assert len(result["data"]["imports"][0]["symbols"]) == artifact_inspector.MAX_RECORDS
    assert result["coverage"] == "partial"
    assert result["stop_reason"] == "record_limit"


def test_pe_per_library_exact_record_limit_is_complete(tmp_path, monkeypatch):
    (tmp_path / "inert.exe").write_bytes(_pe_fixture())
    libraries = [
        SimpleNamespace(dll=b"complete.dll", imports=_pe_imports(artifact_inspector.MAX_RECORDS))
    ]
    monkeypatch.setattr(artifact_inspector, "_pefile", _fake_pefile(imports=libraries))
    result = inspect_artifact(
        Workspace(tmp_path),
        {"path": "inert.exe", "view": "structure", "selection": "imports"},
    )
    assert result["coverage"] == "complete"
    assert result["stop_reason"] == "directory_complete"


def test_pe_export_limit_reports_partial(tmp_path, monkeypatch):
    (tmp_path / "inert.exe").write_bytes(_pe_fixture())
    monkeypatch.setattr(
        artifact_inspector,
        "_pefile",
        _fake_pefile(exports=_pe_exports(artifact_inspector.MAX_RECORDS + 1)),
    )
    result = inspect_artifact(
        Workspace(tmp_path),
        {"path": "inert.exe", "view": "structure", "selection": "exports"},
    )
    assert len(result["data"]["exports"]) == artifact_inspector.MAX_RECORDS
    assert result["coverage"] == "partial"
    assert result["stop_reason"] == "record_limit"


@pytest.mark.parametrize("selection", ["imports", "exports"])
def test_pe_exact_record_limit_is_complete(tmp_path, monkeypatch, selection):
    (tmp_path / "inert.exe").write_bytes(_pe_fixture())
    if selection == "imports":
        libraries = [
            SimpleNamespace(dll=f"lib{index}".encode(), imports=[])
            for index in range(artifact_inspector.MAX_RECORDS)
        ]
        fake = _fake_pefile(imports=libraries)
    else:
        fake = _fake_pefile(exports=_pe_exports(artifact_inspector.MAX_RECORDS))
    monkeypatch.setattr(artifact_inspector, "_pefile", fake)
    result = inspect_artifact(
        Workspace(tmp_path),
        {"path": "inert.exe", "view": "structure", "selection": selection},
    )
    assert result["coverage"] == "complete"
    assert result["stop_reason"] == "directory_complete"


def test_disassembly_is_fixed_and_unavailable_is_not_success(tmp_path, monkeypatch):
    (tmp_path / "inert.elf").write_bytes(_elf_fixture())
    monkeypatch.setattr(
        artifact_inspector.capstone_tools,
        "disassemble",
        lambda *_args: {
            "decoder": "capstone",
            "status": "unsupported",
            "coverage": "unsupported",
            "stop_reason": "dependency_unavailable",
            "instruction_count": 0,
            "instructions": [],
        },
    )
    monkeypatch.setattr(artifact_inspector, "_fixed_executable", lambda _choices: None)
    result = inspect_artifact(
        Workspace(tmp_path),
        {"path": "inert.elf", "view": "text", "selection": "disassembly"},
    )
    assert result["coverage"] == "unsupported"
    assert result["stop_reason"] == "dependency_unavailable"


def test_disassembly_prefers_bounded_multiarchitecture_capstone(tmp_path, monkeypatch):
    (tmp_path / "inert.elf").write_bytes(_elf_fixture())
    result = inspect_artifact(
        Workspace(tmp_path),
        {"path": "inert.elf", "view": "text", "selection": "disassembly"},
    )
    assert result["coverage"] == "partial"
    assert result["stop_reason"] == "end_of_region"
    assert result["data"]["decoder"] == "capstone"
    assert result["data"]["instructions"][0]["mnemonic"] == "nop"
    assert result["data"]["text"] == "0x1000 90 nop\n0x1001 c3 ret"


def test_disassembly_accepts_address_windows_and_cursor_pages(tmp_path):
    (tmp_path / "paged.elf").write_bytes(_elf_fixture(b"\x90" * 600))
    workspace = Workspace(tmp_path)
    selected = inspect_artifact(
        workspace,
        {
            "path": "paged.elf",
            "view": "structure",
            "selection": "disassembly:0x1010",
        },
    )
    assert selected["data"]["start_address"] == "0x1010"
    assert selected["data"]["window"] == "address"
    assert selected["data"]["instruction_count"] == 256
    continued = inspect_artifact(
        workspace,
        {
            "path": "paged.elf",
            "view": "structure",
            "selection": "disassembly:0x1010",
            "cursor": selected["next_cursor"],
        },
    )
    assert continued["data"]["start_address"] == "0x1110"
    with pytest.raises(ToolError) as stale:
        inspect_artifact(
            workspace,
            {
                "path": "paged.elf",
                "view": "structure",
                "selection": "disassembly",
                "cursor": selected["next_cursor"],
            },
        )
    assert stale.value.code == "stale_cursor"


def test_missing_capstone_never_invokes_objdump_or_weakens_confinement(tmp_path, monkeypatch):
    (tmp_path / "inert.elf").write_bytes(_elf_fixture())
    monkeypatch.setattr(
        artifact_inspector.capstone_tools,
        "disassemble",
        lambda *_args: {
            "coverage": "unsupported",
            "stop_reason": "dependency_unavailable",
            "instructions": [],
        },
    )
    monkeypatch.setattr(
        artifact_inspector,
        "_run_fixed",
        lambda *_args: pytest.fail("native fallback must not run"),
    )
    result = inspect_artifact(
        Workspace(tmp_path),
        {"path": "inert.elf", "view": "text", "selection": "disassembly"},
    )
    assert result["coverage"] == "unsupported"
    assert result["stop_reason"] == "dependency_unavailable"


def test_pdf_structure_and_dependency_unavailable_states(tmp_path, monkeypatch):
    if artifact_inspector._pypdf is None:
        pytest.skip("pypdf unavailable")
    writer = artifact_inspector._pypdf.PdfWriter()
    writer.add_blank_page(width=72, height=144)
    with (tmp_path / "one.pdf").open("wb") as output:
        writer.write(output)
    structure = inspect_artifact(Workspace(tmp_path), {"path": "one.pdf", "view": "structure"})
    assert structure["coverage"] == "complete"
    assert structure["data"]["pages"][0]["height_points"] == 144.0
    monkeypatch.setattr(artifact_inspector, "_pypdf", None)
    unavailable = inspect_artifact(Workspace(tmp_path), {"path": "one.pdf"})
    assert unavailable["coverage"] == "unsupported"
    assert unavailable["stop_reason"] == "dependency_unavailable"


def test_raster_metadata_channel_and_lsb_bitplane_signals(tmp_path):
    if artifact_inspector._PILImage is None:
        pytest.skip("Pillow unavailable")
    candidate = "flag{x}"
    bits = [(byte >> shift) & 1 for byte in candidate.encode() for shift in range(7, -1, -1)]
    pixels = [(100 | bit, 10, 20) for bit in bits]
    image = artifact_inspector._PILImage.new("RGB", (len(pixels), 1))
    image.putdata(pixels)
    image.save(tmp_path / "signal.png")
    summary = inspect_artifact(Workspace(tmp_path), {"path": "signal.png"})
    plane = inspect_artifact(
        Workspace(tmp_path),
        {"path": "signal.png", "view": "structure", "selection": "bitplane:R:0"},
    )
    signals = summary["data"]["pixel_signals"]["channels"]["R"]["lsb_signals"]
    assert any(row["text"] == candidate for row in signals["candidate_signals"])
    assert plane["data"]["pixel_signals"]["bitplane"] == 0
    assert plane["coverage"] == "complete"


def test_raster_unavailable_and_fixed_ocr_contract(tmp_path, monkeypatch):
    if artifact_inspector._PILImage is None:
        pytest.skip("Pillow unavailable")
    image = artifact_inspector._PILImage.new("L", (2, 2), 0)
    image.save(tmp_path / "image.png")
    real_pillow = artifact_inspector._PILImage
    monkeypatch.setattr(artifact_inspector, "_PILImage", None)
    unavailable = inspect_artifact(Workspace(tmp_path), {"path": "image.png"})
    assert unavailable["coverage"] == "unsupported"
    monkeypatch.setattr(artifact_inspector, "_PILImage", real_pillow)
    calls = []
    monkeypatch.setattr(
        artifact_inspector,
        "_fixed_executable",
        lambda choices: (
            "/usr/bin/tesseract" if choices == artifact_inspector._FIXED_TESSERACT else None
        ),
    )

    def run(argv, descriptor):
        calls.append((argv, descriptor))
        assert argv[0] == "/usr/bin/tesseract"
        assert argv[1] == "stdin"
        assert argv[2:] == ["stdout", "--psm", "6"]
        return {"returncode": 0, "stdout": b"inert text\n", "stderr": b"", "stop_reason": None}

    monkeypatch.setattr(artifact_inspector, "_run_fixed", run)
    ocr = inspect_artifact(
        Workspace(tmp_path), {"path": "image.png", "view": "text", "selection": "ocr"}
    )
    assert ocr["coverage"] == "complete" and ocr["data"]["text"] == "inert text\n"
    assert len(calls) == 1


def test_wav_and_dicom_delegate_to_existing_bounded_passive_parsers(tmp_path):
    with wave.open(str(tmp_path / "sound.wav"), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(8000)
        output.writeframes(b"\x00\x00" * 8)
    (tmp_path / "image.dcm").write_bytes(_dicom_fixture())
    wav = inspect_artifact(Workspace(tmp_path), {"path": "sound.wav"})
    dicom = inspect_artifact(Workspace(tmp_path), {"path": "image.dcm", "view": "text"})
    assert wav["coverage"] == "complete" and wav["data"]["frames"] == 8
    assert dicom["coverage"] == "partial"
    assert any(row["value"] == "ALPHA^BETA" for row in dicom["data"]["tags"])
    assert "OMITTED" not in json.dumps(dicom)


@pytest.mark.parametrize("kind", ["wav", "dicom"])
def test_media_atomic_replacement_remains_bound_to_hashed_descriptor(tmp_path, monkeypatch, kind):
    path = tmp_path / f"source.{kind}"
    if kind == "wav":
        with wave.open(str(path), "wb") as output:
            output.setnchannels(1)
            output.setsampwidth(2)
            output.setframerate(8000)
            output.writeframes(b"\x00\x00" * 8)
        function_name = "wav_analyze_from_descriptor"
    else:
        path.write_bytes(_dicom_fixture())
        function_name = "dicom_metadata_from_descriptor"
    original_bytes = path.read_bytes()
    original = getattr(artifact_inspector, function_name)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"unrelated replacement")

    def replace_then_parse(descriptor, size, arguments):
        replacement.replace(path)
        return original(descriptor, size, arguments)

    monkeypatch.setattr(artifact_inspector, function_name, replace_then_parse)
    try:
        result = inspect_artifact(Workspace(tmp_path), {"path": path.name})
    except ToolError as error:
        assert error.code == "source_changed"
        return
    assert result["source_sha256"] == hashlib.sha256(original_bytes).hexdigest()
    assert result["source_bytes"] == len(original_bytes)
    assert (result["data"]["frames"] == 8) if kind == "wav" else (result["data"]["tag_count"] >= 2)


def test_media_in_place_change_after_hash_fails_source_changed(tmp_path, monkeypatch):
    path = tmp_path / "source.wav"
    with wave.open(str(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(8000)
        output.writeframes(b"\x00\x00" * 8)
    replacement = tmp_path / "new.wav"
    with wave.open(str(replacement), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(8000)
        output.writeframes(b"\x01\x00" * 8)
    replacement_bytes = replacement.read_bytes()
    original = artifact_inspector.wav_analyze_from_descriptor

    def mutate_then_parse(descriptor, size, arguments):
        path.write_bytes(replacement_bytes)
        return original(descriptor, size, arguments)

    monkeypatch.setattr(artifact_inspector, "wav_analyze_from_descriptor", mutate_then_parse)
    with pytest.raises(ToolError) as error:
        inspect_artifact(Workspace(tmp_path), {"path": path.name})
    assert error.value.code == "source_changed"


def test_unknown_binary_is_unsupported_but_bytes_and_fixed_strings_remain_available(tmp_path):
    (tmp_path / "blob").write_bytes(b"\x00\x01\x02VISIBLE_STRING\x00\xff")
    summary = inspect_artifact(Workspace(tmp_path), {"path": "blob"})
    text = inspect_artifact(Workspace(tmp_path), {"path": "blob", "view": "text"})
    raw = inspect_artifact(Workspace(tmp_path), {"path": "blob", "view": "bytes"})
    assert summary["coverage"] == "unsupported"
    assert text["data"]["strings"][0]["text"] == "VISIBLE_STRING"
    assert base64.b64decode(raw["data"]["data_base64"]) == (tmp_path / "blob").read_bytes()


def test_binary_string_crossing_scan_boundary_is_returned_whole_once(tmp_path, monkeypatch):
    monkeypatch.setattr(artifact_inspector, "MAX_SCAN_BYTES", 64)
    (tmp_path / "blob").write_bytes(b"\x00" * 60 + b"boundary")
    first = inspect_artifact(Workspace(tmp_path), {"path": "blob", "view": "text"})
    assert first["stop_reason"] == "string_boundary"
    assert first["data"]["strings"] == []
    second = inspect_artifact(
        Workspace(tmp_path),
        {"path": "blob", "view": "text", "cursor": first["next_cursor"]},
    )
    assert second["data"]["strings"] == [
        {
            "offset": 60,
            "encoding": "ascii",
            "text": "boundary",
            "truncated": False,
            "span_complete": True,
        }
    ]


def test_binary_string_record_pagination_keeps_earliest_overlapping_omission(tmp_path):
    prefix = (b"\xff\x00\x00\xff" * 100) + b"ABCDE\xff"
    overlapping = b"\x00A\x00B\x00C\x00D\x00\xff\xff"
    path = tmp_path / "overlapping-strings.bin"
    path.write_bytes(prefix + overlapping * 50)
    workspace = Workspace(tmp_path)
    first = isolated_inspect_artifact(workspace, {"path": path.name, "view": "text"})
    second = isolated_inspect_artifact(
        workspace,
        {"path": path.name, "view": "text", "cursor": first["next_cursor"]},
    )
    rows = first["data"]["strings"] + second["data"]["strings"]
    final_little_endian_offset = len(prefix) + 49 * len(overlapping) + 1
    assert first["coverage"] == "partial" and len(first["data"]["strings"]) == 100
    assert second["coverage"] == "complete"
    assert len(rows) == 101
    assert {
        "offset": final_little_endian_offset,
        "encoding": "utf-16-le",
        "text": "ABCD",
        "truncated": False,
        "span_complete": True,
    } in rows


def test_symlink_hardlink_special_file_and_traversal_are_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "link").symlink_to(outside)
    (root / "original").write_bytes(b"inside")
    os.link(root / "original", root / "hard")
    os.mkfifo(root / "pipe")
    workspace = Workspace(root)
    for path, expected in (
        ("link", "symlink_or_invalid_path"),
        ("hard", "symlink_or_invalid_path"),
        ("pipe", "not_a_file"),
        ("../outside", "path_outside_workspace"),
    ):
        with pytest.raises(ToolError) as error:
            inspect_artifact(workspace, {"path": path})
        assert error.value.code == expected


def test_source_byte_cap_precedes_content_scan(tmp_path):
    with (tmp_path / "sparse").open("wb") as output:
        output.truncate(MAX_SOURCE_BYTES + 1)
    with pytest.raises(ToolError) as error:
        inspect_artifact(Workspace(tmp_path), {"path": "sparse"})
    assert error.value.code == "input_too_large"


def test_summary_cursor_and_invalid_cursor_never_silently_restart(tmp_path):
    (tmp_path / "a").write_bytes(b"hello")
    workspace = Workspace(tmp_path)
    with pytest.raises(ToolError) as summary:
        inspect_artifact(workspace, {"path": "a", "cursor": "abc"})
    assert summary.value.code == "invalid_argument"
    with pytest.raises(ToolError) as invalid:
        inspect_artifact(workspace, {"path": "a", "view": "bytes", "cursor": "abc"})
    assert invalid.value.code == "invalid_cursor"


def test_no_interface_view_writes_workspace_content(tmp_path):
    (tmp_path / "plain.txt").write_text("bounded text")
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    workspace = Workspace(tmp_path)
    for view in ("summary", "text", "structure", "bytes"):
        inspect_artifact(workspace, {"path": "plain.txt", "view": view})
    after = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    assert after == before
