#!/usr/bin/env python3
"""Fast, offline acceptance check for the final Rapido tooling image.

This is intentionally a plain-Python runner: the production image does not need
pytest, credentials, a Board, challenge data, or network access.  It creates a
small set of inert files, exercises the model-visible registry plus the native
parsers, and emits one compact JSON document.  All generated files live below a
temporary directory which is removed before the process exits.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import importlib.metadata
import io
import json
import os
import platform
import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Any

PINNED_PARSERS = {
    "Pillow": ("PIL", "12.2.0"),
    "capstone": ("capstone", "5.0.9"),
    "dpkt": ("dpkt", "1.9.8"),
    "pefile": ("pefile", "2024.8.26"),
    "pypdf": ("pypdf", "6.18.1"),
}
EXPECTED_TOOLS = (
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
)
OUTPUT_LIMIT = 128 * 1024
NATIVE_PATHS = {
    "objdump": ("/usr/bin/objdump", "/usr/bin/llvm-objdump"),
    "readelf": ("/usr/bin/readelf", "/usr/bin/llvm-readelf"),
    "tesseract": ("/usr/bin/tesseract", "/usr/local/bin/tesseract"),
}


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, allow_nan=False, separators=(",", ":")).encode("utf-8")


def _assert_result(value: Any, label: str, *, coverage: bool = False) -> dict[str, Any]:
    """Check the common dynamic-tool output contract and return compact facts."""
    encoded = _json_bytes(value)
    if len(encoded) > OUTPUT_LIMIT:
        raise AssertionError(f"{label}: output is {len(encoded)} bytes")
    if not isinstance(value, dict):
        raise TypeError(f"{label}: result is not an object")
    if coverage:
        state = value.get("coverage")
        if state not in {"complete", "partial", "unsupported"}:
            raise AssertionError(f"{label}: missing or invalid coverage")
        if not isinstance(value.get("stop_reason"), str) or not value["stop_reason"]:
            raise AssertionError(f"{label}: missing stop_reason")
    return {"bytes": len(encoded), **({"coverage": value["coverage"]} if coverage else {})}


def _elf_fixture(
    code: bytes,
    *,
    bits: int,
    machine: int,
    entry: int = 0x1000,
) -> bytes:
    """Build a tiny inert ELF with a file-backed executable .text section."""
    header_size, section_size = (64, 64) if bits == 64 else (52, 40)
    header_format = "HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"
    section_format = "IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII"
    endian = "<"
    text_offset = 512
    names_offset = 128
    names = b"\x00.text\x00.shstrtab\x00"
    sections_offset = (text_offset + len(code) + 7) // 8 * 8
    ident = b"\x7fELF" + bytes((2 if bits == 64 else 1, 1, 1)) + b"\x00" * 9
    header = struct.pack(
        endian + header_format,
        2,
        machine,
        1,
        entry,
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
    if bits == 64:
        sections = (
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (1, 1, 6, entry, text_offset, len(code), 0, 0, 1, 0),
            (7, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
        )
    else:
        sections = (
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (1, 1, 6, entry, text_offset, len(code), 0, 0, 1, 0),
            (7, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
        )
    output = bytearray(max(sections_offset + section_size * 3, text_offset + len(code)))
    output[:16] = ident
    output[16 : 16 + len(header)] = header
    output[names_offset : names_offset + len(names)] = names
    output[text_offset : text_offset + len(code)] = code
    for index, section in enumerate(sections):
        start = sections_offset + index * section_size
        output[start : start + section_size] = struct.pack(endian + section_format, *section)
    return bytes(output)


def _png_fixture() -> bytes:
    """A 1x1 opaque black PNG, generated from fixed benign bytes."""
    import zlib

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
        + chunk(b"IEND", b"")
    )


def _bitplane_png_fixture() -> bytes:
    """A tiny RGBA PNG whose red bitplane zero spells ``AB``."""
    from PIL import Image

    bits = [bit for value in b"AB" for bit in ((value >> shift) & 1 for shift in range(7, -1, -1))]
    image = Image.new("RGBA", (len(bits), 1), (0, 0, 0, 255))
    image.putdata([(bit, 0, 0, 255) for bit in bits])
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    return stream.getvalue()


def _pdf_fixture() -> bytes:
    """Build one strict, text-bearing PDF without external files."""
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
        ),
        4: (
            b"<< /Length 51 >>\nstream\n"
            b"BT /F1 12 Tf 20 100 Td (offline PDF fixture) Tj ET\n"
            b"endstream"
        ),
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    result = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number in range(1, 6):
        offsets.append(len(result))
        result.extend(f"{number} 0 obj\n".encode("ascii"))
        result.extend(objects[number])
        result.extend(b"\nendobj\n")
    xref = len(result)
    result.extend(b"xref\n0 6\n0000000000 65535 f \n")
    result.extend(b"".join(f"{offset:010d} 00000 n \n".encode("ascii") for offset in offsets[1:]))
    result.extend(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return bytes(result)


def _pcap_fixture() -> bytes:
    """One deterministic Ethernet/IPv4/TCP packet in classic PCAP form."""
    payload = b"GET / HTTP/1.0\r\n"
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ip_total_length = 20 + 20 + len(payload)
    ipv4 = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_length,
        0,
        0x4000,
        64,
        6,
        0,
        bytes((192, 0, 2, 1)),
        bytes((198, 51, 100, 2)),
    )
    tcp = struct.pack(">HHIIHHHH", 1234, 80, 0, 0, 0x5018, 4096, 0, 0)
    packet = ethernet + ipv4 + tcp + payload
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 0, len(packet), len(packet))
        + packet
    )


def _pe_fixture() -> bytes:
    """A minimal PE32+ with a two-byte x86-64 executable entrypoint."""
    pe_offset = 0x80
    optional_size = 112
    section_offset = pe_offset + 24 + optional_size
    raw_offset = 0x200
    output = bytearray(raw_offset + 2)
    output[:2] = b"MZ"
    struct.pack_into("<I", output, 0x3C, pe_offset)
    output[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        output,
        pe_offset + 4,
        0x8664,
        1,
        0,
        0,
        0,
        optional_size,
        0x2022,
    )
    optional = pe_offset + 24
    struct.pack_into("<H", output, optional, 0x20B)
    struct.pack_into("<I", output, optional + 16, 0x1000)
    struct.pack_into("<Q", output, optional + 24, 0x140000000)
    output[section_offset : section_offset + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", output, section_offset + 8, 2, 0x1000, 2, raw_offset)
    struct.pack_into("<I", output, section_offset + 36, 0x60000020)
    output[raw_offset:] = b"\x90\xc3"
    return bytes(output)


def _wav_fixture() -> bytes:
    samples = bytes(0x80 + ((index % 4) * 2 - 3) for index in range(16))
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 8000, 1, 8)
    body = b"fmt " + struct.pack("<I", len(fmt)) + fmt
    body += b"data" + struct.pack("<I", len(samples)) + samples
    return b"RIFF" + struct.pack("<I", len(body) + 4) + b"WAVE" + body


def _dicom_element(group: int, element: int, vr: bytes, value: bytes) -> bytes:
    if len(value) % 2:
        value += b"\x00" if vr == b"UI" else b" "
    if vr in {b"OB", b"OW", b"OF", b"SQ", b"UT", b"UN"}:
        return struct.pack("<HH2s2xI", group, element, vr, len(value)) + value
    return struct.pack("<HH2sH", group, element, vr, len(value)) + value


def _dicom_fixture() -> bytes:
    transfer_syntax = _dicom_element(0x0002, 0x0010, b"UI", b"1.2.840.10008.1.2.1")
    meta = _dicom_element(0x0002, 0x0000, b"UL", struct.pack("<I", len(transfer_syntax)))
    dataset = b"".join(
        (
            _dicom_element(0x0008, 0x0060, b"CS", b"CT"),
            _dicom_element(0x0010, 0x0010, b"PN", b"OFFLINE^PATIENT"),
            _dicom_element(0x7FE0, 0x0010, b"OW", b"\x00\x01"),
        )
    )
    return b"\x00" * 128 + b"DICM" + meta + transfer_syntax + dataset


def _fixture_files(root: Path) -> None:
    (root / "notes.txt").write_bytes(b"offline tooling acceptance fixture\n")
    payload = b"benign derived payload\n"
    (root / "payload.b64").write_text(base64.b64encode(payload).decode("ascii"), encoding="ascii")
    (root / "payload.hex").write_text(payload.hex(), encoding="ascii")
    (root / "payload.url").write_text("benign%20derived%20payload%0A", encoding="ascii")
    (root / "archive.zip").write_bytes(_zip_bytes({"member.txt": b"inert archive member\n"}))
    (root / "x86_64.elf").write_bytes(_elf_fixture(b"\x90\xc3", bits=64, machine=62))
    (root / "arm.elf").write_bytes(
        _elf_fixture(bytes.fromhex("0100a0e31eff2fe1"), bits=32, machine=40)
    )
    (root / "aarch64.elf").write_bytes(
        _elf_fixture(bytes.fromhex("200080d2c0035fd6"), bits=64, machine=183)
    )
    (root / "tiny.png").write_bytes(_png_fixture())
    (root / "bitplane.png").write_bytes(_bitplane_png_fixture())
    (root / "fixture.pdf").write_bytes(_pdf_fixture())
    (root / "fixture.pcap").write_bytes(_pcap_fixture())
    (root / "fixture.exe").write_bytes(_pe_fixture())
    (root / "fixture.wav").write_bytes(_wav_fixture())
    (root / "fixture.dcm").write_bytes(_dicom_fixture())


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, value in members.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, value)
    return stream.getvalue()


def _parser_check() -> dict[str, Any]:
    observed: dict[str, Any] = {}
    for distribution, (module_name, expected) in PINNED_PARSERS.items():
        importlib.import_module(module_name)
        actual = importlib.metadata.version(distribution)
        if actual != expected:
            raise AssertionError(f"{distribution}: expected {expected}, got {actual}")
        observed[distribution] = {
            "version": actual,
            "import": module_name,
        }
    return observed


def _native_check() -> dict[str, Any]:
    selected: dict[str, str] = {}
    for name, candidates in NATIVE_PATHS.items():
        path = next((candidate for candidate in candidates if os.path.isfile(candidate)), None)
        if path is None or not os.access(path, os.X_OK):
            raise AssertionError(f"{name}: no fixed executable at {candidates}")
        selected[name] = path
    return selected


def _strict_schema(schema: Any) -> bool:
    if isinstance(schema, list):
        return all(_strict_schema(value) for value in schema)
    if not isinstance(schema, dict):
        return True
    if schema.get("type") == "object" and schema.get("additionalProperties") is not False:
        return False
    return all(_strict_schema(value) for value in schema.values())


def _registry_check(workspace: Any) -> tuple[Any, dict[str, Any]]:
    from rapido.tools import AGENT_TOOL_NAMES, ToolRegistry, tool_schemas

    if tuple(AGENT_TOOL_NAMES) != EXPECTED_TOOLS:
        raise AssertionError(f"model-visible names changed: {tuple(AGENT_TOOL_NAMES)!r}")
    registry = ToolRegistry(workspace)
    visible_specs = registry.dynamic_tools()
    visible = tuple(spec["name"] for spec in visible_specs)
    if visible != EXPECTED_TOOLS:
        raise AssertionError(f"registry names changed: {visible!r}")
    if any(not _strict_schema(spec.get("inputSchema", {})) for spec in visible_specs):
        raise AssertionError("model-visible schema is not strict")
    all_names = tuple(spec["name"] for spec in tool_schemas())
    if len(set(all_names)) != len(all_names) or not set(EXPECTED_TOOLS) <= set(all_names):
        raise AssertionError("tool schema registry is inconsistent")
    return registry, {
        "visible": list(visible),
        "schema_count": len(visible_specs),
        "schema_bytes": len(_json_bytes(visible_specs)),
        "all_schema_count": len(all_names),
        "all_schema_bytes": len(_json_bytes(tool_schemas())),
    }


def _operations(registry: Any, root: Path) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    inspect = registry.dispatch("inspect_artifact", {"path": "notes.txt", "view": "text"})
    checks["artifact_text"] = _assert_result(inspect, "artifact_text", coverage=True)
    if inspect["format"] != "text" or "offline tooling" not in inspect["data"].get("text", ""):
        raise AssertionError("artifact text view did not read the inert fixture")
    archive = registry.dispatch("inspect_artifact", {"path": "archive.zip", "view": "structure"})
    checks["artifact_archive"] = _assert_result(archive, "artifact_archive", coverage=True)
    if archive["format"] != "zip" or archive["data"].get("entry_count") != 1:
        raise AssertionError("artifact archive view did not inventory the inert fixture")

    pdf = registry.dispatch("inspect_artifact", {"path": "fixture.pdf", "view": "text"})
    checks["artifact_pdf"] = _assert_result(pdf, "artifact_pdf", coverage=True)
    pdf_data = pdf.get("data", {})
    if (
        pdf["format"] != "pdf"
        or pdf["coverage"] != "complete"
        or pdf_data.get("page_count") != 1
        or "offline PDF fixture" not in pdf_data.get("pages", [{}])[0].get("text", "")
    ):
        raise AssertionError("PDF worker did not extract the expected one-page text")

    pcap = registry.dispatch(
        "inspect_artifact", {"path": "fixture.pcap", "view": "text", "selection": "packets"}
    )
    checks["artifact_pcap"] = _assert_result(pcap, "artifact_pcap", coverage=True)
    packets = pcap.get("data", {}).get("packets", [])
    if (
        pcap["format"] != "pcap"
        or pcap["coverage"] != "complete"
        or len(packets) != 1
        or packets[0].get("ip_source") != "192.0.2.1"
        or packets[0].get("destination_port") != 80
    ):
        raise AssertionError("PCAP worker did not decode the expected TCP packet")

    pe = registry.dispatch(
        "inspect_artifact", {"path": "fixture.exe", "view": "text", "selection": "disassembly"}
    )
    checks["artifact_pe"] = _assert_result(pe, "artifact_pe", coverage=True)
    pe_data = pe.get("data", {})
    if (
        pe["format"] != "pe"
        or pe_data.get("decoder") != "capstone"
        or pe_data.get("architecture") != "x86"
        or pe_data.get("instruction_count", 0) < 2
    ):
        raise AssertionError("PE worker did not decode the expected x86 entrypoint")

    bitplane = registry.dispatch(
        "inspect_artifact",
        {"path": "bitplane.png", "view": "structure", "selection": "bitplane:R:0"},
    )
    checks["artifact_image_bitplane"] = _assert_result(
        bitplane, "artifact_image_bitplane", coverage=True
    )
    plane = bitplane.get("data", {}).get("pixel_signals", {})
    previews = plane.get("signals", {}).get("previews", [])
    if (
        bitplane["format"] != "png"
        or plane.get("channel") != "R"
        or plane.get("bitplane") != 0
        or plane.get("pixel_count") != 16
        or not previews
        or base64.b64decode(previews[0]["data_base64"]) != b"AB"
    ):
        raise AssertionError("image worker did not expose the expected red bitplane")

    wav = registry.dispatch("inspect_artifact", {"path": "fixture.wav", "view": "summary"})
    checks["artifact_wav"] = _assert_result(wav, "artifact_wav", coverage=True)
    wav_data = wav.get("data", {})
    if (
        wav["format"] != "wav"
        or wav["coverage"] != "complete"
        or wav_data.get("encoding") != "integer_pcm"
        or wav_data.get("channels") != 1
        or wav_data.get("sample_rate") != 8000
        or wav_data.get("bits_per_sample") != 8
        or wav_data.get("frames") != 16
    ):
        raise AssertionError("WAV production path did not report the expected PCM metadata")

    dicom = registry.dispatch(
        "inspect_artifact", {"path": "fixture.dcm", "view": "structure", "selection": "metadata"}
    )
    checks["artifact_dicom"] = _assert_result(dicom, "artifact_dicom", coverage=True)
    dicom_data = dicom.get("data", {})
    if (
        dicom["format"] != "dicom"
        or dicom_data.get("format") != "dicom"
        or dicom_data.get("transfer_syntax_uid") != "1.2.840.10008.1.2.1"
        or not dicom_data.get("pixel_data_omitted")
        or dicom.get("stop_reason") != "pixel_data"
    ):
        raise AssertionError("DICOM production path did not stop before pixel data")

    derived = registry.dispatch("derive_artifact", {"path": "payload.b64", "encoding": "base64"})
    checks["derive"] = _assert_result(derived, "derive")
    expected_digest = hashlib.sha256(b"benign derived payload\n").hexdigest()
    if derived.get("sha256") != expected_digest or not (root / derived["path"]).is_file():
        raise AssertionError("derive did not publish the expected content-addressed payload")

    exact = registry.dispatch(
        "compute_exact",
        {"operation": "mod_pow", "base": "7", "exponent": "5", "modulus": "13"},
    )
    checks["exact"] = _assert_result(exact, "exact")
    if exact.get("result") != "11":
        raise AssertionError("exact arithmetic result mismatch")

    capstone_architectures = {
        "x86_64.elf": "x86",
        "arm.elf": "arm",
        "aarch64.elf": "aarch64",
    }
    for filename, architecture in capstone_architectures.items():
        result = registry.dispatch(
            "inspect_artifact",
            {"path": filename, "view": "text", "selection": "disassembly"},
        )
        checks[f"capstone_{architecture}"] = _assert_result(
            result, f"capstone_{architecture}", coverage=True
        )
        data = result.get("data", {})
        if result["coverage"] == "unsupported" or data.get("decoder") != "capstone":
            raise AssertionError(f"{architecture}: Capstone did not provide disassembly")
        if data.get("architecture") != architecture or data.get("instruction_count", 0) < 1:
            raise AssertionError(f"{architecture}: disassembly metadata is incomplete")

    # These are deliberately hidden compatibility operations; the model only sees
    # inspect_artifact for disassembly.  They prove the fixed objdump/readelf path
    # remains usable in the final image without executing the fixture.
    native_file = (
        "aarch64.elf" if platform.machine().lower() in {"aarch64", "arm64"} else "x86_64.elf"
    )
    symbols = registry.dispatch("elf_symbols", {"path": native_file})
    checks["fixed_readelf"] = _assert_result(symbols, "fixed_readelf")
    if symbols.get("status") != "ok" or symbols.get("command") not in {"readelf", "llvm-readelf"}:
        raise AssertionError("fixed readelf smoke test failed")
    native_disassembly = registry.dispatch(
        "disassemble_elf", {"path": native_file, "byte_count": 2}
    )
    checks["fixed_objdump"] = _assert_result(native_disassembly, "fixed_objdump")
    if native_disassembly.get("status") != "ok" or native_disassembly.get("command") not in {
        "objdump",
        "llvm-objdump",
    }:
        raise AssertionError("fixed objdump smoke test failed")

    ocr = registry.dispatch(
        "inspect_artifact", {"path": "tiny.png", "view": "text", "selection": "ocr"}
    )
    checks["fixed_tesseract"] = _assert_result(ocr, "fixed_tesseract", coverage=True)
    if ocr["coverage"] == "unsupported" or ocr.get("data", {}).get("inspector") != "tesseract":
        raise AssertionError("fixed tesseract smoke test failed")
    return checks


def _workspace_check(root: Path, workspace: Any, before: set[str]) -> dict[str, Any]:
    entries, total_bytes = workspace.snapshot()
    expected_new = {
        "derived",
        "derived/" + hashlib.sha256(b"benign derived payload\n").hexdigest() + ".bin",
    }
    if entries - before != expected_new:
        raise AssertionError(f"unexpected workspace entries: {sorted(entries - before)!r}")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise AssertionError("fixture workspace contains a symlink")
    # The harness has no worker pool or live subprocess left at this point.  On
    # Linux, make the absence explicit; other hosts report the check as n/a.
    children: list[str] = []
    proc = Path("/proc")
    if proc.is_dir():
        for item in proc.iterdir():
            if not item.name.isdigit():
                continue
            try:
                fields = (item / "stat").read_text(encoding="ascii").split()
                if int(fields[3]) == os.getpid():
                    children.append(item.name)
            except (OSError, ValueError, IndexError):
                continue
    if children:
        raise AssertionError(f"child processes remain: {children!r}")
    return {"entries": len(entries), "bytes": total_bytes, "child_processes": len(children)}


def _fd_count() -> int | None:
    for candidate in (Path("/proc/self/fd"), Path("/dev/fd")):
        if candidate.is_dir():
            try:
                return len(list(candidate.iterdir()))
            except OSError:
                return None
    return None


def run() -> dict[str, Any]:
    parser_versions = _parser_check()
    native = _native_check()
    with tempfile.TemporaryDirectory(prefix="rapido-tooling-") as temporary:
        root = Path(temporary)
        _fixture_files(root)
        from rapido.tools import Workspace

        workspace = Workspace(root)
        before, _ = workspace.snapshot()
        fds_before = _fd_count()
        registry, registry_facts = _registry_check(workspace)
        operation_facts = _operations(registry, root)
        workspace_facts = _workspace_check(root, workspace, before)
        fds_after = _fd_count()
        if fds_before is not None and fds_after != fds_before:
            raise AssertionError(f"file descriptors leaked: {fds_before} -> {fds_after}")
        workspace_facts.update({"open_fds_before": fds_before, "open_fds_after": fds_after})
    if root.exists():
        raise AssertionError("temporary fixture directory was not removed")
    return {
        "ok": True,
        "offline": True,
        "network": "not_used",
        "auth": "not_used",
        "board": "not_used",
        "live_solver": "not_used",
        "execution": {
            "inference": False,
            "model": None,
            "reasoning_effort": None,
            "note": "deterministic fixture harness; no model inference is performed",
        },
        "parsers": parser_versions,
        "fixed_executables": native,
        "registry": registry_facts,
        "operations": operation_facts,
        "cleanup": workspace_facts | {"temporary_directory_removed": True},
    }


def main() -> int:
    try:
        result = run()
    except Exception as exc:  # noqa: BLE001  # Keep stdout one compact JSON record.
        result = {
            "ok": False,
            "offline": True,
            "execution": {
                "inference": False,
                "model": None,
                "reasoning_effort": None,
                "note": "deterministic fixture harness; no model inference is performed",
            },
            "error": {"type": type(exc).__name__, "message": str(exc)[:240]},
        }
    print(_json_bytes(result).decode("utf-8"))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
