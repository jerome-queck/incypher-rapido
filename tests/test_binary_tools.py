from __future__ import annotations

import json
import os
import struct
import sys
import time

import pytest

from rapido import binary_tools
from rapido.tools import ToolError, ToolRegistry, Workspace, call_tool


def elf_fixture(
    bits: int = 64, byte_order: str = "<", *, extended: bool = False, name_padding: int = 0
) -> bytes:
    """Minimal inert ELF containing .text and its section-name table."""
    header_size, section_size = (64, 64) if bits == 64 else (52, 40)
    text = b"\x90\x90\x90\xc3"
    names = b"\x00.text\x00.shstrtab\x00" + b"x" * name_padding
    names_offset = header_size + len(text)
    sections_offset = (names_offset + len(names) + 7) // 8 * 8
    ident = (
        b"\x7fELF" + bytes((2 if bits == 64 else 1, 1 if byte_order == "<" else 2, 1)) + b"\x00" * 9
    )
    header_format = "HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"
    header = struct.pack(
        byte_order + header_format,
        2,
        62 if bits == 64 else 3,
        1,
        0x1000,
        0,
        sections_offset,
        0,
        header_size,
        0,
        0,
        section_size,
        0 if extended else 3,
        0xFFFF if extended else 2,
    )
    section_format = "IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII"
    sections = (
        (0, 0, 0, 0, 0, 3 if extended else 0, 2 if extended else 0, 0, 0, 0),
        (1, 1, 6, 0x1000, header_size, len(text), 0, 0, 1, 0),
        (7, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
    )
    prefix = ident + header + text + names
    return prefix.ljust(sections_offset, b"\x00") + b"".join(
        struct.pack(byte_order + section_format, *section) for section in sections
    )


@pytest.mark.parametrize("bits,byte_order", [(32, "<"), (32, ">"), (64, "<"), (64, ">")])
def test_pure_metadata_reads_both_elf_classes_and_byte_orders(
    tmp_path, monkeypatch, bits, byte_order
):
    (tmp_path / "input.elf").write_bytes(elf_fixture(bits, byte_order))
    monkeypatch.setattr(binary_tools.subprocess, "Popen", lambda *a, **k: pytest.fail("not pure"))
    result = binary_tools.inspect_elf(Workspace(tmp_path), {"path": "input.elf"})
    assert result["class_bits"] == bits
    assert result["byte_order"] == ("little" if byte_order == "<" else "big")
    assert result["entry_address"] == "0x1000"
    assert result["section_count"] == 3
    assert [section["name"] for section in result["sections"]] == ["", ".text", ".shstrtab"]
    assert result["sections"][1]["executable"] is True
    assert result["next_section_offset"] is None
    json.dumps(result)


def test_extended_section_numbering_and_bounded_pagination(tmp_path):
    (tmp_path / "input.elf").write_bytes(elf_fixture(extended=True))
    workspace = Workspace(tmp_path)
    first = binary_tools.inspect_elf(workspace, {"path": "input.elf", "max_sections": 1})
    assert first["section_count"] == 3
    assert len(first["sections"]) == 1
    assert first["next_section_offset"] == 1
    last = binary_tools.inspect_elf(workspace, {"path": "input.elf", "section_offset": 2})
    assert last["sections"][0]["name"] == ".shstrtab"
    assert last["next_section_offset"] is None


@pytest.mark.parametrize(
    "path", ["../outside", "nested/../../outside", "/etc/passwd", "C:\\outside", "..\\outside"]
)
def test_refuses_paths_outside_workspace(tmp_path, path):
    with pytest.raises(ToolError) as error:
        binary_tools.inspect_elf(Workspace(tmp_path), {"path": path})
    assert error.value.code == "path_outside_workspace"


@pytest.mark.parametrize(
    "operation", [binary_tools.inspect_elf, binary_tools.elf_symbols, binary_tools.disassemble_elf]
)
def test_every_operation_refuses_symlink_components(tmp_path, operation):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "input.elf").write_bytes(elf_fixture())
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    (root / "leaf").symlink_to(outside / "input.elf")
    for path in ("link/input.elf", "leaf"):
        with pytest.raises(ToolError) as error:
            operation(Workspace(root), {"path": path})
        assert error.value.code == "symlink_or_invalid_path"


def test_refuses_nonregular_and_multiply_linked_inputs(tmp_path):
    workspace = Workspace(tmp_path)
    (tmp_path / "folder").mkdir()
    os.mkfifo(tmp_path / "fifo")
    for path in ("folder", "fifo"):
        with pytest.raises(ToolError) as error:
            binary_tools.inspect_elf(workspace, {"path": path})
        assert error.value.code == "not_a_file"
    (tmp_path / "input.elf").write_bytes(elf_fixture())
    os.link(tmp_path / "input.elf", tmp_path / "hardlink")
    with pytest.raises(ToolError, match="multiply linked"):
        binary_tools.inspect_elf(workspace, {"path": "hardlink"})


@pytest.mark.parametrize(
    "data,code",
    [
        (b"x" * 64, "unsupported_format"),
        (b"\x7fELF", "invalid_elf"),
        (elf_fixture()[:-1], "invalid_elf"),
    ],
)
def test_rejects_unknown_and_truncated_inputs(tmp_path, data, code):
    (tmp_path / "input").write_bytes(data)
    with pytest.raises(ToolError) as error:
        binary_tools.inspect_elf(Workspace(tmp_path), {"path": "input"})
    assert error.value.code == code


def test_rejects_oversized_input_without_reading_it(tmp_path, monkeypatch):
    (tmp_path / "input.elf").write_bytes(elf_fixture())
    monkeypatch.setattr(binary_tools, "MAX_BINARY_BYTES", 10)
    with pytest.raises(ToolError) as error:
        binary_tools.inspect_elf(Workspace(tmp_path), {"path": "input.elf"})
    assert error.value.code == "input_too_large"


def test_rejects_oversized_section_names_before_reading_table(tmp_path):
    (tmp_path / "input.elf").write_bytes(
        elf_fixture(name_padding=binary_tools.MAX_STRING_TABLE_BYTES)
    )
    with pytest.raises(ToolError) as error:
        binary_tools.inspect_elf(Workspace(tmp_path), {"path": "input.elf"})
    assert error.value.code == "limit_exceeded"


@pytest.mark.parametrize(
    "operation,extra",
    [
        (binary_tools.inspect_elf, {"max_sections": 129}),
        (binary_tools.inspect_elf, {"section_offset": True}),
        (binary_tools.elf_symbols, {"dynamic": "yes"}),
        (binary_tools.elf_symbols, {"argv": ["--help"]}),
        (binary_tools.disassemble_elf, {"byte_count": 4097}),
        (binary_tools.disassemble_elf, {"start_address": "0x1000; whoami"}),
        (binary_tools.disassemble_elf, {"start_address": (1 << 64) - 1}),
        (binary_tools.disassemble_elf, {"section": ".text --source"}),
    ],
)
def test_invalid_parameters_never_start_an_inspector(tmp_path, monkeypatch, operation, extra):
    (tmp_path / "input.elf").write_bytes(elf_fixture())
    monkeypatch.setattr(binary_tools.subprocess, "Popen", lambda *a, **k: pytest.fail("spawned"))
    with pytest.raises(ToolError) as error:
        operation(Workspace(tmp_path), {"path": "input.elf", **extra})
    assert error.value.code == "invalid_argument"


def test_fixed_symbol_command_uses_original_descriptor_after_filename_swap(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    original = root / "-binary;echo nope"
    original.write_bytes(elf_fixture())
    outside = tmp_path / "outside"
    outside.write_bytes(b"OUTSIDE SENTINEL")
    monkeypatch.setattr(binary_tools.shutil, "which", lambda name, path: f"/usr/bin/{name}")

    def run(argv, descriptor, **kwargs):
        if argv[-1] == "--version":
            return {"status": "ok", "stdout": "GNU readelf", "stderr": ""}
        assert argv[:-1] == [
            "/usr/bin/readelf",
            "--debug-dump=no-follow-links",
            "--debug-dump=do-not-use-debuginfod",
            "--wide",
            "--dyn-syms",
        ]
        assert argv[-1] == f"/dev/fd/{descriptor}"
        original.unlink()
        original.symlink_to(outside)
        assert os.pread(descriptor, 4, 0) == b"\x7fELF"
        return {
            "status": "ok",
            "stdout": argv[-1],
            "stderr": "",
            "returncode": 0,
            "truncated": False,
            "timed_out": False,
        }

    monkeypatch.setattr(binary_tools, "_run_command", run)
    result = binary_tools.elf_symbols(Workspace(root), {"path": original.name, "dynamic": True})
    assert result["stdout"] == "[workspace binary]"
    assert "OUTSIDE SENTINEL" not in json.dumps(result)


def test_disassembly_options_bound_addresses_and_one_section(tmp_path, monkeypatch):
    (tmp_path / "input.elf").write_bytes(elf_fixture())
    monkeypatch.setattr(binary_tools.shutil, "which", lambda name, path: f"/usr/bin/{name}")
    calls = []

    def run(argv, descriptor, **kwargs):
        if argv[-1] == "--version":
            return {"status": "ok", "stdout": "GNU objdump", "stderr": ""}
        calls.append(argv)
        assert os.pread(descriptor, 4, 0) == b"\x7fELF"
        return {"status": "ok", "stdout": "nop", "stderr": ""}

    monkeypatch.setattr(binary_tools, "_run_command", run)
    result = binary_tools.disassemble_elf(
        Workspace(tmp_path), {"path": "input.elf", "start_address": "0x1001", "byte_count": 2}
    )
    assert calls[0][:-1] == [
        "/usr/bin/objdump",
        "--dwarf=no-follow-links",
        "--dwarf=do-not-use-debuginfod",
        "--disassemble",
        "--section=.text",
        "--start-address=0x1001",
        "--stop-address=0x1003",
    ]
    assert result["stop_address"] == "0x1003"


def test_missing_binutils_is_reported_without_fallback_execution(tmp_path, monkeypatch):
    (tmp_path / "input.elf").write_bytes(elf_fixture())
    monkeypatch.setattr(binary_tools.shutil, "which", lambda *a, **k: None)
    for operation in (binary_tools.elf_symbols, binary_tools.disassemble_elf):
        assert operation(Workspace(tmp_path), {"path": "input.elf"})["status"] == "unavailable"


def test_unknown_inspector_policy_refuses_artifact_inspection(tmp_path, monkeypatch):
    (tmp_path / "input.elf").write_bytes(elf_fixture())
    monkeypatch.setattr(binary_tools.shutil, "which", lambda name, path: f"/usr/bin/{name}")
    calls = []

    def run(argv, descriptor, **kwargs):
        calls.append(argv)
        return {"status": "ok", "stdout": "unknown implementation", "stderr": ""}

    monkeypatch.setattr(binary_tools, "_run_command", run)
    result = binary_tools.disassemble_elf(Workspace(tmp_path), {"path": "input.elf"})
    assert result["status"] == "unsupported_tool"
    assert calls == [["/usr/bin/objdump", "--version"]]


def test_expired_shared_command_budget_does_not_spawn(tmp_path, monkeypatch):
    monkeypatch.setattr(binary_tools.subprocess, "Popen", lambda *a, **k: pytest.fail("spawned"))
    (tmp_path / "input.elf").write_bytes(elf_fixture())
    with binary_tools._input(Workspace(tmp_path), "input.elf") as (descriptor, _):
        result = binary_tools._run_command(
            ["/usr/bin/objdump", "--version"], descriptor, deadline=0
        )
    assert result["status"] == "timeout"


def test_runner_uses_bounded_combined_capture_and_clean_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("BINARY_TEST_SECRET", "synthetic sentinel")
    path = tmp_path / "input.elf"
    path.write_bytes(elf_fixture())
    script = "import os,sys; assert 'BINARY_TEST_SECRET' not in os.environ; sys.stdout.buffer.write(b'x'*1000000)"
    with binary_tools._input(Workspace(tmp_path), path.name) as (descriptor, _):
        result = binary_tools._run_command([sys.executable, "-c", script], descriptor)
    assert result["status"] == "output_limit"
    assert result["truncated"] is True
    assert len(result["stdout"]) + len(result["stderr"]) <= binary_tools.MAX_COMMAND_OUTPUT_BYTES


def test_runner_times_out_even_after_child_closes_output_pipes(tmp_path, monkeypatch):
    monkeypatch.setattr(binary_tools, "COMMAND_TIMEOUT_SECONDS", 0.15)
    path = tmp_path / "input.elf"
    path.write_bytes(elf_fixture())
    started = time.monotonic()
    with binary_tools._input(Workspace(tmp_path), path.name) as (descriptor, _):
        result = binary_tools._run_command(
            [sys.executable, "-c", "import os,time; os.close(1); os.close(2); time.sleep(30)"],
            descriptor,
        )
    assert result["timed_out"] is True
    assert result["status"] == "timeout"
    assert time.monotonic() - started < 2


def test_real_installed_objdump_reads_inert_elf(tmp_path):
    if not any(
        binary_tools.shutil.which(name, path="/usr/bin:/bin")
        for name in ("objdump", "llvm-objdump")
    ):
        pytest.skip("no fixed-path objdump is installed")
    (tmp_path / "input.elf").write_bytes(elf_fixture())
    result = binary_tools.disassemble_elf(
        Workspace(tmp_path), {"path": "input.elf", "byte_count": 4}
    )
    assert result["status"] == "ok", result
    assert "nop" in result["stdout"]
    assert result["timed_out"] is False


def test_specs_expose_only_fixed_operations_and_reject_extra_properties():
    specs = binary_tools.binary_tool_specs()
    assert {spec["name"] for spec in specs} == {"inspect_elf", "elf_symbols", "disassemble_elf"}
    assert all(spec["inputSchema"]["additionalProperties"] is False for spec in specs)
    assert all(spec["inputSchema"]["required"] == ["path"] for spec in specs)
    json.dumps(specs)


def test_binary_tools_are_registered_for_native_model_dispatch(tmp_path):
    (tmp_path / "input.elf").write_bytes(elf_fixture())
    workspace = Workspace(tmp_path)
    names = {spec["name"] for spec in ToolRegistry(workspace).dynamic_tools()}
    assert {"inspect_elf", "elf_symbols", "disassemble_elf"} <= names
    assert call_tool(workspace, "inspect_elf", {"path": "input.elf"})["format"] == "elf"
