from __future__ import annotations

import base64
import gzip
import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock

from rapido.tools import (
    AGENT_TOOL_NAMES,
    MAX_ARCHIVE_ENTRIES,
    MAX_COMMAND_OUTPUT_BYTES,
    MAX_SCAN_BYTES,
    MAX_WORKSPACE_ENTRIES,
    ToolError,
    ToolRegistry,
    Workspace,
    _run_bounded_command,
    call_tool,
)


class ToolFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.workspace = Workspace(self.root)
        (self.root / "note.txt").write_text("alpha\nneedle here\n", encoding="utf-8")
        (self.root / "blob.bin").write_bytes(b"\x00hello world\x00needle\x00")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def assertToolError(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(ToolError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_list_read_search_hash_and_strings(self) -> None:
        listed = call_tool(self.workspace, "list_workspace", {"recursive": True})
        self.assertEqual({entry["path"] for entry in listed["entries"]}, {"blob.bin", "note.txt"})
        self.assertEqual(
            call_tool(self.workspace, "read_text", {"path": "note.txt"})["text"],
            "alpha\nneedle here\n",
        )
        self.assertEqual(
            len(
                call_tool(self.workspace, "read_bytes", {"path": "blob.bin", "length": 5})[
                    "data_base64"
                ]
            ),
            8,
        )
        self.assertEqual(
            len(
                call_tool(self.workspace, "search_text", {"path": "note.txt", "query": "needle"})[
                    "matches"
                ]
            ),
            1,
        )
        self.assertTrue(
            call_tool(self.workspace, "extract_strings", {"path": "blob.bin"})["strings"]
        )
        digest = call_tool(self.workspace, "inspect_file", {"path": "note.txt"})["hashes"]["sha256"]
        self.assertEqual(len(digest), 64)

    def test_dynamic_registry_is_workspace_bound(self) -> None:
        registry = ToolRegistry(self.workspace)
        specs = {spec["name"]: spec for spec in registry.dynamic_tool_specs}
        names = set(specs)
        self.assertEqual(names, set(AGENT_TOOL_NAMES))
        self.assertIn("inspect_artifact", names)
        self.assertNotIn("inspect_file", names)
        self.assertEqual(specs["search_text"]["inputSchema"]["required"], ["path", "query"])
        self.assertEqual(
            specs["decompress_gzip"]["inputSchema"]["required"], ["path", "destination"]
        )
        self.assertEqual(
            specs["decode_hex"]["inputSchema"]["oneOf"],
            [{"required": ["data"]}, {"required": ["path"]}],
        )
        self.assertEqual(
            specs["run_shell"]["inputSchema"]["required"],
            ["command", "source_paths"],
        )
        filesystem_schema = specs["inspect_filesystem"]["inputSchema"]
        self.assertEqual(filesystem_schema["required"], ["path"])
        self.assertEqual(filesystem_schema["oneOf"][1]["required"], ["action", "filesystem_path"])
        self.assertEqual(
            filesystem_schema["properties"]["filesystem_path"]["pattern"],
            r"^/(?:[A-Za-z0-9._+@,:=-]+/?)*$",
        )
        self.assertEqual(registry.dispatch("hash", {"path": "note.txt"})["path"], "note.txt")

    def test_validation_error_has_bounded_structural_attribution(self) -> None:
        with self.assertRaises(ToolError) as caught:
            call_tool(self.workspace, "read_text", {"path": 7})
        self.assertEqual(
            caught.exception.details,
            {
                "schema_version": 1,
                "contract_version": 1,
                "failure_stage": "arguments",
                "constraint": "type",
                "field_path": "path",
                "actual_kind": "integer",
            },
        )

        with self.assertRaises(ToolError) as invalid_unicode:
            call_tool(self.workspace, "read_text", {"path": "bad-\ud800"})
        self.assertEqual(invalid_unicode.exception.details["field_path"], "path")
        self.assertEqual(invalid_unicode.exception.details["constraint"], "unicode")

    def test_filesystem_path_grammar_is_discoverable_and_closed(self) -> None:
        with self.assertRaises(ToolError) as caught:
            call_tool(
                self.workspace,
                "inspect_filesystem",
                {"path": "note.txt", "action": "list", "filesystem_path": "relative path"},
            )
        self.assertEqual(caught.exception.code, "invalid_argument")
        self.assertEqual(caught.exception.details["field_path"], "filesystem_path")
        self.assertEqual(caught.exception.details["constraint"], "path_grammar")
        self.assertEqual(caught.exception.details["allowed_values"], ["strict_absolute_path"])

    def test_shell_binds_command_to_hashed_challenge_sources(self) -> None:
        worker_result = {
            "returncode": 0,
            "stdout": "derived value\n",
            "stderr": "",
            "stop_reason": None,
            "sandbox": {"enforced": True, "network": "denied"},
            "cwd": "rapido-analysis",
        }
        with mock.patch(
            "rapido.analysis_worker.run_analysis_worker", return_value=worker_result
        ) as worker:
            result = call_tool(
                self.workspace,
                "run_shell",
                {
                    "command": "python -c 'print(1)'",
                    "source_paths": ["note.txt", "note.txt"],
                    "timeout_seconds": 17,
                },
            )
        worker.assert_called_once_with(self.workspace.root, "python -c 'print(1)'", 17)
        self.assertEqual(result["stdout"], "derived value\n")
        self.assertEqual(result["analysis_directory"], "rapido-analysis")
        self.assertEqual(result["sources"][0]["path"], "note.txt")
        self.assertEqual(len(result["sources"]), 1)
        self.assertEqual(len(result["sources"][0]["sha256"]), 64)
        self.assertEqual(len(result["command_sha256"]), 64)

    def test_shell_rejects_missing_or_analysis_only_sources(self) -> None:
        for source_paths in (None, [], ["rapido-analysis/generated.py"]):
            arguments = {"command": "true"}
            if source_paths is not None:
                arguments["source_paths"] = source_paths
            self.assertToolError(
                "invalid_argument",
                call_tool,
                self.workspace,
                "run_shell",
                arguments,
            )

    def test_shell_registry_removes_new_entries_after_quota_failure(self) -> None:
        _, current = self.workspace.snapshot()

        def write_large_output(root: Path, _command: str, _timeout: int) -> dict[str, Any]:
            analysis = root / "rapido-analysis"
            analysis.mkdir()
            (analysis / "large.bin").write_bytes(b"x" * 16)
            return {"returncode": 0, "stdout": "", "stderr": "", "stop_reason": None}

        registry = ToolRegistry(self.workspace, max_workspace_bytes=current + 8)
        with mock.patch(
            "rapido.analysis_worker.run_analysis_worker", side_effect=write_large_output
        ):
            self.assertToolError(
                "workspace_quota",
                registry.dispatch,
                "run_shell",
                {"command": "produce", "source_paths": ["note.txt"]},
            )
        self.assertFalse((self.root / "rapido-analysis").exists())

    def test_shell_registry_removes_over_entry_limit_without_resnapshot(self) -> None:
        def write_many(root: Path, _command: str, _timeout: int) -> dict[str, Any]:
            analysis = root / "rapido-analysis"
            analysis.mkdir()
            for index in range(MAX_WORKSPACE_ENTRIES + 1):
                (analysis / str(index)).touch()
            return {"returncode": 0, "stdout": "", "stderr": "", "stop_reason": None}

        registry = ToolRegistry(self.workspace)
        with mock.patch("rapido.analysis_worker.run_analysis_worker", side_effect=write_many):
            self.assertToolError(
                "workspace_quota",
                registry.dispatch,
                "run_shell",
                {"command": "produce", "source_paths": ["note.txt"]},
            )
        self.assertFalse((self.root / "rapido-analysis").exists())

    def test_shell_registry_truncates_existing_file_after_byte_quota_failure(self) -> None:
        analysis = self.root / "rapido-analysis"
        analysis.mkdir()
        retained = analysis / "retained.txt"
        retained.write_bytes(b"old")
        _, current = self.workspace.snapshot()

        def enlarge(root: Path, _command: str, _timeout: int) -> dict[str, Any]:
            (root / "rapido-analysis/retained.txt").write_bytes(b"old" + b"x" * 16)
            return {"returncode": 0, "stdout": "", "stderr": "", "stop_reason": None}

        registry = ToolRegistry(self.workspace, max_workspace_bytes=current + 8)
        with mock.patch("rapido.analysis_worker.run_analysis_worker", side_effect=enlarge):
            self.assertToolError(
                "workspace_quota",
                registry.dispatch,
                "run_shell",
                {"command": "produce", "source_paths": ["note.txt"]},
            )
        self.assertEqual(retained.read_bytes(), b"old")

    def test_large_files_use_ranges_streaming_hashes_and_bounded_scans(self) -> None:
        path = self.root / "large.bin"
        with path.open("wb") as handle:
            handle.seek(MAX_SCAN_BYTES)
            handle.write(b"tail")
        result = call_tool(
            self.workspace,
            "read_bytes",
            {"path": "large.bin", "offset": MAX_SCAN_BYTES, "length": 4},
        )
        self.assertEqual(base64.b64decode(result["data_base64"]), b"tail")
        self.assertEqual(
            len(call_tool(self.workspace, "hash", {"path": "large.bin"})["hashes"]["sha256"]), 64
        )
        scan = call_tool(self.workspace, "strings", {"path": "large.bin"})
        self.assertEqual(scan["scanned_bytes"], MAX_SCAN_BYTES)
        self.assertTrue(scan["truncated"])

    def test_traversal_absolute_and_symlink_are_rejected(self) -> None:
        outside = self.root.parent / (self.root.name + "-outside")
        outside.write_text("secret", encoding="utf-8")
        try:
            self.assertToolError("path_outside_workspace", self.workspace.path, "../secret")
            self.assertToolError("path_outside_workspace", self.workspace.path, str(outside))
            link = self.root / "link"
            link.symlink_to(outside)
            self.assertToolError("symlink_or_invalid_path", self.workspace.path, "link")
            self.assertNotIn(
                "link",
                {
                    entry["path"]
                    for entry in call_tool(self.workspace, "list_workspace", {})["entries"]
                },
            )
        finally:
            outside.unlink(missing_ok=True)

    def test_decoders_are_bounded_and_binary_safe(self) -> None:
        decoded = call_tool(
            self.workspace, "decode_base64", {"data": base64.b64encode(b"hello\x00").decode()}
        )
        self.assertEqual(decoded["text"], "hello\x00")
        self.assertEqual(call_tool(self.workspace, "decode_hex", {"data": "6869"})["text"], "hi")
        self.assertEqual(
            call_tool(self.workspace, "decode_url", {"data": "hello%20world"})["text"],
            "hello world",
        )
        self.assertToolError(
            "invalid_encoding", call_tool, self.workspace, "decode_hex", {"data": "not-hex"}
        )
        self.assertToolError(
            "invalid_argument",
            call_tool,
            self.workspace,
            "decode_hex",
            {"data": "00", "path": "blob.bin"},
        )

    def test_zip_extraction_and_tar_compatibility_listing(self) -> None:
        with zipfile.ZipFile(self.root / "good.zip", "w") as archive:
            archive.writestr("dir/value.txt", "value")
        self.assertEqual(
            call_tool(self.workspace, "list_zip", {"path": "good.zip"})["entries"][0]["name"],
            "dir/value.txt",
        )
        result = call_tool(
            self.workspace, "extract_archive", {"path": "good.zip", "destination": "out"}
        )
        self.assertEqual(result["files"], ["out/dir/value.txt"])
        self.assertEqual((self.root / "out/dir/value.txt").read_text(), "value")
        nested = call_tool(
            self.workspace,
            "extract_archive",
            {"path": "good.zip", "destination": "nested/out"},
        )
        self.assertEqual(nested["files"], ["nested/out/dir/value.txt"])
        self.assertEqual((self.root / "nested/out/dir/value.txt").read_text(), "value")

        with tarfile.open(self.root / "good.tar", "w") as archive:
            info = tarfile.TarInfo("inside.txt")
            payload = b"tar value"
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        self.assertEqual(
            call_tool(self.workspace, "list_tar", {"path": "good.tar"})["entries"][0]["name"],
            "inside.txt",
        )
        self.assertToolError(
            "unsupported_archive",
            call_tool,
            self.workspace,
            "extract_archive",
            {"path": "good.tar", "destination": "tar-out", "format": "tar"},
        )
        self.assertFalse((self.root / "tar-out").exists())

    def test_gzip_decompression_is_bounded_and_non_overwriting(self) -> None:
        with gzip.open(self.root / "disk.img.gz", "wb") as archive:
            archive.write(b"filesystem image")
        result = call_tool(
            self.workspace,
            "decompress_gzip",
            {"path": "disk.img.gz", "destination": "expanded/disk.img"},
        )
        self.assertEqual(result["bytes"], 16)
        self.assertEqual((self.root / "expanded/disk.img").read_bytes(), b"filesystem image")
        self.assertEqual((self.root / "expanded/disk.img").stat().st_nlink, 1)
        self.assertFalse(
            any(path.name.startswith(".rapido-part-") for path in self.root.rglob("*"))
        )
        self.assertToolError(
            "write_conflict",
            call_tool,
            self.workspace,
            "decompress_gzip",
            {"path": "disk.img.gz", "destination": "expanded/disk.img"},
        )

    def test_gzip_failure_cleanup_is_bounded_and_inode_owned(self) -> None:
        (self.root / "invalid.gz").write_bytes(b"not gzip")
        self.assertToolError(
            "invalid_archive",
            call_tool,
            self.workspace,
            "decompress_gzip",
            {"path": "invalid.gz", "destination": "invalid/out"},
        )
        self.assertFalse((self.root / "invalid/out").exists())
        self.assertFalse((self.root / "invalid").exists())

        with gzip.open(self.root / "bomb.gz", "wb") as archive:
            archive.write(b"12345678")
        with mock.patch("rapido.tools.MAX_ARCHIVE_BYTES", 4):
            self.assertToolError(
                "archive_too_large",
                call_tool,
                self.workspace,
                "decompress_gzip",
                {"path": "bomb.gz", "destination": "bomb/out"},
            )
        self.assertFalse((self.root / "bomb/out").exists())

        with gzip.open(self.root / "race.gz", "wb") as archive:
            archive.write(b"payload")
        destination = self.root / "race/out"
        original_read = gzip.GzipFile.read
        replaced = False

        def replace_output(handle, *args, **kwargs):
            nonlocal replaced
            if not replaced:
                destination.write_bytes(b"concurrent replacement")
                replaced = True
                raise OSError("synthetic read failure")
            return original_read(handle, *args, **kwargs)

        with mock.patch.object(gzip.GzipFile, "read", replace_output):
            self.assertToolError(
                "invalid_archive",
                ToolRegistry(self.workspace).dispatch,
                "decompress_gzip",
                {"path": "race.gz", "destination": "race/out"},
            )
        self.assertEqual(destination.read_bytes(), b"concurrent replacement")

        entries, _ = self.workspace.snapshot()
        with mock.patch("rapido.tools.MAX_WORKSPACE_ENTRIES", len(entries) + 1):
            self.assertToolError(
                "workspace_quota",
                ToolRegistry(self.workspace).dispatch,
                "decompress_gzip",
                {"path": "race.gz", "destination": "entry/quota/out"},
            )
        self.assertFalse((self.root / "entry").exists())

    def test_encrypted_zip_requires_and_validates_password_before_writing(self) -> None:
        fixture = base64.b64decode(
            "UEsDBAoACQAAAFtTL13uf7cmIQAAABUAAAAJABwAcGxhaW4udHh0VVQJAAPurKhq7qyo"
            "anV4CwABBPUBAAAEFAAAAIt6rrGjEoxMjOR8cji3ziWW71RDaasSyAcRj6dh033dClBL"
            "Bwjuf7cmIQAAABUAAABQSwECHgMKAAkAAABbUy9d7n+3JiEAAAAVAAAACQAYAAAAAAAB"
            "AAAApIEAAAAAcGxhaW4udHh0VVQFAAPurKhqdXgLAAEE9QEAAAQUAAAAUEsFBgAAAAAB"
            "AAEATwAAAHQAAAAAAA=="
        )
        (self.root / "encrypted.zip").write_bytes(fixture)
        self.assertToolError(
            "archive_password_required",
            call_tool,
            self.workspace,
            "extract_archive",
            {"path": "encrypted.zip", "destination": "missing-password"},
        )
        self.assertFalse((self.root / "missing-password").exists())
        self.assertToolError(
            "archive_password_rejected",
            call_tool,
            self.workspace,
            "extract_archive",
            {"path": "encrypted.zip", "destination": "wrong-password", "password": "wrong"},
        )
        self.assertFalse((self.root / "wrong-password").exists())
        call_tool(
            self.workspace,
            "extract_archive",
            {"path": "encrypted.zip", "destination": "decrypted", "password": "test-pass"},
        )
        self.assertEqual(
            (self.root / "decrypted" / "plain.txt").read_text(encoding="utf-8"),
            "inside secret fixture",
        )

    def test_archive_traversal_symlink_and_bomb_do_not_write(self) -> None:
        with zipfile.ZipFile(self.root / "evil.zip", "w") as archive:
            archive.writestr("../outside.txt", "do not write")
        self.assertToolError(
            "unsafe_archive",
            call_tool,
            self.workspace,
            "extract_archive",
            {"path": "evil.zip", "destination": "out"},
        )
        self.assertFalse((self.root.parent / "outside.txt").exists())

    def test_archive_entry_caps_precede_materialization_or_writes(self) -> None:
        with zipfile.ZipFile(self.root / "many.zip", "w") as archive:
            for index in range(MAX_ARCHIVE_ENTRIES + 1):
                archive.writestr(f"{index}.txt", b"")
        with mock.patch("rapido.tools.zipfile.ZipFile", side_effect=AssertionError):
            self.assertToolError(
                "archive_too_large", call_tool, self.workspace, "list_zip", {"path": "many.zip"}
            )

    def test_registry_enforces_cumulative_workspace_quota_and_rolls_back(self) -> None:
        with zipfile.ZipFile(self.root / "quota.zip", "w") as archive:
            archive.writestr("value.txt", "12345")
        _, current = self.workspace.snapshot()
        registry = ToolRegistry(self.workspace, max_workspace_bytes=current + 4)
        self.assertToolError(
            "workspace_quota",
            registry.dispatch,
            "extract_archive",
            {"path": "quota.zip", "destination": "quota-out"},
        )
        self.assertFalse((self.root / "quota-out").exists())

    def test_image_and_audio_metadata(self) -> None:
        # Minimal PNG signature/IHDR header; no pixel data is needed for dimensions.
        png = (
            b"\x89PNG\r\n\x1a\n"
            + b"\x00\x00\x00\rIHDR"
            + (3).to_bytes(4, "big")
            + (2).to_bytes(4, "big")
            + b"\x08\x02"
            + b"\x00\x00\x00"
        )
        (self.root / "image.png").write_bytes(png)
        image = call_tool(self.workspace, "image_metadata", {"path": "image.png"})
        self.assertEqual((image["width"], image["height"]), (3, 2))
        import wave

        with wave.open(str(self.root / "sound.wav"), "wb") as handle:
            handle.setnchannels(1)
            handle.setsampwidth(2)
            handle.setframerate(8_000)
            handle.writeframes(b"\x00\x00" * 8_000)
        audio = call_tool(self.workspace, "audio_metadata", {"path": "sound.wav"})
        self.assertEqual(audio["sample_rate"], 8_000)
        self.assertEqual(audio["duration_seconds"], 1.0)

    def test_binary_inspection_uses_fixed_argv_and_no_shell(self) -> None:
        filename = "binary;touch SHOULD_NOT_EXIST"
        (self.root / filename).write_bytes(b"not a binary")
        with (
            mock.patch(
                "rapido.tools.shutil.which",
                side_effect=lambda command, path=None: "/usr/bin/" + command,
            ),
            mock.patch(
                "rapido.tools._run_bounded_command",
                return_value=(0, b"ok", b"", False, False),
            ) as run,
        ):
            result = call_tool(self.workspace, "inspect_binary", {"path": filename})
        self.assertIn("commands", result)
        for invocation in run.call_args_list:
            self.assertNotIn("touch SHOULD_NOT_EXIST", invocation.args[0][0])
            self.assertEqual(invocation.args[0][-1], filename)
        self.assertFalse((self.root / "SHOULD_NOT_EXIST").exists())

    def test_fixed_command_capture_retains_only_bounded_prefix(self) -> None:
        returncode, stdout, stderr, truncated, timed_out = _run_bounded_command(
            [
                "/usr/bin/env",
                "python3",
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 65536)",
            ],
            self.root,
        )
        self.assertEqual(returncode, 0)
        self.assertEqual(len(stdout), MAX_COMMAND_OUTPUT_BYTES)
        self.assertEqual(stderr, b"")
        self.assertTrue(truncated)
        self.assertFalse(timed_out)

    def test_filesystem_tool_uses_fixed_read_only_command_and_inherited_fd(self) -> None:
        (self.root / "disk.img").write_bytes(b"filesystem")
        with (
            mock.patch("rapido.tools.shutil.which", return_value="/usr/sbin/debugfs"),
            mock.patch(
                "rapido.tools._run_bounded_command",
                return_value=(0, b"12 100644 file.txt\n", b"", False, False),
            ) as run,
        ):
            result = call_tool(
                self.workspace,
                "inspect_filesystem",
                {"path": "disk.img", "action": "list", "filesystem_path": "/safe"},
            )
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ["/usr/sbin/debugfs", "-R", "ls -l /safe"])
        self.assertRegex(argv[3], r"^/proc/self/fd/\d+$")
        self.assertEqual(len(run.call_args.kwargs["pass_fds"]), 1)
        self.assertIn("file.txt", result["text"])
        self.assertToolError(
            "invalid_argument",
            call_tool,
            self.workspace,
            "inspect_filesystem",
            {"path": "disk.img", "action": "read", "filesystem_path": "/safe\n!sh"},
        )

    def test_filesystem_input_is_anchored_and_special_files_never_reach_debugfs(self) -> None:
        os.mkfifo(self.root / "pipe")
        with (
            mock.patch("rapido.tools.shutil.which", return_value="/usr/sbin/debugfs"),
            mock.patch("rapido.tools._run_bounded_command") as run,
        ):
            self.assertToolError(
                "not_a_file",
                call_tool,
                self.workspace,
                "inspect_filesystem",
                {"path": "pipe", "action": "superblock"},
            )
            run.assert_not_called()

        inside = self.root / "inside"
        inside.mkdir()
        (inside / "disk.img").write_bytes(b"inside image")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "disk.img").write_bytes(b"outside image")
        original_open = os.open
        swapped = False

        def swap_ancestor(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == "disk.img" and kwargs.get("dir_fd") is not None and not swapped:
                inside.rename(self.root / "anchored")
                inside.symlink_to(outside, target_is_directory=True)
                swapped = True
            return original_open(path, flags, *args, **kwargs)

        def inspect_descriptor(argv, cwd, *, pass_fds=()):
            self.assertEqual(os.pread(pass_fds[0], 12, 0), b"inside image")
            return 0, b"anchored", b"", False, False

        patched_open = mock.Mock(side_effect=swap_ancestor)
        with (
            mock.patch("rapido.tools.shutil.which", return_value="/usr/sbin/debugfs"),
            mock.patch("rapido.tools.os.open", patched_open),
            mock.patch("rapido.tools.os.supports_dir_fd", {*os.supports_dir_fd, patched_open}),
            mock.patch("rapido.tools._run_bounded_command", side_effect=inspect_descriptor),
        ):
            result = call_tool(
                self.workspace,
                "inspect_filesystem",
                {"path": "inside/disk.img", "action": "superblock"},
            )
        self.assertEqual(result["text"], "anchored")


if __name__ == "__main__":
    unittest.main()
