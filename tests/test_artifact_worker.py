from __future__ import annotations

import io
import json
import os
import signal
import sys
import tarfile
import time
from pathlib import Path

import pytest
from PIL import Image
from pypdf import PdfWriter

from rapido import artifact_inspector, artifact_worker, artifact_worker_main
from rapido.artifact_worker import run_artifact_worker
from rapido.tools import ToolError

_PRODUCTION_PLATFORM_GUARD = artifact_worker._require_linux_sandbox


@pytest.fixture(autouse=True)
def _exercise_worker_protocol_off_linux(monkeypatch):
    """Protocol/parser tests bypass only the public production-platform guard."""
    if sys.platform != "linux":
        monkeypatch.setattr(artifact_worker, "_require_linux_sandbox", lambda: None)


def _open(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC)


def test_public_worker_fails_closed_without_linux_confinement(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"bound")
    descriptor = _open(source)
    monkeypatch.setattr(artifact_worker, "_require_linux_sandbox", _PRODUCTION_PLATFORM_GUARD)
    monkeypatch.setattr(sys, "platform", "darwin")
    try:
        with pytest.raises(ToolError) as error:
            run_artifact_worker(
                descriptor,
                "tar",
                size=source.stat().st_size,
                cursor=None,
                base=_base("source", source.stat().st_size, "tar", "structure", "entries"),
            )
    finally:
        os.close(descriptor)
    assert error.value.code == "tool_unavailable"


def _fixture_worker(tmp_path: Path, source: str) -> str:
    path = tmp_path / f"worker-{len(list(tmp_path.glob('worker-*')))}.py"
    path.write_text(source)
    return str(path)


def _request(operation: str = "_test_limits", **parameters: object) -> bytes:
    return artifact_worker._request_bytes(operation, parameters)


def _base(path: str, size: int, format_name: str, view: str, selection: str | None = None):
    return {
        "path": path,
        "source_bytes": size,
        "source_sha256": "0" * 64,
        "format": format_name,
        "view": view,
        "selection": selection,
    }


def _tar_fixture(path: Path, count: int) -> None:
    with tarfile.open(path, "w") as archive:
        for index in range(count):
            member = tarfile.TarInfo(f"entry-{index:04}.txt")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))


def _wait_group_gone(process_group: int, popen: object) -> None:
    deadline = time.monotonic() + 1.0
    while True:
        process = popen(["/bin/ps", "-axo", "pgid="], stdout=artifact_worker.subprocess.PIPE)
        stdout, _ = process.communicate(timeout=1)
        groups = {int(value) for value in stdout.split()}
        if process_group not in groups:
            return
        if time.monotonic() >= deadline:
            pytest.fail("artifact-worker descendant process group leaked")
        time.sleep(0.01)


def test_real_worker_uses_inherited_descriptor_after_workspace_name_changes(tmp_path):
    source = tmp_path / "source.png"
    Image.new("RGB", (3, 2), (1, 2, 3)).save(source)
    descriptor = _open(source)
    source.rename(tmp_path / "moved.png")
    source.write_bytes(b"replacement outside the bound descriptor")
    try:
        result = run_artifact_worker(
            descriptor,
            "image",
            size=os.fstat(descriptor).st_size,
            cursor=None,
            base=_base("source.png", os.fstat(descriptor).st_size, "png", "structure", "channel:R"),
        )
    finally:
        os.close(descriptor)
    assert (result["data"]["width"], result["data"]["height"]) == (3, 2)
    assert result["data"]["pixel_signals"]["channels"]["R"]["mean"] == 1.0
    assert result["path"] == "source.png"


def test_pdf_parser_is_bounded_behind_structured_protocol(tmp_path):
    source = tmp_path / "one.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=144)
    writer.write(source)
    descriptor = _open(source)
    try:
        result = run_artifact_worker(
            descriptor,
            "pdf",
            size=os.fstat(descriptor).st_size,
            cursor=None,
            base=_base("one.pdf", os.fstat(descriptor).st_size, "pdf", "structure", "page:0"),
        )
    finally:
        os.close(descriptor)
    assert result["data"]["page_count"] == 1
    assert result["data"]["pages"] == [
        {"height_points": 144.0, "index": 0, "rotation": 0, "width_points": 72.0}
    ]


def test_tar_inventory_worker_preserves_pagination_and_display_path(tmp_path):
    source = tmp_path / "many.tar"
    _tar_fixture(source, 101)
    descriptor = _open(source)
    size = os.fstat(descriptor).st_size
    base = _base("many.tar", size, "tar", "structure", "entries")
    try:
        first = run_artifact_worker(descriptor, "tar", size=size, cursor=None, base=base)
        second = run_artifact_worker(
            descriptor,
            "tar",
            size=size,
            cursor=first["next_cursor"],
            base=base,
        )
    finally:
        os.close(descriptor)
    assert len(first["data"]["entries"]) == 100
    assert first["coverage"] == "partial"
    assert first["stop_reason"] == "record_limit"
    assert len(second["data"]["entries"]) == 1
    assert second["coverage"] == "complete"
    assert second["stop_reason"] == "end_of_inventory"
    assert second["path"] == "many.tar"


@pytest.mark.parametrize(
    ("payload", "expected_code"),
    [(b"not a tar archive", "invalid_artifact"), (None, "limit_exceeded")],
)
def test_tar_worker_fails_safely_on_malformed_or_resource_limited_inventory(
    tmp_path, monkeypatch, payload, expected_code
):
    source = tmp_path / "bounded.tar"
    if payload is None:
        _tar_fixture(source, artifact_inspector.MAX_ARCHIVE_ENTRIES + 1)
    else:
        source.write_bytes(payload)
    created = []
    real_mkdtemp = artifact_worker.tempfile.mkdtemp

    def tracked_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        created.append(Path(path))
        return path

    monkeypatch.setattr(artifact_worker.tempfile, "mkdtemp", tracked_mkdtemp)
    descriptor = _open(source)
    size = os.fstat(descriptor).st_size
    try:
        with pytest.raises(ToolError) as error:
            run_artifact_worker(
                descriptor,
                "tar",
                size=size,
                cursor=None,
                base=_base("bounded.tar", size, "tar", "structure", "entries"),
            )
    finally:
        os.close(descriptor)
    assert error.value.code == expected_code
    assert created and all(not path.exists() for path in created)


def test_tar_worker_protocol_binds_operation_to_tar_format(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"not relevant")
    descriptor = _open(source)
    size = os.fstat(descriptor).st_size
    try:
        with pytest.raises(ToolError) as error:
            run_artifact_worker(
                descriptor,
                "tar",
                size=size,
                cursor=None,
                base=_base("source", size, "zip", "structure", "entries"),
            )
    finally:
        os.close(descriptor)
    assert error.value.code == "invalid_argument"
    assert error.value.message == "artifact-worker view binding is invalid"


def test_malformed_third_party_input_maps_to_stable_tool_error(tmp_path):
    source = tmp_path / "bad.png"
    source.write_bytes(b"not an image")
    descriptor = _open(source)
    try:
        with pytest.raises(ToolError) as error:
            run_artifact_worker(
                descriptor,
                "image",
                size=os.fstat(descriptor).st_size,
                cursor=None,
                base=_base("bad.png", os.fstat(descriptor).st_size, "png", "summary"),
            )
    finally:
        os.close(descriptor)
    assert error.value.code == "invalid_artifact"
    assert error.value.message == "raster image is malformed or unsupported"


def test_public_entry_rejects_arbitrary_operations_and_non_files(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"x")
    descriptor = _open(source)
    try:
        with pytest.raises(ToolError) as operation:
            run_artifact_worker(
                descriptor,
                "/bin/sh",
                size=1,
                cursor=None,
                base=_base("source", 1, "png", "summary"),
            )
    finally:
        os.close(descriptor)
    assert operation.value.code == "invalid_argument"
    read_descriptor, write_descriptor = os.pipe()
    try:
        with pytest.raises(ToolError) as non_file:
            run_artifact_worker(
                read_descriptor,
                "image",
                size=0,
                cursor=None,
                base=_base("source", 0, "png", "summary"),
            )
    finally:
        os.close(read_descriptor)
        os.close(write_descriptor)
    assert non_file.value.code == "not_a_file"


def test_public_protocol_never_sends_workspace_path(tmp_path, monkeypatch):
    source = tmp_path / "private-name.png"
    source.write_bytes(b"x")
    descriptor = _open(source)
    captured = []

    def run(_descriptor, request):
        captured.append(json.loads(request))
        return {"path": "[artifact]"}

    monkeypatch.setattr(artifact_worker, "_run_worker", run)
    try:
        result = run_artifact_worker(
            descriptor,
            "image",
            size=1,
            cursor=None,
            base=_base("private-name.png", 1, "png", "summary"),
        )
    finally:
        os.close(descriptor)
    assert captured[0]["parameters"]["base"]["path"] == "[artifact]"
    assert result["path"] == "private-name.png"


def test_worker_command_environment_and_source_are_fixed(tmp_path, monkeypatch):
    source = tmp_path / "private-name"
    source.write_bytes(b"x")
    descriptor = _open(source)
    script = _fixture_worker(
        tmp_path,
        """
import json, os, sys
json.dump({"protocol": 1, "ok": True, "result": {"argv": sys.argv, "env": dict(os.environ)}}, sys.stdout)
""",
    )
    monkeypatch.setenv("BOARD_API_KEY", "must-not-cross")
    calls = []
    real_popen = artifact_worker.subprocess.Popen

    def recording_popen(*args, **kwargs):
        calls.append((args, kwargs))
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(artifact_worker.subprocess, "Popen", recording_popen)
    try:
        result = artifact_worker._run_worker(descriptor, _request(), worker_script=script)
    finally:
        os.close(descriptor)
    command = calls[0][0][0]
    options = calls[0][1]
    assert command[:3] == (os.path.abspath(sys.executable), "-I", "-B")
    assert command[3:6] == (script, "--source-fd", str(descriptor))
    assert command[6] == "--scratch-fd"
    assert command[7].isdigit()
    assert str(source) not in json.dumps(result)
    assert {key: result["env"][key] for key in artifact_worker._SAFE_ENV} == (
        artifact_worker._SAFE_ENV
    )
    assert set(result["env"]) <= set(artifact_worker._SAFE_ENV) | {"__CF_USER_TEXT_ENCODING"}
    assert "BOARD_API_KEY" not in result["env"]
    assert options["env"] == artifact_worker._SAFE_ENV
    assert options["cwd"] == "/"
    assert options["shell"] is False
    assert options["pass_fds"] == (descriptor, int(command[7]))
    assert options["start_new_session"] is True


def test_worker_resource_ceilings_are_applied_before_dispatch(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"x")
    descriptor = _open(source)
    try:
        limits = artifact_worker._run_worker(descriptor, _request())
    finally:
        os.close(descriptor)
    assert limits["RLIMIT_CORE"] == [0, 0]
    assert limits["RLIMIT_FSIZE"] == [artifact_worker_main.SCRATCH_FILE_LIMIT_BYTES] * 2
    assert limits["RLIMIT_CPU"] == [2, 3]
    assert limits["RLIMIT_NOFILE"] == [64, 64]
    if sys.platform != "darwin":
        assert limits["RLIMIT_AS"] == [256 * 1024 * 1024] * 2


@pytest.mark.parametrize("outcome", ["success", "crash", "timeout", "cancel"])
def test_parent_removes_private_scratch_for_every_worker_exit(tmp_path, monkeypatch, outcome):
    source = tmp_path / "source"
    source.write_bytes(b"x")
    if outcome in {"success", "cancel"}:
        body = 'import json,sys; json.dump({"protocol":1,"ok":True,"result":{}},sys.stdout)'
    elif outcome == "crash":
        body = "raise SystemExit(3)"
    else:
        body = "import time; time.sleep(30)"
    script = _fixture_worker(tmp_path, body)
    created: list[Path] = []
    real_mkdtemp = artifact_worker.tempfile.mkdtemp

    def tracked_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        created.append(Path(path))
        return path

    monkeypatch.setattr(artifact_worker.tempfile, "mkdtemp", tracked_mkdtemp)
    if outcome == "cancel":

        def cancel(_raw):
            raise KeyboardInterrupt

        monkeypatch.setattr(artifact_worker, "_read_protocol_response", cancel)
    descriptor = _open(source)
    try:
        if outcome == "success":
            assert artifact_worker._run_worker(descriptor, _request(), worker_script=script) == {}
        elif outcome == "cancel":
            with pytest.raises(KeyboardInterrupt):
                artifact_worker._run_worker(descriptor, _request(), worker_script=script)
        else:
            with pytest.raises(ToolError) as error:
                artifact_worker._run_worker(
                    descriptor,
                    _request(),
                    timeout_seconds=0.1,
                    worker_script=script,
                )
            assert error.value.code == (
                "tool_failed" if outcome == "crash" else "deadline_exceeded"
            )
    finally:
        os.close(descriptor)
    assert created and all(not path.exists() for path in created)


@pytest.mark.parametrize("termination_signal", [signal.SIGKILL, signal.SIGXCPU])
def test_native_resource_signal_maps_to_resource_limit(tmp_path, termination_signal):
    source = tmp_path / "source"
    source.write_bytes(b"x")
    descriptor = _open(source)
    try:
        with pytest.raises(artifact_worker_main.WorkerError) as error:
            artifact_worker_main._native(
                [
                    os.path.abspath(sys.executable),
                    "-c",
                    f"import os,signal; os.kill(os.getpid(), {int(termination_signal)})",
                ],
                descriptor,
            )
    finally:
        os.close(descriptor)
    assert error.value.code == "resource_limit"


def test_native_stdin_uses_bound_descriptor_from_start_after_prior_parser_reads(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"bound source")
    helper = tmp_path / "stdin-reader"
    helper.write_text("#!/bin/sh\n/bin/cat\n")
    helper.chmod(0o700)
    descriptor = _open(source)
    os.lseek(descriptor, 0, os.SEEK_END)
    try:
        result = artifact_worker_main._native([str(helper), "stdin", "stdout"], descriptor)
    finally:
        os.close(descriptor)
    assert result["returncode"] == 0
    assert result["stdout"] == b"bound source"


def test_wall_deadline_kills_entire_worker_process_group(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"x")
    marker = "artifact-worker-descendant-9f23d76b"
    script = _fixture_worker(
        tmp_path,
        f"""
import subprocess, sys, time
subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "{marker}"])
time.sleep(30)
""",
    )
    descriptor = _open(source)
    process_groups = []
    real_popen = artifact_worker.subprocess.Popen

    def recording_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        process_groups.append(process.pid)
        return process

    monkeypatch.setattr(artifact_worker.subprocess, "Popen", recording_popen)
    try:
        with pytest.raises(ToolError) as error:
            artifact_worker._run_worker(
                descriptor,
                _request(),
                timeout_seconds=0.15,
                drain_seconds=0.5,
                worker_script=script,
            )
    finally:
        os.close(descriptor)
    assert error.value.code == "deadline_exceeded"
    _wait_group_gone(process_groups[0], real_popen)


def test_success_response_also_kills_same_group_descendant(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"x")
    script = _fixture_worker(
        tmp_path,
        """
import json, subprocess, sys
subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(30)"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
json.dump({"protocol": 1, "ok": True, "result": {"complete": True}}, sys.stdout)
""",
    )
    descriptor = _open(source)
    process_groups = []
    real_popen = artifact_worker.subprocess.Popen

    def recording_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        process_groups.append(process.pid)
        return process

    monkeypatch.setattr(artifact_worker.subprocess, "Popen", recording_popen)
    try:
        result = artifact_worker._run_worker(descriptor, _request(), worker_script=script)
    finally:
        os.close(descriptor)
    assert result == {"complete": True}
    _wait_group_gone(process_groups[0], real_popen)


def test_output_flood_is_cut_off_and_group_is_killed(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"x")
    script = _fixture_worker(
        tmp_path,
        f"import os; os.write(1, b'x' * {artifact_worker.MAX_RESPONSE_BYTES + 4096})",
    )
    descriptor = _open(source)
    try:
        with pytest.raises(ToolError) as error:
            artifact_worker._run_worker(descriptor, _request(), worker_script=script)
    finally:
        os.close(descriptor)
    assert error.value.code == "output_too_large"


def test_unrecognized_remote_error_never_relays_diagnostic_text(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"x")
    script = _fixture_worker(
        tmp_path,
        """
import json, sys
json.dump({"protocol": 1, "ok": False, "error": {"code": "invented", "message": "SECRET-SENTINEL"}}, sys.stdout)
""",
    )
    descriptor = _open(source)
    try:
        with pytest.raises(ToolError) as error:
            artifact_worker._run_worker(descriptor, _request(), worker_script=script)
    finally:
        os.close(descriptor)
    assert error.value.code == "tool_failed"
    assert error.value.message == "artifact worker failed safely"
    assert "SECRET-SENTINEL" not in str(error.value)


def test_diagnostic_flood_is_not_relayed(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"x")
    script = _fixture_worker(
        tmp_path,
        f"import os; os.write(2, b'secret' * {artifact_worker.MAX_DIAGNOSTIC_BYTES})",
    )
    descriptor = _open(source)
    try:
        with pytest.raises(ToolError) as error:
            artifact_worker._run_worker(descriptor, _request(), worker_script=script)
    finally:
        os.close(descriptor)
    assert error.value.code == "output_too_large"
    assert "secret" not in str(error.value)
