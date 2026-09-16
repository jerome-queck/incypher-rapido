from __future__ import annotations

import copy
import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS_PATH = ROOT / "scripts/issue19_memory_comparison.py"
SPEC = importlib.util.spec_from_file_location("issue19_memory_comparison", HARNESS_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)

TIMESTAMP = "2026-09-16T00:00:00+00:00"


def result() -> dict[str, object]:
    return HARNESS.run_comparison(require_clean_source=False, timestamp=TIMESTAMP)


def test_frozen_comparison_replays_all_rows_and_selects_typed_memory() -> None:
    measured = result()

    assert len(measured["raw_rows"]) == 112
    assert measured["gate"] == {
        "passed": True,
        "expected_raw_row_count": 112,
        "actual_raw_row_count": 112,
        "exact_schema": True,
        "exact_order": True,
        "all_rows_valid": True,
        "permutation_stable": True,
        "eligible_arms": ["lane_local_v1", "typed_challenge_v1"],
    }
    assert measured["selection"] == {"arm": "typed_challenge_v1"}
    summaries = measured["summaries"]
    assert summaries["typed_challenge_v1"]["useful_record_count"] == 48
    assert summaries["lane_local_v1"]["useful_record_count"] == 20
    assert summaries["typed_challenge_v1"]["repeated_fingerprint_count"] == 0
    assert summaries["lane_local_v1"]["repeated_fingerprint_count"] == 0
    assert measured["provenance"]["effect_counters"] == {
        field: 0 for field in HARNESS.EFFECT_FIELDS
    }


def test_comparison_is_byte_deterministic_at_fixed_time() -> None:
    first = HARNESS.canonical_result_bytes(result())
    second = HARNESS.canonical_result_bytes(result())
    assert first == second


def test_result_validator_recomputes_views_and_rejects_raw_tampering() -> None:
    measured = result()
    protocol = HARNESS.load_protocol(HARNESS.DEFAULT_PROTOCOL_PATH)
    changed = copy.deepcopy(measured)
    changed["raw_rows"][0]["useful_record_count"] += 1

    with pytest.raises(ValueError):
        HARNESS.validate_result(
            changed,
            protocol,
            require_clean_source=False,
            expected_source=measured["source"],
        )


def test_clean_source_gate_fails_before_measurement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(HARNESS, "git_source_identity", lambda path: {"clean": False})
    with pytest.raises(RuntimeError, match="clean merged source"):
        HARNESS.run_comparison(require_clean_source=True, timestamp=TIMESTAMP)


def test_output_writer_never_overwrites(tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    payload = HARNESS.canonical_result_bytes(result())
    HARNESS._write_new(output, payload)
    assert output.read_bytes() == payload
    with pytest.raises(FileExistsError):
        HARNESS._write_new(output, payload)


def test_output_writer_preserves_verified_link_after_directory_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "result.json"

    def fail_fsync(path: Path) -> None:
        del path
        raise OSError("injected directory fsync failure")

    monkeypatch.setattr(HARNESS, "_fsync_directory", fail_fsync)
    with pytest.raises(OSError, match="injected directory fsync failure"):
        HARNESS._write_new(output, b"{}\n")
    assert output.read_bytes() == b"{}\n"


def test_cli_rejects_nonregistered_paths(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        HARNESS.main(
            [
                "--protocol",
                str(HARNESS.DEFAULT_PROTOCOL_PATH),
                "--output",
                str(tmp_path / "other.json"),
            ]
        )


def test_cli_preserves_a_preexisting_registered_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "registered-result.json"
    output.write_bytes(b"durable accepted evidence\n")
    monkeypatch.setattr(HARNESS, "DEFAULT_RESULT_PATH", output)
    monkeypatch.setattr(HARNESS.sys, "executable", str(HARNESS.ROOT / ".venv/bin/python"))
    with pytest.raises(FileExistsError, match="already exists"):
        HARNESS.main(
            [
                "--protocol",
                str(HARNESS.DEFAULT_PROTOCOL_PATH),
                "--output",
                str(output),
            ]
        )
    assert output.read_bytes() == b"durable accepted evidence\n"


def test_cli_validates_before_installing_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "registered-result.json"
    monkeypatch.setattr(HARNESS, "DEFAULT_RESULT_PATH", output)
    monkeypatch.setattr(HARNESS.sys, "executable", str(HARNESS.ROOT / ".venv/bin/python"))
    monkeypatch.setattr(
        HARNESS,
        "run_comparison",
        lambda *args, **kwargs: {"source": {}, "result": "not installed yet"},
    )
    monkeypatch.setattr(HARNESS, "load_protocol", lambda path: {})

    def reject(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise ValueError("injected pre-install validation failure")

    monkeypatch.setattr(HARNESS, "validate_result", reject)
    with pytest.raises(ValueError, match="pre-install validation failure"):
        HARNESS.main(
            [
                "--protocol",
                str(HARNESS.DEFAULT_PROTOCOL_PATH),
                "--output",
                str(output),
            ]
        )
    assert not output.exists()


def test_run_and_validation_recomputations_remain_inside_effect_fence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = HARNESS.recompute_views

    def effectful(*args: object, **kwargs: object) -> object:
        subprocess.run(["true"], check=True)
        return original(*args, **kwargs)

    monkeypatch.setattr(HARNESS, "recompute_views", effectful)
    with pytest.raises(RuntimeError, match="blocked forbidden containers"):
        HARNESS.run_comparison(require_clean_source=False, timestamp=TIMESTAMP)

    monkeypatch.setattr(HARNESS, "recompute_views", original)
    measured = result()
    protocol = HARNESS.load_protocol(HARNESS.DEFAULT_PROTOCOL_PATH)
    monkeypatch.setattr(HARNESS, "recompute_views", effectful)
    with pytest.raises(RuntimeError, match="blocked forbidden containers"):
        HARNESS.validate_result(measured, protocol, require_clean_source=False)


def test_merged_source_gate_rejects_an_unmerged_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "a" * 40

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        if command[:3] == ["git", "symbolic-ref", "refs/remotes/origin/HEAD"]:
            return subprocess.CompletedProcess(command, 0, "refs/remotes/origin/main\n", "")
        if command[:2] == ["git", "rev-parse"]:
            return subprocess.CompletedProcess(command, 0, f"{'b' * 40}\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(HARNESS.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="merged remote default-branch tip"):
        HARNESS._verify_merged_source({"commit": commit, "files": {}})
