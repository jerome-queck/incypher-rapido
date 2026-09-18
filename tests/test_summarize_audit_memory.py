from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/summarize_audit_memory.py"
SPEC = importlib.util.spec_from_file_location("summarize_audit_memory", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SUMMARY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SUMMARY
SPEC.loader.exec_module(SUMMARY)


def _write_csv(path: Path, fields: tuple[str, ...], rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _fixture(data_dir: Path) -> None:
    memory = []
    for lane in range(4):
        memory.append(
            {
                "challenge_id": 33,
                "episode": 1,
                "lane": lane,
                "role": "recovery",
                "arm": "typed_challenge_v1",
                "record_count": 42,
                "deduplicated_record_count": 35,
                "omitted_record_count": 8,
                "encoded_bytes": 100,
            }
        )
    for lane in range(5):
        memory.append(
            {
                "challenge_id": 90 + lane,
                "episode": 1,
                "lane": 0,
                "role": "verifier",
                "arm": "typed_challenge_v1",
                "record_count": 0,
                "deduplicated_record_count": 0,
                "omitted_record_count": 0,
                "encoded_bytes": 2,
            }
        )
    _write_csv(data_dir / "memory_projections.csv", SUMMARY.MEMORY_FIELDS, memory)
    carry = [
        {
            "challenge_id": index + 1,
            "episode": int(index == 10),
            "retained_file_events": 18 if index < 10 else 3,
            "retained_bytes_events": 655_438 if index < 10 else 655_440,
            "dropped_unsafe": 0,
            "dropped_byte_cap": 0,
            "dropped_file_cap": 0,
            "dropped_invalid_file": 0,
        }
        for index in range(11)
    ]
    _write_csv(data_dir / "carry_events.csv", SUMMARY.CARRY_FIELDS, carry)


def test_groups_recovery_and_verifier_by_role_and_episode(tmp_path: Path) -> None:
    _fixture(tmp_path)

    result = SUMMARY.summarize(tmp_path)

    groups = result["memory"]["by_episode_and_role"]
    assert groups == [
        {
            "episode": 1,
            "role": "recovery",
            "projection_count": 4,
            "record_count": 168,
            "deduplicated_record_count": 140,
            "omitted_record_count": 32,
            "encoded_bytes": 400,
        },
        {
            "episode": 1,
            "role": "verifier",
            "projection_count": 5,
            "record_count": 0,
            "deduplicated_record_count": 0,
            "omitted_record_count": 0,
            "encoded_bytes": 10,
        },
    ]
    assert result["memory"]["later_episode_projection_count"] == 9
    assert result["memory"]["later_episode_record_count"] == 168


def test_carry_reports_retention_events_and_keeps_unique_files_unknown(tmp_path: Path) -> None:
    _fixture(tmp_path)

    carry = SUMMARY.summarize(tmp_path)["carry"]

    assert carry["operation_count"] == 11
    assert carry["file_retention_event_count"] == 183
    assert carry["retained_bytes_event_total"] == 7_209_820
    assert carry["unique_file_count"] is None
    assert carry["unique_file_count_status"] == "unknown_not_derivable_from_retention_events"
    assert carry["by_episode"][0]["operation_count"] == 10
    assert carry["by_episode"][1]["operation_count"] == 1


def test_rejects_unsanitized_or_invalid_rows(tmp_path: Path) -> None:
    _fixture(tmp_path)
    path = tmp_path / "memory_projections.csv"
    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    fields = (*SUMMARY.MEMORY_FIELDS, "candidate")
    for row in rows:
        row["candidate"] = "private"
    _write_csv(path, fields, rows)

    with pytest.raises(ValueError, match="unexpected sanitized schema"):
        SUMMARY.summarize(tmp_path)


@pytest.mark.parametrize(("field", "value"), (("role", "coordinator"), ("record_count", -1)))
def test_rejects_open_roles_and_negative_counts(tmp_path: Path, field: str, value: object) -> None:
    _fixture(tmp_path)
    path = tmp_path / "memory_projections.csv"
    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    rows[0][field] = value
    _write_csv(path, SUMMARY.MEMORY_FIELDS, rows)

    with pytest.raises(ValueError):
        SUMMARY.summarize(tmp_path)


def test_cli_is_canonical_and_candidate_free(tmp_path: Path) -> None:
    _fixture(tmp_path)

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--data-dir", str(tmp_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    parsed = json.loads(completed.stdout)

    assert completed.stdout.encode() == SUMMARY.canonical_bytes(parsed)
    assert "candidate" not in completed.stdout
    assert parsed["schema"] == SUMMARY.SCHEMA
