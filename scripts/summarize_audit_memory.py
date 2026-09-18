#!/usr/bin/env python3
"""Summarize sanitized memory projections and carry retention events."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import stat
from collections import defaultdict
from pathlib import Path
from typing import Any

SCHEMA = "rapido.audit_memory_summary.v1"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_ROWS = 100_000
MEMORY_FIELDS = (
    "challenge_id",
    "episode",
    "lane",
    "role",
    "arm",
    "record_count",
    "deduplicated_record_count",
    "omitted_record_count",
    "encoded_bytes",
)
CARRY_FIELDS = (
    "challenge_id",
    "episode",
    "retained_file_events",
    "retained_bytes_events",
    "dropped_unsafe",
    "dropped_byte_cap",
    "dropped_file_cap",
    "dropped_invalid_file",
)
ROLES = frozenset({"specialist", "recovery", "verifier"})
_LABEL = re.compile(r"[a-z][a-z0-9_]{0,63}")


def _read_csv(path: Path, fields: tuple[str, ...]) -> tuple[list[dict[str, str]], str]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_INPUT_BYTES:
        raise ValueError(f"{path.name} must be a bounded regular file")
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise ValueError(f"{path.name} changed while opening")
        header = source.readline(4097)
        if len(header) > 4096 or not header.endswith((b"\n", b"\r\n")):
            raise ValueError(f"{path.name} has an invalid header")
        try:
            header_fields = tuple(next(csv.reader([header.decode("utf-8")])))
        except (UnicodeDecodeError, csv.Error) as exc:
            raise ValueError(f"{path.name} has an invalid header") from exc
        if header_fields != fields:
            raise ValueError(f"{path.name} has an unexpected sanitized schema")
        raw = header + source.read(MAX_INPUT_BYTES + 1 - len(header))
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"{path.name} exceeds the input limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path.name} must be UTF-8") from exc
    reader = csv.DictReader(text.splitlines())
    if tuple(reader.fieldnames or ()) != fields:
        raise ValueError(f"{path.name} has an unexpected sanitized schema")
    rows = list(reader)
    if len(rows) > MAX_ROWS:
        raise ValueError(f"{path.name} has too many rows")
    return rows, hashlib.sha256(raw).hexdigest()


def _integer(row: dict[str, str], field: str, *, positive: bool = False) -> int:
    raw = row.get(field)
    try:
        value = int(raw) if raw is not None else -1
    except ValueError as exc:
        raise ValueError(f"{field} must be an integer") from exc
    if value < (1 if positive else 0):
        qualifier = "positive" if positive else "nonnegative"
        raise ValueError(f"{field} must be {qualifier}")
    return value


def _memory_groups(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    totals: dict[tuple[int, str], dict[str, int]] = defaultdict(
        lambda: {
            "projection_count": 0,
            "record_count": 0,
            "deduplicated_record_count": 0,
            "omitted_record_count": 0,
            "encoded_bytes": 0,
        }
    )
    identities: set[tuple[int, int, int]] = set()
    for row in rows:
        challenge_id = _integer(row, "challenge_id", positive=True)
        episode = _integer(row, "episode")
        lane = _integer(row, "lane")
        role = row["role"]
        if role not in ROLES:
            raise ValueError("role is outside the closed sanitized registry")
        if _LABEL.fullmatch(row["arm"]) is None:
            raise ValueError("arm is not a closed label")
        identity = (challenge_id, episode, lane)
        if identity in identities:
            raise ValueError("memory projection identity is duplicated")
        identities.add(identity)
        group = totals[(episode, role)]
        group["projection_count"] += 1
        for field in (
            "record_count",
            "deduplicated_record_count",
            "omitted_record_count",
            "encoded_bytes",
        ):
            group[field] += _integer(row, field)
    return [
        {"episode": episode, "role": role, **totals[(episode, role)]}
        for episode, role in sorted(totals)
    ]


def _carry_summary(rows: list[dict[str, str]]) -> dict[str, object]:
    by_episode: dict[int, dict[str, int]] = defaultdict(
        lambda: {
            "operation_count": 0,
            "file_retention_event_count": 0,
            "retained_bytes_event_total": 0,
            "dropped_unsafe": 0,
            "dropped_byte_cap": 0,
            "dropped_file_cap": 0,
            "dropped_invalid_file": 0,
        }
    )
    totals = {
        "operation_count": 0,
        "file_retention_event_count": 0,
        "retained_bytes_event_total": 0,
        "dropped_unsafe": 0,
        "dropped_byte_cap": 0,
        "dropped_file_cap": 0,
        "dropped_invalid_file": 0,
    }
    seen: set[tuple[int, int]] = set()
    field_map = {
        "retained_file_events": "file_retention_event_count",
        "retained_bytes_events": "retained_bytes_event_total",
        "dropped_unsafe": "dropped_unsafe",
        "dropped_byte_cap": "dropped_byte_cap",
        "dropped_file_cap": "dropped_file_cap",
        "dropped_invalid_file": "dropped_invalid_file",
    }
    for row in rows:
        challenge_id = _integer(row, "challenge_id", positive=True)
        episode = _integer(row, "episode")
        identity = (challenge_id, episode)
        if identity in seen:
            raise ValueError("carry operation identity is duplicated")
        seen.add(identity)
        group = by_episode[episode]
        group["operation_count"] += 1
        totals["operation_count"] += 1
        for source, target in field_map.items():
            value = _integer(row, source)
            group[target] += value
            totals[target] += value
    return {
        **totals,
        "unique_file_count": None,
        "unique_file_count_status": "unknown_not_derivable_from_retention_events",
        "by_episode": [
            {"episode": episode, **by_episode[episode]} for episode in sorted(by_episode)
        ],
    }


def summarize(data_dir: Path) -> dict[str, Any]:
    """Return candidate-free counters from the two sanitized audit CSVs."""
    memory_rows, memory_sha256 = _read_csv(data_dir / "memory_projections.csv", MEMORY_FIELDS)
    carry_rows, carry_sha256 = _read_csv(data_dir / "carry_events.csv", CARRY_FIELDS)
    groups = _memory_groups(memory_rows)
    later = [group for group in groups if int(group["episode"]) > 0]
    return {
        "schema": SCHEMA,
        "inputs": {
            "memory_projections_sha256": memory_sha256,
            "carry_events_sha256": carry_sha256,
        },
        "memory": {
            "projection_count": len(memory_rows),
            "by_episode_and_role": groups,
            "later_episode_projection_count": sum(
                int(group["projection_count"]) for group in later
            ),
            "later_episode_record_count": sum(int(group["record_count"]) for group in later),
        },
        "carry": _carry_summary(carry_rows),
        "limitations": [
            "Retention events may count the same file across multiple carry operations.",
            "These counters show mechanism activity, not correctness or memory quality.",
        ],
    }


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    print(canonical_bytes(summarize(args.data_dir)).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
