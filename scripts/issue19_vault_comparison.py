#!/usr/bin/env python3
"""Reproducible, effect-free issue #19 candidate-retention comparison."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
FIXTURE_VERSION = "issue-19-vault-comparison-v1"
SOURCE_BASE_COMMIT = "3a1390f4370721997a147e15392e1bc3c3a48d15"
_EXIT_CODE = 91
_ADAPTERS = ("sqlite_transaction", "file_index", "volatile")
_CASES = (
    "same_process_commit",
    "clean_commit_reopen",
    "explicit_rollback",
    "crash_after_material",
    "crash_after_catalogue_write",
    "crash_after_commit_return",
    "replay_and_conflict",
    "peer_retention",
    "scope_isolation",
    "public_leak",
    "filesystem_safety",
)


class VaultConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class CandidateRecord:
    record_id: str
    run_id: str
    challenge_id: int
    source_attempt_id: str
    recipe_kind: str
    candidate: bytes

    @property
    def key(self) -> bytes:
        return hashlib.sha256(self.candidate).digest()


def _fixture_candidate() -> str:
    inner = hashlib.sha256(FIXTURE_VERSION.encode("ascii")).hexdigest()[:24]
    return f"INCYPHER{{{inner}}}"


def _record(record_id: str = "record-a") -> CandidateRecord:
    return CandidateRecord(
        record_id=record_id,
        run_id="run-fixture",
        challenge_id=7,
        source_attempt_id=f"attempt-{record_id}",
        recipe_kind="fresh_source_reobservation_v1",
        candidate=_fixture_candidate().encode("ascii"),
    )


def _private_encodings(candidate: str) -> tuple[str, ...]:
    raw = candidate.encode("utf-8")
    return (
        candidate,
        hashlib.sha256(raw).hexdigest(),
        raw.hex(),
        base64.b64encode(raw).decode("ascii"),
        base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        urllib.parse.quote(candidate, safe=""),
    )


def _prepare_root(root: Path) -> None:
    if root.is_symlink():
        raise ValueError("vault root must not be a symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError("vault root is unsafe")
    root.chmod(0o700)


def _secure_files(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        path.chmod(0o700 if path.is_dir() else 0o600)


class _SQLiteVault:
    durability_domains = 1

    def __init__(self, root: Path) -> None:
        _prepare_root(root)
        self.root = root
        self.path = root / "vault.sqlite3"
        self.connection = sqlite3.connect(self.path, isolation_level=None)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS records(
              record_id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL,
              challenge_id INTEGER NOT NULL,
              source_attempt_id TEXT NOT NULL,
              recipe_kind TEXT NOT NULL,
              candidate_key BLOB NOT NULL,
              candidate BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS public_audit(
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              kind TEXT NOT NULL
            );
            """
        )
        _secure_files(root)

    def commit(
        self,
        record: CandidateRecord,
        *,
        fault: str | None = None,
        rollback: bool = False,
    ) -> bool:
        existing = self.connection.execute(
            "SELECT run_id, challenge_id, source_attempt_id, recipe_kind, candidate_key, candidate "
            "FROM records WHERE record_id=?",
            (record.record_id,),
        ).fetchone()
        expected = (
            record.run_id,
            record.challenge_id,
            record.source_attempt_id,
            record.recipe_kind,
            record.key,
            record.candidate,
        )
        if existing is not None:
            if tuple(existing) != expected:
                raise VaultConflict("immutable candidate record conflicts")
            return False
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute(
                "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?)",
                (record.record_id, *expected),
            )
            if fault == "after_material":
                os._exit(_EXIT_CODE)
            self.connection.execute("INSERT INTO public_audit(kind) VALUES ('candidate_retained')")
            if fault == "after_catalogue_write":
                os._exit(_EXIT_CODE)
            if rollback:
                self.connection.execute("ROLLBACK")
                return False
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise
        _secure_files(self.root)
        if fault == "after_commit_return":
            os._exit(_EXIT_CODE)
        return True

    def retrieve(self, record: CandidateRecord) -> bytes | None:
        row = self.connection.execute(
            "SELECT candidate FROM records WHERE record_id=? AND run_id=? AND challenge_id=? "
            "AND source_attempt_id=? AND recipe_kind=?",
            (
                record.record_id,
                record.run_id,
                record.challenge_id,
                record.source_attempt_id,
                record.recipe_kind,
            ),
        ).fetchone()
        return None if row is None else bytes(row[0])

    def count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM records").fetchone()[0])

    def reconcile(self) -> tuple[int, int]:
        return 0, 0

    def public_surfaces(self) -> list[str]:
        audits = [row[0] for row in self.connection.execute("SELECT kind FROM public_audit")]
        return [path.name for path in self.root.rglob("*")] + audits

    def integrity(self) -> bool:
        return self.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

    def close(self) -> None:
        self.connection.close()
        _secure_files(self.root)


class _FileIndexVault:
    durability_domains = 2

    def __init__(self, root: Path) -> None:
        _prepare_root(root)
        self.root = root
        self.blobs = root / "blobs"
        self.blobs.mkdir(mode=0o700, exist_ok=True)
        self.path = root / "index.sqlite3"
        self.connection = sqlite3.connect(self.path, isolation_level=None)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS records(
              record_id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL,
              challenge_id INTEGER NOT NULL,
              source_attempt_id TEXT NOT NULL,
              recipe_kind TEXT NOT NULL,
              candidate_key BLOB NOT NULL,
              blob_name TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS public_audit(
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              kind TEXT NOT NULL
            );
            """
        )
        _secure_files(root)

    @staticmethod
    def _blob_name(record: CandidateRecord) -> str:
        if not record.record_id.replace("-", "").isalnum():
            raise ValueError("record id is unsafe")
        return f"{record.record_id}.bin"

    def commit(
        self,
        record: CandidateRecord,
        *,
        fault: str | None = None,
        rollback: bool = False,
    ) -> bool:
        blob_name = self._blob_name(record)
        existing = self.connection.execute(
            "SELECT run_id, challenge_id, source_attempt_id, recipe_kind, candidate_key, blob_name "
            "FROM records WHERE record_id=?",
            (record.record_id,),
        ).fetchone()
        expected = (
            record.run_id,
            record.challenge_id,
            record.source_attempt_id,
            record.recipe_kind,
            record.key,
            blob_name,
        )
        if existing is not None:
            material = self.blobs / str(existing[5])
            if (
                tuple(existing) != expected
                or not material.is_file()
                or material.read_bytes() != record.candidate
            ):
                raise VaultConflict("immutable candidate record conflicts")
            return False
        staging = self.blobs / f".{record.record_id}.tmp"
        final = self.blobs / blob_name
        descriptor = os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, record.candidate)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if rollback:
            staging.unlink()
            return False
        os.replace(staging, final)
        directory = os.open(self.blobs, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        if fault == "after_material":
            os._exit(_EXIT_CODE)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute(
                "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?)",
                (record.record_id, *expected),
            )
            self.connection.execute("INSERT INTO public_audit(kind) VALUES ('candidate_retained')")
            if fault == "after_catalogue_write":
                os._exit(_EXIT_CODE)
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise
        _secure_files(self.root)
        if fault == "after_commit_return":
            os._exit(_EXIT_CODE)
        return True

    def retrieve(self, record: CandidateRecord) -> bytes | None:
        row = self.connection.execute(
            "SELECT blob_name FROM records WHERE record_id=? AND run_id=? AND challenge_id=? "
            "AND source_attempt_id=? AND recipe_kind=?",
            (
                record.record_id,
                record.run_id,
                record.challenge_id,
                record.source_attempt_id,
                record.recipe_kind,
            ),
        ).fetchone()
        if row is None:
            return None
        path = self.blobs / str(row[0])
        return path.read_bytes() if path.is_file() and not path.is_symlink() else None

    def count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM records").fetchone()[0])

    def reconcile(self) -> tuple[int, int]:
        indexed = {
            str(row[0])
            for row in self.connection.execute("SELECT blob_name FROM records").fetchall()
        }
        actions = 0
        for path in self.blobs.iterdir():
            if path.name not in indexed:
                path.unlink()
                actions += 1
        dangling = [name for name in indexed if not (self.blobs / name).is_file()]
        _secure_files(self.root)
        return actions, len(dangling)

    def public_surfaces(self) -> list[str]:
        audits = [row[0] for row in self.connection.execute("SELECT kind FROM public_audit")]
        return [path.name for path in self.root.rglob("*")] + audits

    def integrity(self) -> bool:
        return self.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

    def close(self) -> None:
        self.connection.close()
        _secure_files(self.root)


class _VolatileVault:
    durability_domains = 0

    def __init__(self, root: Path) -> None:
        _prepare_root(root)
        self.root = root
        self.records: dict[str, CandidateRecord] = {}

    def commit(
        self,
        record: CandidateRecord,
        *,
        fault: str | None = None,
        rollback: bool = False,
    ) -> bool:
        existing = self.records.get(record.record_id)
        if existing is not None:
            if existing != record:
                raise VaultConflict("immutable candidate record conflicts")
            return False
        if rollback:
            return False
        if fault == "after_material":
            os._exit(_EXIT_CODE)
        self.records[record.record_id] = record
        if fault == "after_catalogue_write":
            os._exit(_EXIT_CODE)
        if fault is not None:
            raise ValueError(f"unsupported volatile fault: {fault}")
        return True

    def retrieve(self, record: CandidateRecord) -> bytes | None:
        existing = self.records.get(record.record_id)
        return existing.candidate if existing == record else None

    def count(self) -> int:
        return len(self.records)

    def reconcile(self) -> tuple[int, int]:
        return 0, 0

    def public_surfaces(self) -> list[str]:
        return [path.name for path in self.root.rglob("*")]

    def integrity(self) -> bool:
        return True

    def close(self) -> None:
        pass


def _adapter(name: str, root: Path) -> _SQLiteVault | _FileIndexVault | _VolatileVault:
    if name == "sqlite_transaction":
        return _SQLiteVault(root)
    if name == "file_index":
        return _FileIndexVault(root)
    if name == "volatile":
        return _VolatileVault(root)
    raise ValueError("unknown comparison adapter")


def _crash_case(adapter_name: str, root: Path, fault: str) -> dict[str, object]:
    completed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--child",
            adapter_name,
            fault,
            str(root),
        ],
        check=False,
        capture_output=True,
        timeout=10,
    )
    vault = _adapter(adapter_name, root)
    actions, dangling = vault.reconcile()
    committed = vault.count()
    survived = vault.retrieve(_record()) == _record().candidate
    public = b"\n".join(
        [completed.stdout, completed.stderr, "\n".join(vault.public_surfaces()).encode("utf-8")]
    ).decode("utf-8", errors="replace")
    leak_count = sum(value in public for value in _private_encodings(_fixture_candidate()))
    vault.close()
    return {
        "case": f"crash_{fault}",
        "committed_count": committed,
        "dangling_count": dangling,
        "exit_code": completed.returncode,
        "leak_count": leak_count,
        "reconciliation_actions": actions,
        "survived": survived,
    }


def _unsafe_entry_count(root: Path) -> int:
    count = 0
    for path in (root, *root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            count += 1
        elif stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode):
            count += int(bool(stat.S_IMODE(metadata.st_mode) & 0o077))
        else:
            count += 1
    return count


def _persistent_bytes(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _observed_durability_domains(root: Path) -> int:
    domains: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name.endswith((".sqlite3", ".sqlite3-shm", ".sqlite3-wal")):
            domains.add("sqlite")
        elif path.suffix == ".bin":
            domains.add("blob")
    return len(domains)


def _metrics_from_cases(cases: list[dict[str, object]]) -> dict[str, int]:
    by_case = {str(case["case"]): case for case in cases}
    crash_cases = [
        by_case[f"crash_{fault}"]
        for fault in ("after_material", "after_catalogue_write", "after_commit_return")
    ]
    return {
        "acknowledged_loss_count": int(not by_case["clean_commit_reopen"]["survived"])
        + int(not by_case["crash_after_commit_return"]["survived"]),
        "conflict_acceptance_count": int(by_case["replay_and_conflict"]["conflict_accepted"]),
        "duplicate_logical_record_count": max(
            0, int(by_case["replay_and_conflict"]["committed_count"]) - 1
        ),
        "integrity_failure_count": int(not by_case["filesystem_safety"]["integrity"]),
        "peer_loss_count": int(not by_case["peer_retention"]["peer_a_retained"]),
        "post_reconciliation_residue_count": sum(
            int(case["dangling_count"]) for case in crash_cases
        ),
        "public_leak_count": sum(int(case.get("leak_count", 0)) for case in cases),
        "reconciliation_actions": sum(int(case.get("reconciliation_actions", 0)) for case in cases),
        "scope_bypass_count": int(by_case["scope_isolation"]["scope_bypass_count"]),
        "unacknowledged_committed_count": sum(
            int(case["committed_count"]) for case in crash_cases[:2]
        ),
        "unsafe_entry_count": int(by_case["filesystem_safety"]["unsafe_entry_count"])
        + int(not by_case["filesystem_safety"]["symlink_rejected"]),
    }


def _run_adapter(name: str, root: Path) -> dict[str, object]:
    root.mkdir(mode=0o700, parents=True)
    cases: list[dict[str, object]] = []
    record = _record()

    case_root = root / "same"
    vault = _adapter(name, case_root)
    acknowledged = vault.commit(record)
    cases.append(
        {
            "case": "same_process_commit",
            "acknowledged": acknowledged,
            "committed_count": vault.count(),
            "retrieved": vault.retrieve(record) == record.candidate,
        }
    )
    vault.close()

    case_root = root / "reopen"
    vault = _adapter(name, case_root)
    vault.commit(record)
    vault.close()
    vault = _adapter(name, case_root)
    cases.append(
        {
            "case": "clean_commit_reopen",
            "committed_count": vault.count(),
            "survived": vault.retrieve(record) == record.candidate,
        }
    )
    vault.close()

    case_root = root / "rollback"
    vault = _adapter(name, case_root)
    acknowledged = vault.commit(record, rollback=True)
    vault.close()
    vault = _adapter(name, case_root)
    actions, dangling = vault.reconcile()
    cases.append(
        {
            "case": "explicit_rollback",
            "acknowledged": acknowledged,
            "committed_count": vault.count(),
            "dangling_count": dangling,
            "reconciliation_actions": actions,
        }
    )
    vault.close()

    for fault in ("after_material", "after_catalogue_write", "after_commit_return"):
        cases.append(_crash_case(name, root / fault, fault))

    case_root = root / "replay"
    vault = _adapter(name, case_root)
    vault.commit(record)
    replay_inserted = vault.commit(record)
    conflict_accepted = False
    try:
        vault.commit(replace(record, candidate=record.candidate + b"-changed"))
        conflict_accepted = True
    except VaultConflict:
        pass
    cases.append(
        {
            "case": "replay_and_conflict",
            "committed_count": vault.count(),
            "conflict_accepted": conflict_accepted,
            "replay_inserted": replay_inserted,
        }
    )
    vault.close()

    case_root = root / "peer"
    vault = _adapter(name, case_root)
    vault.commit(record)
    peer_b = replace(_record("record-b"), candidate=record.candidate + b"-peer-b")
    peer_b_acknowledged = vault.commit(peer_b, rollback=True)
    cases.append(
        {
            "case": "peer_retention",
            "committed_count": vault.count(),
            "peer_a_retained": vault.retrieve(record) == record.candidate,
            "peer_b_acknowledged": peer_b_acknowledged,
        }
    )
    vault.close()

    case_root = root / "scope"
    vault = _adapter(name, case_root)
    vault.commit(record)
    wrong_scopes = (
        replace(record, run_id="other-run"),
        replace(record, challenge_id=8),
        replace(record, source_attempt_id="other-attempt"),
        replace(record, recipe_kind="other-recipe"),
    )
    cases.append(
        {
            "case": "scope_isolation",
            "scope_bypass_count": sum(vault.retrieve(item) is not None for item in wrong_scopes),
        }
    )
    vault.close()

    case_root = root / "privacy"
    vault = _adapter(name, case_root)
    vault.commit(record)
    public = json.dumps(vault.public_surfaces(), sort_keys=True)
    cases.append(
        {
            "case": "public_leak",
            "leak_count": sum(
                value in public for value in _private_encodings(_fixture_candidate())
            ),
        }
    )
    vault.close()

    case_root = root / "safety"
    vault = _adapter(name, case_root)
    vault.commit(record)
    integrity = vault.integrity()
    vault.close()
    attack_target = root / "attack-target"
    attack_target.mkdir(mode=0o700)
    symlink = root / "attack-link"
    symlink.symlink_to(attack_target, target_is_directory=True)
    symlink_rejected = False
    try:
        _adapter(name, symlink)
    except ValueError:
        symlink_rejected = True
    symlink.unlink()
    shutil.rmtree(attack_target)
    cases.append(
        {
            "case": "filesystem_safety",
            "durability_domains_observed": _observed_durability_domains(root),
            "integrity": integrity,
            "persistent_bytes_observed": _persistent_bytes(root),
            "symlink_rejected": symlink_rejected,
            "unsafe_entry_count": _unsafe_entry_count(case_root),
        }
    )

    metrics = _metrics_from_cases(cases)
    cost = _cost_from_cases(cases)
    return {
        "adapter": name,
        "cases": sorted(cases, key=lambda item: str(item["case"])),
        "cost": cost,
        "metrics": metrics,
    }


_DISQUALIFYING_METRICS = (
    "acknowledged_loss_count",
    "conflict_acceptance_count",
    "duplicate_logical_record_count",
    "integrity_failure_count",
    "peer_loss_count",
    "post_reconciliation_residue_count",
    "public_leak_count",
    "scope_bypass_count",
    "unacknowledged_committed_count",
    "unsafe_entry_count",
)

_METRIC_FIELDS = (*_DISQUALIFYING_METRICS, "reconciliation_actions")
_COST_FIELDS = ("durability_domains", "persistent_bytes", "reconciliation_actions")


def _expected_case(adapter: str, case: str) -> dict[str, object]:
    persistent = adapter != "volatile"
    file_index = adapter == "file_index"
    common: dict[str, dict[str, object]] = {
        "same_process_commit": {
            "acknowledged": True,
            "committed_count": 1,
            "retrieved": True,
        },
        "clean_commit_reopen": {
            "committed_count": int(persistent),
            "survived": persistent,
        },
        "explicit_rollback": {
            "acknowledged": False,
            "committed_count": 0,
            "dangling_count": 0,
            "reconciliation_actions": 0,
        },
        "crash_after_material": {
            "committed_count": 0,
            "dangling_count": 0,
            "exit_code": _EXIT_CODE,
            "leak_count": 0,
            "reconciliation_actions": int(file_index),
            "survived": False,
        },
        "crash_after_catalogue_write": {
            "committed_count": 0,
            "dangling_count": 0,
            "exit_code": _EXIT_CODE,
            "leak_count": 0,
            "reconciliation_actions": int(file_index),
            "survived": False,
        },
        "crash_after_commit_return": {
            "committed_count": int(persistent),
            "dangling_count": 0,
            "exit_code": _EXIT_CODE,
            "leak_count": 0,
            "reconciliation_actions": 0,
            "survived": persistent,
        },
        "replay_and_conflict": {
            "committed_count": 1,
            "conflict_accepted": False,
            "replay_inserted": False,
        },
        "peer_retention": {
            "committed_count": 1,
            "peer_a_retained": True,
            "peer_b_acknowledged": False,
        },
        "scope_isolation": {"scope_bypass_count": 0},
        "public_leak": {"leak_count": 0},
        "filesystem_safety": {
            "durability_domains_observed": {
                "sqlite_transaction": 1,
                "file_index": 2,
                "volatile": 0,
            }[adapter],
            "integrity": True,
            "symlink_rejected": True,
            "unsafe_entry_count": 0,
        },
    }
    return {"case": case, **common[case]}


def _validate_cases(adapter: str, cases: object) -> list[str]:
    if not isinstance(cases, list):
        return [f"{adapter}:cases_type"]
    names = [case.get("case") if isinstance(case, dict) else None for case in cases]
    if names != sorted(_CASES):
        return [f"{adapter}:case_schema"]
    failures: list[str] = []
    for case in cases:
        assert isinstance(case, dict)
        name = str(case["case"])
        expected = _expected_case(adapter, name)
        expected_fields = set(expected)
        if name == "filesystem_safety":
            expected_fields.add("persistent_bytes_observed")
        if set(case) != expected_fields:
            failures.append(f"{adapter}:{name}:fields")
            continue
        for field, expected_value in expected.items():
            actual = case.get(field)
            if type(actual) is not type(expected_value) or actual != expected_value:
                failures.append(f"{adapter}:{name}:{field}")
        if name == "filesystem_safety":
            observed = case.get("persistent_bytes_observed")
            if (
                type(observed) is not int
                or observed < 0
                or (adapter != "volatile" and observed == 0)
            ):
                failures.append(f"{adapter}:{name}:persistent_bytes_observed")
    return failures


def _cost_from_cases(cases: list[dict[str, object]]) -> dict[str, int]:
    by_case = {str(case["case"]): case for case in cases}
    filesystem = by_case["filesystem_safety"]
    return {
        "durability_domains": int(filesystem["durability_domains_observed"]),
        "persistent_bytes": int(filesystem["persistent_bytes_observed"]),
        "reconciliation_actions": sum(int(case.get("reconciliation_actions", 0)) for case in cases),
    }


def recompute_gate(adapters: list[dict[str, Any]]) -> dict[str, object]:
    failures: list[str] = []
    eligible: dict[str, dict[str, int]] = {}
    names = [adapter.get("adapter") if isinstance(adapter, dict) else None for adapter in adapters]
    if names != list(_ADAPTERS):
        failures.append("adapter_schema")
    for adapter in adapters:
        if not isinstance(adapter, dict):
            failures.append("adapter_type")
            continue
        name = str(adapter.get("adapter"))
        if name not in _ADAPTERS or set(adapter) != {"adapter", "cases", "cost", "metrics"}:
            failures.append(f"{name}:adapter_fields")
            continue
        metrics = adapter.get("metrics")
        cases = adapter.get("cases")
        raw_failures = _validate_cases(name, cases)
        failures.extend(raw_failures)
        if raw_failures or not isinstance(cases, list):
            continue
        if (
            not isinstance(metrics, dict)
            or set(metrics) != set(_METRIC_FIELDS)
            or any(type(metrics.get(field)) is not int for field in _METRIC_FIELDS)
        ):
            failures.append(f"{name}:metrics_schema")
            continue
        recomputed = _metrics_from_cases(cases)
        if metrics != recomputed:
            failures.append(f"{name}:metrics_mismatch")
        cost = adapter.get("cost")
        recomputed_cost = _cost_from_cases(cases)
        if (
            not isinstance(cost, dict)
            or set(cost) != set(_COST_FIELDS)
            or any(type(cost.get(field)) is not int for field in _COST_FIELDS)
            or cost != recomputed_cost
        ):
            failures.append(f"{name}:cost_mismatch")
        defects = [field for field in _DISQUALIFYING_METRICS if recomputed[field] != 0]
        if not defects:
            eligible[name] = recomputed_cost
        expected_defects = {"acknowledged_loss_count": 2} if name == "volatile" else {}
        for field in _DISQUALIFYING_METRICS:
            if recomputed[field] != expected_defects.get(field, 0):
                failures.append(f"{name}:{field}")
    selected = None
    if eligible:
        selected = min(
            eligible,
            key=lambda name: (
                eligible[name]["durability_domains"],
                eligible[name]["reconciliation_actions"],
                eligible[name]["persistent_bytes"],
                name,
            ),
        )
    if selected != "sqlite_transaction":
        failures.append("selection:unexpected")
    return {
        "failures": failures,
        "passed": not failures,
        "selected": selected,
    }


def _provenance(output_root: Path, elapsed_seconds: float) -> dict[str, object]:
    sqlite_path = output_root / "sqlite_transaction" / "same" / "vault.sqlite3"
    connection = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    try:
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
    finally:
        connection.close()
    filesystem = os.statvfs(output_root)
    return {
        "artifact_command": (
            "PYTHONPATH=. python3 scripts/issue19_vault_comparison.py --pretty "
            "--output-root <fresh-0700-dir>"
        ),
        "elapsed_seconds": round(elapsed_seconds, 6),
        "environment": {
            "filesystem_block_size": filesystem.f_bsize,
            "filesystem_fragment_size": filesystem.f_frsize,
            "machine": platform.machine(),
            "platform_release": platform.release(),
            "platform_system": platform.system(),
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "root_mode": "0700",
            "sqlite_file_mode": "0600",
            "sqlite_journal_mode": journal_mode,
            "sqlite_synchronous": synchronous,
            "sqlite_version": sqlite3.sqlite_version,
        },
        "fixture_version": FIXTURE_VERSION,
        "result_format": "json.dumps(sort_keys=True, indent=2) plus newline",
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "source_base_commit": SOURCE_BASE_COMMIT,
    }


def run_comparison(output_root: Path) -> dict[str, object]:
    started = time.monotonic()
    _prepare_root(output_root)
    adapters = [_run_adapter(name, output_root / name) for name in _ADAPTERS]
    gate = recompute_gate(adapters)
    eligible = [
        adapter["adapter"]
        for adapter in adapters
        if all(adapter["metrics"][field] == 0 for field in _DISQUALIFYING_METRICS)
    ]
    ineligible = [adapter["adapter"] for adapter in adapters if adapter["adapter"] not in eligible]
    return {
        "adapters": adapters,
        "fixture": {
            "board_enabled": False,
            "container_enabled": False,
            "model_enabled": False,
            "network_enabled": False,
            "repetitions": 1,
        },
        "gate": gate,
        "provenance": _provenance(output_root, time.monotonic() - started),
        "schema_version": SCHEMA_VERSION,
        "selection": {
            "adapter": gate["selected"],
            "criterion": [
                "durability_domains",
                "reconciliation_actions",
                "persistent_bytes",
            ],
            "eligible": eligible,
            "ineligible": ineligible,
        },
    }


def _child(adapter_name: str, fault: str, root: Path) -> None:
    vault = _adapter(adapter_name, root)
    if fault == "after_commit_return":
        vault.commit(_record())
        os._exit(_EXIT_CODE)
    vault.commit(_record(), fault=fault)
    raise AssertionError("crash fault did not terminate the child")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--child", nargs=3, metavar=("ADAPTER", "FAULT", "ROOT"))
    arguments = parser.parse_args()
    if arguments.child is not None:
        adapter_name, fault, root = arguments.child
        _child(adapter_name, fault, Path(root))
        return 2
    if arguments.output_root is None:
        parser.error("--output-root is required")
    result = run_comparison(arguments.output_root)
    if arguments.pretty:
        print(json.dumps(result, sort_keys=True, indent=2))
    else:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
