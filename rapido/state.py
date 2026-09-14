"""Small durable state store for restartable runs and reviewable events."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_EVENT_BYTES = 128 * 1024


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = path.parent.lstat()
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid not in {0, os.geteuid()}
            or parent.st_mode & 0o077
        ):
            raise ValueError("state directory must be runtime/root owned and mode 0700 or stricter")
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("state database must be a regular file")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        sidecars = (Path(f"{path}-wal"), Path(f"{path}-shm"))
        for sidecar in sidecars:
            try:
                metadata = sidecar.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ValueError("state sidecar is not safely accessible") from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ValueError("state sidecars must be regular files, never symlinks")
        self._connection = sqlite3.connect(
            path, timeout=30, isolation_level=None, check_same_thread=False
        )
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._lease_files: list[int] = []
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        for private_file in (path, *sidecars):
            try:
                metadata = private_file.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                self._connection.close()
                raise ValueError("state files must be regular files, never symlinks")
            private_file.chmod(0o600)
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                config_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                challenge_type TEXT NOT NULL,
                value INTEGER NOT NULL,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attempts (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES runs(id),
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                lane INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                model TEXT NOT NULL,
                effort TEXT NOT NULL,
                summary TEXT NOT NULL DEFAULT '',
                candidate TEXT,
                confidence REAL,
                UNIQUE(run_id, challenge_id, lane)
            );
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(id),
                at TEXT NOT NULL,
                kind TEXT NOT NULL,
                data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS submissions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(id),
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                at TEXT NOT NULL,
                candidate_sha256 TEXT NOT NULL,
                outcome TEXT NOT NULL,
                http_status INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS submission_intents (
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                candidate_sha256 TEXT NOT NULL,
                first_run_id TEXT NOT NULL REFERENCES runs(id),
                reserved_at TEXT NOT NULL,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(challenge_id, candidate_sha256)
            );
            CREATE TABLE IF NOT EXISTS instances (
                challenge_id INTEGER PRIMARY KEY REFERENCES challenges(id),
                run_id TEXT NOT NULL REFERENCES runs(id),
                status TEXT NOT NULL,
                receipt_sha256 TEXT,
                updated_at TEXT NOT NULL
            );
            """
        )
        instance_columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(instances)").fetchall()
        }
        if "receipt_sha256" not in instance_columns:
            self._connection.execute("ALTER TABLE instances ADD COLUMN receipt_sha256 TEXT")

    def acquire_supervisor(
        self,
        auth_lease_path: Path | None = None,
        work_lease_path: Path | None = None,
    ) -> None:
        """Take state plus optional shared-auth/work leases without waiting."""
        with self._lock:
            if self._lease_files:
                return
            paths = [self.path.with_name(f"{self.path.name}.lock")]
            if auth_lease_path is not None and auth_lease_path not in paths:
                paths.append(auth_lease_path)
            if work_lease_path is not None and work_lease_path not in paths:
                paths.append(work_lease_path)
            try:
                for lease_path in paths:
                    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
                    flags |= getattr(os, "O_NOFOLLOW", 0)
                    descriptor = os.open(lease_path, flags, 0o600)
                    try:
                        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                            raise OSError("supervisor lease is not a regular file")
                        os.fchmod(descriptor, 0o600)
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BaseException:
                        os.close(descriptor)
                        raise
                    self._lease_files.append(descriptor)
            except (BlockingIOError, OSError) as exc:
                self.release_supervisor()
                raise RuntimeError(
                    "another Rapido supervisor owns the state or native-auth lease, or work lease"
                ) from exc

    def release_supervisor(self) -> None:
        with self._lock:
            while self._lease_files:
                descriptor = self._lease_files.pop()
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
            else:
                self._connection.execute("COMMIT")

    def start_run(self, run_id: str, config: dict[str, object]) -> None:
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO runs(id, started_at, status, config_json) VALUES (?, ?, 'running', ?)",
                (run_id, self._now(), json.dumps(config, sort_keys=True, separators=(",", ":"))),
            )

    def finish_run(self, run_id: str, status: str) -> None:
        if status not in {"completed", "deadline", "failed", "interrupted"}:
            raise ValueError("invalid run status")
        with self.transaction() as connection:
            changed = connection.execute(
                "UPDATE runs SET finished_at=?, status=? WHERE id=? AND status='running'",
                (self._now(), status, run_id),
            ).rowcount
            if changed != 1:
                raise ValueError("run is absent or not running")

    def upsert_challenge(
        self, challenge_id: int, name: str, category: str, challenge_type: str, value: int
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO challenges(id, name, category, challenge_type, value, status, updated_at)
                VALUES (?, ?, ?, ?, ?, 'queued', ?)
                ON CONFLICT(id) DO UPDATE SET
                  name=excluded.name, category=excluded.category,
                  challenge_type=excluded.challenge_type, value=excluded.value,
                  updated_at=excluded.updated_at
                """,
                (challenge_id, name, category, challenge_type, value, self._now()),
            )

    def set_challenge_status(self, challenge_id: int, status: str) -> None:
        allowed = {
            "queued",
            "running",
            "candidate",
            "solved",
            "unsolved",
            "unsupported",
            "error",
        }
        if status not in allowed:
            raise ValueError("invalid challenge status")
        with self.transaction() as connection:
            changed = connection.execute(
                "UPDATE challenges SET status=?, updated_at=? WHERE id=?",
                (status, self._now(), challenge_id),
            ).rowcount
            if changed != 1:
                raise ValueError("challenge is absent")

    def start_attempt(
        self,
        attempt_id: str,
        run_id: str,
        challenge_id: int,
        lane: int,
        model: str,
        effort: str,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO attempts(id, run_id, challenge_id, lane, started_at, status, model, effort)
                VALUES (?, ?, ?, ?, ?, 'running', ?, ?)
                """,
                (attempt_id, run_id, challenge_id, lane, self._now(), model, effort),
            )

    def finish_attempt(
        self,
        attempt_id: str,
        status: str,
        *,
        summary: str = "",
        candidate: str | None = None,
        confidence: float | None = None,
    ) -> None:
        allowed = {
            "candidate",
            "unsolved",
            "timeout",
            "cancelled",
            "interrupted",
            "failed",
            "unsupported",
        }
        if status not in allowed:
            raise ValueError("invalid attempt status")
        if confidence is not None and not 0 <= confidence <= 1:
            raise ValueError("confidence must be in [0, 1]")
        with self.transaction() as connection:
            changed = connection.execute(
                """
                UPDATE attempts
                SET finished_at=?, status=?, summary=?, candidate=?, confidence=?
                WHERE id=? AND status='running'
                """,
                (self._now(), status, summary[:4000], candidate, confidence, attempt_id),
            ).rowcount
            if changed != 1:
                raise ValueError("attempt is absent or not running")

    def event(self, run_id: str, kind: str, data: dict[str, Any]) -> int:
        if not kind or len(kind) > 100:
            raise ValueError("invalid event kind")
        encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_EVENT_BYTES:
            raise ValueError("event data exceeds the durable audit limit")
        with self.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO events(run_id, at, kind, data_json) VALUES (?, ?, ?, ?)",
                (run_id, self._now(), kind, encoded),
            )
            return int(cursor.lastrowid)

    def active_attempts(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM attempts WHERE status='running' ORDER BY started_at, id"
            ).fetchall()
        return [dict(row) for row in rows]

    def attempts_for_challenge(self, run_id: str, challenge_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM attempts
                WHERE run_id=? AND challenge_id=?
                ORDER BY lane, started_at, id
                """,
                (run_id, challenge_id),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _candidate_fingerprint(candidate: str) -> str:
        if not candidate or len(candidate) > 600:
            raise ValueError("invalid candidate")
        return hashlib.sha256(candidate.encode("utf-8")).hexdigest()

    def reserve_submission(self, run_id: str, challenge_id: int, candidate: str) -> bool:
        """Persist a no-retry intent before the Board-side effect starts."""
        fingerprint = self._candidate_fingerprint(candidate)
        with self.transaction() as connection:
            now = self._now()
            changed = connection.execute(
                """
                INSERT OR IGNORE INTO submission_intents(
                    challenge_id, candidate_sha256, first_run_id, reserved_at, status, updated_at
                ) VALUES (?, ?, ?, ?, 'pending', ?)
                """,
                (challenge_id, fingerprint, run_id, now, now),
            ).rowcount
            if changed == 0:
                changed = connection.execute(
                    """
                    UPDATE submission_intents
                    SET first_run_id=?, reserved_at=?, status='pending', updated_at=?
                    WHERE challenge_id=? AND candidate_sha256=? AND status='not_delivered'
                    """,
                    (run_id, now, now, challenge_id, fingerprint),
                ).rowcount
        return changed == 1

    def pending_submission_intents(self) -> list[dict[str, Any]]:
        """Return only non-secret fingerprints requiring explicit reconciliation."""
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT challenge_id, candidate_sha256, first_run_id, reserved_at, updated_at
                FROM submission_intents WHERE status='pending'
                ORDER BY reserved_at, challenge_id, candidate_sha256
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def reconcile_submission_intent(
        self, challenge_id: int, candidate_sha256: str, outcome: str
    ) -> None:
        """Apply an explicit operator finding; never infer an ambiguous Board effect."""
        if (
            type(challenge_id) is not int
            or challenge_id <= 0
            or len(candidate_sha256) != 64
            or any(char not in "0123456789abcdef" for char in candidate_sha256)
        ):
            raise ValueError("invalid submission reconciliation identity")
        if outcome not in {"correct", "incorrect", "not_delivered"}:
            raise ValueError("invalid submission reconciliation outcome")
        with self.transaction() as connection:
            row = connection.execute(
                """
                SELECT first_run_id FROM submission_intents
                WHERE challenge_id=? AND candidate_sha256=? AND status='pending'
                """,
                (challenge_id, candidate_sha256),
            ).fetchone()
            if row is None:
                raise ValueError("pending submission intent was not found")
            connection.execute(
                """
                UPDATE submission_intents SET status=?, updated_at=?
                WHERE challenge_id=? AND candidate_sha256=? AND status='pending'
                """,
                (outcome, self._now(), challenge_id, candidate_sha256),
            )
            connection.execute(
                "INSERT INTO events(run_id, at, kind, data_json) VALUES (?, ?, ?, ?)",
                (
                    row["first_run_id"],
                    self._now(),
                    "submission_reconciliation",
                    json.dumps(
                        {
                            "challenge_id": challenge_id,
                            "candidate_sha256": candidate_sha256,
                            "outcome": outcome,
                            "source": "explicit_operator_input",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )

    def finalize_submission(
        self,
        run_id: str,
        challenge_id: int,
        candidate: str,
        outcome: str,
        http_status: int,
    ) -> int:
        if outcome not in {
            "correct",
            "incorrect",
            "already_solved",
            "paused",
            "ratelimited",
            "unread",
        }:
            raise ValueError("invalid submission outcome")
        fingerprint = self._candidate_fingerprint(candidate)
        with self.transaction() as connection:
            changed = connection.execute(
                """
                UPDATE submission_intents SET status=?, updated_at=?
                WHERE challenge_id=? AND candidate_sha256=? AND status='pending'
                """,
                (outcome, self._now(), challenge_id, fingerprint),
            ).rowcount
            if changed != 1:
                raise ValueError("submission intent is absent, settled, or owned by a prior effect")
            cursor = connection.execute(
                """
                INSERT INTO submissions(
                    run_id, challenge_id, at, candidate_sha256, outcome, http_status
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (run_id, challenge_id, self._now(), fingerprint, outcome, http_status),
            )
            return int(cursor.lastrowid)

    def record_submission(
        self,
        run_id: str,
        challenge_id: int,
        candidate: str,
        outcome: str,
        http_status: int,
    ) -> int:
        if not self.reserve_submission(run_id, challenge_id, candidate):
            raise ValueError("submission candidate was already reserved")
        return self.finalize_submission(run_id, challenge_id, candidate, outcome, http_status)

    def incorrect_submission_count(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM submission_intents WHERE status='incorrect'"
            ).fetchone()
        return int(row["count"])

    def submission_risk_count(self) -> int:
        """Count settled wrongs plus effects whose Board outcome is not safely known."""
        with self._lock:
            row = self._connection.execute(
                """
                SELECT COUNT(*) AS count FROM submission_intents
                WHERE status IN ('incorrect', 'pending', 'unread')
                """
            ).fetchone()
        return int(row["count"])

    def overlapping_wave_count(self, run_id: str) -> int:
        with self._lock:
            rows = self._connection.execute(
                "SELECT data_json FROM events WHERE run_id=? AND kind='attempt_wave'",
                (run_id,),
            ).fetchall()
        count = 0
        for row in rows:
            try:
                document = json.loads(row["data_json"])
            except (TypeError, ValueError):
                continue
            if isinstance(document, dict) and document.get("overlap") is True:
                count += 1
        return count

    def mark_instance(
        self,
        run_id: str,
        challenge_id: int,
        status: str,
        *,
        receipt_sha256: str | None = None,
    ) -> None:
        if status not in {"owned", "cleanup_pending", "removed"}:
            raise ValueError("invalid instance status")
        if status == "owned" and (
            receipt_sha256 is None
            or len(receipt_sha256) != 64
            or any(char not in "0123456789abcdef" for char in receipt_sha256)
        ):
            raise ValueError("owned instance requires a generation receipt")
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO instances(challenge_id, run_id, status, receipt_sha256, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(challenge_id) DO UPDATE SET
                  run_id=excluded.run_id, status=excluded.status,
                  receipt_sha256=COALESCE(excluded.receipt_sha256, instances.receipt_sha256),
                  updated_at=excluded.updated_at
                """,
                (challenge_id, run_id, status, receipt_sha256, self._now()),
            )

    def owned_instances(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT challenge_id, run_id, status, receipt_sha256, updated_at
                FROM instances WHERE status IN ('owned', 'cleanup_pending')
                ORDER BY challenge_id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def recover_interrupted(self) -> int:
        """Close attempts left running by an earlier process; they may be scheduled anew."""
        if not self._lease_files:
            raise RuntimeError("state recovery requires the supervisor lease")
        with self.transaction() as connection:
            now = self._now()
            rows = connection.execute(
                "SELECT run_id, COUNT(*) AS count FROM attempts WHERE status='running' GROUP BY run_id"
            ).fetchall()
            count = connection.execute(
                """
                UPDATE attempts
                SET finished_at=?, status='interrupted', summary='process ended before restart'
                WHERE status='running'
                """,
                (now,),
            ).rowcount
            for row in rows:
                connection.execute(
                    "INSERT INTO events(run_id, at, kind, data_json) VALUES (?, ?, 'recovery', ?)",
                    (
                        row["run_id"],
                        now,
                        json.dumps(
                            {"interrupted_attempts": row["count"]},
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    ),
                )
            connection.execute(
                "UPDATE challenges SET status='queued', updated_at=? WHERE status='running'", (now,)
            )
            connection.execute(
                "UPDATE runs SET finished_at=?, status='interrupted' WHERE status='running'", (now,)
            )
            return int(count)

    def close(self) -> None:
        with self._lock:
            self.release_supervisor()
            self._connection.close()
