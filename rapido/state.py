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

from .routing import (
    FAILURE_ORIGINS,
    KNOWN_FAILURE_CLASSES,
    RouteDecision,
    RouteRequest,
    RouteSpec,
    classify_failure,
    route_failure,
)

MAX_EVENT_BYTES = 128 * 1024
MAX_ATTEMPT_EVIDENCE_ITEMS = 20
MAX_ATTEMPT_EVIDENCE_ITEM_CHARS = 1000

_FAILURE_CLASSES = KNOWN_FAILURE_CLASSES


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
                episode INTEGER NOT NULL DEFAULT 0,
                lane INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                model TEXT NOT NULL,
                effort TEXT NOT NULL,
                summary TEXT NOT NULL DEFAULT '',
                candidate TEXT,
                confidence REAL,
                evidence_json TEXT NOT NULL DEFAULT '[]',
                next_steps_json TEXT NOT NULL DEFAULT '[]',
                tool_count INTEGER NOT NULL DEFAULT 0,
                failure_class TEXT,
                UNIQUE(run_id, challenge_id, episode, lane)
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
            CREATE TABLE IF NOT EXISTS board_identity (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                user_id INTEGER NOT NULL,
                team_id INTEGER NOT NULL,
                bound_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS control_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(id),
                kind TEXT NOT NULL,
                job_id TEXT,
                data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS control_catalogue (
                run_id TEXT NOT NULL REFERENCES runs(id),
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                catalogue_rank INTEGER NOT NULL,
                executable INTEGER NOT NULL CHECK(executable IN (0, 1)),
                PRIMARY KEY(run_id, challenge_id),
                UNIQUE(run_id, catalogue_rank)
            );
            CREATE TABLE IF NOT EXISTS control_routes (
                run_id TEXT NOT NULL REFERENCES runs(id),
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                route_fingerprint TEXT NOT NULL,
                first_episode INTEGER NOT NULL,
                route_json TEXT NOT NULL,
                PRIMARY KEY(run_id, challenge_id, route_fingerprint)
            );
            CREATE TABLE IF NOT EXISTS control_route_decisions (
                decision_sequence INTEGER PRIMARY KEY REFERENCES control_events(sequence),
                run_id TEXT NOT NULL REFERENCES runs(id),
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                source_episode INTEGER NOT NULL,
                failure_kind TEXT NOT NULL,
                failure_subreason TEXT NOT NULL,
                disposition TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                source_route_fingerprint TEXT NOT NULL,
                successor_route_fingerprint TEXT,
                changed_axes_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                UNIQUE(run_id, challenge_id, source_episode)
            );
            CREATE TABLE IF NOT EXISTS control_failure_origins (
                run_id TEXT NOT NULL REFERENCES runs(id),
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                episode INTEGER NOT NULL,
                origin TEXT NOT NULL CHECK(origin IN ('board', 'container')),
                event_sequence INTEGER NOT NULL UNIQUE REFERENCES control_events(sequence),
                PRIMARY KEY(run_id, challenge_id, episode)
            );
            CREATE TABLE IF NOT EXISTS control_jobs (
                job_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES runs(id),
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                episode INTEGER NOT NULL,
                catalogue_rank INTEGER NOT NULL,
                phase TEXT NOT NULL,
                role TEXT NOT NULL,
                lane INTEGER NOT NULL,
                state TEXT NOT NULL,
                route_fingerprint TEXT NOT NULL,
                admitted_sequence INTEGER NOT NULL UNIQUE REFERENCES control_events(sequence),
                started_sequence INTEGER UNIQUE REFERENCES control_events(sequence),
                closed_sequence INTEGER UNIQUE REFERENCES control_events(sequence),
                UNIQUE(run_id, challenge_id, episode, role, lane),
                FOREIGN KEY(run_id, challenge_id, route_fingerprint)
                  REFERENCES control_routes(run_id, challenge_id, route_fingerprint)
            );
            CREATE TABLE IF NOT EXISTS candidate_proposals (
                source_attempt_id TEXT PRIMARY KEY REFERENCES attempts(id),
                run_id TEXT NOT NULL REFERENCES runs(id),
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                episode INTEGER NOT NULL,
                lane INTEGER NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('specialist', 'verifier', 'recovery')),
                recipe_kind TEXT NOT NULL,
                candidate_key BLOB NOT NULL CHECK(length(candidate_key) = 32),
                candidate BLOB NOT NULL,
                retained_at TEXT NOT NULL,
                UNIQUE(source_attempt_id, run_id, challenge_id, role, candidate_key),
                FOREIGN KEY(source_attempt_id, run_id, challenge_id, episode, lane)
                  REFERENCES attempts(id, run_id, challenge_id, episode, lane)
            );
            CREATE INDEX IF NOT EXISTS candidate_proposals_scope
              ON candidate_proposals(run_id, challenge_id, role, candidate_key);
            CREATE TABLE IF NOT EXISTS candidate_verifications (
                run_id TEXT NOT NULL REFERENCES runs(id),
                challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                candidate_key BLOB NOT NULL CHECK(length(candidate_key) = 32),
                producer_attempt_id TEXT NOT NULL REFERENCES candidate_proposals(source_attempt_id),
                producer_role TEXT NOT NULL CHECK(producer_role IN ('specialist', 'recovery')),
                verifier_attempt_id TEXT NOT NULL UNIQUE
                  REFERENCES candidate_proposals(source_attempt_id),
                verifier_role TEXT NOT NULL CHECK(verifier_role = 'verifier'),
                recipe_kind TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                PRIMARY KEY(run_id, challenge_id, candidate_key),
                FOREIGN KEY(producer_attempt_id, run_id, challenge_id, producer_role, candidate_key)
                  REFERENCES candidate_proposals(
                    source_attempt_id, run_id, challenge_id, role, candidate_key
                  ),
                FOREIGN KEY(verifier_attempt_id, run_id, challenge_id, verifier_role, candidate_key)
                  REFERENCES candidate_proposals(
                    source_attempt_id, run_id, challenge_id, role, candidate_key
                  )
            );
            """
        )
        self._migrate_attempts()
        self._connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS attempts_scope_identity "
            "ON attempts(id, run_id, challenge_id, episode, lane)"
        )
        self._migrate_control_jobs()
        instance_columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(instances)").fetchall()
        }
        if "receipt_sha256" not in instance_columns:
            self._connection.execute("ALTER TABLE instances ADD COLUMN receipt_sha256 TEXT")

    def _migrate_control_jobs(self) -> None:
        """Atomically establish control_routes as the sole route JSON authority."""

        def has_route_foreign_key() -> bool:
            mappings = {
                (str(row["from"]), str(row["to"]))
                for row in self._connection.execute(
                    "PRAGMA foreign_key_list(control_jobs)"
                ).fetchall()
                if str(row["table"]) == "control_routes"
            }
            return mappings == {
                ("run_id", "run_id"),
                ("challenge_id", "challenge_id"),
                ("route_fingerprint", "route_fingerprint"),
            }

        if has_route_foreign_key():
            return
        migration_table = "control_jobs__route_authority_migration"
        with self.transaction() as connection:
            if has_route_foreign_key():
                return
            if (
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                    (migration_table,),
                ).fetchone()
                is not None
            ):
                raise RuntimeError("stale control job migration table is present")
            connection.execute(
                """
                INSERT OR IGNORE INTO control_routes(
                  run_id, challenge_id, route_fingerprint, first_episode, route_json
                )
                SELECT run_id, challenge_id, route_fingerprint, MIN(episode),
                       '{"legacy":"route-unavailable"}'
                FROM control_jobs
                GROUP BY run_id, challenge_id, route_fingerprint
                """
            )
            connection.execute(
                f"""
                CREATE TABLE {migration_table} (
                    job_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(id),
                    challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                    episode INTEGER NOT NULL,
                    catalogue_rank INTEGER NOT NULL,
                    phase TEXT NOT NULL,
                    role TEXT NOT NULL,
                    lane INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    route_fingerprint TEXT NOT NULL,
                    admitted_sequence INTEGER NOT NULL UNIQUE REFERENCES control_events(sequence),
                    started_sequence INTEGER UNIQUE REFERENCES control_events(sequence),
                    closed_sequence INTEGER UNIQUE REFERENCES control_events(sequence),
                    UNIQUE(run_id, challenge_id, episode, role, lane),
                    FOREIGN KEY(run_id, challenge_id, route_fingerprint)
                      REFERENCES control_routes(run_id, challenge_id, route_fingerprint)
                )
                """
            )
            connection.execute(
                f"""
                INSERT INTO {migration_table}(
                  job_id, run_id, challenge_id, episode, catalogue_rank, phase,
                  role, lane, state, route_fingerprint, admitted_sequence,
                  started_sequence, closed_sequence
                )
                SELECT job_id, run_id, challenge_id, episode, catalogue_rank, phase,
                       role, lane, state, route_fingerprint, admitted_sequence,
                       started_sequence, closed_sequence
                FROM control_jobs
                """
            )
            connection.execute("DROP TABLE control_jobs")
            connection.execute(f"ALTER TABLE {migration_table} RENAME TO control_jobs")

    def _migrate_attempts(self) -> None:
        """Atomically upgrade the pre-episode attempts table, retaining every row."""
        required = {
            "episode",
            "evidence_json",
            "next_steps_json",
            "tool_count",
            "failure_class",
        }

        def inspect_schema() -> tuple[set[str], list[tuple[str, ...]]]:
            columns = {
                str(row["name"])
                for row in self._connection.execute("PRAGMA table_info(attempts)").fetchall()
            }
            unique_columns: list[tuple[str, ...]] = []
            for index in self._connection.execute("PRAGMA index_list(attempts)").fetchall():
                if not index["unique"]:
                    continue
                name = index["name"]
                if not isinstance(name, str):
                    continue
                quoted_name = '"' + name.replace('"', '""') + '"'
                unique_columns.append(
                    tuple(
                        str(item["name"])
                        for item in self._connection.execute(
                            f"PRAGMA index_info({quoted_name})"
                        ).fetchall()
                        if item["name"] is not None
                    )
                )
            return columns, unique_columns

        expected_unique = ("run_id", "challenge_id", "episode", "lane")
        legacy_unique = ("run_id", "challenge_id", "lane")

        def is_current(columns: set[str], unique_columns: list[tuple[str, ...]]) -> bool:
            return (
                required <= columns
                and expected_unique in unique_columns
                and legacy_unique not in unique_columns
            )

        columns, unique_columns = inspect_schema()
        if is_current(columns, unique_columns):
            return

        # The table is created by the schema script above, so a missing legacy
        # column only matters for a database created by an older Rapido build.
        migration_table = f"attempts__rapido_migration_{id(self)}"
        existing = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (migration_table,)
        ).fetchone()
        if existing is not None:
            raise RuntimeError("stale attempts migration table is present")

        def source(column: str, fallback: str) -> str:
            return column if column in columns else fallback

        with self.transaction() as connection:
            # Re-read under the write lock so a concurrent opener cannot
            # migrate a newer schema back to legacy defaults.
            columns, unique_columns = inspect_schema()
            if is_current(columns, unique_columns):
                return

            connection.execute(
                f"""
                CREATE TABLE {migration_table} (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(id),
                    challenge_id INTEGER NOT NULL REFERENCES challenges(id),
                    episode INTEGER NOT NULL DEFAULT 0,
                    lane INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    model TEXT NOT NULL,
                    effort TEXT NOT NULL,
                    summary TEXT NOT NULL DEFAULT '',
                    candidate TEXT,
                    confidence REAL,
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    next_steps_json TEXT NOT NULL DEFAULT '[]',
                    tool_count INTEGER NOT NULL DEFAULT 0,
                    failure_class TEXT,
                    UNIQUE(run_id, challenge_id, episode, lane)
                )
                """
            )
            connection.execute(
                f"""
                INSERT INTO {migration_table}(
                    id, run_id, challenge_id, episode, lane, started_at, finished_at,
                    status, model, effort, summary, candidate, confidence,
                    evidence_json, next_steps_json, tool_count, failure_class
                )
                SELECT
                    id, run_id, challenge_id, {source("episode", "0")}, lane, started_at,
                    finished_at, status, model, effort, {source("summary", "''")}, candidate,
                    {source("confidence", "NULL")}, {source("evidence_json", "'[]'")},
                    {source("next_steps_json", "'[]'")}, {source("tool_count", "0")},
                    {source("failure_class", "NULL")}
                FROM attempts
                """
            )
            connection.execute("DROP TABLE attempts")
            connection.execute(f"ALTER TABLE {migration_table} RENAME TO attempts")

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

    def bind_board_identity(self, user_id: int, team_id: int) -> None:
        """Bind durable ownership and submission accounting to one Board identity."""
        if type(user_id) is not int or user_id <= 0 or type(team_id) is not int or team_id <= 0:
            raise ValueError("Board identity must contain positive user and team ids")
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT user_id, team_id FROM board_identity WHERE singleton=1"
            ).fetchone()
            if row is None:
                legacy_effects = connection.execute(
                    """
                    SELECT
                      (SELECT COUNT(*) FROM submission_intents) +
                      (SELECT COUNT(*) FROM instances
                       WHERE status IN ('creating', 'owned', 'cleanup_pending')) AS count
                    """
                ).fetchone()["count"]
                if legacy_effects:
                    raise RuntimeError(
                        "legacy state has unbound external effects; use its original identity or a new state"
                    )
                connection.execute(
                    "INSERT INTO board_identity(singleton, user_id, team_id, bound_at) VALUES (1, ?, ?, ?)",
                    (user_id, team_id, self._now()),
                )
            elif (row["user_id"], row["team_id"]) != (user_id, team_id):
                raise RuntimeError("state is bound to a different qualified Board identity")

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
        episode: int = 0,
        lane: int | str | None = None,
        model: str | None = None,
        effort: str | None = None,
    ) -> None:
        # Accept the pre-episode positional form while callers migrate to the
        # canonical (episode, lane, model, effort) form.
        if effort is None:
            if lane is None or model is None:
                raise TypeError("start_attempt requires lane, model, and effort")
            lane, model, effort, episode = episode, lane, model, 0
        if type(episode) is not int or episode < 0:
            raise ValueError("episode must be a nonnegative integer")
        if type(lane) is not int or model is None or not isinstance(effort, str):
            raise ValueError("invalid attempt identity")
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO attempts(
                    id, run_id, challenge_id, episode, lane, started_at, status, model, effort
                ) VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?)
                """,
                (attempt_id, run_id, challenge_id, episode, lane, self._now(), model, effort),
            )

    @staticmethod
    def _encode_attempt_evidence(name: str, value: list[str] | tuple[str, ...]) -> str:
        if (
            not isinstance(value, (list, tuple))
            or len(value) > MAX_ATTEMPT_EVIDENCE_ITEMS
            or any(
                not isinstance(item, str) or len(item) > MAX_ATTEMPT_EVIDENCE_ITEM_CHARS
                for item in value
            )
        ):
            raise ValueError(
                f"{name} must contain at most {MAX_ATTEMPT_EVIDENCE_ITEMS} strings "
                f"of at most {MAX_ATTEMPT_EVIDENCE_ITEM_CHARS} characters"
            )
        encoded = json.dumps(list(value), ensure_ascii=False, separators=(",", ":"))
        try:
            encoded_size = len(encoded.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValueError(f"{name} contains invalid text") from exc
        if encoded_size > MAX_EVENT_BYTES:
            raise ValueError(f"{name} exceeds the durable audit limit")
        return encoded

    @staticmethod
    def _decode_attempt_evidence(value: object) -> list[str]:
        try:
            decoded = json.loads(value) if isinstance(value, str) else None
        except (TypeError, ValueError, RecursionError):
            decoded = None
        if (
            not isinstance(decoded, list)
            or len(decoded) > MAX_ATTEMPT_EVIDENCE_ITEMS
            or any(
                not isinstance(item, str) or len(item) > MAX_ATTEMPT_EVIDENCE_ITEM_CHARS
                for item in decoded
            )
        ):
            return []
        return decoded

    def finish_attempt(
        self,
        attempt_id: str,
        status: str,
        *,
        summary: str = "",
        candidate: str | None = None,
        confidence: float | None = None,
        evidence: list[str] | tuple[str, ...] = (),
        next_steps: list[str] | tuple[str, ...] = (),
        tool_count: int = 0,
        failure_class: str | None = None,
        retain_private_candidate: bool = False,
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
        evidence_json = self._encode_attempt_evidence("evidence", evidence)
        next_steps_json = self._encode_attempt_evidence("next_steps", next_steps)
        if type(tool_count) is not int or not 0 <= tool_count <= 100:
            raise ValueError("tool_count must be an integer in [0, 100]")
        if failure_class is not None and (
            not isinstance(failure_class, str) or failure_class not in _FAILURE_CLASSES
        ):
            raise ValueError("failure_class is not a recognized closed class")
        if type(retain_private_candidate) is not bool:
            raise TypeError("retain_private_candidate must be boolean")
        if retain_private_candidate and (status != "candidate" or candidate is None):
            raise ValueError("private candidate retention requires a candidate attempt")
        stored_candidate = None if retain_private_candidate else candidate
        with self.transaction() as connection:
            attempt = connection.execute(
                "SELECT run_id, challenge_id, episode, lane FROM attempts "
                "WHERE id=? AND status='running'",
                (attempt_id,),
            ).fetchone()
            if attempt is None:
                raise ValueError("attempt is absent or not running")
            changed = connection.execute(
                """
                UPDATE attempts
                SET finished_at=?, status=?, summary=?, candidate=?, confidence=?,
                    evidence_json=?, next_steps_json=?, tool_count=?, failure_class=?
                WHERE id=? AND status='running'
                """,
                (
                    self._now(),
                    status,
                    summary[:4000],
                    stored_candidate,
                    confidence,
                    evidence_json,
                    next_steps_json,
                    tool_count,
                    failure_class,
                    attempt_id,
                ),
            ).rowcount
            if changed != 1:
                raise ValueError("attempt is absent or not running")
            if retain_private_candidate:
                assert candidate is not None
                self._retain_candidate(
                    connection,
                    attempt_id=attempt_id,
                    run_id=str(attempt["run_id"]),
                    challenge_id=int(attempt["challenge_id"]),
                    episode=int(attempt["episode"]),
                    lane=int(attempt["lane"]),
                    candidate=candidate,
                )

    def _retain_candidate(
        self,
        connection: sqlite3.Connection,
        *,
        attempt_id: str,
        run_id: str,
        challenge_id: int,
        episode: int,
        lane: int,
        candidate: str,
    ) -> None:
        encoded = candidate.encode("utf-8")
        if not encoded or len(candidate) > 600:
            raise ValueError("invalid private candidate")
        route = connection.execute(
            """
            SELECT jobs.role, routes.route_json
            FROM control_jobs AS jobs
            JOIN control_routes AS routes
              ON routes.run_id=jobs.run_id
             AND routes.challenge_id=jobs.challenge_id
             AND routes.route_fingerprint=jobs.route_fingerprint
            WHERE jobs.run_id=? AND jobs.challenge_id=? AND jobs.episode=? AND jobs.lane=?
              AND jobs.state='running'
            """,
            (run_id, challenge_id, episode, lane),
        ).fetchone()
        if route is None:
            raise ValueError("private candidate has no running control job")
        role = str(route["role"])
        try:
            route_spec = RouteSpec.from_dict(json.loads(str(route["route_json"])))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("private candidate route is invalid") from exc
        if route_spec.role != role:
            raise ValueError("private candidate route role changed")
        if role == "verifier":
            recipe = route_spec.verification_recipe
            if recipe != "fresh_source_reobservation_v1":
                raise ValueError("verifier candidate lacks the approved recipe")
        elif role in {"specialist", "recovery"}:
            recipe = "source_bound_tool_observation_v1"
        else:
            raise ValueError("private candidate role is invalid")
        candidate_key = hashlib.sha256(encoded).digest()
        connection.execute(
            """
            INSERT INTO candidate_proposals(
              source_attempt_id, run_id, challenge_id, episode, lane, role,
              recipe_kind, candidate_key, candidate, retained_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                run_id,
                challenge_id,
                episode,
                lane,
                role,
                recipe,
                candidate_key,
                encoded,
                self._now(),
            ),
        )
        if role != "verifier":
            return
        producer = connection.execute(
            """
            SELECT source_attempt_id, role
            FROM candidate_proposals
            WHERE run_id=? AND challenge_id=? AND role IN ('specialist', 'recovery')
              AND candidate_key=? AND candidate=?
            ORDER BY episode, source_attempt_id
            LIMIT 1
            """,
            (run_id, challenge_id, candidate_key, encoded),
        ).fetchone()
        if producer is not None:
            connection.execute(
                """
                INSERT OR IGNORE INTO candidate_verifications(
                  run_id, challenge_id, candidate_key, producer_attempt_id, producer_role,
                  verifier_attempt_id, verifier_role, recipe_kind, verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'verifier', ?, ?)
                """,
                (
                    run_id,
                    challenge_id,
                    candidate_key,
                    producer["source_attempt_id"],
                    producer["role"],
                    attempt_id,
                    recipe,
                    self._now(),
                ),
            )

    def candidate_counts(self, run_id: str) -> tuple[int, int]:
        """Return aggregate pending and verified producer identities for one run."""
        with self._lock:
            pending = int(
                self._connection.execute(
                    """
                    SELECT COUNT(*) FROM (
                      SELECT proposal.challenge_id, proposal.candidate_key
                      FROM candidate_proposals AS proposal
                      WHERE proposal.run_id=? AND proposal.role IN ('specialist', 'recovery')
                        AND NOT EXISTS (
                          SELECT 1 FROM candidate_verifications AS verification
                          WHERE verification.run_id=proposal.run_id
                            AND verification.challenge_id=proposal.challenge_id
                            AND verification.candidate_key=proposal.candidate_key
                        )
                      GROUP BY proposal.challenge_id, proposal.candidate_key
                    )
                    """,
                    (run_id,),
                ).fetchone()[0]
            )
            verified = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM candidate_verifications WHERE run_id=?", (run_id,)
                ).fetchone()[0]
            )
        return pending, verified

    def pending_candidate_count(self, run_id: str, challenge_id: int) -> int:
        with self._lock:
            return int(
                self._connection.execute(
                    """
                    SELECT COUNT(DISTINCT proposal.candidate_key)
                    FROM candidate_proposals AS proposal
                    WHERE proposal.run_id=? AND proposal.challenge_id=?
                      AND proposal.role IN ('specialist', 'recovery')
                      AND NOT EXISTS (
                        SELECT 1 FROM candidate_verifications AS verification
                        WHERE verification.run_id=proposal.run_id
                          AND verification.challenge_id=proposal.challenge_id
                          AND verification.candidate_key=proposal.candidate_key
                      )
                    """,
                    (run_id, challenge_id),
                ).fetchone()[0]
            )

    def verified_candidate(self, run_id: str, challenge_id: int) -> str | None:
        """Return one privately verified value to the effect-owning controller only."""
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT proposal.candidate
                FROM candidate_verifications AS verification
                JOIN candidate_proposals AS proposal
                  ON proposal.source_attempt_id=verification.producer_attempt_id
                WHERE verification.run_id=? AND verification.challenge_id=?
                ORDER BY verification.verified_at, verification.candidate_key
                """,
                (run_id, challenge_id),
            ).fetchall()
        if len(rows) != 1:
            return None
        try:
            return bytes(rows[0]["candidate"]).decode("utf-8")
        except (TypeError, UnicodeDecodeError) as exc:
            raise ValueError("verified private candidate is invalid") from exc

    def candidate_is_verified(self, run_id: str, challenge_id: int, candidate: str) -> bool:
        if not candidate or len(candidate) > 600:
            raise ValueError("invalid private candidate")
        try:
            encoded = candidate.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("invalid private candidate") from exc
        candidate_key = hashlib.sha256(encoded).digest()
        with self._lock:
            row = self._connection.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN verification.candidate_key=? AND producer.candidate=?
                                THEN 1 ELSE 0 END) AS matching
                FROM candidate_verifications AS verification
                JOIN candidate_proposals AS producer
                  ON producer.source_attempt_id=verification.producer_attempt_id
                WHERE verification.run_id=? AND verification.challenge_id=?
                """,
                (candidate_key, encoded, run_id, challenge_id),
            ).fetchone()
        return row is not None and int(row["total"]) == 1 and int(row["matching"] or 0) == 1

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

    @staticmethod
    def _control_event(
        connection: sqlite3.Connection,
        run_id: str,
        kind: str,
        job_id: str | None,
        data: dict[str, object],
    ) -> int:
        cursor = connection.execute(
            "INSERT INTO control_events(run_id, kind, job_id, data_json) VALUES (?, ?, ?, ?)",
            (run_id, kind, job_id, json.dumps(data, sort_keys=True, separators=(",", ":"))),
        )
        return int(cursor.lastrowid)

    @classmethod
    def _admit_control_wave(
        cls,
        connection: sqlite3.Connection,
        run_id: str,
        challenge_id: int,
        episode: int,
        catalogue_rank: int,
        lanes: int,
        route: RouteSpec,
        *,
        require_unused_route: bool,
    ) -> None:
        phase = "initial" if episode == 0 else "retry"
        route_json = json.dumps(route.as_dict(), sort_keys=True, separators=(",", ":"))
        fingerprint = route.fingerprint
        inserted = connection.execute(
            """
            INSERT OR IGNORE INTO control_routes(
              run_id, challenge_id, route_fingerprint, first_episode, route_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (run_id, challenge_id, fingerprint, episode, route_json),
        ).rowcount
        if require_unused_route and inserted != 1:
            raise ValueError("control route was already admitted")
        for lane in range(lanes):
            job_id = f"{run_id}:{challenge_id}:{episode}:{route.role}:{lane}"
            sequence = cls._control_event(
                connection,
                run_id,
                "job_admitted",
                job_id,
                {
                    "catalogue_rank": catalogue_rank,
                    "challenge_id": challenge_id,
                    "episode": episode,
                    "lane": lane,
                    "phase": phase,
                    "role": route.role,
                },
            )
            connection.execute(
                """
                INSERT INTO control_jobs(
                  job_id, run_id, challenge_id, episode, catalogue_rank,
                  phase, role, lane, state, route_fingerprint, admitted_sequence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)
                """,
                (
                    job_id,
                    run_id,
                    challenge_id,
                    episode,
                    catalogue_rank,
                    phase,
                    route.role,
                    lane,
                    fingerprint,
                    sequence,
                ),
            )

    def admit_control_wave(
        self,
        run_id: str,
        challenge_id: int,
        episode: int,
        catalogue_rank: int,
        lanes: int,
        route: RouteSpec,
    ) -> None:
        with self.transaction() as connection:
            self._admit_control_wave(
                connection,
                run_id,
                challenge_id,
                episode,
                catalogue_rank,
                lanes,
                route,
                require_unused_route=False,
            )

    def record_control_catalogue(self, run_id: str, entries: list[tuple[int, int, bool]]) -> None:
        with self.transaction() as connection:
            connection.executemany(
                """
                INSERT INTO control_catalogue(run_id, challenge_id, catalogue_rank, executable)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (run_id, challenge_id, catalogue_rank, int(executable))
                    for catalogue_rank, challenge_id, executable in entries
                ],
            )

    def start_control_wave(self, run_id: str, challenge_id: int, episode: int) -> None:
        with self.transaction() as connection:
            rows = connection.execute(
                "SELECT job_id, lane FROM control_jobs "
                "WHERE run_id=? AND challenge_id=? AND episode=? AND state='queued' ORDER BY lane",
                (run_id, challenge_id, episode),
            ).fetchall()
            if not rows:
                raise ValueError("control wave is absent or not queued")
            for row in rows:
                sequence = self._control_event(
                    connection,
                    run_id,
                    "job_started",
                    str(row["job_id"]),
                    {"challenge_id": challenge_id, "episode": episode, "lane": int(row["lane"])},
                )
                connection.execute(
                    "UPDATE control_jobs SET state='running', started_sequence=? WHERE job_id=?",
                    (sequence, row["job_id"]),
                )

    @classmethod
    def _finish_control_wave(
        cls,
        connection: sqlite3.Connection,
        run_id: str,
        challenge_id: int,
        episode: int,
        terminal: str,
    ) -> None:
        rows = connection.execute(
            "SELECT job_id, lane FROM control_jobs "
            "WHERE run_id=? AND challenge_id=? AND episode=? AND state='running' ORDER BY lane",
            (run_id, challenge_id, episode),
        ).fetchall()
        if not rows:
            raise ValueError("control wave is absent or not running")
        for row in rows:
            attempt = connection.execute(
                "SELECT status FROM attempts "
                "WHERE run_id=? AND challenge_id=? AND episode=? AND lane=?",
                (run_id, challenge_id, episode, row["lane"]),
            ).fetchone()
            lane_state = (
                str(attempt["status"])
                if attempt is not None
                else ("failed" if terminal == "error" else "cancelled")
            )
            sequence = cls._control_event(
                connection,
                run_id,
                "job_closed",
                str(row["job_id"]),
                {
                    "challenge_id": challenge_id,
                    "episode": episode,
                    "lane": int(row["lane"]),
                    "lane_state": lane_state,
                    "terminal": terminal,
                },
            )
            connection.execute(
                "UPDATE control_jobs SET state=?, closed_sequence=? WHERE job_id=?",
                (lane_state, sequence, row["job_id"]),
            )

    def finish_control_wave(
        self, run_id: str, challenge_id: int, episode: int, terminal: str
    ) -> None:
        with self.transaction() as connection:
            self._finish_control_wave(connection, run_id, challenge_id, episode, terminal)

    def record_control_failure_origin(
        self,
        run_id: str,
        challenge_id: int,
        episode: int,
        origin: str,
    ) -> None:
        if origin not in FAILURE_ORIGINS:
            raise ValueError("control failure origin is invalid")
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT origin FROM control_failure_origins "
                "WHERE run_id=? AND challenge_id=? AND episode=?",
                (run_id, challenge_id, episode),
            ).fetchone()
            if existing is not None:
                current = str(existing["origin"])
                if current == origin or current == "board":
                    return
                if current != "container" or origin != "board":
                    raise ValueError("control failure origin transition is invalid")
                sequence = self._control_event(
                    connection,
                    run_id,
                    "failure_origin_escalated",
                    None,
                    {
                        "challenge_id": challenge_id,
                        "episode": episode,
                        "from": current,
                        "to": origin,
                    },
                )
                connection.execute(
                    "UPDATE control_failure_origins SET origin=?, event_sequence=? "
                    "WHERE run_id=? AND challenge_id=? AND episode=?",
                    (origin, sequence, run_id, challenge_id, episode),
                )
                return
            sequence = self._control_event(
                connection,
                run_id,
                "failure_origin_recorded",
                None,
                {
                    "challenge_id": challenge_id,
                    "episode": episode,
                    "origin": origin,
                },
            )
            connection.execute(
                "INSERT INTO control_failure_origins("
                "run_id, challenge_id, episode, origin, event_sequence) VALUES (?, ?, ?, ?, ?)",
                (run_id, challenge_id, episode, origin, sequence),
            )

    def _decide_control_successor(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        challenge_id: int,
        source_episode: int,
        next_episode: int,
        catalogue_rank: int,
        lanes: int,
        terminal: str,
        attempts_remaining: bool,
        remaining_milliseconds: int,
    ) -> RouteDecision | None:
        route_rows = connection.execute(
            """
            SELECT DISTINCT routes.route_json
            FROM control_jobs AS jobs
            JOIN control_routes AS routes
              ON routes.run_id=jobs.run_id
             AND routes.challenge_id=jobs.challenge_id
             AND routes.route_fingerprint=jobs.route_fingerprint
            WHERE jobs.run_id=? AND jobs.challenge_id=? AND jobs.episode=?
            """,
            (run_id, challenge_id, source_episode),
        ).fetchall()
        if len(route_rows) != 1:
            raise ValueError("source control wave has no unique durable route")
        try:
            current = RouteSpec.from_dict(json.loads(str(route_rows[0]["route_json"])))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("source control route is invalid") from exc
        attempts = connection.execute(
            "SELECT failure_class FROM attempts "
            "WHERE run_id=? AND challenge_id=? AND episode=? ORDER BY lane",
            (run_id, challenge_id, source_episode),
        ).fetchall()
        failure_classes = frozenset(
            str(row["failure_class"]) for row in attempts if row["failure_class"] is not None
        )
        candidate_identity_count = int(
            connection.execute(
                """
                SELECT COUNT(DISTINCT candidate_key)
                FROM candidate_proposals
                WHERE run_id=? AND challenge_id=? AND episode=?
                  AND role IN ('specialist', 'recovery')
                """,
                (run_id, challenge_id, source_episode),
            ).fetchone()[0]
        )
        origin_row = connection.execute(
            "SELECT origin FROM control_failure_origins "
            "WHERE run_id=? AND challenge_id=? AND episode=?",
            (run_id, challenge_id, source_episode),
        ).fetchone()
        signal = classify_failure(
            terminal=terminal,
            failure_origin=None if origin_row is None else str(origin_row["origin"]),
            failure_classes=failure_classes,
            candidate_identity_count=candidate_identity_count,
            attempt_count=len(attempts),
        )
        if signal is None:
            return None
        used_fingerprints = frozenset(
            str(row["route_fingerprint"])
            for row in connection.execute(
                "SELECT route_fingerprint FROM control_routes WHERE run_id=? AND challenge_id=?",
                (run_id, challenge_id),
            ).fetchall()
        )
        effects_safe = (
            int(
                connection.execute(
                    "SELECT COUNT(*) FROM submission_intents WHERE status='pending'"
                ).fetchone()[0]
            )
            == 0
        )
        instances_safe = (
            int(
                connection.execute(
                    "SELECT COUNT(*) FROM instances "
                    "WHERE status IN ('creating', 'owned', 'cleanup_pending')"
                ).fetchone()[0]
            )
            == 0
        )
        decision = route_failure(
            RouteRequest(
                failure=signal,
                current=current,
                used_fingerprints=used_fingerprints,
                attempts_remaining=attempts_remaining,
                remaining_milliseconds=remaining_milliseconds,
                effects_safe=effects_safe,
                instances_safe=instances_safe,
            )
        )
        successor_fingerprint = (
            None if decision.successor is None else decision.successor.fingerprint
        )
        decision_sequence = self._control_event(
            connection,
            run_id,
            "failure_route_decision",
            None,
            {
                "challenge_id": challenge_id,
                "changed_axes": list(decision.changed_axes),
                "disposition": decision.disposition,
                "failure_kind": signal.kind,
                "failure_subreason": signal.subreason,
                "rule_id": decision.rule_id,
                "source_episode": source_episode,
                "source_route_fingerprint": decision.source_fingerprint,
                "successor_route_fingerprint": successor_fingerprint,
            },
        )
        connection.execute(
            """
            INSERT INTO control_route_decisions(
              decision_sequence, run_id, challenge_id, source_episode,
              failure_kind, failure_subreason, disposition, rule_id,
              source_route_fingerprint, successor_route_fingerprint,
              changed_axes_json, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision_sequence,
                run_id,
                challenge_id,
                source_episode,
                signal.kind,
                signal.subreason,
                decision.disposition,
                decision.rule_id,
                decision.source_fingerprint,
                successor_fingerprint,
                json.dumps(list(decision.changed_axes), separators=(",", ":")),
                decision.reason,
            ),
        )
        if decision.disposition == "dispatch":
            if decision.successor is None:
                raise AssertionError("dispatch requires a successor route")
            self._admit_control_wave(
                connection,
                run_id,
                challenge_id,
                next_episode,
                catalogue_rank,
                lanes,
                decision.successor,
                require_unused_route=True,
            )
        return decision

    def finish_and_decide_control_wave(
        self,
        *,
        run_id: str,
        challenge_id: int,
        source_episode: int,
        next_episode: int,
        catalogue_rank: int,
        lanes: int,
        terminal: str,
        attempts_remaining: bool,
        remaining_milliseconds: int,
    ) -> RouteDecision | None:
        """Close a wave, decide, record, and admit its successor in one transaction."""
        with self.transaction() as connection:
            self._finish_control_wave(connection, run_id, challenge_id, source_episode, terminal)
            return self._decide_control_successor(
                connection,
                run_id=run_id,
                challenge_id=challenge_id,
                source_episode=source_episode,
                next_episode=next_episode,
                catalogue_rank=catalogue_rank,
                lanes=lanes,
                terminal=terminal,
                attempts_remaining=attempts_remaining,
                remaining_milliseconds=remaining_milliseconds,
            )

    @classmethod
    def _interrupt_control_jobs(
        cls, connection: sqlite3.Connection, run_id: str, reason: str
    ) -> int:
        rows = connection.execute(
            "SELECT job_id, challenge_id, episode, lane FROM control_jobs "
            "WHERE run_id=? AND state IN ('queued', 'running') ORDER BY admitted_sequence",
            (run_id,),
        ).fetchall()
        for row in rows:
            attempt = connection.execute(
                "SELECT status FROM attempts "
                "WHERE run_id=? AND challenge_id=? AND episode=? AND lane=?",
                (run_id, row["challenge_id"], row["episode"], row["lane"]),
            ).fetchone()
            attempt_state = None if attempt is None else str(attempt["status"])
            job_state = (
                attempt_state
                if attempt_state is not None and attempt_state != "running"
                else "interrupted"
            )
            sequence = cls._control_event(
                connection,
                run_id,
                "job_closed" if job_state != "interrupted" else "job_interrupted",
                str(row["job_id"]),
                {
                    "challenge_id": int(row["challenge_id"]),
                    "episode": int(row["episode"]),
                    "lane_state": job_state,
                    "lane": int(row["lane"]),
                    "reason": reason,
                },
            )
            connection.execute(
                "UPDATE control_jobs SET state=?, closed_sequence=? WHERE job_id=?",
                (job_state, sequence, row["job_id"]),
            )
        return len(rows)

    def interrupt_control_run(self, run_id: str, reason: str) -> int:
        with self.transaction() as connection:
            return self._interrupt_control_jobs(connection, run_id, reason)

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

    def prior_attempts_for_lane(
        self,
        run_id: str,
        challenge_id: int,
        lane: int,
        *,
        before_episode: int | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return terminal carryable lane history without candidate values."""
        if before_episode is not None and (type(before_episode) is not int or before_episode < 0):
            raise ValueError("before_episode must be a nonnegative integer")
        if limit is not None and (type(limit) is not int or not 1 <= limit <= 100):
            raise ValueError("limit must be an integer in [1, 100]")
        conditions = ["run_id=?", "challenge_id=?", "lane=?"]
        parameters: list[object] = [run_id, challenge_id, lane]
        conditions.append("status NOT IN ('running', 'candidate')")
        if before_episode is not None:
            conditions.append("episode < ?")
            parameters.append(before_episode)
        query = f"""
            SELECT episode, status, summary, evidence_json, next_steps_json,
                   tool_count, failure_class
            FROM attempts
            WHERE {" AND ".join(conditions)}
            ORDER BY episode DESC, started_at DESC, id DESC
        """
        if limit is not None:
            query += " LIMIT ?"
            parameters.append(limit)
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        rows = list(reversed(rows))
        return [
            {
                "episode": row["episode"],
                "status": row["status"],
                "summary": row["summary"],
                "evidence": self._decode_attempt_evidence(row["evidence_json"]),
                "next_steps": self._decode_attempt_evidence(row["next_steps_json"]),
                "tool_count": row["tool_count"],
                "failure_class": row["failure_class"],
            }
            for row in rows
        ]

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
        if status not in {"creating", "owned", "cleanup_pending", "removed"}:
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
                  receipt_sha256=CASE
                    WHEN excluded.status='creating' THEN NULL
                    ELSE COALESCE(excluded.receipt_sha256, instances.receipt_sha256)
                  END,
                  updated_at=excluded.updated_at
                """,
                (challenge_id, run_id, status, receipt_sha256, self._now()),
            )

    def owned_instances(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT challenge_id, run_id, status, receipt_sha256, updated_at
                FROM instances WHERE status IN ('creating', 'owned', 'cleanup_pending')
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
            interrupted_run_ids = [
                str(row["id"])
                for row in connection.execute(
                    "SELECT id FROM runs WHERE status='running' ORDER BY started_at, id"
                ).fetchall()
            ]
            for interrupted_run_id in interrupted_run_ids:
                self._interrupt_control_jobs(connection, interrupted_run_id, "supervisor_restart")
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
