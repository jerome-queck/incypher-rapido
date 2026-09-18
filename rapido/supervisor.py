"""Long-lived container supervisor for disposable Rapido worker processes."""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import math
import os
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Self

RESTART_BACKOFF_SECONDS = (5.0, 30.0, 120.0)
_RECORD_VERSION = 1
_RECORD_PHASES = frozenset({"active", "blocked", "scheduled", "stopping", "terminal"})
_TERMINAL_RUN_STATES = frozenset({"completed", "deadline", "failed", "interrupted"})
_FINGERPRINT_TABLES = {
    "runs": ("id", "status", "started_at", "finished_at", "config_json"),
    "submission_intents": (
        "challenge_id",
        "candidate_sha256",
        "first_run_id",
        "context_episode",
        "context_sha256",
        "status",
        "updated_at",
    ),
    "instances": ("challenge_id", "run_id", "status", "receipt_sha256", "updated_at"),
    "control_catalogue": (
        "run_id",
        "challenge_id",
        "catalogue_rank",
        "executable",
        "context_sha256",
        "context_episode",
    ),
    "control_jobs": (
        "job_id",
        "run_id",
        "challenge_id",
        "episode",
        "state",
        "started_sequence",
        "closed_sequence",
    ),
}
_PRISTINE_SCHEMA_TABLES = frozenset(
    {
        "attempts",
        "board_identity",
        "candidate_evidence_proofs",
        "candidate_proposals",
        "candidate_verification_history",
        "candidate_verifications",
        "challenges",
        "control_catalogue",
        "control_events",
        "control_failure_origins",
        "control_jobs",
        "control_route_comparison_decision_facts",
        "control_route_comparison_decisions",
        "control_route_comparison_facts",
        "control_route_decisions",
        "control_routes",
        "events",
        "instances",
        "runs",
        "submission_intents",
        "submissions",
    }
)
_PRISTINE_SCHEMA_COLUMNS = {
    "runs": ("id", "started_at", "finished_at", "status", "config_json"),
    "attempts": (
        "id",
        "run_id",
        "challenge_id",
        "episode",
        "lane",
        "started_at",
        "finished_at",
        "status",
        "model",
        "effort",
        "summary",
        "candidate",
        "confidence",
        "evidence_json",
        "next_steps_json",
        "checkpoint_observations_json",
        "tool_count",
        "failure_class",
    ),
    "events": ("sequence", "run_id", "at", "kind", "data_json"),
    "submissions": (
        "sequence",
        "run_id",
        "challenge_id",
        "at",
        "candidate_sha256",
        "context_episode",
        "outcome",
        "http_status",
    ),
    "submission_intents": (
        "challenge_id",
        "candidate_sha256",
        "first_run_id",
        "context_episode",
        "context_sha256",
        "reserved_at",
        "status",
        "updated_at",
    ),
    "instances": ("challenge_id", "run_id", "status", "receipt_sha256", "updated_at"),
    "control_events": ("sequence", "run_id", "kind", "job_id", "data_json"),
    "control_catalogue": (
        "run_id",
        "challenge_id",
        "catalogue_rank",
        "executable",
        "context_sha256",
        "context_episode",
    ),
    "control_jobs": (
        "job_id",
        "run_id",
        "challenge_id",
        "episode",
        "catalogue_rank",
        "phase",
        "role",
        "agent_role",
        "model",
        "effort",
        "lane",
        "state",
        "route_fingerprint",
        "admitted_sequence",
        "started_sequence",
        "closed_sequence",
    ),
}


class SupervisorRefused(RuntimeError):
    """Durable state cannot safely authorize a worker process."""


@dataclass(frozen=True)
class DurableRun:
    run_id: str
    status: str


@dataclass(frozen=True)
class SupervisorRecord:
    version: int
    phase: str
    run_id: str | None
    replacement_count: int
    not_before: float
    disposition: str | None
    state_fingerprint: str | None
    updated_at: float

    def validate(self) -> None:
        if (
            self.version != _RECORD_VERSION
            or not isinstance(self.phase, str)
            or self.phase not in _RECORD_PHASES
        ):
            raise SupervisorRefused("supervisor record has an unsupported shape")
        if self.run_id is not None and (not self.run_id or len(self.run_id) > 200):
            raise SupervisorRefused("supervisor record has an invalid run identity")
        if type(self.replacement_count) is not int or not 0 <= self.replacement_count <= 100:
            raise SupervisorRefused("supervisor record has an invalid replacement count")
        if (
            not isinstance(self.not_before, (int, float))
            or isinstance(self.not_before, bool)
            or not math.isfinite(self.not_before)
        ):
            raise SupervisorRefused("supervisor record has an invalid restart time")
        if self.disposition is not None and (
            not isinstance(self.disposition, str)
            or not self.disposition
            or len(self.disposition) > 100
        ):
            raise SupervisorRefused("supervisor record has an invalid disposition")
        if self.phase == "blocked":
            if (
                self.run_id is None
                or self.disposition is None
                or not isinstance(self.state_fingerprint, str)
                or len(self.state_fingerprint) != 64
                or any(character not in "0123456789abcdef" for character in self.state_fingerprint)
            ):
                raise SupervisorRefused("blocked supervisor record has an invalid fingerprint")
        elif self.state_fingerprint is not None:
            raise SupervisorRefused("non-blocked supervisor record has a fingerprint")
        if (
            not isinstance(self.updated_at, (int, float))
            or isinstance(self.updated_at, bool)
            or not math.isfinite(self.updated_at)
        ):
            raise SupervisorRefused("supervisor record has an invalid update time")


class _SupervisorFiles:
    """Crash-durable private restart record plus one live-supervisor lease."""

    def __init__(self, state_path: Path) -> None:
        self.record_path = state_path.with_name(f"{state_path.name}.supervisor.json")
        self.lock_path = state_path.with_name(f"{state_path.name}.supervisor.lock")
        self._lock_descriptor: int | None = None

    def __enter__(self) -> Self:
        parent = self.record_path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = parent.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_mode & 0o077
        ):
            raise SupervisorRefused(
                "supervisor state directory must be runtime/root owned and private"
            )
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.lock_path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise SupervisorRefused("supervisor lease is not a regular file")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(descriptor)
            raise
        self._lock_descriptor = descriptor
        return self

    def __exit__(self, _error_type: object, _error: object, _traceback: object) -> None:
        if self._lock_descriptor is not None:
            try:
                fcntl.flock(self._lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_descriptor)
                self._lock_descriptor = None

    def load(self) -> SupervisorRecord | None:
        try:
            metadata = self.record_path.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise SupervisorRefused("supervisor record is not a regular file")
        if metadata.st_mode & 0o077:
            raise SupervisorRefused("supervisor record is not private")
        try:
            document = json.loads(self.record_path.read_bytes())
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            raise SupervisorRefused("supervisor record is unreadable") from exc
        expected = {
            "version",
            "phase",
            "run_id",
            "replacement_count",
            "not_before",
            "disposition",
            "state_fingerprint",
            "updated_at",
        }
        if not isinstance(document, dict) or set(document) != expected:
            raise SupervisorRefused("supervisor record has an unsupported shape")
        record = SupervisorRecord(**document)
        record.validate()
        return record

    def write(self, record: SupervisorRecord) -> None:
        record.validate()
        encoded = json.dumps(asdict(record), sort_keys=True, separators=(",", ":")).encode()
        temporary = self.record_path.with_name(
            f".{self.record_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        )
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("supervisor record write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        except BaseException:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)
        os.replace(temporary, self.record_path)
        self.record_path.chmod(0o600)
        directory = os.open(
            self.record_path.parent,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _read_durable_run(state_path: Path) -> DurableRun | None:
    try:
        metadata = state_path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SupervisorRefused("state database is not a regular file")
    if metadata.st_size == 0:
        raise SupervisorRefused("state database exists without durable run state")
    encoded = urllib.parse.quote(str(state_path), safe="/")
    try:
        connection = sqlite3.connect(f"file:{encoded}?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        rows = connection.execute("SELECT id, status FROM runs ORDER BY started_at, id").fetchall()
    except sqlite3.Error as exc:
        raise SupervisorRefused("state database cannot prove one durable run") from exc
    finally:
        if "connection" in locals():
            connection.close()
    if len(rows) != 1:
        raise SupervisorRefused("state database must contain exactly one durable run")
    run_id = rows[0]["id"]
    status = rows[0]["status"]
    if not isinstance(run_id, str) or not run_id or not isinstance(status, str):
        raise SupervisorRefused("state database contains an invalid run record")
    if status != "running" and status not in _TERMINAL_RUN_STATES:
        raise SupervisorRefused("state database contains an unknown run state")
    return DurableRun(run_id, status)


def _is_pristine_rapido_state(state_path: Path) -> bool:
    try:
        metadata = state_path.lstat()
    except FileNotFoundError:
        return True
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return False
    if metadata.st_size == 0:
        return True
    encoded = urllib.parse.quote(str(state_path), safe="/")
    try:
        connection = sqlite3.connect(f"file:{encoded}?mode=ro", uri=True, timeout=5)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
            return False
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        if tables != _PRISTINE_SCHEMA_TABLES:
            return False
        for table, columns in _PRISTINE_SCHEMA_COLUMNS.items():
            actual = tuple(row[1] for row in connection.execute(f'PRAGMA table_info("{table}")'))
            if actual != columns:
                return False
        for table in _PRISTINE_SCHEMA_TABLES:
            if connection.execute(f'SELECT 1 FROM "{table}" LIMIT 1').fetchone() is not None:
                return False
        return connection.execute("PRAGMA foreign_key_check").fetchone() is None
    except sqlite3.Error:
        return False
    finally:
        if "connection" in locals():
            connection.close()


def _read_initially_recoverable_run(state_path: Path, *, initial_record: bool) -> DurableRun | None:
    try:
        return _read_durable_run(state_path)
    except SupervisorRefused:
        if initial_record and _is_pristine_rapido_state(state_path):
            return None
        raise


def _state_fingerprint(connection: sqlite3.Connection, run_id: str) -> str:
    table_names = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    state: list[list[object]] = []
    for table, preferred_columns in _FINGERPRINT_TABLES.items():
        if table not in table_names:
            continue
        available = {
            row[1] for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
        }
        columns = tuple(column for column in preferred_columns if column in available)
        if not columns:
            continue
        selected = ", ".join(f'"{column}"' for column in columns)
        order = ", ".join(f'"{column}"' for column in columns)
        parameters: tuple[object, ...] = ()
        where = ""
        if "run_id" in columns:
            where = ' WHERE "run_id"=?'
            parameters = (run_id,)
        elif table == "runs" and "id" in columns:
            where = ' WHERE "id"=?'
            parameters = (run_id,)
        rows = connection.execute(
            f'SELECT {selected} FROM "{table}"{where} ORDER BY {order}', parameters
        ).fetchall()
        state.append([table, list(columns), [list(row) for row in rows]])
    encoded_state = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded_state).hexdigest()


def _reconciliation_fingerprint(state_path: Path, run_id: str) -> str | None:
    """Atomically classify ambiguity and hash its durable reconciliation authority."""
    encoded = urllib.parse.quote(str(state_path), safe="/")
    try:
        connection = sqlite3.connect(f"file:{encoded}?mode=ro", uri=True, timeout=5)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='submission_intents'"
        ).fetchone()
        if table is None:
            connection.rollback()
            return None
        columns = {row[1] for row in connection.execute("PRAGMA table_info(submission_intents)")}
        if not {"first_run_id", "status"} <= columns:
            raise SupervisorRefused("submission intent state has an unsupported shape")
        row = connection.execute(
            "SELECT 1 FROM submission_intents "
            "WHERE first_run_id=? AND status IN ('pending', 'unread') LIMIT 1",
            (run_id,),
        ).fetchone()
        fingerprint = _state_fingerprint(connection, run_id) if row is not None else None
        connection.rollback()
        return fingerprint
    except sqlite3.Error as exc:
        raise SupervisorRefused("state database cannot prove reconciliation requirement") from exc
    finally:
        if "connection" in locals():
            connection.close()


def supervisor_projection(state_path: Path) -> dict[str, object] | None:
    """Read the public, sanitized portion of the private supervisor record."""
    record = _SupervisorFiles(state_path).load()
    if record is None:
        return None
    return {
        "phase": record.phase,
        "replacement_count": record.replacement_count,
        "disposition": record.disposition,
        "run_bound": record.run_id is not None,
    }


class Supervisor:
    """Own one disposable solver process group until the durable Run is terminal."""

    def __init__(
        self,
        state_path: Path,
        *,
        command: Sequence[str] | None = None,
        restart_backoffs: Sequence[float] = RESTART_BACKOFF_SECONDS,
        stop_seconds: float = 180.0,
        descendant_seconds: float = 2.0,
        stay_quiescent: bool = True,
        environ: Mapping[str, str] | None = None,
        reporter: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if not state_path.is_absolute():
            raise SupervisorRefused("RAPIDO_STATE_PATH must be absolute")
        if not restart_backoffs or any(delay < 0 for delay in restart_backoffs):
            raise ValueError("restart backoffs must be a non-empty non-negative sequence")
        if stop_seconds <= 0 or descendant_seconds < 0:
            raise ValueError("supervisor shutdown bounds must be positive")
        self.state_path = state_path
        self.command = tuple(command or (sys.executable, "-m", "rapido", "_worker"))
        self.restart_backoffs = tuple(float(delay) for delay in restart_backoffs)
        self.stop_seconds = float(stop_seconds)
        self.descendant_seconds = float(descendant_seconds)
        self.stay_quiescent = stay_quiescent
        self.environ = dict(os.environ if environ is None else environ)
        self.reporter = reporter or self._default_reporter
        self._files = _SupervisorFiles(state_path)
        self._process: subprocess.Popen[bytes] | None = None
        self._stop_signal: int | None = None
        self._stop_at: float | None = None
        self._stop_event = threading.Event()
        self._forwarded = False
        self._previous_handlers: dict[int, Any] = {}
        self._child_adoption_ready = False

    @staticmethod
    def _default_reporter(document: dict[str, Any]) -> None:
        print(json.dumps(document, sort_keys=True), file=sys.stderr, flush=True)

    def run(self) -> int:
        self._install_signal_handlers()
        try:
            try:
                with self._files:
                    self._enable_child_adoption()
                    try:
                        return self._run_owned()
                    finally:
                        if self._stop_signal is not None:
                            self._finalize_operator_stop()
            except (BlockingIOError, OSError, SupervisorRefused, sqlite3.Error) as exc:
                self.reporter({"status": "refused", "reason": str(exc)})
                return self._quiesce()
        finally:
            self._restore_signal_handlers()

    def _run_owned(self) -> int:
        record = self._files.load()
        initial_record = (
            record is not None
            and record.phase in {"active", "scheduled", "stopping"}
            and record.run_id is None
        )
        durable = _read_initially_recoverable_run(self.state_path, initial_record=initial_record)
        if record is not None and record.phase == "terminal":
            return self._quiesce(record.disposition or "refused", record.run_id)
        if record is not None and record.phase == "stopping":
            self._finalize_operator_stop(record)
            finalized = self._files.load()
            if finalized is not None and finalized.phase == "terminal":
                return self._quiesce(finalized.disposition or "operator_stopped", finalized.run_id)
            return self._quiesce("operator_stop_pending", record.run_id)
        if durable is not None and durable.status != "running":
            self._write_terminal(record, durable.run_id, durable.status)
            return self._quiesce(durable.status, durable.run_id)

        if record is None:
            if durable is None:
                return self._worker_loop(None, 0, initial=True)
            return self._schedule_or_refuse(durable, 1)

        if record.run_id is not None and durable is not None and record.run_id != durable.run_id:
            self._write_terminal(record, record.run_id, "run_identity_mismatch")
            return self._quiesce("run_identity_mismatch", record.run_id)
        if record.phase == "blocked":
            if durable is None:
                self._write_terminal(record, record.run_id, "durable_run_absent")
                return self._quiesce("durable_run_absent", record.run_id)
            return self._wait_blocked(durable, record)
        if durable is None and record.run_id is not None:
            self._write_terminal(record, record.run_id, "durable_run_absent")
            return self._quiesce("durable_run_absent", record.run_id)
        if record.phase == "scheduled":
            if record.run_id is None and durable is not None:
                self._write_terminal(record, None, "durable_run_changed_before_restart")
                return self._quiesce("durable_run_changed_before_restart")
            return self._wait_and_launch(durable, record)
        if record.phase == "active":
            return self._schedule_or_refuse(durable, record.replacement_count + 1)
        raise SupervisorRefused("supervisor record has an unknown phase")

    def _schedule_or_refuse(self, durable: DurableRun | None, replacement_count: int) -> int:
        if durable is not None and durable.status != "running":
            self._write_terminal(None, durable.run_id, durable.status)
            return self._quiesce(durable.status, durable.run_id)
        run_id = durable.run_id if durable is not None else None
        if replacement_count > len(self.restart_backoffs):
            self._write_terminal(None, run_id, "restart_budget_exhausted", replacement_count - 1)
            return self._quiesce("restart_budget_exhausted", run_id)
        delay = self.restart_backoffs[replacement_count - 1]
        record = SupervisorRecord(
            _RECORD_VERSION,
            "scheduled",
            run_id,
            replacement_count,
            time.time() + delay,
            None,
            None,
            time.time(),
        )
        self._files.write(record)
        self.reporter(
            {
                "status": "restart_scheduled",
                "run_id": run_id,
                "replacement": replacement_count,
                "delay_seconds": delay,
            }
        )
        return self._wait_and_launch(durable, record)

    def _wait_and_launch(self, durable: DurableRun | None, record: SupervisorRecord) -> int:
        while not self._stop_event.is_set():
            remaining = record.not_before - time.time()
            if remaining <= 0:
                break
            self._stop_event.wait(min(remaining, 0.25))
        if self._stop_signal is not None:
            return 128 + self._stop_signal
        current = _read_initially_recoverable_run(
            self.state_path, initial_record=record.run_id is None
        )
        if current != durable or (current is not None and current.status != "running"):
            disposition = "durable_run_changed_before_restart"
            if current is not None and current.status != "running":
                disposition = current.status
            self._write_terminal(record, record.run_id, disposition)
            return self._quiesce(disposition, record.run_id)
        return self._worker_loop(record.run_id, record.replacement_count, initial=False)

    def _worker_loop(self, run_id: str | None, replacement_count: int, *, initial: bool) -> int:
        active = SupervisorRecord(
            _RECORD_VERSION,
            "active",
            run_id,
            replacement_count,
            0.0,
            None,
            None,
            time.time(),
        )
        self._files.write(active)
        if self._stop_signal is not None:
            return 128 + self._stop_signal
        self.reporter(
            {
                "status": "worker_starting",
                "run_id": run_id,
                "replacement": replacement_count,
                "initial": initial,
            }
        )
        if self._stop_signal is not None:
            return 128 + self._stop_signal
        gate_read, gate_write = os.pipe()
        try:
            process = subprocess.Popen(
                (sys.executable, "-m", "rapido.spawn_gate", str(gate_read), "--", *self.command),
                env=self.environ,
                start_new_session=True,
                pass_fds=(gate_read,),
            )
        except OSError:
            os.close(gate_read)
            os.close(gate_write)
            durable = _read_initially_recoverable_run(
                self.state_path, initial_record=run_id is None
            )
            if durable is not None and durable.status == "running":
                return self._schedule_or_refuse(durable, replacement_count + 1)
            if durable is not None:
                self._write_terminal(active, durable.run_id, durable.status)
                return self._quiesce(durable.status, durable.run_id)
            if durable is None and run_id is None:
                return self._schedule_or_refuse(None, replacement_count + 1)
            self._write_terminal(active, run_id, "worker_launch_failed")
            return self._quiesce("worker_launch_failed", run_id)
        os.close(gate_read)
        self._process = process
        self._forwarded = False
        try:
            if self._stop_signal is None:
                os.write(gate_write, b"1")
        except OSError:
            if self._stop_signal is None:
                self.reporter({"status": "refused", "reason": "worker start gate failed"})
        finally:
            os.close(gate_write)
        self._forward_if_requested()
        exit_code = self._wait_worker(process)
        self._process = None
        try:
            descendants_extinguished = self._extinguish_worker(process.pid)
        except (OSError, SupervisorRefused) as exc:
            descendants_extinguished = False
            self.reporter({"status": "refused", "reason": str(exc)})
        if not descendants_extinguished:
            self._write_terminal(active, run_id, "descendant_cleanup_failed")
            return self._quiesce("descendant_cleanup_failed", run_id)
        if self._stop_signal is not None:
            return 128 + self._stop_signal

        try:
            durable = _read_initially_recoverable_run(
                self.state_path, initial_record=run_id is None
            )
        except SupervisorRefused as exc:
            self._write_terminal(active, run_id, "durable_state_refused")
            self.reporter({"status": "refused", "reason": str(exc)})
            return self._quiesce("durable_state_refused", run_id)
        if durable is not None and durable.status != "running":
            self._write_terminal(active, durable.run_id, durable.status)
            return self._quiesce(durable.status, durable.run_id)
        if exit_code in {2, 130}:
            fingerprint = (
                _reconciliation_fingerprint(self.state_path, durable.run_id)
                if durable is not None and durable.status == "running"
                else None
            )
            if durable is not None and fingerprint is not None:
                blocked = SupervisorRecord(
                    _RECORD_VERSION,
                    "blocked",
                    durable.run_id,
                    replacement_count,
                    0.0,
                    "operator_reconciliation_required",
                    fingerprint,
                    time.time(),
                )
                self._files.write(blocked)
                return self._wait_blocked(durable, blocked)
            if durable is not None and durable.status == "running":
                return self._schedule_or_refuse(durable, replacement_count + 1)
            if durable is None and run_id is None:
                return self._schedule_or_refuse(None, replacement_count + 1)
            self._write_terminal(active, durable.run_id if durable else run_id, "refused")
            return self._quiesce("refused", durable.run_id if durable else run_id)
        if exit_code == 0:
            self._write_terminal(active, durable.run_id if durable else run_id, "inconsistent_exit")
            return self._quiesce("inconsistent_exit", durable.run_id if durable else run_id)
        if durable is None:
            if run_id is None:
                return self._schedule_or_refuse(None, replacement_count + 1)
            self._write_terminal(active, run_id, "durable_run_absent")
            return self._quiesce("durable_run_absent", run_id)
        return self._schedule_or_refuse(durable, replacement_count + 1)

    def _wait_blocked(self, durable: DurableRun, record: SupervisorRecord) -> int:
        assert record.state_fingerprint is not None
        self.reporter(
            {
                "status": "blocked",
                "run_id": durable.run_id,
                "replacement": record.replacement_count,
                "disposition": record.disposition,
            }
        )
        while True:
            current = _read_durable_run(self.state_path)
            if current is None or current.run_id != durable.run_id:
                self._write_terminal(record, durable.run_id, "durable_run_changed_while_blocked")
                return self._quiesce("durable_run_changed_while_blocked", durable.run_id)
            if current.status != "running":
                self._write_terminal(record, current.run_id, current.status)
                return self._quiesce(current.status, current.run_id)
            fingerprint = _reconciliation_fingerprint(self.state_path, current.run_id)
            if fingerprint is None:
                self.reporter(
                    {
                        "status": "reconciliation_changed",
                        "run_id": current.run_id,
                        "replacement": record.replacement_count,
                    }
                )
                return self._worker_loop(current.run_id, record.replacement_count, initial=False)
            if fingerprint != record.state_fingerprint:
                record = SupervisorRecord(
                    _RECORD_VERSION,
                    "blocked",
                    current.run_id,
                    record.replacement_count,
                    0.0,
                    record.disposition,
                    fingerprint,
                    time.time(),
                )
                self._files.write(record)
            if not self.stay_quiescent:
                return 0
            if self._stop_event.wait(0.25):
                return 0
            self._reap_children()

    def _wait_worker(self, process: subprocess.Popen[bytes]) -> int:
        stop_deadline: float | None = None
        killed = False
        while process.poll() is None:
            self._reap_adopted_children(process.pid)
            if self._stop_signal is not None:
                if stop_deadline is None:
                    stop_deadline = (self._stop_at or time.monotonic()) + self.stop_seconds
                elif time.monotonic() >= stop_deadline and not killed:
                    self._signal_group(process.pid, signal.SIGKILL)
                    killed = True
            time.sleep(0.05)
        return process.wait()

    def _forward_if_requested(self) -> None:
        if self._stop_signal is None or self._forwarded or self._process is None:
            return
        if self._process.poll() is None:
            self._signal_group(self._process.pid, self._stop_signal)
            self._forwarded = True

    def _on_signal(self, signum: int, _frame: object) -> None:
        if self._stop_signal is not None:
            return
        self._stop_signal = signum
        self._stop_at = time.monotonic()
        self._stop_event.set()
        self._forward_if_requested()

    def _install_signal_handlers(self) -> None:
        for signum in (signal.SIGTERM, signal.SIGINT):
            self._previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, self._on_signal)

    def _restore_signal_handlers(self) -> None:
        for signum, handler in self._previous_handlers.items():
            signal.signal(signum, handler)
        self._previous_handlers.clear()

    def _enable_child_adoption(self) -> None:
        if self._child_adoption_ready or not sys.platform.startswith("linux"):
            self._child_adoption_ready = True
            return
        if os.getpid() != 1:
            library = ctypes.CDLL(None, use_errno=True)
            prctl = library.prctl
            prctl.argtypes = [
                ctypes.c_int,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
            ]
            prctl.restype = ctypes.c_int
            if prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
                error = ctypes.get_errno()
                raise SupervisorRefused(f"cannot adopt worker descendants: errno {error}")
        self._child_adoption_ready = True

    @staticmethod
    def _signal_group(process_group: int, signum: int) -> None:
        try:
            os.killpg(process_group, signum)
        except ProcessLookupError:
            pass

    @staticmethod
    def _group_exists(process_group: int) -> bool:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    @staticmethod
    def _children_of(process: int) -> set[int]:
        if not sys.platform.startswith("linux"):
            return set()
        task_root = Path(f"/proc/{process}/task")
        try:
            tasks = tuple(task_root.iterdir())
        except FileNotFoundError:
            if process == os.getpid():
                raise SupervisorRefused("cannot enumerate owned worker descendants")
            return set()
        except OSError as exc:
            raise SupervisorRefused("cannot enumerate owned worker descendants") from exc
        children: set[int] = set()
        for task in tasks:
            children_path = task / "children"
            try:
                raw = children_path.read_text(encoding="ascii")
            except FileNotFoundError:
                continue
            except (OSError, UnicodeError) as exc:
                raise SupervisorRefused("cannot enumerate owned worker descendants") from exc
            for field in raw.split():
                try:
                    child = int(field)
                except ValueError as exc:
                    raise SupervisorRefused("invalid worker descendant identity") from exc
                if child <= 0:
                    raise SupervisorRefused("invalid worker descendant identity")
                children.add(child)
        return children

    def _direct_children(self) -> set[int]:
        return self._children_of(os.getpid())

    @classmethod
    def _owned_descendants(cls) -> set[int]:
        pending = [os.getpid()]
        descendants: set[int] = set()
        while pending:
            parent = pending.pop()
            for child in cls._children_of(parent):
                if child not in descendants:
                    descendants.add(child)
                    pending.append(child)
        return descendants

    def _reap_adopted_children(self, worker_pid: int) -> None:
        """Reap exited direct children without consuming the live worker's status."""
        for child in sorted(self._direct_children()):
            if child == worker_pid:
                continue
            try:
                os.waitpid(child, os.WNOHANG)
            except (ChildProcessError, InterruptedError, ProcessLookupError):
                continue

    @staticmethod
    def _signal_processes(processes: set[int], signum: int) -> None:
        for process in processes:
            try:
                os.kill(process, signum)
            except ProcessLookupError:
                pass

    def _extinguish_worker(self, process_group: int) -> bool:
        descendants = self._owned_descendants()
        if not self._forwarded:
            if self._group_exists(process_group):
                self._signal_group(process_group, signal.SIGTERM)
            self._signal_processes(descendants, signal.SIGTERM)
        deadline = time.monotonic() + self.descendant_seconds
        while time.monotonic() < deadline:
            self._reap_children()
            descendants = self._owned_descendants()
            if not self._group_exists(process_group) and not descendants:
                return True
            if not self._forwarded:
                self._signal_processes(descendants, signal.SIGTERM)
            time.sleep(0.05)

        self._signal_group(process_group, signal.SIGKILL)
        descendants = self._owned_descendants()
        self._signal_processes(descendants, signal.SIGKILL)
        deadline = time.monotonic() + self.descendant_seconds
        while time.monotonic() < deadline:
            self._reap_children()
            descendants = self._owned_descendants()
            if not self._group_exists(process_group) and not descendants:
                return True
            self._signal_processes(descendants, signal.SIGKILL)
            time.sleep(0.05)
        self._reap_children()
        return not self._group_exists(process_group) and not self._owned_descendants()

    @staticmethod
    def _reap_children() -> None:
        while True:
            try:
                child, _status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            except InterruptedError:
                continue
            if child == 0:
                return

    def _write_terminal(
        self,
        previous: SupervisorRecord | None,
        run_id: str | None,
        disposition: str,
        replacement_count: int | None = None,
    ) -> None:
        count = (
            replacement_count
            if replacement_count is not None
            else previous.replacement_count
            if previous is not None
            else 0
        )
        self._files.write(
            SupervisorRecord(
                _RECORD_VERSION,
                "terminal",
                run_id,
                count,
                0.0,
                disposition,
                None,
                time.time(),
            )
        )

    def _finalize_operator_stop(self, record: SupervisorRecord | None = None) -> None:
        """Persist stop intent after worker/descendant drain and before process exit."""
        if record is None:
            record = self._files.load()
        if record is not None and record.phase == "terminal":
            return
        run_id = None if record is None else record.run_id
        stopping_written = record is not None and record.phase == "stopping"
        if record is None or record.phase != "stopping":
            record = SupervisorRecord(
                _RECORD_VERSION,
                "stopping",
                run_id,
                0 if record is None else record.replacement_count,
                0.0,
                "operator_stop_pending",
                None,
                time.time(),
            )
            try:
                self._files.write(record)
                stopping_written = True
            except OSError as exc:
                # The Run database is an independent durable fence. Continue so a
                # transient sidecar failure cannot leave a running Run restartable.
                self.reporter({"status": "refused", "reason": str(exc)})
        try:
            durable = _read_durable_run(self.state_path)
        except SupervisorRefused as exc:
            self.reporter({"status": "refused", "reason": str(exc)})
            if not stopping_written:
                self._files.write(record)
            return
        if run_id is None and durable is not None:
            run_id = durable.run_id
        if durable is not None and durable.status != "running":
            disposition = "operator_stopped" if durable.status == "interrupted" else durable.status
            self._write_terminal(record, durable.run_id, disposition)
            return
        if run_id is not None and durable is not None and durable.status == "running":
            from .state import StateStore

            state: StateStore | None = None
            try:
                state = StateStore(self.state_path)
                state.acquire_supervisor()
                durable_status = state.finalize_operator_stop(run_id)
                if durable_status not in {"interrupted", "completed", "deadline", "failed"}:
                    raise RuntimeError("operator stop produced an invalid durable run state")
            except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
                self.reporter({"status": "refused", "reason": str(exc)})
                if not stopping_written:
                    self._files.write(record)
                return
            finally:
                if state is not None:
                    state.close()
        self._write_terminal(record, run_id, "operator_stopped")

    def _quiesce(self, disposition: str = "refused", run_id: str | None = None) -> int:
        self.reporter({"status": "quiescent", "run_id": run_id, "disposition": disposition})
        if not self.stay_quiescent:
            return 0
        while not self._stop_event.wait(0.25):
            self._reap_children()
        return 0


def run_supervisor(environ: Mapping[str, str] | None = None) -> int:
    selected = os.environ if environ is None else environ
    state_path = Path(selected.get("RAPIDO_STATE_PATH", "/state/rapido.sqlite3"))
    try:
        return Supervisor(state_path, environ=selected).run()
    except (OSError, SupervisorRefused, ValueError) as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)}), file=sys.stderr)
        stopped = threading.Event()

        def stop(_signum: int, _frame: object) -> None:
            stopped.set()

        previous = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
        try:
            for signum in previous:
                signal.signal(signum, stop)
            while not stopped.wait(0.25):
                pass
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
        return 0


__all__ = [
    "RESTART_BACKOFF_SECONDS",
    "DurableRun",
    "Supervisor",
    "SupervisorRecord",
    "SupervisorRefused",
    "run_supervisor",
    "supervisor_projection",
]
