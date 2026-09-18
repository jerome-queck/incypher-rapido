from __future__ import annotations

import json
import os
import signal
import sqlite3
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from rapido import cli
from rapido.state import StateStore
from rapido.supervisor import Supervisor, SupervisorRefused

ROOT = Path(__file__).resolve().parents[1]


def _private_state(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    return root / "rapido.sqlite3"


def _write_run(state_path: Path, status: str, run_id: str = "run-1") -> None:
    with sqlite3.connect(state_path) as connection:
        connection.execute(
            "CREATE TABLE runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
            "finished_at TEXT, status TEXT NOT NULL, config_json TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO runs VALUES (?, '2026-09-18T00:00:00+00:00', NULL, ?, '{}')",
            (run_id, status),
        )


def _record(state_path: Path) -> dict[str, object]:
    return json.loads(state_path.with_name(f"{state_path.name}.supervisor.json").read_text())


def _write_supervisor_record(state_path: Path, **overrides: object) -> None:
    document: dict[str, object] = {
        "version": 1,
        "phase": "active",
        "run_id": None,
        "replacement_count": 0,
        "not_before": 0.0,
        "disposition": None,
        "state_fingerprint": None,
        "updated_at": 0.0,
    }
    document.update(overrides)
    record_path = state_path.with_name(f"{state_path.name}.supervisor.json")
    record_path.write_text(json.dumps(document))
    record_path.chmod(0o600)


def test_public_run_dispatches_supervisor_and_private_worker(monkeypatch) -> None:
    monkeypatch.setattr(cli, "run_supervisor", lambda: 17)
    monkeypatch.setattr(cli, "_run", lambda: 23)

    assert cli.main(["run"]) == 17
    assert cli.main(["_worker"]) == 23


def test_terminal_state_never_starts_a_new_worker(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    _write_run(state_path, "completed")
    marker = tmp_path / "started"
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )

    assert supervisor.run() == 0
    assert not marker.exists()
    assert _record(state_path)["disposition"] == "completed"


def test_crashed_worker_resumes_same_durable_run(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    counter = tmp_path / "counter"
    worker = textwrap.dedent(
        """
        import os
        import sqlite3
        from pathlib import Path

        state = Path(os.environ["TEST_STATE"])
        counter = Path(os.environ["TEST_COUNTER"])
        invocation = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(invocation))
        with sqlite3.connect(state) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
                "finished_at TEXT, status TEXT NOT NULL, config_json TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO runs VALUES "
                "('same-run', '2026-09-18T00:00:00+00:00', NULL, 'running', '{}')"
            )
            if invocation > 1:
                connection.execute("UPDATE runs SET status='completed' WHERE id='same-run'")
        if invocation == 1:
            os._exit(23)
        """
    )
    environment = dict(os.environ, TEST_STATE=str(state_path), TEST_COUNTER=str(counter))
    events: list[dict[str, object]] = []
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0,),
        stay_quiescent=False,
        environ=environment,
        reporter=events.append,
    )

    assert supervisor.run() == 0
    assert counter.read_text() == "2"
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT id, status FROM runs").fetchone() == (
            "same-run",
            "completed",
        )
    assert _record(state_path)["replacement_count"] == 1
    assert [event["status"] for event in events].count("worker_starting") == 2


def test_pre_run_worker_refusal_uses_bounded_restart_budget(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    counter = tmp_path / "counter"
    worker = (
        "from pathlib import Path; import sys; "
        f"p=Path({str(counter)!r}); p.write_text(str(int(p.read_text())+1 if p.exists() else 1)); "
        "sys.exit(2)"
    )
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0, 0, 0),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )

    assert supervisor.run() == 0
    assert counter.read_text() == "4"
    assert _record(state_path)["disposition"] == "restart_budget_exhausted"


def test_restart_budget_is_durable_and_bounded(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    counter = tmp_path / "counter"
    worker = textwrap.dedent(
        """
        import os
        import sqlite3
        from pathlib import Path

        state = Path(os.environ["TEST_STATE"])
        counter = Path(os.environ["TEST_COUNTER"])
        invocation = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(invocation))
        with sqlite3.connect(state) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
                "finished_at TEXT, status TEXT NOT NULL, config_json TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO runs VALUES "
                "('same-run', '2026-09-18T00:00:00+00:00', NULL, 'running', '{}')"
            )
        os._exit(23)
        """
    )
    environment = dict(os.environ, TEST_STATE=str(state_path), TEST_COUNTER=str(counter))

    first = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0, 0),
        stay_quiescent=False,
        environ=environment,
        reporter=lambda _document: None,
    )
    assert first.run() == 0
    assert counter.read_text() == "3"
    assert _record(state_path)["disposition"] == "restart_budget_exhausted"

    second = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0, 0),
        stay_quiescent=False,
        environ=environment,
        reporter=lambda _document: None,
    )
    assert second.run() == 0
    assert counter.read_text() == "3"


@pytest.mark.parametrize("backoff", [5, 30, 120])
def test_operator_stop_during_restart_backoff_is_durable(tmp_path: Path, backoff: int) -> None:
    state_path = _private_state(tmp_path)
    state = StateStore(state_path)
    state.start_run("same-run", {})
    state.close()
    marker = tmp_path / "started"
    _write_supervisor_record(
        state_path,
        phase="scheduled",
        run_id="same-run",
        replacement_count=1,
        not_before=time.time() + backoff,
    )
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        restart_backoffs=(float(backoff),),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    supervisor._stop_signal = signal.SIGTERM
    supervisor._stop_at = time.monotonic()
    supervisor._stop_event.set()

    assert supervisor.run() == 128 + signal.SIGTERM
    assert not marker.exists()
    assert _record(state_path)["phase"] == "terminal"
    assert _record(state_path)["disposition"] == "operator_stopped"
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone() == ("interrupted",)

    restarted = Supervisor(
        state_path,
        command=(sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    assert restarted.run() == 0
    assert not marker.exists()


def test_operator_stop_preserves_pending_submission_intent(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    state = StateStore(state_path)
    state.start_run("same-run", {})
    state.upsert_challenge(7, "fixture", "web", "standard", 100)
    assert state.reserve_submission("same-run", 7, "INCYPHER{private-fixture}")
    state.close()
    _write_supervisor_record(
        state_path,
        phase="scheduled",
        run_id="same-run",
        replacement_count=1,
        not_before=time.time() + 30,
    )
    supervisor = Supervisor(
        state_path,
        restart_backoffs=(30,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    supervisor._stop_signal = signal.SIGTERM
    supervisor._stop_at = time.monotonic()
    supervisor._stop_event.set()

    assert supervisor.run() == 128 + signal.SIGTERM
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status FROM submission_intents").fetchone() == (
            "pending",
        )
    assert _record(state_path)["disposition"] == "operator_stopped"


def test_operator_stop_from_blocked_reconciliation_never_restarts(tmp_path: Path) -> None:
    import rapido.supervisor as supervisor_module

    state_path = _private_state(tmp_path)
    state = StateStore(state_path)
    state.start_run("same-run", {})
    state.upsert_challenge(7, "fixture", "web", "standard", 100)
    assert state.reserve_submission("same-run", 7, "INCYPHER{private-fixture}")
    state.finalize_submission("same-run", 7, "INCYPHER{private-fixture}", "unread", 0)
    state.close()
    fingerprint = supervisor_module._reconciliation_fingerprint(state_path, "same-run")
    assert fingerprint is not None
    _write_supervisor_record(
        state_path,
        phase="blocked",
        run_id="same-run",
        replacement_count=1,
        disposition="operator_reconciliation_required",
        state_fingerprint=fingerprint,
    )
    supervisor = Supervisor(
        state_path,
        restart_backoffs=(30,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    supervisor._stop_signal = signal.SIGTERM
    supervisor._stop_at = time.monotonic()
    supervisor._stop_event.set()

    assert supervisor.run() == 0
    assert _record(state_path)["disposition"] == "operator_stopped"
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone() == ("interrupted",)
        assert connection.execute("SELECT status FROM submission_intents").fetchone() == ("unread",)


def test_transient_stop_read_failure_retries_only_finalization(monkeypatch, tmp_path: Path) -> None:
    import rapido.supervisor as supervisor_module

    state_path = _private_state(tmp_path)
    marker = tmp_path / "started"
    state = StateStore(state_path)
    state.start_run("same-run", {})
    state.upsert_challenge(7, "fixture", "web", "standard", 100)
    assert state.reserve_submission("same-run", 7, "INCYPHER{private-fixture}")
    state.finalize_submission("same-run", 7, "INCYPHER{private-fixture}", "unread", 0)
    state.close()
    _write_supervisor_record(
        state_path,
        phase="scheduled",
        run_id="same-run",
        replacement_count=1,
        not_before=time.time() + 30,
    )
    real_read = supervisor_module._read_durable_run
    reads = 0

    def fail_second_read(path: Path):
        nonlocal reads
        reads += 1
        if reads == 2:
            raise SupervisorRefused("transient read failure")
        return real_read(path)

    monkeypatch.setattr(supervisor_module, "_read_durable_run", fail_second_read)
    stopped = Supervisor(
        state_path,
        restart_backoffs=(30,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    stopped._stop_signal = signal.SIGTERM
    stopped._stop_at = time.monotonic()
    stopped._stop_event.set()

    assert stopped.run() == 128 + signal.SIGTERM
    assert _record(state_path)["phase"] == "stopping"
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone() == ("running",)
        assert connection.execute("SELECT status FROM submission_intents").fetchone() == ("unread",)

    monkeypatch.setattr(supervisor_module, "_read_durable_run", real_read)
    restarted = Supervisor(
        state_path,
        command=(sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    assert restarted.run() == 0
    assert not marker.exists()
    assert _record(state_path)["disposition"] == "operator_stopped"
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone() == ("interrupted",)
        assert connection.execute("SELECT status FROM submission_intents").fetchone() == ("unread",)


def test_transient_stop_write_failure_retries_without_worker_spawn(
    monkeypatch, tmp_path: Path
) -> None:
    state_path = _private_state(tmp_path)
    marker = tmp_path / "started"
    state = StateStore(state_path)
    state.start_run("same-run", {})
    state.close()
    _write_supervisor_record(
        state_path,
        phase="scheduled",
        run_id="same-run",
        replacement_count=1,
        not_before=time.time() + 30,
    )
    real_finalize = StateStore.finalize_operator_stop

    def fail_once(self: StateStore, run_id: str) -> str:
        monkeypatch.setattr(StateStore, "finalize_operator_stop", real_finalize)
        raise sqlite3.OperationalError("transient write failure")

    monkeypatch.setattr(StateStore, "finalize_operator_stop", fail_once)
    stopped = Supervisor(
        state_path,
        restart_backoffs=(30,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    stopped._stop_signal = signal.SIGTERM
    stopped._stop_at = time.monotonic()
    stopped._stop_event.set()

    assert stopped.run() == 128 + signal.SIGTERM
    assert _record(state_path)["phase"] == "stopping"
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone() == ("running",)

    restarted = Supervisor(
        state_path,
        command=(sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    assert restarted.run() == 0
    assert not marker.exists()
    assert _record(state_path)["disposition"] == "operator_stopped"
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone() == ("interrupted",)


def test_transient_stopping_sidecar_failure_still_terminalizes_run(
    monkeypatch, tmp_path: Path
) -> None:
    import rapido.supervisor as supervisor_module

    state_path = _private_state(tmp_path)
    marker = tmp_path / "started"
    state = StateStore(state_path)
    state.start_run("same-run", {})
    state.close()
    _write_supervisor_record(
        state_path,
        phase="scheduled",
        run_id="same-run",
        replacement_count=1,
        not_before=time.time() + 30,
    )
    real_write = supervisor_module._SupervisorFiles.write
    failed = False

    def fail_stopping_once(files, record) -> None:
        nonlocal failed
        if record.phase == "stopping" and not failed:
            failed = True
            raise OSError("transient sidecar failure")
        real_write(files, record)

    monkeypatch.setattr(supervisor_module._SupervisorFiles, "write", fail_stopping_once)
    stopped = Supervisor(
        state_path,
        restart_backoffs=(30,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    stopped._stop_signal = signal.SIGTERM
    stopped._stop_at = time.monotonic()
    stopped._stop_event.set()

    assert stopped.run() == 128 + signal.SIGTERM
    assert failed
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone() == ("interrupted",)
    assert _record(state_path)["disposition"] == "operator_stopped"

    restarted = Supervisor(
        state_path,
        command=(sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    assert restarted.run() == 0
    assert not marker.exists()


def test_combined_transient_stop_fence_failures_retry_sidecar_without_worker_spawn(
    monkeypatch, tmp_path: Path
) -> None:
    import rapido.supervisor as supervisor_module

    state_path = _private_state(tmp_path)
    marker = tmp_path / "started"
    state = StateStore(state_path)
    state.start_run("same-run", {})
    state.close()
    _write_supervisor_record(
        state_path,
        phase="scheduled",
        run_id="same-run",
        replacement_count=1,
        not_before=time.time() + 30,
    )
    real_write = supervisor_module._SupervisorFiles.write
    real_read = supervisor_module._read_durable_run
    write_failed = False
    reads = 0

    def fail_stopping_once(files, record) -> None:
        nonlocal write_failed
        if record.phase == "stopping" and not write_failed:
            write_failed = True
            raise OSError("transient sidecar failure")
        real_write(files, record)

    def fail_read_once(path: Path):
        nonlocal reads
        reads += 1
        if reads == 2:
            raise SupervisorRefused("transient durable read failure")
        return real_read(path)

    monkeypatch.setattr(supervisor_module._SupervisorFiles, "write", fail_stopping_once)
    monkeypatch.setattr(supervisor_module, "_read_durable_run", fail_read_once)
    stopped = Supervisor(
        state_path,
        restart_backoffs=(30,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    stopped._stop_signal = signal.SIGTERM
    stopped._stop_at = time.monotonic()
    stopped._stop_event.set()

    assert stopped.run() == 128 + signal.SIGTERM
    assert write_failed and reads >= 2
    assert _record(state_path)["phase"] == "stopping"
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone() == ("running",)

    monkeypatch.setattr(supervisor_module, "_read_durable_run", real_read)
    restarted = Supervisor(
        state_path,
        command=(sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    assert restarted.run() == 0
    assert not marker.exists()
    assert _record(state_path)["disposition"] == "operator_stopped"


def test_signal_persists_stop_fence_before_process_cleanup(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    marker = tmp_path / "started"
    state = StateStore(state_path)
    state.start_run("same-run", {})
    state.close()
    _write_supervisor_record(
        state_path,
        phase="active",
        run_id="same-run",
        replacement_count=1,
    )
    interrupted = Supervisor(
        state_path,
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )

    interrupted._on_signal(signal.SIGTERM, None)

    assert _record(state_path)["phase"] == "stopping"
    restarted = Supervisor(
        state_path,
        command=(sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    assert restarted.run() == 0
    assert not marker.exists()
    assert _record(state_path)["disposition"] == "operator_stopped"


def test_signal_at_worker_start_boundary_never_spawns_child(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    marker = tmp_path / "started"
    holder: dict[str, Supervisor] = {}

    def stop_before_spawn(document: dict[str, object]) -> None:
        if document.get("status") == "worker_starting":
            holder["supervisor"]._on_signal(signal.SIGTERM, None)

    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=stop_before_spawn,
    )
    holder["supervisor"] = supervisor

    assert supervisor.run() == 128 + signal.SIGTERM
    assert not marker.exists()
    assert _record(state_path)["disposition"] == "operator_stopped"


def test_signal_during_process_launch_cancels_gate_before_worker_exec(
    monkeypatch, tmp_path: Path
) -> None:
    state_path = _private_state(tmp_path)
    marker = tmp_path / "started"
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    real_pipe = os.pipe
    real_write = os.write
    gate_write: list[int] = []

    def tracked_pipe() -> tuple[int, int]:
        read_fd, write_fd = real_pipe()
        gate_write.append(write_fd)
        return read_fd, write_fd

    def stop_before_release(descriptor: int, payload: bytes) -> int:
        if gate_write and descriptor == gate_write[0]:
            supervisor._on_signal(signal.SIGTERM, None)
        return real_write(descriptor, payload)

    monkeypatch.setattr(os, "pipe", tracked_pipe)
    monkeypatch.setattr(os, "write", stop_before_release)

    assert supervisor.run() == 128 + signal.SIGTERM
    assert not marker.exists()
    assert _record(state_path)["disposition"] == "operator_stopped"


def test_failed_descendant_cleanup_terminalizes_without_replacement(
    monkeypatch, tmp_path: Path
) -> None:
    state_path = _private_state(tmp_path)
    counter = tmp_path / "counter"
    worker = textwrap.dedent(
        """
        import os
        import sqlite3
        from pathlib import Path

        counter = Path(os.environ["TEST_COUNTER"])
        counter.write_text(str(int(counter.read_text()) + 1 if counter.exists() else 1))
        with sqlite3.connect(os.environ["TEST_STATE"]) as connection:
            connection.execute(
                "CREATE TABLE runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
                "finished_at TEXT, status TEXT NOT NULL, config_json TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO runs VALUES "
                "('same-run', '2026-09-18T00:00:00+00:00', NULL, 'running', '{}')"
            )
        os._exit(23)
        """
    )
    monkeypatch.setattr(Supervisor, "_extinguish_worker", lambda _self, _group: False)
    environment = dict(os.environ, TEST_STATE=str(state_path), TEST_COUNTER=str(counter))
    first = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0, 0, 0),
        stay_quiescent=False,
        environ=environment,
        reporter=lambda _document: None,
    )

    assert first.run() == 0
    assert counter.read_text() == "1"
    assert _record(state_path)["phase"] == "terminal"
    assert _record(state_path)["disposition"] == "descendant_cleanup_failed"

    second = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0, 0, 0),
        stay_quiescent=False,
        environ=environment,
        reporter=lambda _document: None,
    )
    assert second.run() == 0
    assert counter.read_text() == "1"


def test_scheduled_replacement_is_reconstructed_without_spending_again(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    _write_run(state_path, "running", "same-run")
    _write_supervisor_record(
        state_path,
        phase="scheduled",
        run_id="same-run",
        replacement_count=1,
    )
    counter = tmp_path / "counter"
    worker = textwrap.dedent(
        """
        import os
        import sqlite3
        from pathlib import Path

        Path(os.environ["TEST_COUNTER"]).write_text("started")
        with sqlite3.connect(os.environ["TEST_STATE"]) as connection:
            connection.execute("UPDATE runs SET status='completed' WHERE id='same-run'")
        """
    )
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0, 0),
        stay_quiescent=False,
        environ=dict(os.environ, TEST_STATE=str(state_path), TEST_COUNTER=str(counter)),
        reporter=lambda _document: None,
    )

    assert supervisor.run() == 0
    assert counter.read_text() == "started"
    assert _record(state_path)["replacement_count"] == 1


def test_crash_before_first_run_commit_gets_bounded_replacement(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    counter = tmp_path / "counter"
    worker = textwrap.dedent(
        """
        import os
        import sqlite3
        from pathlib import Path

        counter = Path(os.environ["TEST_COUNTER"])
        invocation = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(invocation))
        if invocation == 1:
            os._exit(23)
        with sqlite3.connect(os.environ["TEST_STATE"]) as connection:
            connection.execute(
                "CREATE TABLE runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
                "finished_at TEXT, status TEXT NOT NULL, config_json TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO runs VALUES "
                "('fresh-run', '2026-09-18T00:00:00+00:00', NULL, 'completed', '{}')"
            )
        """
    )
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0,),
        stay_quiescent=False,
        environ=dict(os.environ, TEST_STATE=str(state_path), TEST_COUNTER=str(counter)),
        reporter=lambda _document: None,
    )

    assert supervisor.run() == 0
    assert counter.read_text() == "2"
    assert _record(state_path)["disposition"] == "completed"


def test_active_pre_spawn_record_with_absent_database_gets_replacement(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    _write_supervisor_record(state_path, phase="active", run_id=None)
    marker = tmp_path / "started"
    worker = textwrap.dedent(
        """
        import os
        import sqlite3
        from pathlib import Path

        Path(os.environ["TEST_MARKER"]).touch()
        with sqlite3.connect(os.environ["TEST_STATE"]) as connection:
            connection.execute(
                "CREATE TABLE runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
                "finished_at TEXT, status TEXT NOT NULL, config_json TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO runs VALUES "
                "('fresh-run', '2026-09-18T00:00:00+00:00', NULL, 'completed', '{}')"
            )
        """
    )
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0,),
        stay_quiescent=False,
        environ=dict(os.environ, TEST_STATE=str(state_path), TEST_MARKER=str(marker)),
        reporter=lambda _document: None,
    )

    assert supervisor.run() == 0
    assert marker.exists()
    assert _record(state_path)["replacement_count"] == 1


def test_state_store_schema_commit_before_run_gets_bounded_replacement(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    counter = tmp_path / "counter"
    worker = textwrap.dedent(
        """
        import os
        from pathlib import Path
        from rapido.state import StateStore

        counter = Path(os.environ["TEST_COUNTER"])
        invocation = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(invocation))
        state = StateStore(Path(os.environ["TEST_STATE"]))
        if invocation == 1:
            os._exit(23)
        state.start_run("fresh-run", {})
        state.finish_run("fresh-run", "completed")
        state.close()
        """
    )
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0,),
        stay_quiescent=False,
        environ=dict(
            os.environ,
            PYTHONPATH=str(ROOT),
            TEST_STATE=str(state_path),
            TEST_COUNTER=str(counter),
        ),
        reporter=lambda _document: None,
    )

    assert supervisor.run() == 0
    assert counter.read_text() == "2"
    assert _record(state_path)["replacement_count"] == 1
    assert _record(state_path)["disposition"] == "completed"


def test_zero_byte_database_from_initial_worker_gets_bounded_replacement(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    counter = tmp_path / "counter"
    worker = textwrap.dedent(
        """
        import os
        from pathlib import Path
        from rapido.state import StateStore

        counter = Path(os.environ["TEST_COUNTER"])
        invocation = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(invocation))
        if invocation == 1:
            original_fchmod = os.fchmod
            def crash_after_chmod(descriptor, mode):
                original_fchmod(descriptor, mode)
                os._exit(23)
            os.fchmod = crash_after_chmod
            StateStore(Path(os.environ["TEST_STATE"]))
        state = StateStore(Path(os.environ["TEST_STATE"]))
        state.start_run("fresh-run", {})
        state.finish_run("fresh-run", "completed")
        state.close()
        """
    )
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0,),
        stay_quiescent=False,
        environ=dict(
            os.environ,
            PYTHONPATH=str(ROOT),
            TEST_STATE=str(state_path),
            TEST_COUNTER=str(counter),
        ),
        reporter=lambda _document: None,
    )

    assert supervisor.run() == 0
    assert counter.read_text() == "2"
    assert _record(state_path)["replacement_count"] == 1
    assert _record(state_path)["disposition"] == "completed"


def test_nonempty_schema_without_one_run_fails_closed(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    with sqlite3.connect(state_path) as connection:
        connection.execute(
            "CREATE TABLE runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
            "finished_at TEXT, status TEXT NOT NULL, config_json TEXT NOT NULL)"
        )
    _write_supervisor_record(state_path, phase="active", run_id=None)
    marker = tmp_path / "started"
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )

    assert supervisor.run() == 0
    assert not marker.exists()


@pytest.mark.parametrize(
    ("record"),
    (
        None,
        {"phase": "active", "run_id": "stale-run"},
        {"phase": "terminal", "run_id": None, "disposition": "refused"},
    ),
)
def test_zero_byte_database_without_live_initial_record_fails_closed(
    record: dict[str, object] | None, tmp_path: Path
) -> None:
    state_path = _private_state(tmp_path)
    state_path.touch()
    if record is not None:
        _write_supervisor_record(state_path, **record)
    marker = tmp_path / "started"
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )

    assert supervisor.run() == 0
    assert not marker.exists()


def test_generic_exit_two_with_running_run_retries_without_state_change(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    counter = tmp_path / "counter"
    worker = textwrap.dedent(
        """
        import os
        import sqlite3
        import sys
        from pathlib import Path

        counter = Path(os.environ["TEST_COUNTER"])
        invocation = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(invocation))
        with sqlite3.connect(os.environ["TEST_STATE"]) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
                "finished_at TEXT, status TEXT NOT NULL, config_json TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO runs VALUES "
                "('same-run', '2026-09-18T00:00:00+00:00', NULL, 'running', '{}')"
            )
            if invocation > 1:
                connection.execute("UPDATE runs SET status='completed' WHERE id='same-run'")
        if invocation == 1:
            sys.exit(2)
        """
    )
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0,),
        stay_quiescent=False,
        environ=dict(os.environ, TEST_STATE=str(state_path), TEST_COUNTER=str(counter)),
        reporter=lambda _document: None,
    )

    assert supervisor.run() == 0
    assert counter.read_text() == "2"
    assert _record(state_path)["disposition"] == "completed"


def test_unread_effect_waits_for_reconcile_without_spending_crash_budget(
    tmp_path: Path,
) -> None:
    state_path = _private_state(tmp_path)
    counter = tmp_path / "counter"
    worker = textwrap.dedent(
        """
        import os
        import sqlite3
        import sys
        from pathlib import Path

        counter = Path(os.environ["TEST_COUNTER"])
        invocation = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(invocation))
        with sqlite3.connect(os.environ["TEST_STATE"]) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
                "finished_at TEXT, status TEXT NOT NULL, config_json TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO runs VALUES "
                "('same-run', '2026-09-18T00:00:00+00:00', NULL, 'running', '{}')"
            )
            if invocation == 2:
                connection.execute(
                    "CREATE TABLE submission_intents (challenge_id INTEGER, "
                    "candidate_sha256 TEXT, first_run_id TEXT, context_episode INTEGER, "
                    "status TEXT, updated_at TEXT)"
                )
                connection.execute(
                    "INSERT INTO submission_intents VALUES "
                    "(7, ?, 'same-run', 0, 'unread', 'before')",
                    ("a" * 64,),
                )
            if invocation > 2:
                connection.execute("UPDATE runs SET status='completed' WHERE id='same-run'")
        if invocation == 1:
            os._exit(23)
        if invocation == 2:
            sys.exit(2)
        """
    )
    environment = dict(os.environ, TEST_STATE=str(state_path), TEST_COUNTER=str(counter))

    first = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0, 0, 0),
        stay_quiescent=False,
        environ=environment,
        reporter=lambda _document: None,
    )
    assert first.run() == 0
    assert counter.read_text() == "2"
    assert _record(state_path)["phase"] == "blocked"
    assert _record(state_path)["replacement_count"] == 1

    unchanged = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0, 0, 0),
        stay_quiescent=False,
        environ=environment,
        reporter=lambda _document: None,
    )
    assert unchanged.run() == 0
    assert counter.read_text() == "2"

    with sqlite3.connect(state_path) as connection:
        connection.execute(
            "UPDATE submission_intents SET status='not_delivered', updated_at='after'"
        )
    resumed = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0, 0, 0),
        stay_quiescent=False,
        environ=environment,
        reporter=lambda _document: None,
    )
    assert resumed.run() == 0
    assert counter.read_text() == "3"
    assert _record(state_path)["replacement_count"] == 1
    assert _record(state_path)["disposition"] == "completed"


def test_reconcile_between_atomic_classification_and_block_record_is_not_lost(
    monkeypatch, tmp_path: Path
) -> None:
    state_path = _private_state(tmp_path)
    counter = tmp_path / "counter"
    worker = textwrap.dedent(
        """
        import os
        import sqlite3
        import sys
        from pathlib import Path

        counter = Path(os.environ["TEST_COUNTER"])
        invocation = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(invocation))
        with sqlite3.connect(os.environ["TEST_STATE"]) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
                "finished_at TEXT, status TEXT NOT NULL, config_json TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO runs VALUES "
                "('same-run', '2026-09-18T00:00:00+00:00', NULL, 'running', '{}')"
            )
            if invocation == 1:
                connection.execute(
                    "CREATE TABLE submission_intents (challenge_id INTEGER, "
                    "candidate_sha256 TEXT, first_run_id TEXT, context_episode INTEGER, "
                    "status TEXT, updated_at TEXT)"
                )
                connection.execute(
                    "INSERT INTO submission_intents VALUES "
                    "(7, ?, 'same-run', 0, 'unread', 'before')",
                    ("a" * 64,),
                )
            else:
                connection.execute("UPDATE runs SET status='completed' WHERE id='same-run'")
        if invocation == 1:
            sys.exit(2)
        """
    )
    import rapido.supervisor as supervisor_module

    original = supervisor_module._reconciliation_fingerprint

    def reconcile_after_snapshot(path: Path, run_id: str) -> str | None:
        fingerprint = original(path, run_id)
        if fingerprint is not None:
            with sqlite3.connect(path) as connection:
                connection.execute(
                    "UPDATE submission_intents SET status='not_delivered', updated_at='after'"
                )
        return fingerprint

    monkeypatch.setattr(supervisor_module, "_reconciliation_fingerprint", reconcile_after_snapshot)
    environment = dict(os.environ, TEST_STATE=str(state_path), TEST_COUNTER=str(counter))
    first = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0,),
        stay_quiescent=False,
        environ=environment,
        reporter=lambda _document: None,
    )
    assert first.run() == 0
    assert counter.read_text() == "2"
    assert _record(state_path)["disposition"] == "completed"


def test_terminal_supervisor_stays_quiescent_until_stopped(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    _write_run(state_path, "completed")
    runner = textwrap.dedent(
        """
        import os
        from pathlib import Path
        from rapido.supervisor import Supervisor

        raise SystemExit(
            Supervisor(Path(os.environ["TEST_STATE"]), reporter=lambda _document: None).run()
        )
        """
    )
    process = subprocess.Popen(
        [sys.executable, "-c", runner],
        env=dict(os.environ, PYTHONPATH=str(ROOT), TEST_STATE=str(state_path)),
    )
    time.sleep(0.2)
    assert process.poll() is None
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=5) == 0


def test_live_worker_wait_reaps_other_direct_children_without_reaping_worker(
    monkeypatch, tmp_path: Path
) -> None:
    state_path = _private_state(tmp_path)
    supervisor = Supervisor(
        state_path,
        stay_quiescent=False,
        reporter=lambda _document: None,
    )

    class LiveThenExitedProcess:
        pid = 41

        def __init__(self) -> None:
            self.polls = iter((None, 7))

        def poll(self) -> int | None:
            return next(self.polls)

        def wait(self) -> int:
            return 7

    waited: list[int] = []

    def waitpid(child: int, options: int) -> tuple[int, int]:
        assert options == os.WNOHANG
        waited.append(child)
        if child == 43:
            raise ChildProcessError
        return 0, 0

    monkeypatch.setattr(
        supervisor,
        "_direct_children",
        lambda: {41, 42, 43},
    )
    monkeypatch.setattr(os, "waitpid", waitpid)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    assert supervisor._wait_worker(LiveThenExitedProcess()) == 7
    assert waited == [42, 43]


def test_signal_is_forwarded_once_and_descendant_is_extinguished(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    worker_pid_path = tmp_path / "worker.pid"
    child_pid_path = tmp_path / "child.pid"
    signals_path = tmp_path / "signals"
    child = textwrap.dedent(
        """
        import os
        import signal
        import time
        from pathlib import Path

        Path(os.environ["TEST_CHILD_PID"]).write_text(str(os.getpid()))
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        time.sleep(60)
        """
    )
    worker = textwrap.dedent(
        """
        import os
        import signal
        import subprocess
        import sys
        import time
        from pathlib import Path

        def stop(signum, _frame):
            with Path(os.environ["TEST_SIGNALS"]).open("a") as stream:
                stream.write(f"{signum}\\n")
            raise SystemExit(130)

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        subprocess.Popen([sys.executable, "-c", os.environ["TEST_CHILD_CODE"]])
        Path(os.environ["TEST_WORKER_PID"]).write_text(str(os.getpid()))
        while True:
            time.sleep(1)
        """
    )
    runner = textwrap.dedent(
        """
        import os
        import sys
        from pathlib import Path
        from rapido.supervisor import Supervisor

        supervisor = Supervisor(
            Path(os.environ["TEST_STATE"]),
            command=(sys.executable, "-c", os.environ["TEST_WORKER_CODE"]),
            restart_backoffs=(0,),
            stop_seconds=1,
            descendant_seconds=0.2,
            stay_quiescent=False,
            reporter=lambda _document: None,
        )
        raise SystemExit(supervisor.run())
        """
    )
    environment = dict(
        os.environ,
        PYTHONPATH=str(ROOT),
        TEST_STATE=str(state_path),
        TEST_WORKER_CODE=worker,
        TEST_CHILD_CODE=child,
        TEST_WORKER_PID=str(worker_pid_path),
        TEST_CHILD_PID=str(child_pid_path),
        TEST_SIGNALS=str(signals_path),
    )
    process = subprocess.Popen([sys.executable, "-c", runner], env=environment)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not child_pid_path.exists():
        time.sleep(0.05)
    assert worker_pid_path.exists() and child_pid_path.exists()

    process.send_signal(signal.SIGTERM)
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=5) == 128 + signal.SIGTERM
    assert signals_path.read_text().splitlines() == [str(signal.SIGTERM)]
    assert _record(state_path)["disposition"] == "operator_stopped"

    child_pid = int(child_pid_path.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        raise AssertionError("worker descendant survived supervisor shutdown")

    restart_marker = tmp_path / "restart-started"
    restarted = Supervisor(
        state_path,
        command=(
            sys.executable,
            "-c",
            f"from pathlib import Path; Path({str(restart_marker)!r}).touch()",
        ),
        restart_backoffs=(0,),
        stay_quiescent=False,
        reporter=lambda _document: None,
    )
    assert restarted.run() == 0
    assert not restart_marker.exists()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux subreaper contract")
def test_direct_child_enumeration_unions_all_supervisor_threads(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    started = threading.Event()
    release = threading.Event()
    child_pid: list[int] = []

    def spawn_from_thread() -> None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
        child_pid.append(child.pid)
        started.set()
        try:
            assert release.wait(timeout=5)
        finally:
            child.terminate()
            child.wait(timeout=5)

    thread = threading.Thread(target=spawn_from_thread)
    thread.start()
    try:
        assert started.wait(timeout=5)
        supervisor = Supervisor(
            state_path,
            stay_quiescent=False,
            reporter=lambda _document: None,
        )
        assert child_pid[0] in supervisor._direct_children()
    finally:
        release.set()
        thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux subreaper contract")
def test_exited_adopted_descendant_is_reaped_while_worker_remains_alive(
    tmp_path: Path,
) -> None:
    state_path = _private_state(tmp_path)
    orphan_pid_path = tmp_path / "orphan.pid"
    orphan = textwrap.dedent(
        """
        import os
        import time
        from pathlib import Path

        Path(os.environ["TEST_ORPHAN_PID"]).write_text(str(os.getpid()))
        time.sleep(0.1)
        """
    )
    intermediate = textwrap.dedent(
        """
        import os
        import subprocess
        import sys

        subprocess.Popen([sys.executable, "-c", os.environ["TEST_ORPHAN_CODE"]])
        """
    )
    worker = textwrap.dedent(
        """
        import os
        import sqlite3
        import subprocess
        import sys
        import time
        from pathlib import Path

        with sqlite3.connect(os.environ["TEST_STATE"]) as connection:
            connection.execute(
                "CREATE TABLE runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
                "finished_at TEXT, status TEXT NOT NULL, config_json TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO runs VALUES "
                "('same-run', '2026-09-18T00:00:00+00:00', NULL, 'running', '{}')"
            )
        parent = subprocess.Popen(
            [sys.executable, "-c", os.environ["TEST_INTERMEDIATE_CODE"]]
        )
        parent.wait(timeout=5)
        orphan_pid_path = Path(os.environ["TEST_ORPHAN_PID"])
        deadline = time.monotonic() + 3
        while not orphan_pid_path.exists():
            if time.monotonic() >= deadline:
                raise SystemExit(90)
            time.sleep(0.01)
        orphan_path = Path("/proc") / orphan_pid_path.read_text()
        while orphan_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        status = "completed" if not orphan_path.exists() else "failed"
        with sqlite3.connect(os.environ["TEST_STATE"]) as connection:
            connection.execute("UPDATE runs SET status=? WHERE id='same-run'", (status,))
        raise SystemExit(0 if status == "completed" else 91)
        """
    )
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0,),
        stay_quiescent=False,
        environ=dict(
            os.environ,
            TEST_STATE=str(state_path),
            TEST_ORPHAN_PID=str(orphan_pid_path),
            TEST_ORPHAN_CODE=orphan,
            TEST_INTERMEDIATE_CODE=intermediate,
        ),
        reporter=lambda _document: None,
    )

    assert supervisor.run() == 0
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone() == ("completed",)
    assert _record(state_path)["disposition"] == "completed"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux subreaper contract")
def test_detached_worker_session_is_extinguished_before_replacement(tmp_path: Path) -> None:
    state_path = _private_state(tmp_path)
    counter = tmp_path / "counter"
    child_pid_path = tmp_path / "detached.pid"
    child = textwrap.dedent(
        """
        import os
        import signal
        import time
        from pathlib import Path

        Path(os.environ["TEST_CHILD_PID"]).write_text(str(os.getpid()))
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        while True:
            time.sleep(1)
        """
    )
    worker = textwrap.dedent(
        """
        import os
        import sqlite3
        import subprocess
        import sys
        import time
        from pathlib import Path

        counter = Path(os.environ["TEST_COUNTER"])
        invocation = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(invocation))
        with sqlite3.connect(os.environ["TEST_STATE"]) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
                "finished_at TEXT, status TEXT NOT NULL, config_json TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO runs VALUES "
                "('same-run', '2026-09-18T00:00:00+00:00', NULL, 'running', '{}')"
            )
        if invocation == 1:
            subprocess.Popen(
                [sys.executable, "-c", os.environ["TEST_CHILD_CODE"]],
                start_new_session=True,
            )
            deadline = time.monotonic() + 5
            while not Path(os.environ["TEST_CHILD_PID"]).exists():
                if time.monotonic() >= deadline:
                    os._exit(88)
                time.sleep(0.01)
            os._exit(23)
        detached = int(Path(os.environ["TEST_CHILD_PID"]).read_text())
        try:
            os.kill(detached, 0)
        except ProcessLookupError:
            with sqlite3.connect(os.environ["TEST_STATE"]) as connection:
                connection.execute("UPDATE runs SET status='completed' WHERE id='same-run'")
        else:
            os._exit(89)
        """
    )
    supervisor = Supervisor(
        state_path,
        command=(sys.executable, "-c", worker),
        restart_backoffs=(0,),
        descendant_seconds=0.5,
        stay_quiescent=False,
        environ=dict(
            os.environ,
            TEST_STATE=str(state_path),
            TEST_COUNTER=str(counter),
            TEST_CHILD_PID=str(child_pid_path),
            TEST_CHILD_CODE=child,
        ),
        reporter=lambda _document: None,
    )

    assert supervisor.run() == 0
    assert counter.read_text() == "2"
    assert _record(state_path)["disposition"] == "completed"


def test_monitor_projects_sanitized_terminal_supervisor_and_follow_exits(
    monkeypatch, capsys, tmp_path: Path
) -> None:
    state_path = _private_state(tmp_path)
    _write_run(state_path, "running", "private-run-identity")
    _write_supervisor_record(
        state_path,
        phase="terminal",
        run_id="private-run-identity",
        replacement_count=3,
        disposition="restart_budget_exhausted",
    )
    monkeypatch.setenv("RAPIDO_STATE_PATH", str(state_path))
    view = type("View", (), {"status": "running"})()
    monkeypatch.setattr(
        cli.DurableJobControl,
        "monitor_snapshot",
        staticmethod(lambda _path, run_id=None: view),
    )
    monkeypatch.setattr(
        cli,
        "monitor_payload",
        lambda _view, previous=None: ({"status": "running"}, previous),
    )
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: pytest.fail("follow did not exit"))

    assert (
        cli._monitor(
            run_id=None,
            output_format="json",
            follow=True,
            interval=5,
            record_jsonl=False,
        )
        == 0
    )
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["supervisor"] == {
        "phase": "terminal",
        "replacement_count": 3,
        "disposition": "restart_budget_exhausted",
        "run_bound": True,
    }
    assert "private-run-identity" not in output
    assert str(state_path) not in output
    assert "fingerprint" not in output


def test_monitor_follow_keeps_blocked_visible_until_terminal(monkeypatch, capsys, tmp_path) -> None:
    state_path = _private_state(tmp_path)
    monkeypatch.setenv("RAPIDO_STATE_PATH", str(state_path))
    view = type("View", (), {"status": "running"})()
    monkeypatch.setattr(
        cli.DurableJobControl,
        "monitor_snapshot",
        staticmethod(lambda _path, run_id=None: view),
    )
    monkeypatch.setattr(
        cli,
        "monitor_payload",
        lambda _view, previous=None: ({"status": "running"}, previous),
    )
    projections = iter(
        (
            {
                "phase": "blocked",
                "replacement_count": 1,
                "disposition": "operator_reconciliation_required",
                "run_bound": True,
            },
            {
                "phase": "terminal",
                "replacement_count": 1,
                "disposition": "completed",
                "run_bound": True,
            },
        )
    )
    monkeypatch.setattr(cli, "supervisor_projection", lambda _path: next(projections))
    sleeps: list[int] = []
    monkeypatch.setattr(cli.time, "sleep", sleeps.append)

    assert (
        cli._monitor(
            run_id=None,
            output_format="json",
            follow=True,
            interval=5,
            record_jsonl=False,
        )
        == 0
    )
    payloads = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [payload["supervisor"]["phase"] for payload in payloads] == [
        "blocked",
        "terminal",
    ]
    assert sleeps == [5]


def test_monitor_shows_terminal_supervisor_before_run_exists(
    monkeypatch, capsys, tmp_path: Path
) -> None:
    state_path = _private_state(tmp_path)
    _write_supervisor_record(
        state_path,
        phase="terminal",
        run_id=None,
        replacement_count=3,
        disposition="restart_budget_exhausted",
    )
    monkeypatch.setenv("RAPIDO_STATE_PATH", str(state_path))

    assert (
        cli._monitor(
            run_id=None,
            output_format="json",
            follow=True,
            interval=5,
            record_jsonl=False,
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "status": "refused",
        "supervisor": {
            "phase": "terminal",
            "replacement_count": 3,
            "disposition": "restart_budget_exhausted",
            "run_bound": False,
        },
    }


def test_monitor_follows_scheduled_pre_run_state_until_terminal(
    monkeypatch, capsys, tmp_path: Path
) -> None:
    state_path = _private_state(tmp_path)
    monkeypatch.setenv("RAPIDO_STATE_PATH", str(state_path))
    projections = iter(
        (
            {
                "phase": "scheduled",
                "replacement_count": 1,
                "disposition": None,
                "run_bound": False,
            },
            {
                "phase": "terminal",
                "replacement_count": 3,
                "disposition": "restart_budget_exhausted",
                "run_bound": False,
            },
        )
    )
    monkeypatch.setattr(cli, "supervisor_projection", lambda _path: next(projections))
    monkeypatch.setattr(
        cli.DurableJobControl,
        "monitor_snapshot",
        staticmethod(lambda _path, run_id=None: (_ for _ in ()).throw(ValueError("run is absent"))),
    )
    sleeps: list[int] = []
    monkeypatch.setattr(cli.time, "sleep", sleeps.append)

    assert (
        cli._monitor(
            run_id=None,
            output_format="json",
            follow=True,
            interval=5,
            record_jsonl=False,
        )
        == 0
    )
    payloads = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [payload["status"] for payload in payloads] == ["starting", "refused"]
    assert sleeps == [5]


def test_deployment_templates_use_persistent_restart_policy() -> None:
    compose = (ROOT / "deploy" / "docker-compose.example.yml").read_text()
    setup = (ROOT / "scripts" / "setup_container.sh").read_text()
    live_line = next(line for line in setup.splitlines() if "--restart unless-stopped" in line)

    assert "restart: unless-stopped" in compose
    assert "init: true" not in compose
    assert "--detach --restart unless-stopped --name rapido" in live_line
    assert "--init" not in setup
    assert "--rm" not in live_line
    assert 'ENTRYPOINT ["rapido", "run"]' in (ROOT / "Dockerfile").read_text()
