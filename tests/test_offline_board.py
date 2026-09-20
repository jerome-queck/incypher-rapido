from __future__ import annotations

import json
import os
import socket
import stat
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from rapido.board import BoardError
from rapido.offline_board import OfflineBoard, _regular_metadata
from rapido.offline_process import ProcessChecker, ProcessServiceController


def _task(
    board_id: int,
    task_id: str,
    *,
    dynamic: bool = False,
    files: list[str] | None = None,
) -> dict[str, object]:
    return {
        "board_id": board_id,
        "task_id": task_id,
        "name": task_id,
        "category": "misc",
        "type": "dynamic_iac" if dynamic else "standard",
        "description": "Synthetic registered task",
        "value": 100,
        "files": files or [],
        "solved": False,
        "attempts": 0,
        "max_attempts": None,
        "timeout": None,
        "shared": False,
        "service_required": dynamic,
        "resource_profile_id": "small-v1" if dynamic else "none",
        "generator_version": "generator-v1",
        "checker_version": "checker-v1",
        "service_version": "service-v1" if dynamic else "none",
    }


def _make_bank(
    tmp_path: Path,
    *,
    tasks: list[dict[str, object]] | None = None,
) -> tuple[Path, Path]:
    bank = tmp_path / "bank"
    workspace = tmp_path / "workspace"
    bank.mkdir(parents=True)
    workspace.mkdir()
    os.chmod(bank, 0o700)
    os.chmod(workspace, 0o700)
    selected = tasks or [
        _task(101, "EAS-005", files=["artifact.bin"]),
        _task(102, "EAS-006", dynamic=True),
        _task(103, "EAS-007", dynamic=True),
    ]
    for row in selected:
        visible = bank / "capsules" / str(row["task_id"]) / "visible"
        visible.mkdir(parents=True, exist_ok=True)
        for file_ref in row.get("files", []):
            source = visible / str(file_ref)
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(f"payload:{row['task_id']}:{file_ref}".encode())
    (bank / "public-catalogue.json").write_text(
        json.dumps({"catalogue_version": "catalogue-v1", "tasks": selected}),
        encoding="utf-8",
    )
    return bank, workspace


class _Checker:
    def __init__(
        self, *, failure: BaseException | None = None, result: object | None = None
    ) -> None:
        self.calls: list[tuple[str, bytes]] = []
        self.failure = failure
        self.result = result

    def __call__(self, task_id: str, candidate: bytes) -> bool:
        self.calls.append((task_id, candidate))
        if self.failure is not None:
            raise self.failure
        if self.result is not None:
            return self.result  # type: ignore[return-value]
        return candidate == b"flag{synthetic-accepted}"


class _ServiceController:
    def __init__(self) -> None:
        self.generation = 0
        self.active: str | None = None
        self.starts: list[str] = []
        self.renews: list[str] = []
        self.stops: list[str] = []

    def start(self, task_id: str) -> dict[str, object]:
        assert self.active is None
        self.generation += 1
        self.active = task_id
        self.starts.append(task_id)
        return {
            "connection_info": f"http://127.0.0.1:{41000 + self.generation}/",
            "since": self.generation,
            "until": 100 + self.generation,
        }

    def renew(self, task_id: str) -> dict[str, object]:
        assert self.active == task_id
        self.renews.append(task_id)
        return {
            "connection_info": f"http://127.0.0.1:{41000 + self.generation}/",
            "since": self.generation,
            "until": 200 + self.generation,
        }

    def stop(self, task_id: str) -> None:
        assert self.active == task_id
        self.stops.append(task_id)
        self.active = None


def _board(
    tmp_path: Path,
    *,
    checker: _Checker | None = None,
    controller: _ServiceController | None = None,
    tasks: list[dict[str, object]] | None = None,
) -> tuple[OfflineBoard, Path, Path, _Checker]:
    bank, workspace = _make_bank(tmp_path, tasks=tasks)
    selected_checker = checker or _Checker()
    return (
        OfflineBoard(
            bank,
            workspace,
            selected_checker,
            service_controller=controller,
            synthetic_in_process=True,
        ),
        bank,
        workspace,
        selected_checker,
    )


def _private_worker(bank: Path, name: str, source: str) -> Path:
    root = bank / "private"
    root.mkdir(mode=0o700, exist_ok=True)
    worker = root / name
    worker.write_text(textwrap.dedent(source), encoding="utf-8")
    worker.chmod(0o600)
    return worker


def test_catalogue_identity_list_and_detail_are_bounded_and_fresh(tmp_path: Path) -> None:
    board, _, _, _ = _board(tmp_path)

    identity = board.identity()
    assert type(identity["id"]) is int and identity["id"] > 0
    assert type(identity["team_id"]) is int and identity["team_id"] > 0
    assert board.anonymous_identity_is_rejected()
    assert [row["id"] for row in board.list_challenges()] == [101, 102, 103]
    assert all(row["solved_by_me"] is False for row in board.list_challenges())
    challenge = board.challenge(101)
    assert challenge.files == ("artifact.bin",)
    assert not challenge.solved

    with pytest.raises(BoardError, match="not selected"):
        board.challenge(999)


@pytest.mark.parametrize(
    "file_ref",
    [
        "/absolute",
        "../escape",
        "nested/../escape",
        "nested//empty",
        "nested/./dot",
        "C:/alternate",
        "nested\\alternate",
        "nul\x00value",
        "control\nvalue",
        "missing.bin",
    ],
)
def test_ob03_download_rejects_malformed_unregistered_and_cross_capsule_references(
    tmp_path: Path, file_ref: str
) -> None:
    board, _, workspace, _ = _board(tmp_path)

    with pytest.raises(BoardError):
        board.download(file_ref, workspace / "out.bin", byte_limit=1024)
    assert not (workspace / "out.bin").exists()


def test_ob03_download_is_bounded_atomic_and_returns_closed_metadata(tmp_path: Path) -> None:
    board, bank, workspace, _ = _board(tmp_path)
    expected = (bank / "capsules" / "EAS-005" / "visible" / "artifact.bin").read_bytes()

    result = board.download("artifact.bin", workspace / "nested" / "out.bin", byte_limit=1024)

    assert result == {"bytes": len(expected), "status": "closed"}
    assert (workspace / "nested" / "out.bin").read_bytes() == expected
    assert not list(workspace.rglob(".offline-copy-*"))

    with pytest.raises(BoardError, match="byte limit"):
        board.download("artifact.bin", workspace / "too-small.bin", byte_limit=1)
    assert not (workspace / "too-small.bin").exists()


def test_ob03_download_rejects_destination_escape_and_symlink_parent(tmp_path: Path) -> None:
    board, _, workspace, _ = _board(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(BoardError, match="escapes"):
        board.download("artifact.bin", outside / "escaped.bin", byte_limit=1024)

    (workspace / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(BoardError, match="directory component"):
        board.download("artifact.bin", workspace / "linked" / "escaped.bin", byte_limit=1024)
    assert not (outside / "escaped.bin").exists()


def test_ob03_download_rejects_replaced_workspace_root(tmp_path: Path) -> None:
    board, _, workspace, _ = _board(tmp_path)
    original = tmp_path / "workspace-original"
    workspace.rename(original)
    workspace.mkdir()

    with pytest.raises(BoardError, match="boundary changed"):
        board.download("artifact.bin", workspace / "out.bin", byte_limit=1024)
    assert not (workspace / "out.bin").exists()


def test_ob03_download_rejects_source_symlink_and_hardlink_swaps(tmp_path: Path) -> None:
    board, bank, workspace, _ = _board(tmp_path)
    source = bank / "capsules" / "EAS-005" / "visible" / "artifact.bin"
    external = tmp_path / "external.bin"
    external.write_bytes(b"external")

    source.unlink()
    source.symlink_to(external)
    with pytest.raises(BoardError, match="regular|invalid"):
        board.download("artifact.bin", workspace / "symlink.bin", byte_limit=1024)

    source.unlink()
    os.link(external, source)
    with pytest.raises(BoardError, match="regular"):
        board.download("artifact.bin", workspace / "hardlink.bin", byte_limit=1024)


def test_ob03_download_detects_same_inode_content_change_with_restored_metadata(
    tmp_path: Path,
) -> None:
    board, bank, workspace, _ = _board(tmp_path)
    source = bank / "capsules" / "EAS-005" / "visible" / "artifact.bin"
    registered = source.stat()
    original = source.read_bytes()
    replacement = bytes(byte ^ 1 for byte in original)
    source.write_bytes(replacement)
    os.utime(source, ns=(registered.st_atime_ns, registered.st_mtime_ns))

    with pytest.raises(BoardError, match="changed during copy"):
        board.download("artifact.bin", workspace / "changed.bin", byte_limit=1024)
    assert not (workspace / "changed.bin").exists()
    assert not list(workspace.rglob(".offline-copy-*"))


@pytest.mark.parametrize("kind", ["fifo", "socket"])
def test_ob03_catalogue_rejects_fifo_and_socket_sources(
    tmp_path: Path, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    bank, workspace = _make_bank(tmp_path)
    source = bank / "capsules" / "EAS-005" / "visible" / "artifact.bin"
    source.unlink()
    opened_socket = None
    if kind == "fifo":
        os.mkfifo(source)
    else:
        opened_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        monkeypatch.chdir(source.parent)
        opened_socket.bind(source.name)
    try:
        with pytest.raises(BoardError, match="regular"):
            OfflineBoard(bank, workspace, _Checker(), synthetic_in_process=True)
    finally:
        if opened_socket is not None:
            opened_socket.close()


def test_ob03_regular_file_policy_rejects_device_shape() -> None:
    metadata = SimpleNamespace(st_mode=stat.S_IFCHR, st_nlink=1)

    with pytest.raises(BoardError, match="regular"):
        _regular_metadata(metadata)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda tasks: tasks.append(dict(tasks[0])),
        lambda tasks: tasks[0].update(board_id=0),
        lambda tasks: tasks[0].update(solved=True),
        lambda tasks: tasks[0].update(attempts=1),
        lambda tasks: tasks[0].update(type="dynamic_iac", service_required=False),
        lambda tasks: tasks[0].update(files=["../escape"]),
        lambda tasks: tasks[0].update(files=["artifact.bin", "artifact.bin"]),
    ],
)
def test_catalogue_rejects_invalid_or_nonfresh_rows(tmp_path: Path, mutate) -> None:
    tasks = [_task(101, "EAS-005", files=["artifact.bin"])]
    mutate(tasks)

    with pytest.raises(BoardError):
        _board(tmp_path, tasks=tasks)


def test_ob04_exact_candidate_dedup_calls_checker_once_and_uses_ordinals_only(
    tmp_path: Path,
) -> None:
    checker = _Checker()
    board, _, _, _ = _board(tmp_path, checker=checker)
    candidate = "flag{synthetic-accepted}"

    with ThreadPoolExecutor(max_workers=8) as executor:
        verdicts = list(executor.map(lambda _index: board.submit(101, candidate), range(8)))

    assert all(verdict.correct for verdict in verdicts)
    assert checker.calls == [("EAS-005", candidate.encode())]
    snapshot = board.public_snapshot()
    assert snapshot["unique_candidate_count"] == 1
    assert snapshot["repeat_candidate_count"] == 7
    assert snapshot["checker_call_count"] == 1
    assert snapshot["candidates"] == [
        {
            "task_id": "EAS-005",
            "candidate_ordinal": 1,
            "outcome": "correct",
            "repeat_count": 7,
        }
    ]
    serialized = json.dumps(snapshot, sort_keys=True)
    assert candidate not in serialized
    assert "sha256" not in serialized
    assert "digest" not in serialized
    assert "candidate_length" not in serialized


def test_ob04_exact_bytes_distinguish_unicode_and_invalid_shape_never_calls_checker(
    tmp_path: Path,
) -> None:
    checker = _Checker(result=False)
    board, _, _, _ = _board(tmp_path, checker=checker)

    board.submit(101, "flag{caf\N{LATIN SMALL LETTER E WITH ACUTE}}")
    board.submit(101, "flag{cafe\N{COMBINING ACUTE ACCENT}}")
    with pytest.raises(BoardError, match="supported flag shape"):
        board.submit(101, "not-a-supported-shape")

    assert len(checker.calls) == 2
    assert checker.calls[0][1] != checker.calls[1][1]


def test_ob05_wrong_and_decoy_values_are_closed_incorrect_without_checker_detail(
    tmp_path: Path,
) -> None:
    checker = _Checker(result=False)
    board, _, _, _ = _board(tmp_path, checker=checker)

    first = board.submit(101, "flag{synthetic-decoy-one}")
    second = board.submit(101, "flag{synthetic-decoy-two}")

    assert (first.outcome, first.message, first.http_status) == ("incorrect", "incorrect", 200)
    assert (second.outcome, second.message, second.http_status) == (
        "incorrect",
        "incorrect",
        200,
    )
    assert len(checker.calls) == 2
    serialized = json.dumps(board.public_snapshot())
    assert "synthetic-decoy" not in serialized


def test_ob05_attempt_limit_counts_unique_candidates_and_never_rechecks(tmp_path: Path) -> None:
    checker = _Checker(result=False)
    task = _task(101, "EAS-005", files=["artifact.bin"])
    task["max_attempts"] = 1
    board, _, _, _ = _board(tmp_path, checker=checker, tasks=[task])

    first = board.submit(101, "flag{synthetic-first-attempt}")
    repeated = board.submit(101, "flag{synthetic-first-attempt}")
    blocked = board.submit(101, "flag{synthetic-second-attempt}")

    assert (first.outcome, first.http_status) == ("incorrect", 200)
    assert repeated == first
    assert (blocked.outcome, blocked.message, blocked.http_status) == (
        "paused",
        "attempt limit reached",
        403,
    )
    assert checker.calls == [("EAS-005", b"flag{synthetic-first-attempt}")]
    assert board.challenge(101).attempts == 1
    assert board.list_challenges()[0]["attempts"] == 1
    assert board.public_snapshot()["attempt_counts"] == [{"task_id": "EAS-005", "attempts": 1}]


def test_ob06_second_board_has_fresh_identity_and_zero_run_state(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_controller = _ServiceController()
    first, bank, _, _ = _board(first_root, controller=first_controller)
    first_identity = first.identity()
    assert first.submit(101, "flag{synthetic-accepted}").correct
    assert first.instance("POST", 102)["success"] is True
    first.close()
    assert first_controller.active is None

    second_workspace = second_root / "workspace"
    second_workspace.mkdir(parents=True)
    os.chmod(second_workspace, 0o700)
    second = OfflineBoard(
        bank,
        second_workspace,
        _Checker(),
        service_controller=_ServiceController(),
        synthetic_in_process=True,
    )

    assert first_identity != second.identity()
    assert all(row["solved_by_me"] is False for row in second.list_challenges())
    assert second.public_snapshot()["unique_candidate_count"] == 0
    assert second.public_snapshot()["checker_call_count"] == 0
    assert second.public_snapshot()["active_service_count"] == 0
    assert second.instance("GET", 102)["status"] == 404


def test_ob07_dynamic_lifecycle_has_exact_shape_one_lease_and_proven_absence(
    tmp_path: Path,
) -> None:
    controller = _ServiceController()
    board, _, _, _ = _board(tmp_path, controller=controller)
    expected_keys = {"success", "status", "connection_info", "until", "since", "message"}

    absent = board.instance("GET", 102)
    created = board.instance("POST", 102)
    ready = board.instance("GET", 102)
    busy = board.instance("POST", 103)
    renewed = board.instance("PATCH", 102)
    assert board.submit(102, "flag{synthetic-accepted}").correct
    deleted = board.instance("DELETE", 102)
    final_absent = board.instance("GET", 102)
    second_created = board.instance("POST", 102)
    second_deleted = board.instance("DELETE", 102)

    assert all(
        set(result) == expected_keys
        for result in (
            absent,
            created,
            ready,
            busy,
            renewed,
            deleted,
            final_absent,
            second_created,
            second_deleted,
        )
    )
    assert (absent["success"], absent["status"]) == (False, 404)
    assert (created["success"], created["status"]) == (True, 200)
    assert ready == created
    assert (busy["success"], busy["status"]) == (False, 429)
    assert renewed["until"] != created["until"]
    assert (deleted["success"], deleted["status"]) == (True, 200)
    assert (final_absent["success"], final_absent["status"]) == (False, 404)
    assert second_created["connection_info"] != created["connection_info"]
    assert (second_deleted["success"], second_deleted["status"]) == (True, 200)
    assert controller.starts == ["EAS-006", "EAS-006"]
    assert controller.renews == ["EAS-006"]
    assert controller.stops == ["EAS-006", "EAS-006"]
    assert controller.active is None
    assert board.public_snapshot()["active_service_count"] == 0


def test_dynamic_create_validation_failure_stops_partial_service(tmp_path: Path) -> None:
    class InvalidController(_ServiceController):
        def start(self, task_id: str) -> dict[str, object]:
            self.active = task_id
            self.starts.append(task_id)
            return {"connection_info": ""}

    controller = InvalidController()
    board, _, _, _ = _board(tmp_path, controller=controller)

    result = board.instance("POST", 102)

    assert result == {
        "success": False,
        "status": 503,
        "connection_info": "",
        "until": None,
        "since": None,
        "message": "service create failed",
    }
    assert controller.starts == ["EAS-006"]
    assert controller.stops == ["EAS-006"]
    assert controller.active is None
    assert board.public_snapshot()["active_service_count"] == 0


def test_partial_create_cleanup_failure_stays_fenced_and_close_retries(tmp_path: Path) -> None:
    class PartialController(_ServiceController):
        def __init__(self) -> None:
            super().__init__()
            self.stop_calls = 0

        def start(self, task_id: str) -> dict[str, object]:
            self.active = task_id
            self.starts.append(task_id)
            raise RuntimeError("private partial create")

        def stop(self, task_id: str) -> None:
            assert self.active == task_id
            self.stop_calls += 1
            if self.stop_calls == 1:
                raise RuntimeError("private cleanup failure")
            self.stops.append(task_id)
            self.active = None

    controller = PartialController()
    board, _, _, _ = _board(tmp_path, controller=controller)

    failed = board.instance("POST", 102)

    assert (failed["success"], failed["status"], failed["message"]) == (
        False,
        503,
        "service create failed",
    )
    assert board.public_snapshot()["active_service_count"] == 1
    assert board.public_snapshot()["cleanup_pending_service_count"] == 1
    assert board.instance("POST", 103)["message"] == "service cleanup pending"

    board.close()

    assert controller.stop_calls == 2
    assert controller.active is None
    assert board.public_snapshot()["active_service_count"] == 0
    assert board.public_snapshot()["cleanup_pending_service_count"] == 0
    assert board.public_snapshot()["service_counts"]["delete"] == 1


@pytest.mark.parametrize(
    "connection_info",
    [
        "https://example.invalid/",
        "http://localhost:41000/",
        "tcp://192.0.2.1:41000",
    ],
)
def test_dynamic_service_rejects_non_loopback_or_dns_endpoint(
    tmp_path: Path, connection_info: str
) -> None:
    class NonlocalController(_ServiceController):
        def start(self, task_id: str) -> dict[str, object]:
            self.active = task_id
            self.starts.append(task_id)
            return {"connection_info": connection_info, "since": 1, "until": 2}

    controller = NonlocalController()
    board, _, _, _ = _board(tmp_path, controller=controller)

    result = board.instance("POST", 102)

    assert (result["success"], result["status"], result["message"]) == (
        False,
        503,
        "service create failed",
    )
    assert controller.stops == ["EAS-006"]
    assert controller.active is None
    assert board.public_snapshot()["active_service_count"] == 0


def test_close_removes_active_service_and_candidate_bytes_but_preserves_closed_counts(
    tmp_path: Path,
) -> None:
    controller = _ServiceController()
    board, _, _, _ = _board(tmp_path, controller=controller)
    board.submit(101, "flag{synthetic-accepted}")
    board.instance("POST", 102)

    board.close()
    board.close()

    snapshot = board.public_snapshot()
    assert snapshot["unique_candidate_count"] == 1
    assert snapshot["checker_call_count"] == 1
    assert snapshot["active_service_count"] == 0
    assert snapshot["service_counts"]["delete"] == 1
    assert controller.stops == ["EAS-006"]
    assert board._candidate_cache == {}
    assert board._run_id == b""
    with pytest.raises(BoardError, match="closed"):
        board.identity()


@pytest.mark.parametrize(
    "checker",
    [
        _Checker(failure=TimeoutError("private timeout details")),
        _Checker(failure=RuntimeError("private oracle details")),
        _Checker(failure=KeyboardInterrupt("private checker interrupt details")),
        _Checker(result="not-a-boolean"),
    ],
)
def test_ob09_checker_failure_is_cached_inconclusive_never_incorrect_or_correct(
    tmp_path: Path, checker: _Checker
) -> None:
    board, _, _, _ = _board(tmp_path, checker=checker)
    candidate = "flag{synthetic-inconclusive}"

    first = board.submit(101, candidate)
    second = board.submit(101, candidate)

    assert (first.outcome, first.message, first.http_status) == (
        "unread",
        "oracle_inconclusive",
        503,
    )
    assert second == first
    assert len(checker.calls) == 1
    assert board.public_snapshot()["candidates"][0]["outcome"] == "oracle_inconclusive"
    assert not board.challenge(101).solved


def test_ob09_process_checker_timeout_is_bounded_reaped_and_cached_once(tmp_path: Path) -> None:
    bank, workspace = _make_bank(tmp_path, tasks=[_task(101, "EAS-005")])
    worker = _private_worker(
        bank,
        "checker_hang.py",
        """
        import signal
        import time

        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        while True:
            time.sleep(1)
        """,
    )
    checker = ProcessChecker(
        (sys.executable, str(worker)),
        (bank,),
        term_grace_ns=50_000_000,
        cleanup_reserve_ns=300_000_000,
    )
    board = OfflineBoard(bank, workspace, checker, timeout=0.8, synthetic_in_process=True)

    started = time.monotonic()
    first = board.submit(101, "flag{bounded-timeout-synthetic}")
    elapsed = time.monotonic() - started
    repeated = board.submit(101, "flag{bounded-timeout-synthetic}")

    assert elapsed < 1.1
    assert (first.outcome, first.message, first.http_status) == (
        "unread",
        "oracle_inconclusive",
        503,
    )
    assert repeated == first
    assert checker.spawn_count == checker.reaped_count == 1
    assert checker.last_cleanup_proof.kill_sent == 1
    assert checker.last_cleanup_proof.exact_cleanup
    assert board.public_snapshot()["checker_call_count"] == 1
    board.close()


def test_ob07_process_service_readiness_timeout_forces_absence_and_clears_fence(
    tmp_path: Path,
) -> None:
    bank, workspace = _make_bank(tmp_path, tasks=[_task(102, "EAS-006", dynamic=True)])
    checker_worker = _private_worker(
        bank,
        "checker.py",
        """
        import json
        import sys
        print(json.dumps({"schema": "rapido-checker-response-v1", "result": "incorrect"}))
        """,
    )
    state_file = bank / "private" / "listener.json"
    service_worker = _private_worker(
        bank,
        "service_hang.py",
        """
        import json
        import signal
        import socket
        import sys
        import time

        request = json.loads(sys.stdin.buffer.readline())
        if request["operation"] == "preflight":
            print(json.dumps({"schema": "rapido-service-response-v1", "ok": True}), flush=True)
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        with open(sys.argv[1], "w", encoding="utf-8") as target:
            json.dump({"port": listener.getsockname()[1]}, target)
        while True:
            time.sleep(1)
        """,
    )
    checker = ProcessChecker(
        (sys.executable, str(checker_worker)),
        (bank / "private",),
        cleanup_reserve_ns=300_000_000,
    )
    controller = ProcessServiceController(
        (sys.executable, str(service_worker), state_file.name),
        (bank / "private",),
        term_grace_ns=50_000_000,
        cleanup_reserve_ns=300_000_000,
    )
    board = OfflineBoard(
        bank,
        workspace,
        checker,
        service_controller=controller,
        timeout=0.8,
        instance_ready_timeout=0.8,
        instance_cleanup_timeout=0.8,
        synthetic_in_process=True,
    )
    assert board.preflight() is True

    started = time.monotonic()
    result = board.instance("POST", 102)
    elapsed = time.monotonic() - started

    assert elapsed < 1.1
    assert (result["success"], result["status"], result["message"]) == (
        False,
        503,
        "service create failed",
    )
    assert board.public_snapshot()["active_service_count"] == 0
    assert board.public_snapshot()["cleanup_pending_service_count"] == 0
    assert controller.inventory(time.monotonic_ns() + 1_000_000_000) == 0
    port = json.loads(state_file.read_text(encoding="utf-8"))["port"]
    probe = socket.socket()
    try:
        probe.settimeout(0.2)
        assert probe.connect_ex(("127.0.0.1", port)) != 0
    finally:
        probe.close()
    board.close()


def test_isolated_service_none_cleanup_proof_never_clears_owned_lease(tmp_path: Path) -> None:
    bank, workspace = _make_bank(tmp_path, tasks=[_task(102, "EAS-006", dynamic=True)])

    class Checker:
        process_isolated = True
        descendant_confined = True
        private_roots = (bank,)

        def inventory(self, **_kwargs: object) -> int:
            return 0

        def preflight(self, *_args: object, **_kwargs: object) -> bool:
            return True

        def check(self, *_args: object, **_kwargs: object) -> bool:
            return False

        def abort_and_reap(self, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(exact_cleanup=True, remaining=0)

    class LeakyService:
        process_isolated = True
        descendant_confined = True
        private_roots = (bank,)
        source_version = "service-v1"

        def inventory(self, **_kwargs: object) -> int:
            return 0

        def preflight(self, *_args: object, **_kwargs: object) -> bool:
            return True

        def start(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "connection_info": "http://127.0.0.1:41000/",
                "since": 1,
                "until": 2,
            }

        def stop(self, *_args: object, **_kwargs: object) -> None:
            return None

        def abort_and_reap(self, **_kwargs: object) -> None:
            return None

    board = OfflineBoard(bank, workspace, Checker(), service_controller=LeakyService())
    assert board.preflight() is True
    assert board.instance("POST", 102)["success"] is True

    deleted = board.instance("DELETE", 102)

    assert deleted["success"] is False
    assert deleted["status"] == 503
    assert board.public_snapshot()["active_service_count"] == 1
    with pytest.raises(BoardError, match="cleanup"):
        board.close()


def test_dynamic_service_uses_registered_ready_and_cleanup_budgets(
    tmp_path: Path,
) -> None:
    bank, workspace = _make_bank(tmp_path, tasks=[_task(102, "EAS-006", dynamic=True)])
    observed: dict[str, float] = {}

    class Checker:
        process_isolated = True
        descendant_confined = True
        private_roots = (bank,)

        def inventory(self, *, deadline_ns: int) -> int:
            observed["checker"] = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
            return 0

        def preflight(self, *_args: object, **_kwargs: object) -> bool:
            return True

        def check(self, *_args: object, **_kwargs: object) -> bool:
            return False

        def abort_and_reap(self, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(exact_cleanup=True, remaining=0)

    class DelayedService:
        process_isolated = True
        descendant_confined = True
        private_roots = (bank,)
        source_version = "service-v1"

        def inventory(self, *, deadline_ns: int) -> int:
            observed["service_preflight"] = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
            return 0

        def preflight(self, *_args: object, **kwargs: object) -> bool:
            observed["service_registration"] = (
                int(kwargs["deadline_ns"]) - time.monotonic_ns()
            ) / 1_000_000_000
            return True

        def start(self, *_args: object, **kwargs: object) -> dict[str, object]:
            time.sleep(0.08)
            observed["start"] = (int(kwargs["deadline_ns"]) - time.monotonic_ns()) / 1_000_000_000
            return {
                "connection_info": "http://127.0.0.1:41000/",
                "since": 1,
                "until": 2,
            }

        def stop(self, *_args: object, **kwargs: object) -> SimpleNamespace:
            observed["stop"] = (int(kwargs["deadline_ns"]) - time.monotonic_ns()) / 1_000_000_000
            return SimpleNamespace(exact_cleanup=True, remaining=0)

        def abort_and_reap(self, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(exact_cleanup=True, remaining=0)

    board = OfflineBoard(
        bank,
        workspace,
        Checker(),
        service_controller=DelayedService(),
        timeout=0.02,
        instance_ready_timeout=0.3,
        instance_cleanup_timeout=0.2,
    )

    assert board.preflight() is True
    assert board.instance("POST", 102)["success"] is True
    assert board.instance("DELETE", 102)["success"] is True
    assert 0 < observed["checker"] <= 0.02
    assert observed["service_preflight"] > 0.25
    assert observed["service_registration"] > 0.25
    assert observed["start"] > 0.15
    assert observed["stop"] > 0.15
    board.close()


def test_ob10_public_projection_and_output_exclude_candidates_paths_authority_and_payloads(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    controller = _ServiceController()
    board, bank, workspace, _ = _board(tmp_path, controller=controller)
    candidate = "flag{synthetic-accepted}"
    board.download("artifact.bin", workspace / "copy.bin", byte_limit=1024)
    created = board.instance("POST", 102)
    board.submit(101, candidate)
    board.instance("DELETE", 102)

    serialized = json.dumps(board.public_snapshot(), sort_keys=True)
    assert candidate not in serialized
    assert str(bank) not in serialized
    assert str(workspace) not in serialized
    assert str(created["connection_info"]) not in serialized
    assert "authority" not in serialized
    assert "payload:" not in serialized
    assert "oracle" not in serialized
    assert "sha256" not in serialized
    assert capsys.readouterr() == ("", "")
