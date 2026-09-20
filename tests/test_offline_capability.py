from __future__ import annotations

import asyncio
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import textwrap
import time
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

import rapido.board as board_module
from rapido.evidence import project_tool_observation
from rapido.offline_board import OFFLINE_BOARD_IMPLEMENTATION_VERSION, OfflineBoard
from rapido.offline_container import DockerChecker, DockerServiceController
from rapido.offline_profile import OfflineRuntimeConfig, OfflineTaskRegistration
from rapido.offline_run import (
    OFFLINE_ACCEPTANCE_SCHEMA,
    OfflineRunPlan,
    OfflineRunRegistration,
    execute_offline_plan,
    validate_offline_acceptance_receipt,
    validate_offline_stage_receipt,
)

_ENTRYPOINT_SPEC = importlib.util.spec_from_file_location(
    "offline_capability_run",
    Path(__file__).parents[1] / "scripts" / "offline_capability_run.py",
)
assert _ENTRYPOINT_SPEC is not None and _ENTRYPOINT_SPEC.loader is not None
offline_capability_run = importlib.util.module_from_spec(_ENTRYPOINT_SPEC)
_ENTRYPOINT_SPEC.loader.exec_module(offline_capability_run)

_CANDIDATE = "flag{synthetic-capability-sentinel}"
_RUNNER_IMAGE = "sha256:0eef1ceb74759bf64e9a89ca0dd1cf722bd1f6967a9b53666577164ee4d71c52"
_STAGE_RECEIPT = Path(__file__).parents[1] / "notes" / "research" / "offline-board-acceptance.json"


def _task(board_id: int, task_id: str, *, dynamic: bool) -> dict[str, object]:
    return {
        "board_id": board_id,
        "task_id": task_id,
        "name": task_id,
        "category": "misc",
        "type": "dynamic_iac" if dynamic else "standard",
        "description": "Synthetic capability sentinel",
        "value": 100,
        "files": [] if dynamic else ["artifact.bin"],
        "solved": False,
        "attempts": 0,
        "max_attempts": 3,
        "timeout": None,
        "shared": False,
        "service_required": dynamic,
        "resource_profile_id": "small-v1" if dynamic else "none",
        "generator_version": "generator-v1",
        "checker_version": "checker-v1",
        "service_version": "service-v1" if dynamic else "none",
    }


def _bank(root: Path, *, dynamic: bool) -> Path:
    bank = root / "bank"
    task_id = "EAS-006" if dynamic else "EAS-005"
    visible = bank / "capsules" / task_id / "visible"
    visible.mkdir(parents=True, mode=0o700)
    if not dynamic:
        (visible / "artifact.bin").write_bytes(b"synthetic source material\n")
    (bank / "public-catalogue.json").write_text(
        json.dumps(
            {
                "catalogue_version": "catalogue-v1",
                "tasks": [_task(106 if dynamic else 105, task_id, dynamic=dynamic)],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(bank, 0o700)
    return bank


def _private_worker(bank: Path, name: str, source: str) -> Path:
    root = bank / "private"
    root.mkdir(mode=0o700, exist_ok=True)
    path = root / name
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    path.chmod(0o600)
    return path


def _process_ports(
    bank: Path, *, dynamic: bool
) -> tuple[DockerChecker, DockerServiceController | None]:
    checker_worker = _private_worker(
        bank,
        "checker.py",
        f"""
        import json
        import struct
        import sys

        size = struct.unpack(">I", sys.stdin.buffer.read(4))[0]
        header = json.loads(sys.stdin.buffer.read(size))
        candidate = sys.stdin.buffer.read(header["candidate_bytes"])
        result = "correct" if candidate == {_CANDIDATE.encode()!r} else "incorrect"
        print(json.dumps({{"schema": "rapido-checker-response-v1", "result": result}}))
        """,
    )
    checker = DockerChecker(
        worker_entrypoint=checker_worker,
        private_roots=(bank,),
        worker_sha256=hashlib.sha256(checker_worker.read_bytes()).hexdigest(),
        image=_RUNNER_IMAGE,
        checker_version="checker-v1",
    )
    if not dynamic:
        return checker, None
    service_worker = _private_worker(
        bank,
        "service.py",
        """
        import json
        import secrets
        import socket
        import sys
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"synthetic service observation\\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, _format, *_args):
                return

        internal_port = int(sys.argv[1])
        request = json.loads(sys.stdin.buffer.readline())
        try:
            probe = socket.create_connection(("1.1.1.1", 53), timeout=0.2)
        except OSError:
            pass
        else:
            probe.close()
            raise SystemExit(9)
        token = secrets.token_hex(32)
        server = ThreadingHTTPServer(("0.0.0.0", internal_port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        record = {
            "schema": "rapido-service-response-v1",
            "ready": True,
            "connection_info": f"http://127.0.0.1:{internal_port}/",
            "since": 1,
            "until": 2,
            "generation_nonce": token,
        }
        print(json.dumps(record), flush=True)
        for line in sys.stdin.buffer:
            command = json.loads(line)
            if command["operation"] == "renew":
                record["until"] += 1
                print(json.dumps(record), flush=True)
        """,
    )
    controller = DockerServiceController(
        worker_entrypoint=service_worker,
        private_roots=(bank,),
        worker_sha256=hashlib.sha256(service_worker.read_bytes()).hexdigest(),
        image=_RUNNER_IMAGE,
        source_version="service-v1",
    )
    return checker, controller


@dataclass(frozen=True)
class _ProcessEvidence:
    checker: DockerChecker
    service: DockerServiceController | None


def _process_deadline() -> int:
    return time.monotonic_ns() + 2_000_000_000


class _SentinelRuntime:
    def __init__(self, *, dynamic: bool) -> None:
        self.dynamic = dynamic
        self.started = False
        self.closed = False
        self.validated: list[tuple[str, str]] = []
        self.target_calls = 0

    async def start(self) -> None:
        self.started = True

    async def validate_model(self, model: str, effort: str) -> None:
        self.validated.append((model, effort))

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        document = json.loads(prompt)
        role = document["control_route"]["role"]
        lane = document["lane"]
        selected = lane == 0 and role in (
            {"specialist", "verifier", "recovery"} if self.dynamic else {"specialist", "verifier"}
        )
        candidate = _CANDIDATE if selected else None
        registry = kwargs.get("tool_registry")
        tool_name = "http_request" if self.dynamic and registry is not None else "inspect_file"
        calls: list[dict[str, object]] = []
        if candidate is not None:
            if self.dynamic and registry is not None:
                result = registry.dispatch("http_request", {"path": "/"})
                assert result["status"] == 200
                self.target_calls += 1
            elif not self.dynamic:
                artifacts = sorted((workspace / "artifacts").glob("artifact-*-artifact.bin"))
                assert len(artifacts) == 1
                assert artifacts[0].read_bytes() == b"synthetic source material\n"
            digest = hashlib.sha256(candidate.encode()).hexdigest()
            observation = project_tool_observation(
                tool_name,
                success=True,
                source_bound=True,
                candidate_sensitive=True,
                candidate_sha256s=(digest,),
            )
            calls.append(
                {
                    "name": tool_name,
                    "success": True,
                    "source_bound": True,
                    "candidate_sensitive": True,
                    "candidate_sha256s": [digest],
                    "supplied_candidate_sha256s": [],
                    "host_observation": observation,
                }
            )
        await asyncio.sleep(0)
        return type(
            "SentinelTurn",
            (),
            {
                "status": "completed",
                "text": json.dumps(
                    {
                        "status": "candidate" if candidate else "unsolved",
                        "candidate": candidate,
                        "confidence": 0.9 if candidate else 0.1,
                        "summary": "synthetic source-bound result",
                        "evidence": ["closed observation"] if candidate else [],
                        "next_steps": [],
                    }
                ),
                "tool_calls": calls,
            },
        )()

    async def close(self) -> None:
        self.closed = True

    def cleanup_record(self) -> dict[str, object]:
        return {
            "process_absent": self.closed,
            "active_process_count": 0 if self.closed else 1,
        }


class _BlockingDynamicRuntime(_SentinelRuntime):
    def __init__(self) -> None:
        super().__init__(dynamic=True)
        self.target_started = asyncio.Event()
        self.cancelled = False

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        if kwargs.get("tool_registry") is None:
            return await super().solve(workspace, prompt, **kwargs)
        self.target_started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("unreachable")


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True)
    os.chmod(path, 0o700)
    return path


def _plan(
    tmp_path: Path, *, dynamic: bool
) -> tuple[OfflineRunPlan, _SentinelRuntime, _ProcessEvidence, Path]:
    private = _private_directory(tmp_path / ("dynamic" if dynamic else "static"))
    run_parent = _private_directory(private / "runs")
    receipt_parent = _private_directory(private / "receipts")
    codex_home = _private_directory(private / "codex-home")
    auth = codex_home / "auth.json"
    auth.write_text("{}", encoding="utf-8")
    auth.chmod(0o600)
    bank = _bank(private, dynamic=dynamic)
    run_root = run_parent / "run"
    receipt = receipt_parent / "offline-board-acceptance.json"
    challenge_id = 106 if dynamic else 105
    config = OfflineRuntimeConfig.build(
        offline_profile_id="capability-v1",
        catalogue_version="catalogue-v1",
        board_implementation_version=OFFLINE_BOARD_IMPLEMENTATION_VERSION,
        state_path=run_root / "state.sqlite3",
        work_root=run_root / "work",
        codex_home=codex_home,
        runner_image=_RUNNER_IMAGE,
        task_registrations=(
            OfflineTaskRegistration(
                challenge_id,
                "EAS-006" if dynamic else "EAS-005",
                "generator-v1",
                "checker-v1",
                "service-v1" if dynamic else "none",
            ),
        ),
        active_challenges=1,
        episodes_per_challenge=3 if dynamic else 2,
        attempts_per_challenge=2,
        lead_lanes=1,
        max_artifact_bytes=1024,
        max_challenge_bytes=2048,
        max_workspace_bytes=6144,
        run_seconds=800,
    )
    runtime = _SentinelRuntime(dynamic=dynamic)
    checker, service = _process_ports(bank, dynamic=dynamic)

    return (
        OfflineRunPlan(
            config=config,
            board_factory=lambda: OfflineBoard(
                bank,
                config.work_root,
                checker,
                service_controller=service if dynamic else None,
                offline_profile_id=config.offline_profile_id,
                artifact_limit=config.max_artifact_bytes,
                capsule_limit=config.max_challenge_bytes,
                timeout=config.board_timeout_seconds,
                instance_ready_timeout=config.instance_ready_seconds,
                instance_cleanup_timeout=config.instance_cleanup_seconds,
            ),
            runtime=runtime,
            run_root=run_root,
            receipt_path=receipt,
            private_roots=(bank,),
            isolation_backend="synthetic-container-controller-v1",
            isolation_probe=lambda: True,
            runtime_cleanup_probe=runtime.cleanup_record,
        ),
        runtime,
        _ProcessEvidence(checker, service),
        bank,
    )


@pytest.mark.parametrize("dynamic", [False, True], ids=["EAS-005", "EAS-006"])
def test_ob02_ob07_static_and_dynamic_sentinels_use_unchanged_control_and_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dynamic: bool,
) -> None:
    def production_board_forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("production BoardClient was constructed")

    monkeypatch.setattr(board_module.BoardClient, "__init__", production_board_forbidden)
    plan, runtime, processes, _ = _plan(tmp_path, dynamic=dynamic)

    receipt = asyncio.run(execute_offline_plan(plan))

    assert receipt["schema"] == OFFLINE_ACCEPTANCE_SCHEMA
    assert receipt["status"] == "completed"
    assert receipt["cleanup"]["exact_cleanup"] is True
    assert receipt["run_report"]["submission_http_200_correct"] == 1
    assert receipt["run_report"]["run_local_verified"] == 1
    assert receipt["board"]["checker_call_count"] == 1
    assert receipt["board"]["active_service_count"] == 0
    assert runtime.started and runtime.closed
    assert ("gpt-daybreak-blue-latest", "xhigh") in runtime.validated
    assert not plan.run_root.exists()
    assert not (plan.config.codex_home / ".rapido-supervisor.lock").exists()
    assert processes.checker.spawn_count == processes.checker.reaped_count == 1
    if dynamic:
        assert processes.service is not None
        assert processes.service.spawn_count == processes.service.reaped_count == 2
        assert processes.service.peak_active_processes == 1
        assert processes.service.inventory(_process_deadline()) == 0
        assert runtime.target_calls == 2
        assert receipt["board"]["service_counts"] == {
            "create": 2,
            "renew": 0,
            "delete": 2,
            "absence": 4,
        }
    else:
        assert processes.service is None
        assert runtime.target_calls == 0


@pytest.mark.parametrize("dynamic", [False, True], ids=["static", "dynamic"])
def test_ob06_ob08_ob10_two_fresh_runs_are_private_and_leave_only_sanitized_receipts(
    tmp_path: Path,
    dynamic: bool,
) -> None:
    first, _, first_processes, first_bank = _plan(tmp_path / "first", dynamic=dynamic)
    second, _, second_processes, second_bank = _plan(tmp_path / "second", dynamic=dynamic)

    first_receipt = asyncio.run(execute_offline_plan(first))
    second_receipt = asyncio.run(execute_offline_plan(second))

    for plan, receipt, bank in (
        (first, first_receipt, first_bank),
        (second, second_receipt, second_bank),
    ):
        validate_offline_acceptance_receipt(receipt)
        persisted = plan.receipt_path.read_text(encoding="utf-8")
        assert _CANDIDATE not in persisted
        assert hashlib.sha256(_CANDIDATE.encode()).hexdigest() not in persisted
        assert str(bank) not in persisted
        assert str(plan.run_root) not in persisted
        assert "http://" not in persisted
        assert not plan.run_root.exists()
        assert receipt["board"]["unique_candidate_count"] == 1
        assert receipt["board"]["checker_call_count"] == 1
    assert first_receipt["run_report"]["run_id"] != second_receipt["run_report"]["run_id"]
    if dynamic:
        assert first_processes.service is not None and second_processes.service is not None
        first_states = set(first_processes.service.private_generation_nonces)
        second_states = set(second_processes.service.private_generation_nonces)
        assert len(first_states) == len(second_states) == 2
        assert first_states.isdisjoint(second_states)
        assert first_processes.service.inventory(_process_deadline()) == 0
        assert second_processes.service.inventory(_process_deadline()) == 0


def test_ob08_cancellation_drains_owned_service_and_exact_run_state(tmp_path: Path) -> None:
    plan, _, processes, _ = _plan(tmp_path, dynamic=True)
    runtime = _BlockingDynamicRuntime()
    plan = replace(plan, runtime=runtime, runtime_cleanup_probe=runtime.cleanup_record)

    async def cancel_after_target_start() -> dict[str, object]:
        task = asyncio.create_task(execute_offline_plan(plan))
        await asyncio.wait_for(runtime.target_started.wait(), timeout=3)
        task.cancel()
        return await task

    receipt = asyncio.run(cancel_after_target_start())

    assert receipt["status"] == "interrupted"
    assert receipt["cleanup"]["exact_cleanup"] is True
    assert receipt["board"]["active_service_count"] == 0
    assert processes.service is not None
    assert processes.service.spawn_count == processes.service.reaped_count == 1
    assert processes.service.inventory(_process_deadline()) == 0
    assert runtime.cancelled and runtime.closed
    assert not plan.run_root.exists()


def test_ob08_repeated_cancellation_cannot_interrupt_cleanup_or_leave_active_receipt(
    tmp_path: Path,
) -> None:
    plan, _, processes, _ = _plan(tmp_path, dynamic=True)
    runtime = _BlockingDynamicRuntime()
    cleanup_started = asyncio.Event()

    async def delayed_cleanup() -> dict[str, object]:
        cleanup_started.set()
        await asyncio.sleep(0.1)
        return runtime.cleanup_record()

    plan = replace(plan, runtime=runtime, runtime_cleanup_probe=delayed_cleanup)

    async def cancel_twice() -> dict[str, object]:
        task = asyncio.create_task(execute_offline_plan(plan))
        await asyncio.wait_for(runtime.target_started.wait(), timeout=5)
        task.cancel()
        await asyncio.wait_for(cleanup_started.wait(), timeout=5)
        task.cancel()
        return await task

    receipt = asyncio.run(cancel_twice())

    assert receipt["status"] == "interrupted"
    assert receipt["cleanup"]["exact_cleanup"] is True
    assert receipt["board"]["active_service_count"] == 0
    assert receipt["board"]["cleanup_pending_service_count"] == 0
    assert processes.service is not None
    assert processes.service.inventory(_process_deadline()) == 0
    assert not plan.run_root.exists()

    malformed = copy.deepcopy(receipt)
    malformed["board"]["active_service_count"] = 1
    with pytest.raises(ValueError, match="retains an owned service"):
        validate_offline_acceptance_receipt(malformed)


def test_cleanup_failure_retains_run_state_and_never_claims_exact_cleanup(tmp_path: Path) -> None:
    plan, _, _, _ = _plan(tmp_path, dynamic=False)
    created: list[OfflineBoard] = []
    original_factory = plan.board_factory

    class CloseFailure:
        def __init__(self, board: OfflineBoard) -> None:
            self.board = board

        def __getattr__(self, name: str) -> object:
            return getattr(self.board, name)

        def close(self) -> None:
            raise RuntimeError("private cleanup detail")

    def factory() -> CloseFailure:
        board = original_factory()
        assert isinstance(board, OfflineBoard)
        created.append(board)
        return CloseFailure(board)

    plan = replace(plan, board_factory=factory)

    receipt = asyncio.run(execute_offline_plan(plan))

    assert receipt["status"] == "failed"
    assert receipt["cleanup"]["board_closed"] is False
    assert receipt["cleanup"]["exact_cleanup"] is False
    assert receipt["cleanup"]["run_root_absent"] is False
    assert plan.run_root.exists()
    assert "private cleanup detail" not in plan.receipt_path.read_text(encoding="utf-8")
    created[0].close()


def test_native_process_absence_failure_retains_run_state_and_fence(tmp_path: Path) -> None:
    plan, _, _, _ = _plan(tmp_path, dynamic=False)
    plan = replace(
        plan,
        runtime_cleanup_probe=lambda: {
            "process_absent": False,
            "active_process_count": 1,
        },
    )

    receipt = asyncio.run(execute_offline_plan(plan))

    assert receipt["status"] == "failed"
    assert receipt["cleanup"]["native_process_absent"] is False
    assert receipt["cleanup"]["native_active_process_count"] == 1
    assert receipt["cleanup"]["exact_cleanup"] is False
    assert plan.run_root.exists()


def test_run_root_identity_swap_fails_closed_without_deleting_replacement(tmp_path: Path) -> None:
    plan, _, _, _ = _plan(tmp_path, dynamic=False)
    parked = plan.run_root.with_name("parked-real-run")
    victim = plan.run_root.with_name("victim")
    victim.mkdir(mode=0o700)
    marker = victim / "keep.txt"
    marker.write_text("keep", encoding="utf-8")

    def swap_before_cleanup() -> dict[str, object]:
        plan.run_root.rename(parked)
        victim.rename(plan.run_root)
        return {"process_absent": True, "active_process_count": 0}

    swapped = replace(plan, runtime_cleanup_probe=swap_before_cleanup)
    try:
        receipt = asyncio.run(execute_offline_plan(swapped))

        assert receipt["status"] == "failed"
        assert receipt["cleanup"]["exact_cleanup"] is False
        assert (plan.run_root / "keep.txt").read_text(encoding="utf-8") == "keep"
        assert parked.is_dir()
        assert (parked / "work").is_dir()
    finally:
        shutil.rmtree(plan.run_root, ignore_errors=True)
        shutil.rmtree(parked, ignore_errors=True)


def test_owned_tree_file_substitution_cannot_claim_exact_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rapido.offline_run import _remove_owned_tree

    owned = tmp_path / "owned"
    owned.mkdir()
    state = owned / "state"
    state.write_text("owned", encoding="utf-8")
    victim = tmp_path / "victim"
    victim.write_text("victim", encoding="utf-8")
    parked = tmp_path / "parked-owned-state"
    original_unlink = os.unlink
    swapped = False

    def swap_then_unlink(path: object, *, dir_fd: int | None = None) -> None:
        nonlocal swapped
        if path == "state" and dir_fd is not None and not swapped:
            state.rename(parked)
            victim.rename(state)
            swapped = True
        original_unlink(path, dir_fd=dir_fd)

    descriptor = os.open(owned, os.O_RDONLY | os.O_DIRECTORY)
    monkeypatch.setattr(os, "unlink", swap_then_unlink)
    try:
        with pytest.raises(OSError, match="not exact"):
            _remove_owned_tree(descriptor)
    finally:
        os.close(descriptor)
    assert parked.read_text(encoding="utf-8") == "owned"


def test_owned_tree_directory_substitution_cannot_claim_exact_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rapido.offline_run import _remove_owned_tree

    owned = tmp_path / "owned"
    child = owned / "work"
    child.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.mkdir()
    parked = tmp_path / "parked-owned-work"
    original_rmdir = os.rmdir
    swapped = False

    def swap_then_rmdir(path: object, *, dir_fd: int | None = None) -> None:
        nonlocal swapped
        if path == "work" and dir_fd is not None and not swapped:
            child.rename(parked)
            victim.rename(child)
            swapped = True
        original_rmdir(path, dir_fd=dir_fd)

    descriptor = os.open(owned, os.O_RDONLY | os.O_DIRECTORY)
    monkeypatch.setattr(os, "rmdir", swap_then_rmdir)
    try:
        with pytest.raises(OSError, match="not exact"):
            _remove_owned_tree(descriptor)
    finally:
        os.close(descriptor)
    assert parked.is_dir()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda receipt: receipt["effective_config"].update(task_registrations=[]),
        lambda receipt: receipt["effective_config"].update(
            diagnostic="diagnostic at /private/oracle/answer"
        ),
        lambda receipt: receipt["board"].update(note=r"secret path C:\private\oracle"),
        lambda receipt: receipt["run_report"].update(challenge_count=0),
        lambda receipt: receipt["run_report"].update(run_id="prefix /Users/example/private"),
        lambda receipt: receipt["board"].update(active_service_count=1),
        lambda receipt: receipt["cleanup"].update(native_active_process_count=1),
        lambda receipt: (
            receipt.update(status="interrupted"),
            receipt["run_report"].update(status="completed"),
        ),
    ],
)
def test_acceptance_validator_rejects_empty_active_or_cross_field_inconsistency(
    tmp_path: Path, mutation
) -> None:
    plan, _, _, _ = _plan(tmp_path, dynamic=False)
    receipt = asyncio.run(execute_offline_plan(plan))
    malformed = copy.deepcopy(receipt)
    mutation(malformed)

    with pytest.raises(ValueError):
        validate_offline_acceptance_receipt(malformed)


def test_acceptance_validator_binds_multi_task_ordinals_and_attempts(tmp_path: Path) -> None:
    plan, _, _, _ = _plan(tmp_path, dynamic=False)
    receipt = asyncio.run(execute_offline_plan(plan))
    multi = copy.deepcopy(receipt)
    second = copy.deepcopy(multi["effective_config"]["task_registrations"][0])
    second.update(board_id=106, task_id="EAS-006")
    multi["effective_config"]["task_registrations"].append(second)
    multi["effective_config"]["selected_challenge_count"] = 2
    multi["effective_config"]["active_challenges"] = 2
    multi["effective_config"]["concurrency"] *= 2
    multi["board"]["task_registrations"] = copy.deepcopy(
        multi["effective_config"]["task_registrations"]
    )
    multi["board"]["selected_task_count"] = 2
    multi["board"]["unique_candidate_count"] = 2
    multi["board"]["checker_call_count"] = 2
    multi["board"]["attempt_counts"].append({"task_id": "EAS-006", "attempts": 1})
    multi["board"]["candidates"].append(
        {
            "task_id": "EAS-006",
            "candidate_ordinal": 1,
            "outcome": "incorrect",
            "repeat_count": 0,
        }
    )
    multi["run_report"]["challenge_count"] = 2
    multi["run_report"]["unsolved"] = 1
    validate_offline_acceptance_receipt(multi)

    wrong_ordinal = copy.deepcopy(multi)
    wrong_ordinal["board"]["candidates"][1]["candidate_ordinal"] = 2
    with pytest.raises(ValueError, match="candidate rows are inconsistent"):
        validate_offline_acceptance_receipt(wrong_ordinal)

    wrong_attempts = copy.deepcopy(multi)
    wrong_attempts["board"]["attempt_counts"][1]["attempts"] = 0
    with pytest.raises(ValueError, match="attempt accounting"):
        validate_offline_acceptance_receipt(wrong_attempts)


def test_offline_cli_closes_factory_errors_without_private_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(_value: str):
        print("flag{private-factory-stdout}")
        print("/private/oracle", file=sys.stderr)
        raise RuntimeError("/private/oracle/flag{must-not-leak}")

    monkeypatch.setattr(offline_capability_run, "_factory", fail)

    result = offline_capability_run.main(["--factory", "private.module:factory"])

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "schema": OFFLINE_ACCEPTANCE_SCHEMA,
        "status": "failed",
        "error": "offline_setup_failed",
    }
    assert "oracle" not in captured.err
    assert "flag{" not in captured.err
    assert "Traceback" not in captured.err


def test_offline_cli_discards_private_fd_output(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    def fail(_value: str):
        os.write(1, b"flag{private-fd-stdout}")
        os.write(2, b"/private/oracle/fd-stderr")
        raise RuntimeError("closed")

    monkeypatch.setattr(offline_capability_run, "_factory", fail)

    result = offline_capability_run.main(["--factory", "private.module:factory"])

    captured = capfd.readouterr()
    assert result == 1
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "schema": OFFLINE_ACCEPTANCE_SCHEMA,
        "status": "failed",
        "error": "offline_setup_failed",
    }


def test_offline_cli_deadline_is_not_a_success_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plan, _, _, _ = _plan(tmp_path, dynamic=False)
    registration = OfflineRunRegistration(
        config=plan.config,
        board_factory=plan.board_factory,
        run_root=plan.run_root,
        receipt_path=plan.receipt_path,
        private_roots=plan.private_roots,
        isolation_backend="docker-container-v1",
    )

    async def deadline(_plan: object) -> dict[str, object]:
        return {
            "schema": OFFLINE_ACCEPTANCE_SCHEMA,
            "status": "deadline",
            "cleanup": {"exact_cleanup": True},
        }

    monkeypatch.setattr(offline_capability_run, "_factory", lambda _value: lambda: registration)
    monkeypatch.setattr(offline_capability_run, "build_native_offline_plan", lambda _value: plan)
    monkeypatch.setattr(offline_capability_run, "execute_offline_plan", deadline)

    result = offline_capability_run.main(["--factory", "private.module:factory"])

    assert result == 1
    assert json.loads(capsys.readouterr().out)["run_completed"] is False


def test_offline_cli_discards_private_output_from_entire_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plan, _, _, _ = _plan(tmp_path, dynamic=False)
    original_factory = plan.board_factory

    def noisy_board_factory() -> OfflineBoard:
        print("flag{private-board-stdout}")
        print("/private/oracle/answer", file=sys.stderr)
        return original_factory()  # type: ignore[return-value]

    plan = replace(plan, board_factory=noisy_board_factory)
    registration = OfflineRunRegistration(
        config=plan.config,
        board_factory=plan.board_factory,
        run_root=plan.run_root,
        receipt_path=plan.receipt_path,
        private_roots=plan.private_roots,
        isolation_backend="docker-container-v1",
    )
    monkeypatch.setattr(offline_capability_run, "_factory", lambda _value: lambda: registration)
    monkeypatch.setattr(offline_capability_run, "build_native_offline_plan", lambda _value: plan)

    result = offline_capability_run.main(["--factory", "private.module:factory"])

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "schema": OFFLINE_ACCEPTANCE_SCHEMA,
        "status": "failed",
        "error": "offline_setup_failed",
    }
    assert "flag{" not in captured.err
    assert "/private" not in captured.err


def test_offline_entrypoint_source_has_no_production_authority_construction() -> None:
    source = (Path(__file__).parents[1] / "scripts" / "offline_capability_run.py").read_text(
        encoding="utf-8"
    )

    assert "BoardClient" not in source
    assert "RuntimeConfig.from_env" not in source
    assert "CTFD_" not in source


def test_cap02_stage_receipt_is_complete_closed_and_candidate_free() -> None:
    receipt = json.loads(_STAGE_RECEIPT.read_text(encoding="utf-8"))
    validate_offline_stage_receipt(receipt)

    assert receipt["schema"] == "rapido-offline-board-stage-acceptance-v1"
    assert receipt["evidence_level"] == "synthetic_controller_acceptance"
    assert receipt["sentinel_ids"] == ["EAS-005", "EAS-006"]
    assert all(row["passed"] for row in receipt["existing_board_scenarios"])
    assert [row["case_id"] for row in receipt["offline_cases"]] == [
        f"OB-{index:02d}" for index in range(1, 11)
    ]
    assert all(row["passed"] for row in receipt["offline_cases"])
    assert all(row["exact_cleanup"] for row in receipt["sentinel_results"])
    assert receipt["candidate_economy"]["checker_call_count"] == 2
    assert receipt["fresh_second_run"] == {
        "new_synthetic_identity": True,
        "zero_initial_solved_state": True,
        "zero_initial_candidate_cache": True,
        "zero_initial_service_state": True,
        "old_run_root_absent": True,
        "fresh_dynamic_private_state": True,
        "second_dynamic_run_exact_cleanup": True,
    }
    assert receipt["owned_lifecycle"]["exact_cleanup"] is True
    assert receipt["owned_lifecycle"]["final_owned_service_count"] == 0
    assert receipt["owned_lifecycle"]["final_owned_process_count"] == 0
    assert receipt["owned_lifecycle"]["final_workspace_count"] == 0
    assert receipt["owned_lifecycle"]["final_state_count"] == 0
    assert all(receipt["privacy"].values())
    assert receipt["passed"] is True
    encoded = json.dumps(receipt, sort_keys=True)
    for forbidden in (
        _CANDIDATE,
        hashlib.sha256(_CANDIDATE.encode()).hexdigest(),
        "http://",
        "https://",
        "CTFD_API_TOKEN",
        "TEAM_KEY",
        "raw_payload",
    ):
        assert forbidden not in encoded
