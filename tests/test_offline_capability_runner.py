from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import rapido.offline_capability_runner as capability_runner
from rapido.control import DurableJobControl
from rapido.offline_board import OFFLINE_BOARD_IMPLEMENTATION_VERSION, OfflineBoard
from rapido.offline_capability_runner import (
    RUNNER_RECEIPT_SCHEMA,
    CandidateCheck,
    CapabilityRunnerError,
    CapabilitySupervisorError,
    CheckerCandidateAttestation,
    CheckerEconomyAttestation,
    CleanupInventory,
    ExecutionPolicy,
    FlowEvidence,
    ModelDescriptor,
    ProviderAttempt,
    RegisteredFlowFactory,
    ResourceObservation,
    RunControl,
    RunnerContract,
    ServiceAttempt,
    TaskEvidence,
    TaskRegistration,
    Usage,
    UsageCaps,
    _run_completion_driven_worker,
    durable_job_control_flow,
    run_completion_driven,
    validate_runner_receipt,
)
from rapido.offline_profile import OfflineRuntimeConfig, OfflineTaskRegistration
from rapido.orchestrator import RunReport


def _sha256_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _attestation(tasks: dict[str, TaskEvidence]) -> CheckerEconomyAttestation:
    candidates = tuple(
        CheckerCandidateAttestation(
            task_id=task_id,
            checker_version="checker-v1",
            ordinal=ordinal,
            result=check.result,
            repeat_count=evidence.candidate_repeat_count if ordinal == 1 else 0,
        )
        for task_id, evidence in tasks.items()
        for ordinal, check in enumerate(evidence.candidate_checks, 1)
    )
    return CheckerEconomyAttestation(
        source="offline_board_private_cache_v1",
        cache_scope="run_local",
        unique_candidate_count=len(candidates),
        repeat_candidate_count=sum(item.repeat_count for item in candidates),
        checker_call_count=len(candidates),
        candidates=candidates,
    )


class AttestedBoard:
    def __init__(
        self,
        attestation: CheckerEconomyAttestation,
        registrations: tuple[TaskRegistration, ...],
    ) -> None:
        self.attestation = attestation
        self.registrations = registrations

    def public_snapshot(self) -> dict[str, object]:
        return {
            "unique_candidate_count": self.attestation.unique_candidate_count,
            "repeat_candidate_count": self.attestation.repeat_candidate_count,
            "checker_call_count": self.attestation.checker_call_count,
            "task_registrations": [
                {
                    "task_id": task.task_id,
                    "generator_version": task.generator_version,
                    "checker_version": task.checker_version,
                    "service_version": task.service_version,
                }
                for task in self.registrations
            ],
            "candidates": [
                {
                    "task_id": row.task_id,
                    "candidate_ordinal": row.ordinal,
                    "outcome": "oracle_inconclusive"
                    if row.result == "inconclusive"
                    else row.result,
                    "repeat_count": row.repeat_count,
                }
                for row in self.attestation.candidates
            ],
        }


def _task(
    task_id: str,
    family: str = "SENT-A",
    tier: str = "sentinel",
    category: str | None = None,
) -> TaskRegistration:
    return TaskRegistration(
        task_id=task_id,
        family_id=family,
        category=("sentinel" if tier == "sentinel" else "reverse")
        if category is None
        else category,
        tier=tier,
        checker_version="checker-v1",
    )


def _frozen_tasks(*overrides: TaskRegistration) -> tuple[TaskRegistration, ...]:
    tasks = [
        *(_task(f"EAS-00{index}") for index in range(1, 7)),
        *(
            _task(
                f"CAL-{index:03d}",
                family=f"FAM-{(index - 1) % 4 + 1}",
                tier="A",
                category=("reverse", "crypto", "web", "pwn")[(index - 1) % 4],
            )
            for index in range(1, 13)
        ),
    ]
    replacements = {task.task_id: task for task in overrides}
    if len(replacements) != len(overrides):
        raise CapabilityRunnerError("runner task IDs are not unique")
    return tuple(replacements.get(task.task_id, task) for task in tasks)


def _cleanup() -> CleanupInventory:
    return CleanupInventory(0, 0, 0, 0, 0, 0, 0, 0)


def _resources() -> ResourceObservation:
    return ResourceObservation(
        cpu_peak_cores=0.25,
        memory_peak_bytes=1024,
        pids_peak=1,
        disk_peak_bytes=2048,
        unavailable_reason=None,
    )


def _correct(start: int, terminal: int) -> TaskEvidence:
    return TaskEvidence(
        admitted_ms=max(0, start - 1),
        started_ms=start,
        terminal_ms=terminal,
        terminal_label="correct",
        candidate_checks=(
            CandidateCheck(
                candidate_returned_ms=start + 1,
                checker_started_ms=start + 1,
                checker_ended_ms=start + 2,
                result="correct",
            ),
        ),
        provider_attempts=(
            ProviderAttempt(
                lane=0,
                requested_model="gpt-daybreak-blue-latest",
                requested_effort="xhigh",
                effective_model="gpt-daybreak-blue-latest",
                effective_effort="xhigh",
                effective_revision_build="provider-v1",
                native_client_version="codex-v1",
                status="completed",
                started_ms=start,
                ended_ms=start + 2,
                usage=Usage(input=3, cached_input=1, output=2, reasoning=1),
            ),
        ),
        qualification="accepted",
        qualification_ms=start + 2,
        independent_verification=None,
        resources=_resources(),
        cleanup_passed=True,
    )


def _complete_tasks(**overrides: TaskEvidence) -> dict[str, TaskEvidence]:
    return {
        task.task_id: overrides.get(
            task.task_id,
            TaskEvidence(
                admitted_ms=0,
                started_ms=0,
                terminal_ms=0,
                terminal_label="no_unique_candidate",
                resources=_resources(),
                cleanup_passed=True,
            ),
        )
        for task in _frozen_tasks()
    }


class FakeFlow:
    def __init__(
        self,
        evidence: FlowEvidence,
        *,
        wait_for_cap: bool = False,
        cleanup: CleanupInventory | None = None,
        cleanup_delay: float = 0,
        drive_delay: float = 0.01,
        error: Exception | None = None,
    ) -> None:
        if not wait_for_cap and error is None:
            settled = {
                task.task_id: TaskEvidence(
                    admitted_ms=0,
                    started_ms=0,
                    terminal_ms=0,
                    terminal_label="no_unique_candidate",
                    resources=_resources(),
                    cleanup_passed=True,
                )
                for task in _frozen_tasks()
                if task.task_id not in evidence.tasks
            }
            if settled:
                evidence = replace(evidence, tasks={**settled, **dict(evidence.tasks)})
        if evidence.checker_attestation.unique_candidate_count == 0 and any(
            task.candidate_checks for task in evidence.tasks.values()
        ):
            evidence = replace(evidence, checker_attestation=_attestation(dict(evidence.tasks)))
        self.evidence = evidence
        self.wait_for_cap = wait_for_cap
        self.cleanup_result = _cleanup() if cleanup is None else cleanup
        self.cleanup_delay = cleanup_delay
        self.drive_delay = drive_delay
        self.error = error
        self.drive_calls = 0
        self.cleanup_calls = 0
        self.cleanup_remaining: float | None = None

    async def drive(self, control: RunControl) -> None:
        self.drive_calls += 1
        if self.wait_for_cap:
            await control.wait_for_admissions_closed()
        if self.drive_delay:
            await asyncio.sleep(self.drive_delay)
        if self.error is not None:
            raise self.error

    def snapshot(self) -> FlowEvidence:
        return self.evidence

    async def cleanup(self, deadline: float) -> CleanupInventory:
        self.cleanup_calls += 1
        self.cleanup_remaining = deadline - asyncio.get_running_loop().time()
        if self.cleanup_delay:
            await asyncio.sleep(self.cleanup_delay)
        return self.cleanup_result


class RegisteredProbeFlow:
    def __init__(self, contract: RunnerContract, mode: str, marker: str | None) -> None:
        self.contract = contract
        self.mode = mode
        self.marker = marker
        self.evidence = FlowEvidence(
            tasks={
                task.task_id: TaskEvidence(
                    admitted_ms=0,
                    started_ms=0,
                    terminal_ms=0,
                    terminal_label="no_unique_candidate",
                    resources=_resources(),
                    cleanup_passed=True,
                )
                for task in contract.tasks
            },
            resources=_resources(),
        )

    def _mutate(self) -> None:
        if self.marker is None:
            return
        marker = Path(tempfile.gettempdir()) / f"{self.marker}.cap05-probe"
        with marker.open("ab") as stream:
            stream.write(b"x")

    async def _resist_forever(self) -> None:
        while True:
            self._mutate()
            try:
                await asyncio.sleep(0.001)
            except asyncio.CancelledError:
                pass

    async def drive(self, _control: RunControl) -> None:
        if self.mode == "loop_block_receipt":
            await asyncio.sleep(0.1)
            return
        if self.mode == "detached_setsid":
            assert self.marker is not None
            marker = Path(tempfile.gettempdir()) / f"{self.marker}.cap05-probe"
            ready = Path(tempfile.gettempdir()) / f"{self.marker}.cap05-ready"
            code = textwrap.dedent(
                """
                import signal
                import sys
                import time
                from pathlib import Path

                marker = Path(sys.argv[1])
                ready = Path(sys.argv[2])
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                ready.write_bytes(b"ready")
                while True:
                    with marker.open("ab") as stream:
                        stream.write(b"x")
                    time.sleep(0.001)
                """
            )
            subprocess.Popen(  # noqa: ASYNC220 - containment regression needs a real descendant
                [sys.executable, "-c", code, str(marker), str(ready)],
                start_new_session=True,
            )
            deadline = time.monotonic() + 1.0
            while not ready.exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("detached containment probe did not become ready")
                time.sleep(0.002)  # noqa: ASYNC251 - child readiness is cross-process
            await self._resist_forever()
        if self.mode == "drive_ignore_sigterm":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            await self._resist_forever()
        if self.mode == "drive_forever":
            await self._resist_forever()

    def snapshot(self) -> FlowEvidence:
        return self.evidence

    async def cleanup(self, _deadline: float) -> CleanupInventory:
        if self.mode == "cleanup_forever":
            await self._resist_forever()
        return _cleanup()


def registered_probe_flow_factory(
    contract: RunnerContract, configuration: object
) -> RegisteredProbeFlow:
    assert isinstance(configuration, dict)
    mode = configuration.get("mode")
    marker = configuration.get("marker")
    assert mode in {
        "normal",
        "environment_probe",
        "drive_forever",
        "drive_ignore_sigterm",
        "cleanup_forever",
        "detached_setsid",
        "loop_block_receipt",
    }
    assert marker is None or isinstance(marker, str)
    if mode == "environment_probe":
        assert "CTFD_API_TOKEN" not in os.environ
        assert "TEAM_KEY" not in os.environ
        assert "RAPIDO_PRIVATE_CANDIDATE" not in os.environ
    return RegisteredProbeFlow(contract, mode, marker)


def _registered_probe_factory(mode: str, marker: str | None = None) -> RegisteredFlowFactory:
    return RegisteredFlowFactory.from_public_configuration(
        "cap05-probe-v1",
        "tests.test_offline_capability_runner:registered_probe_flow_factory",
        {"marker": marker, "mode": mode},
    )


def _contract(*tasks: TaskRegistration) -> RunnerContract:
    return RunnerContract(
        run_id="cap05-test",
        experiment_id="HARD-BASELINE",
        tasks=_frozen_tasks(*tasks),
        scoring_seconds=3600,
        settlement_seconds=180,
        cleanup_grace_seconds=190,
    )


def _runtime_config() -> SimpleNamespace:
    return SimpleNamespace(
        board_url="",
        board_token="",
        team_key="",
        watch_board=False,
        submit_candidates=True,
        manage_dynamic_instances=True,
        active_challenges=5,
        concurrency=20,
        dynamic_concurrency=1,
        attempts_per_challenge=4,
        episodes_per_challenge=3,
        attempt_seconds=800,
        run_seconds=3600,
        peer_profile="mixed_v1",
        lead_lanes=2,
        model="gpt-daybreak-blue-latest",
        reasoning_effort="xhigh",
        specialist_model="gpt-5.6-luna",
        specialist_reasoning_efforts=("max", "xhigh"),
    )


class JumpClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += max(0.0, seconds)
        await asyncio.sleep(0)


def test_early_drain_uses_one_flow_and_reports_complete_undersized_denominator() -> None:
    tasks = (_task("EAS-001"), _task("EAS-002"))
    flow = FakeFlow(
        FlowEvidence(
            tasks={
                "EAS-001": _correct(1, 4),
                "EAS-002": _correct(2, 5),
            },
            resources=_resources(),
        )
    )

    receipt = asyncio.run(_run_completion_driven_worker(_contract(*tasks), flow))

    assert receipt["schema"] == RUNNER_RECEIPT_SCHEMA
    assert receipt["status"] == "completed", receipt
    assert receipt["task_order"] == [task.task_id for task in _frozen_tasks(*tasks)]
    assert [row["task_id"] for row in receipt["tasks"]] == receipt["task_order"]
    assert receipt["aggregate"]["undersized_reservoir"] is True
    assert receipt["aggregate"]["terminal"] == 18
    assert receipt["aggregate"]["usage"] == {
        "input": 6,
        "cached_input": 2,
        "output": 4,
        "reasoning": 2,
    }
    assert flow.drive_calls == flow.cleanup_calls == 1
    assert receipt["cleanup"]["passed"] is True


def test_cap_preserves_running_queued_and_unstarted_rows_in_frozen_order() -> None:
    tasks = (
        _task("EAS-001"),
        _task("EAS-002"),
        _task("EAS-003"),
    )
    flow = FakeFlow(
        FlowEvidence(
            tasks={
                "EAS-001": TaskEvidence(admitted_ms=0, started_ms=1),
                "EAS-002": TaskEvidence(admitted_ms=2),
            }
        ),
        wait_for_cap=True,
    )

    receipt = asyncio.run(_run_completion_driven_worker(_contract(*tasks), flow, clock=JumpClock()))

    assert receipt["status"] == "deadline"
    assert [row["terminal_label"] for row in receipt["tasks"][:3]] == [
        "global_cap",
        "queued_at_cap",
        "unstarted_at_cap",
    ]
    assert receipt["cap_snapshot"] == {"active": 1, "queued": 1, "unstarted": 17}
    assert receipt["aggregate"]["unstarted"] == 17
    assert all(row["terminal_ms"] > receipt["admissions_closed_ms"] for row in receipt["tasks"])


def test_pre_cap_candidate_may_finish_deterministic_check_during_settlement() -> None:
    task = _task("EAS-001")
    flow = FakeFlow(
        FlowEvidence(
            tasks={
                task.task_id: TaskEvidence(
                    admitted_ms=0,
                    started_ms=1,
                    candidate_checks=(CandidateCheck(3_599_995, 3_599_995, 3_600_017, "correct"),),
                )
            }
        ),
        wait_for_cap=True,
    )

    receipt = asyncio.run(_run_completion_driven_worker(_contract(task), flow, clock=JumpClock()))
    row = receipt["tasks"][0]

    assert receipt["status"] == "deadline"
    assert row["terminal_label"] == "correct"
    assert row["first_correct_ms"] == 3_600_017
    assert row["cleanup_passed"] is True
    assert row["candidate_checks"][0]["checker_started_ms"] < receipt["scoring_cap_ms"]
    assert row["candidate_checks"][0]["checker_ended_ms"] <= receipt["settlement_end_ms"]


def test_candidate_evidence_exposes_only_ordinals_and_calls_checker_once_per_unique() -> None:
    task = _task("EAS-001")
    evidence = _correct(1, 8)
    evidence = TaskEvidence(
        admitted_ms=evidence.admitted_ms,
        started_ms=evidence.started_ms,
        terminal_ms=evidence.terminal_ms,
        terminal_label=evidence.terminal_label,
        candidate_checks=(
            *evidence.candidate_checks,
            CandidateCheck(4, 4, 5, "incorrect"),
        ),
        candidate_repeat_count=3,
        provider_attempts=evidence.provider_attempts,
        qualification=evidence.qualification,
        qualification_ms=evidence.qualification_ms,
        resources=evidence.resources,
        cleanup_passed=True,
    )
    receipt = asyncio.run(
        _run_completion_driven_worker(
            _contract(task), FakeFlow(FlowEvidence(tasks={task.task_id: evidence}))
        )
    )
    row = receipt["tasks"][0]

    assert row["candidate_unique_count"] == row["checker_call_count"] == 2
    assert row["candidate_repeat_count"] == 3
    assert [check["ordinal"] for check in row["candidate_checks"]] == [1, 2]
    encoded = json.dumps(receipt, sort_keys=True)
    for forbidden in ("candidate_value", "candidate_digest", "candidate_sha256", "raw_output"):
        assert forbidden not in encoded


def test_service_attempts_are_ordinal_closed_and_bound_to_registered_tasks() -> None:
    task = _task("EAS-001")
    service = ServiceAttempt(
        service_id="owned-service-1",
        task_id=task.task_id,
        status="stopped",
        started_ms=1,
        ready_ms=2,
        ended_ms=4,
    )
    receipt = asyncio.run(
        _run_completion_driven_worker(
            _contract(task),
            FakeFlow(
                FlowEvidence(
                    tasks={task.task_id: _correct(1, 5)},
                    service_attempts=(service,),
                )
            ),
        )
    )

    assert receipt["service_attempts"] == [
        {
            "ordinal": 1,
            "task_id": "EAS-001",
            "status": "stopped",
            "started_ms": 1,
            "ready_ms": 2,
            "ended_ms": 4,
            "failure_label": None,
        }
    ]
    assert service.service_id not in json.dumps(receipt, sort_keys=True)
    with pytest.raises(CapabilityRunnerError, match="status/failure"):
        ServiceAttempt(
            service_id="owned-service-2",
            task_id=task.task_id,
            status="lost",
            started_ms=1,
            ready_ms=2,
            ended_ms=3,
        )


def test_usage_null_and_resource_sampling_gap_are_not_replaced_with_zero() -> None:
    task = _task("EAS-001")
    evidence = TaskEvidence(
        admitted_ms=0,
        started_ms=1,
        terminal_ms=3,
        terminal_label="no_unique_candidate",
        provider_attempts=(
            ProviderAttempt(
                lane=0,
                requested_model="gpt-daybreak-blue-latest",
                requested_effort="xhigh",
                effective_model="gpt-daybreak-blue-latest",
                effective_effort="xhigh",
                effective_revision_build="provider-v1",
                native_client_version="codex-v1",
                status="completed",
                started_ms=1,
                ended_ms=2,
                usage=Usage(),
            ),
        ),
        resources=ResourceObservation(unavailable_reason="sampling_gap"),
        cleanup_passed=True,
    )
    receipt = asyncio.run(
        _run_completion_driven_worker(
            _contract(task), FakeFlow(FlowEvidence(tasks={task.task_id: evidence}))
        )
    )
    row = receipt["tasks"][0]

    assert set(row["usage"].values()) == {None}
    assert receipt["aggregate"]["usage"] == row["usage"]
    assert row["resources"]["unavailable_reason"] == "sampling_gap"
    assert row["resources"]["memory_peak_bytes"] is None


def test_cleanup_timeout_retains_unknown_inventory_instead_of_inventing_counts() -> None:
    task = _task("EAS-001")
    contract = _contract(task)
    flow = FakeFlow(
        FlowEvidence(tasks={task.task_id: _correct(1, 4)}),
        cleanup_delay=0.1,
        drive_delay=0.005,
    )

    receipt = asyncio.run(_run_completion_driven_worker(contract, flow, clock=JumpClock()))

    assert receipt["status"] == "failed"
    assert receipt["failure_label"] == "cleanup_inventory_unavailable"
    assert receipt["cleanup"]["passed"] is False
    assert receipt["cleanup"]["inventory_complete"] is False
    counts = {
        value
        for key, value in receipt["cleanup"].items()
        if key.startswith("owned_") and key.endswith("_remaining")
    }
    assert counts == {None}


def test_outer_cancellation_drains_flow_then_runs_exact_cleanup() -> None:
    task = _task("EAS-001")
    flow = FakeFlow(FlowEvidence(tasks={}), wait_for_cap=True, drive_delay=0)

    async def exercise() -> dict[str, object]:
        running = asyncio.create_task(_run_completion_driven_worker(_contract(task), flow))
        await asyncio.sleep(0.005)
        running.cancel()
        return await running

    receipt = asyncio.run(exercise())

    assert receipt["status"] == "interrupted"
    assert receipt["failure_label"] == "interrupted"
    assert receipt["tasks"][0]["terminal_label"] == "fixture_invalid"
    assert receipt["cleanup"]["passed"] is True
    assert flow.cleanup_calls == 1


def test_drive_failure_preserves_every_row_with_closed_failure_only() -> None:
    tasks = (_task("EAS-001"), _task("EAS-002"))
    flow = FakeFlow(FlowEvidence(tasks={}), error=RuntimeError("private detail"))

    receipt = asyncio.run(_run_completion_driven_worker(_contract(*tasks), flow))

    assert receipt["status"] == "failed"
    assert receipt["failure_label"] == "drive_failure"
    assert {row["terminal_label"] for row in receipt["tasks"]} == {"fixture_invalid"}
    assert len(receipt["tasks"]) == 18
    assert "private detail" not in json.dumps(receipt)


def test_temporal_boundary_failure_is_rejected() -> None:
    task = _task("EAS-001")
    evidence = TaskEvidence(
        admitted_ms=20,
        started_ms=21,
        terminal_ms=22,
        terminal_label="no_unique_candidate",
        cleanup_passed=True,
    )
    with pytest.raises(CapabilityRunnerError, match="admitted or started"):
        asyncio.run(
            _run_completion_driven_worker(
                _contract(task),
                FakeFlow(FlowEvidence(tasks={task.task_id: evidence})),
            )
        )


def test_runner_rejects_unregistered_evidence_and_invalid_receipt_reordering() -> None:
    task = _task("EAS-001")
    flow = FakeFlow(FlowEvidence(tasks={"EAS-999": TaskEvidence()}))
    receipt = asyncio.run(_run_completion_driven_worker(_contract(task), flow))

    assert receipt["status"] == "failed"
    assert receipt["failure_label"] == "evidence_contract_failure"
    mutated = dict(receipt)
    mutated["task_order"] = ["EAS-002"]
    with pytest.raises(CapabilityRunnerError, match="dropped or reordered"):
        validate_runner_receipt(mutated)


def test_registration_and_task_evidence_reject_ambiguous_or_inconsistent_shapes() -> None:
    with pytest.raises(CapabilityRunnerError, match="not unique"):
        _contract(_task("EAS-001"), _task("EAS-001"))
    with pytest.raises(CapabilityRunnerError, match="correct terminal"):
        TaskEvidence(
            admitted_ms=0,
            started_ms=1,
            terminal_ms=2,
            terminal_label="correct",
            cleanup_passed=True,
        )
    with pytest.raises(CapabilityRunnerError, match="cleanup grace|settlement or cleanup"):
        RunnerContract(
            run_id="bad-grace",
            experiment_id="HARD-BASELINE",
            tasks=_frozen_tasks(),
            scoring_seconds=3600,
            settlement_seconds=2,
            cleanup_grace_seconds=1,
        )


def test_cleanup_inventory_requires_failure_label_for_residue_or_null() -> None:
    with pytest.raises(CapabilityRunnerError, match="requires a failure"):
        CleanupInventory(1, 0, 0, 0, 0, 0, 0, 0)
    with pytest.raises(CapabilityRunnerError, match="requires a failure"):
        CleanupInventory(None, 0, 0, 0, 0, 0, 0, 0)


def test_snapshot_type_failure_stays_closed() -> None:
    task = _task("EAS-001")

    class BadSnapshotFlow(FakeFlow):
        def snapshot(self) -> FlowEvidence:
            return {"private": "/tmp/private"}  # type: ignore[return-value]

    receipt = asyncio.run(
        _run_completion_driven_worker(_contract(task), BadSnapshotFlow(FlowEvidence(tasks={})))
    )
    assert receipt["status"] == "failed"
    assert receipt["failure_label"] == "evidence_contract_failure"
    assert "/tmp/private" not in json.dumps(receipt)


def test_actual_offline_board_durable_control_runner_smoke_is_model_free(tmp_path: Path) -> None:
    contract = _contract()
    bank = tmp_path / "bank"
    bank.mkdir(mode=0o700)
    candidates = {
        task.task_id: f"INCYPHER{{cap05-{index:03d}-fresh}}"
        for index, task in enumerate(contract.tasks, 1)
    }
    catalogue: list[dict[str, object]] = []
    offline_registrations: list[OfflineTaskRegistration] = []
    for index, task in enumerate(contract.tasks, 1):
        board_id = 1000 + index
        (bank / "capsules" / task.task_id / "visible").mkdir(parents=True, mode=0o700)
        catalogue.append(
            {
                "board_id": board_id,
                "task_id": task.task_id,
                "name": task.task_id,
                "category": task.category,
                "type": "standard",
                "description": f"Fresh exact literal {candidates[task.task_id]}",
                "value": 100,
                "files": [],
                "solved": False,
                "attempts": 0,
                "max_attempts": 0,
                "timeout": None,
                "shared": False,
                "service_required": False,
                "resource_profile_id": "none",
                "generator_version": task.generator_version,
                "checker_version": task.checker_version,
                "service_version": task.service_version,
            }
        )
        offline_registrations.append(
            OfflineTaskRegistration(
                board_id,
                task.task_id,
                task.generator_version,
                task.checker_version,
                task.service_version,
            )
        )
    (bank / "public-catalogue.json").write_text(
        json.dumps({"catalogue_version": "catalogue-v1", "tasks": catalogue}),
        encoding="utf-8",
    )
    os.chmod(bank, 0o700)
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(mode=0o700)
    config = OfflineRuntimeConfig.build(
        offline_profile_id="cap05-smoke",
        catalogue_version="catalogue-v1",
        board_implementation_version=OFFLINE_BOARD_IMPLEMENTATION_VERSION,
        state_path=tmp_path / "state.sqlite3",
        work_root=tmp_path / "work",
        codex_home=codex_home,
        runner_image="sha256:" + "0" * 64,
        task_registrations=tuple(offline_registrations),
        active_challenges=5,
        episodes_per_challenge=3,
        attempts_per_challenge=4,
        lead_lanes=2,
        run_seconds=3600,
        max_artifact_bytes=1024,
        max_challenge_bytes=2048,
        max_workspace_bytes=1024 * 1024,
    )
    config.work_root.mkdir(mode=0o700)

    def checker(task_id: str, candidate: bytes) -> bool:
        return candidate == candidates[task_id].encode()

    board = OfflineBoard(
        bank,
        config.work_root,
        checker,
        offline_profile_id=config.offline_profile_id,
        timeout=config.board_timeout_seconds,
        artifact_limit=config.max_artifact_bytes,
        capsule_limit=config.max_challenge_bytes,
        synthetic_in_process=True,
    )

    class NoModelRuntime:
        def __init__(self) -> None:
            self.started = False
            self.closed = False
            self.solve_calls = 0

        async def start(self) -> None:
            self.started = True

        async def validate_model(self, _model: str, _effort: str) -> None:
            return

        async def solve(self, *_args: object, **_kwargs: object) -> object:
            self.solve_calls += 1
            raise AssertionError("Board-literal smoke must not invoke a model")

        async def close(self) -> None:
            self.closed = True

    runtime = NoModelRuntime()

    def evidence_source() -> FlowEvidence:
        snapshot = board.public_snapshot()
        attestation = CheckerEconomyAttestation.from_offline_board_snapshot(
            snapshot, contract.tasks
        )
        tasks = {
            task.task_id: TaskEvidence(
                admitted_ms=0,
                started_ms=0,
                terminal_ms=0,
                terminal_label="correct",
                candidate_checks=(CandidateCheck(0, 0, 0, "correct"),),
                resources=_resources(),
                cleanup_passed=True,
            )
            for task in contract.tasks
        }
        return FlowEvidence(
            tasks=tasks,
            checker_attestation=attestation,
            resources=_resources(),
        )

    inspected: list[str] = []

    async def cleanup(_deadline: float) -> CleanupInventory:
        view = DurableJobControl.inspect(config.state_path)
        inspected.append(f"{view.status}:{view.catalogue_count}:{len(view.jobs)}:{runtime.closed}")
        board.close()
        shutil.rmtree(config.work_root, ignore_errors=True)
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(config.state_path) + suffix)
            if path.exists():
                path.unlink()
        return _cleanup()

    flow = durable_job_control_flow(
        contract=contract,
        config=config,
        board=board,
        runtime=runtime,  # type: ignore[arg-type]
        evidence_source=evidence_source,
        cleanup=cleanup,
    )
    receipt = asyncio.run(_run_completion_driven_worker(contract, flow))

    assert receipt["status"] == "completed", receipt
    assert receipt["aggregate"]["raw_correct_tasks"] == 12
    assert receipt["checker_attestation"]["checker_call_count"] == 18
    assert inspected == ["completed:18:72:True"]
    assert runtime.started and runtime.closed
    assert runtime.solve_calls == 0
    assert not config.state_path.exists()


def test_concrete_durable_adapter_runs_one_unchanged_flow_real_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = _task("EAS-001")
    contract = _contract(task)
    tasks = _complete_tasks(**{task.task_id: _correct(1, 4)})
    evidence = FlowEvidence(
        tasks=tasks,
        checker_attestation=_attestation(tasks),
        resources=_resources(),
    )
    calls: list[tuple[object, object, object]] = []

    async def fake_drive(
        config: object,
        *,
        board: object,
        runtime: object,
        clock: object,
        absolute_deadline: float,
    ) -> RunReport:
        del clock, absolute_deadline
        calls.append((config, board, runtime))
        await asyncio.sleep(0.01)
        return RunReport("adapter-smoke", "completed", 1, 1, 1, 0, 0, 0, 0)

    monkeypatch.setattr(
        "rapido.offline_capability_runner.DurableJobControl.drive",
        fake_drive,
    )
    board = AttestedBoard(evidence.checker_attestation, contract.tasks)
    runtime = object()

    async def cleanup(_deadline: float) -> CleanupInventory:
        return _cleanup()

    flow = durable_job_control_flow(
        contract=contract,
        config=_runtime_config(),  # type: ignore[arg-type]
        board=board,  # type: ignore[arg-type]
        runtime=runtime,  # type: ignore[arg-type]
        evidence_source=lambda: evidence,
        cleanup=cleanup,
    )
    receipt = asyncio.run(_run_completion_driven_worker(contract, flow))

    assert receipt["status"] == "completed"
    assert len(calls) == 1
    assert calls[0][1:] == (board, runtime)
    assert flow.report is not None and flow.report.run_id == "adapter-smoke"


def test_concrete_adapter_rejects_roster_lane_and_one_lease_drift() -> None:
    task = _task("EAS-001")
    contract = _contract(task)
    config = _runtime_config()
    config.specialist_reasoning_efforts = ("xhigh", "max")

    async def cleanup(_deadline: float) -> CleanupInventory:
        return _cleanup()

    with pytest.raises(CapabilityRunnerError, match="roster"):
        durable_job_control_flow(
            contract=contract,
            config=config,  # type: ignore[arg-type]
            board=object(),  # type: ignore[arg-type]
            runtime=object(),  # type: ignore[arg-type]
            evidence_source=lambda: FlowEvidence(tasks={}),
            cleanup=cleanup,
        )
    config = _runtime_config()
    config.dynamic_concurrency = 2
    with pytest.raises(CapabilityRunnerError, match="scheduler"):
        durable_job_control_flow(
            contract=contract,
            config=config,  # type: ignore[arg-type]
            board=object(),  # type: ignore[arg-type]
            runtime=object(),  # type: ignore[arg-type]
            evidence_source=lambda: FlowEvidence(tasks={}),
            cleanup=cleanup,
        )


def test_effective_descriptor_fallback_and_overlapping_services_fail_closed() -> None:
    first = _task("EAS-001")
    bad_attempt = ProviderAttempt(
        lane=0,
        requested_model="gpt-daybreak-blue-latest",
        requested_effort="xhigh",
        effective_model="gpt-5.6-luna",
        effective_effort="xhigh",
        effective_revision_build="provider-v1",
        native_client_version="codex-v1",
        status="completed",
        started_ms=1,
        ended_ms=2,
        usage=Usage(input=1, cached_input=0, output=1, reasoning=1),
    )
    fallback = TaskEvidence(
        admitted_ms=0,
        started_ms=1,
        terminal_ms=3,
        terminal_label="no_unique_candidate",
        provider_attempts=(bad_attempt,),
        cleanup_passed=True,
    )
    with pytest.raises(CapabilityRunnerError, match="silently fell back"):
        asyncio.run(
            _run_completion_driven_worker(
                _contract(first), FakeFlow(FlowEvidence(tasks={first.task_id: fallback}))
            )
        )

    second = _task("EAS-002")
    tasks = {first.task_id: _correct(1, 5), second.task_id: _correct(1, 5)}
    services = (
        ServiceAttempt("service-1", first.task_id, "stopped", 1, 2, 5),
        ServiceAttempt("service-2", second.task_id, "stopped", 2, 3, 4),
    )
    with pytest.raises(CapabilityRunnerError, match="one-lease"):
        asyncio.run(
            _run_completion_driven_worker(
                _contract(first, second),
                FakeFlow(
                    FlowEvidence(
                        tasks=tasks,
                        checker_attestation=_attestation(tasks),
                        service_attempts=services,
                    )
                ),
            )
        )


def test_usage_cap_and_usage_null_have_distinct_closed_results() -> None:
    task = _task("EAS-001")
    with pytest.raises(CapabilityRunnerError, match="usage caps changed"):
        replace(
            _contract(task),
            execution_policy=ExecutionPolicy(usage_caps=UsageCaps(input=1, output=1, reasoning=1)),
        )
    correct = _correct(1, 4)
    over_cap = replace(
        correct,
        provider_attempts=(
            replace(correct.provider_attempts[0], usage=Usage(20_000_001, 0, 1, 1)),
        ),
    )
    receipt = asyncio.run(
        _run_completion_driven_worker(
            _contract(task),
            FakeFlow(
                FlowEvidence(
                    tasks={task.task_id: over_cap},
                    checker_attestation=_attestation({task.task_id: over_cap}),
                )
            ),
        )
    )
    assert receipt["status"] == "failed"
    assert receipt["failure_label"] == "usage_cap"

    unavailable = TaskEvidence(
        admitted_ms=0,
        started_ms=1,
        terminal_ms=3,
        terminal_label="no_unique_candidate",
        provider_attempts=(
            ProviderAttempt(
                lane=0,
                requested_model="gpt-daybreak-blue-latest",
                requested_effort="xhigh",
                effective_model="gpt-daybreak-blue-latest",
                effective_effort="xhigh",
                effective_revision_build="provider-v1",
                native_client_version="codex-v1",
                status="completed",
                started_ms=1,
                ended_ms=2,
                usage=Usage(),
            ),
        ),
        cleanup_passed=True,
    )
    receipt = asyncio.run(
        _run_completion_driven_worker(
            _contract(task), FakeFlow(FlowEvidence(tasks={task.task_id: unavailable}))
        )
    )
    assert receipt["status"] == "inconclusive"
    assert receipt["failure_label"] == "usage_unavailable"
    assert set(receipt["aggregate"]["usage"].values()) == {None}
    wrong_status = copy.deepcopy(receipt)
    wrong_status["status"] = "failed"
    with pytest.raises(CapabilityRunnerError, match="label/status"):
        validate_runner_receipt(wrong_status)
    wrong_label = copy.deepcopy(receipt)
    wrong_label["failure_label"] = "other_inconclusive"
    with pytest.raises(CapabilityRunnerError, match="inconclusive status"):
        validate_runner_receipt(wrong_label)


def test_oracle_inconclusive_is_not_reclassified_as_incorrect() -> None:
    task = _task("EAS-001")
    evidence = TaskEvidence(
        admitted_ms=0,
        started_ms=1,
        terminal_ms=4,
        terminal_label="oracle_inconclusive",
        candidate_checks=(CandidateCheck(2, 2, 3, "inconclusive"),),
        cleanup_passed=True,
    )
    receipt = asyncio.run(
        _run_completion_driven_worker(
            _contract(task), FakeFlow(FlowEvidence(tasks={task.task_id: evidence}))
        )
    )
    assert receipt["tasks"][0]["raw_correct"] is None
    assert receipt["checker_attestation"]["candidates"][0]["result"] == "inconclusive"


def test_board_cache_attestation_mismatch_is_not_hidden_by_derived_counts() -> None:
    task = _task("EAS-001")
    evidence = _correct(1, 4)
    wrong = CheckerEconomyAttestation(
        "offline_board_private_cache_v1",
        "run_local",
        1,
        0,
        1,
        (CheckerCandidateAttestation(task.task_id, "checker-v1", 1, "incorrect", 0),),
    )
    with pytest.raises(CapabilityRunnerError, match="Board cache"):
        asyncio.run(
            _run_completion_driven_worker(
                _contract(task),
                FakeFlow(
                    FlowEvidence(
                        tasks={task.task_id: evidence},
                        checker_attestation=wrong,
                    )
                ),
            )
        )


def test_scored_lane_and_active_wall_are_clipped_at_cap() -> None:
    task = _task("EAS-001")
    evidence = TaskEvidence(
        admitted_ms=0,
        started_ms=1,
        provider_attempts=(
            ProviderAttempt(
                lane=0,
                requested_model="gpt-daybreak-blue-latest",
                requested_effort="xhigh",
                effective_model=None,
                effective_effort=None,
                effective_revision_build=None,
                native_client_version="codex-v1",
                status="cancelled",
                started_ms=1,
                ended_ms=3_600_020,
                usage=Usage(input=1, cached_input=0, output=0, reasoning=0),
            ),
        ),
    )
    receipt = asyncio.run(
        _run_completion_driven_worker(
            _contract(task),
            FakeFlow(FlowEvidence(tasks={task.task_id: evidence}), wait_for_cap=True),
            clock=JumpClock(),
        )
    )
    assert receipt["aggregate"]["lane_time_ms"] == 3_599_999
    assert receipt["aggregate"]["global_active_wall_ms"] == 3_599_999
    assert receipt["aggregate"]["global_active_wall_ms"] < receipt["scoring_cap_ms"]


def test_early_cleanup_deadline_is_anchored_to_completion_not_full_cap() -> None:
    task = _task("EAS-001")
    flow = FakeFlow(FlowEvidence(tasks={task.task_id: _correct(1, 4)}))
    contract = _contract(task)
    asyncio.run(_run_completion_driven_worker(contract, flow))
    assert flow.cleanup_remaining is not None
    assert 0 < flow.cleanup_remaining <= 190


def test_deep_validator_rejects_nested_extra_privacy_and_cross_field_mutations() -> None:
    task = _task("EAS-001")
    receipt = asyncio.run(
        _run_completion_driven_worker(
            _contract(task), FakeFlow(FlowEvidence(tasks={task.task_id: _correct(1, 4)}))
        )
    )
    extra = copy.deepcopy(receipt)
    extra["tasks"][0]["candidate_checks"][0]["extra"] = 1
    with pytest.raises(CapabilityRunnerError, match="fields are not exact"):
        validate_runner_receipt(extra)
    private = copy.deepcopy(receipt)
    private["tasks"][0]["family_id"] = "/private/root"
    with pytest.raises(CapabilityRunnerError, match="forbidden public value"):
        validate_runner_receipt(private)
    inconsistent = copy.deepcopy(receipt)
    inconsistent["aggregate"]["raw_correct_tasks"] += 1
    with pytest.raises(CapabilityRunnerError, match="aggregate contradicts"):
        validate_runner_receipt(inconsistent)


def test_lifecycle_evidence_before_task_start_is_rejected() -> None:
    with pytest.raises(CapabilityRunnerError, match="precedes task start"):
        TaskEvidence(
            admitted_ms=0,
            started_ms=3,
            terminal_ms=5,
            terminal_label="no_unique_candidate",
            provider_attempts=(
                ProviderAttempt(
                    lane=0,
                    requested_model="gpt-daybreak-blue-latest",
                    requested_effort="xhigh",
                    effective_model=None,
                    effective_effort=None,
                    effective_revision_build=None,
                    native_client_version="codex-v1",
                    status="cancelled",
                    started_ms=2,
                    ended_ms=4,
                    usage=Usage(input=0, cached_input=0, output=0, reasoning=0),
                ),
            ),
            cleanup_passed=True,
        )


def test_contract_rejects_unknown_experiment_and_cross_experiment_roster() -> None:
    task = _task("EAS-001")
    with pytest.raises(CapabilityRunnerError, match="experiment ID is not frozen"):
        RunnerContract(
            run_id="unknown-experiment",
            experiment_id="UNKNOWN",
            tasks=(task,),
            scoring_seconds=1,
        )
    with pytest.raises(CapabilityRunnerError, match="experiment routing contract changed"):
        RunnerContract(
            run_id="wrong-route",
            experiment_id="HARD-BASELINE",
            tasks=_frozen_tasks(task),
            scoring_seconds=3600,
            execution_policy=ExecutionPolicy(
                routing_profile="rte_daybreak_v1",
                lane_descriptors=(ModelDescriptor("gpt-daybreak-blue-latest", "xhigh"),) * 4,
            ),
        )


def test_contract_rejects_short_wall_grace_and_nonfrozen_denominator() -> None:
    with pytest.raises(CapabilityRunnerError, match="wall cap changed"):
        RunnerContract(
            run_id="short-wall",
            experiment_id="HARD-BASELINE",
            tasks=_frozen_tasks(),
            scoring_seconds=1,
        )
    with pytest.raises(CapabilityRunnerError, match="settlement or cleanup"):
        RunnerContract(
            run_id="short-grace",
            experiment_id="HARD-BASELINE",
            tasks=_frozen_tasks(),
            scoring_seconds=3600,
            settlement_seconds=179,
            cleanup_grace_seconds=190,
        )
    with pytest.raises(CapabilityRunnerError, match="difficult denominator"):
        RunnerContract(
            run_id="short-denominator",
            experiment_id="HARD-BASELINE",
            tasks=_frozen_tasks()[:6],
            scoring_seconds=3600,
        )
    with pytest.raises(CapabilityRunnerError, match="all six sentinels"):
        RunnerContract(
            run_id="missing-sentinel",
            experiment_id="HARD-BASELINE",
            tasks=_frozen_tasks()[1:],
            scoring_seconds=3600,
        )
    wrong_namespace = replace(_frozen_tasks()[6], task_id="BAD-001")
    with pytest.raises(CapabilityRunnerError, match="namespace"):
        RunnerContract(
            run_id="wrong-namespace",
            experiment_id="HARD-BASELINE",
            tasks=(*_frozen_tasks()[:6], wrong_namespace, *_frozen_tasks()[7:]),
            scoring_seconds=3600,
        )
    collapsed = tuple(
        replace(task, family_id="ONE", category="reverse") if task.tier == "A" else task
        for task in _frozen_tasks()
    )
    with pytest.raises(CapabilityRunnerError, match="family denominator"):
        RunnerContract(
            run_id="collapsed-diversity",
            experiment_id="HARD-BASELINE",
            tasks=collapsed,
            scoring_seconds=3600,
        )


def test_empty_provider_sequence_is_exact_zero_usage() -> None:
    row = TaskEvidence().public(_task("EAS-001"))
    assert row["usage"] == {"input": 0, "cached_input": 0, "output": 0, "reasoning": 0}


def test_checker_attestation_is_bound_to_frozen_registration_versions() -> None:
    contract = _contract()
    tasks = _complete_tasks(**{"EAS-001": _correct(1, 4)})
    attestation = _attestation(tasks)
    snapshot = AttestedBoard(attestation, contract.tasks).public_snapshot()
    snapshot["task_registrations"][0]["checker_version"] = "changed-v2"
    with pytest.raises(CapabilityRunnerError, match="task registration changed"):
        CheckerEconomyAttestation.from_offline_board_snapshot(snapshot, contract.tasks)


def test_known_usage_lower_bound_over_cap_wins_over_null_usage() -> None:
    task = _task("EAS-001")
    attempts = (
        ProviderAttempt(
            lane=0,
            requested_model="gpt-daybreak-blue-latest",
            requested_effort="xhigh",
            effective_model="gpt-daybreak-blue-latest",
            effective_effort="xhigh",
            effective_revision_build="provider-v1",
            native_client_version="codex-v1",
            status="completed",
            started_ms=1,
            ended_ms=2,
            usage=Usage(input=20_000_001, cached_input=0, output=1, reasoning=1),
        ),
        ProviderAttempt(
            lane=1,
            requested_model="gpt-daybreak-blue-latest",
            requested_effort="xhigh",
            effective_model="gpt-daybreak-blue-latest",
            effective_effort="xhigh",
            effective_revision_build="provider-v1",
            native_client_version="codex-v1",
            status="completed",
            started_ms=2,
            ended_ms=3,
            usage=Usage(input=None, cached_input=None, output=None, reasoning=None),
        ),
    )
    evidence = TaskEvidence(
        admitted_ms=0,
        started_ms=1,
        terminal_ms=4,
        terminal_label="no_unique_candidate",
        provider_attempts=attempts,
        cleanup_passed=True,
    )

    receipt = asyncio.run(
        _run_completion_driven_worker(
            _contract(task), FakeFlow(FlowEvidence(tasks={task.task_id: evidence}))
        )
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_label"] == "usage_cap"
    assert receipt["aggregate"]["usage"]["input"] is None


@pytest.mark.parametrize(
    "private_value",
    ["sk-proj-1234567890abcdefgh", "private.example.com"],
)
def test_public_privacy_scan_rejects_credentials_and_domain_authorities(
    private_value: str,
) -> None:
    task = _task("EAS-001")
    receipt = asyncio.run(
        _run_completion_driven_worker(
            _contract(task), FakeFlow(FlowEvidence(tasks={task.task_id: _correct(1, 4)}))
        )
    )
    hostile = copy.deepcopy(receipt)
    hostile["tasks"][0]["family_id"] = private_value
    with pytest.raises(CapabilityRunnerError, match="forbidden public value"):
        validate_runner_receipt(hostile)


def test_provider_terminal_requires_matching_attempt() -> None:
    with pytest.raises(CapabilityRunnerError, match="provider terminal"):
        TaskEvidence(
            admitted_ms=0,
            started_ms=1,
            terminal_ms=2,
            terminal_label="provider_failure",
            cleanup_passed=True,
        )


def test_service_terminal_requires_matching_service_attempt() -> None:
    task = _task("EAS-001")
    evidence = TaskEvidence(
        admitted_ms=0,
        started_ms=1,
        terminal_ms=2,
        terminal_label="service_lost",
        cleanup_passed=True,
    )
    with pytest.raises(CapabilityRunnerError, match="service terminal"):
        asyncio.run(
            _run_completion_driven_worker(
                _contract(task), FakeFlow(FlowEvidence(tasks={task.task_id: evidence}))
            )
        )


def test_repeated_outer_cancellation_cannot_bypass_cleanup() -> None:
    flow = FakeFlow(FlowEvidence(tasks={}), wait_for_cap=True, drive_delay=0)

    async def exercise() -> dict[str, object]:
        running = asyncio.create_task(_run_completion_driven_worker(_contract(), flow))
        await asyncio.sleep(0.005)
        running.cancel()
        await asyncio.sleep(0)
        running.cancel()
        return await running

    receipt = asyncio.run(exercise())
    assert receipt["status"] == "interrupted"
    assert flow.cleanup_calls == 1


def test_cancellation_waits_for_stubborn_drive_before_snapshot() -> None:
    class StubbornFlow(FakeFlow):
        def __init__(self) -> None:
            super().__init__(FlowEvidence(tasks={}), wait_for_cap=True, drive_delay=0)
            self.finished = False
            self.snapshot_calls = 0

        async def drive(self, control: RunControl) -> None:
            try:
                await control.wait_for_admissions_closed()
                await asyncio.Future()
            except asyncio.CancelledError:
                await asyncio.sleep(0.02)
                self.finished = True

        def snapshot(self) -> FlowEvidence:
            self.snapshot_calls += 1
            assert self.finished
            return self.evidence

    flow = StubbornFlow()

    async def exercise() -> dict[str, object]:
        running = asyncio.create_task(_run_completion_driven_worker(_contract(), flow))
        await asyncio.sleep(0.005)
        running.cancel()
        return await running

    receipt = asyncio.run(exercise())
    assert receipt["status"] == "interrupted"
    assert flow.finished is True
    assert flow.snapshot_calls == 1
    assert flow.cleanup_calls == 1


def test_indefinitely_cancellation_resistant_drive_never_overlaps_cleanup_or_returns_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class IndefiniteDriveFlow(FakeFlow):
        def __init__(self) -> None:
            super().__init__(FlowEvidence(tasks={}), wait_for_cap=True, drive_delay=0)
            self.release = asyncio.Event()
            self.drive_active = False
            self.post_failure_mutations = 0

        async def drive(self, control: RunControl) -> None:
            self.drive_active = True
            while control.admissions_open:
                try:
                    await control.wait_for_admissions_closed()
                except asyncio.CancelledError:
                    pass
            while not self.release.is_set():
                self.post_failure_mutations += 1
                try:
                    await asyncio.sleep(0)
                except asyncio.CancelledError:
                    pass
            self.drive_active = False

    monkeypatch.setattr(capability_runner, "_CANCEL_DRAIN_SECONDS", 0.001)
    flow = IndefiniteDriveFlow()

    async def exercise() -> None:
        running = asyncio.create_task(_run_completion_driven_worker(_contract(), flow))
        while not flow.drive_active:
            await asyncio.sleep(0)
        running.cancel()
        with pytest.raises(CapabilityRunnerError, match="outer supervisor escalation"):
            await running
        mutations_at_failure = flow.post_failure_mutations
        await asyncio.sleep(0.001)
        assert flow.drive_active is True
        assert flow.post_failure_mutations > mutations_at_failure
        assert flow.cleanup_calls == 0
        flow.release.set()
        await asyncio.sleep(0)

    asyncio.run(exercise())


def test_indefinitely_cancellation_resistant_cleanup_never_returns_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class IndefiniteCleanupFlow(FakeFlow):
        def __init__(self) -> None:
            super().__init__(FlowEvidence(tasks=_complete_tasks()), drive_delay=0)
            self.release = asyncio.Event()
            self.cleanup_active = False
            self.post_failure_mutations = 0

        async def cleanup(self, deadline: float) -> CleanupInventory:
            self.cleanup_calls += 1
            self.cleanup_active = True
            while not self.release.is_set():
                self.post_failure_mutations += 1
                try:
                    await asyncio.sleep(0)
                except asyncio.CancelledError:
                    pass
            self.cleanup_active = False
            return _cleanup()

    monkeypatch.setattr(capability_runner, "_CANCEL_DRAIN_SECONDS", 0.001)
    flow = IndefiniteCleanupFlow()

    async def exercise() -> None:
        running = asyncio.create_task(
            _run_completion_driven_worker(_contract(), flow, clock=JumpClock())
        )
        with pytest.raises(CapabilityRunnerError, match="outer supervisor escalation"):
            await running
        mutations_at_failure = flow.post_failure_mutations
        await asyncio.sleep(0)
        assert flow.cleanup_active is True
        assert flow.post_failure_mutations > mutations_at_failure
        flow.release.set()
        await asyncio.sleep(0)

    asyncio.run(exercise())


def test_registered_public_runner_preserves_normal_model_free_receipt() -> None:
    contract = _contract()
    configuration = {"marker": None, "mode": "normal"}
    direct = asyncio.run(
        _run_completion_driven_worker(
            contract,
            registered_probe_flow_factory(contract, configuration),
        )
    )
    supervised = asyncio.run(
        run_completion_driven(
            contract,
            _registered_probe_factory("normal"),
            outer_deadline_seconds=3.0,
        )
    )

    assert supervised == direct


def test_public_runner_requires_closed_factory_and_private_configuration_never_serializes() -> None:
    with pytest.raises(CapabilityRunnerError, match="registered flow factory"):
        asyncio.run(
            run_completion_driven(  # type: ignore[arg-type]
                _contract(),
                FakeFlow(FlowEvidence(tasks={})),
            )
        )
    with pytest.raises(CapabilityRunnerError, match="forbidden public (key|value)"):
        RegisteredFlowFactory.from_public_configuration(
            "private-probe-v1",
            "tests.test_offline_capability_runner:registered_probe_flow_factory",
            {"candidate_value": "INCYPHER{private}"},
        )
    with pytest.raises(CapabilityRunnerError, match="approved provider boundary"):
        RegisteredFlowFactory.from_public_configuration(
            "auth-probe-v1",
            "tests.test_offline_capability_runner:registered_probe_flow_factory",
            {"marker": None, "mode": "normal"},
            inherit_codex_home=True,
        )
    for private_configuration in (
        {"raw_payload": "opaque-private-bytes"},
        {"candidates": ["Y2FuZGlkYXRlLWJ5dGVz"]},
        {"checker_source": "def check(value): return True"},
        {"auth": "opaque-base64-material"},
    ):
        with pytest.raises(CapabilityRunnerError, match="configuration"):
            RegisteredFlowFactory.from_public_configuration(
                "private-probe-v1",
                "tests.test_offline_capability_runner:registered_probe_flow_factory",
                private_configuration,
            )
    with pytest.raises(CapabilityRunnerError, match="approved flow factory"):
        RegisteredFlowFactory.from_public_configuration(
            "private-probe-v1",
            "tests.test_offline_capability_runner:FakeFlow",
            {"opaque": "value"},
        )


def test_disposable_worker_environment_strips_board_and_candidate_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CTFD_API_TOKEN", "private-board-token")
    monkeypatch.setenv("TEAM_KEY", "private-team-key")
    monkeypatch.setenv("RAPIDO_PRIVATE_CANDIDATE", "INCYPHER{private}")

    receipt = asyncio.run(
        run_completion_driven(
            _contract(),
            _registered_probe_factory("environment_probe"),
            outer_deadline_seconds=3.0,
        )
    )

    assert receipt["status"] == "completed"


@pytest.mark.parametrize(
    ("mode", "expected_killed"),
    [
        ("drive_forever", False),
        ("cleanup_forever", False),
        ("drive_ignore_sigterm", True),
    ],
)
def test_registered_public_runner_reaps_infinite_worker_without_post_return_mutation(
    mode: str, expected_killed: bool
) -> None:
    marker_name = f"cap05-{mode}-{uuid.uuid4().hex}"
    marker = Path(tempfile.gettempdir()) / f"{marker_name}.cap05-probe"
    try:
        with pytest.raises(CapabilitySupervisorError) as caught:
            asyncio.run(
                run_completion_driven(
                    _contract(),
                    _registered_probe_factory(mode, marker_name),
                    outer_deadline_seconds=1.0,
                )
            )
        failure = caught.value
        assert failure.failure_label == "outer_deadline"
        assert failure.terminated is True
        assert failure.killed is expected_killed
        assert failure.child_reaped is True
        assert failure.child_absent is True
        assert marker.exists()
        size_at_return = marker.stat().st_size
        assert size_at_return > 0
        time.sleep(0.05)
        assert marker.stat().st_size == size_at_return
    finally:
        marker.unlink(missing_ok=True)


def test_public_runner_cancellation_reaps_worker_before_propagating() -> None:
    marker_name = f"cap05-cancel-{uuid.uuid4().hex}"
    marker = Path(tempfile.gettempdir()) / f"{marker_name}.cap05-probe"

    async def exercise() -> None:
        running = asyncio.create_task(
            run_completion_driven(
                _contract(),
                _registered_probe_factory("drive_forever", marker_name),
                outer_deadline_seconds=10.0,
            )
        )
        for _ in range(200):
            if marker.exists() and marker.stat().st_size > 0:
                break
            await asyncio.sleep(0.01)
        assert marker.exists()
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running

    try:
        asyncio.run(exercise())
        size_at_return = marker.stat().st_size
        time.sleep(0.05)
        assert marker.stat().st_size == size_at_return
    finally:
        marker.unlink(missing_ok=True)


def test_parent_deadline_dominates_receipt_after_event_loop_stall() -> None:
    async def exercise() -> None:
        running = asyncio.create_task(
            run_completion_driven(
                _contract(),
                _registered_probe_factory("loop_block_receipt"),
                outer_deadline_seconds=0.05,
            )
        )
        await asyncio.sleep(0.01)
        time.sleep(0.35)  # noqa: ASYNC251 - deliberately stalls the parent event loop
        with pytest.raises(CapabilitySupervisorError) as caught:
            await running
        assert caught.value.failure_label == "outer_deadline"
        assert caught.value.child_reaped is True
        assert caught.value.child_absent is True

    asyncio.run(exercise())


def test_default_parent_deadline_reanchors_only_after_worker_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resets: list[float] = []
    original = capability_runner._ParentDeadline.reset

    def tracked_reset(self: object, deadline: float) -> None:
        resets.append(deadline)
        original(self, deadline)  # type: ignore[arg-type]

    monkeypatch.setattr(capability_runner._ParentDeadline, "reset", tracked_reset)
    started = time.monotonic()
    receipt = asyncio.run(run_completion_driven(_contract(), _registered_probe_factory("normal")))

    assert receipt["status"] == "completed"
    assert len(resets) == 1
    assert resets[0] >= started + 3600 + 190


def test_linux_partial_setup_releases_lock_restores_subreaper_and_closes_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_pipe = os.pipe
    opened: list[int] = []
    calls = 0

    def failing_pipe() -> tuple[int, int]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("proof pipe failed")
        pair = real_pipe()
        opened.extend(pair)
        return pair

    restored: list[bool] = []
    monkeypatch.setattr(capability_runner.sys, "platform", "linux")
    monkeypatch.setattr(capability_runner.os, "pipe", failing_pipe)
    monkeypatch.setattr(capability_runner, "_linux_owned_descendants", lambda: set())
    monkeypatch.setattr(capability_runner, "_enable_linux_child_adoption", lambda: False)
    monkeypatch.setattr(
        capability_runner,
        "_restore_linux_child_adoption",
        lambda previous: restored.append(previous),
    )

    with pytest.raises(OSError, match="proof pipe failed"):
        asyncio.run(
            run_completion_driven(
                _contract(),
                _registered_probe_factory("normal"),
                outer_deadline_seconds=1.0,
            )
        )

    assert restored == [False]
    assert capability_runner._LINUX_SUPERVISOR_LOCK.acquire(blocking=False)
    capability_runner._LINUX_SUPERVISOR_LOCK.release()
    for descriptor in opened:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux subreaper contract")
def test_linux_containment_reaps_setsid_descendant_before_absence_claim() -> None:
    marker_name = f"cap05-setsid-{uuid.uuid4().hex}"
    marker = Path(tempfile.gettempdir()) / f"{marker_name}.cap05-probe"
    ready = Path(tempfile.gettempdir()) / f"{marker_name}.cap05-ready"
    try:
        with pytest.raises(CapabilitySupervisorError) as caught:
            asyncio.run(
                run_completion_driven(
                    _contract(),
                    _registered_probe_factory("detached_setsid", marker_name),
                    outer_deadline_seconds=1.5,
                )
            )
        failure = caught.value
        assert failure.failure_label == "outer_deadline"
        assert failure.terminated is True
        assert failure.killed is True
        assert failure.child_reaped is True
        assert failure.child_absent is True
        size_at_return = marker.stat().st_size
        assert size_at_return > 0
        time.sleep(0.05)
        assert marker.stat().st_size == size_at_return
    finally:
        marker.unlink(missing_ok=True)
        ready.unlink(missing_ok=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux subreaper contract")
def test_outer_wrapper_sigkill_reaps_adopted_setsid_descendant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker_name = f"cap05-wrapper-kill-{uuid.uuid4().hex}"
    marker = Path(tempfile.gettempdir()) / f"{marker_name}.cap05-probe"
    ready = Path(tempfile.gettempdir()) / f"{marker_name}.cap05-ready"
    launched: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def tracking_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)  # type: ignore[arg-type]
        launched.append(process)
        return process

    monkeypatch.setattr(capability_runner.subprocess, "Popen", tracking_popen)

    async def exercise() -> None:
        running = asyncio.create_task(
            run_completion_driven(
                _contract(),
                _registered_probe_factory("detached_setsid", marker_name),
                outer_deadline_seconds=5.0,
            )
        )
        for _ in range(500):
            if launched and ready.exists() and marker.exists():
                break
            await asyncio.sleep(0.005)
        assert launched and ready.exists() and marker.exists()
        os.kill(launched[0].pid, signal.SIGKILL)
        with pytest.raises(CapabilitySupervisorError) as caught:
            await running
        assert caught.value.child_reaped is True
        assert caught.value.child_absent is True

    try:
        asyncio.run(exercise())
        size_at_return = marker.stat().st_size
        time.sleep(0.05)
        assert marker.stat().st_size == size_at_return
    finally:
        marker.unlink(missing_ok=True)
        ready.unlink(missing_ok=True)


def test_outer_sigkill_without_containment_proof_never_claims_absence() -> None:
    class OuterKilledWrapper:
        pid = 999_999
        returncode = -signal.SIGKILL

        def poll(self) -> int:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return self.returncode

    proof_read, proof_write = os.pipe()
    os.close(proof_write)
    try:
        evidence = capability_runner._terminate_and_reap(  # type: ignore[arg-type]
            OuterKilledWrapper(),
            linux_containment=True,
            proof_descriptor=proof_read,
        )
    finally:
        os.close(proof_read)

    assert evidence == (False, False, True, False)
    with pytest.raises(RuntimeError, match="could not be proven absent"):
        capability_runner._closed_supervisor_error("outer_deadline", evidence)


def test_provider_auth_validation_uses_concrete_boundary_without_provider_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import rapido.offline_run as offline_run_module
    from rapido.offline_capability_runtime import (
        RegisteredDurableRuntime,
        _validate_adapter_result,
    )
    from rapido.offline_profile import offline_child_env
    from rapido.offline_run import _DockerRuntimeBoundary, _OfflineCodexClient

    contract = _contract()
    runtime_root = tmp_path / "private-runtime"
    runtime_root.mkdir(mode=0o700)
    work_root = tmp_path / "work"
    work_root.mkdir(mode=0o700)
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(mode=0o700)
    auth_path = codex_home / "auth.json"
    auth_path.write_text('{"credential":"fake"}', encoding="utf-8")
    auth_path.chmod(0o600)
    registrations = tuple(
        OfflineTaskRegistration(
            3000 + index,
            task.task_id,
            task.generator_version,
            task.checker_version,
            task.service_version,
        )
        for index, task in enumerate(contract.tasks, 1)
    )
    configuration: dict[str, object] = {
        "registry_id": "cap05-provider-auth-v1",
        "offline_profile_id": "cap05-provider-auth",
        "catalogue_version": "catalogue-v1",
        "board_implementation_version": OFFLINE_BOARD_IMPLEMENTATION_VERSION,
        "runner_image": "sha256:" + "0" * 64,
        "requires_provider_auth": True,
    }
    config = OfflineRuntimeConfig.build(
        offline_profile_id="cap05-provider-auth",
        catalogue_version="catalogue-v1",
        board_implementation_version=OFFLINE_BOARD_IMPLEMENTATION_VERSION,
        state_path=tmp_path / "state.sqlite3",
        work_root=work_root,
        codex_home=codex_home,
        runner_image=configuration["runner_image"],  # type: ignore[arg-type]
        task_registrations=registrations,
        active_challenges=5,
        episodes_per_challenge=3,
        attempts_per_challenge=4,
        lead_lanes=2,
        run_seconds=3600,
        max_artifact_bytes=1024,
        max_challenge_bytes=2048,
        max_workspace_bytes=1024 * 1024,
    )
    first_task = contract.tasks[0]
    first_visible = runtime_root / "capsules" / first_task.task_id / "visible"
    first_visible.mkdir(mode=0o700, parents=True)
    first_file = first_visible / "evidence.txt"
    first_file.write_bytes(b"provider-authenticated capsule evidence")
    catalogue = {
        "catalogue_version": "catalogue-v1",
        "tasks": [
            {
                "board_id": registration.board_id,
                "task_id": registration.task_id,
                "name": registration.task_id,
                "category": task.category,
                "type": "standard",
                "description": f"Provider-auth boundary test {task.task_id}",
                "value": 100,
                "files": ["evidence.txt"] if task.task_id == first_task.task_id else [],
                "solved": False,
                "attempts": 0,
                "max_attempts": None,
                "timeout": None,
                "shared": False,
                "service_required": False,
                "resource_profile_id": "none",
                "generator_version": registration.generator_version,
                "checker_version": registration.checker_version,
                "service_version": registration.service_version,
            }
            for registration, task in zip(registrations, contract.tasks, strict=True)
        ],
    }
    (runtime_root / "public-catalogue.json").write_text(json.dumps(catalogue), encoding="utf-8")

    def checker(_task_id: str, _candidate: bytes) -> bool:
        return False

    checker.process_isolated = True  # type: ignore[attr-defined]
    checker.descendant_confined = True  # type: ignore[attr-defined]
    board = OfflineBoard(
        runtime_root,
        work_root,
        checker,
        offline_profile_id=config.offline_profile_id,
        timeout=config.board_timeout_seconds,
        artifact_limit=config.max_artifact_bytes,
        capsule_limit=config.max_challenge_bytes,
        synthetic_in_process=True,
    )
    monkeypatch.setattr(offline_run_module.shutil, "which", lambda _name: "/usr/bin/true")
    boundary = _DockerRuntimeBoundary(
        workspace_root=work_root,
        codex_home=codex_home,
        private_roots=(runtime_root,),
        binary=config.codex_binary,
        image=config.runner_image,
        max_workspace_bytes=config.max_lane_workspace_bytes,
    )
    runtime = _OfflineCodexClient(
        boundary=boundary,
        env=offline_child_env(config),
        binary=config.codex_binary,
        model=config.model,
        reasoning_effort=config.reasoning_effort,
        cwd=config.work_root,
        max_workspace_bytes=config.max_lane_workspace_bytes,
        process_factory=boundary.process_factory,
    )
    cleanup_calls = 0

    async def cleanup(_deadline: float) -> CleanupInventory:
        nonlocal cleanup_calls
        cleanup_calls += 1
        return _cleanup()

    result = RegisteredDurableRuntime(
        config=config,
        board=board,
        runtime=runtime,
        evidence_source=lambda: None,  # type: ignore[return-value]
        cleanup=cleanup,
        private_roots=(runtime_root,),
        isolation_probe=boundary.verify,
    )
    offline_task_registrations = tuple(task.public_record() for task in registrations)
    capsule_binding = {
        "tasks": [
            {
                "task_id": task.task_id,
                "file_bytes_commitments": (
                    [
                        {
                            "path": "evidence.txt",
                            "sha256": hashlib.sha256(first_file.read_bytes()).hexdigest(),
                        }
                    ]
                    if task.task_id == first_task.task_id
                    else []
                ),
            }
            for task in contract.tasks
        ]
    }
    validated, owned_cleanup = _validate_adapter_result(
        result,
        contract,
        configuration,
        runtime_root,
        codex_home,
        offline_task_registrations,
        catalogue_payload=(runtime_root / "public-catalogue.json").read_bytes(),
        capsule_binding=capsule_binding,
        adapter_module_name=__name__,
    )
    assert validated is result
    assert owned_cleanup == boundary.cleanup_record
    assert cleanup_calls == 0

    changed_catalogue = copy.deepcopy(catalogue)
    changed_catalogue["tasks"][0]["description"] = "uncommitted alternate capsule"
    with pytest.raises(CapabilityRunnerError, match="catalogue projection changed"):
        _validate_adapter_result(
            result,
            contract,
            configuration,
            runtime_root,
            codex_home,
            offline_task_registrations,
            catalogue_payload=json.dumps(changed_catalogue).encode(),
            capsule_binding=capsule_binding,
            adapter_module_name=__name__,
        )

    foreign_evidence = lambda: None
    foreign_evidence.__module__ = "untrusted_runtime"
    with pytest.raises(CapabilityRunnerError, match="evidence boundary changed"):
        _validate_adapter_result(
            replace(result, evidence_source=foreign_evidence),  # type: ignore[arg-type]
            contract,
            configuration,
            runtime_root,
            codex_home,
            offline_task_registrations,
            catalogue_payload=(runtime_root / "public-catalogue.json").read_bytes(),
            capsule_binding=capsule_binding,
            adapter_module_name=__name__,
        )

    provider_calls: list[str] = []
    rejected = replace(
        result,
        isolation_probe=lambda: provider_calls.append("provider") or True,
    )
    with pytest.raises(CapabilityRunnerError, match="isolation proof is not concrete"):
        _validate_adapter_result(
            rejected,
            contract,
            configuration,
            runtime_root,
            codex_home,
            offline_task_registrations,
            catalogue_payload=(runtime_root / "public-catalogue.json").read_bytes(),
            capsule_binding=capsule_binding,
            adapter_module_name=__name__,
        )
    assert provider_calls == []
    cleanup_record = asyncio.run(boundary.cleanup_record())
    assert cleanup_record == {"process_absent": True, "active_process_count": 0}


def test_registered_runtime_rejects_stale_state_and_work_paths(tmp_path: Path) -> None:
    from rapido.offline_capability_runtime import _validate_fresh_run_paths

    state_path = tmp_path / "state.sqlite3"
    work_root = tmp_path / "work"
    work_root.mkdir(mode=0o700)
    _validate_fresh_run_paths(state_path, work_root)

    state_path.write_bytes(b"stale")
    with pytest.raises(CapabilityRunnerError, match="state path is not fresh"):
        _validate_fresh_run_paths(state_path, work_root)

    state_path.unlink()
    (work_root / "stale-artifact").write_bytes(b"stale")
    with pytest.raises(CapabilityRunnerError, match="work root is not fresh"):
        _validate_fresh_run_paths(state_path, work_root)


def test_registered_runtime_pins_every_additional_private_root(tmp_path: Path) -> None:
    from rapido.offline_capability_runtime import _pin_additional_private_roots

    runtime_root = tmp_path / "runtime"
    private_root = runtime_root / "checker"
    private_root.mkdir(mode=0o700, parents=True)
    pinned = _pin_additional_private_roots((runtime_root, private_root), runtime_root)
    displaced = runtime_root / "checker-old"
    try:
        private_root.rename(displaced)
        private_root.mkdir(mode=0o700)
        with pytest.raises(CapabilityRunnerError, match="isolation root changed"):
            pinned[0].revalidate("private runtime isolation root")
    finally:
        for boundary in pinned:
            boundary.close()


def test_registered_durable_factory_runs_actual_model_free_offline_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rapido.offline_capability_runtime import (
        PRIVATE_RUNTIME_REGISTRY_DIGEST_ENV,
        PRIVATE_RUNTIME_REGISTRY_SCHEMA,
        PRIVATE_RUNTIME_ROOT_ENV,
        _contract_binding,
    )

    contract = _contract()
    runtime_root = tmp_path / "private-runtime"
    runtime_root.mkdir(mode=0o700)
    candidates = {
        task.task_id: f"INCYPHER{{cap05-registered-{index:03d}}}"
        for index, task in enumerate(contract.tasks, 1)
    }
    catalogue: list[dict[str, object]] = []
    for index, task in enumerate(contract.tasks, 1):
        visible = runtime_root / "capsules" / task.task_id / "visible"
        visible.mkdir(mode=0o700, parents=True)
        catalogue.append(
            {
                "board_id": 2000 + index,
                "task_id": task.task_id,
                "name": task.task_id,
                "category": task.category,
                "type": "standard",
                "description": f"Fresh exact literal {candidates[task.task_id]}",
                "value": 100,
                "files": [],
                "solved": False,
                "attempts": 0,
                "max_attempts": 0,
                "timeout": None,
                "shared": False,
                "service_required": False,
                "resource_profile_id": "none",
                "generator_version": task.generator_version,
                "checker_version": task.checker_version,
                "service_version": task.service_version,
            }
        )
    catalogue_path = runtime_root / "public-catalogue.json"
    catalogue_payload = json.dumps({"catalogue_version": "catalogue-v1", "tasks": catalogue})
    catalogue_path.write_text(catalogue_payload, encoding="utf-8")
    admitted = [
        {
            "task_id": task.task_id,
            "family_id": task.family_id,
            "category": task.category,
            "assignment": "sentinel" if task.tier == "sentinel" else "calibration",
            "tier": task.tier,
            "resource_profile_id": "none",
            "generator_version": task.generator_version,
            "checker_version": task.checker_version,
            "service_version": task.service_version,
        }
        for task in contract.tasks
    ]
    manifest_payload = json.dumps(
        {
            "schema": "rapido-offline-capsule-export-v1",
            "catalogue_version": "catalogue-v1",
            "admitted": admitted,
            "excluded": [],
        }
    )
    manifest_path = runtime_root / "public-readiness.json"
    manifest_path.write_text(manifest_payload, encoding="utf-8")
    answers_path = runtime_root / "answers.json"
    answers_path.write_text(json.dumps(candidates), encoding="utf-8")
    adapter_source = textwrap.dedent(
        """
        import json
        import shutil
        import tempfile
        from pathlib import Path

        from rapido.offline_board import OFFLINE_BOARD_IMPLEMENTATION_VERSION, OfflineBoard
        from rapido.offline_capability_runner import (
            CandidateCheck,
            CheckerEconomyAttestation,
            CleanupInventory,
            FlowEvidence,
            ResourceObservation,
            TaskEvidence,
        )
        from rapido.offline_capability_runtime import RegisteredDurableRuntime
        from rapido.offline_profile import OfflineRuntimeConfig, OfflineTaskRegistration


        class NoModelRuntime:
            def __init__(self):
                self.solve_calls = 0

            async def start(self):
                return None

            async def validate_model(self, _model, _effort):
                return None

            async def solve(self, *_args, **_kwargs):
                self.solve_calls += 1
                raise AssertionError("model invocation is forbidden in this smoke")

            async def close(self):
                return None


        def build_runtime(contract, configuration, runtime_root, _codex_home):
            answers = json.loads((runtime_root / "answers.json").read_text(encoding="utf-8"))
            run_root = Path(tempfile.mkdtemp(prefix="cap05-runtime-"))
            run_root.chmod(0o700)
            work_root = run_root / "work"
            work_root.mkdir(mode=0o700)
            codex_home = run_root / "codex-home"
            codex_home.mkdir(mode=0o700)
            (runtime_root / "run-path.txt").write_text(str(run_root), encoding="utf-8")
            registrations = tuple(
                OfflineTaskRegistration(
                    2000 + index,
                    task.task_id,
                    task.generator_version,
                    task.checker_version,
                    task.service_version,
                )
                for index, task in enumerate(contract.tasks, 1)
            )
            config = OfflineRuntimeConfig.build(
                offline_profile_id=configuration["offline_profile_id"],
                catalogue_version=configuration["catalogue_version"],
                board_implementation_version=OFFLINE_BOARD_IMPLEMENTATION_VERSION,
                state_path=run_root / "state.sqlite3",
                work_root=work_root,
                codex_home=codex_home,
                runner_image=configuration["runner_image"],
                task_registrations=registrations,
                active_challenges=5,
                episodes_per_challenge=3,
                attempts_per_challenge=4,
                lead_lanes=2,
                run_seconds=3600,
                max_artifact_bytes=1024,
                max_challenge_bytes=2048,
                max_workspace_bytes=1024 * 1024,
            )

            def checker(task_id, candidate):
                return candidate == answers[task_id].encode()

            board = OfflineBoard(
                runtime_root,
                work_root,
                checker,
                offline_profile_id=config.offline_profile_id,
                timeout=config.board_timeout_seconds,
                artifact_limit=config.max_artifact_bytes,
                capsule_limit=config.max_challenge_bytes,
                synthetic_in_process=True,
            )
            runtime = NoModelRuntime()

            def evidence_source():
                snapshot = board.public_snapshot()
                attestation = CheckerEconomyAttestation.from_offline_board_snapshot(
                    snapshot, contract.tasks
                )
                outcomes = {
                    row["task_id"]: row["outcome"] for row in snapshot["candidates"]
                }
                resources = ResourceObservation(unavailable_reason="model_free")
                tasks = {
                    task.task_id: TaskEvidence(
                        admitted_ms=0,
                        started_ms=0,
                        terminal_ms=0,
                        terminal_label=(
                            "correct"
                            if outcomes.get(task.task_id) == "correct"
                            else "no_unique_candidate"
                        ),
                        candidate_checks=(CandidateCheck(0, 0, 0, "correct"),)
                        if outcomes.get(task.task_id) == "correct"
                        else (),
                        resources=resources,
                        cleanup_passed=True,
                    )
                    for task in contract.tasks
                }
                return FlowEvidence(
                    tasks=tasks,
                    checker_attestation=attestation,
                    resources=resources,
                )

            async def cleanup(_deadline):
                shutil.rmtree(run_root)
                return CleanupInventory(0, 0, 0, 0, 0, 0, 0, 0)

            return RegisteredDurableRuntime(
                config=config,
                board=board,
                runtime=runtime,
                evidence_source=evidence_source,
                cleanup=cleanup,
                private_roots=(runtime_root,),
                isolation_probe=lambda: True,
            )
        """
    ).encode()
    adapter_path = runtime_root / "adapter.py"
    adapter_path.write_bytes(adapter_source)
    public_configuration: dict[str, object] = {
        "registry_id": "cap05-model-free-v1",
        "offline_profile_id": "cap05-model-free",
        "catalogue_version": "catalogue-v1",
        "board_implementation_version": OFFLINE_BOARD_IMPLEMENTATION_VERSION,
        "runner_image": "sha256:" + "0" * 64,
        "requires_provider_auth": False,
    }
    registry_path = runtime_root / "registry.json"
    binding_rows = []
    for task, catalogue_row, manifest_row in zip(contract.tasks, catalogue, admitted, strict=True):
        row = {
            "board_id": catalogue_row["board_id"],
            "task_id": task.task_id,
            "family_id": task.family_id,
            "category": task.category,
            "tier": task.tier,
            "assignment": manifest_row["assignment"],
            "description_commitment": _sha256_json(catalogue_row["description"]),
            "files_commitment": _sha256_json(catalogue_row["files"]),
            "file_bytes_commitments": [],
            "resource_profile_id": catalogue_row["resource_profile_id"],
            "generator_version": task.generator_version,
            "checker_version": task.checker_version,
            "service_version": task.service_version,
        }
        binding_rows.append({**row, "task_commitment": _sha256_json(row)})
    registry_payload = json.dumps(
        {
            "schema": PRIVATE_RUNTIME_REGISTRY_SCHEMA,
            "registry_id": public_configuration["registry_id"],
            "public_configuration": public_configuration,
            "contract": _contract_binding(contract),
            "offline_task_registrations": [
                {
                    "board_id": 2000 + index,
                    "task_id": task.task_id,
                    "generator_version": task.generator_version,
                    "checker_version": task.checker_version,
                    "service_version": task.service_version,
                }
                for index, task in enumerate(contract.tasks, 1)
            ],
            "capsule_binding": {
                "namespace": "cap05-model-free-v1",
                "catalogue_sha256": hashlib.sha256(catalogue_payload.encode()).hexdigest(),
                "manifest_sha256": hashlib.sha256(manifest_payload.encode()).hexdigest(),
                "tasks": binding_rows,
            },
            "adapter": {
                "module": "adapter.py",
                "sha256": __import__("hashlib").sha256(adapter_source).hexdigest(),
                "callable": "build_runtime",
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    registry_path.write_text(registry_payload, encoding="utf-8")
    for path in (catalogue_path, manifest_path, answers_path, adapter_path, registry_path):
        path.chmod(0o600)
    monkeypatch.setenv(PRIVATE_RUNTIME_ROOT_ENV, str(runtime_root))
    monkeypatch.setenv(
        PRIVATE_RUNTIME_REGISTRY_DIGEST_ENV,
        __import__("hashlib").sha256(registry_payload.encode()).hexdigest(),
    )
    factory = RegisteredFlowFactory.from_public_configuration(
        "registered-durable-v1",
        "rapido.offline_capability_runtime:registered_durable_flow_factory",
        public_configuration,
        inherit_private_runtime_root=True,
    )
    resolved = capability_runner._resolve_flow_factory(factory)
    assert resolved.__name__ == "registered_durable_flow_factory"
    serialized_factory = json.dumps(capability_runner._factory_public(factory), sort_keys=True)
    assert str(runtime_root) not in serialized_factory
    assert all(candidate not in serialized_factory for candidate in candidates.values())

    receipt = asyncio.run(run_completion_driven(contract, factory, outer_deadline_seconds=10.0))

    assert receipt["status"] == "completed", receipt
    assert receipt["checker_attestation"]["checker_call_count"] == len(contract.tasks)
    assert receipt["aggregate"]["raw_correct_tasks"] == 12
    serialized = json.dumps(receipt, sort_keys=True)
    assert str(runtime_root) not in serialized
    assert all(candidate not in serialized for candidate in candidates.values())
    run_root = Path((runtime_root / "run-path.txt").read_text(encoding="utf-8"))
    assert not run_root.exists()
